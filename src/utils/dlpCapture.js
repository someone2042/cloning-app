'use strict';

const fs   = require('fs');
const path = require('path');

/**
 * DLP Data Extractor
 *
 * Extracts all "typed values" and sensitive data from proxy traffic
 * into a flat, searchable JSONL (JSON Lines) log that DLP word-list
 * scanners can consume directly.
 *
 * What it captures:
 *  - Cookies (name + value, both request and response Set-Cookie)
 *  - Form fields (application/x-www-form-urlencoded POST bodies)
 *  - JSON payloads (recursively flattened key.path = value)
 *  - Query string parameters
 *  - Client-side input captures (typed text in input/textarea fields)
 *  - URL paths themselves (can contain tokens, IDs, etc.)
 *
 * Output: one JSON object per line in dlp_data_YYYY-MM-DD.jsonl
 * Each line has: { timestamp, type, source, field, value, url, method }
 */

const LOG_DIR = process.env.TRAFFIC_LOG_DIR || path.join(process.cwd(), 'traffic_logs');

// ═══════════════════════════════════════════════════════════════
//  In-memory buffer — flushed to disk periodically
// ═══════════════════════════════════════════════════════════════
let buffer = [];
let flushTimer = null;
const FLUSH_INTERVAL_MS = 10_000; // flush every 10 seconds
const MAX_BUFFER_SIZE   = 200;    // or when buffer hits 200 entries

function ensureLogDir() {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  }
}

function getDlpLogFile() {
  const date = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  return path.join(LOG_DIR, `dlp_data_${date}.jsonl`);
}

function addEntry(entry) {
  buffer.push({
    timestamp: new Date().toISOString(),
    ...entry,
  });

  if (buffer.length >= MAX_BUFFER_SIZE) {
    flushDlp();
  }
}

function flushDlp() {
  if (buffer.length === 0) return;
  try {
    ensureLogDir();
    const lines = buffer.map(e => JSON.stringify(e)).join('\n') + '\n';
    fs.appendFileSync(getDlpLogFile(), lines, 'utf8');
    buffer = [];
  } catch (err) {
    console.error('[DLP] Failed to flush:', err.message);
  }
}

// ═══════════════════════════════════════════════════════════════
//  Extractors
// ═══════════════════════════════════════════════════════════════

/**
 * Extract cookies from a Cookie: header string.
 */
function extractRequestCookies(cookieHeader, url, method) {
  if (!cookieHeader) return;
  const pairs = cookieHeader.split(';');
  for (const pair of pairs) {
    const eqIdx = pair.indexOf('=');
    if (eqIdx === -1) continue;
    const name  = pair.slice(0, eqIdx).trim();
    const value = pair.slice(eqIdx + 1).trim();
    if (name && value) {
      addEntry({
        type: 'cookie',
        source: 'request',
        field: name,
        value,
        url,
        method,
      });
    }
  }
}

/**
 * Extract cookies from Set-Cookie response headers.
 */
function extractResponseCookies(setCookieHeaders, url, method) {
  if (!setCookieHeaders) return;
  const list = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
  for (const header of list) {
    const parts = header.split(';');
    const main  = (parts[0] || '').trim();
    const eqIdx = main.indexOf('=');
    if (eqIdx === -1) continue;
    const name  = main.slice(0, eqIdx).trim();
    const value = main.slice(eqIdx + 1).trim();
    if (name && value) {
      addEntry({
        type: 'cookie',
        source: 'response',
        field: name,
        value,
        url,
        method,
      });
    }
  }
}

/**
 * Extract query string parameters from a URL.
 */
function extractQueryParams(url, method) {
  try {
    const parsed = new URL(url, 'http://localhost');
    for (const [name, value] of parsed.searchParams) {
      if (value && value.length > 0) {
        addEntry({
          type: 'query_param',
          source: 'request',
          field: name,
          value,
          url,
          method,
        });
      }
    }
  } catch {}
}

/**
 * Extract form-urlencoded POST body fields.
 */
function extractFormBody(body, url, method) {
  if (!body) return;
  try {
    const text = typeof body === 'string' ? body : body.toString('utf8');
    const params = new URLSearchParams(text);
    for (const [name, value] of params) {
      if (value && value.length > 0) {
        addEntry({
          type: 'form_field',
          source: 'request',
          field: name,
          value,
          url,
          method,
        });
      }
    }
  } catch {}
}

/**
 * Recursively flatten a JSON object into dot-notation key-value pairs.
 */
function flattenJson(obj, prefix, results, depth) {
  if (depth > 8) return; // prevent infinite recursion
  if (obj === null || obj === undefined) return;

  if (typeof obj === 'string' || typeof obj === 'number' || typeof obj === 'boolean') {
    const strVal = String(obj);
    if (strVal.length > 0 && strVal.length < 10000) {
      results.push({ field: prefix, value: strVal });
    }
    return;
  }

  if (Array.isArray(obj)) {
    for (let i = 0; i < Math.min(obj.length, 50); i++) {
      flattenJson(obj[i], `${prefix}[${i}]`, results, depth + 1);
    }
    return;
  }

  if (typeof obj === 'object') {
    for (const [key, val] of Object.entries(obj)) {
      flattenJson(val, prefix ? `${prefix}.${key}` : key, results, depth + 1);
    }
  }
}

/**
 * Extract JSON body fields (request or response).
 */
function extractJsonBody(body, url, method, source) {
  if (!body) return;
  try {
    const text = typeof body === 'string' ? body : body.toString('utf8');
    // Quick check — is this JSON?
    const trimmed = text.trim();
    if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return;

    const parsed = JSON.parse(trimmed);
    const results = [];
    flattenJson(parsed, '', results, 0);

    for (const { field, value } of results) {
      addEntry({
        type: 'json_field',
        source,
        field,
        value,
        url,
        method,
      });
    }
  } catch {} // not JSON — skip
}

// ═══════════════════════════════════════════════════════════════
//  Public API
// ═══════════════════════════════════════════════════════════════

/**
 * Process a complete request/response pair and extract all DLP-relevant data.
 *
 * @param {object} req         Express request
 * @param {object} upstreamRes Axios response ({ data, status, headers })
 * @param {string} upstreamUrl The real upstream URL
 */
function extractDlpData(req, upstreamRes, upstreamUrl) {
  const method = req.method;
  const url    = upstreamUrl;
  const reqCt  = (req.headers['content-type'] || '').toLowerCase();
  const resCt  = upstreamRes ? (upstreamRes.headers['content-type'] || '').toLowerCase() : '';

  // 1. Request cookies
  extractRequestCookies(req.headers['cookie'], url, method);

  // 2. Response Set-Cookie
  if (upstreamRes && upstreamRes.headers['set-cookie']) {
    extractResponseCookies(upstreamRes.headers['set-cookie'], url, method);
  }

  // 3. Query string parameters
  extractQueryParams(url, method);

  // 4. Request body — form fields
  if (req.rawBody && req.rawBody.length > 0 && reqCt.includes('x-www-form-urlencoded')) {
    extractFormBody(req.rawBody, url, method);
  }

  // 5. Request body — JSON
  if (req.rawBody && req.rawBody.length > 0 && reqCt.includes('json')) {
    extractJsonBody(req.rawBody, url, method, 'request');
  }

  // 6. Response body — JSON (API responses often contain user data)
  if (upstreamRes && upstreamRes.data && resCt.includes('json')) {
    const bodyBuf = Buffer.from(upstreamRes.data);
    if (bodyBuf.length < 512 * 1024) { // skip huge JSON
      extractJsonBody(bodyBuf, url, method, 'response');
    }
  }
}

/**
 * Record a client-side input capture (sent by the input monitor script).
 */
function recordInputCapture(data) {
  if (!data) return;
  const { field, value, inputType, pageUrl, formAction } = data;
  if (!value || value.length === 0) return;

  addEntry({
    type: 'input_capture',
    source: 'client',
    field: field || 'unknown',
    value,
    inputType: inputType || 'text',
    url: pageUrl || '',
    formAction: formAction || '',
    method: 'INPUT',
  });
}

/**
 * Initialize — set up periodic flush and exit handlers.
 */
function initDlp() {
  if (flushTimer) clearInterval(flushTimer);
  flushTimer = setInterval(flushDlp, FLUSH_INTERVAL_MS);

  process.on('SIGINT',  () => { flushDlp(); });
  process.on('SIGTERM', () => { flushDlp(); });
  process.on('exit',    () => { flushDlp(); });

  console.log(`[DLP] ──────────────────────────────────────`);
  console.log(`[DLP]   Data extractor active`);
  console.log(`[DLP]   Log file : ${getDlpLogFile()}`);
  console.log(`[DLP] ──────────────────────────────────────`);
}

/**
 * Get current DLP data stats.
 */
function getDlpStats() {
  const logFile = getDlpLogFile();
  let lineCount = 0;
  let fileSize  = 0;
  try {
    if (fs.existsSync(logFile)) {
      const stat = fs.statSync(logFile);
      fileSize = stat.size;
      const content = fs.readFileSync(logFile, 'utf8');
      lineCount = content.split('\n').filter(l => l.trim()).length;
    }
  } catch {}

  return {
    currentFile: path.basename(logFile),
    buffered: buffer.length,
    totalEntries: lineCount,
    fileSize,
    logDir: LOG_DIR,
  };
}

/**
 * Read all DLP entries from today's log (for the admin API).
 * Supports optional type filter.
 */
function getDlpEntries(typeFilter, limit) {
  flushDlp(); // flush buffer first
  const logFile = getDlpLogFile();
  if (!fs.existsSync(logFile)) return [];

  try {
    const lines = fs.readFileSync(logFile, 'utf8')
      .split('\n')
      .filter(l => l.trim())
      .map(l => {
        try { return JSON.parse(l); } catch { return null; }
      })
      .filter(Boolean);

    let filtered = typeFilter
      ? lines.filter(e => e.type === typeFilter)
      : lines;

    if (limit && limit > 0) {
      filtered = filtered.slice(-limit); // last N entries
    }

    return filtered;
  } catch {
    return [];
  }
}

/**
 * List all DLP log files.
 */
function listDlpFiles() {
  try {
    return fs.readdirSync(LOG_DIR)
      .filter(f => f.startsWith('dlp_data_') && f.endsWith('.jsonl'))
      .map(f => {
        const stat = fs.statSync(path.join(LOG_DIR, f));
        return { name: f, size: stat.size, modified: stat.mtime };
      })
      .sort((a, b) => b.modified - a.modified);
  } catch {
    return [];
  }
}

module.exports = {
  extractDlpData,
  recordInputCapture,
  initDlp,
  getDlpStats,
  getDlpEntries,
  listDlpFiles,
  flushDlp,
};
