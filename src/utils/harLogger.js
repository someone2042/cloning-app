'use strict';

const fs   = require('fs');
const path = require('path');
const config = require('../config');

/**
 * HAR (HTTP Archive v1.2) Traffic Logger
 *
 * Records every request/response pair flowing through the proxy into
 * standard HAR files that can be consumed by any DLP, SIEM, or
 * packet-inspection tool.
 *
 * Design:
 *  - One HAR file per "page session" (configurable rotation)
 *  - Entries include full headers, timing, body size, and MIME type
 *  - Request/response bodies are optionally captured for text/* and
 *    application/json content (configurable, off by default for
 *    binary payloads to save disk)
 *  - Files are written to TRAFFIC_LOG_DIR (default: ./traffic_logs/)
 *  - Rotation happens every TRAFFIC_LOG_ROTATE_MINUTES (default: 60)
 *
 * HAR spec: http://www.softwareishard.com/blog/har-12-spec/
 */

// ═══════════════════════════════════════════════════════════════
//  Configuration
// ═══════════════════════════════════════════════════════════════
const LOG_DIR          = process.env.TRAFFIC_LOG_DIR || path.join(process.cwd(), 'traffic_logs');
const ROTATE_MINUTES   = parseInt(process.env.TRAFFIC_LOG_ROTATE_MINUTES || '60', 10);
const CAPTURE_BODIES   = (process.env.TRAFFIC_LOG_BODIES || 'true').toLowerCase() === 'true';
const MAX_BODY_SIZE    = parseInt(process.env.TRAFFIC_LOG_MAX_BODY_KB || '512', 10) * 1024;
const LOG_INTERNAL     = (process.env.TRAFFIC_LOG_INTERNAL || 'false').toLowerCase() === 'true';

// MIME types whose bodies we capture (when CAPTURE_BODIES is true)
const CAPTURABLE_MIMES = [
  'text/html', 'text/css', 'text/javascript', 'text/plain', 'text/xml',
  'application/json', 'application/javascript', 'application/xml',
  'application/x-www-form-urlencoded',
  'multipart/form-data',
];

// ═══════════════════════════════════════════════════════════════
//  HAR Document State
// ═══════════════════════════════════════════════════════════════
let currentHar     = null;
let currentFile    = null;
let rotationTimer  = null;
let entryCount     = 0;
let pageCounter    = 0;

function ensureLogDir() {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
    console.log(`[HAR Logger] Created log directory: ${LOG_DIR}`);
  }
}

function newHarDocument() {
  pageCounter++;
  const now = new Date();
  return {
    log: {
      version: '1.2',
      creator: {
        name: 'internal-web-proxy',
        version: '1.0.0',
        comment: `Target: ${config.targetOrigin}`,
      },
      pages: [{
        startedDateTime: now.toISOString(),
        id: `page_${pageCounter}`,
        title: `Proxy Session — ${config.targetOrigin}`,
        pageTimings: {
          onContentLoad: -1,
          onLoad: -1,
        },
      }],
      entries: [],
    },
  };
}

function rotate() {
  // Flush current HAR to disk
  flush();
  // Start a fresh document
  currentHar  = newHarDocument();
  entryCount  = 0;
  currentFile = generateFilename();
  console.log(`[HAR Logger] Rotated → ${path.basename(currentFile)}`);
}

function generateFilename() {
  const now = new Date();
  const ts  = now.toISOString().replace(/[:.]/g, '-').replace('T', '_').slice(0, 19);
  return path.join(LOG_DIR, `traffic_${ts}.har`);
}

function flush() {
  if (!currentHar || currentHar.log.entries.length === 0) return;
  try {
    ensureLogDir();
    const filePath = currentFile || generateFilename();
    fs.writeFileSync(filePath, JSON.stringify(currentHar, null, 2), 'utf8');
    console.log(`[HAR Logger] Flushed ${currentHar.log.entries.length} entries → ${path.basename(filePath)}`);
  } catch (err) {
    console.error('[HAR Logger] Failed to write HAR file:', err.message);
  }
}

// ═══════════════════════════════════════════════════════════════
//  Header Helpers
// ═══════════════════════════════════════════════════════════════
function headersToHar(headers) {
  if (!headers) return [];
  // Express req.headers is a flat object; axios response.headers is similar
  // Set-Cookie can be an array
  const result = [];
  for (const [name, value] of Object.entries(headers)) {
    if (Array.isArray(value)) {
      for (const v of value) {
        result.push({ name, value: String(v) });
      }
    } else if (value !== undefined && value !== null) {
      result.push({ name, value: String(value) });
    }
  }
  return result;
}

function cookiesToHar(cookieHeader) {
  if (!cookieHeader) return [];
  return cookieHeader.split(';').map(pair => {
    const eqIdx = pair.indexOf('=');
    if (eqIdx === -1) return { name: pair.trim(), value: '' };
    return {
      name: pair.slice(0, eqIdx).trim(),
      value: pair.slice(eqIdx + 1).trim(),
    };
  }).filter(c => c.name);
}

function queryStringToHar(url) {
  try {
    const parsed = new URL(url, 'http://localhost');
    const result = [];
    for (const [name, value] of parsed.searchParams) {
      result.push({ name, value });
    }
    return result;
  } catch {
    return [];
  }
}

function isCapturable(contentType) {
  if (!contentType) return false;
  const lower = contentType.toLowerCase();
  return CAPTURABLE_MIMES.some(mime => lower.includes(mime));
}

// ═══════════════════════════════════════════════════════════════
//  Determine the real upstream URL from the proxy request
// ═══════════════════════════════════════════════════════════════
function resolveUpstreamUrl(req) {
  const proxyPath = req.originalUrl || req.url;

  // /__relay__?url=https://... → the relay destination
  if (proxyPath.startsWith('/__relay__') && req.query && req.query.url) {
    return req.query.url;
  }

  // /__ext__?url=https://... → the external resource
  if (proxyPath.startsWith('/__ext__') && req.query && req.query.url) {
    return req.query.url;
  }

  // /__relay__/some/path → target domain + path
  if (proxyPath.startsWith('/__relay__')) {
    const subPath = proxyPath.slice('/__relay__'.length);
    return config.targetOrigin + (subPath || '/');
  }

  // Normal proxied path → target domain + path
  return config.targetOrigin + proxyPath;
}

// ═══════════════════════════════════════════════════════════════
//  Core: Build a HAR Entry
// ═══════════════════════════════════════════════════════════════
function buildEntry(req, res, upstreamRes, timingMs) {
  const now           = new Date();
  const upstreamUrl   = resolveUpstreamUrl(req);
  const requestBody   = req.rawBody || null;
  const responseBody  = upstreamRes ? Buffer.from(upstreamRes.data) : null;
  const reqCt         = req.headers['content-type'] || '';
  const resCt         = upstreamRes ? (upstreamRes.headers['content-type'] || '') : '';

  // Request postData
  let postData = undefined;
  if (requestBody && requestBody.length > 0 && CAPTURE_BODIES) {
    const mimeType = reqCt.split(';')[0].trim() || 'application/octet-stream';
    if (isCapturable(reqCt) && requestBody.length <= MAX_BODY_SIZE) {
      postData = {
        mimeType,
        text: requestBody.toString('utf8'),
      };
      // Parse params for form-urlencoded
      if (mimeType === 'application/x-www-form-urlencoded') {
        try {
          const params = new URLSearchParams(requestBody.toString('utf8'));
          postData.params = [];
          for (const [name, value] of params) {
            postData.params.push({ name, value });
          }
        } catch {}
      }
    } else {
      postData = {
        mimeType,
        text: `[Binary body, ${requestBody.length} bytes]`,
        comment: 'Body not captured (binary or exceeds size limit)',
      };
    }
  }

  // Response content
  let responseContent = {
    size: responseBody ? responseBody.length : 0,
    compression: 0,
    mimeType: resCt.split(';')[0].trim() || 'application/octet-stream',
  };

  if (CAPTURE_BODIES && responseBody && isCapturable(resCt) && responseBody.length <= MAX_BODY_SIZE) {
    responseContent.text = responseBody.toString('utf8');
  }

  const entry = {
    startedDateTime: new Date(now.getTime() - timingMs).toISOString(),
    time: timingMs,
    request: {
      method: req.method,
      url: upstreamUrl,
      httpVersion: 'HTTP/' + (req.httpVersion || '1.1'),
      cookies: cookiesToHar(req.headers['cookie']),
      headers: headersToHar(req.headers),
      queryString: queryStringToHar(upstreamUrl),
      headersSize: -1,
      bodySize: requestBody ? requestBody.length : 0,
    },
    response: {
      status: upstreamRes ? upstreamRes.status : res.statusCode,
      statusText: upstreamRes ? (upstreamRes.statusText || '') : '',
      httpVersion: 'HTTP/1.1',
      cookies: [],
      headers: upstreamRes ? headersToHar(upstreamRes.headers) : [],
      content: responseContent,
      redirectURL: '',
      headersSize: -1,
      bodySize: responseBody ? responseBody.length : 0,
    },
    cache: {},
    timings: {
      send: 0,
      wait: timingMs,
      receive: 0,
    },
    pageref: `page_${pageCounter}`,
    _proxyPath: req.originalUrl || req.url,
    _handler: req._proxyHandler || 'unknown',
  };

  if (postData) {
    entry.request.postData = postData;
  }

  // Parse Set-Cookie from response
  if (upstreamRes && upstreamRes.headers['set-cookie']) {
    const setCookies = Array.isArray(upstreamRes.headers['set-cookie'])
      ? upstreamRes.headers['set-cookie']
      : [upstreamRes.headers['set-cookie']];
    entry.response.cookies = setCookies.map(sc => {
      const parts = sc.split(';').map(s => s.trim());
      const main  = parts[0] || '';
      const eqIdx = main.indexOf('=');
      return {
        name: eqIdx > 0 ? main.slice(0, eqIdx) : main,
        value: eqIdx > 0 ? main.slice(eqIdx + 1) : '',
        path: '/',
        httpOnly: sc.toLowerCase().includes('httponly'),
        secure: sc.toLowerCase().includes('secure'),
      };
    });
  }

  return entry;
}

// ═══════════════════════════════════════════════════════════════
//  Public API
// ═══════════════════════════════════════════════════════════════

/**
 * Record a completed request/response to the HAR log.
 * Called by each handler after the upstream round-trip is done.
 *
 * @param {object} req         Express request
 * @param {object} res         Express response
 * @param {object} upstreamRes Axios response (or { data, status, headers })
 * @param {number} timingMs    Round-trip time in ms
 */
function recordEntry(req, res, upstreamRes, timingMs) {
  // Skip internal proxy plumbing unless explicitly enabled
  const proxyPath = req.originalUrl || req.url;
  if (!LOG_INTERNAL && (
    proxyPath.startsWith('/__proxy_shim__') ||
    proxyPath === '/favicon.ico'
  )) {
    return;
  }

  if (!currentHar) {
    init(); // lazy init
  }

  try {
    const entry = buildEntry(req, res, upstreamRes, timingMs);
    currentHar.log.entries.push(entry);
    entryCount++;

    // Auto-flush every 50 entries to prevent data loss
    if (entryCount % 50 === 0) {
      flush();
    }
  } catch (err) {
    console.error('[HAR Logger] Failed to record entry:', err.message);
  }
}

/**
 * Initialize the HAR logger — creates log dir, sets up rotation timer.
 */
function init() {
  ensureLogDir();
  currentHar  = newHarDocument();
  currentFile = generateFilename();

  // Set up rotation
  if (rotationTimer) clearInterval(rotationTimer);
  rotationTimer = setInterval(rotate, ROTATE_MINUTES * 60 * 1000);

  // Flush on process exit
  process.on('SIGINT',  () => { flush(); process.exit(0); });
  process.on('SIGTERM', () => { flush(); process.exit(0); });
  process.on('exit',    () => { flush(); });

  console.log(`[HAR Logger] ──────────────────────────────────────`);
  console.log(`[HAR Logger]   Log dir       : ${LOG_DIR}`);
  console.log(`[HAR Logger]   Rotation      : every ${ROTATE_MINUTES} min`);
  console.log(`[HAR Logger]   Capture bodies: ${CAPTURE_BODIES}`);
  console.log(`[HAR Logger]   Max body size : ${MAX_BODY_SIZE / 1024} KB`);
  console.log(`[HAR Logger] ──────────────────────────────────────`);
}

/**
 * Force-flush the current HAR to disk. Useful for API-triggered exports.
 */
function forceFlush() {
  flush();
  return currentFile;
}

/**
 * Get a summary of the current session.
 */
function getStats() {
  return {
    currentFile: currentFile ? path.basename(currentFile) : null,
    entries: currentHar ? currentHar.log.entries.length : 0,
    logDir: LOG_DIR,
    rotateMinutes: ROTATE_MINUTES,
    captureBodies: CAPTURE_BODIES,
  };
}

module.exports = { recordEntry, init, forceFlush, getStats };
