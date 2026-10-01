'use strict';
const axios  = require('axios');
const config = require('../config');
const { fetchTarget }             = require('../utils/fetchTarget');
const { rewriteSetCookieHeaders } = require('../utils/cookieRewriter');
const { getCookieString, ingestResponseCookies, exportSessionCookies } = require('../utils/cookieJar');
const { recordEntry }             = require('../utils/harLogger');
const { extractDlpData }          = require('../utils/dlpCapture');

const DROP_RESPONSE_HEADERS = new Set([
  'content-security-policy',
  'content-security-policy-report-only',
  'x-frame-options',
  'strict-transport-security',
  'transfer-encoding',
  'content-encoding',
]);

const DROP_REQUEST_HEADERS = new Set([
  'host', 'connection', 'transfer-encoding',
  'upgrade', 'proxy-authorization', 'te', 'trailers', 'keep-alive',
]);

/**
 * Relay handler — two modes:
 *
 * MODE A — Path relay:   /__relay__/api/v1/data
 *   Forwards to TARGET_DOMAIN/api/v1/data.
 *
 * MODE B — Full-URL relay:  /__relay__?url=https://api.other.com/data
 *   Forwards to any absolute URL (used by the client shim for external API calls).
 *
 * In both modes: method, headers, and body are preserved.
 * Cookies come from the server-side jar (auto-accumulated from target responses).
 */
async function handleRelay(req, res) {
  const _startTime = Date.now();
  req._proxyHandler = 'relay';

  // ── CORS preflight ──────────────────────────────────────────────────────────
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin',      req.headers.origin || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods',     'GET,POST,PUT,PATCH,DELETE,OPTIONS');
    res.setHeader(
      'Access-Control-Allow-Headers',
      req.headers['access-control-request-headers'] || '*'
    );
    res.setHeader('Access-Control-Max-Age', '86400');
    return res.status(204).end();
  }

  try {
    let upstream;

    if (req.query.url) {
      // MODE B: relay to an arbitrary external URL
      upstream = await relayToAbsoluteUrl(req);
    } else {
      // MODE A: relay to the configured target domain
      const targetPath = req.path || '/';
      const rawQuery   = req.url.includes('?') ? req.url.slice(req.url.indexOf('?') + 1) : '';

      upstream = await fetchTarget(targetPath, {
        method     : req.method,
        headers    : req.headers,
        body       : req.rawBody && req.rawBody.length > 0 ? req.rawBody : null,
        queryString: rawQuery,
        sessionId  : req.sessionId,
      });
    }

    // ── Build response headers ──────────────────────────────────────────────
    const outHeaders = {};
    for (const [k, v] of Object.entries(upstream.headers)) {
      if (!DROP_RESPONSE_HEADERS.has(k.toLowerCase())) {
        outHeaders[k] = v;
      }
    }

    // Rewrite Set-Cookie for the browser (strip Domain/Secure so they stick on localhost)
    if (outHeaders['set-cookie']) {
      outHeaders['set-cookie'] = rewriteSetCookieHeaders(outHeaders['set-cookie']);
    }

    if (req._newProxySession) {
      if (!outHeaders['set-cookie']) outHeaders['set-cookie'] = [];
      else if (!Array.isArray(outHeaders['set-cookie'])) outHeaders['set-cookie'] = [outHeaders['set-cookie']];
      outHeaders['set-cookie'].push(`__proxy_session=${req.sessionId}; Path=/; HttpOnly; SameSite=Lax`);

      const existingNames = new Set(outHeaders['set-cookie'].map(h => h.split('=')[0].trim()));
      const sessionCookies = exportSessionCookies(req.sessionId);
      for (const sc of sessionCookies) {
        if (!existingNames.has(sc.name)) {
          let setStr = `${sc.name}=${sc.value}; Path=${sc.path || '/'}; SameSite=Lax`;
          if (sc.httpOnly) setStr += '; HttpOnly';
          if (sc.expirationDate) {
            const d = new Date(sc.expirationDate * 1000);
            setStr += `; Expires=${d.toUTCString()}`;
          }
          outHeaders['set-cookie'].push(setStr);
        }
      }
    }

    // CORS — relay responses must be readable by the proxied page
    outHeaders['access-control-allow-origin']      = req.headers.origin || '*';
    outHeaders['access-control-allow-credentials'] = 'true';

    res.status(upstream.status);
    for (const [k, v] of Object.entries(outHeaders)) {
      try { res.setHeader(k, v); } catch {}
    }

    // DLP extraction
    const upstreamUrl = req.query.url || (config.targetOrigin + (req.path || '/'));
    extractDlpData(req, upstream, upstreamUrl);

    recordEntry(req, res, upstream, Date.now() - _startTime);
    return res.send(Buffer.from(upstream.data));

  } catch (err) {
    console.error('[Relay] Error:', err.message);
    return res.status(502).json({ error: 'relay_failed', message: err.message });
  }
}

/**
 * MODE B: relay to an arbitrary absolute URL.
 * Uses jar cookies (so the external service — e.g. facebook.com/api — gets
 * the same session as the main target when they share cookies).
 */
async function relayToAbsoluteUrl(req) {
  const destUrl = req.query.url;

  let parsed;
  try {
    parsed = new URL(destUrl);
  } catch {
    throw new Error(`Invalid relay URL: ${destUrl}`);
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error(`Unsupported protocol: ${parsed.protocol}`);
  }

  const fwdHeaders = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (!DROP_REQUEST_HEADERS.has(k.toLowerCase())) {
      fwdHeaders[k.toLowerCase()] = v;
    }
  }

  fwdHeaders['host'] = parsed.host;

  if (fwdHeaders['origin']) {
    fwdHeaders['origin'] = config.targetOrigin;
  }
  if (fwdHeaders['referer']) {
    try {
      const ref = new URL(fwdHeaders['referer']);
      fwdHeaders['referer'] = config.targetOrigin + ref.pathname + ref.search;
    } catch {
      fwdHeaders['referer'] = config.targetOrigin + '/';
    }
  } else {
    fwdHeaders['referer'] = config.targetOrigin + '/';
  }

  // Use the jar + incoming client cookies — same session across all domains
  const jarCookies = getCookieString(req.sessionId, req.headers['cookie']);
  if (jarCookies) fwdHeaders['cookie'] = jarCookies;

  const response = await axios({
    method      : req.method.toLowerCase(),
    url         : destUrl,
    headers     : fwdHeaders,
    data        : (req.rawBody && req.rawBody.length > 0) ? req.rawBody : undefined,
    responseType: 'arraybuffer',
    decompress  : true,
    maxRedirects: 5,
    validateStatus: () => true,
    timeout     : 30_000,
  });

  // Ingest cookies from external responses too
  const setCookie = response.headers['set-cookie'];
  if (setCookie) {
    ingestResponseCookies(req.sessionId, setCookie);
  }

  return response;
}

module.exports = { handleRelay };
