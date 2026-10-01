'use strict';
const axios  = require('axios');
const config = require('../config');
const { recordEntry } = require('../utils/harLogger');

const DROP_RESPONSE_HEADERS = new Set([
  'content-security-policy',
  'content-security-policy-report-only',
  'x-frame-options',
  'strict-transport-security',
  'transfer-encoding',
  'content-encoding',
]);

/**
 * External resource handler — proxies third-party CDN assets
 * (fonts, analytics scripts, images, etc.) so the browser can
 * load them without leaving our proxy context.
 *
 * Route: GET /__ext__?url=https://cdn.example.com/file.js
 */
async function handleExternal(req, res) {
  const _startTime = Date.now();
  req._proxyHandler = 'external';
  const rawUrl = req.query.url;

  if (!rawUrl) {
    return res.status(400).send('Missing ?url= parameter');
  }

  // Validate URL
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return res.status(400).send('Invalid URL');
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return res.status(400).send('Only http/https URLs are allowed');
  }

  try {
    const upstream = await axios({
      method      : 'GET',
      url         : rawUrl,
      responseType: 'arraybuffer',
      decompress  : true,
      maxRedirects: 5,
      validateStatus: () => true,
      timeout     : 15_000,
      headers: {
        'User-Agent'     : req.headers['user-agent'] || 'Mozilla/5.0',
        'Accept'         : req.headers['accept'] || '*/*',
        'Accept-Language': req.headers['accept-language'] || 'en-US,en;q=0.9',
        // Pretend we come from the target site (some CDNs check Referer)
        'Referer'        : config.targetOrigin + '/',
      },
    });

    const outHeaders = {};
    for (const [k, v] of Object.entries(upstream.headers)) {
      if (!DROP_RESPONSE_HEADERS.has(k.toLowerCase())) {
        outHeaders[k] = v;
      }
    }
    outHeaders['access-control-allow-origin'] = '*';

    // Cache external assets aggressively — they are immutable CDN files
    if (!outHeaders['cache-control']) {
      outHeaders['cache-control'] = 'public, max-age=86400';
    }

    res.status(upstream.status);
    for (const [k, v] of Object.entries(outHeaders)) {
      try { res.setHeader(k, v); } catch {}
    }

    recordEntry(req, res, upstream, Date.now() - _startTime);
    return res.send(Buffer.from(upstream.data));

  } catch (err) {
    console.error('[External] Failed to fetch:', rawUrl, '-', err.message);
    return res.status(502).send('Failed to fetch external resource');
  }
}

module.exports = { handleExternal };
