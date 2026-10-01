'use strict';
const axios  = require('axios');
const config = require('../config');
const { getCookieString, ingestResponseCookies } = require('./cookieJar');

// Hop-by-hop headers that must never be forwarded upstream
const DROP_REQUEST_HEADERS = new Set([
  'host', 'connection', 'transfer-encoding',
  'upgrade', 'proxy-authorization', 'te', 'trailers', 'keep-alive',
]);

/**
 * Fetch a resource from the configured target domain.
 * Cookies are handled automatically by the server-side cookie jar:
 *   - Jar cookies are sent with every request
 *   - Set-Cookie headers in the response are ingested into the jar
 *
 * @param {string} targetPath  - Absolute path on the target (e.g. "/api/v1/users")
 * @param {object} opts
 *   @param {string}      opts.method      - HTTP method (default: 'GET')
 *   @param {object}      opts.headers     - Incoming request headers (sanitised)
 *   @param {Buffer|null} opts.body        - Raw request body (null for GET/HEAD)
 *   @param {string}      opts.queryString - Raw query string without leading '?'
 * @returns {Promise<axios.AxiosResponse>}
 */
async function fetchTarget(targetPath, opts = {}) {
  const {
    method      = 'GET',
    headers     = {},
    body        = null,
    queryString = '',
    sessionId   = null,
  } = opts;

  const url = config.targetOrigin + targetPath + (queryString ? '?' + queryString : '');

  // ── Sanitise & build request headers ──────────────────────────────────────
  const fwdHeaders = {};
  for (const [k, v] of Object.entries(headers)) {
    if (!DROP_REQUEST_HEADERS.has(k.toLowerCase())) {
      fwdHeaders[k.toLowerCase()] = v;
    }
  }

  // Set correct Host for the target
  fwdHeaders['host'] = config.targetHost;

  // Cookie = jar + incoming browser cookies merged
  const jarCookies = getCookieString(sessionId, headers['cookie']);
  if (jarCookies) {
    fwdHeaders['cookie'] = jarCookies;
  }

  // Rewrite Origin / Referer so the target sees its own domain, not localhost
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
  }

  // ── Fire the upstream request ──────────────────────────────────────────────
  const response = await axios({
    method      : method.toLowerCase(),
    url,
    headers     : fwdHeaders,
    data        : (body && body.length > 0) ? body : undefined,
    responseType: 'arraybuffer',  // always receive raw bytes
    decompress  : true,           // auto-decompress gzip/deflate/br
    maxRedirects: 0,              // redirects are handled in mainProxy.js
    validateStatus: () => true,  // never throw on HTTP error codes
    timeout     : 30_000,
  });

  // ── Ingest any new cookies from the response into our jar ─────────────────
  const setCookie = response.headers['set-cookie'];
  if (setCookie) {
    ingestResponseCookies(sessionId, setCookie);
  }

  return response;
}

module.exports = { fetchTarget };
