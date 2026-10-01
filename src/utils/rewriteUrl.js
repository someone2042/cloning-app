'use strict';
const config = require('../config');

const baseDomain = config.targetHost.replace(/^www\./, '');

function isTargetHost(host) {
  if (!host) return false;
  return host === config.targetHost ||
         host === 'www.' + baseDomain ||
         host === baseDomain;
}

/**
 * Rewrites a single URL so it routes through our proxy instead of
 * going directly to the target (or an external CDN).
 *
 * Rules:
 *  - Special schemes (data:, blob:, javascript:, mailto:, tel:, #) → unchanged
 *  - Proxy internal paths (/__relay__, /__ext__, etc.) → unchanged
 *  - Target domain and its www/base aliases → relative path on proxy
 *  - Any other external URL → /__ext__?url=<encoded>
 *  - Relative URL → unchanged
 */
function rewriteUrl(url) {
  if (!url) return url;
  const t = url.trim();

  // ── Skip special schemes ────────────────────────────────
  if (
    t === '' ||
    t.startsWith('data:')       ||
    t.startsWith('blob:')       ||
    t.startsWith('javascript:') ||
    t.startsWith('mailto:')     ||
    t.startsWith('tel:')        ||
    t.startsWith('#')
  ) {
    return url;
  }

  // ── Skip already proxied routes ─────────────────────────
  if (
    t.startsWith('/__relay__') ||
    t.startsWith('/__ext__')   ||
    t.startsWith('/__proxy_shim__')
  ) {
    return url;
  }

  // ── Absolute / protocol-relative URL ─────────────────────
  if (/^https?:\/\//i.test(t) || t.startsWith('//')) {
    try {
      const parsed = new URL(t.startsWith('//') ? ('https:' + t) : t);
      if (isTargetHost(parsed.host)) {
        return (parsed.pathname || '/') + parsed.search + parsed.hash;
      }
      return '/__ext__?url=' + encodeURIComponent(parsed.href);
    } catch {
      return url;
    }
  }

  // ── Relative URL — already points to our proxy ──────────
  return url;
}

module.exports = { rewriteUrl, isTargetHost };
