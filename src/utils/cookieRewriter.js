'use strict';

/**
 * Rewrites Set-Cookie headers received from the target so the browser
 * stores them under our proxy domain (localhost / internal host), not
 * under the target's domain.
 *
 * Key transforms:
 *  1. Remove Domain=   → browser scopes cookie to our host automatically
 *  2. Remove Secure    → required on plain HTTP (dev); set PROXY_HTTPS=true to keep it
 *  3. SameSite=None    → downgrade to Lax  (None requires Secure; without it browser rejects)
 *  4. SameSite=Strict  → downgrade to Lax  (we are cross-site relative to the target)
 *
 * Result: the browser will store the cookies and send them back to our proxy
 * on subsequent requests, which we then forward to the target.
 */
function rewriteSetCookieHeaders(cookies) {
  if (!cookies) return [];
  const list      = Array.isArray(cookies) ? cookies : [cookies];
  const keepSecure = process.env.PROXY_HTTPS === 'true';

  return list.map(cookie => {
    let c = cookie;

    // 1. Remove Domain scoping — let browser default to our host
    c = c.replace(/;\s*Domain=[^;]*/gi, '');

    if (keepSecure) {
      // HTTPS mode: only fix SameSite=Strict → Lax, keep Secure
      c = c.replace(/;\s*SameSite=Strict/gi, '; SameSite=Lax');
    } else {
      // HTTP mode (dev): must remove Secure flag.
      // SameSite=None REQUIRES Secure — without Secure, browser rejects the cookie.
      // So downgrade SameSite=None → Lax as well.
      c = c.replace(/;\s*Secure/gi, '');
      c = c.replace(/;\s*SameSite=None/gi,   '; SameSite=Lax');
      c = c.replace(/;\s*SameSite=Strict/gi, '; SameSite=Lax');
    }

    return c;
  });
}

module.exports = { rewriteSetCookieHeaders };

