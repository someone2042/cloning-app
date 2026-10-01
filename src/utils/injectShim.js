'use strict';

// No `defer` — the shim must execute synchronously, BEFORE any of the page's
// own scripts, so that our fetch/XHR patches are in place when they run.
// We inject into <head> as the FIRST child so nothing slips past us.
const SHIM_SCRIPT = '<script src="/__proxy_shim__/proxy.js"></script>\n<script src="/__proxy_shim__/inputMonitor.js" defer></script>';

/**
 * Injects the proxy shim <script> tag into an HTML document.
 *
 * Injection strategy (ordered by preference):
 *   1. As the very first child of <head>  — BEST: beats all other scripts
 *   2. Before </head>                     — good fallback
 *   3. Before </body>                     — last resort
 *   4. Appended at end                    — malformed HTML fallback
 *
 * Idempotent: skips if already present.
 */
function injectShim(html) {
  if (!html) return html;

  // Already injected — skip
  if (html.includes('/__proxy_shim__/proxy.js')) return html;

  // 1. Inject immediately after opening <head> tag so we run first
  if (/<head(\s[^>]*)?>/i.test(html)) {
    return html.replace(/<head(\s[^>]*)?>/i, (match) => `${match}\n${SHIM_SCRIPT}`);
  }

  // 2. Before </head>
  if (/<\/head>/i.test(html)) {
    return html.replace(/<\/head>/i, `${SHIM_SCRIPT}\n</head>`);
  }

  // 3. Before </body>
  if (/<\/body>/i.test(html)) {
    return html.replace(/<\/body>/i, `${SHIM_SCRIPT}\n</body>`);
  }

  // 4. Append at end (malformed HTML)
  return html + '\n' + SHIM_SCRIPT;
}

module.exports = { injectShim };
