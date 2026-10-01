'use strict';
const { rewriteUrl } = require('./rewriteUrl');

/**
 * Rewrites all url() references inside a CSS string.
 * Works on both full stylesheets and inline style attributes.
 *
 * Handles:
 *   url("https://example.com/img.png")
 *   url('https://example.com/img.png')
 *   url(https://example.com/img.png)
 *   @import url(...)
 *   @import "..."    ← also caught
 */
function rewriteCss(css) {
  if (!css) return css;

  // url("...") / url('...') / url(...)
  let result = css.replace(
    /url\(\s*(['"]?)([^)'"]+)\1\s*\)/gi,
    (match, quote, urlVal) => {
      const rewritten = rewriteUrl(urlVal.trim());
      return `url(${quote}${rewritten}${quote})`;
    }
  );

  // @import "..." or @import '...'  (without url())
  result = result.replace(
    /@import\s+(['"])([^'"]+)\1/gi,
    (match, quote, urlVal) => {
      const rewritten = rewriteUrl(urlVal.trim());
      return `@import ${quote}${rewritten}${quote}`;
    }
  );

  return result;
}

module.exports = { rewriteCss };
