'use strict';
const cheerio  = require('cheerio');
const { rewriteUrl } = require('./rewriteUrl');
const { rewriteCss } = require('./rewriteCss');

// Attributes that hold a single URL
const SINGLE_URL_ATTRS = [
  'href', 'src', 'action', 'poster',
  'data',       // <object data="...">
  'ping',       // <a ping="...">
  'formaction', // <button formaction="...">
];

// Common lazy-load / custom data attributes
const LAZY_ATTRS = [
  'data-src', 'data-href', 'data-lazy',
  'data-original', 'data-url', 'data-bg',
];

/**
 * Parse HTML with cheerio and rewrite every URL so that all
 * resources and links are routed through our proxy.
 */
function rewriteHtml(html) {
  if (!html) return html;

  const $ = cheerio.load(html, { decodeEntities: false });

  // ── <base> — rewrite or strip ──────────────────────────────────────────────
  $('base[href]').each((_, el) => {
    const href = $(el).attr('href');
    if (href) $(el).attr('href', rewriteUrl(href));
  });

  // ── Single-URL attributes ──────────────────────────────────────────────────
  SINGLE_URL_ATTRS.forEach(attr => {
    $(`[${attr}]`).each((_, el) => {
      const val = $(el).attr(attr);
      if (val) $(el).attr(attr, rewriteUrl(val));
    });
  });

  // ── Lazy-load data-* attributes ────────────────────────────────────────────
  LAZY_ATTRS.forEach(attr => {
    $(`[${attr}]`).each((_, el) => {
      const val = $(el).attr(attr);
      if (val) $(el).attr(attr, rewriteUrl(val));
    });
  });

  // ── srcset  (format: "url descriptor, url descriptor, …") ─────────────────
  $('[srcset]').each((_, el) => {
    const srcset = $(el).attr('srcset');
    if (!srcset) return;
    const rewritten = srcset
      .split(',')
      .map(part => {
        const trimmed = part.trim();
        const spaceIdx = trimmed.search(/\s/);
        if (spaceIdx === -1) return rewriteUrl(trimmed);
        return rewriteUrl(trimmed.slice(0, spaceIdx)) + trimmed.slice(spaceIdx);
      })
      .join(', ');
    $(el).attr('srcset', rewritten);
  });

  // ── Inline style="" attributes ─────────────────────────────────────────────
  $('[style]').each((_, el) => {
    const style = $(el).attr('style');
    if (style) $(el).attr('style', rewriteCss(style));
  });

  // ── <style> tag contents ───────────────────────────────────────────────────
  $('style').each((_, el) => {
    const content = $(el).html();
    if (content) $(el).html(rewriteCss(content));
  });

  // ── <meta http-equiv="refresh" content="N; url=..."> ──────────────────────
  $('meta[http-equiv="refresh" i]').each((_, el) => {
    const content = $(el).attr('content');
    if (!content) return;
    const rewritten = content.replace(
      /(;\s*url=)(.*)/i,
      (_, prefix, url) => prefix + rewriteUrl(url.trim())
    );
    $(el).attr('content', rewritten);
  });

  return $.html();
}

module.exports = { rewriteHtml };
