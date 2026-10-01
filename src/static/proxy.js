/* ============================================================
   Proxy Shim — injected into every proxied page.
   Intercepts fetch(), XHR, history API, window.open, dynamic DOM
   elements, and Service Workers so ALL requests stay inside our proxy.

   Routing logic:
     • Target domain (and its www/root aliases) → relative path (main proxy)
     • Same origin (localhost)                 → relative path
     • Any other domain (external APIs/CDNs)   → /__relay__?url=

   NOTE: __TARGET_ORIGIN__ is replaced server-side at
   request time with the real JSON-encoded target origin.
   ============================================================ */
(function () {
  'use strict';

  const TARGET_ORIGIN = __TARGET_ORIGIN__;  // e.g. "https://www.instagram.com"
  const RELAY_PREFIX  = '/__relay__';       // all external calls go through here

  let targetHost = '';
  let baseDomain = '';
  try {
    targetHost = new URL(TARGET_ORIGIN).host;
    baseDomain = targetHost.replace(/^www\./, '');
  } catch (_) {}

  function isTargetHost(h) {
    if (!h) return false;
    return h === targetHost || h === 'www.' + baseDomain || h === baseDomain;
  }

  /* ----------------------------------------------------------
     rewriteUrl — central routing logic.
  ---------------------------------------------------------- */
  function rewriteUrl(url) {
    if (!url || typeof url !== 'string') return url;
    try {
      // 1. Skip non-rewritable schemes
      if (/^(data:|blob:|javascript:|mailto:|tel:|#)/i.test(url)) return url;

      // 2. Skip URLs already routed through our proxy (prevents loops)
      if (
        url.startsWith('/__relay__') ||
        url.startsWith('/__ext__')   ||
        url.startsWith('/__proxy_shim__')
      ) return url;

      // 3. Relative URL — already destined for our proxy server
      if (url.startsWith('/') || url.startsWith('.')) return url;

      // Resolve protocol-relative URLs
      let full = url.startsWith('//') ? (location.protocol + url) : url;

      // Must be http(s) to continue
      if (!/^https?:\/\//i.test(full)) return url;

      const parsed = new URL(full);

      // Points to our own proxy server
      if (parsed.origin === window.location.origin) {
        return parsed.pathname + parsed.search + parsed.hash;
      }

      // Points to target domain or its www/root alias
      if (isTargetHost(parsed.host)) {
        return parsed.pathname + parsed.search + parsed.hash;
      }

      // Any other external domain → relay through proxy
      return RELAY_PREFIX + '?url=' + encodeURIComponent(full);
    } catch (_) {
      return url; // parse error — leave unchanged
    }
  }

  /* ----------------------------------------------------------
     Intercept window.fetch
  ---------------------------------------------------------- */
  const _fetch = window.fetch.bind(window);

  window.fetch = function (input, init) {
    try {
      if (input instanceof Request) {
        const rewritten = rewriteUrl(input.url);
        if (rewritten !== input.url) {
          const newInit = {
            method     : input.method,
            headers    : input.headers,
            body       : input.body,
            mode       : input.mode,
            credentials: input.credentials,
            cache      : input.cache,
            redirect   : input.redirect,
            referrer   : input.referrer,
            integrity  : input.integrity,
            ...(init || {}),
          };
          input = new Request(rewritten, newInit);
          init  = undefined;
        }
      } else if (typeof input === 'string' || input instanceof URL) {
        const raw = (input instanceof URL) ? input.href : input;
        input = rewriteUrl(raw);
      }
    } catch (_) {}

    return _fetch(input, init);
  };

  /* ----------------------------------------------------------
     Intercept XMLHttpRequest.open
  ---------------------------------------------------------- */
  const _xhrOpen = XMLHttpRequest.prototype.open;

  XMLHttpRequest.prototype.open = function (method, url, async, user, pass) {
    try {
      url = rewriteUrl(String(url));
    } catch (_) {}
    return _xhrOpen.call(
      this, method, url,
      async === undefined ? true : async,
      user, pass
    );
  };

  /* ----------------------------------------------------------
     Intercept History API (SPA client-side routing)
     Ensures pushState/replaceState never rewrite routes into /__relay__
  ---------------------------------------------------------- */
  const _pushState    = history.pushState.bind(history);
  const _replaceState = history.replaceState.bind(history);

  function cleanHistoryUrl(url) {
    if (!url) return url;
    if (typeof url === 'string' && (url.startsWith('/') || url.startsWith('.'))) {
      return url;
    }
    try {
      const u = new URL(url, window.location.href);
      if (isTargetHost(u.hostname) || u.origin === window.location.origin) {
        return u.pathname + u.search + u.hash;
      }
    } catch (_) {}
    return url;
  }

  history.pushState = function (state, title, url) {
    try { url = cleanHistoryUrl(url); } catch (_) {}
    return _pushState(state, title, url);
  };

  history.replaceState = function (state, title, url) {
    try { url = cleanHistoryUrl(url); } catch (_) {}
    return _replaceState(state, title, url);
  };

  /* ----------------------------------------------------------
     Intercept window.open (popups / new tabs)
  ---------------------------------------------------------- */
  const _windowOpen = window.open.bind(window);

  window.open = function (url, target, features) {
    try { if (url) url = rewriteUrl(String(url)); } catch (_) {}
    return _windowOpen(url, target, features);
  };

  /* ----------------------------------------------------------
     Block Service Worker registration
  ---------------------------------------------------------- */
  if ('serviceWorker' in navigator) {
    try {
      Object.defineProperty(navigator, 'serviceWorker', {
        get () {
          return {
            register        : () => Promise.reject(new Error('[Proxy] SW blocked')),
            getRegistrations: () => Promise.resolve([]),
            ready           : Promise.resolve(null),
          };
        },
        configurable: true,
      });
    } catch (_) {
      navigator.serviceWorker.register = () =>
        Promise.reject(new Error('[Proxy] SW blocked'));
    }
  }

  /* ----------------------------------------------------------
     Intercept DOM dynamic elements (scripts, links, iframes)
  ---------------------------------------------------------- */
  const _setAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (name, value) {
    if (name && (name.toLowerCase() === 'src' || name.toLowerCase() === 'href') && value) {
      try { value = rewriteUrl(String(value)); } catch (_) {}
    }
    return _setAttribute.call(this, name, value);
  };

  function interceptProperty(prototype, property) {
    const descriptor = Object.getOwnPropertyDescriptor(prototype, property);
    if (!descriptor || !descriptor.set) return;
    Object.defineProperty(prototype, property, {
      configurable: true,
      enumerable: true,
      get: descriptor.get,
      set: function (val) {
        let rewritten = val;
        try { if (val) rewritten = rewriteUrl(String(val)); } catch (_) {}
        descriptor.set.call(this, rewritten);
      }
    });
  }

  if (window.HTMLScriptElement) interceptProperty(HTMLScriptElement.prototype, 'src');
  if (window.HTMLLinkElement) interceptProperty(HTMLLinkElement.prototype, 'href');
  if (window.HTMLImageElement) interceptProperty(HTMLImageElement.prototype, 'src');
  if (window.HTMLIFrameElement) interceptProperty(HTMLIFrameElement.prototype, 'src');

  /* ----------------------------------------------------------
     Debug banner
  ---------------------------------------------------------- */
  console.log(
    '%c[Proxy Shim]%c Active — Target: ' + TARGET_ORIGIN + ' (Host: ' + targetHost + ')',
    'color:#4ade80;font-weight:bold', 'color:inherit'
  );

})();
