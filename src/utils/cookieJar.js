'use strict';
const fs = require('fs');
const path = require('path');
const config = require('../config');

/**
 * Multi-session Cookie Jar
 * Stores cookies per session in a structured format (EditThisCookie compatible).
 * Seeds new sessions with initial cookies configured in .env (JSON array or standard cookie string).
 */

const SESSIONS_DIR = path.join(process.cwd(), 'traffic_logs', 'sessions');
if (!fs.existsSync(SESSIONS_DIR)) {
  fs.mkdirSync(SESSIONS_DIR, { recursive: true });
}

// In-memory store: { sessionId: { cookieName: { ...cookieProps } } }
const store = {};

/**
 * Parse seed cookies from raw input (JSON string, file path, or "name=value; name2=value2").
 */
function parseSeedCookies(rawInput) {
  if (!rawInput) return [];
  let input = String(rawInput).trim();
  if (!input) return [];

  // If input points to an existing file
  if (!input.startsWith('[') && !input.startsWith('{')) {
    const candidatePath = path.isAbsolute(input) ? input : path.join(process.cwd(), input);
    if (fs.existsSync(candidatePath)) {
      try {
        input = fs.readFileSync(candidatePath, 'utf8').trim();
      } catch (err) {
        console.error('[CookieJar] Failed to read cookie file:', candidatePath, err.message);
        return [];
      }
    }
  }

  // Attempt JSON parsing (EditThisCookie / Chrome DevTools format)
  if (input.startsWith('[') || input.startsWith('{')) {
    try {
      const parsed = JSON.parse(input);
      const list = Array.isArray(parsed) ? parsed : [parsed];
      const valid = [];
      for (const item of list) {
        if (!item || !item.name || item.value === undefined) continue;
        let domain = item.domain || ('.' + (config.targetHost || ''));
        if (domain && !domain.startsWith('.')) domain = '.' + domain;

        let expDate = typeof item.expirationDate === 'number' ? item.expirationDate : null;
        const nowSec = Date.now() / 1000;
        if (expDate && expDate < nowSec) {
          // If an exported seed cookie's expiration is in the past (e.g. temporary session cookies like wd/dpr),
          // refresh it so it is not immediately pruned.
          expDate = nowSec + (30 * 86400); // 30 days
        }

        valid.push({
          domain: domain,
          expirationDate: expDate,
          hostOnly: item.hostOnly ?? false,
          httpOnly: item.httpOnly ?? false,
          name: String(item.name).trim(),
          path: item.path || '/',
          sameSite: item.sameSite || 'no_restriction',
          secure: item.secure ?? true,
          session: item.session ?? (expDate ? false : true),
          storeId: item.storeId ?? null,
          value: String(item.value)
        });
      }
      return valid;
    } catch (e) {
      console.warn('[CookieJar] Failed to parse cookies as JSON, falling back to name=value parser:', e.message);
    }
  }

  // Fallback: parse as standard cookie header string "name=value; name2=value2"
  const cookies = [];
  const parts = input.split(';');
  for (const part of parts) {
    const eqIdx = part.indexOf('=');
    if (eqIdx === -1) continue;
    const name = part.slice(0, eqIdx).trim();
    const value = part.slice(eqIdx + 1).trim();
    if (name) {
      cookies.push({
        domain: '.' + (config.targetHost || ''),
        expirationDate: null,
        hostOnly: false,
        httpOnly: false,
        name: name,
        path: '/',
        sameSite: 'no_restriction',
        secure: true,
        session: true,
        storeId: null,
        value: value
      });
    }
  }
  return cookies;
}

/**
 * Load initial seed cookies from environment or default file.
 */
function loadSeedCookies() {
  let raw = process.env.SESSION_COOKIE || '';

  if (!raw && (process.env.SESSION_COOKIE_FILE || process.env.COOKIE_FILE)) {
    const f = process.env.SESSION_COOKIE_FILE || process.env.COOKIE_FILE;
    const p = path.isAbsolute(f) ? f : path.join(process.cwd(), f);
    if (fs.existsSync(p)) {
      try { raw = fs.readFileSync(p, 'utf8'); } catch {}
    }
  }

  if (!raw) {
    const defaultJson = path.join(process.cwd(), 'cookies.json');
    if (fs.existsSync(defaultJson)) {
      try { raw = fs.readFileSync(defaultJson, 'utf8'); } catch {}
    }
  }

  const cookies = parseSeedCookies(raw);
  if (cookies.length > 0) {
    console.log(`[CookieJar] Seeded ${cookies.length} initial cookies (${cookies.map(c => c.name).join(', ')})`);
  } else {
    console.log('[CookieJar] No seed cookies configured.');
  }
  return cookies;
}

const seedCookies = loadSeedCookies();

/**
 * Get or initialize a session jar.
 * If new session, seeds it with initial cookies.
 */
function getSessionJar(sessionId) {
  if (!sessionId) {
    const tempJar = {};
    for (const c of seedCookies) {
      tempJar[c.name] = { ...c };
    }
    return tempJar;
  }

  if (!store[sessionId]) {
    store[sessionId] = {};
    let loadedFromDisk = false;
    // Try to load from disk
    try {
      const file = path.join(SESSIONS_DIR, `${sessionId}.json`);
      if (fs.existsSync(file)) {
        const arr = JSON.parse(fs.readFileSync(file, 'utf8'));
        if (Array.isArray(arr) && arr.length > 0) {
          for (const c of arr) {
            store[sessionId][c.name] = c;
          }
          loadedFromDisk = true;
        }
      }
    } catch {}

    if (!loadedFromDisk) {
      // Seed new session with initial cookies
      for (const c of seedCookies) {
        store[sessionId][c.name] = { ...c };
      }
      saveSessionJar(sessionId);
    } else {
      // If loaded from disk, ensure any seed cookies not yet in session are seeded
      let updated = false;
      for (const c of seedCookies) {
        if (!store[sessionId][c.name]) {
          store[sessionId][c.name] = { ...c };
          updated = true;
        }
      }
      if (updated) saveSessionJar(sessionId);
    }
  }
  return store[sessionId];
}

function saveSessionJar(sessionId) {
  if (!sessionId) return;
  try {
    const arr = exportSessionCookies(sessionId);
    fs.writeFileSync(path.join(SESSIONS_DIR, `${sessionId}.json`), JSON.stringify(arr, null, 4));
  } catch {}
}

/**
 * Parse a Set-Cookie header and store it in the session jar.
 */
function storeCookie(sessionId, header) {
  if (!header || typeof header !== 'string') return;
  const jar = getSessionJar(sessionId);

  const parts = header.split(';').map(s => s.trim());
  const nameVal = parts[0];
  if (!nameVal || !nameVal.includes('=')) return;

  const eqIdx = nameVal.indexOf('=');
  const name  = nameVal.slice(0, eqIdx).trim();
  const value = nameVal.slice(eqIdx + 1).trim();

  if (!name) return;

  const cookieObj = {
    domain: config.targetHost || '',
    expirationDate: null,
    hostOnly: false,
    httpOnly: false,
    name: name,
    path: '/',
    sameSite: 'no_restriction',
    secure: false,
    session: true,
    storeId: null,
    value: value
  };

  for (const part of parts.slice(1)) {
    const lower = part.toLowerCase();
    if (lower.startsWith('expires=')) {
      try { 
        const d = new Date(part.slice(8));
        cookieObj.expirationDate = d.getTime() / 1000;
        cookieObj.session = false;
      } catch {}
    } else if (lower.startsWith('max-age=')) {
      const maxAge = parseInt(part.slice(8), 10);
      if (maxAge <= 0) {
        delete jar[name];
        saveSessionJar(sessionId);
        return;
      }
      cookieObj.expirationDate = (Date.now() / 1000) + maxAge;
      cookieObj.session = false;
    } else if (lower === 'httponly') {
      cookieObj.httpOnly = true;
    } else if (lower === 'secure') {
      cookieObj.secure = true;
    } else if (lower.startsWith('path=')) {
      cookieObj.path = part.slice(5);
    } else if (lower.startsWith('domain=')) {
      cookieObj.domain = part.slice(7);
    } else if (lower.startsWith('samesite=')) {
      cookieObj.sameSite = lower.slice(9);
    }
  }

  // Ensure domain starts with dot for EditThisCookie compatibility if it's a root domain
  if (cookieObj.domain && !cookieObj.domain.startsWith('.')) {
    cookieObj.domain = '.' + cookieObj.domain;
  }

  jar[name] = cookieObj;
  saveSessionJar(sessionId);
}

function ingestResponseCookies(sessionId, setCookieHeaders) {
  if (!sessionId || !setCookieHeaders) return;
  const list = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
  for (const h of list) {
    storeCookie(sessionId, h);
  }
}

function ingestCookieHeader(sessionId, cookieHeader) {
  if (!sessionId || !cookieHeader || typeof cookieHeader !== 'string') return;
  const jar = getSessionJar(sessionId);
  let changed = false;

  const pairs = cookieHeader.split(';');
  for (const pair of pairs) {
    const eqIdx = pair.indexOf('=');
    if (eqIdx === -1) continue;
    const name = pair.slice(0, eqIdx).trim();
    const value = pair.slice(eqIdx + 1).trim();
    if (name && name !== '__proxy_session') {
      if (!jar[name] || value !== jar[name].value) {
        if (!jar[name]) {
          jar[name] = {
            domain: '.' + (config.targetHost || ''),
            expirationDate: null,
            hostOnly: false,
            httpOnly: false,
            name: name,
            path: '/',
            sameSite: 'unspecified',
            secure: false,
            session: true,
            storeId: null,
            value: value
          };
        } else {
          jar[name].value = value;
        }
        changed = true;
      }
    }
  }
  if (changed) saveSessionJar(sessionId);
}

function getCookieString(sessionId, clientCookieHeader) {
  if (!sessionId) {
    return seedCookies.map(c => `${c.name}=${c.value}`).join('; ');
  }
  if (clientCookieHeader) {
    ingestCookieHeader(sessionId, clientCookieHeader);
  }

  const jar = getSessionJar(sessionId);
  const now = Date.now() / 1000;
  const parts = [];
  
  let changed = false;
  for (const [name, cookieObj] of Object.entries(jar)) {
    if (cookieObj.expirationDate && cookieObj.expirationDate < now) {
      delete jar[name];
      changed = true;
      continue;
    }
    parts.push(`${name}=${cookieObj.value}`);
  }
  
  if (changed) saveSessionJar(sessionId);
  return parts.join('; ');
}

function exportSessionCookies(sessionId) {
  const jar = getSessionJar(sessionId);
  return Object.values(jar);
}

module.exports = {
  ingestResponseCookies,
  ingestCookieHeader,
  getCookieString,
  exportSessionCookies,
  loadSeedCookies,
  getSeedCookies: () => seedCookies
};
