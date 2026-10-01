'use strict';
require('dotenv').config();

function required(name) {
  const val = process.env[name];
  if (!val) {
    console.error(`[Config] FATAL: "${name}" is required in .env`);
    process.exit(1);
  }
  return val;
}

const rawTarget = required('TARGET_DOMAIN').trim().replace(/\/$/, '');

let targetOrigin, targetHost;
try {
  const parsed = new URL(rawTarget);
  targetOrigin = parsed.origin;
  targetHost   = parsed.host;
} catch {
  console.error(`[Config] FATAL: TARGET_DOMAIN "${rawTarget}" is not a valid URL`);
  process.exit(1);
}

const config = {
  targetDomain : rawTarget,
  targetOrigin,                                      // e.g. https://app.example.com
  targetHost,                                        // e.g. app.example.com
  sessionCookie: process.env.SESSION_COOKIE || '',   // injected into every upstream request
  port         : parseInt(process.env.PORT || '3000', 10),
};

console.log('[Config] ─────────────────────────────────');
console.log(`[Config]   Target  : ${config.targetOrigin}`);
console.log(`[Config]   Port    : ${config.port}`);
console.log(`[Config]   Cookie  : ${config.sessionCookie ? '[set]' : '[not set]'}`);
console.log('[Config] ─────────────────────────────────');

module.exports = config;
