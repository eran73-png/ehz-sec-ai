#!/usr/bin/env node
/**
 * EHZ-SEC-AI — Claude Code Hook
 * PreToolUse / PostToolUse / ConfigChange interceptor
 *
 * עקרון ברזל: תמיד מחזיר continue: true — לעולם לא חוסם בשלב א
 * רק מנטר ומתריע.
 *
 * קריאה מ-stdin (JSON) → checkLocalRules() → sendToCollector() [async]
 */

'use strict';

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');

// ─── Config ────────────────────────────────────────────────────────────────

const COLLECTOR_URL = 'http://localhost:3010/event';
const PROJECT_DIR   = path.resolve(__dirname, '..');
const DISABLE_FILE  = path.join(PROJECT_DIR, '.ccsm-disable');
const LOG_FILE      = path.join(PROJECT_DIR, 'logs', 'hook.log');

// ─── Utils ──────────────────────────────────────────────────────────────────

function isDisabled() {
  return fs.existsSync(DISABLE_FILE);
}

function log(msg) {
  try {
    const ts  = new Date().toISOString();
    const line = `[${ts}] ${msg}\n`;
    fs.appendFileSync(LOG_FILE, line);
  } catch (_) { /* best-effort */ }
}

// ─── Local Quick Rules (before sending to collector) ──────────────────────
// Returns { level, reason } or null

function checkLocalRules(event) {
  const tool  = event.tool_name || '';
  const input = JSON.stringify(event.tool_input || {}).toLowerCase();

  // Signature rules — CRITICAL
  const criticalPatterns = [
    { re: /curl[^|]*\|[^|]*sh/,         reason: 'curl|sh — pipe to shell' },
    { re: /wget[^|]*\|[^|]*sh/,         reason: 'wget|sh — pipe to shell' },
    { re: /rm\s+-rf\s+\//,              reason: 'rm -rf / — recursive delete root' },
    { re: /base64\s+-d.*\|.*sh/,        reason: 'base64 decode pipe to shell' },
    { re: /\/etc\/passwd/,              reason: 'access to /etc/passwd' },
    { re: /\/etc\/shadow/,              reason: 'access to /etc/shadow' },
    { re: /ncat|netcat|nc\s+-[le]/,     reason: 'netcat listener' },
    { re: /meterpreter|metasploit/,     reason: 'metasploit reference' },
    { re: /powershell.*\-enc\s+[a-z0-9+/]{20,}/i, reason: 'encoded PowerShell payload' },
  ];

  // HIGH
  const highPatterns = [
    { re: /ngrok/,                      reason: 'ngrok tunnel' },
    { re: /\.onion/,                    reason: 'TOR .onion address' },
    { re: /password\s*=/i,              reason: 'hardcoded password' },
    { re: /api[_-]?key\s*=/i,          reason: 'hardcoded API key' },
    { re: /secret\s*=/i,               reason: 'hardcoded secret' },
    { re: /AKIA[0-9A-Z]{16}/,          reason: 'AWS Access Key' },
    { re: /BEGIN\s+(RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY/, reason: 'Private key in content' },
  ];

  // Context rules — sensitive paths
  const sensitivePaths = ['.ssh', '.gnupg', '/etc/', 'id_rsa', 'id_ed25519', '.aws/credentials'];

  for (const p of criticalPatterns) {
    if (p.re.test(input)) return { level: 'CRITICAL', reason: p.reason };
  }
  for (const p of highPatterns) {
    if (p.re.test(input)) return { level: 'HIGH', reason: p.reason };
  }

  // Sensitive path on Write/Edit
  if (['Write', 'Edit'].includes(tool)) {
    for (const sp of sensitivePaths) {
      if (input.includes(sp.toLowerCase())) {
        return { level: 'HIGH', reason: `Write to sensitive path: ${sp}` };
      }
    }
  }

  return null;
}

// ─── Send to Collector ──────────────────────────────────────────────────────

function sendToCollector(payload) {
  const body = JSON.stringify(payload);
  const req  = http.request(COLLECTOR_URL, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    timeout: 3000,
  });
  req.on('error', (e) => log(`collector error: ${e.message}`));
  req.write(body);
  req.end();
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  let raw = '';
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) raw += chunk;

  let event = {};
  try { event = JSON.parse(raw); } catch (_) { /* ignore parse error */ }

  // Always continue — iron rule for Phase A
  const response = { continue: true };

  if (isDisabled()) {
    process.stdout.write(JSON.stringify(response));
    return;
  }

  const hookType = event.hook_type || 'unknown';
  const tool     = event.tool_name || 'unknown';
  const session  = event.session_id || 'unknown';
  const ts       = Date.now();

  // Check local rules for quick classification
  const match = checkLocalRules(event);
  const level = match ? match.level : 'INFO';
  const reason = match ? match.reason : null;

  // Build collector payload
  const payload = {
    ts,
    hook_type:  hookType,
    tool_name:  tool,
    session_id: session,
    level,
    reason,
    input_summary: JSON.stringify(event.tool_input || {}).slice(0, 500),
    output_summary: JSON.stringify(event.tool_response || {}).slice(0, 500),
  };

  // Fire-and-forget to collector
  try { sendToCollector(payload); } catch (e) { log(`send error: ${e.message}`); }

  log(`[${level}] ${hookType} → ${tool}${reason ? ' | ' + reason : ''}`);

  process.stdout.write(JSON.stringify(response));
}

main().catch((e) => {
  log(`hook fatal: ${e.message}`);
  process.stdout.write(JSON.stringify({ continue: true }));
});
