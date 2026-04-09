#!/usr/bin/env node
/**
 * EHZ-SEC-AI — Claude Code Hook
 * PreToolUse / PostToolUse / ConfigChange interceptor
 *
 * עקרון ברזל: תמיד מחזיר continue: true — לעולם לא חוסם בשלב א
 * רק מנטר ומתריע.
 *
 * stdin (JSON) → rules.js → sendToCollector() [async fire-and-forget]
 */

'use strict';

const http = require('http');
const fs   = require('fs');
const path = require('path');

// ─── Config ─────────────────────────────────────────────────────────────────

const COLLECTOR_URL = 'http://localhost:3010/event';
const PROJECT_DIR   = path.resolve(__dirname, '..');
const DISABLE_FILE  = path.join(PROJECT_DIR, '.ccsm-disable');
const LOG_FILE      = path.join(PROJECT_DIR, 'logs', 'hook.log');

// ─── Rules + Hardening (Milestones 2 + 4) ───────────────────────────────────

let checkRules;
try { checkRules = require('./rules').checkRules; } catch (_) { checkRules = () => null; }

let hardening;
try { hardening = require('../config/hardening'); } catch (_) { hardening = null; }

function getHardeningLevel() {
  return hardening ? hardening.getLevel() : 1;
}
function shouldSend(level) {
  return hardening ? hardening.shouldAlert(level) : ['HIGH','CRITICAL'].includes(level);
}

// ─── Utils ──────────────────────────────────────────────────────────────────

function isDisabled() {
  return fs.existsSync(DISABLE_FILE);
}

function log(msg) {
  try {
    fs.appendFileSync(LOG_FILE, `[${new Date().toISOString()}] ${msg}\n`);
  } catch (_) { /* best-effort */ }
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
  try { event = JSON.parse(raw); } catch (_) { /* ignore */ }

  // Iron rule: always continue in Phase A
  const response = { continue: true };

  if (isDisabled()) {
    process.stdout.write(JSON.stringify(response));
    return;
  }

  const hookType = event.hook_event_name || event.hook_type || 'unknown';
  const tool     = event.tool_name       || 'unknown';
  const session  = event.session_id      || 'unknown';

  // Run rules engine
  const match    = checkRules(event);
  const level    = match ? match.level    : 'INFO';
  const reason   = match ? match.reason   : null;
  const ruleType = match ? match.ruleType : null;

  const hardeningLevel = getHardeningLevel();

  const payload = {
    ts:               Date.now(),
    hook_type:        hookType,
    tool_name:        tool,
    session_id:       session,
    level,
    reason,
    rule_type:        ruleType,
    hardening_level:  hardeningLevel,
    input_summary:    JSON.stringify(event.tool_input   || {}).slice(0, 500),
    output_summary:   JSON.stringify(event.tool_response || {}).slice(0, 500),
  };

  // Always send WebSearch + WebFetch events (web monitoring) — regardless of hardening level
  const isWebEvent = ['WebSearch', 'WebFetch'].includes(tool);
  if (isWebEvent || shouldSend(level, hardeningLevel)) {
    try { sendToCollector(payload); } catch (e) { log(`send error: ${e.message}`); }
  }

  log(`[${level}] ${hookType} → ${tool}${reason ? ' | ' + reason : ''}`);

  process.stdout.write(JSON.stringify(response));
}

main().catch((e) => {
  log(`hook fatal: ${e.message}`);
  process.stdout.write(JSON.stringify({ continue: true }));
});
