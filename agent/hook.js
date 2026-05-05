#!/usr/bin/env node
/**
 * EHZ-SEC-AI — Claude Code Hook
 * PreToolUse / PostToolUse / ConfigChange interceptor
 *
 * Iron rule: always returns continue: true — never blocks.
 * Monitor and alert only.
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

  // Extract cwd from Claude Code event for project root auto-detection
  const cwd = event.cwd || process.cwd();

  const payload = {
    ts:               Date.now(),
    hook_type:        hookType,
    tool_name:        tool,
    session_id:       session,
    cwd,
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

  // Real-time Write Guard (MS6.8) — scan full file content after Write/Edit
  if (['Write', 'Edit', 'NotebookEdit'].includes(tool) && hookType === 'PostToolUse') {
    try {
      const filePath = (event.tool_input || {}).file_path || (event.tool_input || {}).path || '';
      if (filePath && fs.existsSync(filePath)) {
        const stat = fs.statSync(filePath);
        if (stat.size > 2 * 1024 * 1024) { /* skip files > 2MB */ } else {
        const content = fs.readFileSync(filePath, 'utf8');
        let writeMatch = null;
        // Run SECRETS_RULES on full file content
        const secretsRules = [
          { level: 'CRITICAL', re: /sk-[A-Za-z0-9]{48}/, reason: 'OpenAI API key in file' },
          { level: 'CRITICAL', re: /sk-ant-[A-Za-z0-9\-_]{40,}/, reason: 'Anthropic API key in file' },
          { level: 'CRITICAL', re: /AKIA[0-9A-Z]{16}/, reason: 'AWS Access Key in file' },
          { level: 'CRITICAL', re: /-----BEGIN\s+(RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY/i, reason: 'Private key in file' },
          { level: 'HIGH', re: /password\s*[=:]\s*\S{6,}/i, reason: 'Hardcoded password in file' },
          { level: 'HIGH', re: /secret\s*[=:]\s*\S{6,}/i, reason: 'Hardcoded secret in file' },
          { level: 'HIGH', re: /api[_-]?key\s*[=:]\s*\S{6,}/i, reason: 'Hardcoded API key in file' },
          { level: 'HIGH', re: /ghp_[A-Za-z0-9]{36}/, reason: 'GitHub Token in file' },
          { level: 'HIGH', re: /\b4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b/, reason: 'Credit card number (Visa) in file' },
        ];
        for (const rule of secretsRules) {
          if (rule.re.test(content)) {
            writeMatch = { level: rule.level, reason: `🛡️ Write Guard: ${rule.reason} — ${filePath}`, ruleType: 'write-guard' };
            break;
          }
        }
        if (writeMatch) {
          sendToCollector({
            ts:            Date.now(),
            hook_type:     'WriteGuard',
            tool_name:     tool,
            session_id:    session,
            level:         writeMatch.level,
            reason:        writeMatch.reason,
            rule_type:     'write-guard',
            hardening_level: hardeningLevel,
            input_summary: filePath,
          });
          log(`[WRITE-GUARD] ${writeMatch.level} — ${writeMatch.reason}`);
        }
      } // end size check
      }
    } catch(e) { log(`write-guard error: ${e.message}`); }
  }

  // Auto-discover domains from WebSearch results (MS6.13)
  if (tool === 'WebSearch' && hookType === 'PostToolUse') {
    try {
      const responseText = JSON.stringify(event.tool_response || '');
      const urlRe = /https?:\/\/([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}/g;
      const matches = responseText.match(urlRe) || [];
      const domains = [...new Set(matches.map(u => {
        try { return new URL(u).hostname.toLowerCase(); } catch(_) { return null; }
      }).filter(Boolean))];
      if (domains.length > 0) {
        const body = JSON.stringify({ domains });
        const req2 = http.request('http://localhost:3010/domains/autodiscover', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
          timeout: 3000,
        });
        req2.on('error', () => {});
        req2.write(body);
        req2.end();
        log(`[AutoDiscover] ${domains.length} domains from WebSearch`);
      }
    } catch(e) { log(`autodiscover error: ${e.message}`); }
  }

  log(`[${level}] ${hookType} → ${tool}${reason ? ' | ' + reason : ''}`);

  process.stdout.write(JSON.stringify(response));
}

main().catch((e) => {
  log(`hook fatal: ${e.message}`);
  process.stdout.write(JSON.stringify({ continue: true }));
});
