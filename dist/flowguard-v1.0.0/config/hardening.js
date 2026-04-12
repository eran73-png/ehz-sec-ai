'use strict';
/**
 * EHZ-SEC-AI — Hardening Levels
 * Milestone 4
 *
 * Level 0 — OFF:       ניטור בלבד, אפס הגבלות, אין alerts
 * Level 1 — SOFT:      התראות בלבד (מצב ברירת מחדל)
 * Level 2 — STRICT:    חוקים מחמירים, חסימת TLDs חשודים, הרחבת patterns
 * Level 3 — LOCKDOWN:  התראה על כל פעולה, כולל INFO
 */

const fs   = require('fs');
const path = require('path');

const CONFIG_FILE = path.join(__dirname, 'project-scope.json');

// ─── Level Definitions ───────────────────────────────────────────────────────

const LEVELS = {
  0: {
    name:        'OFF',
    emoji:       '⚫',
    description: 'ניטור בלבד — ללא התראות',
    telegram_min_level: null,        // לא שולח כלום
    extra_patterns:     false,       // ללא patterns נוספים
    alert_on_info:      false,
  },
  1: {
    name:        'SOFT',
    emoji:       '🟢',
    description: 'התראות HIGH + CRITICAL בלבד',
    telegram_min_level: 'HIGH',
    extra_patterns:     false,
    alert_on_info:      false,
  },
  2: {
    name:        'STRICT',
    emoji:       '🟡',
    description: 'חוקים מחמירים + חסימת TLDs + patterns נוספים',
    telegram_min_level: 'HIGH',
    extra_patterns:     true,        // patterns נוספים ב-rules.js
    alert_on_info:      false,
    extra_rules: [
      { level: 'HIGH', re: /pastebin\.com|hastebin\.com/i,      reason: 'Pastebin — potential data exfil' },
      { level: 'HIGH', re: /discord\.gg|t\.me\/joinchat/i,      reason: 'External messaging link' },
      { level: 'HIGH', re: /\btelnet\s+/i,                       reason: 'Telnet (cleartext protocol)' },
      { level: 'HIGH', re: /ftp:\/\//i,                          reason: 'FTP (cleartext protocol)' },
      { level: 'HIGH', re: /chmod\s+[0-7]*7[0-7]{2}/i,          reason: 'chmod world-writable' },
      { level: 'HIGH', re: /sudo\s+/i,                           reason: 'sudo command (STRICT mode)' },
      { level: 'CRITICAL', re: /\/dev\/tcp\//i,                  reason: 'Bash TCP redirect (reverse shell)' },
      { level: 'CRITICAL', re: /exec\s+[0-9]+<>\/dev\/tcp/i,    reason: 'Bash TCP socket' },
    ],
  },
  3: {
    name:        'LOCKDOWN',
    emoji:       '🔴',
    description: 'התראה על כל פעולה כולל INFO',
    telegram_min_level: 'INFO',
    extra_patterns:     true,
    alert_on_info:      true,
  },
};

// ─── Read / Write config ─────────────────────────────────────────────────────

function readConfig() {
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    }
  } catch (_) {}
  return { hardening_level: 1 };
}

function writeConfig(cfg) {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2), 'utf8');
}

// ─── Public API ──────────────────────────────────────────────────────────────

function getLevel() {
  const cfg = readConfig();
  const lvl = parseInt(cfg.hardening_level ?? 1);
  return Math.min(3, Math.max(0, lvl));
}

function setLevel(n) {
  const lvl = Math.min(3, Math.max(0, parseInt(n)));
  const cfg = readConfig();
  cfg.hardening_level = lvl;
  cfg.updated_at = new Date().toISOString();
  writeConfig(cfg);
  return lvl;
}

function getLevelConfig(n) {
  const lvl = n ?? getLevel();
  return { level: lvl, ...LEVELS[lvl] };
}

function shouldAlert(eventLevel, hardeningLevel) {
  const h = hardeningLevel ?? getLevel();
  if (h === 0) return false;
  const cfg = LEVELS[h];
  if (!cfg.telegram_min_level) return false;
  const ORDER = ['INFO', 'MEDIUM', 'HIGH', 'CRITICAL'];
  return ORDER.indexOf(eventLevel) >= ORDER.indexOf(cfg.telegram_min_level);
}

function getExtraRules(hardeningLevel) {
  const h = hardeningLevel ?? getLevel();
  return LEVELS[h]?.extra_rules || [];
}

module.exports = { getLevel, setLevel, getLevelConfig, shouldAlert, getExtraRules, LEVELS };
