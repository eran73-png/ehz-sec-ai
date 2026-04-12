'use strict';
/**
 * EHZ-SEC-AI — Skill Security Scanner
 * Milestone 5
 *
 * סורק את כל הסקילים ב-~/.claude/skills/
 * בודק: hash integrity, suspicious patterns
 * מחזיר: { skills[], summary }
 */

const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');

const SKILLS_DIR    = path.join(process.env.USERPROFILE || process.env.HOME, '.claude', 'skills');
const REGISTRY_FILE = path.join(__dirname, 'skill-registry.json');

// ─── Suspicious Patterns ─────────────────────────────────────────────────────

const SCAN_PATTERNS = [
  { level: 'CRITICAL', re: /curl[^\n]*\|\s*(ba)?sh/i,              reason: 'curl|sh — pipe to shell' },
  { level: 'CRITICAL', re: /base64\s+(-d|--decode)[^\n]*\|\s*(ba)?sh/i, reason: 'base64 decode | sh' },
  { level: 'CRITICAL', re: /python[23]?\s+-c\s+['""]import\s+(os|subprocess|socket)/i, reason: 'Python reverse shell' },
  { level: 'CRITICAL', re: /\bnc\s+-[a-z]*l[a-z]*\s/i,            reason: 'Netcat listener' },
  { level: 'CRITICAL', re: /meterpreter|metasploit/i,              reason: 'Metasploit reference' },
  { level: 'CRITICAL', re: /\\\\[a-z0-9._-]/i,                     reason: 'UNC path in skill' },
  { level: 'HIGH',     re: /AKIA[0-9A-Z]{16}/,                     reason: 'AWS Access Key ID' },
  { level: 'HIGH',     re: /-----BEGIN\s+(RSA|EC|OPENSSH)\s+PRIVATE\s+KEY/i, reason: 'Private key embedded' },
  { level: 'HIGH',     re: /password\s*[=:]\s*\S{8,}/i,            reason: 'Hardcoded password' },
  { level: 'HIGH',     re: /eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/, reason: 'JWT token' },
  { level: 'HIGH',     re: /ngrok/i,                               reason: 'ngrok tunnel reference' },
  { level: 'HIGH',     re: /\.onion/i,                             reason: 'TOR .onion address' },
  { level: 'MEDIUM',   re: /eval\s*\(/i,                           reason: 'eval() call' },
  { level: 'MEDIUM',   re: /exec\s*\(/i,                           reason: 'exec() call' },
  { level: 'MEDIUM',   re: /require\s*\(['""]child_process/i,       reason: 'child_process import' },
  { level: 'MEDIUM',   re: /http:\/\/(?!localhost)/i,              reason: 'Non-HTTPS URL (http://)' },
];

// ─── Hash ─────────────────────────────────────────────────────────────────────

function hashFile(filePath) {
  try {
    const content = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(content).digest('hex');
  } catch (_) { return null; }
}

// ─── Registry ─────────────────────────────────────────────────────────────────

function loadRegistry() {
  try {
    if (fs.existsSync(REGISTRY_FILE)) {
      return JSON.parse(fs.readFileSync(REGISTRY_FILE, 'utf8'));
    }
  } catch (_) {}
  return {};
}

function saveRegistry(registry) {
  fs.writeFileSync(REGISTRY_FILE, JSON.stringify(registry, null, 2), 'utf8');
}

// ─── Scan one skill ───────────────────────────────────────────────────────────

function scanSkill(skillName, skillDir, registry) {
  const result = {
    name:          skillName,
    path:          skillDir,
    is_symlink:    false,
    real_path:     skillDir,
    files:         [],
    hash:          null,
    prev_hash:     registry[skillName]?.hash || null,
    hash_changed:  false,
    first_seen:    registry[skillName]?.first_seen || new Date().toISOString(),
    last_scanned:  new Date().toISOString(),
    findings:      [],
    status:        'OK',   // OK | NEW | CHANGED | SUSPICIOUS | CRITICAL
  };

  // Resolve symlink
  try {
    const lstat = fs.lstatSync(path.join(SKILLS_DIR, skillName));
    if (lstat.isSymbolicLink()) {
      result.is_symlink = true;
      result.real_path  = fs.realpathSync(path.join(SKILLS_DIR, skillName));
    }
  } catch (_) {}

  // List .md files
  try {
    result.files = fs.readdirSync(result.real_path)
      .filter(f => f.endsWith('.md') || f.endsWith('.js') || f.endsWith('.json'));
  } catch (_) { result.status = 'ERROR'; return result; }

  // Compute combined hash
  const combined = result.files.map(f => {
    const fp = path.join(result.real_path, f);
    return hashFile(fp) || '';
  }).join(':');
  result.hash = crypto.createHash('sha256').update(combined).digest('hex').slice(0, 16);

  // Hash changed?
  if (!result.prev_hash) {
    result.status = 'NEW';
  } else if (result.prev_hash !== result.hash) {
    result.hash_changed = true;
    result.status       = 'CHANGED';
  }

  // Pattern scan on all .md/.js files
  result.files.forEach(f => {
    if (!f.endsWith('.md') && !f.endsWith('.js')) return;
    let content = '';
    try { content = fs.readFileSync(path.join(result.real_path, f), 'utf8'); } catch (_) { return; }

    for (const p of SCAN_PATTERNS) {
      if (p.re.test(content)) {
        result.findings.push({ file: f, level: p.level, reason: p.reason });
        // Escalate status
        if (p.level === 'CRITICAL') result.status = 'CRITICAL';
        else if (p.level === 'HIGH'   && result.status !== 'CRITICAL') result.status = 'SUSPICIOUS';
        else if (p.level === 'MEDIUM' && !['CRITICAL','SUSPICIOUS'].includes(result.status)) result.status = 'SUSPICIOUS';
      }
    }
  });

  return result;
}

// ─── Main Export ──────────────────────────────────────────────────────────────

function scanAllSkills() {
  const registry = loadRegistry();
  const results  = [];

  let entries = [];
  try {
    entries = fs.readdirSync(SKILLS_DIR, { withFileTypes: true });
  } catch (_) {
    return { skills: [], summary: { total: 0, ok: 0, new: 0, changed: 0, suspicious: 0, critical: 0, scanned_at: new Date().toISOString() } };
  }

  for (const entry of entries) {
    const skillDir = path.join(SKILLS_DIR, entry.name);
    const skill = scanSkill(entry.name, skillDir, registry);
    results.push(skill);

    // Update registry
    registry[entry.name] = {
      hash:       skill.hash,
      first_seen: skill.first_seen,
      last_scanned: skill.last_scanned,
    };
  }

  saveRegistry(registry);

  const summary = {
    total:      results.length,
    ok:         results.filter(s => s.status === 'OK').length,
    new:        results.filter(s => s.status === 'NEW').length,
    changed:    results.filter(s => s.status === 'CHANGED').length,
    suspicious: results.filter(s => s.status === 'SUSPICIOUS').length,
    critical:   results.filter(s => s.status === 'CRITICAL').length,
    scanned_at: new Date().toISOString(),
  };

  return { skills: results, summary };
}

module.exports = { scanAllSkills, SKILLS_DIR };
