'use strict';
/**
 * EHZ-SEC-AI — File Audit Scanner
 * Milestone 6.3
 *
 * סורק תיקיות לפי preset, מזהה secrets/PII/חשוד
 * מחזיר: { files[], summary }
 */

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

// ─── Config ──────────────────────────────────────────────────────────────────

const DEFAULT_SCAN_PATH = 'C:/Claude-Repo';

const EXCLUDE_DIRS = new Set([
  'node_modules', '.git', '.svn', 'dist', 'build',
  'coverage', '.nyc_output', '__pycache__', 'venv',
  'backups', 'ccsm.db',
]);

const SCAN_EXTENSIONS = new Set([
  '.js', '.ts', '.jsx', '.tsx', '.py', '.sh', '.ps1', '.psm1',
  '.json', '.env', '.yml', '.yaml', '.xml', '.config',
  '.txt', '.md', '.html', '.css', '.sql', '.rb', '.php',
  '.conf', '.cfg', '.ini', '.toml', '.properties',
]);

const MAX_FILE_SIZE = 500 * 1024; // 500KB

// ─── Scan Patterns ───────────────────────────────────────────────────────────

const AUDIT_PATTERNS = [
  // CRITICAL
  { level: 'CRITICAL', re: /sk-[A-Za-z0-9]{48}/,                          reason: 'OpenAI API key' },
  { level: 'CRITICAL', re: /sk-ant-[A-Za-z0-9\-_]{40,}/,                  reason: 'Anthropic API key' },
  { level: 'CRITICAL', re: /AKIA[0-9A-Z]{16}/,                            reason: 'AWS Access Key ID' },
  { level: 'CRITICAL', re: /-----BEGIN\s+(RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY/i, reason: 'Private key' },
  { level: 'CRITICAL', re: /curl[^\n]*\|\s*(ba)?sh/i,                     reason: 'curl|sh — pipe to shell' },
  { level: 'CRITICAL', re: /base64\s+(-d|--decode)[^\n]*\|\s*(ba)?sh/i,   reason: 'base64 decode | sh' },

  // HIGH
  { level: 'HIGH', re: /AIza[0-9A-Za-z\-_]{30,}/,                        reason: 'Google API key' },
  { level: 'HIGH', re: /ghp_[A-Za-z0-9]{36}/,                            reason: 'GitHub PAT' },
  { level: 'HIGH', re: /sk_live_[0-9a-zA-Z]{24}/,                        reason: 'Stripe Secret Key' },
  { level: 'HIGH', re: /SG\.[A-Za-z0-9._-]{22,}\.[A-Za-z0-9._-]{22,}/,  reason: 'SendGrid API key' },
  { level: 'HIGH', re: /eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/,     reason: 'JWT token' },
  { level: 'HIGH', re: /password\s*[=:]\s*["']?\S{6,}/i,                 reason: 'Hardcoded password' },
  { level: 'HIGH', re: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@/i,              reason: 'MongoDB credentials' },
  { level: 'HIGH', re: /postgres(ql)?:\/\/[^:]+:[^@]+@/i,                reason: 'PostgreSQL credentials' },
  { level: 'HIGH', re: /\b4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b/, reason: 'כרטיס Visa' },
  { level: 'HIGH', re: /\b3[47][0-9]{13}\b/,                             reason: 'כרטיס Amex' },
  { level: 'HIGH', re: /\.onion/i,                                        reason: 'TOR .onion address' },
  { level: 'HIGH', re: /ngrok/i,                                          reason: 'ngrok tunnel' },

  // MEDIUM
  { level: 'MEDIUM', re: /\b05[0-9]{1}[-\s]?[0-9]{7}\b/,                reason: 'פלאפון ישראלי' },
  { level: 'MEDIUM', re: /eval\s*\(/i,                                    reason: 'eval() call' },
  { level: 'MEDIUM', re: /http:\/\/(?!localhost|127\.0\.0\.1)/i,          reason: 'Non-HTTPS URL' },
  { level: 'MEDIUM', re: /TODO.*password|FIXME.*secret/i,                 reason: 'TODO/FIXME עם credentials' },
];

// ─── Risk Score ───────────────────────────────────────────────────────────────

function calcRiskScore(findings) {
  let score = 0;
  findings.forEach(f => {
    if (f.level === 'CRITICAL') score += 40;
    else if (f.level === 'HIGH')   score += 20;
    else if (f.level === 'MEDIUM') score += 5;
  });
  return Math.min(score, 100);
}

function riskLabel(score) {
  if (score >= 40) return 'CRITICAL';
  if (score >= 20) return 'HIGH';
  if (score >= 5)  return 'MEDIUM';
  return 'OK';
}

// ─── File Scanner ─────────────────────────────────────────────────────────────

function scanFile(filePath) {
  const result = {
    path:     filePath,
    size:     0,
    ext:      path.extname(filePath).toLowerCase(),
    findings: [],
    risk_score: 0,
    risk_label: 'OK',
    scanned_at: new Date().toISOString(),
  };

  try {
    const stat = fs.statSync(filePath);
    result.size = stat.size;
    if (stat.size > MAX_FILE_SIZE) {
      result.skipped = true;
      result.skip_reason = 'גודל קובץ מעל 500KB';
      return result;
    }

    const content = fs.readFileSync(filePath, 'utf8');
    const lines   = content.split('\n');

    for (const pattern of AUDIT_PATTERNS) {
      // Find line number for better reporting
      for (let i = 0; i < lines.length; i++) {
        if (pattern.re.test(lines[i])) {
          // Avoid duplicate reason per file
          if (!result.findings.some(f => f.reason === pattern.reason)) {
            result.findings.push({
              level:  pattern.level,
              reason: pattern.reason,
              line:   i + 1,
            });
          }
          break;
        }
      }
    }
  } catch (e) {
    result.error = e.message;
  }

  result.risk_score = calcRiskScore(result.findings);
  result.risk_label = riskLabel(result.risk_score);
  return result;
}

// ─── Directory Walker ─────────────────────────────────────────────────────────

function walkDir(dirPath, results) {
  let entries;
  try { entries = fs.readdirSync(dirPath, { withFileTypes: true }); }
  catch (_) { return; }

  for (const entry of entries) {
    if (EXCLUDE_DIRS.has(entry.name)) continue;

    const fullPath = path.join(dirPath, entry.name);

    if (entry.isDirectory()) {
      walkDir(fullPath, results);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (!SCAN_EXTENSIONS.has(ext)) continue;
      results.push(scanFile(fullPath));
    }
  }
}

// ─── Main Export ──────────────────────────────────────────────────────────────

function runFileAudit(scanPath) {
  const targetPath = scanPath || DEFAULT_SCAN_PATH;
  const files      = [];

  walkDir(targetPath, files);

  const withFindings = files.filter(f => f.findings.length > 0);

  const summary = {
    scan_path:   targetPath,
    scanned_at:  new Date().toISOString(),
    total_files: files.length,
    clean:       files.filter(f => f.risk_label === 'OK').length,
    medium:      files.filter(f => f.risk_label === 'MEDIUM').length,
    high:        files.filter(f => f.risk_label === 'HIGH').length,
    critical:    files.filter(f => f.risk_label === 'CRITICAL').length,
    skipped:     files.filter(f => f.skipped).length,
  };

  return { files: withFindings, all_files: files, summary };
}

module.exports = { runFileAudit, DEFAULT_SCAN_PATH };
