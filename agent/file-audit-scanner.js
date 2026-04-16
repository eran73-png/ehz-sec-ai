'use strict';
/**
 * EHZ-SEC-AI — File Audit Scanner
 * Milestone 6.3
 *
 * סורק תיקיות לפי preset, מזהה secrets/PII/חשוד
 * מחזיר: { files[], summary }
 */

const fs       = require('fs');
const path     = require('path');
const crypto   = require('crypto');

let unzipper;
try { unzipper = require('unzipper'); } catch (_) {}

// ─── Config ──────────────────────────────────────────────────────────────────

const DEFAULT_SCAN_PATH = 'C:/Claude-Repo';

const EXCLUDE_DIRS = new Set([
  'node_modules', '.git', '.svn', 'dist', 'build',
  'coverage', '.nyc_output', '__pycache__', 'venv',
  'backups', 'ccsm.db',
]);

const SCAN_EXTENSIONS = new Set([
  '',    // extensionless files (VISA, credentials, passwords, etc.)
  '.js', '.ts', '.jsx', '.tsx', '.py', '.sh', '.ps1', '.psm1',
  '.json', '.env', '.yml', '.yaml', '.xml', '.config',
  '.txt', '.md', '.html', '.css', '.sql', '.rb', '.php',
  '.conf', '.cfg', '.ini', '.toml', '.properties',
  '.docx', '.xlsx', '.pptx', '.odt', '.ods', '.odp',
]);

// Office XML formats (ZIP-based) — need special text extraction
const OFFICE_EXTENSIONS = new Set(['.docx', '.xlsx', '.pptx', '.odt', '.ods', '.odp']);

// Which XML entries to read per format
const OFFICE_XML_ENTRIES = {
  '.docx': ['word/document.xml'],
  '.odt':  ['content.xml'],
  '.xlsx': ['xl/sharedStrings.xml'],
  '.ods':  ['content.xml'],
  '.pptx': null, // all ppt/slides/slide*.xml — matched by prefix
  '.odp':  ['content.xml'],
};

const MAX_FILE_SIZE = 500 * 1024; // 500KB

// ─── Scan Patterns ───────────────────────────────────────────────────────────

const AUDIT_PATTERNS = [
  // CRITICAL
  { level: 'CRITICAL', re: /sk-[A-Za-z0-9]{48}/,                          reason: 'OpenAI API key',           explain: 'An OpenAI API key is hardcoded in this file. If leaked, anyone can use your account and rack up charges.' },
  { level: 'CRITICAL', re: /sk-ant-[A-Za-z0-9\-_]{40,}/,                  reason: 'Anthropic API key',        explain: 'An Anthropic (Claude) API key is exposed. Revoke it immediately at console.anthropic.com.' },
  { level: 'CRITICAL', re: /AKIA[0-9A-Z]{16}/,                            reason: 'AWS Access Key ID',        explain: 'An Amazon AWS access key is in the file. A leak could expose your cloud infrastructure or cause massive billing.' },
  { level: 'CRITICAL', re: /-----BEGIN\s+(RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY/i, reason: 'Private key',     explain: 'A private SSH/SSL key is stored in code. This is like leaving your server password in plain sight.' },
  { level: 'CRITICAL', re: /curl[^\n]*\|\s*(ba)?sh/i,                     reason: 'curl|sh — pipe to shell',  explain: 'Code downloads a script from the internet and runs it immediately — a classic malware delivery technique.' },
  { level: 'CRITICAL', re: /base64\s+(-d|--decode)[^\n]*\|\s*(ba)?sh/i,   reason: 'base64 decode | sh',       explain: 'Hidden command encoded in Base64 is being decoded and executed directly. Common technique to disguise malicious code.' },

  // HIGH
  { level: 'HIGH', re: /AIza[0-9A-Za-z\-_]{30,}/,                        reason: 'Google API key',            explain: 'A Google API key (Maps, Gmail, etc.) is exposed. Could result in unauthorized usage billed to your account.' },
  { level: 'HIGH', re: /ghp_[A-Za-z0-9]{36}/,                            reason: 'GitHub Personal Access Token', explain: 'A GitHub PAT gives full read/write access to your repositories. Revoke it immediately in GitHub settings.' },
  { level: 'HIGH', re: /sk_live_[0-9a-zA-Z]{24}/,                        reason: 'Stripe Secret Key',         explain: 'A live Stripe secret key is exposed. Anyone with this key can access payment data and charge customers.' },
  { level: 'HIGH', re: /SG\.[A-Za-z0-9._-]{22,}\.[A-Za-z0-9._-]{22,}/,  reason: 'SendGrid API key',          explain: 'A SendGrid key is exposed. It can be used to send spam or phishing emails in your name.' },
  { level: 'HIGH', re: /eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/,     reason: 'JWT token',                 explain: 'A JWT authentication token is hardcoded. If leaked, someone can impersonate an authenticated user.' },
  { level: 'HIGH', re: /password\s*[=:]\s*["']?\S{6,}/i,                 reason: 'Hardcoded password',        explain: 'A password is written directly in the code. Anyone who reads this file can see it.' },
  { level: 'HIGH', re: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@/i,              reason: 'MongoDB credentials',       explain: 'MongoDB username and password are embedded in the code. This gives full database access to anyone who sees it.' },
  { level: 'HIGH', re: /postgres(ql)?:\/\/[^:]+:[^@]+@/i,                reason: 'PostgreSQL credentials',    explain: 'PostgreSQL username and password are in the code. Full database access is exposed.' },
  { level: 'HIGH', re: /\b4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b/, reason: 'Visa card number', explain: 'A Visa credit card number was found. Storing card numbers in code violates PCI-DSS compliance.' },
  { level: 'HIGH', re: /\b3[47][0-9]{13}\b/,                             reason: 'Amex card number',          explain: 'An American Express card number was found in the file.' },
  { level: 'HIGH', re: /\.onion/i,                                        reason: 'TOR .onion address',        explain: 'A TOR hidden service address was found. Why is this code connecting to an anonymous network?' },
  { level: 'HIGH', re: /ngrok/i,                                          reason: 'ngrok tunnel',              explain: 'ngrok creates a public tunnel directly to your machine. This can expose internal services to the internet.' },

  // MEDIUM
  { level: 'MEDIUM', re: /\b05[0-9]{1}[-\s]?[0-9]{7}\b/,                reason: 'Israeli phone number',      explain: 'An Israeli phone number was found in the code. Check if this is personal data that should not be here.' },
  { level: 'MEDIUM', re: /eval\s*\(/i,                                    reason: 'eval() call',               explain: 'eval() executes a string as code at runtime. This can allow arbitrary code execution if the input is not trusted.' },
  { level: 'MEDIUM', re: /http:\/\/(?!localhost|127\.0\.0\.1)/i,          reason: 'Non-HTTPS URL',             explain: 'An unencrypted HTTP URL was found. Traffic is sent in plain text and can be intercepted. Use HTTPS instead.' },
  { level: 'MEDIUM', re: /TODO.*password|FIXME.*secret/i,                 reason: 'TODO/FIXME with credentials', explain: 'A comment marks that a password or secret has not been properly handled yet.' },
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

// ─── Office Text Extractor ────────────────────────────────────────────────────

async function readOfficeText(filePath, ext) {
  if (!unzipper) return '';
  try {
    const zip = await unzipper.Open.file(filePath);
    const targets = OFFICE_XML_ENTRIES[ext];
    const entries = zip.files.filter(f => {
      if (targets) return targets.includes(f.path);
      // pptx/odp slides: match any ppt/slides/slide*.xml
      return /^ppt\/slides\/slide\d+\.xml$/.test(f.path);
    });
    const texts = await Promise.all(entries.map(e => e.buffer().then(b => b.toString('utf8'))));
    // Strip XML tags, collapse whitespace
    return texts.join(' ').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
  } catch (_) { return ''; }
}

// ─── File Scanner ─────────────────────────────────────────────────────────────

async function scanFile(filePath) {
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

    let content;
    if (OFFICE_EXTENSIONS.has(result.ext)) {
      content = await readOfficeText(filePath, result.ext);
    } else {
      content = fs.readFileSync(filePath, 'utf8');
    }
    const lines = content.split('\n');

    for (const pattern of AUDIT_PATTERNS) {
      for (let i = 0; i < lines.length; i++) {
        if (pattern.re.test(lines[i])) {
          if (!result.findings.some(f => f.reason === pattern.reason)) {
            result.findings.push({
              level:   pattern.level,
              reason:  pattern.reason,
              explain: pattern.explain || '',
              line:    i + 1,
              snippet: lines[i].trim().slice(0, 120),
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

async function walkDir(dirPath, promises, sinceMs) {
  let entries;
  try { entries = fs.readdirSync(dirPath, { withFileTypes: true }); }
  catch (_) { return; }

  for (const entry of entries) {
    if (EXCLUDE_DIRS.has(entry.name)) continue;

    const fullPath = path.join(dirPath, entry.name);

    if (entry.isDirectory()) {
      await walkDir(fullPath, promises, sinceMs);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (!SCAN_EXTENSIONS.has(ext)) continue;

      // Incremental mode: skip files not modified since last scan
      if (sinceMs) {
        try {
          const mtime = fs.statSync(fullPath).mtimeMs;
          if (mtime <= sinceMs) continue;
        } catch (_) {}
      }

      promises.push(scanFile(fullPath));
    }
  }
}

// ─── Main Export ──────────────────────────────────────────────────────────────

/**
 * @param {string}  scanPath   - תיקייה לסריקה (ברירת מחדל: C:/Claude-Repo)
 * @param {object}  opts
 * @param {boolean} opts.incremental - true → סרוק רק קבצים שהשתנו מאז הסריקה האחרונה
 * @param {string}  opts.since_iso  - ISO timestamp — "מאז מתי" (משמש אם incremental=true)
 */
async function runFileAudit(scanPath, opts = {}) {
  const targetPath = scanPath || DEFAULT_SCAN_PATH;
  const promises   = [];

  let sinceMs = null;
  if (opts.incremental && opts.since_iso) {
    sinceMs = new Date(opts.since_iso).getTime();
  }

  await walkDir(targetPath, promises, sinceMs);
  const files = await Promise.all(promises);

  const withFindings = files.filter(f => f.findings.length > 0);

  const summary = {
    scan_path:   targetPath,
    scanned_at:  new Date().toISOString(),
    incremental: !!sinceMs,
    since:       sinceMs ? new Date(sinceMs).toISOString() : null,
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
