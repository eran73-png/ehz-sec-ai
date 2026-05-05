'use strict';
/**
 * FlowGuard — Detection Rules Engine
 * Signature + Context + Behavioral + Whitelist + Hardening Levels
 *
 * exports.checkRules(event) → { level, reason, ruleType } | null
 */

const RULES_VERSION   = '2.0.0';
const RULES_UPDATED   = '2026-05-05';
module.exports.RULES_VERSION = RULES_VERSION;
module.exports.RULES_UPDATED = RULES_UPDATED;

const fs   = require('fs');
const path = require('path');

// ─── Hardening ───────────────────────────────────────────────────────────────
let hardening;
try { hardening = require('../config/hardening'); } catch (_) { hardening = null; }

function getExtraRules() {
  return hardening ? hardening.getExtraRules() : [];
}

// ─── Domain Reputation (MS6.10) ──────────────────────────────────────────────
let _domainRep;
try { _domainRep = require('./domain-reputation'); } catch(_) {}

// ─── Whitelist ───────────────────────────────────────────────────────────────

let _whitelist = null;
function getWhitelist() {
  if (_whitelist) return _whitelist;
  try {
    const wlPath = path.join(__dirname, 'whitelist.json');
    _whitelist = JSON.parse(fs.readFileSync(wlPath, 'utf8'));
  } catch (_) {
    _whitelist = { domains: [], commands: [], paths: [] };
  }
  return _whitelist;
}

function isWhitelistedDomain(url) {
  const wl = getWhitelist();
  try {
    const host = new URL(url).hostname.toLowerCase();
    return wl.domains.some(d => host === d || host.endsWith('.' + d));
  } catch (_) { return false; }
}

function isAllowedDomain(url, allowedList) {
  try {
    const host = new URL(url).hostname.toLowerCase();
    return allowedList.some(d => {
      const dn = d.toLowerCase().replace(/^https?:\/\//, '');
      return host === dn || host.endsWith('.' + dn);
    });
  } catch (_) { return true; } // if URL parse fails → don't block
}

function isWhitelistedCommand(cmd) {
  const wl = getWhitelist();
  return wl.commands.some(pattern => {
    if (pattern.startsWith('/') && pattern.endsWith('/')) {
      // ReDoS protection: limit pattern length + timeout via try/catch
      const raw = pattern.slice(1, -1);
      if (raw.length > 200) return false;
      try { return new RegExp(raw).test(cmd.slice(0, 1000)); }
      catch(_) { return false; }
    }
    return cmd.trim().startsWith(pattern);
  });
}

function isWhitelistedPath(filePath) {
  const wl = getWhitelist();
  return wl.paths.some(p => filePath.toLowerCase().includes(p.toLowerCase()));
}

// ─── Rule 1: Signature Rules (Bash / any tool) ───────────────────────────────

const SIGNATURE_RULES = [
  // CRITICAL
  { level: 'CRITICAL', re: /curl[^\n]*\|\s*(ba)?sh/i,             reason: 'curl|sh — pipe to shell (RCE pattern)' },
  { level: 'CRITICAL', re: /wget[^\n]*\|\s*(ba)?sh/i,             reason: 'wget|sh — pipe to shell (RCE pattern)' },
  { level: 'CRITICAL', re: /fetch[^\n]*\|\s*(ba)?sh/i,            reason: 'fetch|sh — pipe to shell' },
  { level: 'CRITICAL', re: /base64\s+(-d|--decode)[^\n]*\|\s*(ba)?sh/i, reason: 'base64 decode | sh — obfuscated payload' },
  { level: 'CRITICAL', re: /python[23]?\s+-c\s+['"]import\s+(os|subprocess|socket)/i, reason: 'Python reverse shell pattern' },
  { level: 'CRITICAL', re: /rm\s+-rf\s+(\/[^a-z]|\/\s*$|\*)/i,   reason: 'rm -rf / — destructive delete' },
  { level: 'CRITICAL', re: /:\s*\(\s*\)\s*\{[^}]*:\s*\|/,         reason: 'Fork bomb pattern' },
  { level: 'CRITICAL', re: /dd\s+if=\/dev\/(zero|urandom)\s+of=\/dev\//i, reason: 'dd disk wipe' },
  { level: 'CRITICAL', re: /mkfs\s+/i,                             reason: 'mkfs — format disk' },
  { level: 'CRITICAL', re: /meterpreter|metasploit|msfconsole/i,  reason: 'Metasploit reference' },
  { level: 'CRITICAL', re: /\bnc\s+-[a-z]*l[a-z]*\s/i,             reason: 'Netcat listener' },
  { level: 'CRITICAL', re: /\bncat\s+.*-l/i,                       reason: 'Ncat listener' },
  { level: 'CRITICAL', re: /\/etc\/(passwd|shadow|sudoers)/i,      reason: 'Access to sensitive system files' },
  // WebDAV UNC (Milestone 12.1) — checked on raw command below


  // HIGH
  { level: 'HIGH', re: /ngrok/i,                                    reason: 'ngrok — public tunnel' },
  { level: 'CRITICAL', re: /\.onion/i,                              reason: 'TOR .onion address' },
  { level: 'HIGH', re: /powershell\s+.*-[Ee][Nn][Cc]\s+[A-Za-z0-9+/]{20,}/, reason: 'Encoded PowerShell payload' },
  { level: 'HIGH', re: /iex\s*\(|invoke-expression/i,              reason: 'PowerShell IEX (code injection)' },
  { level: 'HIGH', re: /invoke-webrequest.*\|\s*iex/i,             reason: 'IWR | IEX — download and execute' },
  { level: 'HIGH', re: /certutil.*-decode/i,                        reason: 'certutil decode (LOLBin abuse)' },
  { level: 'HIGH', re: /bitsadmin.*\/transfer/i,                    reason: 'bitsadmin download (LOLBin)' },
  { level: 'HIGH', re: /reg\s+(add|delete|export)\s+HKLM/i,        reason: 'Registry modification (HKLM)' },
  { level: 'HIGH', re: /schtasks\s+\/create/i,                      reason: 'Scheduled task creation' },
  { level: 'HIGH', re: /net\s+(user|localgroup)\s+.*\/add/i,        reason: 'User/group addition' },
  { level: 'HIGH', re: /whoami|net\s+user\s+\/domain/i,             reason: 'Reconnaissance command' },
  { level: 'HIGH', re: /nmap\s+/i,                                  reason: 'Network scan (nmap)' },
  { level: 'HIGH', re: /sqlmap/i,                                   reason: 'SQL injection tool' },
  { level: 'HIGH', re: /hydra\s+|john\s+--/i,                      reason: 'Password cracking tool' },
];

// ─── Rule 2: Secrets / DLP (any tool input/output) ───────────────────────────

const SECRETS_RULES = [
  // ── Generic secrets ──
  { level: 'HIGH', re: /password\s*[=:]\s*\S{4,}/i,               reason: 'Hardcoded password' },
  { level: 'HIGH', re: /secret\s*[=:]\s*\S{4,}/i,                  reason: 'Hardcoded secret' },
  { level: 'HIGH', re: /api[_-]?key\s*[=:]\s*\S{4,}/i,            reason: 'Hardcoded API key' },
  { level: 'HIGH', re: /token\s*[=:]\s*[A-Za-z0-9._\-]{20,}/i,    reason: 'Hardcoded token' },

  // ── Cloud & SaaS API keys ──
  { level: 'CRITICAL', re: /sk-[A-Za-z0-9]{48}/,                   reason: 'OpenAI API key' },
  { level: 'CRITICAL', re: /sk-ant-[A-Za-z0-9\-_]{40,}/,           reason: 'Anthropic API key' },
  { level: 'CRITICAL', re: /AKIA[0-9A-Z]{16}/,                     reason: 'AWS Access Key ID' },
  { level: 'HIGH',     re: /AIza[0-9A-Za-z\-_]{30,}/,              reason: 'Google API key' },
  { level: 'HIGH',     re: /ghp_[A-Za-z0-9]{36}/,                  reason: 'GitHub Personal Access Token' },
  { level: 'HIGH',     re: /github_pat_[A-Za-z0-9_]{82}/,          reason: 'GitHub Fine-grained PAT' },
  { level: 'HIGH',     re: /sk_live_[0-9a-zA-Z]{24}/,              reason: 'Stripe Secret Key (live)' },
  { level: 'HIGH',     re: /pk_live_[0-9a-zA-Z]{24}/,              reason: 'Stripe Publishable Key (live)' },
  { level: 'HIGH',     re: /SG\.[A-Za-z0-9._-]{22,}\.[A-Za-z0-9._-]{22,}/, reason: 'SendGrid API key' },
  { level: 'HIGH',     re: /[A-Za-z0-9/+]{40}(?:[A-Za-z0-9/+]{0,3}={0,2})?(?=\s|$)/, reason: 'Possible AWS Secret Key (base64-40)' },

  // ── Private keys & certificates ──
  { level: 'CRITICAL', re: /-----BEGIN\s+(RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY/i, reason: 'Private key in content' },

  // ── Tokens ──
  { level: 'HIGH', re: /eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/, reason: 'JWT token' },

  // ── Connection strings with credentials ──
  { level: 'HIGH', re: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@/i,        reason: 'MongoDB connection string with credentials' },
  { level: 'HIGH', re: /mysql:\/\/[^:]+:[^@]+@/i,                  reason: 'MySQL connection string with credentials' },
  { level: 'HIGH', re: /postgres(ql)?:\/\/[^:]+:[^@]+@/i,          reason: 'PostgreSQL connection string with credentials' },

  // ── Israeli PII (6.2) ──
  { level: 'HIGH',   re: /\b4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b/, reason: 'Credit card number (Visa)' },
  { level: 'HIGH',   re: /\b5[1-5][0-9]{14}\b/,                    reason: 'Credit card number (MasterCard)' },
  { level: 'HIGH',   re: /\b3[47][0-9]{13}\b/,                     reason: 'Credit card number (American Express)' },
  { level: 'MEDIUM', re: /\b05[0-9]{1}[-\s]?[0-9]{7}\b/,          reason: 'Israeli phone number (PII)' },
  { level: 'MEDIUM', re: /(?:id|tz|t\.z\.|zehut|teudat|מספר.?זהות)\s*[=:]\s*\b[0-9]{9}\b/i, reason: 'Possible Israeli ID number (9 digits)' },
];

// ─── Rule 3: Context Rules (per tool) ────────────────────────────────────────

function checkContextRules(event) {
  const tool  = event.tool_name || '';
  const input = event.tool_input || {};

  // WebSearch — always log the query (MS6.10b)
  if (tool === 'WebSearch') {
    const query = input.query || '';
    return { level: 'INFO', reason: `WebSearch: "${query}"`, ruleType: 'websearch' };
  }

  // WebFetch — check URL
  if (tool === 'WebFetch') {
    const url = (input.url || '').toLowerCase();

    // CRITICAL / HIGH patterns — always checked first
    if (url.includes('.onion')) {
      return { level: 'CRITICAL', reason: 'WebFetch to TOR .onion address', ruleType: 'context' };
    }
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url.replace(/https?:\/\//, ''))) {
      return { level: 'HIGH', reason: 'WebFetch to raw IP address', ruleType: 'context' };
    }
    const suspiciousTLDs = ['.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz'];
    if (suspiciousTLDs.some(tld => url.includes(tld + '/') || url.endsWith(tld))) {
      return { level: 'HIGH', reason: `WebFetch to suspicious TLD (${suspiciousTLDs.find(t => url.includes(t))})`, ruleType: 'context' };
    }

    // Allowlist check (MS6.9) — domain not in allowed list → HIGH
    const wl = getWhitelist();
    const allowedDomains = wl.allowed_domains || wl.domains || [];
    if (allowedDomains.length > 0 && !isAllowedDomain(url, allowedDomains)) {
      let host = url;
      try { host = new URL(url).hostname; } catch(_) {}
      const reputation = _domainRep ? _domainRep.scoreDomain(host, allowedDomains) : null;
      return { level: 'HIGH', reason: `WebFetch to unauthorized domain: ${host}`, ruleType: 'allowlist', domain: host, reputation };
    }

    // Legacy whitelist (domains array) — no alert if in list
    if (isWhitelistedDomain(url)) return null;
  }

  // Write / Edit — sensitive paths
  if (['Write', 'Edit', 'NotebookEdit'].includes(tool)) {
    const filePath = (input.file_path || input.path || '').toLowerCase();
    if (isWhitelistedPath(filePath)) return null;

    const sensitivePaths = ['.ssh/', 'id_rsa', 'id_ed25519', 'authorized_keys',
                             '.aws/credentials', '.gnupg/', '/etc/passwd', '/etc/shadow',
                             '/etc/sudoers', 'windows/system32', 'appdata/roaming/microsoft'];
    for (const sp of sensitivePaths) {
      if (filePath.includes(sp)) {
        return { level: 'CRITICAL', reason: `Write to sensitive path: ${sp}`, ruleType: 'context' };
      }
    }
  }

  // Bash — check for whitelist first
  if (tool === 'Bash') {
    const cmd = (input.command || '').toLowerCase();
    if (isWhitelistedCommand(cmd)) return null;
  }

  return null;
}

// ─── Rule 5: Scope Check — drive + UNC paths outside project ─────────────────

const FILE_SCOPE_TOOLS = ['Read', 'Write', 'Edit', 'Glob', 'Grep'];

/** Normalize slashes + lowercase for comparison */
function normPath(p) { return p.replace(/\\/g, '/').toLowerCase(); }

/** Is this a drive path? (C:/ D:\ etc.) */
function isDrivePath(p) { return /^[a-z]:/i.test(p); }

/** Is this a UNC path? (\\server\share or //server/share) */
function isUNCPath(p) {
  const n = normPath(p);
  return n.startsWith('//') && n.length > 4 && !/^\/\/[./]/.test(n);
}

/** Is a path inside one of the allowed paths? */
function isPathAllowed(rawPath, allowedPaths) {
  const n = normPath(rawPath);
  return allowedPaths.some(ap => n.startsWith(normPath(ap)));
}

/** Extract all drive + UNC paths from a Bash command string */
function extractPathsFromCommand(cmd) {
  const found = [];
  // Drive paths: X:/ or X:\ — negative lookbehind: not preceded by a letter (avoids http://)
  const driveRe = /(?<![a-zA-Z])([A-Za-z]:[/\\][^\s"'`;|&<>]*)/g;
  let m;
  while ((m = driveRe.exec(cmd)) !== null) found.push(m[1]);
  // UNC paths: \\server\ or //server/ — exclude http://, https://, ftp://
  const uncRe = /(?<![a-zA-Z:])([/\\]{2})([a-zA-Z0-9._-]+)[/\\][^\s"'`;|&<>]*/g;
  while ((m = uncRe.exec(cmd)) !== null) found.push(m[0].replace(/^[^/\\]*/,''));
  return [...new Set(found)];
}

function checkScopeRule(event) {
  const tool  = event.tool_name || '';
  const input = event.tool_input || {};
  const wl    = getWhitelist();
  const allowedPaths = wl.allowed_paths || [];

  // If no allowed_paths configured → skip scope check entirely
  if (!allowedPaths.length) return null;

  // ── File tools: check file_path / path parameter ──
  if (FILE_SCOPE_TOOLS.includes(tool)) {
    const rawPath = input.file_path || input.path || '';
    if (!rawPath) return null;

    // Only check drive paths and UNC paths
    if (!isDrivePath(rawPath) && !isUNCPath(rawPath)) return null;

    if (!isPathAllowed(rawPath, allowedPaths)) {
      const label = isUNCPath(rawPath) ? 'UNC' : 'Drive';
      return {
        level:    'CRITICAL',
        reason:   `⚠️ Claude accessing OUTSIDE project (${label}) — path: ${rawPath}`,
        ruleType: 'scope',
      };
    }
  }

  // ── Bash: extract all paths from the command string ──
  // Only skip commands whose arguments are NOT file paths (git/npm/node text may contain UNC text)
  const SCOPE_EXEMPT_BASH = ['git ', 'npm ', 'node ', 'echo ', 'Write-Host', 'Get-'];
  if (tool === 'Bash') {
    const cmd = input.command || '';
    const isScopeExempt = SCOPE_EXEMPT_BASH.some(p => cmd.trim().startsWith(p));
    if (!isScopeExempt) {
      const paths = extractPathsFromCommand(cmd);
      for (const p of paths) {
        if (!isPathAllowed(p, allowedPaths)) {
          const label = isUNCPath(p) ? 'UNC' : 'Drive';
          return {
            level:    'CRITICAL',
            reason:   `⚠️ Claude accessing OUTSIDE project (Bash ${label}) — path: ${p}`,
            ruleType: 'scope',
          };
        }
      }
    }
  }

  return null;
}

// ─── Rule 6: Git + Env Monitor (MS7.4) ───────────────────────────────────────

// Allowed remotes — loaded from whitelist.json (configurable per installation)
function getAllowedGitRemotes() {
  const wl = getWhitelist();
  return wl.git_remotes || ['github.com', 'gitlab.com', 'bitbucket.org', 'localhost', '127.0.0.1'];
}

// Suspicious commit message patterns
const SUSPICIOUS_COMMIT_MSG = [
  /\b(secret|password|passwd|token|api.?key|credential|private.?key)\b/i,
  /\b(backdoor|exfil|payload|exploit)\b/i,
];

function checkGitEnvRules(event) {
  const tool  = event.tool_name || '';
  const input = event.tool_input || {};

  // ── Read / Glob / Grep on .env files ──
  if (['Read', 'Glob', 'Grep'].includes(tool)) {
    const p = (input.file_path || input.path || input.pattern || '').toLowerCase();
    if (p.endsWith('.env') || p.includes('/.env') || p.includes('\\.env')) {
      return { level: 'MEDIUM', reason: `📂 Environment file read — ${input.file_path || input.path || input.pattern}`, ruleType: 'git_env' };
    }
  }

  // ── Bash commands only from here ──
  if (tool !== 'Bash') return null;
  const cmd = (input.command || '').trim();

  // git push --force
  if (/git\s+push\s+.*--force/.test(cmd) || /git\s+push\s+.*-f\b/.test(cmd)) {
    return { level: 'HIGH', reason: `🔴 git push --force — history rewrite!`, ruleType: 'git_env' };
  }

  // git push to unknown remote
  const pushMatch = cmd.match(/git\s+push\s+(\S+)/);
  if (pushMatch) {
    const urlMatch = cmd.match(/https?:\/\/([a-zA-Z0-9._-]+)/) || cmd.match(/@([a-zA-Z0-9._-]+)[:/]/);
    if (urlMatch) {
      const host = urlMatch[1].toLowerCase();
      const isAllowed = getAllowedGitRemotes().some(r => host === r || host.endsWith('.' + r));
      if (!isAllowed) {
        return { level: 'HIGH', reason: `🔴 git push to unauthorized server — ${host}`, ruleType: 'git_env' };
      }
    }
  }

  // git commit with suspicious message
  const commitMatch = cmd.match(/git\s+commit\s+.*-m\s+["']?(.+?)["']?\s*$/i);
  if (commitMatch) {
    const msg = commitMatch[1];
    if (SUSPICIOUS_COMMIT_MSG.some(re => re.test(msg))) {
      return { level: 'HIGH', reason: `🔴 git commit with suspicious message — "${msg.slice(0,60)}"`, ruleType: 'git_env' };
    }
  }

  // git remote add / set-url
  if (/git\s+remote\s+(add|set-url)/.test(cmd)) {
    const urlInCmd = cmd.match(/https?:\/\/([a-zA-Z0-9._-]+)/) || cmd.match(/git@([a-zA-Z0-9._-]+)/);
    if (urlInCmd) {
      const host = urlInCmd[1].toLowerCase();
      const isAllowed = getAllowedGitRemotes().some(r => host === r || host.endsWith('.' + r));
      if (!isAllowed) {
        return { level: 'HIGH', reason: `🔴 git remote changed to unauthorized server — ${host}`, ruleType: 'git_env' };
      }
    }
    return { level: 'MEDIUM', reason: `⚠️ git remote changed — ${cmd.slice(0,80)}`, ruleType: 'git_env' };
  }

  return null;
}

// ─── Rule 7: Code Quality Scanner (Phase 2) ─────────────────────────────────
// Scans code written by Claude for security anti-patterns

const CODE_SECURITY_RULES = [
  // SQL Injection
  { level: 'CRITICAL', re: /['"`]\s*\+\s*(?:req\.(?:body|query|params)|input|user)/i, reason: 'SQL injection — string concat with user input' },
  { level: 'CRITICAL', re: /\$\{(?:req\.(?:body|query|params)|input|user)[^}]*\}/i, reason: 'SQL injection — template literal with user input' },
  { level: 'HIGH',     re: /(?:query|exec|execute)\s*\(\s*['"`].*\+/i, reason: 'SQL injection risk — dynamic query concatenation' },

  // XSS
  { level: 'HIGH', re: /\.innerHTML\s*=\s*(?!['"`]<).*(?:req\.|input|user|data|res)/i, reason: 'XSS risk — innerHTML with dynamic data' },
  { level: 'HIGH', re: /document\.write\s*\(/i, reason: 'XSS risk — document.write()' },
  { level: 'MEDIUM', re: /\$\(.*\)\.html\s*\((?!['"`])/i, reason: 'XSS risk — jQuery .html() with dynamic content' },

  // Command Injection
  { level: 'CRITICAL', re: /exec\s*\(\s*['"`].*\$\{/i, reason: 'Command injection — exec with template literal' },
  { level: 'CRITICAL', re: /exec\s*\(\s*.*\+\s*(?:req\.|input|user|args)/i, reason: 'Command injection — exec with user input' },
  { level: 'HIGH',     re: /execSync\s*\(\s*['"`].*\$\{/i, reason: 'Command injection — execSync with template literal' },
  { level: 'MEDIUM',   re: /child_process/i, reason: 'Uses child_process — verify no user input flows in' },

  // Path Traversal
  { level: 'HIGH', re: /path\.join\s*\([^)]*req\.(params|query|body)/i, reason: 'Path traversal risk — path.join with user input' },
  { level: 'HIGH', re: /readFile(?:Sync)?\s*\([^)]*req\./i, reason: 'Path traversal risk — readFile with user input' },
  { level: 'HIGH', re: /sendFile\s*\([^)]*req\./i, reason: 'Path traversal risk — sendFile with user input' },

  // Insecure Crypto
  { level: 'HIGH', re: /createHash\s*\(\s*['"]md5['"]/i, reason: 'Weak hash — MD5 is broken' },
  { level: 'HIGH', re: /createHash\s*\(\s*['"]sha1['"]/i, reason: 'Weak hash — SHA1 is deprecated' },
  { level: 'HIGH', re: /createCipher\b/i, reason: 'Deprecated createCipher — use createCipheriv' },
  { level: 'MEDIUM', re: /Math\.random\s*\(\s*\).*(?:token|key|secret|password|salt|nonce)/i, reason: 'Insecure random for security — use crypto.randomBytes' },

  // Dangerous Functions
  { level: 'HIGH', re: /eval\s*\(\s*(?!['"`])/i, reason: 'eval() with dynamic input' },
  { level: 'HIGH', re: /new\s+Function\s*\(/i, reason: 'new Function() — dynamic code execution' },
  { level: 'MEDIUM', re: /setTimeout\s*\(\s*['"`]/i, reason: 'setTimeout with string — use function reference' },
  { level: 'MEDIUM', re: /setInterval\s*\(\s*['"`]/i, reason: 'setInterval with string — use function reference' },

  // Missing Security Headers / Config
  { level: 'MEDIUM', re: /Access-Control-Allow-Origin.*\*/i, reason: 'CORS wildcard — allows any origin' },
  { level: 'MEDIUM', re: /disable\s*\(\s*['"]x-powered-by['"]\s*\)/i, reason: 'Good: x-powered-by disabled' },

  // Hardcoded IPs / URLs
  { level: 'MEDIUM', re: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i, reason: 'Hardcoded IP in URL' },

  // No Error Handling
  { level: 'LOW', re: /catch\s*\(\s*_?\s*\)\s*\{\s*\}/i, reason: 'Empty catch block — errors silently swallowed' },

  // Logging Sensitive Data
  { level: 'HIGH', re: /console\.log\s*\(.*(?:password|secret|token|apiKey|api_key|credential)/i, reason: 'Logging sensitive data' },
];

function checkCodeQuality(event) {
  const tool = event.tool_name || '';
  const input = event.tool_input || {};

  // Only scan Write/Edit operations (code Claude is writing)
  if (!['Write', 'Edit', 'NotebookEdit'].includes(tool)) return null;

  const content = input.content || input.new_string || '';
  if (!content || content.length < 10) return null;

  // Skip non-code files
  const filePath = (input.file_path || '').toLowerCase();
  const codeExts = ['.js', '.ts', '.py', '.jsx', '.tsx', '.php', '.rb', '.java', '.go', '.rs', '.cs', '.html'];
  if (!codeExts.some(ext => filePath.endsWith(ext))) return null;

  for (const rule of CODE_SECURITY_RULES) {
    if (rule.re.test(content)) {
      return { level: rule.level, reason: `Code Review: ${rule.reason}`, ruleType: 'code_quality' };
    }
  }

  return null;
}

// ─── Main Export ─────────────────────────────────────────────────────────────

/**
 * checkRules(event) → { level, reason, ruleType } | null
 * Checks all rules in priority order.
 */
function checkRules(event) {
  const tool  = event.tool_name || '';
  const input = event.tool_input || {};

  // Build searchable text from input
  const inputText = JSON.stringify(input);

  // WebDAV UNC path — check both raw value and JSON-encoded
  // Skip if Bash command is whitelisted (git commit messages may contain \\server text)
  const rawCmd = input.command || input.file_path || '';
  const SCOPE_EXEMPT_BASH = ['git ', 'npm ', 'node ', 'echo ', 'Write-Host', 'Get-'];
  const isBashWhitelisted = (tool === 'Bash') && SCOPE_EXEMPT_BASH.some(p => rawCmd.trim().startsWith(p));
  if (!isBashWhitelisted && (/\\\\[a-z0-9._-]/i.test(rawCmd) || /\\\\\\\\[a-z0-9._-]/i.test(inputText))) {
    return { level: 'INFO', reason: 'UNC path detected — possible lateral movement (\\\\server\\share)', ruleType: 'signature' };
  }

  // 1. Signature rules (on all tools)
  for (const rule of SIGNATURE_RULES) {
    if (rule.re.test(inputText)) {
      return { level: rule.level, reason: rule.reason, ruleType: 'signature' };
    }
  }

  // 2. Secrets rules (on Write / Bash output — check input text)
  if (['Write', 'Edit', 'Bash', 'NotebookEdit'].includes(tool)) {
    for (const rule of SECRETS_RULES) {
      if (rule.re.test(inputText)) {
        return { level: rule.level, reason: rule.reason, ruleType: 'secrets' };
      }
    }
  }

  // 3. Context rules
  const contextResult = checkContextRules(event);
  if (contextResult) return contextResult;

  // 4. Extra rules (Hardening Level 2+)
  for (const rule of getExtraRules()) {
    if (rule.re.test(inputText)) {
      return { level: rule.level, reason: rule.reason, ruleType: 'hardening' };
    }
  }

  // 5. Scope check — file access outside project paths
  const scopeResult = checkScopeRule(event);
  if (scopeResult) return scopeResult;

  // 6. Git + Env Monitor (MS7.4)
  const gitEnvResult = checkGitEnvRules(event);
  if (gitEnvResult) return gitEnvResult;

  // 7. Code Quality Scanner (Phase 2)
  const codeResult = checkCodeQuality(event);
  if (codeResult) return codeResult;

  return null;
}

module.exports = { checkRules, RULES_VERSION, RULES_UPDATED };
