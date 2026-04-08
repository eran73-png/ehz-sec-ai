'use strict';
/**
 * EHZ-SEC-AI — Anomaly Rules Engine
 * Milestone 2+4: Signature + Context + Behavioral + Whitelist + Hardening Levels
 *
 * exports.checkRules(event) → { level, reason, ruleType } | null
 */

const fs   = require('fs');
const path = require('path');

// ─── Hardening ───────────────────────────────────────────────────────────────
let hardening;
try { hardening = require('../config/hardening'); } catch (_) { hardening = null; }

function getExtraRules() {
  return hardening ? hardening.getExtraRules() : [];
}

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

function isWhitelistedCommand(cmd) {
  const wl = getWhitelist();
  return wl.commands.some(pattern => {
    if (pattern.startsWith('/') && pattern.endsWith('/')) {
      return new RegExp(pattern.slice(1, -1)).test(cmd);
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
  { level: 'HIGH', re: /password\s*[=:]\s*\S{4,}/i,               reason: 'Hardcoded password' },
  { level: 'HIGH', re: /secret\s*[=:]\s*\S{4,}/i,                  reason: 'Hardcoded secret' },
  { level: 'HIGH', re: /api[_-]?key\s*[=:]\s*\S{4,}/i,            reason: 'Hardcoded API key' },
  { level: 'HIGH', re: /token\s*[=:]\s*[A-Za-z0-9._\-]{20,}/i,    reason: 'Hardcoded token' },
  { level: 'HIGH', re: /AKIA[0-9A-Z]{16}/,                         reason: 'AWS Access Key ID' },
  { level: 'HIGH', re: /[A-Za-z0-9/+]{40}(?:[A-Za-z0-9/+]{0,3}={0,2})?(?=\s|$)/, reason: 'Possible AWS Secret Key (base64-40)' },
  { level: 'HIGH', re: /-----BEGIN\s+(RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY/i, reason: 'Private key in content' },
  { level: 'HIGH', re: /eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/,       reason: 'JWT token' },
  { level: 'HIGH', re: /\b4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b/, reason: 'Credit card number pattern (Visa)' },
  { level: 'HIGH', re: /\b5[1-5][0-9]{14}\b/,                      reason: 'Credit card number pattern (MC)' },
  { level: 'MEDIUM', re: /\b[0-9]{9}\b/,                           reason: 'Possible Israeli ID number (9 digits)' },
];

// ─── Rule 3: Context Rules (per tool) ────────────────────────────────────────

function checkContextRules(event) {
  const tool  = event.tool_name || '';
  const input = event.tool_input || {};

  // WebFetch — check URL
  if (tool === 'WebFetch') {
    const url = (input.url || '').toLowerCase();
    if (isWhitelistedDomain(url)) return null;

    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url.replace(/https?:\/\//, ''))) {
      return { level: 'HIGH', reason: 'WebFetch to raw IP address', ruleType: 'context' };
    }
    if (url.includes('.onion')) {
      return { level: 'CRITICAL', reason: 'WebFetch to TOR .onion address', ruleType: 'context' };
    }
    const suspiciousTLDs = ['.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz'];
    if (suspiciousTLDs.some(tld => url.includes(tld + '/') || url.endsWith(tld))) {
      return { level: 'HIGH', reason: `WebFetch to suspicious TLD (${suspiciousTLDs.find(t => url.includes(t))})`, ruleType: 'context' };
    }
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

  // ── File tools: check file_path / path parameter ──
  if (FILE_SCOPE_TOOLS.includes(tool)) {
    const rawPath = input.file_path || input.path || '';
    if (!rawPath) return null;

    // Only check drive paths and UNC paths
    if (!isDrivePath(rawPath) && !isUNCPath(rawPath)) return null;

    if (!isPathAllowed(rawPath, allowedPaths)) {
      const label = isUNCPath(rawPath) ? 'UNC' : 'כונן';
      return {
        level:    'HIGH',
        reason:   `גישה מחוץ לפרויקט (${label}) — נתיב: ${rawPath}`,
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
          const label = isUNCPath(p) ? 'UNC' : 'כונן';
          return {
            level:    'HIGH',
            reason:   `גישה מחוץ לפרויקט (Bash ${label}) — נתיב: ${p}`,
            ruleType: 'scope',
          };
        }
      }
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
    return { level: 'INFO', reason: 'UNC path זוהה — ייתכן lateral movement (\\\\server\\share)', ruleType: 'signature' };
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

  return null;
}

module.exports = { checkRules };
