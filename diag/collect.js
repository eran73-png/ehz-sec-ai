#!/usr/bin/env node
// ============================================================
// FlowGuard Standalone Diagnostics — v1.0
// ============================================================
// Portable diagnostic tool. Runs WITHOUT FlowGuard installed.
// Use when installation failed or FlowGuard service is broken.
//
// Collects: install logs, system info, event logs, config files.
// Sanitizes: tokens, passwords, usernames before packaging.
// Opens: default mail client pre-filled for eranhz26@gmail.com
// ============================================================

'use strict';

const fs        = require('fs');
const path      = require('path');
const os        = require('os');
const { execSync, exec } = require('child_process');
const zlib      = require('zlib');

const SUPPORT_EMAIL = 'eranhz26@gmail.com';
const VERSION       = '2.4.2';

// ─── Helpers ────────────────────────────────────────────────

function log(level, msg) {
  const colors = { info: '\x1b[36m', ok: '\x1b[32m', warn: '\x1b[33m', err: '\x1b[31m', dim: '\x1b[90m' };
  const reset  = '\x1b[0m';
  console.log((colors[level] || '') + msg + reset);
}

function safeExec(cmd, fallback = '') {
  try {
    return execSync(cmd, { encoding: 'utf8', timeout: 10000, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return fallback;
  }
}

function sanitize(text) {
  if (!text) return text;
  let t = String(text);

  // Secrets & tokens
  t = t.replace(/(TELEGRAM_TOKEN\s*[=:]\s*["']?)[^\s\r\n"']+/gi, '$1[REDACTED]');
  t = t.replace(/(TELEGRAM_CHAT_ID\s*[=:]\s*["']?)[^\s\r\n"']+/gi, '$1[REDACTED]');
  t = t.replace(/(api[_-]?key\s*[=:]\s*["']?)[^\s\r\n"']+/gi, '$1[REDACTED]');
  t = t.replace(/(secret\s*[=:]\s*["']?)[^\s\r\n"']+/gi, '$1[REDACTED]');
  t = t.replace(/(password\s*[=:]\s*["']?)[^\s\r\n"']+/gi, '$1[REDACTED]');
  t = t.replace(/(token\s*[=:]\s*["']?)[a-zA-Z0-9_\-]{16,}/gi, '$1[REDACTED]');

  // Telegram bot token pattern: digits:alphanumeric
  t = t.replace(/\b\d{7,12}:[A-Za-z0-9_\-]{30,}\b/g, '[REDACTED-BOT-TOKEN]');

  // Bearer tokens
  t = t.replace(/(Bearer\s+)[A-Za-z0-9._\-]{20,}/gi, '$1[REDACTED]');

  // User paths
  const user = os.userInfo().username;
  const safeUser = user.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  t = t.replace(new RegExp(`C:\\\\Users\\\\${safeUser}`, 'gi'), 'C:\\Users\\[USER]');
  t = t.replace(new RegExp(`/Users/${safeUser}`, 'gi'), '/Users/[USER]');
  t = t.replace(new RegExp(`/home/${safeUser}`, 'gi'), '/home/[USER]');
  t = t.replace(new RegExp('\\b' + safeUser + '\\b', 'gi'), '[USER]');

  return t;
}

function saveSanitized(destPath, content) {
  fs.writeFileSync(destPath, sanitize(content), 'utf8');
}

// ─── Auto-detect FlowGuard install dir ──────────────────────

function findInstallDir() {
  const candidates = [
    'C:\\FlowGuard',
    'C:\\Program Files\\FlowGuard',
    'C:\\Program Files (x86)\\FlowGuard'
  ];
  for (const dir of candidates) {
    if (fs.existsSync(path.join(dir, 'agent', 'tray.js'))) return dir;
  }
  return '';
}

// ─── Simple ZIP implementation (stored, no dependencies) ────
// Creates a ZIP archive using only Node.js built-ins.
// Uses STORE method (no compression) for simplicity.

function crc32(buf) {
  let c;
  const table = crc32.table || (crc32.table = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      c = n;
      for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      t[n] = c;
    }
    return t;
  })());
  c = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) c = table[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}

function createZip(files, outPath) {
  // files: [{ name, data: Buffer }]
  const localParts = [];
  const centralParts = [];
  let offset = 0;

  for (const f of files) {
    const deflated  = zlib.deflateRawSync(f.data);
    const crc       = crc32(f.data);
    const nameBuf   = Buffer.from(f.name, 'utf8');
    const method    = 8; // DEFLATE
    const compSize  = deflated.length;
    const uncompSize= f.data.length;

    // Local file header
    const local = Buffer.alloc(30 + nameBuf.length);
    local.writeUInt32LE(0x04034b50, 0);        // signature
    local.writeUInt16LE(20, 4);                 // version
    local.writeUInt16LE(0x0800, 6);             // flags (UTF-8 names)
    local.writeUInt16LE(method, 8);             // compression method
    local.writeUInt16LE(0, 10);                 // mod time
    local.writeUInt16LE(0, 12);                 // mod date
    local.writeUInt32LE(crc, 14);               // CRC32
    local.writeUInt32LE(compSize, 18);          // compressed size
    local.writeUInt32LE(uncompSize, 22);        // uncompressed size
    local.writeUInt16LE(nameBuf.length, 26);    // name length
    local.writeUInt16LE(0, 28);                 // extra length
    nameBuf.copy(local, 30);

    localParts.push(local, deflated);

    // Central directory record
    const central = Buffer.alloc(46 + nameBuf.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt16LE(0, 12);
    central.writeUInt16LE(0, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(compSize, 20);
    central.writeUInt32LE(uncompSize, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(0, 38);
    central.writeUInt32LE(offset, 42);
    nameBuf.copy(central, 46);
    centralParts.push(central);

    offset += local.length + deflated.length;
  }

  const centralSize   = centralParts.reduce((s, b) => s + b.length, 0);
  const centralOffset = offset;

  // End of central directory
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(centralSize, 12);
  eocd.writeUInt32LE(centralOffset, 16);
  eocd.writeUInt16LE(0, 20);

  fs.writeFileSync(outPath, Buffer.concat([...localParts, ...centralParts, eocd]));
}

// ─── Main collection logic ──────────────────────────────────

async function main() {
  const hostname = os.hostname();
  const now      = new Date();
  const stamp    = now.toISOString().slice(0, 19).replace(/[:T]/g, '').replace(/-/g, '');
  const installDir = findInstallDir();
  const isAdmin = (() => {
    try { execSync('net session', { stdio: 'ignore' }); return true; }
    catch { return false; }
  })();

  log('info', '');
  log('info', 'FlowGuard Standalone Diagnostics v' + VERSION);
  log('info', '=========================================');
  log('dim',  'Hostname:    ' + hostname);
  log('dim',  'Install dir: ' + (installDir || 'NOT FOUND'));
  log('dim',  'Admin:       ' + isAdmin);
  log('info', '');

  const entries = []; // files to add to ZIP

  // 1. System info
  log('warn', '[1/7] Collecting system info...');
  const sys = [
    'FlowGuard Diagnostics Report (Standalone)',
    '===========================================',
    `Generated:    ${now.toISOString()}`,
    `Hostname:     ${hostname}`,
    `User:         [USER]`,
    `Admin:        ${isAdmin}`,
    '',
    '=== Operating System ===',
    `OS:           ${os.type()} ${os.release()}`,
    `Arch:         ${os.arch()}`,
    `Platform:     ${os.platform()}`,
    `CPU:          ${os.cpus()[0] ? os.cpus()[0].model : 'unknown'} (${os.cpus().length} cores)`,
    `RAM:          ${Math.round(os.totalmem() / 1024 / 1024 / 1024)} GB`,
    `Free RAM:     ${Math.round(os.freemem() / 1024 / 1024 / 1024)} GB`,
    '',
    '=== Runtime ===',
    `Node.js:      ${process.version}`,
    `Node path:    ${safeExec('where node', 'NOT FOUND').split('\n')[0]}`,
    `PowerShell:   ${safeExec('powershell -Command "$PSVersionTable.PSVersion.ToString()"')}`,
    '',
    '=== FlowGuard Install ===',
    `Install dir:       ${installDir || 'NOT FOUND'}`,
    `Dir exists:        ${installDir ? fs.existsSync(installDir) : false}`,
    installDir ? `Tray.js:           ${fs.existsSync(path.join(installDir, 'agent', 'tray.js'))}` : '',
    installDir ? `VBS exists:        ${fs.existsSync(path.join(installDir, 'install', 'start-tray.vbs'))}` : '',
    installDir ? `Server.js:         ${fs.existsSync(path.join(installDir, 'collector', 'server.js'))}` : ''
  ].filter(Boolean).join('\n');
  entries.push({ name: '01-system-info.txt', data: Buffer.from(sys, 'utf8') });

  // 2. Folder structure
  log('warn', '[2/7] Mapping install folder...');
  if (installDir && fs.existsSync(installDir)) {
    const lines = ['FlowGuard install folder contents:\n'];
    const walk = (dir, prefix = '') => {
      try {
        for (const item of fs.readdirSync(dir)) {
          const p = path.join(dir, item);
          let st; try { st = fs.statSync(p); } catch { continue; }
          if (st.isDirectory()) {
            lines.push(`${prefix}${item}/`);
            if (prefix.length < 12) walk(p, prefix + '  ');
          } else {
            lines.push(`${prefix}${item}  (${Math.round(st.size / 1024 * 100) / 100} KB)`);
          }
        }
      } catch {}
    };
    walk(installDir);
    entries.push({ name: '02-folder-structure.txt', data: Buffer.from(lines.join('\n'), 'utf8') });
  } else {
    entries.push({ name: '02-folder-structure.txt', data: Buffer.from('FlowGuard install directory NOT found.\nChecked: C:\\FlowGuard, C:\\Program Files\\FlowGuard, C:\\Program Files (x86)\\FlowGuard', 'utf8') });
  }

  // 3. Install logs (Inno Setup)
  log('warn', '[3/7] Collecting installer logs...');
  const temp = os.tmpdir();
  try {
    const tempFiles = fs.readdirSync(temp).filter(f => /^Setup Log .* #\d+\.txt$/i.test(f));
    if (tempFiles.length === 0) {
      entries.push({ name: '03-installer-none.txt', data: Buffer.from('No Inno Setup installer logs found in %TEMP%', 'utf8') });
    }
    for (const f of tempFiles) {
      try {
        const content = fs.readFileSync(path.join(temp, f), 'utf8');
        entries.push({ name: `03-installer-${f}`, data: Buffer.from(sanitize(content), 'utf8') });
      } catch {}
    }
  } catch {}

  // 4. Config files
  log('warn', '[4/7] Collecting config (sanitized)...');
  if (installDir) {
    const cfgFiles = [
      { name: 'whitelist.json', path: path.join(installDir, 'agent', 'whitelist.json') },
      { name: 'package.json',   path: path.join(installDir, 'package.json') },
      { name: '.env',           path: path.join(installDir, '.env') }
    ];
    for (const f of cfgFiles) {
      const p = f.path;
      if (fs.existsSync(p)) {
        try {
          const content = fs.readFileSync(p, 'utf8');
          const outName = f.name === '.env' ? 'env-sanitized.txt' : f.name;
          entries.push({ name: `04-config-${outName}`, data: Buffer.from(sanitize(content), 'utf8') });
        } catch {}
      }
    }
  }

  // 5. Service status
  log('warn', '[5/7] Checking Windows service...');
  const serviceOut = safeExec('sc.exe query FlowGuardCollector', 'Service "FlowGuardCollector" not registered.');
  const serviceConfig = safeExec('sc.exe qc FlowGuardCollector', '');
  entries.push({ name: '05-service-status.txt', data: Buffer.from(sanitize(serviceOut + '\n\n' + serviceConfig), 'utf8') });

  // 6. Port 3010
  log('warn', '[6/7] Checking collector port 3010...');
  let portInfo = 'Collector Port Check\n====================\n\n';
  const netstat = safeExec('netstat -ano | findstr :3010', '');
  if (netstat) {
    portInfo += 'Port 3010: FOUND\n' + netstat + '\n';
    try {
      const http = require('http');
      portInfo += '\nAttempting health check...\n';
      await new Promise((resolve) => {
        const req = http.get('http://localhost:3010/health', { timeout: 3000 }, (r) => {
          let body = '';
          r.on('data', c => body += c);
          r.on('end', () => { portInfo += `HTTP ${r.statusCode}\n${body}\n`; resolve(); });
        });
        req.on('error', e => { portInfo += 'Health check failed: ' + e.message + '\n'; resolve(); });
        req.on('timeout', () => { req.destroy(); portInfo += 'Health check timed out\n'; resolve(); });
      });
    } catch {}
  } else {
    portInfo += 'Port 3010: NOT LISTENING (collector service is not running)\n';
  }
  entries.push({ name: '06-port-check.txt', data: Buffer.from(sanitize(portInfo), 'utf8') });

  // 7. Event Log
  log('warn', '[7/7] Collecting Windows Event Log...');
  const eventLog = safeExec(
    'powershell -Command "Get-WinEvent -FilterHashtable @{LogName=\'Application\'; ProviderName=\'*FlowGuard*\'} -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated,LevelDisplayName,Id,Message | Format-List"',
    'No FlowGuard events found in Event Log.'
  );
  entries.push({ name: '07-event-log.txt', data: Buffer.from(sanitize(eventLog), 'utf8') });

  // ─── Write ZIP ──────────────────────────────────────────
  // Save to <InstallDir>\support\ if available, otherwise real user Desktop
  let fallbackHome = os.homedir();
  if (fallbackHome.includes('systemprofile')) {
    try {
      const logged = execSync('powershell -NoProfile -Command "(Get-CimInstance Win32_ComputerSystem).UserName"', { encoding: 'utf8' }).trim();
      if (logged.includes('\\')) fallbackHome = path.join('C:', 'Users', logged.split('\\').pop());
    } catch(_) {}
  }
  const supportDir = installDir ? path.join(installDir, 'support') : path.join(fallbackHome, 'Desktop');
  if (!fs.existsSync(supportDir)) fs.mkdirSync(supportDir, { recursive: true });
  const zipName = `FlowGuard-Diag-${hostname}-${stamp}.zip`;
  const zipPath = path.join(supportDir, zipName);
  createZip(entries, zipPath);

  const zipSize = Math.round(fs.statSync(zipPath).size / 1024 * 100) / 100;

  log('ok',   '');
  log('ok',   '================================================');
  log('ok',   '  DONE - Diagnostics ZIP created');
  log('ok',   '================================================');
  log('info', '');
  log('info', 'File: ' + zipPath);
  log('info', 'Size: ' + zipSize + ' KB');
  log('info', '');

  // ─── Open mail client ───────────────────────────────────
  const subject = `FlowGuard Diagnostics - ${hostname} - ${now.toISOString().slice(0, 16)}`;
  const body = [
    'Hi Eran,',
    '',
    'Attached: FlowGuard diagnostics report (Standalone).',
    '',
    `Hostname:  ${hostname}`,
    `Date:      ${now.toISOString()}`,
    `File size: ${zipSize} KB`,
    `File path: ${zipPath}`,
    '',
    'Describe the issue here:',
    '[What were you trying to do? What happened? What error did you see?]',
    '',
    '--',
    'IMPORTANT: Please DRAG the ZIP file from the File Explorer window',
    '(which just opened) into this email before sending.',
    '',
    'All sensitive data has been sanitized automatically.'
  ].join('\n');

  const mailto = `mailto:${SUPPORT_EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;

  log('info', 'Opening your default mail client...');
  log('dim',  'To: ' + SUPPORT_EMAIL);
  log('info', '');
  log('warn', 'ACTION REQUIRED:');
  log('info', '  1. Drag the ZIP file from File Explorer into the email');
  log('info', '  2. Add a short description of your issue');
  log('info', '  3. Click Send');
  log('info', '');

  // Open File Explorer with ZIP selected
  exec(`explorer.exe /select,"${zipPath}"`);

  // Open default mail client
  exec(`start "" "${mailto}"`, { shell: true });

  log('dim',  'All sensitive data (tokens, passwords, username) has been sanitized.');
  log('info', '');
  log('dim',  'Press any key to exit...');

  // Wait for keypress
  process.stdin.setRawMode?.(true);
  process.stdin.resume();
  process.stdin.once('data', () => process.exit(0));
}

main().catch(err => {
  log('err', 'ERROR: ' + err.message);
  log('err', err.stack);
  console.log('\nPress any key to exit...');
  process.stdin.setRawMode?.(true);
  process.stdin.resume();
  process.stdin.once('data', () => process.exit(1));
});
