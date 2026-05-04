'use strict';
/**
 * FlowGuard Auto-Updater — MS10
 * Checks GitHub Releases for new FlowGuard versions
 * Downloads, backs up, extracts, and restarts
 */

const fs    = require('fs');
const path  = require('path');
const https = require('https');
const { execSync } = require('child_process');

const ROOT_DIR    = path.join(__dirname, '..');
const BACKUP_DIR  = path.join(ROOT_DIR, 'update-backups');
const STATE_FILE  = path.join(__dirname, 'update-state.json');
const GITHUB_REPO = 'eran73-png/ehz-sec-ai';
const GITHUB_API  = `https://api.github.com/repos/${GITHUB_REPO}/releases/latest`;

// Folders to update (skip node_modules, .env, license.json, update-backups, dist, .git)
const UPDATE_FOLDERS = ['collector', 'dashboard', 'agent', 'docs', 'install'];
const UPDATE_FILES   = ['package.json'];
const KEEP_FILES     = ['license.json', '.env', 'collector/ccsm.db', 'collector/notifications.json',
                        'collector/app-config.json', 'agent/skill-registry.json'];

function loadState() {
  try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); }
  catch(_) { return { lastCheck: null, latestVersion: null, downloadUrl: null, changelog: '' }; }
}

function saveState(state) {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), 'utf8');
}

function getCurrentVersion() {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT_DIR, 'package.json'), 'utf8'));
    return pkg.version;
  } catch(_) { return '0.0.0'; }
}

function compareVersions(a, b) {
  const pa = a.replace(/^v/, '').split('.').map(Number);
  const pb = b.replace(/^v/, '').split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) > (pb[i] || 0)) return 1;
    if ((pa[i] || 0) < (pb[i] || 0)) return -1;
  }
  return 0;
}

function httpsGet(url) {
  return new Promise((resolve, reject) => {
    const opts = { headers: { 'User-Agent': 'FlowGuard-Updater' } };
    https.get(url, opts, (res) => {
      // Follow redirects
      if (res.statusCode === 301 || res.statusCode === 302) {
        return httpsGet(res.headers.location).then(resolve).catch(reject);
      }
      let data = '';
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode}`));
      }
      res.on('data', c => data += c);
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

function httpsDownload(url, dest) {
  return new Promise((resolve, reject) => {
    const opts = { headers: { 'User-Agent': 'FlowGuard-Updater' } };
    https.get(url, opts, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        return httpsDownload(res.headers.location, dest).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode}`));
      }
      const file = fs.createWriteStream(dest);
      res.pipe(file);
      file.on('finish', () => { file.close(); resolve(); });
    }).on('error', reject);
  });
}

async function checkForUpdate() {
  const current = getCurrentVersion();
  const json = await httpsGet(GITHUB_API);
  const release = JSON.parse(json);
  const latest = (release.tag_name || '').replace(/^v/, '');
  const isNewer = compareVersions(latest, current) > 0;

  // Find zip asset
  let downloadUrl = null;
  if (release.assets && release.assets.length > 0) {
    const zip = release.assets.find(a => a.name.endsWith('.zip'));
    if (zip) downloadUrl = zip.browser_download_url;
  }
  // Fallback to zipball
  if (!downloadUrl) {
    downloadUrl = release.zipball_url;
  }

  const state = {
    lastCheck: new Date().toISOString(),
    latestVersion: latest,
    currentVersion: current,
    updateAvailable: isNewer,
    downloadUrl,
    changelog: release.body || '',
    releaseName: release.name || `v${latest}`,
  };
  saveState(state);
  return state;
}

async function applyUpdate() {
  const state = loadState();
  if (!state.updateAvailable || !state.downloadUrl) {
    throw new Error('No update available');
  }

  const current = getCurrentVersion();
  const tmpDir = path.join(ROOT_DIR, 'update-tmp');
  const zipPath = path.join(tmpDir, 'update.zip');

  // 1. Create temp dir
  if (fs.existsSync(tmpDir)) fs.rmSync(tmpDir, { recursive: true });
  fs.mkdirSync(tmpDir, { recursive: true });

  // 2. Download zip
  console.log(`[Updater] Downloading v${state.latestVersion}...`);
  await httpsDownload(state.downloadUrl, zipPath);

  // 3. Backup current version
  if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
  const backupName = `flowguard-v${current}-${Date.now()}`;
  const backupPath = path.join(BACKUP_DIR, backupName);
  fs.mkdirSync(backupPath, { recursive: true });

  for (const folder of UPDATE_FOLDERS) {
    const src = path.join(ROOT_DIR, folder);
    if (fs.existsSync(src)) {
      copyDirSync(src, path.join(backupPath, folder));
    }
  }
  for (const file of UPDATE_FILES) {
    const src = path.join(ROOT_DIR, file);
    if (fs.existsSync(src)) {
      fs.copyFileSync(src, path.join(backupPath, file));
    }
  }
  console.log(`[Updater] Backed up v${current} to ${backupPath}`);

  // 4. Extract zip — use safe paths (no user input in shell commands)
  console.log('[Updater] Extracting...');
  try {
    const safeZip = path.resolve(zipPath).replace(/'/g, "''");
    const safeDest = path.resolve(tmpDir, 'extracted').replace(/'/g, "''");
    execSync(`powershell -NoProfile -Command "Expand-Archive -Path '${safeZip}' -DestinationPath '${safeDest}' -Force"`, { timeout: 60000 });
  } catch(e) {
    throw new Error('Failed to extract update: ' + e.message);
  }

  // Find the extracted root (GitHub zips have a nested folder)
  const extracted = path.join(tmpDir, 'extracted');
  let updateRoot = extracted;
  const entries = fs.readdirSync(extracted);
  if (entries.length === 1 && fs.statSync(path.join(extracted, entries[0])).isDirectory()) {
    updateRoot = path.join(extracted, entries[0]);
  }

  // 5. Copy new files over (skip KEEP_FILES)
  for (const folder of UPDATE_FOLDERS) {
    const src = path.join(updateRoot, folder);
    const dest = path.join(ROOT_DIR, folder);
    if (fs.existsSync(src)) {
      // Remove old folder (except keep files)
      if (fs.existsSync(dest)) {
        const keepInFolder = KEEP_FILES.filter(f => f.startsWith(folder + '/'));
        const keepNames = keepInFolder.map(f => f.split('/').slice(1).join('/'));
        removeDirExcept(dest, keepNames);
      }
      copyDirSync(src, dest);
    }
  }
  for (const file of UPDATE_FILES) {
    const src = path.join(updateRoot, file);
    if (fs.existsSync(src)) {
      fs.copyFileSync(src, path.join(ROOT_DIR, file));
    }
  }

  // 6. Cleanup tmp
  fs.rmSync(tmpDir, { recursive: true, force: true });

  // 7. Update state
  state.updateAvailable = false;
  state.currentVersion = state.latestVersion;
  state.lastApplied = new Date().toISOString();
  state.backupPath = backupPath;
  saveState(state);

  console.log(`[Updater] Updated to v${state.latestVersion}. Restart required.`);
  return { ok: true, version: state.latestVersion, backupPath, restartRequired: true };
}

async function rollback() {
  const state = loadState();
  if (!state.backupPath || !fs.existsSync(state.backupPath)) {
    throw new Error('No backup available for rollback');
  }

  for (const folder of UPDATE_FOLDERS) {
    const src = path.join(state.backupPath, folder);
    const dest = path.join(ROOT_DIR, folder);
    if (fs.existsSync(src)) {
      if (fs.existsSync(dest)) fs.rmSync(dest, { recursive: true });
      copyDirSync(src, dest);
    }
  }
  for (const file of UPDATE_FILES) {
    const src = path.join(state.backupPath, file);
    if (fs.existsSync(src)) {
      fs.copyFileSync(src, path.join(ROOT_DIR, file));
    }
  }

  console.log(`[Updater] Rolled back to backup: ${state.backupPath}`);
  return { ok: true, rolledBackTo: state.backupPath };
}

// ── Helpers ──

function copyDirSync(src, dest) {
  if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, entry.name);
    const d = path.join(dest, entry.name);
    if (entry.isDirectory()) copyDirSync(s, d);
    else fs.copyFileSync(s, d);
  }
}

function removeDirExcept(dir, keepNames) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (keepNames.includes(entry.name)) continue;
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) fs.rmSync(p, { recursive: true });
    else fs.unlinkSync(p);
  }
}

module.exports = { checkForUpdate, applyUpdate, rollback, getCurrentVersion, loadState };
