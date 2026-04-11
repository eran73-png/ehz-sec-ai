'use strict';
/**
 * FlowGuard — System Tray (MS8.8)
 * Full tray menu: status, agent toggle, silent mode, stats, recent events, exit
 */

const SysTray  = require('systray2').default;
const http     = require('http');
const path     = require('path');
const os       = require('os');
const fs       = require('fs');
const { exec } = require('child_process');

const COLLECTOR_URL  = 'http://localhost:3010';
const DASHBOARD_URL  = 'http://localhost:3010/dashboard';
const DASHBOARD_FILE = path.join(__dirname, '..', 'dashboard', 'index.html');
const DISABLE_FILE   = path.join(__dirname, '..', '.ccsm-disable');
const ICON_PATH      = path.join(__dirname, 'flowguard.ico');
const CHECK_INTERVAL = 15000;
const PC_NAME        = os.hostname();

// ── Helpers ──────────────────────────────────────────────────────────────────

function apiGet(urlPath, cb) {
  const req = http.get(`${COLLECTOR_URL}${urlPath}`, { timeout: 3000 }, (res) => {
    let d = '';
    res.on('data', c => d += c);
    res.on('end', () => {
      try { cb(null, JSON.parse(d)); } catch(e) { cb(e); }
    });
  });
  req.on('error', cb);
}

function apiPost(urlPath, cb) {
  const req = http.request(`${COLLECTOR_URL}${urlPath}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': 2 },
    timeout: 3000,
  });
  req.on('response', (res) => {
    let d = '';
    res.on('data', c => d += c);
    res.on('end', () => { try { cb(null, JSON.parse(d)); } catch(e) { cb(e); } });
  });
  req.on('error', cb);
  req.write('{}');
  req.end();
}

function isAgentDisabled() {
  return fs.existsSync(DISABLE_FILE);
}

function openDashboard() {
  exec(`start "" "${DASHBOARD_URL}"`, (err) => {
    if (err) exec(`start "" "${DASHBOARD_FILE}"`);
  });
}

function sep() {
  return { title: '\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500', tooltip: '', checked: false, enabled: false };
}

function truncate(str, n) {
  if (!str) return '';
  return str.length > n ? str.slice(0, n) + '...' : str;
}

// ── Menu layout (fixed seq_ids) ───────────────────────────────────────────────
// 0  : PC info (disabled)
// 1  : Open Dashboard
// 2  : separator
// 3  : Agent toggle
// 4  : Silent Mode toggle
// 5  : separator
// 6  : Stats line (disabled)
// 7  : separator
// 8  : Recent event 1 (disabled)
// 9  : Recent event 2 (disabled)
// 10 : Recent event 3 (disabled)
// 11 : separator
// 12 : Exit FlowGuard

function buildInitMenu(stats, recentEvs, agentDisabled, silentOn) {
  return [
    /* 0  */ { title: `FlowGuard | PC: ${PC_NAME}`, tooltip: 'FlowGuard AI Security Monitor', checked: false, enabled: false },
    /* 1  */ { title: 'Open Dashboard', tooltip: 'Open FlowGuard dashboard in browser', checked: false, enabled: true },
    /* 2  */ sep(),
    /* 3  */ agentItem(agentDisabled),
    /* 4  */ silentItem(silentOn),
    /* 5  */ sep(),
    /* 6  */ statsItem(stats),
    /* 7  */ sep(),
    /* 8  */ recentItem(recentEvs, 0),
    /* 9  */ recentItem(recentEvs, 1),
    /* 10 */ recentItem(recentEvs, 2),
    /* 11 */ sep(),
    /* 12 */ { title: 'Exit FlowGuard', tooltip: 'Stop tray and exit', checked: false, enabled: true },
  ];
}

function agentItem(disabled) {
  return disabled
    ? { title: '[DISABLED] Agent is OFF — click to enable', tooltip: 'Agent is disabled (.ccsm-disable exists)', checked: false, enabled: true }
    : { title: '[ACTIVE]   Agent is ON  — click to disable', tooltip: 'Click to disable monitoring', checked: false, enabled: true };
}

function silentItem(silent) {
  return silent
    ? { title: '[SILENT]   Silent Mode ON  — click to unmute', tooltip: 'Telegram alerts suppressed', checked: true, enabled: true }
    : { title: '[ mute ]   Silent Mode OFF — click to mute',   tooltip: 'Click to suppress Telegram alerts', checked: false, enabled: true };
}

function statsItem(stats) {
  if (!stats || !stats.ok) return { title: 'Collector: OFFLINE', tooltip: '', checked: false, enabled: false };
  return {
    title: `Events: ${stats.total}  |  Critical: ${stats.critical}  |  High: ${stats.high}  |  ${stats.emoji} ${stats.level}`,
    tooltip: 'Today\'s security stats',
    checked: false,
    enabled: false,
  };
}

function recentItem(evs, idx) {
  const ev = evs && evs[idx];
  if (!ev) return { title: '  (no events yet)', tooltip: '', checked: false, enabled: false };
  const lvl  = (ev.level || 'INFO').padEnd(8);
  const tool = (ev.tool_name || '').padEnd(12);
  const reason = truncate(ev.reason || ev.hook_type || '', 42);
  return {
    title: `  ${lvl} ${tool} ${reason}`,
    tooltip: ev.reason || '',
    checked: false,
    enabled: false,
  };
}

// ── Fetch all data needed for menu ───────────────────────────────────────────

function fetchAll(cb) {
  let stats = null, recent = [], silentOn = false, done = 0;

  function finish() {
    done++;
    if (done === 3) cb({ stats, recent, silentOn });
  }

  // Stats + config
  apiGet('/stats', (err, s) => {
    if (!err && s) {
      apiGet('/config', (err2, cfg) => {
        stats = {
          ok:       true,
          total:    s.total    || 0,
          critical: s.critical || 0,
          high:     s.high     || 0,
          level:    (!err2 && cfg) ? (cfg.name  || 'SOFT') : 'SOFT',
          emoji:    (!err2 && cfg) ? (cfg.emoji || 'G')    : 'G',
        };
        finish();
      });
    } else {
      stats = { ok: false };
      finish();
    }
  });

  // Recent events
  apiGet('/recent?n=3', (err, evs) => {
    recent = err ? [] : (Array.isArray(evs) ? evs : []);
    finish();
  });

  // Silent mode
  apiGet('/silent', (err, s) => {
    silentOn = (!err && s) ? !!s.silent : false;
    finish();
  });
}

// ── Main ─────────────────────────────────────────────────────────────────────

console.log('[FlowGuard Tray] Starting...');

fetchAll(({ stats, recent, silentOn }) => {
  const agentDisabled = isAgentDisabled();

  const tooltip = stats && stats.ok
    ? `FlowGuard | ${stats.emoji} ${stats.level} | ${stats.total} events`
    : 'FlowGuard — Collector offline';

  const tray = new SysTray({
    menu: {
      icon:    ICON_PATH,
      title:   '',
      tooltip: tooltip,
      items:   buildInitMenu(stats, recent, agentDisabled, silentOn),
    },
    debug:   false,
    copyDir: true,
  });

  console.log('[FlowGuard Tray] Tray icon active');

  // ── Click handler ─────────────────────────────────────────────────────────
  tray.onClick((action) => {
    const id = action.seq_id;

    if (id === 1) {
      // Open Dashboard
      openDashboard();

    } else if (id === 3) {
      // Toggle agent enable/disable
      if (isAgentDisabled()) {
        try { fs.unlinkSync(DISABLE_FILE); } catch(_) {}
      } else {
        try { fs.writeFileSync(DISABLE_FILE, '', 'utf8'); } catch(_) {}
      }
      const nowDisabled = isAgentDisabled();
      tray.sendAction({ type: 'update-item', seq_id: 3, item: agentItem(nowDisabled) });
      tray.sendAction({ type: 'update-tooltip', tooltip: nowDisabled
        ? 'FlowGuard — AGENT DISABLED'
        : `FlowGuard | Events: ${(tray._lastStats && tray._lastStats.total) || 0}` });

    } else if (id === 4) {
      // Toggle silent mode
      apiPost('/silent', (err, r) => {
        const nowSilent = err ? false : !!r.silent;
        tray.sendAction({ type: 'update-item', seq_id: 4, item: silentItem(nowSilent) });
      });

    } else if (id === 12) {
      // Exit
      console.log('[FlowGuard Tray] Exiting...');
      tray.kill();
      process.exit(0);
    }
  });

  // ── Periodic refresh ──────────────────────────────────────────────────────
  setInterval(() => {
    fetchAll(({ stats: s, recent: evs, silentOn: silent }) => {
      tray._lastStats = s;
      const disabled = isAgentDisabled();

      // Update stats
      tray.sendAction({ type: 'update-item', seq_id: 6, item: statsItem(s) });
      // Update recent events
      tray.sendAction({ type: 'update-item', seq_id: 8,  item: recentItem(evs, 0) });
      tray.sendAction({ type: 'update-item', seq_id: 9,  item: recentItem(evs, 1) });
      tray.sendAction({ type: 'update-item', seq_id: 10, item: recentItem(evs, 2) });
      // Update agent + silent state
      tray.sendAction({ type: 'update-item', seq_id: 3, item: agentItem(disabled) });
      tray.sendAction({ type: 'update-item', seq_id: 4, item: silentItem(silent) });
      // Update tooltip
      const tip = disabled
        ? 'FlowGuard — AGENT DISABLED'
        : (s && s.ok
          ? `FlowGuard | ${s.emoji} ${s.level} | ${s.total} events`
          : 'FlowGuard — Collector offline');
      tray.sendAction({ type: 'update-tooltip', tooltip: tip });
    });
  }, CHECK_INTERVAL);

  process.on('uncaughtException', (err) => {
    console.error('[FlowGuard Tray] Error:', err.message);
  });
});
