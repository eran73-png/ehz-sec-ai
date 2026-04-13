'use strict';
/**
 * FlowGuard — System Tray (MS8.8)
 * Menu: version, dashboard, collector status, service control, stats, exit
 */

const SysTray  = require('systray2').default;
const http     = require('http');
const path     = require('path');
const os       = require('os');
const { exec } = require('child_process');

const APP_VERSION    = 'v1.0.7';
const COLLECTOR_URL  = 'http://localhost:3010';
const DASHBOARD_FILE = path.join(__dirname, '..', 'dashboard', 'index.html');
const ICON_PATH      = path.join(__dirname, 'flowguard.ico');
const CHECK_INTERVAL = 10000;
const PC_NAME        = os.hostname();
const SERVICE_NAME   = 'FlowGuardCollector';

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

function openDashboard() {
  exec(`start "" "${DASHBOARD_FILE}"`);
}

function controlService(action, cb) {
  const psCmd = action === 'stop'
    ? `Stop-Service ${SERVICE_NAME} -Force`
    : `Start-Service ${SERVICE_NAME}`;
  // RunAs required to start/stop Windows Services
  exec(
    `powershell -Command "Start-Process powershell -Verb RunAs -ArgumentList '-Command ${psCmd}' -Wait"`,
    { timeout: 20000 },
    (err) => cb(err)
  );
}

function sep() {
  return { title: '\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500', tooltip: '', checked: false, enabled: false };
}

// ── Menu items ────────────────────────────────────────────────────────────────

// 0  : FlowGuard v1.0.4 | PC: NAME
// 1  : Open Dashboard
// 2  : separator
// 3  : Collector status (display only)
// 4  : Start / Stop Service
// 5  : separator
// 6  : Stats
// 7  : separator
// 8  : Exit

function collectorStatusItem(online) {
  return {
    title:   online ? '\uD83D\uDFE2 Collector: RUNNING' : '\uD83D\uDD34 Collector: OFFLINE',
    tooltip: online ? 'Collector is running on port 3010' : 'Collector is not responding',
    checked: false,
    enabled: false,
  };
}

function serviceControlItem(online) {
  return online
    ? { title: '\u25A0 Stop Service',  tooltip: 'Stop FlowGuardCollector Windows Service',  checked: false, enabled: true }
    : { title: '\u25BA Start Service', tooltip: 'Start FlowGuardCollector Windows Service', checked: false, enabled: true };
}

function buildMenu(stats, online) {
  return [
    /* 0 */ { title: `FlowGuard ${APP_VERSION} | PC: ${PC_NAME}`, tooltip: 'FlowGuard AI Security Monitor', checked: false, enabled: false },
    /* 1 */ { title: 'Open Dashboard', tooltip: 'Open FlowGuard dashboard', checked: false, enabled: true },
    /* 2 */ sep(),
    /* 3 */ collectorStatusItem(online),
    /* 4 */ serviceControlItem(online),
    /* 5 */ sep(),
    /* 6 */ { title: 'Exit FlowGuard', tooltip: 'Stop tray and exit', checked: false, enabled: true },
  ];
}

// ── Fetch data ────────────────────────────────────────────────────────────────

function fetchAll(cb) {
  apiGet('/stats', (err, s) => {
    if (err || !s) return cb({ stats: null, online: false });
    apiGet('/config', (err2, cfg) => {
      cb({
        stats: {
          ok:       true,
          total:    s.total    || 0,
          critical: s.critical || 0,
          high:     s.high     || 0,
          level:    (!err2 && cfg) ? (cfg.name  || 'SOFT') : 'SOFT',
          emoji:    (!err2 && cfg) ? (cfg.emoji || '\u26AA') : '\u26AA',
        },
        online: true,
      });
    });
  });
}

// ── Main ──────────────────────────────────────────────────────────────────────

console.log('[FlowGuard Tray] Starting...');

fetchAll(({ stats, online }) => {
  const tooltip = online
    ? `FlowGuard ${APP_VERSION} | ${stats.emoji} ${stats.level} | ${stats.total} events`
    : `FlowGuard ${APP_VERSION} — Collector OFFLINE`;

  const tray = new SysTray({
    menu: {
      icon:    ICON_PATH,
      title:   '',
      tooltip: tooltip,
      items:   buildMenu(stats, online),
    },
    debug:   false,
    copyDir: true,
  });

  console.log('[FlowGuard Tray] Tray icon active');

  let _online = online;
  let _stats  = stats;

  // ── Click handler ───────────────────────────────────────────────────────────
  tray.onClick((action) => {
    const id = action.seq_id;

    if (id === 1) {
      openDashboard();

    } else if (id === 4) {
      // Start / Stop Service
      const action = _online ? 'stop' : 'start';
      controlService(action, (err) => {
        if (err) {
          console.error('[FlowGuard Tray] Service control error:', err.message);
        }
        // Wait 3s then refresh status
        setTimeout(() => {
          fetchAll(({ stats: s, online: o }) => {
            _online = o;
            _stats  = s;
            tray.sendAction({ type: 'update-item', seq_id: 3, item: collectorStatusItem(o) });
            tray.sendAction({ type: 'update-item', seq_id: 4, item: serviceControlItem(o) });
            tray.sendAction({ type: 'update-item', seq_id: 6, item: statsItem(s) });
          });
        }, 3000);
      });

    } else if (id === 6) {
      console.log('[FlowGuard Tray] Exiting...');
      tray.kill();
      process.exit(0);
    }
  });

  // ── Periodic refresh ────────────────────────────────────────────────────────
  setInterval(() => {
    fetchAll(({ stats: s, online: o }) => {
      _online = o;
      _stats  = s;
      tray.sendAction({ type: 'update-item', seq_id: 3, item: collectorStatusItem(o) });
      tray.sendAction({ type: 'update-item', seq_id: 4, item: serviceControlItem(o) });
      const tip = o
        ? `FlowGuard ${APP_VERSION} | Collector RUNNING`
        : `FlowGuard ${APP_VERSION} — Collector OFFLINE`;
      tray.sendAction({ type: 'update-tooltip', tooltip: tip });
    });
  }, CHECK_INTERVAL);

  process.on('uncaughtException', (err) => {
    console.error('[FlowGuard Tray] Error:', err.message);
  });
});
