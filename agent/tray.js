'use strict';
/**
 * FlowGuard — System Tray (MS8.7)
 * Runs as a background process — shows status icon in Windows System Tray
 *
 * Usage: node agent/tray.js
 */

const SysTray = require('systray2').default;
const http    = require('http');
const path    = require('path');
const { exec } = require('child_process');

const COLLECTOR_URL = 'http://localhost:3010';
const DASHBOARD     = path.join(__dirname, '..', 'dashboard', 'index.html');
const CHECK_INTERVAL = 15000; // בדוק סטטוס כל 15 שניות

// ── Icon (base64 PNG 16x16) ───────────────────────────────────
// Shield icon — cyan on dark background
const ICON_ACTIVE = `iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABHNCSVQICAgIfAhkiAAAAAlwSFlz
AAALEgAACxIB0t1+/AAAABx0RVh0U29mdHdhcmUAQWRvYmUgRmlyZXdvcmtzIENTNXG14zYA
AAFsSURBVDiNpZM9a1RBFIZ37s7uvWuMiQlCQMgHiAhCijQBKws/wFqwEqwEK8E6jYWFhZWF
hYWVYGFjYWFjYWGTQiQkIYQQSAIhIYQkJIS9O3fOcR7c3c0mmyzswMDMe+Y888w5goh
IgLVWSymllAAAVVV9tNb6AAAAASUVORK5CYII=`;

const ICON_ERROR = ICON_ACTIVE; // same icon, title will show error

// ── Collector Status ──────────────────────────────────────────
function getStatus(cb) {
  const req = http.get(`${COLLECTOR_URL}/health`, { timeout: 3000 }, (res) => {
    let d = '';
    res.on('data', c => d += c);
    res.on('end', () => {
      try {
        http.get(`${COLLECTOR_URL}/stats`, { timeout: 3000 }, (res2) => {
          let d2 = '';
          res2.on('data', c => d2 += c);
          res2.on('end', () => {
            try {
              const stats = JSON.parse(d2);
              http.get(`${COLLECTOR_URL}/config`, { timeout: 3000 }, (res3) => {
                let d3 = '';
                res3.on('data', c => d3 += c);
                res3.on('end', () => {
                  try {
                    const cfg = JSON.parse(d3);
                    cb({
                      ok:       true,
                      total:    stats.total    || 0,
                      critical: stats.critical || 0,
                      high:     stats.high     || 0,
                      level:    cfg.name       || 'SOFT',
                      emoji:    cfg.emoji      || '🟢',
                    });
                  } catch(_) { cb({ ok: true, total: 0, critical: 0, high: 0, level: 'SOFT', emoji: '🟢' }); }
                });
              }).on('error', () => cb({ ok: true, total: stats.total || 0, critical: 0, high: 0, level: 'SOFT', emoji: '🟢' }));
            } catch(_) { cb({ ok: true, total: 0, critical: 0, high: 0, level: 'SOFT', emoji: '🟢' }); }
          });
        }).on('error', () => cb({ ok: true, total: 0, critical: 0, high: 0, level: 'SOFT', emoji: '🟢' }));
      } catch(_) { cb({ ok: false }); }
    });
  });
  req.on('error', () => cb({ ok: false }));
}

// ── Open Dashboard in browser ─────────────────────────────────
function openDashboard() {
  exec(`start "" "http://localhost:3010/dashboard"`, (err) => {
    if (err) {
      // fallback — open HTML file directly
      exec(`start "" "${DASHBOARD}"`);
    }
  });
}

// ── Build menu items ──────────────────────────────────────────
function buildMenu(status) {
  const statusTitle = status.ok
    ? `Status: ${status.emoji} ${status.level} | Events: ${status.total} | Critical: ${status.critical}`
    : 'Status: ❌ Collector offline';

  return [
    { title: 'Open Dashboard', tooltip: 'Open FlowGuard Dashboard', checked: false, enabled: true },
    { title: statusTitle,      tooltip: 'Current monitoring status', checked: false, enabled: false },
    { title: '────────────',   tooltip: '', checked: false, enabled: false },
    { title: 'Exit FlowGuard', tooltip: 'Stop tray and exit', checked: false, enabled: true },
  ];
}

// ── Main ──────────────────────────────────────────────────────
console.log('[FlowGuard Tray] Starting...');

getStatus((status) => {
  const trayTitle = status.ok
    ? `FlowGuard — Active (${status.level})`
    : 'FlowGuard — Collector Offline';

  const tray = new SysTray({
    menu: {
      icon:    ICON_ACTIVE,
      title:   '',
      tooltip: trayTitle,
      items:   buildMenu(status),
    },
    debug:    false,
    copyDir:  true,
  });

  tray.onClick((action) => {
    if (action.seq_id === 0) {
      // Open Dashboard
      openDashboard();
    } else if (action.seq_id === 3) {
      // Exit
      console.log('[FlowGuard Tray] Exiting...');
      tray.kill();
      process.exit(0);
    }
  });

  console.log('[FlowGuard Tray] ✅ Tray icon active');

  // ── Update status periodically ────────────────────────────
  setInterval(() => {
    getStatus((newStatus) => {
      const newTooltip = newStatus.ok
        ? `FlowGuard — Active (${newStatus.level}) | ${newStatus.total} events`
        : 'FlowGuard — Collector Offline';

      tray.sendAction({
        type:    'update-item',
        seq_id:  1,
        item:    {
          title: newStatus.ok
            ? `Status: ${newStatus.emoji} ${newStatus.level} | Events: ${newStatus.total} | Critical: ${newStatus.critical}`
            : 'Status: ❌ Collector offline',
          tooltip: newTooltip,
          checked: false,
          enabled: false,
        },
      });
    });
  }, CHECK_INTERVAL);

  process.on('uncaughtException', (err) => {
    console.error('[FlowGuard Tray] Error:', err.message);
  });
});
