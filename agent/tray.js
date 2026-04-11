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
// FlowGuard logo 32x32 PNG
const ICON_ACTIVE = 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAEvElEQVR4nM1XS2tdVRT+1j6Pe5PcWqPRlDYo2gYqgg7UFCmJtNqBiBMn4sg/4B/yBzgRRHCggqATpTVaRdGBExMsBkKKrcntvfe89pa19uPsc3Iz1LjDvefc/Vprfetbj9Di6jMGIMggfpL82Sn728+fuGfOuuyJ75BhkCjC34dHePWVK/jio/eRyi4ikJb1aK8X0A4R2ptx91o9+MtQe1Re/B7eZOQhr26kcsxdYIJl86yxc7LnBIu94PaO1nJ5DQa2Wih+sbr17bPWeDs7e4IFrRAvmPccG3KY5bDgzgWwCMRCO9bZL8MuClsiXsTWx07pW+9WPYbtPJDSPOijS9prHPTxJxDNIxbxoiNMvN8lmZmLAI8OHgHS8B2Ma3nR4UOshIOb/8gzr8fCVHSKoOyHXyuYAGXXiVTkLi/YneWnGKsDefy0CA5Kexdgfmh1oA8+j5RjHbzwsNsr0VobKB7410MAQVysiCVeUKQPuwDAwoIW7VOsdJHmHWj6HLC/rALziBegdQKUsu4IbiAYnnNnbALqEN6CEQTHw0eEzwPziOeJxC9pCiSRpaRgeM4JtrHPOioksi+C3xgokOgcoPc5IY4CRDjbmHfPQQKsnAE1Grg/AYwCqhL0oABGI5h8KJex8PHRGLpu8PBoBN00oqhKFIqiQF03GAwyGO04QXMRoOBq8VSqQCtLIFUDQwCPLonw5tJllG+/C716AeqvAyTlDMXBATZfeh5vvXEd9+7exYPJFIdHY9zb28fa+VU89+w6iulMXNhyIiDQj3nnDvGxAc4/BrBF+4egcoZmYxPV1S2Yh5bRvHAFmE6hkhTvvfMadn/5FaQ1zp4ZYbS4gHJW4trWBj755Et8/91PWFhkxHzV65CQuulWwkyBqinKrdeh/txBeucrQCV2aX8fzYsvQ2uN+uwyFvIcA+zizRtbuHHtKpq6xrnHV/Dt7Z9xef0pfPjx55a8HUq6PIC4QMVKNAZGZVB7u1B7fwCUwOQDqB+3oba/gb64DugGeVmgKBt8sKzw9BNrmEwmYv1sWuDrWz/g+uYGft+9gzzLoBtt7e3mAXIx74T7xMKwmyGS7ZtWuUYBSYalnd+gkgzJ3g4oSVDXNR5JU3xaadRVhaosUY2nwq4sy3Dr5m3ki0MMhjm00UhC7nAKUCf/RBxgV40rYJBZjSeVTFd5DkoTEOUCmx5kqImQ5xp5mcBkKZrBQM5wVCwNB2i0Fne1otpsmBoTJZ5QrFyymdag+zM7X2rxY1NWDh0HpSLUTCwWUGuAQ1YM4DkD7TohDjvOC91sBUbARuTxguQig1FQBJKoIFDjLvfmiMCo2vF9vB4RrdMr9IayC76M+nOudXBpnaTC2eClDopRl8PrnGi0s9Dt96WYP91i5F0AXyH71js39OqjNbSbz9s064W3TWhbijs+bl2gON6PtWLH+wHpAeLup1dkRFSUYiWyXMiFFp4po/jTdlLpbFb0esFePx9XRusPZ0hkrYPcMBn5t9ZdwkV7uGDpyRRFUVoFLl188gTB0Xvc2vis1fojCivHgcjH/Xe2ngvX2oVz1q6iLPsF+98f4gpCmqZMzvj/lP9+pKcm3xE8bVvr0xnqVKX/HxT4B4vZMTlk5u+fAAAAAElFTkSuQmCC';

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
