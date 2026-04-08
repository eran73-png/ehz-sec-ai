'use strict';
/**
 * EHZ-SEC-AI — Collector
 * Express server (port 3010) — קולט events מה-Hook
 * שומר ב-NeDB (pure JS, ללא native compilation) → שולח Telegram alerts
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const express  = require('express');
const Datastore = require('@seald-io/nedb');
const https    = require('https');
const path     = require('path');
const fs       = require('fs');

// ─── Config ─────────────────────────────────────────────────────────────────

const PORT           = process.env.PORT           || 3010;
const TELEGRAM_TOKEN = process.env.TELEGRAM_TOKEN  || '';
const TELEGRAM_CHAT  = process.env.TELEGRAM_CHAT_ID || '';
const DB_PATH        = path.join(__dirname, 'ccsm.db');

const RETENTION_DAYS = 30;
const MAX_EVENTS     = 10000;

// ─── DB Init ─────────────────────────────────────────────────────────────────

const db = new Datastore({ filename: DB_PATH, autoload: true });

// Indexes for fast queries
db.ensureIndex({ fieldName: 'ts' });
db.ensureIndex({ fieldName: 'level' });
db.ensureIndex({ fieldName: 'tool_name' });

// ─── Retention: TTL 30d + FIFO 10k ──────────────────────────────────────────

function enforceRetention() {
  const cutoff = Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000;

  // 1. מחק events ישנים מ-30 יום
  db.remove({ ts: { $lt: cutoff } }, { multi: true }, (err, n1) => {
    if (n1 > 0) console.log(`[Retention] מחיקת ${n1} events ישנים (>${RETENTION_DAYS} יום)`);

    // 2. FIFO — אם עדיין מעל 10,000 מחק הכי ישנים
    db.count({}, (err, total) => {
      if (total <= MAX_EVENTS) return;
      const excess = total - MAX_EVENTS;
      db.find({}).sort({ ts: 1 }).limit(excess).exec((err, docs) => {
        if (err || !docs.length) return;
        const ids = docs.map(d => d._id);
        db.remove({ _id: { $in: ids } }, { multi: true }, (err, n2) => {
          if (n2 > 0) console.log(`[Retention] FIFO — מחיקת ${n2} events עודפים (מעל ${MAX_EVENTS})`);
        });
      });
    });
  });
}

// הרץ retention פעם ביום (86400000ms) + מיד בהפעלה
enforceRetention();
setInterval(enforceRetention, 24 * 60 * 60 * 1000);

// ─── Telegram ────────────────────────────────────────────────────────────────

function sendTelegram(text) {
  if (!TELEGRAM_TOKEN || !TELEGRAM_CHAT) return;

  const body = JSON.stringify({ chat_id: TELEGRAM_CHAT, text, parse_mode: 'HTML' });
  const req  = https.request({
    hostname: 'api.telegram.org',
    path:     `/bot${TELEGRAM_TOKEN}/sendMessage`,
    method:   'POST',
    headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
  });
  req.on('error', (e) => console.error('[Telegram]', e.message));
  req.write(body);
  req.end();
}

function buildTelegramMsg(ev) {
  const emoji = ev.level === 'CRITICAL' ? '🚨' : ev.level === 'HIGH' ? '⚠️' : 'ℹ️';
  const ts    = new Date(ev.ts).toLocaleString('he-IL', { timeZone: 'Asia/Jerusalem' });
  return `${emoji} <b>EHZ-SEC-AI — ${ev.level}</b>\n` +
         `🔧 כלי: <code>${ev.tool_name}</code>\n` +
         `📌 Hook: ${ev.hook_type}\n` +
         (ev.reason ? `⚡ סיבה: ${ev.reason}\n` : '') +
         `🕐 ${ts}`;
}

// ─── Express ─────────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());

// CORS for dashboard
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

// POST /event — Hook → Collector
app.post('/event', (req, res) => {
  const ev = req.body;

  if (!ev || !ev.tool_name) {
    return res.status(400).json({ error: 'missing tool_name' });
  }

  const doc = {
    ts:             ev.ts            || Date.now(),
    hook_type:      ev.hook_type     || 'unknown',
    tool_name:      ev.tool_name,
    session_id:     ev.session_id    || 'unknown',
    level:          ev.level         || 'INFO',
    reason:         ev.reason        || null,
    rule_type:      ev.rule_type     || null,
    input_summary:  ev.input_summary  || null,
    output_summary: ev.output_summary || null,
    telegram_sent:  false,
    created_at:     new Date().toISOString(),
  };

  db.insert(doc, (err, newDoc) => {
    if (err) {
      console.error('[DB]', err.message);
      return res.status(500).json({ error: 'db error' });
    }

    // Send Telegram for HIGH / CRITICAL
    if (['HIGH', 'CRITICAL'].includes(doc.level)) {
      sendTelegram(buildTelegramMsg(doc));
      db.update({ _id: newDoc._id }, { $set: { telegram_sent: true } }, {});
    }

    res.json({ ok: true, id: newDoc._id, level: doc.level });
  });
});

// GET /events — Dashboard feed
app.get('/events', (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit)  || 100, 500);
  const level  = req.query.level || null;

  const query = level ? { level } : {};

  db.find(query).sort({ ts: -1 }).limit(limit).exec((err, docs) => {
    if (err) return res.status(500).json({ error: err.message });
    db.count({}, (err2, total) => {
      res.json({ events: docs, total: err2 ? 0 : total });
    });
  });
});

// GET /stats — Dashboard summary
app.get('/stats', (req, res) => {
  db.count({},                    (e1, total)    => {
  db.count({ level: 'CRITICAL' }, (e2, critical) => {
  db.count({ level: 'HIGH' },     (e3, high)     => {
    db.find({}).sort({ ts: -1 }).limit(1).exec((e4, last) => {
      db.find({}, { session_id: 1, _id: 0 }, (e5, docs) => {
        const sessions = new Set((docs || []).map(d => d.session_id)).size;
        res.json({
          total:    total    || 0,
          critical: critical || 0,
          high:     high     || 0,
          sessions: sessions || 0,
          last_ts:  last[0]  ? last[0].ts : null,
        });
      });
    });
  });});});
});

// GET /config — return current hardening level
app.get('/config', (req, res) => {
  let hardening;
  try { hardening = require('../config/hardening'); } catch (_) {}
  if (!hardening) return res.json({ hardening_level: 1 });
  const level = hardening.getLevel();
  const cfg   = hardening.getLevelConfig(level);
  res.json({ hardening_level: level, name: cfg.name, emoji: cfg.emoji, description: cfg.description });
});

// POST /config — set hardening level
app.post('/config', (req, res) => {
  const { hardening_level } = req.body || {};
  if (hardening_level === undefined) return res.status(400).json({ error: 'missing hardening_level' });
  let hardening;
  try { hardening = require('../config/hardening'); } catch (_) {}
  if (!hardening) return res.status(500).json({ error: 'hardening module not available' });
  const newLevel = hardening.setLevel(hardening_level);
  const cfg      = hardening.getLevelConfig(newLevel);
  res.json({ ok: true, hardening_level: newLevel, name: cfg.name, emoji: cfg.emoji });
});

// ─── Skills (Milestone 5) ─────────────────────────────────────────────────────

let skillScanner;
try { skillScanner = require('../agent/skill-scanner'); } catch (_) {}

// GET /skills — last scan results (from registry file)
app.get('/skills', (req, res) => {
  if (!skillScanner) return res.status(500).json({ error: 'skill-scanner not available' });
  try {
    const registryPath = require('path').join(__dirname, '..', 'agent', 'skill-registry.json');
    const registry = require('fs').existsSync(registryPath)
      ? JSON.parse(require('fs').readFileSync(registryPath, 'utf8'))
      : {};
    res.json({ skills: registry, count: Object.keys(registry).length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /skills/scan — run a fresh scan now
app.post('/skills/scan', (req, res) => {
  if (!skillScanner) return res.status(500).json({ error: 'skill-scanner not available' });
  try {
    const result = skillScanner.scanAllSkills();

    // Send Telegram for CRITICAL or CHANGED skills
    result.skills.forEach(s => {
      if (['CRITICAL', 'SUSPICIOUS'].includes(s.status)) {
        const emoji = s.status === 'CRITICAL' ? '🚨' : '🔶';
        sendTelegram(`${emoji} <b>EHZ-SEC-AI — Skill Alert</b>\n🔧 Skill: <code>${s.name}</code>\n📌 סטטוס: ${s.status}\n⚡ ${s.findings.map(f=>f.reason).join(', ')}`);
      }
      if (s.hash_changed) {
        sendTelegram(`⚠️ <b>EHZ-SEC-AI — Skill Changed</b>\n🔧 Skill: <code>${s.name}</code>\n📌 Hash השתנה — ייתכן שהסקיל עודכן או שונה`);
      }
    });

    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── File Audit (Milestone 6.3) ──────────────────────────────────────────────

let fileAuditScanner;
try { fileAuditScanner = require('../agent/file-audit-scanner'); } catch (_) {}

const AUDIT_RESULT_FILE = path.join(__dirname, 'file-audit-result.json');

// GET /audit — last scan results
app.get('/audit', (req, res) => {
  try {
    if (fs.existsSync(AUDIT_RESULT_FILE)) {
      const data = JSON.parse(fs.readFileSync(AUDIT_RESULT_FILE, 'utf8'));
      return res.json(data);
    }
    res.json({ files: [], summary: null, msg: 'לא נמצאה סריקה קודמת' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /audit/export — export to Excel
app.get('/audit/export', async (req, res) => {
  try {
    if (!fs.existsSync(AUDIT_RESULT_FILE))
      return res.status(404).json({ error: 'אין תוצאות סריקה — הפעל סריקה קודם' });

    const data    = JSON.parse(fs.readFileSync(AUDIT_RESULT_FILE, 'utf8'));
    const ExcelJS = require('exceljs');
    const wb      = new ExcelJS.Workbook();
    wb.creator    = 'EHZ-SEC-AI';
    wb.created    = new Date();

    // ── Sheet 1: Summary ──
    const wsSummary = wb.addWorksheet('סיכום');
    wsSummary.views = [{ rightToLeft: true }];
    wsSummary.columns = [
      { header: 'פרמטר', key: 'k', width: 25 },
      { header: 'ערך',   key: 'v', width: 30 },
    ];
    const s = data.summary || {};
    [
      ['תיקייה סרוקה',   s.scan_path],
      ['תאריך סריקה',    s.scanned_at ? new Date(s.scanned_at).toLocaleString('he-IL') : ''],
      ['סה"כ קבצים',     s.total_files],
      ['תקין',           s.clean],
      ['MEDIUM',         s.medium],
      ['HIGH',           s.high],
      ['CRITICAL',       s.critical],
      ['דולגו',          s.skipped],
    ].forEach(([k,v]) => wsSummary.addRow({ k, v }));

    // ── Sheet 2: Findings ──
    const wsFindings = wb.addWorksheet('ממצאים');
    wsFindings.views = [{ rightToLeft: true }];
    wsFindings.columns = [
      { header: 'קובץ',       key: 'path',      width: 55 },
      { header: 'סיכון',      key: 'risk_label', width: 12 },
      { header: 'ציון',       key: 'risk_score', width: 8  },
      { header: 'רמה',        key: 'level',      width: 10 },
      { header: 'ממצא',       key: 'reason',     width: 35 },
      { header: 'שורה',       key: 'line',       width: 8  },
    ];

    // Header style
    wsFindings.getRow(1).eachCell(cell => {
      cell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
      cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF0D1424' } };
    });

    const colorMap = { CRITICAL: 'FFEF4444', HIGH: 'FFF97316', MEDIUM: 'FFF59E0B', OK: 'FF10B981' };

    (data.files || [])
      .sort((a,b) => b.risk_score - a.risk_score)
      .forEach(f => {
        if (!f.findings.length) return;
        f.findings.forEach((finding, i) => {
          const row = wsFindings.addRow({
            path:       i === 0 ? f.path : '',
            risk_label: i === 0 ? f.risk_label : '',
            risk_score: i === 0 ? f.risk_score : '',
            level:      finding.level,
            reason:     finding.reason,
            line:       finding.line,
          });
          // Color risk_label cell
          if (i === 0) {
            const labelCell = row.getCell('risk_label');
            labelCell.font = { bold: true, color: { argb: colorMap[f.risk_label] || 'FFFFFFFF' } };
          }
          const levelCell = row.getCell('level');
          levelCell.font = { color: { argb: colorMap[finding.level] || 'FFFFFFFF' } };
        });
      });

    // ── Sheet 3: All Clean Files ──
    const wsClean = wb.addWorksheet('קבצים תקינים');
    wsClean.views = [{ rightToLeft: true }];
    wsClean.columns = [{ header: 'קובץ', key: 'path', width: 60 }];
    wsClean.getRow(1).getCell(1).font = { bold: true };
    (data.all_files || []).filter(f => f.risk_label === 'OK').forEach(f => wsClean.addRow({ path: f.path }));

    // Send file
    const filename = `EHZ-SEC-AI-FileAudit-${new Date().toISOString().slice(0,10)}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    await wb.xlsx.write(res);
    res.end();
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /audit/scan — run scan now
// body: { scan_path: 'C:/Claude-Repo' } (optional)
app.post('/audit/scan', (req, res) => {
  if (!fileAuditScanner) return res.status(500).json({ error: 'file-audit-scanner not available' });
  try {
    const scanPath = (req.body && req.body.scan_path) || fileAuditScanner.DEFAULT_SCAN_PATH;
    const result   = fileAuditScanner.runFileAudit(scanPath);

    // Save result
    fs.writeFileSync(AUDIT_RESULT_FILE, JSON.stringify(result, null, 2), 'utf8');

    // Telegram alert for CRITICAL files
    result.files.forEach(f => {
      if (f.risk_label === 'CRITICAL') {
        sendTelegram(`🚨 <b>EHZ-SEC-AI — File Audit CRITICAL</b>\n📄 ${f.path}\n⚡ ${f.findings.map(x=>x.reason).join(', ')}`);
      }
    });

    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// DELETE /events — מחיקה ידנית (עם אפשרות לפי גיל)
// body: { older_than_days: N } — אם לא נשלח → מוחק הכל
app.delete('/events', (req, res) => {
  const days = req.body && req.body.older_than_days;
  const query = days ? { ts: { $lt: Date.now() - days * 24 * 60 * 60 * 1000 } } : {};
  db.remove(query, { multi: true }, (err, n) => {
    if (err) return res.status(500).json({ error: err.message });
    db.compactDatafile();
    res.json({ ok: true, deleted: n, msg: `נמחקו ${n} events` });
  });
});

// GET /retention — מדיניות שמירה נוכחית
app.get('/retention', (req, res) => {
  db.count({}, (err, total) => {
    const cutoff = new Date(Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000);
    res.json({
      retention_days: RETENTION_DAYS,
      max_events:     MAX_EVENTS,
      total_events:   total || 0,
      oldest_kept:    cutoff.toISOString(),
    });
  });
});

// GET /health
app.get('/health', (req, res) => res.json({ ok: true, ts: Date.now() }));

// ─── Start ───────────────────────────────────────────────────────────────────

app.listen(PORT, '127.0.0.1', () => {
  console.log(`[EHZ-SEC-AI] Collector listening on http://127.0.0.1:${PORT}`);
  console.log(`[EHZ-SEC-AI] DB: ${DB_PATH}`);
  console.log(`[EHZ-SEC-AI] Telegram: ${TELEGRAM_TOKEN ? 'configured ✓' : 'NOT configured'}`);

  // Startup Telegram ping
  if (TELEGRAM_TOKEN && TELEGRAM_CHAT) {
    sendTelegram('✅ <b>EHZ-SEC-AI</b> — Collector הופעל בהצלחה\n🖥️ ניטור Claude Code פעיל');
  }
});

process.on('SIGINT',  () => process.exit(0));
process.on('SIGTERM', () => process.exit(0));
