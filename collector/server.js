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

// ─── Weekly Auto-Scan (MS6.7) ────────────────────────────────────────────────
// בדוק כל דקה אם הגיע זמן הסריקה השבועית (יום ראשון 04:00)
function checkWeeklyScan() {
  const now = new Date();
  // 0=ראשון, שעה 4, דקה 0, פחות מדקה
  if (now.getDay() === 0 && now.getHours() === 4 && now.getMinutes() === 0) {
    console.log('[Weekly Scan] Starting automatic weekly scan...');
    try {
      if (!fileAuditScanner) return;
      const result = fileAuditScanner.runFileAudit(fileAuditScanner.DEFAULT_SCAN_PATH);
      fs.writeFileSync(AUDIT_RESULT_FILE, JSON.stringify(result, null, 2), 'utf8');
      const critCount = result.files.filter(f => f.risk_label === 'CRITICAL').length;
      sendTelegram(
        `📋 <b>EHZ-SEC-AI — סריקה שבועית אוטומטית</b>\n` +
        `📁 ${result.summary.total_files} קבצים נסרקו\n` +
        `🚨 CRITICAL: ${result.summary.critical} | HIGH: ${result.summary.high} | MEDIUM: ${result.summary.medium}\n` +
        `✅ נקי: ${result.summary.clean}`
      );
      if (critCount > 0) {
        result.files.filter(f => f.risk_label === 'CRITICAL').forEach(f => {
          sendTelegram(`🚨 <b>CRITICAL</b>\n📄 ${f.path}\n⚡ ${f.findings.map(x => x.reason).join(', ')}`);
        });
      }
      console.log(`[Weekly Scan] Done — ${result.summary.total_files} files, ${critCount} CRITICAL`);
    } catch(e) {
      console.error('[Weekly Scan] Error:', e.message);
    }
  }
}
setInterval(checkWeeklyScan, 60 * 1000); // בדוק כל דקה

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

// GET /audit/export — export to Excel (single unified sheet)
app.get('/audit/export', async (req, res) => {
  try {
    if (!fs.existsSync(AUDIT_RESULT_FILE))
      return res.status(404).json({ error: 'אין תוצאות סריקה — הפעל סריקה קודם' });

    const data    = JSON.parse(fs.readFileSync(AUDIT_RESULT_FILE, 'utf8'));
    const ExcelJS = require('exceljs');
    const wb      = new ExcelJS.Workbook();
    wb.creator    = 'EHZ-SEC-AI';
    wb.created    = new Date();

    const s  = data.summary || {};
    const clr = {
      CRITICAL: { bg: 'FFEF4444', fg: 'FFFFFFFF' },
      HIGH:     { bg: 'FFF97316', fg: 'FFFFFFFF' },
      MEDIUM:   { bg: 'FFF59E0B', fg: 'FF000000' },
      OK:       { bg: 'FF10B981', fg: 'FFFFFFFF' },
    };

    const ws = wb.addWorksheet('דוח אבטחה — EHZ-SEC-AI');
    ws.views = [{ rightToLeft: true, showGridLines: false }];

    // ── Title row (A:E = 5 cols) ──
    ws.mergeCells('A1:E1');
    const titleCell = ws.getCell('A1');
    titleCell.value = '🛡️  EHZ-SEC-AI — דוח File Audit';
    titleCell.font  = { bold: true, size: 16, color: { argb: 'FFFFFFFF' } };
    titleCell.fill  = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF0D1424' } };
    titleCell.alignment = { horizontal: 'center', vertical: 'middle', readingOrder: 'rightToLeft' };
    ws.getRow(1).height = 38;

    // ── Subtitle / scan info ──
    ws.mergeCells('A2:E2');
    const subCell = ws.getCell('A2');
    subCell.value = `תיקייה: ${s.scan_path || ''}   |   תאריך: ${s.scanned_at ? new Date(s.scanned_at).toLocaleString('he-IL') : ''}`;
    subCell.font  = { size: 10, color: { argb: 'FF94A3B8' } };
    subCell.fill  = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF111827' } };
    subCell.alignment = { horizontal: 'center', vertical: 'middle', readingOrder: 'rightToLeft' };
    ws.getRow(2).height = 20;

    // ── Spacer ──
    ws.mergeCells('A3:E3');
    ws.getCell('A3').fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF0D1424' } };
    ws.getRow(3).height = 6;

    // ── Summary stats — 5 cards matching 5 columns ──
    const statLabels   = ['סה"כ קבצים', '✅ תקין', '⚠️ MEDIUM', '🔶 HIGH', '🚨 CRITICAL'];
    const statValues   = [s.total_files, s.clean, s.medium, s.high, s.critical];
    const statBgColors = ['FF1E293B', 'FF064E3B', 'FF78350F', 'FF431407', 'FF450A0A'];
    const statTxtColors= ['FFFFFFFF', 'FF10B981', 'FFF59E0B', 'FFF97316', 'FFEF4444'];
    const statCols     = ['A','B','C','D','E'];

    ws.getRow(4).height = 20;
    ws.getRow(5).height = 32;
    statLabels.forEach((lbl, i) => {
      const lCell = ws.getCell(`${statCols[i]}4`);
      lCell.value = lbl;
      lCell.font  = { bold: true, size: 9, color: { argb: statTxtColors[i] } };
      lCell.fill  = { type: 'pattern', pattern: 'solid', fgColor: { argb: statBgColors[i] } };
      lCell.alignment = { horizontal: 'center', vertical: 'middle' };

      const vCell = ws.getCell(`${statCols[i]}5`);
      vCell.value = statValues[i];
      vCell.font  = { bold: true, size: 18, color: { argb: statTxtColors[i] } };
      vCell.fill  = { type: 'pattern', pattern: 'solid', fgColor: { argb: statBgColors[i] } };
      vCell.alignment = { horizontal: 'center', vertical: 'middle' };
    });

    // Spacer
    ws.getRow(6).height = 10;

    // ── Table header — 5 columns: קובץ | תיקייה | סיכון | ציון | ממצאים ──
    const HDR_ROW = 7;
    const COLS = [
      { key: 'A', header: 'קובץ',     width: 32 },
      { key: 'B', header: 'תיקייה',   width: 38 },
      { key: 'C', header: 'סיכון',    width: 12 },
      { key: 'D', header: 'ציון',     width:  8 },
      { key: 'E', header: 'ממצאים',   width: 55 },
    ];
    COLS.forEach(({ key, header, width }) => {
      ws.getColumn(key).width = width;
      const cell = ws.getCell(`${key}${HDR_ROW}`);
      cell.value = header;
      cell.font  = { bold: true, size: 11, color: { argb: 'FFFFFFFF' } };
      cell.fill  = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1E3A5F' } };
      cell.alignment = { horizontal: 'center', vertical: 'middle', readingOrder: 'rightToLeft' };
      cell.border = {
        top:    { style: 'thin', color: { argb: 'FF0EA5E9' } },
        bottom: { style: 'medium', color: { argb: 'FF0EA5E9' } },
        left:   { style: 'thin', color: { argb: 'FF1E3A5F' } },
        right:  { style: 'thin', color: { argb: 'FF1E3A5F' } },
      };
    });
    ws.getRow(HDR_ROW).height = 26;

    // ── Data rows — one row per file ──
    const files   = (data.all_files || []).sort((a, b) => b.risk_score - a.risk_score);
    const altBg   = ['FFFFFFFF', 'FFF1F5F9'];
    let rowIdx    = HDR_ROW + 1;

    files.forEach((f, fileIdx) => {
      const rc      = clr[f.risk_label] || clr.OK;
      const rowBg   = altBg[fileIdx % 2];
      const isOK    = f.risk_label === 'OK';

      const shortFile = path.basename(f.path);
      const shortDir  = path.dirname(f.path).replace(/\\/g, '/');

      // Build findings text: "• רמה — סיבה (שורה X)" per finding
      const findingsText = isOK
        ? '✓ תקין'
        : f.findings.map(fn => `${fn.level === 'CRITICAL' ? '🔴' : fn.level === 'HIGH' ? '🟠' : '🟡'} ${fn.reason}  (שורה ${fn.line})`).join('\n');

      const r   = ws.getRow(rowIdx++);
      const numLines = isOK ? 1 : f.findings.length;
      r.height  = Math.max(20, numLines * 17);

      // A: filename
      const aCell = r.getCell('A');
      aCell.value = shortFile;
      aCell.font  = { size: 10, bold: true, color: { argb: isOK ? 'FF047857' : 'FF1E293B' } };
      aCell.fill  = { type: 'pattern', pattern: 'solid', fgColor: { argb: rowBg } };
      aCell.alignment = { readingOrder: 'rightToLeft', vertical: 'top', wrapText: false };
      aCell.border = { bottom: { style: 'thin', color: { argb: 'FFE2E8F0' } }, right: { style: 'thin', color: { argb: 'FFE2E8F0' } } };

      // B: directory
      const bCell = r.getCell('B');
      bCell.value = shortDir;
      bCell.font  = { size: 9, color: { argb: 'FF64748B' } };
      bCell.fill  = { type: 'pattern', pattern: 'solid', fgColor: { argb: rowBg } };
      bCell.alignment = { readingOrder: 'rightToLeft', vertical: 'top', wrapText: false };
      bCell.border = { bottom: { style: 'thin', color: { argb: 'FFE2E8F0' } }, right: { style: 'thin', color: { argb: 'FFE2E8F0' } } };

      // C: risk badge — colored background
      const cCell = r.getCell('C');
      cCell.value = f.risk_label;
      cCell.font  = { bold: true, size: 10, color: { argb: rc.fg } };
      cCell.fill  = { type: 'pattern', pattern: 'solid', fgColor: { argb: rc.bg } };
      cCell.alignment = { horizontal: 'center', vertical: 'middle' };
      cCell.border = { bottom: { style: 'thin', color: { argb: 'FFE2E8F0' } }, right: { style: 'thin', color: { argb: 'FFE2E8F0' } } };

      // D: score
      const dCell = r.getCell('D');
      dCell.value = f.risk_score;
      dCell.font  = { bold: true, size: 11, color: { argb: isOK ? 'FF10B981' : rc.bg } };
      dCell.fill  = { type: 'pattern', pattern: 'solid', fgColor: { argb: rowBg } };
      dCell.alignment = { horizontal: 'center', vertical: 'middle' };
      dCell.border = { bottom: { style: 'thin', color: { argb: 'FFE2E8F0' } }, right: { style: 'thin', color: { argb: 'FFE2E8F0' } } };

      // E: all findings in one cell, one per line
      const eCell = r.getCell('E');
      eCell.value = findingsText;
      eCell.font  = { size: 10, color: { argb: isOK ? 'FF047857' : 'FF1E293B' } };
      eCell.fill  = { type: 'pattern', pattern: 'solid', fgColor: { argb: rowBg } };
      eCell.alignment = { readingOrder: 'rightToLeft', vertical: 'top', wrapText: true };
      eCell.border = { bottom: { style: 'thin', color: { argb: 'FFE2E8F0' } } };
    });

    // Freeze rows up to header
    ws.views[0].state       = 'frozen';
    ws.views[0].xSplit      = 0;
    ws.views[0].ySplit      = HDR_ROW;
    ws.views[0].topLeftCell = `A${HDR_ROW + 1}`;

    // Send
    const filename = `EHZ-SEC-AI-FileAudit-${new Date().toISOString().slice(0,10)}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    await wb.xlsx.write(res);
    res.end();
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /audit/scan — run scan now
// body: { scan_path, incremental } (all optional)
//   incremental=true → scan only files modified since last scan's scanned_at
app.post('/audit/scan', (req, res) => {
  if (!fileAuditScanner) return res.status(500).json({ error: 'file-audit-scanner not available' });
  try {
    const body        = req.body || {};
    const scanPath    = body.scan_path || fileAuditScanner.DEFAULT_SCAN_PATH;
    const incremental = !!body.incremental;

    // For incremental: read last scan timestamp from saved result
    let since_iso = null;
    if (incremental && fs.existsSync(AUDIT_RESULT_FILE)) {
      try {
        const prev = JSON.parse(fs.readFileSync(AUDIT_RESULT_FILE, 'utf8'));
        since_iso  = prev.summary && prev.summary.scanned_at;
      } catch (_) {}
    }

    const result = fileAuditScanner.runFileAudit(scanPath, { incremental, since_iso });

    // In incremental mode: merge new findings with previous full results
    if (incremental && fs.existsSync(AUDIT_RESULT_FILE)) {
      try {
        const prev       = JSON.parse(fs.readFileSync(AUDIT_RESULT_FILE, 'utf8'));
        const prevPaths  = new Set((result.all_files || []).map(f => f.path));
        // Keep old files that weren't re-scanned
        const keptFiles  = (prev.all_files || []).filter(f => !prevPaths.has(f.path));
        const merged     = [...(result.all_files || []), ...keptFiles];
        result.all_files = merged;
        result.files     = merged.filter(f => f.findings && f.findings.length > 0);
        // Update summary totals
        result.summary.total_files = merged.length;
        result.summary.clean       = merged.filter(f => f.risk_label === 'OK').length;
        result.summary.medium      = merged.filter(f => f.risk_label === 'MEDIUM').length;
        result.summary.high        = merged.filter(f => f.risk_label === 'HIGH').length;
        result.summary.critical    = merged.filter(f => f.risk_label === 'CRITICAL').length;
        result.summary.skipped     = merged.filter(f => f.skipped).length;
        result.summary.incremental_new = (result.all_files.length - keptFiles.length);
      } catch (_) {}
    }

    // Save result
    fs.writeFileSync(AUDIT_RESULT_FILE, JSON.stringify(result, null, 2), 'utf8');

    // Telegram alert for CRITICAL files (only newly scanned)
    (incremental ? result.all_files.filter(f => {
      const prevPaths = new Set();
      return !prevPaths.has(f.path);
    }) : result.files).forEach(f => {
      if (f.risk_label === 'CRITICAL') {
        sendTelegram(`🚨 <b>EHZ-SEC-AI — File Audit CRITICAL</b>\n📄 ${f.path}\n⚡ ${f.findings.map(x=>x.reason).join(', ')}`);
      }
    });

    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /audit/schedule — מידע על הסריקה השבועית האוטומטית
app.get('/audit/schedule', (req, res) => {
  const now  = new Date();
  // חשב את יום ראשון הבא השעה 04:00
  const next = new Date(now);
  const daysUntilSunday = (7 - now.getDay()) % 7 || 7;
  next.setDate(now.getDate() + daysUntilSunday);
  next.setHours(4, 0, 0, 0);
  res.json({
    schedule: 'כל יום ראשון 04:00',
    day_of_week: 'Sunday',
    hour: 4,
    minute: 0,
    next_run: next.toISOString(),
    next_run_he: next.toLocaleString('he-IL', { timeZone: 'Asia/Jerusalem' }),
    scan_path: fileAuditScanner ? fileAuditScanner.DEFAULT_SCAN_PATH : null,
  });
});

// ─── Projects Explorer (Milestone 6.11) ──────────────────────────────────────

const PROJECTS_ROOT    = 'C:/Claude-Repo';
const PROJECTS_NOTES_FILE = path.join(__dirname, 'projects-notes.json');
const EXCLUDE_PROJ = new Set(['node_modules', '.git', 'backups', 'dist', 'build', '__pycache__']);

function readNotes() {
  try { return JSON.parse(fs.readFileSync(PROJECTS_NOTES_FILE, 'utf8')); } catch(_) { return {}; }
}

function getFolderStats(dirPath) {
  let files = 0, folders = 0, lastMod = 0;
  try {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const e of entries) {
      if (EXCLUDE_PROJ.has(e.name)) continue;
      if (e.isDirectory()) { folders++; }
      else {
        files++;
        try {
          const m = fs.statSync(path.join(dirPath, e.name)).mtimeMs;
          if (m > lastMod) lastMod = m;
        } catch(_) {}
      }
    }
  } catch(_) {}
  return { files, folders, lastMod };
}

function buildProjectTree(rootPath, depth = 0) {
  const notes = readNotes();
  let entries;
  try { entries = fs.readdirSync(rootPath, { withFileTypes: true }); }
  catch(_) { return []; }

  const dirs = entries
    .filter(e => e.isDirectory() && !EXCLUDE_PROJ.has(e.name))
    .sort((a, b) => a.name.localeCompare(b.name));

  return dirs.map(e => {
    const fullPath = path.join(rootPath, e.name).replace(/\\/g, '/');
    const stats    = getFolderStats(fullPath);
    const node = {
      name:     e.name,
      path:     fullPath,
      files:    stats.files,
      folders:  stats.folders,
      last_mod: stats.lastMod ? new Date(stats.lastMod).toISOString() : null,
      note:     notes[fullPath] || '',
      children: [],
    };
    if (depth < 1) {
      node.children = buildProjectTree(fullPath, depth + 1);
    }
    return node;
  });
}

// GET /projects — עץ תיקיות C:/Claude-Repo (רמה 0-1)
app.get('/projects', (req, res) => {
  try {
    const tree = buildProjectTree(PROJECTS_ROOT);
    res.json({ root: PROJECTS_ROOT, tree, count: tree.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET /projects/notes — כל ההערות
app.get('/projects/notes', (req, res) => {
  res.json(readNotes());
});

// POST /projects/notes — שמור הערה לתיקייה
// body: { path, note }
app.post('/projects/notes', (req, res) => {
  try {
    const { path: p, note } = req.body || {};
    if (!p) return res.status(400).json({ error: 'path required' });
    const notes = readNotes();
    if (note === '' || note == null) { delete notes[p]; }
    else { notes[p] = note; }
    fs.writeFileSync(PROJECTS_NOTES_FILE, JSON.stringify(notes, null, 2), 'utf8');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
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
