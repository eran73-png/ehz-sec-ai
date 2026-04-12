-- EHZ-SEC-AI — Collector SQLite Schema
-- Milestone 1

CREATE TABLE IF NOT EXISTS events (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            INTEGER NOT NULL,                   -- Unix ms
  hook_type     TEXT    NOT NULL,                   -- PreToolUse / PostToolUse / ConfigChange
  tool_name     TEXT    NOT NULL,
  session_id    TEXT    NOT NULL,
  level         TEXT    NOT NULL DEFAULT 'INFO',    -- INFO / HIGH / CRITICAL
  reason        TEXT,                               -- human-readable rule match
  input_summary TEXT,                               -- first 500 chars of tool input
  output_summary TEXT,                              -- first 500 chars of tool response
  telegram_sent INTEGER NOT NULL DEFAULT 0,         -- 1 = alert sent
  created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_events_ts    ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_level ON events(level);
CREATE INDEX IF NOT EXISTS idx_events_tool  ON events(tool_name);
