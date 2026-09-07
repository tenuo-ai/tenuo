CREATE TABLE IF NOT EXISTS events (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  session             TEXT NOT NULL,
  cohort              TEXT,
  sent_at             TEXT NOT NULL,
  received_at         TEXT NOT NULL,
  event               TEXT NOT NULL,
  stage               INTEGER NOT NULL,
  command             TEXT,
  scenario            TEXT,
  functionality_ok    INTEGER,
  score               INTEGER,
  failed_checks       TEXT NOT NULL DEFAULT '[]',
  central_calls       INTEGER,
  exercise_load_error INTEGER,
  elapsed_ms          INTEGER,
  platform            TEXT,
  node                INTEGER
);
CREATE INDEX IF NOT EXISTS events_session ON events (session);
CREATE INDEX IF NOT EXISTS events_cohort_stage ON events (cohort, stage);
