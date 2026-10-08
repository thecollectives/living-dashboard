-- livingdb schema v1 — Living Dashboard (self-hosted Postgres on the spark)
-- Applied to the `livingdb` database inside the existing skills-postgres.
-- No secrets in this file: roles/credentials are created by roles.sql from
-- environment values on the spark; the repo never carries them.

-- ============================================================
-- Enrollment / identity
-- ============================================================
CREATE TABLE IF NOT EXISTS hosts (
  host_id        TEXT PRIMARY KEY,
  label          TEXT NOT NULL,
  platform       TEXT NOT NULL,            -- linux | windows | darwin
  os             TEXT,
  tailnet_ip     INET,
  ssh_target     TEXT,                     -- how the operator reaches it (SSH-push record)
  serial         TEXT,
  agent_version  TEXT,
  enrolled_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen      TIMESTAMPTZ,
  baseline_scan_id BIGINT
);

CREATE TABLE IF NOT EXISTS scans (
  scan_id        BIGSERIAL PRIMARY KEY,
  host_id        TEXT NOT NULL REFERENCES hosts(host_id),
  ts             TIMESTAMPTZ NOT NULL DEFAULT now(),
  kind           TEXT NOT NULL,            -- deep | metrics | baseline
  duration_ms    INT,
  status         TEXT NOT NULL DEFAULT 'ok',
  error          TEXT,
  payload_version INT NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS scans_host_ts ON scans(host_id, ts DESC);

-- ============================================================
-- Canonical current inventory: one row per (host, category, item_key)
-- Categories: cron, sched_task, software, users, listening_port,
--   docker_app, host_service, disk, net_iface, web_service,
--   log_source, gpu, startup_svc
-- ============================================================
CREATE TABLE IF NOT EXISTS inventory_current (
  host_id    TEXT NOT NULL REFERENCES hosts(host_id),
  category   TEXT NOT NULL,
  item_key   TEXT NOT NULL,
  item       JSONB NOT NULL,
  first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (host_id, category, item_key)
);

CREATE TABLE IF NOT EXISTS inventory_history (
  scan_id  BIGINT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
  host_id  TEXT NOT NULL,
  category TEXT NOT NULL,
  item_key TEXT NOT NULL,
  item     JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS inventory_history_host ON inventory_history(host_id, category);

-- ============================================================
-- Metrics time-series (agent heartbeat). Rollups pruned by living-sync.
--   raw 1-min  -> 48h | rollup_5m -> 30d | rollup_1h -> 1y
-- ============================================================
CREATE TABLE IF NOT EXISTS metrics_ts (
  host_id       TEXT NOT NULL REFERENCES hosts(host_id),
  ts            TIMESTAMPTZ NOT NULL,
  cpu_pct       REAL,
  mem_pct       REAL,
  load1         REAL,
  gpu_util      REAL,
  gpu_temp      REAL,
  gpu_mem_used  BIGINT,
  net_rx        BIGINT,
  net_tx        BIGINT,
  disk_used_pct REAL,
  PRIMARY KEY (host_id, ts)
);

CREATE TABLE IF NOT EXISTS metrics_5m (
  host_id       TEXT NOT NULL,
  ts            TIMESTAMPTZ NOT NULL,
  cpu_pct       REAL,
  mem_pct       REAL,
  load1         REAL,
  gpu_util      REAL,
  gpu_temp      REAL,
  gpu_mem_used  BIGINT,
  net_rx        BIGINT,
  net_tx        BIGINT,
  disk_used_pct REAL,
  PRIMARY KEY (host_id, ts)
);

CREATE TABLE IF NOT EXISTS metrics_1h (
  host_id       TEXT NOT NULL,
  ts            TIMESTAMPTZ NOT NULL,
  cpu_pct       REAL,
  mem_pct       REAL,
  load1         REAL,
  gpu_util      REAL,
  gpu_temp      REAL,
  gpu_mem_used  BIGINT,
  net_rx        BIGINT,
  net_tx        BIGINT,
  disk_used_pct REAL,
  PRIMARY KEY (host_id, ts)
);

-- ============================================================
-- The LIVING feed: new | gone | changed
-- ============================================================
CREATE TABLE IF NOT EXISTS events (
  event_id   BIGSERIAL PRIMARY KEY,
  host_id    TEXT NOT NULL REFERENCES hosts(host_id),
  ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
  kind       TEXT NOT NULL,              -- new | gone | changed
  category   TEXT NOT NULL,
  item_key   TEXT NOT NULL,
  summary    TEXT NOT NULL,
  scan_id    BIGINT REFERENCES scans(scan_id),
  acked      BOOL NOT NULL DEFAULT FALSE,
  dismissed  BOOL NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS events_host_ts ON events(host_id, ts DESC);
CREATE INDEX IF NOT EXISTS events_unacked ON events(host_id) WHERE acked = FALSE AND dismissed = FALSE;

-- ============================================================
-- Page launcher: new web services auto-become bookmarks
-- ============================================================
CREATE TABLE IF NOT EXISTS bookmarks (
  bookmark_id         BIGSERIAL PRIMARY KEY,
  host_id             TEXT NOT NULL REFERENCES hosts(host_id),
  title               TEXT NOT NULL,
  url                 TEXT NOT NULL,
  detected_from_event BIGINT REFERENCES events(event_id),
  auto                BOOL NOT NULL DEFAULT TRUE,
  pinned              BOOL NOT NULL DEFAULT FALSE,
  dismissed           BOOL NOT NULL DEFAULT FALSE,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (host_id, url)
);

-- ============================================================
-- Log source catalog (identified at deep-scan time)
-- ============================================================
CREATE TABLE IF NOT EXISTS log_sources (
  host_id      TEXT NOT NULL REFERENCES hosts(host_id),
  name         TEXT NOT NULL,
  path         TEXT,
  kind         TEXT NOT NULL,            -- file | journald | eventlog | docker
  pullable     BOOL NOT NULL DEFAULT TRUE,
  sensitive    BOOL NOT NULL DEFAULT FALSE,
  bytes_approx BIGINT,
  last_checked TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (host_id, name)
);

-- ============================================================
-- Enrollment tokens (single-use, sha256 hash stored)
-- ============================================================
CREATE TABLE IF NOT EXISTS enrollment_tokens (
  token_hash      TEXT PRIMARY KEY,
  label           TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at      TIMESTAMPTZ NOT NULL,
  used_at         TIMESTAMPTZ,
  used_by_host_id TEXT REFERENCES hosts(host_id),
  max_uses        INT NOT NULL DEFAULT 1,
  use_count       INT NOT NULL DEFAULT 0
);

-- ============================================================
-- Agent ingest staging: agents POST here; living-sync processes.
-- kind: deep | metrics
-- ============================================================
CREATE TABLE IF NOT EXISTS scan_staging (
  staging_id BIGSERIAL PRIMARY KEY,
  host_id    TEXT NOT NULL,
  ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
  kind       TEXT NOT NULL,
  payload    JSONB NOT NULL,
  processed  BOOL NOT NULL DEFAULT FALSE,
  error      TEXT
);
CREATE INDEX IF NOT EXISTS scan_staging_unprocessed
  ON scan_staging (staging_id) WHERE processed = FALSE;

-- ============================================================
-- Enrollment claim: validates a single-use token, registers the host.
-- Called via PostgREST RPC as the anon role (EXECUTE granted).
-- ============================================================
CREATE OR REPLACE FUNCTION claim_enrollment_token(
  p_token    TEXT,
  p_host_id  TEXT,
  p_label    TEXT,
  p_platform TEXT,
  p_os       TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_hash TEXT := encode(digest(p_token, 'sha256'), 'hex');
  v_row  enrollment_tokens%ROWTYPE;
BEGIN
  SELECT * INTO v_row FROM enrollment_tokens WHERE token_hash = v_hash;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', FALSE, 'error', 'unknown token');
  END IF;
  IF v_row.expires_at < now() THEN
    RETURN jsonb_build_object('ok', FALSE, 'error', 'token expired');
  END IF;
  IF v_row.use_count >= v_row.max_uses THEN
    RETURN jsonb_build_object('ok', FALSE, 'error', 'token already used');
  END IF;

  -- Host row FIRST: enrollment_tokens.used_by_host_id is a FK to hosts.
  INSERT INTO hosts (host_id, label, platform, os, last_seen)
  VALUES (p_host_id, COALESCE(NULLIF(p_label, ''), p_host_id),
          p_platform, p_os, now())
  ON CONFLICT (host_id) DO UPDATE
     SET label = EXCLUDED.label, platform = EXCLUDED.platform,
         os = EXCLUDED.os, last_seen = now();

  UPDATE enrollment_tokens
     SET use_count = use_count + 1,
         used_at = now(),
         used_by_host_id = p_host_id
   WHERE token_hash = v_hash;

  RETURN jsonb_build_object('ok', TRUE, 'host_id', p_host_id);
END;
$$;
