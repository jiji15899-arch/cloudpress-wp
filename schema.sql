-- CloudPress v11 — schema.sql
-- D1 콘솔 또는: wrangler d1 execute <DB명> --file=schema.sql --remote

-- ── users ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id                  TEXT PRIMARY KEY,
  name                TEXT NOT NULL,
  email               TEXT NOT NULL UNIQUE,
  password_hash       TEXT NOT NULL,
  role                TEXT NOT NULL DEFAULT 'user',
  plan                TEXT NOT NULL DEFAULT 'free',
  plan_expires_at     INTEGER,
  cf_global_api_key   TEXT,
  cf_account_email    TEXT,
  cf_account_id       TEXT,
  twofa_type          TEXT,
  twofa_secret        TEXT,
  twofa_enabled       INTEGER DEFAULT 0,
  twofa_pending_code  TEXT,
  twofa_code_expires  INTEGER,
  created_at          TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── sessions ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
  token       TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id),
  expires_at  TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── sites ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sites (
  id                  TEXT PRIMARY KEY,
  user_id             TEXT NOT NULL REFERENCES users(id),
  name                TEXT NOT NULL,
  primary_domain      TEXT,
  domain_status       TEXT DEFAULT 'pending',
  site_prefix         TEXT UNIQUE,
  worker_name         TEXT,
  worker_route        TEXT,
  worker_route_www    TEXT,
  worker_route_id     TEXT,
  worker_route_www_id TEXT,
  cf_zone_id          TEXT,
  dns_record_id       TEXT,
  dns_record_www_id   TEXT,
  wp_username         TEXT,
  wp_password         TEXT,
  wp_admin_email      TEXT,
  wp_admin_url        TEXT,
  status              TEXT NOT NULL DEFAULT 'pending',
  provision_step      TEXT DEFAULT 'init',
  error_message       TEXT,
  suspended           INTEGER DEFAULT 0,
  suspension_reason   TEXT,
  disk_used           INTEGER DEFAULT 0,
  bandwidth_used      INTEGER DEFAULT 0,
  plan                TEXT NOT NULL DEFAULT 'free',
  created_at          TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at          TEXT NOT NULL DEFAULT (datetime('now')),
  deleted_at          TEXT
);

-- ── settings ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── notices ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS notices (
  id          TEXT PRIMARY KEY,
  title       TEXT NOT NULL,
  content     TEXT NOT NULL,
  type        TEXT NOT NULL DEFAULT 'info',
  target_role TEXT DEFAULT 'all',
  active      INTEGER DEFAULT 1,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── payments ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS payments (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users(id),
  order_id     TEXT,
  amount       INTEGER NOT NULL,
  plan         TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'pending',
  payment_key  TEXT,
  method       TEXT,
  card_company TEXT,
  receipt_url  TEXT,
  confirmed_at INTEGER,
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── push_subscriptions ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS push_subscriptions (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  endpoint   TEXT NOT NULL UNIQUE,
  p256dh     TEXT NOT NULL,
  auth       TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── domain_verifications ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS domain_verifications (
  id          TEXT PRIMARY KEY,
  site_id     TEXT NOT NULL REFERENCES sites(id),
  domain      TEXT NOT NULL,
  method      TEXT NOT NULL,
  verified    INTEGER DEFAULT 0,
  verified_at TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── vp_accounts ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vp_accounts (
  id              TEXT PRIMARY KEY,
  label           TEXT NOT NULL,
  vp_username     TEXT NOT NULL,
  vp_password     TEXT NOT NULL,
  panel_url       TEXT NOT NULL,
  server_domain   TEXT NOT NULL,
  web_root        TEXT DEFAULT '/htdocs',
  php_bin         TEXT,
  mysql_host      TEXT,
  wp_download_url TEXT,
  max_sites       INTEGER DEFAULT 5,
  current_sites   INTEGER DEFAULT 0,
  is_active       INTEGER DEFAULT 1,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── traffic_logs ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS traffic_logs (
  id         TEXT PRIMARY KEY,
  user_id    TEXT REFERENCES users(id),
  path       TEXT NOT NULL,
  referrer   TEXT,
  country    TEXT,
  device     TEXT,
  ua         TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── 인덱스 ───────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_sites_user_id        ON sites(user_id);
CREATE INDEX IF NOT EXISTS idx_sites_status         ON sites(status);
CREATE INDEX IF NOT EXISTS idx_sites_primary_domain ON sites(primary_domain);
CREATE INDEX IF NOT EXISTS idx_sites_site_prefix    ON sites(site_prefix);
CREATE INDEX IF NOT EXISTS idx_payments_user_id     ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_order_id    ON payments(order_id);
CREATE INDEX IF NOT EXISTS idx_traffic_created_at   ON traffic_logs(created_at);

-- ── settings 기본값 ───────────────────────────────────────────────
INSERT OR IGNORE INTO settings (key, value) VALUES
  ('plan_free_sites',        '1'),
  ('plan_starter_sites',     '3'),
  ('plan_pro_sites',         '10'),
  ('plan_enterprise_sites',  '-1'),
  ('plan_starter_price',     '9900'),
  ('plan_pro_price',         '29900'),
  ('plan_enterprise_price',  '99000'),
  ('wp_origin_url',          ''),
  ('wp_origin_secret',       ''),
  ('wp_admin_base_url',      ''),
  ('cf_api_token',           ''),
  ('cf_account_id',          ''),
  ('cf_worker_name',         'cloudpress-proxy'),
  ('worker_cname_target',    ''),
  ('maintenance_mode',       '0'),
  ('site_name',              'CloudPress'),
  ('site_domain',            'cloudpress.site'),
  ('toss_client_key',        ''),
  ('toss_secret_key',        '');
