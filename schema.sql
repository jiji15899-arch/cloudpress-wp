-- CloudPress v12 — schema.sql
-- D1 콘솔 또는: wrangler d1 execute <DB명> --file=schema.sql --remote
--
-- v12 변경사항:
--   sites 테이블에 site_d1_id, site_d1_name, site_kv_id, site_kv_title 컬럼 추가
--   각 사이트는 독립된 D1 DB + KV 네임스페이스를 가짐
--   vp_accounts 테이블 제거 (VP 방식 미사용)

-- ── users ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id                  TEXT PRIMARY KEY,
  name                TEXT NOT NULL,
  email               TEXT NOT NULL UNIQUE,
  password_hash       TEXT NOT NULL,
  role                TEXT NOT NULL DEFAULT 'user',
  plan                TEXT NOT NULL DEFAULT 'free',
  plan_expires_at     INTEGER,
  twofa_type          TEXT,
  twofa_secret        TEXT,
  twofa_enabled       INTEGER DEFAULT 0,
  twofa_pending_code  TEXT,
  twofa_code_expires  INTEGER,
  created_at          TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── sessions ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
  token       TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id),
  expires_at  TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── sites ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sites (
  id                  TEXT PRIMARY KEY,
  user_id             TEXT NOT NULL REFERENCES users(id),
  name                TEXT NOT NULL,

  -- 도메인
  primary_domain      TEXT,
  domain_status       TEXT DEFAULT 'pending',

  -- 사이트 격리 ID
  site_prefix         TEXT UNIQUE,           -- 7자 고유 prefix (예: s_a3k9x2)

  -- 사이트 전용 Cloudflare 리소스 (CF API로 생성)
  site_d1_id          TEXT,                  -- 사이트 전용 D1 DB UUID
  site_d1_name        TEXT,                  -- 사이트 전용 D1 DB 이름
  site_kv_id          TEXT,                  -- 사이트 전용 KV 네임스페이스 ID
  site_kv_title       TEXT,                  -- 사이트 전용 KV 이름

  -- Cloudflare Worker/DNS
  worker_name         TEXT,
  worker_route        TEXT,
  worker_route_www    TEXT,
  worker_route_id     TEXT,
  worker_route_www_id TEXT,
  cf_zone_id          TEXT,
  dns_record_id       TEXT,
  dns_record_www_id   TEXT,

  -- WordPress 접속 정보 (origin WP admin)
  wp_username         TEXT,
  wp_password         TEXT,
  wp_admin_email      TEXT,
  wp_admin_url        TEXT,

  -- 상태
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

-- ── settings ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── notices ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS notices (
  id          TEXT PRIMARY KEY,
  title       TEXT NOT NULL,
  content     TEXT NOT NULL,
  type        TEXT NOT NULL DEFAULT 'info',
  target_role TEXT DEFAULT 'all',
  active      INTEGER DEFAULT 1,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── payments ───────────────────────────────────────────────────────
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

-- ── push_subscriptions ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS push_subscriptions (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  endpoint   TEXT NOT NULL UNIQUE,
  p256dh     TEXT NOT NULL,
  auth       TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── domain_verifications ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS domain_verifications (
  id          TEXT PRIMARY KEY,
  site_id     TEXT NOT NULL REFERENCES sites(id),
  domain      TEXT NOT NULL,
  method      TEXT NOT NULL,
  verified    INTEGER DEFAULT 0,
  verified_at TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── traffic_logs ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS traffic_logs (
  id         TEXT PRIMARY KEY,
  user_id    TEXT REFERENCES users(id),
  site_id    TEXT REFERENCES sites(id),
  path       TEXT NOT NULL,
  referrer   TEXT,
  country    TEXT,
  device     TEXT,
  ua         TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── 인덱스 ─────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_sites_user_id        ON sites(user_id);
CREATE INDEX IF NOT EXISTS idx_sites_status         ON sites(status);
CREATE INDEX IF NOT EXISTS idx_sites_primary_domain ON sites(primary_domain);
CREATE INDEX IF NOT EXISTS idx_sites_site_prefix    ON sites(site_prefix);
CREATE INDEX IF NOT EXISTS idx_sites_site_d1_id     ON sites(site_d1_id);
CREATE INDEX IF NOT EXISTS idx_sites_site_kv_id     ON sites(site_kv_id);
CREATE INDEX IF NOT EXISTS idx_payments_user_id     ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_order_id    ON payments(order_id);
CREATE INDEX IF NOT EXISTS idx_traffic_created_at   ON traffic_logs(created_at);

-- ── settings 기본값 ────────────────────────────────────────────────
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
  ('site_name',              '클라우드프레스'),
  ('site_domain',            'cloud-press.co.kr),
  ('toss_client_key',        ''),
  ('toss_secret_key',        '');

-- ── 기존 DB 마이그레이션 (컬럼 추가) ──────────────────────────────
-- 이미 sites 테이블이 있는 경우 아래 ALTER를 실행하세요:
-- ALTER TABLE sites ADD COLUMN site_d1_id    TEXT;
-- ALTER TABLE sites ADD COLUMN site_d1_name  TEXT;
-- ALTER TABLE sites ADD COLUMN site_kv_id    TEXT;
-- ALTER TABLE sites ADD COLUMN site_kv_title TEXT;
