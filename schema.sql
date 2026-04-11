-- CloudPress — DB 마이그레이션 스크립트
-- 실제 D1 DB(구버전 ensureSchema 기반)에 v11 컬럼을 추가합니다.
-- wrangler d1 execute <DB명> --file=schema.sql --remote
-- 이미 존재하는 테이블/컬럼은 IF NOT EXISTS / OR IGNORE로 안전하게 처리됩니다.

-- ── 기존 테이블 유지 (없으면 생성) ──────────────────────────────

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  plan TEXT NOT NULL DEFAULT 'free',
  plan_expires_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS sites (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  suspended INTEGER DEFAULT 0,
  plan TEXT NOT NULL DEFAULT 'free',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS notices (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'info',
  target_role TEXT DEFAULT 'all',
  active INTEGER DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS payments (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  plan TEXT NOT NULL,
  amount INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  payment_key TEXT,
  order_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS push_subscriptions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  endpoint TEXT NOT NULL UNIQUE,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS domain_verifications (
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  method TEXT NOT NULL,
  verified INTEGER DEFAULT 0,
  verified_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (site_id) REFERENCES sites(id)
);

CREATE TABLE IF NOT EXISTS traffic_logs (
  id TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id),
  path TEXT NOT NULL,
  referrer TEXT,
  country TEXT,
  device TEXT,
  ua TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── sites 테이블: v11 컬럼 추가 (이미 있으면 에러 무시) ──────────

ALTER TABLE sites ADD COLUMN primary_domain TEXT;
ALTER TABLE sites ADD COLUMN www_domain TEXT;
ALTER TABLE sites ADD COLUMN domain_status TEXT DEFAULT 'pending';
ALTER TABLE sites ADD COLUMN site_prefix TEXT;
ALTER TABLE sites ADD COLUMN worker_name TEXT;
ALTER TABLE sites ADD COLUMN worker_route TEXT;
ALTER TABLE sites ADD COLUMN worker_route_www TEXT;
ALTER TABLE sites ADD COLUMN worker_route_id TEXT;
ALTER TABLE sites ADD COLUMN worker_route_www_id TEXT;
ALTER TABLE sites ADD COLUMN cf_zone_id TEXT;
ALTER TABLE sites ADD COLUMN dns_record_id TEXT;
ALTER TABLE sites ADD COLUMN dns_record_www_id TEXT;
ALTER TABLE sites ADD COLUMN wp_username TEXT;
ALTER TABLE sites ADD COLUMN wp_password TEXT;
ALTER TABLE sites ADD COLUMN wp_admin_email TEXT;
ALTER TABLE sites ADD COLUMN wp_admin_url TEXT;
ALTER TABLE sites ADD COLUMN provision_step TEXT DEFAULT 'init';
ALTER TABLE sites ADD COLUMN error_message TEXT;
ALTER TABLE sites ADD COLUMN suspension_reason TEXT;
ALTER TABLE sites ADD COLUMN disk_used INTEGER DEFAULT 0;
ALTER TABLE sites ADD COLUMN bandwidth_used INTEGER DEFAULT 0;
ALTER TABLE sites ADD COLUMN deleted_at TEXT;

-- ── users 테이블: v11 컬럼 추가 ──────────────────────────────────

ALTER TABLE users ADD COLUMN twofa_type TEXT DEFAULT NULL;
ALTER TABLE users ADD COLUMN twofa_secret TEXT DEFAULT NULL;
ALTER TABLE users ADD COLUMN twofa_enabled INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN twofa_pending_code TEXT DEFAULT NULL;
ALTER TABLE users ADD COLUMN twofa_code_expires INTEGER DEFAULT NULL;
ALTER TABLE users ADD COLUMN updated_at TEXT DEFAULT (datetime('now'));

-- ── 인덱스 ───────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_sites_user_id        ON sites(user_id);
CREATE INDEX IF NOT EXISTS idx_sites_status         ON sites(status);
CREATE INDEX IF NOT EXISTS idx_sites_primary_domain ON sites(primary_domain);
CREATE INDEX IF NOT EXISTS idx_sites_site_prefix    ON sites(site_prefix);
CREATE INDEX IF NOT EXISTS idx_payments_user_id     ON payments(user_id);

-- ── settings 기본값 ───────────────────────────────────────────────

INSERT OR IGNORE INTO settings (key, value) VALUES
  ('plan_free_sites',       '1'),
  ('plan_starter_sites',    '3'),
  ('plan_pro_sites',        '10'),
  ('plan_enterprise_sites', '-1'),
  ('wp_origin_url',         ''),
  ('wp_origin_secret',      ''),
  ('wp_admin_base_url',     ''),
  ('cf_api_token',          ''),
  ('cf_account_id',         ''),
  ('cf_worker_name',        'cloudpress-proxy'),
  ('worker_cname_target',   ''),
  ('maintenance_mode',      '0'),
  ('site_name',             'CloudPress'),
  ('site_domain',           'cloudpress.site'),
  ('toss_client_key',       ''),
  ('toss_secret_key',       '');
