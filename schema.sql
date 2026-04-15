-- CloudPress v16.0 — schema.sql (VP 방식 완전 제거, GitHub HTTP fetch 방식)
-- D1 Console 또는: wrangler d1 execute cloudpress-db --file=schema.sql --remote
--
-- 이 파일 하나만 실행하면 모든 테이블·인덱스·기본값이 세팅됩니다.
-- 이미 존재하는 테이블은 IF NOT EXISTS로 보호.
-- 기존 DB 마이그레이션은 파일 하단 ALTER TABLE 섹션 참고.

-- ── users ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id                  TEXT PRIMARY KEY,
  name                TEXT NOT NULL,
  email               TEXT NOT NULL UNIQUE,
  password_hash       TEXT NOT NULL,
  role                TEXT NOT NULL DEFAULT 'user',
  plan                TEXT NOT NULL DEFAULT 'free',
  plan_expires_at     TEXT,
  twofa_type          TEXT,
  twofa_secret        TEXT,
  twofa_enabled       INTEGER DEFAULT 0,
  twofa_pending_code  TEXT,
  twofa_code_expires  INTEGER,
  cf_global_api_key   TEXT,
  cf_account_email    TEXT,
  cf_account_id       TEXT,
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
  site_prefix         TEXT UNIQUE,

  -- 사이트 전용 Cloudflare 리소스 (D1 + KV — 자동 생성)
  site_d1_id          TEXT,
  site_d1_name        TEXT,
  site_kv_id          TEXT,
  site_kv_title       TEXT,

  -- Cloudflare Worker/DNS
  worker_name         TEXT,
  worker_route        TEXT,
  worker_route_www    TEXT,
  worker_route_id     TEXT,
  worker_route_www_id TEXT,
  cf_zone_id          TEXT,
  dns_record_id       TEXT,
  dns_record_www_id   TEXT,

  -- CMS 어드민 접속 URL (설치 후 /cp-admin/setup-config)
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
CREATE INDEX IF NOT EXISTS idx_sessions_user_id     ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires     ON sessions(expires_at);

-- ── settings 기본값 ────────────────────────────────────────────────
INSERT OR IGNORE INTO settings (key, value) VALUES
  -- 플랜별 사이트 수
  ('plan_free_sites',        '1'),
  ('plan_starter_sites',     '3'),
  ('plan_pro_sites',         '10'),
  ('plan_enterprise_sites',  '-1'),

  -- 플랜 가격 (원)
  ('plan_starter_price',     '9900'),
  ('plan_pro_price',         '29900'),
  ('plan_enterprise_price',  '99000'),

  -- Cloudflare 설정
  ('cf_api_token',           ''),
  ('cf_account_id',          ''),
  ('cf_worker_name',         ''),
  ('worker_cname_target',    ''),
  ('main_db_id',             ''),
  ('cache_kv_id',            ''),
  ('sessions_kv_id',         ''),
  ('cloudflare_cdn_enabled', '1'),

  -- GitHub CMS 소스 설정 (v16.0 — VP 방식 대체)
  -- cms_github_repo: cloudflare-cms 소스가 있는 GitHub 레포 (owner/repo)
  -- 예: myorg/cloudflare-cms
  ('cms_github_repo',        ''),
  ('cms_github_branch',      'main'),
  ('cms_github_token',       ''),

  -- CMS 버전 관리
  ('cms_versions',           '[]'),

  -- 결제
  ('toss_client_key',        ''),
  ('toss_secret_key',        ''),

  -- 일반
  ('maintenance_mode',       '0'),
  ('site_name',              '클라우드프레스'),
  ('site_domain',            'cloud-press.co.kr'),
  ('auto_ssl',               '1'),
  ('cloudflare_cdn_enabled', '1');

-- ── 기존 DB 마이그레이션 (컬럼 없으면 추가, 있으면 무시) ──────────
-- D1 Console에서 개별 실행 또는 wrangler로 실행
-- 이미 컬럼이 있으면 "table already has column" 오류 → 무시

-- users 컬럼 마이그레이션
ALTER TABLE users ADD COLUMN cf_global_api_key TEXT;
ALTER TABLE users ADD COLUMN cf_account_email TEXT;
ALTER TABLE users ADD COLUMN cf_account_id TEXT;
ALTER TABLE users ADD COLUMN twofa_type TEXT;
ALTER TABLE users ADD COLUMN twofa_secret TEXT;
ALTER TABLE users ADD COLUMN twofa_enabled INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN twofa_pending_code TEXT;
ALTER TABLE users ADD COLUMN twofa_code_expires INTEGER;
ALTER TABLE users ADD COLUMN plan_expires_at TEXT;
ALTER TABLE users ADD COLUMN updated_at TEXT DEFAULT (datetime('now'));

-- sites 컬럼 마이그레이션 (v16.0)
ALTER TABLE sites ADD COLUMN site_d1_id TEXT;
ALTER TABLE sites ADD COLUMN site_d1_name TEXT;
ALTER TABLE sites ADD COLUMN site_kv_id TEXT;
ALTER TABLE sites ADD COLUMN site_kv_title TEXT;
ALTER TABLE sites ADD COLUMN primary_domain TEXT;
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
ALTER TABLE sites ADD COLUMN wp_admin_url TEXT;
ALTER TABLE sites ADD COLUMN provision_step TEXT DEFAULT 'init';
ALTER TABLE sites ADD COLUMN suspension_reason TEXT;
ALTER TABLE sites ADD COLUMN disk_used INTEGER DEFAULT 0;
ALTER TABLE sites ADD COLUMN bandwidth_used INTEGER DEFAULT 0;
ALTER TABLE sites ADD COLUMN deleted_at TEXT;

-- v16.0 신규 settings 추가 (기존 DB 마이그레이션용)
INSERT OR IGNORE INTO settings (key, value) VALUES ('cms_github_repo',   '');
INSERT OR IGNORE INTO settings (key, value) VALUES ('cms_github_branch', 'main');
INSERT OR IGNORE INTO settings (key, value) VALUES ('cms_github_token',  '');
INSERT OR IGNORE INTO settings (key, value) VALUES ('cms_versions',      '[]');
