-- CloudPress CMS DB Schema v3.0

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',   -- user | manager | admin
  plan TEXT NOT NULL DEFAULT 'starter',
  plan_expires_at INTEGER,
  -- Cloudflare Global API 키 (암호화 저장)
  cf_global_api_key TEXT,
  cf_account_email TEXT,
  cf_account_id TEXT,
  -- 2FA 설정
  twofa_type TEXT DEFAULT NULL,        -- null | email | second_password
  twofa_secret TEXT DEFAULT NULL,      -- 2차 비밀번호 해시 또는 이메일 인증 코드
  twofa_enabled INTEGER DEFAULT 0,
  twofa_pending_code TEXT DEFAULT NULL,
  twofa_code_expires INTEGER DEFAULT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS sites (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  subdomain TEXT UNIQUE NOT NULL,
  custom_domain TEXT,
  -- CF CMS 관련 (InstaWP 제거, Cloudflare 자체 CMS)
  cms_url TEXT,
  cms_admin_url TEXT,
  cms_username TEXT DEFAULT 'admin',
  cms_password TEXT,
  cms_version TEXT DEFAULT 'latest',
  cf_zone_id TEXT,
  cf_pages_project TEXT,
  cf_kv_namespace TEXT,
  cf_d1_database TEXT,
  -- 기존 호환 컬럼 유지
  wp_url TEXT GENERATED ALWAYS AS (cms_url) VIRTUAL,
  wp_admin_url TEXT GENERATED ALWAYS AS (cms_admin_url) VIRTUAL,
  vps_container_id TEXT,
  db_name TEXT,
  db_user TEXT,
  db_password TEXT,
  status TEXT NOT NULL DEFAULT 'provisioning',
  php_version TEXT DEFAULT '8.3',
  region TEXT DEFAULT 'auto',
  plan TEXT NOT NULL DEFAULT 'starter',
  disk_usage_mb INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS cms_versions (
  id TEXT PRIMARY KEY,
  version TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL,
  description TEXT,
  is_stable INTEGER DEFAULT 1,
  is_latest INTEGER DEFAULT 0,
  release_notes TEXT,
  created_by TEXT REFERENCES users(id),
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS payments (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  order_id TEXT UNIQUE NOT NULL,
  payment_key TEXT,
  amount INTEGER NOT NULL,
  plan TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  method TEXT,
  card_company TEXT,
  receipt_url TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  confirmed_at INTEGER
);

CREATE TABLE IF NOT EXISTS notices (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'info',
  is_active INTEGER DEFAULT 1,
  created_by TEXT REFERENCES users(id),
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS traffic_logs (
  id TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id),
  path TEXT NOT NULL,
  referrer TEXT,
  country TEXT,
  device TEXT,
  ua TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

INSERT OR IGNORE INTO settings (key, value) VALUES
  ('plan_starter_price',   '9900'),
  ('plan_pro_price',       '29900'),
  ('plan_enterprise_price','99000'),
  ('plan_starter_sites',   '3'),
  ('plan_pro_sites',       '10'),
  ('plan_enterprise_sites','-1'),
  ('site_domain',          'cloudpress.site'),
  ('toss_client_key',      ''),
  ('toss_secret_key',      ''),
  ('contact_email',        'choichoi3227@gmail.com'),
  ('cms_latest_version',   '1.0.0');

INSERT OR IGNORE INTO cms_versions (id, version, label, description, is_stable, is_latest) VALUES
  ('cv1', '1.0.0', 'CloudPress CMS v1.0.0', '초기 안정 버전 — 워드프레스 호환 블록 에디터, 테마·플러그인 지원', 1, 1),
  ('cv2', '1.1.0-beta', 'CloudPress CMS v1.1.0 Beta', '베타: 멀티사이트, WooCommerce 호환 레이어 추가', 0, 0);

CREATE INDEX IF NOT EXISTS idx_sites_user      ON sites(user_id);
CREATE INDEX IF NOT EXISTS idx_sites_subdomain ON sites(subdomain);
CREATE INDEX IF NOT EXISTS idx_payments_user   ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_order  ON payments(order_id);
CREATE INDEX IF NOT EXISTS idx_traffic_time    ON traffic_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_traffic_user    ON traffic_logs(user_id);

-- CMS 패키지 메타데이터 (ZIP 업로드 기록)
-- 실제 ZIP 데이터는 KV(SESSIONS)에 저장: cms_package:{version}
CREATE TABLE IF NOT EXISTS cms_packages (
  id           TEXT PRIMARY KEY,
  version      TEXT NOT NULL UNIQUE,
  filename     TEXT NOT NULL DEFAULT '',
  filesize     INTEGER NOT NULL DEFAULT 0,
  description  TEXT DEFAULT '',
  is_latest    INTEGER DEFAULT 0,
  is_stable    INTEGER DEFAULT 1,
  uploaded_by  TEXT REFERENCES users(id),
  uploaded_at  INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_pkg_version ON cms_packages(version);
