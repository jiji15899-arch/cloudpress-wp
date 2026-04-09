-- CloudPress v4.0 — WordPress 호스팅 자동화 스키마
-- Cloudflare D1 호환

-- 사용자 테이블
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  plan TEXT NOT NULL DEFAULT 'free',
  plan_expires_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 세션 (KV 대신 D1 폴백용)
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- WordPress 호스팅 사이트 테이블
CREATE TABLE IF NOT EXISTS sites (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,

  -- 호스팅 정보
  hosting_provider TEXT NOT NULL,
  hosting_email TEXT NOT NULL,
  hosting_password TEXT NOT NULL,
  hosting_domain TEXT,
  subdomain TEXT DEFAULT NULL,
  account_username TEXT,
  cpanel_url TEXT,

  -- WordPress 정보
  wp_url TEXT,
  wp_admin_url TEXT,
  wp_username TEXT NOT NULL,
  wp_password TEXT NOT NULL,
  wp_admin_email TEXT,
  wp_version TEXT DEFAULT '6.x',
  breeze_installed INTEGER DEFAULT 0,
  cron_enabled INTEGER DEFAULT 0,

  -- SSL / CDN
  ssl_active INTEGER DEFAULT 0,
  cloudflare_zone_id TEXT,

  -- 도메인 관련
  primary_domain TEXT,                    -- 현재 주 도메인 (커스텀 or 서브도메인)
  custom_domain TEXT,                     -- 연결된 커스텀 도메인
  domain_status TEXT DEFAULT NULL,        -- null | pending_cname | active | failed

  -- 상태
  status TEXT NOT NULL DEFAULT 'pending',
  provision_step TEXT DEFAULT NULL,
  error_message TEXT,
  suspended INTEGER DEFAULT 0,
  suspension_reason TEXT,
  speed_optimized INTEGER DEFAULT 0,
  suspend_protected INTEGER DEFAULT 0,

  -- 리소스 사용량
  disk_used INTEGER DEFAULT 0,
  bandwidth_used INTEGER DEFAULT 0,

  plan TEXT NOT NULL DEFAULT 'free',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  deleted_at TEXT,

  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 도메인 테이블 (사이트별 커스텀 도메인 관리)
CREATE TABLE IF NOT EXISTS domains (
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  domain TEXT NOT NULL UNIQUE,
  cname_target TEXT NOT NULL,             -- CNAME 레코드가 가리켜야 할 값
  cname_verified INTEGER DEFAULT 0,       -- CNAME 인증 여부
  is_primary INTEGER DEFAULT 0,           -- 주 도메인 여부
  status TEXT NOT NULL DEFAULT 'pending', -- pending | verifying | active | failed
  verified_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (site_id) REFERENCES sites(id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 설정 테이블
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 알림 테이블
CREATE TABLE IF NOT EXISTS notices (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'info',
  target_role TEXT DEFAULT 'all',
  active INTEGER DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 결제 내역
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

-- 인덱스
CREATE INDEX IF NOT EXISTS idx_sites_user_id ON sites(user_id);
CREATE INDEX IF NOT EXISTS idx_sites_status ON sites(status);
CREATE INDEX IF NOT EXISTS idx_sites_hosting_provider ON sites(hosting_provider);
CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_domains_site_id ON domains(site_id);
CREATE INDEX IF NOT EXISTS idx_domains_user_id ON domains(user_id);
CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain);

-- 기본 설정값
INSERT OR IGNORE INTO settings (key, value) VALUES
  ('plan_free_sites', '1'),
  ('plan_starter_sites', '3'),
  ('plan_pro_sites', '10'),
  ('plan_enterprise_sites', '-1'),
  ('maintenance_mode', '0'),
  ('site_name', 'CloudPress'),
  ('puppeteer_worker_url', ''),
  ('cloudflare_cdn_enabled', '1'),
  ('auto_ssl', '1'),
  ('auto_breeze', '1'),
  ('cname_target', 'proxy.cloudpress.site');
