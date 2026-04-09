-- CloudPress v6.0 — 완전 자체 관리 WordPress 호스팅 스키마
-- ✅ 외부 호스팅사 계정 없음 — iFastnet 서버 IP만 사용
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

-- 세션
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

  -- 자체 관리 정보 (외부 호스팅사 없음)
  hosting_provider TEXT NOT NULL DEFAULT 'self_managed',
  hosting_email TEXT,               -- 사용 안 함 (하위 호환용)
  hosting_password TEXT,            -- 서버 접근용 임시 키
  hosting_domain TEXT,
  subdomain TEXT DEFAULT NULL,
  account_username TEXT,            -- 자체 생성 서브도메인 슬러그
  cpanel_url TEXT,                  -- 서버 패널 URL
  web_path TEXT,                    -- 서버 실제 경로 (예: /htdocs/mysite4x2k)

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

  -- 도메인
  primary_domain TEXT,
  custom_domain TEXT,
  domain_status TEXT DEFAULT NULL,
  cname_target TEXT,

  -- 상태
  status TEXT NOT NULL DEFAULT 'pending',
  provision_step TEXT DEFAULT NULL,
  error_message TEXT,
  suspended INTEGER DEFAULT 0,
  suspension_reason TEXT,
  speed_optimized INTEGER DEFAULT 0,
  suspend_protected INTEGER DEFAULT 0,

  -- 리소스
  disk_used INTEGER DEFAULT 0,
  bandwidth_used INTEGER DEFAULT 0,

  php_version TEXT,
  plan TEXT NOT NULL DEFAULT 'free',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  deleted_at TEXT,

  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 도메인 테이블
CREATE TABLE IF NOT EXISTS domains (
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  domain TEXT NOT NULL UNIQUE,
  cname_target TEXT NOT NULL,
  cname_verified INTEGER DEFAULT 0,
  is_primary INTEGER DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending',
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

-- Push 구독
CREATE TABLE IF NOT EXISTS push_subscriptions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  endpoint TEXT NOT NULL UNIQUE,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 인덱스
CREATE INDEX IF NOT EXISTS idx_sites_user_id      ON sites(user_id);
CREATE INDEX IF NOT EXISTS idx_sites_status       ON sites(status);
CREATE INDEX IF NOT EXISTS idx_payments_user_id   ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_domains_site_id    ON domains(site_id);
CREATE INDEX IF NOT EXISTS idx_domains_domain     ON domains(domain);

-- 기본 설정값
INSERT OR IGNORE INTO settings (key, value) VALUES
  -- 플랜별 사이트 수
  ('plan_free_sites',        '1'),
  ('plan_starter_sites',     '3'),
  ('plan_pro_sites',         '10'),
  ('plan_enterprise_sites',  '-1'),

  -- ✅ iFastnet 서버 직접 접근 설정 (관리자가 채워야 함)
  ('server_ip',     ''),   -- iFastnet 서버 IP
  ('ftp_host',      ''),   -- FTP 호스트 (보통 server_ip와 동일)
  ('ftp_user',      ''),   -- FTP 계정
  ('ftp_pass',      ''),   -- FTP 비밀번호 (암호화 저장 권장)
  ('ftp_port',      '21'),
  ('server_panel',  ''),   -- 서버 패널 URL
  ('panel_user',    ''),
  ('panel_pass',    ''),
  ('db_host',       'localhost'),
  ('db_root_user',  'root'),
  ('db_root_pass',  ''),
  ('web_root',      '/htdocs'),
  ('php_bin',       'php8.3'),

  -- Worker
  ('puppeteer_worker_url',    ''),
  ('puppeteer_worker_secret', ''),

  -- ✅ 호스팅 서버 접근 설정 (getHostingServerConfig에서 사용)
  ('hosting_cpanel_url',       ''),   -- cPanel URL (예: https://cpanel.example.com:2083)
  ('hosting_server_username',  ''),   -- cPanel 관리자 계정
  ('hosting_server_password',  ''),   -- cPanel 관리자 비밀번호
  ('hosting_server_domain',    ''),   -- 서버 기본 도메인

  -- Cloudflare
  ('cloudflare_cdn_enabled',  '1'),
  ('auto_ssl',                '1'),
  ('auto_breeze',             '1'),
  ('cname_target',            'proxy.cloudpress.site'),

  -- 일반
  ('maintenance_mode',  '0'),
  ('site_name',         'CloudPress'),
  ('site_domain',       'cloudpress.site');
