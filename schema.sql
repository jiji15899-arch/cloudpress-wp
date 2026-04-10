-- CloudPress v7.0 — 개인도메인 + Cloudflare Worker 프록시 스키마
-- ✅ v7: cf_worker_name, cf_worker_url, cf_kv_namespace_id 필드 추가
-- ✅ D1/KV 콘텐츠 동기화 테이블 추가
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

  -- 호스팅 정보 (내부용 — 사용자에게 노출 안 됨)
  hosting_provider TEXT NOT NULL DEFAULT 'self_managed',
  hosting_email TEXT,
  hosting_password TEXT,
  hosting_domain TEXT,            -- 실제 WP 서버 서브도메인 (내부)
  subdomain TEXT DEFAULT NULL,
  account_username TEXT,
  cpanel_url TEXT,
  web_path TEXT,

  -- WordPress 정보
  -- wp_url / wp_admin_url은 개인 도메인 기준 (사용자에게 보이는 URL)
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

  -- ★ Cloudflare Worker 정보 (개인도메인 프록시)
  cf_worker_name TEXT,             -- Worker 이름 (예: myblog-com-proxy)
  cf_worker_url TEXT,              -- Worker URL (workers.dev)
  cf_kv_namespace_id TEXT,         -- KV Namespace ID (콘텐츠 캐시용)
  cf_d1_database_id TEXT,          -- D1 Database ID (콘텐츠 저장용)

  -- 도메인 (사용자 개인 도메인)
  primary_domain TEXT,             -- 개인 도메인 (예: myblog.com)
  custom_domain TEXT,              -- 동일 (하위 호환)
  domain_status TEXT DEFAULT NULL, -- pending / deploying / active / pending_manual
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
  server_type TEXT DEFAULT 'shared',
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

-- ★ 사이트 콘텐츠 D1 동기화 상태
-- 글/페이지/미디어의 CF KV 동기화 기록
CREATE TABLE IF NOT EXISTS site_content_sync (
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL,
  content_type TEXT NOT NULL,      -- post / page / media
  wp_id INTEGER NOT NULL,          -- WordPress post ID
  kv_key TEXT NOT NULL,            -- CF KV 키
  synced_at TEXT NOT NULL DEFAULT (datetime('now')),
  checksum TEXT,                   -- 변경 감지용
  FOREIGN KEY (site_id) REFERENCES sites(id)
);

-- 인덱스
CREATE INDEX IF NOT EXISTS idx_sites_user_id      ON sites(user_id);
CREATE INDEX IF NOT EXISTS idx_sites_status       ON sites(status);
CREATE INDEX IF NOT EXISTS idx_sites_custom_domain ON sites(custom_domain);
CREATE INDEX IF NOT EXISTS idx_payments_user_id   ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_domains_site_id    ON domains(site_id);
CREATE INDEX IF NOT EXISTS idx_domains_domain     ON domains(domain);
CREATE INDEX IF NOT EXISTS idx_content_sync_site  ON site_content_sync(site_id);

-- 기본 설정값
INSERT OR IGNORE INTO settings (key, value) VALUES
  -- 플랜별 사이트 수
  ('plan_free_sites',        '1'),
  ('plan_starter_sites',     '3'),
  ('plan_pro_sites',         '10'),
  ('plan_enterprise_sites',  '-1'),

  -- 서버 직접 접근 설정
  ('server_ip',              ''),
  ('ftp_host',               ''),
  ('ftp_user',               ''),
  ('ftp_pass',               ''),
  ('ftp_port',               '21'),
  ('server_panel',           ''),
  ('panel_user',             ''),
  ('panel_pass',             ''),
  ('db_host',                'localhost'),
  ('db_root_user',           'root'),
  ('db_root_pass',           ''),
  ('web_root',               '/htdocs'),
  ('php_bin',                'php8.3'),

  -- Puppeteer Worker
  ('puppeteer_worker_url',    ''),
  ('puppeteer_worker_secret', ''),

  -- 호스팅 서버 접근 설정
  ('hosting_cpanel_url',       ''),
  ('hosting_server_username',  ''),
  ('hosting_server_password',  ''),
  ('hosting_server_domain',    ''),

  -- Cloudflare (관리자 계정 — 선택사항)
  ('cf_api_token',            ''),
  ('cf_account_id',           ''),
  ('cloudflare_cdn_enabled',  '1'),
  ('auto_ssl',                '1'),
  ('auto_breeze',             '1'),
  ('cname_target',            'proxy.cloudpress.site'),

  -- 일반
  ('maintenance_mode',  '0'),
  ('site_name',         'CloudPress'),
  ('site_domain',       'cloudpress.site');
