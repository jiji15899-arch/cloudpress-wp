-- CloudPress v3.0 — WordPress 호스팅 자동화 스키마
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
  hosting_provider TEXT NOT NULL,         -- infinityfree | byethost | hyperphp | freehosting | profreehost | aeonfree
  hosting_email TEXT NOT NULL,            -- 호스팅 계정 이메일
  hosting_password TEXT NOT NULL,         -- 호스팅 계정 비밀번호
  hosting_domain TEXT,                    -- 호스팅 도메인 (예: mysite.infinityfreeapp.com)
  subdomain TEXT NOT NULL DEFAULT '',          -- 서브도메인 (예: mysite)
  cpanel_url TEXT,                        -- cPanel 로그인 URL

  -- WordPress 정보
  wp_url TEXT,                            -- WordPress 사이트 URL
  wp_admin_url TEXT,                      -- WordPress 관리자 URL
  wp_username TEXT NOT NULL,              -- WordPress 관리자 아이디
  wp_password TEXT NOT NULL,              -- WordPress 관리자 비밀번호
  wp_admin_email TEXT,                    -- WordPress 관리자 이메일
  wp_version TEXT DEFAULT '6.x',         -- WordPress 버전
  breeze_installed INTEGER DEFAULT 0,    -- Breeze 캐시 플러그인 설치 여부

  -- SSL / CDN
  ssl_active INTEGER DEFAULT 0,           -- SSL 인증서 활성 여부
  cloudflare_zone_id TEXT,               -- Cloudflare Zone ID

  -- 상태
  status TEXT NOT NULL DEFAULT 'pending', -- pending | provisioning | installing_wp | active | failed | deleted
  error_message TEXT,
  suspended INTEGER DEFAULT 0,           -- 일시정지 여부
  suspension_reason TEXT,                -- 일시정지 사유

  -- 리소스 사용량
  disk_used INTEGER DEFAULT 0,           -- 디스크 사용량 (MB)
  bandwidth_used INTEGER DEFAULT 0,      -- 대역폭 사용량 (MB)

  plan TEXT NOT NULL DEFAULT 'free',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  deleted_at TEXT,

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
  type TEXT NOT NULL DEFAULT 'info',  -- info | warning | success | danger
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
  status TEXT NOT NULL DEFAULT 'pending',  -- pending | paid | failed | refunded
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

-- 기본 설정값
INSERT OR IGNORE INTO settings (key, value) VALUES
  ('plan_free_sites', '1'),
  ('plan_starter_sites', '3'),
  ('plan_pro_sites', '10'),
  ('plan_enterprise_sites', '-1'),
  ('maintenance_mode', '0'),
  ('site_name', 'CloudPress'),
  ('puppeteer_worker_url', 'https://cloudpress-puppet.workers.dev'),
  ('cloudflare_cdn_enabled', '1'),
  ('auto_ssl', '1'),
  ('auto_breeze', '1');
