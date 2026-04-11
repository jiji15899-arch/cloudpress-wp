-- CloudPress v11.0 — 단일 WP Origin + Worker 프록시 + 도메인별 D1/KV 격리
-- 아키텍처:
--   관리자 지정 WP origin 1개
--   Cloudflare Worker가 요청 도메인 → D1에서 사이트 조회 → prefix 헤더 붙여 WP 프록시
--   각 사이트: D1 테이블 prefix 분리 + KV key prefix 분리 (완전 격리)
--   개인 도메인: CF DNS API 자동 + CNAME 수동 + Worker Route로 루트도메인 덮어씌우기

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

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ★ 핵심: 사이트 테이블
-- WP 설치는 없음. 단일 origin WP를 공유하되 prefix로 완전 격리
CREATE TABLE IF NOT EXISTS sites (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,

  -- 사용자 개인 도메인 (실제 접속 도메인 — 루트 덮어씌우기)
  primary_domain TEXT,              -- 예: myblog.com
  www_domain TEXT,                  -- 예: www.myblog.com (자동)
  domain_status TEXT DEFAULT 'pending',
  -- pending / dns_propagating / worker_deploying / active / failed / manual_required

  -- D1/KV 격리 키
  -- 이 prefix로 모든 WP 테이블명 분리 (wp_{prefix}_posts 등)
  -- KV에도 {prefix}:{key} 형태로 격리
  site_prefix TEXT NOT NULL UNIQUE, -- 예: s_a3k9x2 (7자, 충돌방지)

  -- Cloudflare Worker 배포 정보
  worker_name TEXT,                 -- 예: cp-myblog-com
  worker_route TEXT,                -- 예: myblog.com/* (루트 라우트)
  worker_route_www TEXT,            -- 예: www.myblog.com/*
  worker_route_id TEXT,             -- CF route ID (삭제용)
  worker_route_www_id TEXT,
  cf_zone_id TEXT,                  -- 사용자 도메인의 CF zone ID (자동 연결 시)
  dns_record_id TEXT,               -- CF DNS A/CNAME record ID
  dns_record_www_id TEXT,

  -- WP 관리자 계정 (origin WP에 생성된 계정)
  wp_username TEXT NOT NULL,
  wp_password TEXT NOT NULL,
  wp_admin_email TEXT,

  -- WP 관리자 접속 URL (origin 기반)
  wp_admin_url TEXT,                -- https://origin.cloudpress.site/wp-admin/?siteprefix=xxx

  -- 상태
  status TEXT NOT NULL DEFAULT 'pending',
  -- pending / provisioning / active / failed / suspended
  provision_step TEXT DEFAULT 'init',
  error_message TEXT,
  suspended INTEGER DEFAULT 0,
  suspension_reason TEXT,

  -- 리소스
  disk_used INTEGER DEFAULT 0,
  bandwidth_used INTEGER DEFAULT 0,
  plan TEXT NOT NULL DEFAULT 'free',

  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  deleted_at TEXT,

  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 설정
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 알림
CREATE TABLE IF NOT EXISTS notices (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'info',
  target_role TEXT DEFAULT 'all',
  active INTEGER DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 결제
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

-- 도메인 이력 (수동 검증 추적)
CREATE TABLE IF NOT EXISTS domain_verifications (
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  method TEXT NOT NULL,         -- 'cname' / 'cf_api' / 'worker_route'
  verified INTEGER DEFAULT 0,
  verified_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (site_id) REFERENCES sites(id)
);

-- 인덱스
CREATE INDEX IF NOT EXISTS idx_sites_user_id       ON sites(user_id);
CREATE INDEX IF NOT EXISTS idx_sites_status        ON sites(status);
CREATE INDEX IF NOT EXISTS idx_sites_primary_domain ON sites(primary_domain);
CREATE INDEX IF NOT EXISTS idx_sites_site_prefix   ON sites(site_prefix);
CREATE INDEX IF NOT EXISTS idx_payments_user_id    ON payments(user_id);

-- 기본 설정값
INSERT OR IGNORE INTO settings (key, value) VALUES
  -- 플랜별 사이트 수
  ('plan_free_sites',        '1'),
  ('plan_starter_sites',     '3'),
  ('plan_pro_sites',         '10'),
  ('plan_enterprise_sites',  '-1'),

  -- ★ 핵심: 단일 WP Origin 설정
  ('wp_origin_url',          ''),   -- 예: https://origin.cloudpress.site
  ('wp_origin_secret',       ''),   -- WP mu-plugin 공유 시크릿 (헤더 검증용)
  ('wp_admin_base_url',      ''),   -- origin WP admin URL

  -- Cloudflare (관리자 계정)
  ('cf_api_token',           ''),   -- Edit DNS + Worker Routes 권한
  ('cf_account_id',          ''),
  ('cf_worker_script',       ''),   -- 배포된 Worker 스크립트 이름 (단일 Worker)
  ('cf_worker_name',         'cloudpress-proxy'), -- Worker 이름

  -- 도메인 기본값 (사용자 CNAME 대상)
  ('worker_cname_target',    ''),   -- workers.dev subdomain (CNAME 수동 설정 시 안내)

  -- 일반
  ('maintenance_mode',       '0'),
  ('site_name',              'CloudPress'),
  ('site_domain',            'cloudpress.site'),
  ('toss_client_key',        ''),
  ('toss_secret_key',        '');

-- ─────────────────────────────────────────────
-- Migration: www_domain 컬럼 추가 (기존 DB 호환)
-- 이미 컬럼이 있으면 무시됨 (SQLite는 IF NOT EXISTS 미지원 → 앱 레벨에서 처리)
-- Cloudflare D1 콘솔 또는 wrangler에서 아래 구문을 직접 실행:
--   ALTER TABLE sites ADD COLUMN www_domain TEXT;
-- ─────────────────────────────────────────────
