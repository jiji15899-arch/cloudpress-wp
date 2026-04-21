-- CloudPress v20.0 — migrate-v20.sql
-- 기존 v19 이하에서 v20으로 업그레이드 시 실행
-- wrangler d1 execute cloudpress-db --file=migrate-v20.sql --remote

-- sites 테이블에 Supabase + 설치 잠금 컬럼 추가
ALTER TABLE sites ADD COLUMN supabase_url TEXT;
ALTER TABLE sites ADD COLUMN supabase_key TEXT;
ALTER TABLE sites ADD COLUMN supabase_project_id TEXT;
ALTER TABLE sites ADD COLUMN storage_bucket TEXT DEFAULT 'media';
ALTER TABLE sites ADD COLUMN supabase_url2 TEXT;
ALTER TABLE sites ADD COLUMN supabase_key2 TEXT;
ALTER TABLE sites ADD COLUMN supabase_project_id2 TEXT;
ALTER TABLE sites ADD COLUMN storage_bucket2 TEXT DEFAULT 'media-backup';
ALTER TABLE sites ADD COLUMN storage_active INTEGER DEFAULT 1;
ALTER TABLE sites ADD COLUMN wp_installed INTEGER DEFAULT 0;
ALTER TABLE sites ADD COLUMN wp_version TEXT DEFAULT '6.7';
ALTER TABLE sites ADD COLUMN custom_domain TEXT;

-- settings에 Supabase 관리 설정 추가
INSERT OR IGNORE INTO settings (key, value) VALUES ('supabase_mgmt_token', '');
INSERT OR IGNORE INTO settings (key, value) VALUES ('supabase_org_id', '');

-- 기존 active 사이트들 설치 잠금 표시
UPDATE sites SET wp_installed = 1 WHERE status = 'active';

-- 인덱스
CREATE INDEX IF NOT EXISTS idx_sites_custom_domain ON sites(custom_domain);
