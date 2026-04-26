-- 자동 업데이트 마지막 실행 시각
ALTER TABLE sites ADD COLUMN wp_auto_update_at TEXT;

-- 신규 기능 대응 컬럼 추가 (Task 1, 4, 7, 10, 11 관련)
ALTER TABLE sites ADD COLUMN region TEXT DEFAULT 'icn';
ALTER TABLE sites ADD COLUMN edge_ip TEXT;
ALTER TABLE sites ADD COLUMN wp_username TEXT;
ALTER TABLE sites ADD COLUMN wp_password TEXT;
ALTER TABLE sites ADD COLUMN wp_version TEXT DEFAULT 'latest';
ALTER TABLE sites ADD COLUMN php_version TEXT DEFAULT '8.3';
ALTER TABLE sites ADD COLUMN wp_auto_update TEXT DEFAULT 'minor';
ALTER TABLE sites ADD COLUMN alias_domains TEXT DEFAULT '[]';

-- 설정: WordPress 자동 업데이트 활성화 여부
INSERT OR IGNORE INTO settings (key, value) VALUES ('wp_auto_update_enabled', 'true');
-- 설정: 자동 업데이트 대상 버전 (major, minor, all)
INSERT OR IGNORE INTO settings (key, value) VALUES ('wp_auto_update_channel', 'minor');
-- 설정: 자동 업데이트 최대 동시 사이트 수
INSERT OR IGNORE INTO settings (key, value) VALUES ('wp_auto_update_batch',   '10');

-- 결제 및 호스팅 단위 관리 컬럼 추가
ALTER TABLE sites ADD COLUMN billing_status TEXT DEFAULT 'trial'; -- trial, active, past_due
ALTER TABLE sites ADD COLUMN trial_ends_at TEXT;
ALTER TABLE sites ADD COLUMN subscription_id TEXT;

-- 사용자 카드 정보 (암호화 권장, 여기서는 필드만 추가)
ALTER TABLE users ADD COLUMN card_number TEXT;
ALTER TABLE users ADD COLUMN card_expiry TEXT;

-- 관리자 설정: 토스 가상계좌
INSERT OR IGNORE INTO settings (key, value) VALUES ('toss_virtual_account', '');

-- 포럼 및 문의하기 테이블 생성
CREATE TABLE IF NOT EXISTS forum_posts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, title TEXT, content TEXT, status TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS support_tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, subject TEXT, message TEXT, email TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
