-- CloudPress v20.0 — schema.sql
-- WordPress 호환 D1 스키마 (완전한 WordPress DB 구조)
-- + Supabase 스토리지 이중화 + 설치 잠금
-- wrangler d1 execute cloudpress-db --file=schema.sql --remote

-- ══════════════════════════════════════════════════════════════════
-- 플랫폼 테이블 (CloudPress 관리용)
-- ══════════════════════════════════════════════════════════════════

-- ── users (플랫폼 사용자) ──────────────────────────────────────────
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

-- ── sessions (플랫폼 세션) ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
  token       TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id),
  expires_at  TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── sites (호스팅 사이트) ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sites (
  id                  TEXT PRIMARY KEY,
  user_id             TEXT NOT NULL REFERENCES users(id),
  name                TEXT NOT NULL,

  -- 도메인
  primary_domain      TEXT,
  custom_domain       TEXT,
  domain_status       TEXT DEFAULT 'pending',

  -- 사이트 격리 ID
  site_prefix         TEXT UNIQUE,

  -- Cloudflare 리소스
  site_d1_id          TEXT,
  site_d1_name        TEXT,
  site_kv_id          TEXT,
  site_kv_title       TEXT,
  worker_name         TEXT,
  worker_route        TEXT,
  worker_route_www    TEXT,
  worker_route_id     TEXT,
  worker_route_www_id TEXT,
  cf_zone_id          TEXT,
  dns_record_id       TEXT,
  dns_record_www_id   TEXT,

  -- Supabase 스토리지 (Primary)
  supabase_url        TEXT,
  supabase_key        TEXT,
  supabase_project_id TEXT,
  storage_bucket      TEXT DEFAULT 'media',

  -- Supabase 스토리지 (Secondary — Primary 소진 시 자동 전환)
  supabase_url2       TEXT,
  supabase_key2       TEXT,
  supabase_project_id2 TEXT,
  storage_bucket2     TEXT DEFAULT 'media',
  storage_active      INTEGER DEFAULT 1,  -- 1=Primary, 2=Secondary, 3=D1 fallback

  -- WordPress 설치 정보
  wp_admin_url        TEXT,
  wp_admin_username   TEXT DEFAULT 'admin',
  wp_admin_password   TEXT,
  wp_installed        INTEGER DEFAULT 0,  -- 한 번 설치 후 재설치 방지
  wp_version          TEXT DEFAULT '6.7',

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

-- ── settings (플랫폼 설정) ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── notices (공지사항) ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS notices (
  id          TEXT PRIMARY KEY,
  title       TEXT NOT NULL,
  content     TEXT NOT NULL,
  type        TEXT NOT NULL DEFAULT 'info',
  target_role TEXT DEFAULT 'all',
  active      INTEGER DEFAULT 1,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ══════════════════════════════════════════════════════════════════
-- WordPress 호환 테이블 (wp_ prefix — 실제 WordPress와 완전 동일)
-- ══════════════════════════════════════════════════════════════════

-- ── wp_posts ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS wp_posts (
  ID                    INTEGER PRIMARY KEY AUTOINCREMENT,
  post_author           INTEGER NOT NULL DEFAULT 0,
  post_date             TEXT NOT NULL DEFAULT '',
  post_date_gmt         TEXT NOT NULL DEFAULT '',
  post_content          TEXT NOT NULL DEFAULT '',
  post_title            TEXT NOT NULL DEFAULT '',
  post_excerpt          TEXT NOT NULL DEFAULT '',
  post_status           TEXT NOT NULL DEFAULT 'publish',
  comment_status        TEXT NOT NULL DEFAULT 'open',
  ping_status           TEXT NOT NULL DEFAULT 'open',
  post_password         TEXT NOT NULL DEFAULT '',
  post_name             TEXT NOT NULL DEFAULT '',
  to_ping               TEXT NOT NULL DEFAULT '',
  pinged                TEXT NOT NULL DEFAULT '',
  post_modified         TEXT NOT NULL DEFAULT '',
  post_modified_gmt     TEXT NOT NULL DEFAULT '',
  post_content_filtered TEXT NOT NULL DEFAULT '',
  post_parent           INTEGER NOT NULL DEFAULT 0,
  guid                  TEXT NOT NULL DEFAULT '',
  menu_order            INTEGER NOT NULL DEFAULT 0,
  post_type             TEXT NOT NULL DEFAULT 'post',
  post_mime_type        TEXT NOT NULL DEFAULT '',
  comment_count         INTEGER NOT NULL DEFAULT 0
);

-- ── wp_postmeta ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS wp_postmeta (
  meta_id    INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id    INTEGER NOT NULL DEFAULT 0,
  meta_key   TEXT DEFAULT NULL,
  meta_value TEXT
);

-- ── wp_users (WordPress 사용자) ───────────────────────────────────
CREATE TABLE IF NOT EXISTS wp_users (
  ID                  INTEGER PRIMARY KEY AUTOINCREMENT,
  user_login          TEXT NOT NULL DEFAULT '',
  user_pass           TEXT NOT NULL DEFAULT '',
  user_nicename       TEXT NOT NULL DEFAULT '',
  user_email          TEXT NOT NULL DEFAULT '',
  user_url            TEXT NOT NULL DEFAULT '',
  user_registered     TEXT NOT NULL DEFAULT '',
  user_activation_key TEXT NOT NULL DEFAULT '',
  user_status         INTEGER NOT NULL DEFAULT 0,
  display_name        TEXT NOT NULL DEFAULT ''
);

-- ── wp_usermeta ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS wp_usermeta (
  umeta_id   INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL DEFAULT 0,
  meta_key   TEXT DEFAULT NULL,
  meta_value TEXT
);

-- ── wp_options ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS wp_options (
  option_id    INTEGER PRIMARY KEY AUTOINCREMENT,
  option_name  TEXT NOT NULL DEFAULT '',
  option_value TEXT NOT NULL DEFAULT '',
  autoload     TEXT NOT NULL DEFAULT 'yes',
  UNIQUE(option_name)
);

-- ── wp_terms ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS wp_terms (
  term_id    INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT NOT NULL DEFAULT '',
  slug       TEXT NOT NULL DEFAULT '',
  term_group INTEGER NOT NULL DEFAULT 0
);

-- ── wp_term_taxonomy ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS wp_term_taxonomy (
  term_taxonomy_id INTEGER PRIMARY KEY AUTOINCREMENT,
  term_id          INTEGER NOT NULL DEFAULT 0,
  taxonomy         TEXT NOT NULL DEFAULT '',
  description      TEXT NOT NULL DEFAULT '',
  parent           INTEGER NOT NULL DEFAULT 0,
  count            INTEGER NOT NULL DEFAULT 0
);

-- ── wp_term_relationships ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS wp_term_relationships (
  object_id        INTEGER NOT NULL DEFAULT 0,
  term_taxonomy_id INTEGER NOT NULL DEFAULT 0,
  term_order       INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (object_id, term_taxonomy_id)
);

-- ── wp_term_meta ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS wp_term_meta (
  meta_id    INTEGER PRIMARY KEY AUTOINCREMENT,
  term_id    INTEGER NOT NULL DEFAULT 0,
  meta_key   TEXT DEFAULT NULL,
  meta_value TEXT
);

-- ── wp_comments ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS wp_comments (
  comment_ID           INTEGER PRIMARY KEY AUTOINCREMENT,
  comment_post_ID      INTEGER NOT NULL DEFAULT 0,
  comment_author       TEXT NOT NULL DEFAULT '',
  comment_author_email TEXT NOT NULL DEFAULT '',
  comment_author_url   TEXT NOT NULL DEFAULT '',
  comment_author_IP    TEXT NOT NULL DEFAULT '',
  comment_date         TEXT NOT NULL DEFAULT '',
  comment_date_gmt     TEXT NOT NULL DEFAULT '',
  comment_content      TEXT NOT NULL DEFAULT '',
  comment_karma        INTEGER NOT NULL DEFAULT 0,
  comment_approved     TEXT NOT NULL DEFAULT '1',
  comment_agent        TEXT NOT NULL DEFAULT '',
  comment_type         TEXT NOT NULL DEFAULT 'comment',
  comment_parent       INTEGER NOT NULL DEFAULT 0,
  user_id              INTEGER NOT NULL DEFAULT 0
);

-- ── wp_commentmeta ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS wp_commentmeta (
  meta_id    INTEGER PRIMARY KEY AUTOINCREMENT,
  comment_id INTEGER NOT NULL DEFAULT 0,
  meta_key   TEXT DEFAULT NULL,
  meta_value TEXT
);

-- ── wp_links (북마크/링크) ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS wp_links (
  link_id          INTEGER PRIMARY KEY AUTOINCREMENT,
  link_url         TEXT NOT NULL DEFAULT '',
  link_name        TEXT NOT NULL DEFAULT '',
  link_image       TEXT NOT NULL DEFAULT '',
  link_target      TEXT NOT NULL DEFAULT '',
  link_description TEXT NOT NULL DEFAULT '',
  link_visible     TEXT NOT NULL DEFAULT 'Y',
  link_owner       INTEGER NOT NULL DEFAULT 1,
  link_rating      INTEGER NOT NULL DEFAULT 0,
  link_updated     TEXT NOT NULL DEFAULT '',
  link_rel         TEXT NOT NULL DEFAULT '',
  link_notes       TEXT NOT NULL DEFAULT '',
  link_rss         TEXT NOT NULL DEFAULT ''
);

-- ── wp_media (CloudPress 미디어 레코드 + Supabase 연동) ───────────
CREATE TABLE IF NOT EXISTS wp_media (
  media_id    INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id     INTEGER DEFAULT 0,
  file_name   TEXT NOT NULL,
  file_path   TEXT NOT NULL UNIQUE,
  mime_type   TEXT NOT NULL DEFAULT 'application/octet-stream',
  file_size   INTEGER NOT NULL DEFAULT 0,
  upload_date TEXT NOT NULL DEFAULT '',
  storage     TEXT NOT NULL DEFAULT 'supabase',  -- 'supabase', 'supabase2', 'd1', 'kv'
  storage_url TEXT,
  alt_text    TEXT DEFAULT '',
  caption     TEXT DEFAULT '',
  width       INTEGER DEFAULT 0,
  height      INTEGER DEFAULT 0
);

-- ── wp_cron_events ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS wp_cron_events (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp INTEGER NOT NULL,
  schedule  TEXT,
  hook      TEXT NOT NULL,
  args      TEXT NOT NULL DEFAULT '[]'
);

-- ── wp_nav_menus (네비게이션 메뉴) ───────────────────────────────
-- wp_posts + wp_postmeta 활용 (WordPress 표준 방식)

-- ══════════════════════════════════════════════════════════════════
-- 채팅 / 상담봇 테이블
-- ══════════════════════════════════════════════════════════════════

-- ── chat_tickets (상담 티켓) ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS chat_tickets (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users(id),
  subject      TEXT NOT NULL DEFAULT '문의',
  status       TEXT NOT NULL DEFAULT 'open',   -- open | answered | closed
  is_read_user INTEGER DEFAULT 0,              -- 사용자 미확인 답변 있음
  is_read_admin INTEGER DEFAULT 0,             -- 어드민 미확인 문의 있음
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── chat_messages (상담 메시지) ───────────────────────────────────
CREATE TABLE IF NOT EXISTS chat_messages (
  id          TEXT PRIMARY KEY,
  ticket_id   TEXT NOT NULL REFERENCES chat_tickets(id),
  sender_role TEXT NOT NULL DEFAULT 'user',    -- user | admin | bot
  content     TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_chat_tickets_user   ON chat_tickets(user_id);
CREATE INDEX IF NOT EXISTS idx_chat_tickets_status ON chat_tickets(status);
CREATE INDEX IF NOT EXISTS idx_chat_messages_ticket ON chat_messages(ticket_id);

-- ══════════════════════════════════════════════════════════════════
-- 인덱스
-- ══════════════════════════════════════════════════════════════════
CREATE INDEX IF NOT EXISTS idx_sites_domain     ON sites(primary_domain);
CREATE INDEX IF NOT EXISTS idx_sites_prefix     ON sites(site_prefix);
CREATE INDEX IF NOT EXISTS idx_sites_user       ON sites(user_id);
CREATE INDEX IF NOT EXISTS idx_sites_status     ON sites(status);

CREATE INDEX IF NOT EXISTS idx_wp_posts_name    ON wp_posts(post_name);
CREATE INDEX IF NOT EXISTS idx_wp_posts_type_status ON wp_posts(post_type, post_status);
CREATE INDEX IF NOT EXISTS idx_wp_posts_date    ON wp_posts(post_date);
CREATE INDEX IF NOT EXISTS idx_wp_posts_parent  ON wp_posts(post_parent);
CREATE INDEX IF NOT EXISTS idx_wp_posts_author  ON wp_posts(post_author);

CREATE INDEX IF NOT EXISTS idx_wp_postmeta_post ON wp_postmeta(post_id);
CREATE INDEX IF NOT EXISTS idx_wp_postmeta_key  ON wp_postmeta(meta_key);

CREATE INDEX IF NOT EXISTS idx_wp_users_login   ON wp_users(user_login);
CREATE INDEX IF NOT EXISTS idx_wp_users_email   ON wp_users(user_email);

CREATE INDEX IF NOT EXISTS idx_wp_usermeta_user ON wp_usermeta(user_id);
CREATE INDEX IF NOT EXISTS idx_wp_usermeta_key  ON wp_usermeta(meta_key);

CREATE INDEX IF NOT EXISTS idx_wp_options_auto  ON wp_options(autoload);

CREATE INDEX IF NOT EXISTS idx_wp_terms_slug    ON wp_terms(slug);
CREATE INDEX IF NOT EXISTS idx_wp_tt_term       ON wp_term_taxonomy(term_id);
CREATE INDEX IF NOT EXISTS idx_wp_tt_tax        ON wp_term_taxonomy(taxonomy);
CREATE INDEX IF NOT EXISTS idx_wp_tr_tax        ON wp_term_relationships(term_taxonomy_id);

CREATE INDEX IF NOT EXISTS idx_wp_comments_post ON wp_comments(comment_post_ID);
CREATE INDEX IF NOT EXISTS idx_wp_comments_approved ON wp_comments(comment_approved);
CREATE INDEX IF NOT EXISTS idx_wp_commentmeta_comment ON wp_commentmeta(comment_id);

CREATE INDEX IF NOT EXISTS idx_wp_cron_ts       ON wp_cron_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_wp_media_post    ON wp_media(post_id);

-- ══════════════════════════════════════════════════════════════════
-- 기본 WordPress 옵션 데이터 (WordPress 표준)
-- ══════════════════════════════════════════════════════════════════
INSERT OR IGNORE INTO wp_options (option_name, option_value, autoload) VALUES
  ('siteurl',                 'https://example.com',         'yes'),
  ('home',                    'https://example.com',         'yes'),
  ('blogname',                'My WordPress Site',           'yes'),
  ('blogdescription',         'Just another WordPress site', 'yes'),
  ('users_can_register',      '0',                           'yes'),
  ('admin_email',             'admin@example.com',           'yes'),
  ('start_of_week',           '0',                           'yes'),
  ('use_balanceTags',         '0',                           'yes'),
  ('use_smilies',             '1',                           'yes'),
  ('require_name_email',      '1',                           'yes'),
  ('comments_notify',         '1',                           'yes'),
  ('posts_per_rss',           '10',                          'yes'),
  ('rss_use_excerpt',         '0',                           'yes'),
  ('mailserver_url',          'mail.example.com',            'yes'),
  ('mailserver_login',        'login@example.com',           'yes'),
  ('mailserver_pass',         'password',                    'yes'),
  ('mailserver_port',         '110',                         'yes'),
  ('default_category',        '1',                           'yes'),
  ('default_comment_status',  'open',                        'yes'),
  ('default_ping_status',     'open',                        'yes'),
  ('default_pingback_flag',   '1',                           'yes'),
  ('posts_per_page',          '10',                          'yes'),
  ('date_format',             'Y년 n월 j일',                  'yes'),
  ('time_format',             'A g:i',                       'yes'),
  ('links_updated_date_format','Y년 n월 j일 g:i a',           'yes'),
  ('comment_moderation',      '0',                           'yes'),
  ('moderation_notify',       '1',                           'yes'),
  ('permalink_structure',     '/%postname%/',                'yes'),
  ('rewrite_rules',           '',                            'yes'),
  ('hack_file',               '0',                           'yes'),
  ('blog_charset',            'UTF-8',                       'yes'),
  ('moderation_keys',         '',                            'no'),
  ('active_plugins',          'a:0:{}',                      'yes'),
  ('active_theme',            '',                            'yes'),
  ('template',                'twentytwentyfour',            'yes'),
  ('stylesheet',              'twentytwentyfour',            'yes'),
  ('comment_registration',    '0',                           'yes'),
  ('html_type',               'text/html',                   'yes'),
  ('use_trackback',           '0',                           'yes'),
  ('default_role',            'subscriber',                  'yes'),
  ('db_version',              '57155',                       'yes'),
  ('uploads_use_yearmonth_folders','1',                      'yes'),
  ('upload_path',             '',                            'yes'),
  ('blog_public',             '1',                           'yes'),
  ('default_link_category',   '2',                           'yes'),
  ('show_on_front',           'posts',                       'yes'),
  ('tag_base',                '',                            'yes'),
  ('show_avatars',            '1',                           'yes'),
  ('avatar_rating',           'G',                           'yes'),
  ('upload_url_path',         '',                            'yes'),
  ('thumbnail_size_w',        '150',                         'yes'),
  ('thumbnail_size_h',        '150',                         'yes'),
  ('thumbnail_crop',          '1',                           'yes'),
  ('medium_size_w',           '300',                         'yes'),
  ('medium_size_h',           '300',                         'yes'),
  ('avatar_default',          'mystery',                     'yes'),
  ('large_size_w',            '1024',                        'yes'),
  ('large_size_h',            '1024',                        'yes'),
  ('image_default_link_type', 'none',                        'yes'),
  ('image_default_size',      '',                            'yes'),
  ('image_default_align',     'none',                        'yes'),
  ('close_comments_for_old_posts','0',                       'yes'),
  ('close_comments_days_old', '14',                          'yes'),
  ('thread_comments',         '1',                           'yes'),
  ('thread_comments_depth',   '5',                           'yes'),
  ('page_comments',           '0',                           'yes'),
  ('comments_per_page',       '50',                          'yes'),
  ('default_comments_page',   'newest',                      'yes'),
  ('comment_order',           'asc',                         'yes'),
  ('timezone_string',         'Asia/Seoul',                  'yes'),
  ('gmt_offset',              '9',                           'yes'),
  ('active_widgets',          'a:0:{}',                      'yes'),
  ('widget_search',           'a:2:{i:2;a:1:{s:5:"title";s:0:"";}s:12:"_multiwidget";i:1;}','yes'),
  ('widget_recent-posts',     'a:2:{i:2;a:2:{s:5:"title";s:0:"";s:6:"number";i:5;}s:12:"_multiwidget";i:1;}','yes'),
  ('widget_archives',         'a:2:{i:2;a:3:{s:5:"title";s:0:"";s:4:"type";s:8:"dropdown";s:5:"limit";i:0;}s:12:"_multiwidget";i:1;}','yes'),
  ('widget_categories',       'a:2:{i:2;a:4:{s:5:"title";s:0:"";s:8:"dropdown";i:0;s:9:"hierarchy";i:0;s:5:"count";i:0;}s:12:"_multiwidget";i:1;}','yes'),
  ('sidebars_widgets',        'a:4:{s:19:"wp_inactive_widgets";a:0:{}s:9:"sidebar-1";a:2:{i:0;s:8:"search-2";i:1;s:14:"recent-posts-2";}s:9:"sidebar-2";a:3:{i:0;s:13:"archives-2";i:1;s:14:"categories-2";} s:13:"array_version";i:3;}','yes'),
  ('page_uris',               '',                            'no'),
  ('taxonomies',              '',                            'no'),
  ('can_compress_scripts',    '1',                           'no'),
  ('wp_user_roles',           '',                            'no'),
  ('initial_db_version',      '57155',                       'yes'),
  ('wp_user_roles',           'a:5:{s:13:"administrator";a:2:{s:4:"name";s:13:"Administrator";s:12:"capabilities";a:1:{s:13:"administrator";b:1;}}s:6:"editor";a:2:{s:4:"name";s:6:"Editor";s:12:"capabilities";a:1:{s:6:"editor";b:1;}}s:6:"author";a:2:{s:4:"name";s:6:"Author";s:12:"capabilities";a:1:{s:6:"author";b:1;}}s:11:"contributor";a:2:{s:4:"name";s:11:"Contributor";s:12:"capabilities";a:1:{s:11:"contributor";b:1;}}s:10:"subscriber";a:2:{s:4:"name";s:10:"Subscriber";s:12:"capabilities";a:1:{s:4:"read";b:1;}}}','yes'),
  ('fresh_site',              '1',                           'yes'),
  ('user_count',              '0',                           'yes'),
  ('finished_splitting_shared_terms','1',                    'yes'),
  ('db_upgraded',             '',                            'yes'),
  ('medium_large_size_w',     '768',                         'yes'),
  ('medium_large_size_h',     '0',                           'yes'),
  ('WPLANG',                  'ko_KR',                       'yes'),
  ('wp_attachment_pages_enabled','0',                        'yes'),
  ('disallowed_keys',         '',                            'no'),
  ('comment_previously_approved','1',                        'yes'),
  ('auto_update_core_major',  'unset',                       'yes'),
  ('auto_update_core_minor',  'enabled',                     'yes'),
  ('auto_update_core_dev',    'enabled',                     'yes'),
  ('permalink_structure',     '/%postname%/',                'yes'),
  ('recently_activated',      'a:0:{}',                      'yes'),
  ('recovery_mode_email_last_sent','0',                      'yes'),
  ('wp_force_deactivated_plugins','a:0:{}',                  'yes'),
  ('cp_installed',            '1',                           'yes'),
  ('cp_version',              '20.0',                        'yes'),
  ('cp_storage',              'supabase',                    'yes');

-- 기본 카테고리
INSERT OR IGNORE INTO wp_terms (term_id, name, slug, term_group) VALUES (1, '미분류', 'uncategorized', 0);
INSERT OR IGNORE INTO wp_term_taxonomy (term_taxonomy_id, term_id, taxonomy, description, parent, count) VALUES (1, 1, 'category', '', 0, 1);

-- 기본 Hello World 포스트
INSERT OR IGNORE INTO wp_posts (
  ID, post_author, post_date, post_date_gmt, post_content, post_title, post_excerpt,
  post_status, comment_status, ping_status, post_name, post_modified, post_modified_gmt,
  post_type, comment_count, guid
) VALUES (
  1, 1, datetime('now'), datetime('now'),
  '<p>WordPress에 오신 것을 환영합니다. 이것은 첫 번째 게시글입니다. 이 글을 수정하거나 삭제하고 새로운 게시글을 작성해 보세요!</p>',
  'Hello world!', '',
  'publish', 'open', 'open',
  'hello-world',
  datetime('now'), datetime('now'),
  'post', 0, 'https://example.com/?p=1'
);
INSERT OR IGNORE INTO wp_term_relationships (object_id, term_taxonomy_id, term_order) VALUES (1, 1, 0);

-- 기본 샘플 페이지
INSERT OR IGNORE INTO wp_posts (
  ID, post_author, post_date, post_date_gmt, post_content, post_title, post_excerpt,
  post_status, comment_status, ping_status, post_name, post_modified, post_modified_gmt,
  post_type, menu_order, comment_count, guid
) VALUES (
  2, 1, datetime('now'), datetime('now'),
  '<p>이것은 샘플 페이지입니다. 게시글과 다르게 페이지는 고정된 위치에 있으며 대부분의 WordPress 테마에서 웹사이트 내비게이션 메뉴에 표시됩니다.</p>',
  '샘플 페이지', '',
  'publish', 'closed', 'closed',
  'sample-page',
  datetime('now'), datetime('now'),
  'page', 2, 0, 'https://example.com/?page_id=2'
);

-- 기본 관리자 댓글
INSERT OR IGNORE INTO wp_comments (
  comment_ID, comment_post_ID, comment_author, comment_author_email,
  comment_author_url, comment_author_IP, comment_date, comment_date_gmt,
  comment_content, comment_karma, comment_approved, comment_agent, comment_type,
  comment_parent, user_id
) VALUES (
  1, 1, 'WordPress 댓글 작성자', 'wapuu@wordpress.example',
  'https://wordpress.org/', '127.0.0.1', datetime('now'), datetime('now'),
  '<p>안녕하세요, 이것은 댓글입니다.<br>댓글을 수정하거나 삭제하려면 댓글 화면을 방문해 보세요.<br>그리고 지금 작성을 시작해 보세요!</p>',
  0, '1', '', 'comment', 0, 0
);

UPDATE wp_posts SET comment_count = 1 WHERE ID = 1;

-- ══════════════════════════════════════════════════════════════════
-- 설치 잠금 (한 번 설치 후 재설치 차단)
-- ══════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS cp_install_lock (
  id         INTEGER PRIMARY KEY DEFAULT 1,
  installed_at TEXT NOT NULL DEFAULT (datetime('now')),
  version    TEXT NOT NULL DEFAULT '20.0',
  CONSTRAINT one_row CHECK (id = 1)
);
INSERT OR IGNORE INTO cp_install_lock (id, installed_at, version) VALUES (1, datetime('now'), '20.0');
