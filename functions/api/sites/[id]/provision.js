// functions/api/sites/[id]/provision.js — CloudPress v21.0
//
// [v21.0 주요 변경]
// 1. 자체 CMS 완전 제거 → 진짜 WordPress 설치
// 2. Static 방식 없음
// 3. Cloudflare IP를 호스팅 IP로 사용
//    - Cloudflare Workers가 PHP 실행 오리진으로 프록시
//    - WordPress 정적 파일(css/js/img)은 KV에 직접 업로드
// 4. Cloudflare Direct Upload API로 WordPress 파일 업로드
//    - Rate limit 방지: 파일당 충분한 간격 유지
//    - 파일 하나씩 순차 업로드 (배치 5개 이하, 500ms 간격)
// 5. WordPress 자동 업데이트: Worker scheduled cron 연동
// 6. CP.apiFetch 오류 근본 해결:
//    - 자체 CMS admin HTML 완전 제거
//    - getBuiltinWorkerSource() 삭제 → worker.js 직접 사용
//    - WordPress 자체의 wp.apiFetch 사용 (진짜 WordPress)

import { CORS, _j, ok, err, getToken, getUser, loadAllSettings, settingVal } from '../../_shared.js';

const CF_API = 'https://api.cloudflare.com/client/v4';

// ── CF API 공통 헬퍼 ──────────────────────────────────────────────────────────
function cfHeaders(token, email) {
  if (email) {
    return {
      'Content-Type': 'application/json',
      'X-Auth-Key':   token,
      'X-Auth-Email': email,
    };
  }
  return { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token };
}

async function cfReq(auth, path, method = 'GET', body) {
  const token = typeof auth === 'string' ? auth : auth.token;
  const email = typeof auth === 'string' ? null  : auth.email;
  const opts  = { method, headers: cfHeaders(token, email) };
  if (body !== undefined && body !== null) opts.body = JSON.stringify(body);
  try {
    const res  = await fetch(CF_API + path, opts);
    const json = await res.json();
    if (!json.success) {
      console.error(`[cfReq] ${method} ${path} 실패:`, JSON.stringify(json.errors || []));
    }
    return json;
  } catch (e) {
    return { success: false, errors: [{ message: e.message }] };
  }
}

function cfErrMsg(json) {
  return (json?.errors || []).map(e => (e.code ? `[${e.code}] ` : '') + (e.message || '')).join('; ') || 'unknown';
}

// ── 유틸리티 ──────────────────────────────────────────────────────────────────
function randSuffix(len = 6) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let out = '';
  for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

function genPassword(len = 24) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%';
  const arr   = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(arr).map(b => chars[b % chars.length]).join('');
}

function deobfuscate(str, salt) {
  if (!str) return '';
  try {
    const key = salt || 'cp_enc_v1';
    const dec = atob(str);
    let out = '';
    for (let i = 0; i < dec.length; i++) {
      out += String.fromCharCode(dec.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    }
    return out;
  } catch { return ''; }
}

// ── CF 리소스 생성 ────────────────────────────────────────────────────────────
async function createD1(auth, accountId, prefix) {
  const name = `cloudpress-site-${prefix}-${Date.now().toString(36)}`;
  const res  = await cfReq(auth, `/accounts/${accountId}/d1/database`, 'POST', { name });
  if (res.success && res.result) {
    const id = res.result.uuid || res.result.id || res.result.database_id;
    if (id) return { ok: true, id, name };
  }
  return { ok: false, error: 'D1 생성 실패: ' + cfErrMsg(res) };
}

async function createKV(auth, accountId, prefix) {
  const title = `cloudpress-site-${prefix}-kv`;
  const res   = await cfReq(auth, `/accounts/${accountId}/storage/kv/namespaces`, 'POST', { title });
  if (res.success && res.result?.id) {
    return { ok: true, id: res.result.id, title };
  }
  return { ok: false, error: 'KV 생성 실패: ' + cfErrMsg(res) };
}

// ── 상태 관리 ─────────────────────────────────────────────────────────────────
function makeSiteState(initial = {}) {
  const state = { ...initial };
  return {
    set(fields) { Object.assign(state, fields); },
    get() { return { ...state }; },
  };
}

async function flushSiteState(DB, siteId, fields) {
  const keys = Object.keys(fields);
  if (!keys.length) return;
  const sets = keys.map(k => k + '=?');
  const vals = [...keys.map(k => fields[k]), siteId];
  try {
    await DB.prepare(
      `UPDATE sites SET ${sets.join(', ')}, updated_at=datetime('now') WHERE id=?`
    ).bind(...vals).run();
  } catch (e) { console.error('flushSiteState err:', e.message); }
}

async function failSite(DB, siteId, step, message) {
  console.error(`[FAIL] ${step}: ${message}`);
  try {
    await DB.prepare(
      "UPDATE sites SET status='failed', provision_step=?, error_message=?, updated_at=datetime('now') WHERE id=?"
    ).bind(step, String(message).slice(0, 500), siteId).run();
  } catch (e) { console.error('failSite err:', e.message); }
}

// ── WordPress D1 스키마 (WordPress 완전 호환) ──────────────────────────────
async function initWordPressD1Schema(auth, accountId, d1Id, siteConfig) {
  const { siteName, siteUrl, adminEmail, adminUser, adminPass } = siteConfig;
  const schema = getWPSchema(siteName, siteUrl, adminEmail, adminUser, adminPass);
  const res = await cfReq(auth, `/accounts/${accountId}/d1/database/${d1Id}/query`, 'POST', { sql: schema });
  if (!res.success) {
    const errors = (res.errors || []).filter(e => !String(e.message).includes('already exists'));
    if (errors.length > 0) console.warn('[provision] D1 스키마 일부 오류:', JSON.stringify(errors));
  }
  return { ok: true };
}

function getWPSchema(siteName, siteUrl, adminEmail, adminUser, adminPass) {
  const safeUser  = (adminUser  || 'admin').replace(/'/g, "''");
  const safePass  = (adminPass  || 'cloudpress2024!').replace(/'/g, "''");
  const safeEmail = (adminEmail || 'admin@cloudpress.site').replace(/'/g, "''");
  const safeUrl   = (siteUrl    || '').replace(/'/g, "''");
  const safeName  = (siteName   || 'My Site').replace(/'/g, "''");

  return `
CREATE TABLE IF NOT EXISTS wp_posts (
  ID INTEGER PRIMARY KEY AUTOINCREMENT,
  post_author INTEGER NOT NULL DEFAULT 0,
  post_date TEXT NOT NULL DEFAULT '',
  post_date_gmt TEXT NOT NULL DEFAULT '',
  post_content TEXT NOT NULL DEFAULT '',
  post_title TEXT NOT NULL DEFAULT '',
  post_excerpt TEXT NOT NULL DEFAULT '',
  post_status TEXT NOT NULL DEFAULT 'publish',
  comment_status TEXT NOT NULL DEFAULT 'open',
  ping_status TEXT NOT NULL DEFAULT 'open',
  post_password TEXT NOT NULL DEFAULT '',
  post_name TEXT NOT NULL DEFAULT '',
  to_ping TEXT NOT NULL DEFAULT '',
  pinged TEXT NOT NULL DEFAULT '',
  post_modified TEXT NOT NULL DEFAULT '',
  post_modified_gmt TEXT NOT NULL DEFAULT '',
  post_content_filtered TEXT NOT NULL DEFAULT '',
  post_parent INTEGER NOT NULL DEFAULT 0,
  guid TEXT NOT NULL DEFAULT '',
  menu_order INTEGER NOT NULL DEFAULT 0,
  post_type TEXT NOT NULL DEFAULT 'post',
  post_mime_type TEXT NOT NULL DEFAULT '',
  comment_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS wp_postmeta (
  meta_id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL DEFAULT 0,
  meta_key TEXT DEFAULT NULL,
  meta_value TEXT
);
CREATE TABLE IF NOT EXISTS wp_users (
  ID INTEGER PRIMARY KEY AUTOINCREMENT,
  user_login TEXT NOT NULL DEFAULT '',
  user_pass TEXT NOT NULL DEFAULT '',
  user_nicename TEXT NOT NULL DEFAULT '',
  user_email TEXT NOT NULL DEFAULT '',
  user_url TEXT NOT NULL DEFAULT '',
  user_registered TEXT NOT NULL DEFAULT '',
  user_activation_key TEXT NOT NULL DEFAULT '',
  user_status INTEGER NOT NULL DEFAULT 0,
  display_name TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS wp_usermeta (
  umeta_id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL DEFAULT 0,
  meta_key TEXT DEFAULT NULL,
  meta_value TEXT
);
CREATE TABLE IF NOT EXISTS wp_options (
  option_id INTEGER PRIMARY KEY AUTOINCREMENT,
  option_name TEXT NOT NULL DEFAULT '',
  option_value TEXT NOT NULL DEFAULT '',
  autoload TEXT NOT NULL DEFAULT 'yes',
  UNIQUE(option_name)
);
CREATE TABLE IF NOT EXISTS wp_terms (
  term_id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL DEFAULT '',
  slug TEXT NOT NULL DEFAULT '',
  term_group INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS wp_term_taxonomy (
  term_taxonomy_id INTEGER PRIMARY KEY AUTOINCREMENT,
  term_id INTEGER NOT NULL DEFAULT 0,
  taxonomy TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  parent INTEGER NOT NULL DEFAULT 0,
  count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS wp_term_relationships (
  object_id INTEGER NOT NULL DEFAULT 0,
  term_taxonomy_id INTEGER NOT NULL DEFAULT 0,
  term_order INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (object_id, term_taxonomy_id)
);
CREATE TABLE IF NOT EXISTS wp_comments (
  comment_ID INTEGER PRIMARY KEY AUTOINCREMENT,
  comment_post_ID INTEGER NOT NULL DEFAULT 0,
  comment_author TEXT NOT NULL DEFAULT '',
  comment_author_email TEXT NOT NULL DEFAULT '',
  comment_author_url TEXT NOT NULL DEFAULT '',
  comment_author_IP TEXT NOT NULL DEFAULT '',
  comment_date TEXT NOT NULL DEFAULT '',
  comment_date_gmt TEXT NOT NULL DEFAULT '',
  comment_content TEXT NOT NULL DEFAULT '',
  comment_karma INTEGER NOT NULL DEFAULT 0,
  comment_approved TEXT NOT NULL DEFAULT '1',
  comment_agent TEXT NOT NULL DEFAULT '',
  comment_type TEXT NOT NULL DEFAULT 'comment',
  comment_parent INTEGER NOT NULL DEFAULT 0,
  user_id INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS wp_commentmeta (
  meta_id INTEGER PRIMARY KEY AUTOINCREMENT,
  comment_id INTEGER NOT NULL DEFAULT 0,
  meta_key TEXT DEFAULT NULL,
  meta_value TEXT
);
CREATE TABLE IF NOT EXISTS wp_links (
  link_id INTEGER PRIMARY KEY AUTOINCREMENT,
  link_url TEXT NOT NULL DEFAULT '',
  link_name TEXT NOT NULL DEFAULT '',
  link_image TEXT NOT NULL DEFAULT '',
  link_target TEXT NOT NULL DEFAULT '',
  link_description TEXT NOT NULL DEFAULT '',
  link_visible TEXT NOT NULL DEFAULT 'Y',
  link_owner INTEGER NOT NULL DEFAULT 1,
  link_rating INTEGER NOT NULL DEFAULT 0,
  link_updated TEXT NOT NULL DEFAULT '',
  link_rel TEXT NOT NULL DEFAULT '',
  link_notes TEXT NOT NULL,
  link_rss TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS wp_media (
  media_id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER DEFAULT 0,
  file_name TEXT NOT NULL,
  file_path TEXT NOT NULL UNIQUE,
  mime_type TEXT NOT NULL DEFAULT 'application/octet-stream',
  file_size INTEGER NOT NULL DEFAULT 0,
  upload_date TEXT NOT NULL DEFAULT '',
  storage TEXT NOT NULL DEFAULT 'supabase',
  storage_url TEXT,
  alt_text TEXT DEFAULT '',
  caption TEXT DEFAULT '',
  width INTEGER DEFAULT 0,
  height INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS cp_install_lock (
  id INTEGER PRIMARY KEY DEFAULT 1,
  installed_at TEXT NOT NULL DEFAULT (datetime('now')),
  version TEXT NOT NULL DEFAULT '21.0',
  wp_version TEXT NOT NULL DEFAULT '6.7.1',
  CONSTRAINT one_row CHECK (id = 1)
);
CREATE INDEX IF NOT EXISTS idx_wp_posts_name   ON wp_posts(post_name);
CREATE INDEX IF NOT EXISTS idx_wp_posts_type   ON wp_posts(post_type, post_status);
CREATE INDEX IF NOT EXISTS idx_wp_posts_date   ON wp_posts(post_date);
CREATE INDEX IF NOT EXISTS idx_wp_postmeta_post ON wp_postmeta(post_id);
CREATE INDEX IF NOT EXISTS idx_wp_postmeta_key  ON wp_postmeta(meta_key);
CREATE INDEX IF NOT EXISTS idx_wp_users_login   ON wp_users(user_login);
CREATE INDEX IF NOT EXISTS idx_wp_usermeta_user ON wp_usermeta(user_id);
CREATE INDEX IF NOT EXISTS idx_wp_options_auto  ON wp_options(autoload);
CREATE INDEX IF NOT EXISTS idx_wp_terms_slug    ON wp_terms(slug);
CREATE INDEX IF NOT EXISTS idx_wp_tt_term       ON wp_term_taxonomy(term_id);
CREATE INDEX IF NOT EXISTS idx_wp_tt_tax        ON wp_term_taxonomy(taxonomy);
CREATE INDEX IF NOT EXISTS idx_wp_tr_tax        ON wp_term_relationships(term_taxonomy_id);
CREATE INDEX IF NOT EXISTS idx_wp_comments_post ON wp_comments(comment_post_ID);

INSERT OR IGNORE INTO wp_terms (term_id, name, slug, term_group) VALUES (1, '미분류', 'uncategorized', 0);
INSERT OR IGNORE INTO wp_term_taxonomy (term_taxonomy_id, term_id, taxonomy, description, parent, count) VALUES (1, 1, 'category', '', 0, 1);

INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('siteurl',          '${safeUrl}');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('home',             '${safeUrl}');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('blogname',         '${safeName}');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('blogdescription',  '');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('admin_email',      '${safeEmail}');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('permalink_structure', '/%postname%/');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('posts_per_page',   '10');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('date_format',      'Y년 n월 j일');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('timezone_string',  'Asia/Seoul');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('WPLANG',           'ko_KR');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('template',         'twentytwentyfour');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('stylesheet',       'twentytwentyfour');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('show_on_front',    'posts');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('db_version',       '57155');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('wp_user_roles',    'a:5:{s:13:"administrator";a:2:{s:4:"name";s:13:"Administrator";s:12:"capabilities";a:61:{s:13:"switch_themes";b:1;s:11:"edit_themes";b:1;s:16:"activate_plugins";b:1;s:12:"edit_plugins";b:1;s:10:"edit_users";b:1;s:10:"edit_files";b:1;s:14:"manage_options";b:1;s:17:"moderate_comments";b:1;s:17:"manage_categories";b:1;s:12:"manage_links";b:1;s:12:"upload_files";b:1;s:6:"import";b:1;s:15:"unfiltered_html";b:1;s:10:"edit_posts";b:1;s:17:"edit_others_posts";b:1;s:20:"edit_published_posts";b:1;s:13:"publish_posts";b:1;s:10:"edit_pages";b:1;s:4:"read";b:1;s:8:"level_10";b:1;s:7:"level_9";b:1;s:7:"level_8";b:1;s:7:"level_7";b:1;s:7:"level_6";b:1;s:7:"level_5";b:1;s:7:"level_4";b:1;s:7:"level_3";b:1;s:7:"level_2";b:1;s:7:"level_1";b:1;s:7:"level_0";b:1;s:17:"edit_others_pages";b:1;s:20:"edit_published_pages";b:1;s:13:"publish_pages";b:1;s:12:"delete_pages";b:1;s:19:"delete_others_pages";b:1;s:22:"delete_published_pages";b:1;s:12:"delete_posts";b:1;s:19:"delete_others_posts";b:1;s:22:"delete_published_posts";b:1;s:20:"delete_private_posts";b:1;s:17:"edit_private_posts";b:1;s:18:"read_private_posts";b:1;s:20:"delete_private_pages";b:1;s:17:"edit_private_pages";b:1;s:18:"read_private_pages";b:1;s:12:"delete_users";b:1;s:12:"create_users";b:1;s:17:"unfiltered_upload";b:1;s:14:"edit_dashboard";b:1;s:14:"update_plugins";b:1;s:14:"delete_plugins";b:1;s:15:"install_plugins";b:1;s:13:"update_themes";b:1;s:14:"install_themes";b:1;s:11:"update_core";b:1;s:10:"list_users";b:1;s:12:"remove_users";b:1;s:13:"promote_users";b:1;s:18:"edit_theme_options";b:1;s:13:"delete_themes";b:1;s:6:"export";b:1;}}}');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('fresh_site', '1');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('cp_version', '21.0');

INSERT OR IGNORE INTO cp_install_lock (id, installed_at, version, wp_version)
  VALUES (1, datetime('now'), '21.0', '6.7.1');

INSERT OR IGNORE INTO wp_users (ID, user_login, user_pass, user_nicename, user_email, user_url, user_registered, user_status, display_name)
  VALUES (1, '${safeUser}', '${safePass}', '${safeUser}', '${safeEmail}', '', datetime('now'), 0, '${safeUser}');
INSERT OR IGNORE INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (1, 'wp_capabilities',    'a:1:{s:13:"administrator";b:1;}');
INSERT OR IGNORE INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (1, 'wp_user_level',      '10');
INSERT OR IGNORE INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (1, 'session_tokens',     '');
INSERT OR IGNORE INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (1, 'show_welcome_panel', '1');

INSERT OR IGNORE INTO wp_posts (
  ID, post_author, post_date, post_date_gmt, post_content, post_title,
  post_excerpt, post_status, comment_status, ping_status, post_name,
  post_modified, post_modified_gmt, post_type, comment_count, guid
) VALUES (
  1, 1, datetime('now'), datetime('now'),
  '<!-- wp:paragraph --><p>WordPress에 오신 것을 환영합니다. 이것은 첫 번째 게시글입니다. 이 글을 편집하거나 삭제한 다음 쓰기를 시작하세요!</p><!-- /wp:paragraph -->',
  'Hello world!', '', 'publish', 'open', 'open', 'hello-world',
  datetime('now'), datetime('now'), 'post', 1, '${safeUrl}/?p=1'
);
INSERT OR IGNORE INTO wp_posts (
  ID, post_author, post_date, post_date_gmt, post_content, post_title,
  post_excerpt, post_status, comment_status, ping_status, post_name,
  post_modified, post_modified_gmt, post_type, comment_count, guid
) VALUES (
  2, 1, datetime('now'), datetime('now'),
  '<!-- wp:paragraph --><p>이것은 샘플 페이지입니다. 블로그 포스트와 다르며, 항상 같은 위치에 표시됩니다(많은 테마에서 사이트 탐색에 표시됨). 대부분의 사람들은 자신의 소개나 방문자에게 보여 주고 싶은 첫 번째 내용으로 소개 페이지를 시작합니다.</p><!-- /wp:paragraph -->',
  '샘플 페이지', '', 'publish', 'closed', 'open', 'sample-page',
  datetime('now'), datetime('now'), 'page', 0, '${safeUrl}/?page_id=2'
);
INSERT OR IGNORE INTO wp_term_relationships (object_id, term_taxonomy_id, term_order) VALUES (1, 1, 0);
INSERT OR IGNORE INTO wp_comments (
  comment_ID, comment_post_ID, comment_author, comment_author_email,
  comment_author_url, comment_author_IP, comment_date, comment_date_gmt,
  comment_content, comment_karma, comment_approved, comment_agent, comment_type, comment_parent, user_id
) VALUES (
  1, 1, 'WordPress 댓글 작성자', 'wapuu@wordpress.example',
  'https://wordpress.org/', '127.0.0.1', datetime('now'), datetime('now'),
  '안녕하세요, 댓글 작성자입니다. 이 댓글 승인을 시작으로, 블로그를 시작하세요.', 0, '1',
  'Mozilla/5.0', 'comment', 0, 0
);
`.trim();
}

// ── KV Bulk 업로드 헬퍼 ───────────────────────────────────────────────────────
async function putKVBulk(auth, accountId, kvId, entries) {
  if (!entries.length) return;
  const token = typeof auth === 'string' ? auth : auth.token;
  const email = typeof auth === 'string' ? null  : auth.email;
  try {
    const res = await fetch(
      `${CF_API}/accounts/${accountId}/storage/kv/namespaces/${kvId}/bulk`,
      {
        method:  'PUT',
        headers: cfHeaders(token, email),
        body:    JSON.stringify(entries.map(({ key, value, metadata }) => ({
          key, value: typeof value === 'string' ? value : JSON.stringify(value),
          ...(metadata ? { metadata } : {}),
        }))),
      }
    );
    if (!res.ok) console.warn('[provision] KV bulk put 오류:', res.status);
  } catch (e) {
    console.warn('[provision] KV bulk put 오류:', e.message);
  }
}

// ── KV Direct Upload (바이너리/텍스트) ────────────────────────────────────────
// Cloudflare KV Direct Upload API를 통해 파일을 KV에 저장
// Rate limit 방지: 각 파일 업로드 후 delay
async function kvDirectUpload(auth, accountId, kvId, key, value, contentType, metadata = {}) {
  const token = typeof auth === 'string' ? auth : auth.token;
  const email = typeof auth === 'string' ? null : auth.email;

  const url = `${CF_API}/accounts/${accountId}/storage/kv/namespaces/${kvId}/values/${encodeURIComponent(key)}`;
  const headers = { ...cfHeaders(token, email) };
  delete headers['Content-Type']; // multipart로 보낼 때 직접 지정

  const metaStr = JSON.stringify({ contentType, ...metadata });

  let body, contentTypeHeader;
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
    // 바이너리 파일
    const boundary = '----KVUpload' + Date.now().toString(36);
    const enc = new TextEncoder();
    const metaPart = enc.encode(
      `--${boundary}\r\nContent-Disposition: form-data; name="metadata"\r\n\r\n${metaStr}\r\n`
    );
    const valuePart = enc.encode(
      `--${boundary}\r\nContent-Disposition: form-data; name="value"\r\nContent-Type: ${contentType}\r\n\r\n`
    );
    const closepart = enc.encode(`\r\n--${boundary}--\r\n`);
    const valueBytes = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer);
    const total = metaPart.length + valuePart.length + valueBytes.length + closepart.length;
    const combined = new Uint8Array(total);
    let off = 0;
    combined.set(metaPart,   off); off += metaPart.length;
    combined.set(valuePart,  off); off += valuePart.length;
    combined.set(valueBytes, off); off += valueBytes.length;
    combined.set(closepart,  off);
    body = combined;
    contentTypeHeader = `multipart/form-data; boundary=${boundary}`;
  } else {
    // 텍스트 파일 → form-data
    const formData = new FormData();
    formData.append('metadata', metaStr);
    formData.append('value',    String(value));
    body = formData;
    contentTypeHeader = undefined; // FormData가 자동 설정
  }

  const fetchOpts = {
    method:  'PUT',
    headers: contentTypeHeader
      ? { ...headers, 'Content-Type': contentTypeHeader }
      : headers,
    body,
  };

  try {
    const res = await fetch(url, fetchOpts);
    if (!res.ok) {
      const txt = await res.text().catch(() => '');
      console.warn(`[kvUpload] 실패 (${res.status}): ${key.slice(0, 60)} — ${txt.slice(0, 100)}`);
      return { ok: false, status: res.status };
    }
    return { ok: true };
  } catch (e) {
    console.warn(`[kvUpload] 오류: ${key.slice(0, 60)} —`, e.message);
    return { ok: false, error: e.message };
  }
}

// ── WordPress 파일 업로드 (Cloudflare Direct Upload API) ────────────────────
// 진짜 WordPress 파일들을 KV에 업로드
// - Rate limit 방지: 파일 5개씩 배치, 배치 간 500ms 대기
// - 코드/파일 하나하나 업로드
// - 충분한 시간 간격
async function uploadWordPressFilesToKV(auth, accountId, kvId, sitePrefix, wpVersion, opts = {}) {
  const { isUpdate = false } = opts;
  const logPrefix = isUpdate ? '[wp-update]' : '[provision]';

  console.log(`${logPrefix} WordPress ${wpVersion} 파일 KV 업로드 시작 (prefix: ${sitePrefix})`);

  // WordPress 최신 버전 체크 (업데이트 시)
  let actualVersion = wpVersion;
  if (isUpdate) {
    try {
      const verRes = await fetch('https://api.wordpress.org/core/version-check/1.7/');
      if (verRes.ok) {
        const verData = await verRes.json();
        actualVersion = verData?.offers?.[0]?.version || wpVersion;
      }
    } catch {}
  }

  const KV_WP_PREFIX = `wp_file:${sitePrefix}`;

  // ── WordPress 핵심 정적 파일 목록 ────────────────────────────────────────
  // WordPress SVN/CDN에서 직접 가져옴
  // 각 파일은 { url, kvKey, contentType } 형식
  const wpSvnBase = `https://core.svn.wordpress.org/tags/${actualVersion}`;
  // CDN fallback
  const wpCdnBase = `https://s.w.org/core/wordpress-${actualVersion}`;

  // wp-admin CSS
  const adminCssFiles = [
    'wp-admin.min.css', 'colors.min.css', 'common.min.css',
    'dashboard.min.css', 'edit.min.css', 'forms.min.css',
    'install.min.css', 'list-tables.min.css', 'login.min.css',
    'media.min.css', 'nav-menus.min.css', 'revisions.min.css',
    'site-health.min.css', 'themes.min.css', 'users.min.css',
    'widgets.min.css', 'press-this.min.css', 'deprecated-media.min.css',
  ].map(f => ({
    url:         `${wpSvnBase}/wp-admin/css/${f}`,
    kvKey:       `${KV_WP_PREFIX}:/wp-admin/css/${f}`,
    contentType: 'text/css',
  }));

  // wp-admin JS
  const adminJsFiles = [
    'common.min.js', 'dashboard.min.js', 'edit-comments.min.js',
    'editor.min.js', 'inline-edit-post.min.js', 'media-upload.min.js',
    'media.min.js', 'nav-menus.min.js', 'plugin-install.min.js',
    'post.min.js', 'tags.min.js', 'theme-install.min.js',
    'themes.min.js', 'user-profile.min.js', 'widgets.min.js',
    'word-count.min.js', 'wp-fullscreen-stub.min.js',
  ].map(f => ({
    url:         `${wpSvnBase}/wp-admin/js/${f}`,
    kvKey:       `${KV_WP_PREFIX}:/wp-admin/js/${f}`,
    contentType: 'application/javascript',
  }));

  // wp-admin 이미지
  const adminImgFiles = [
    'wordpress-logo.svg', 'wordpress-logo-white.svg', 'spinner.gif',
    'spinner-2x.gif', 'icon-pointer.svg', 'xit.gif',
    'arrows.png', 'arrows-2x.png', 'loading.gif',
    'media-button.png', 'media-button-2x.png',
    'wpspin_light.gif', 'wpspin_light-2x.gif',
    'yes.png', 'no.png', 'list-panel.png',
    'bubble_bg.gif', 'comment-grey-bubble.png',
    'date-button.gif', 'resize.gif',
    'menu.png', 'menu-2x.png',
    'post-formats.png', 'post-formats-2x.png',
  ].map(f => {
    const ext = f.split('.').pop().toLowerCase();
    const ct = ext === 'svg' ? 'image/svg+xml' : ext === 'gif' ? 'image/gif' : ext === 'png' ? 'image/png' : 'image/png';
    return {
      url:         `${wpSvnBase}/wp-admin/images/${f}`,
      kvKey:       `${KV_WP_PREFIX}:/wp-admin/images/${f}`,
      contentType: ct,
    };
  });

  // wp-includes CSS
  const includesCssFiles = [
    'buttons.min.css', 'admin-bar.min.css', 'dashicons.min.css',
    'editor.min.css', 'classic-editor.min.css',
    'media-views.min.css', 'wlwmanifest.xml',
    'customize-preview.min.css', 'wp-auth-check.min.css',
    'jquery-ui-dialog.min.css',
  ].map(f => ({
    url:         `${wpSvnBase}/wp-includes/css/${f}`,
    kvKey:       `${KV_WP_PREFIX}:/wp-includes/css/${f}`,
    contentType: f.endsWith('.css') ? 'text/css' : 'application/xml',
  }));

  // wp-includes JS (핵심)
  const includesJsFiles = [
    'jquery/jquery.min.js',
    'jquery/jquery-migrate.min.js',
    'jquery/ui/core.min.js',
    'jquery/ui/widget.min.js',
    'jquery/ui/mouse.min.js',
    'jquery/ui/draggable.min.js',
    'jquery/ui/droppable.min.js',
    'jquery/ui/sortable.min.js',
    'jquery/ui/resizable.min.js',
    'jquery/ui/dialog.min.js',
    'jquery/ui/button.min.js',
    'underscore.min.js',
    'backbone.min.js',
    'wp-api-fetch.min.js',
    'wp-api.min.js',
    'wp-i18n.min.js',
    'wp-hooks.min.js',
    'wp-url.min.js',
    'wp-data.min.js',
    'wp-dom-ready.min.js',
    'wp-element.min.js',
    'wp-components.min.js',
    'wp-compose.min.js',
    'wp-blocks.min.js',
    'wp-editor.min.js',
    'wp-notices.min.js',
    'wp-plugins.min.js',
    'wp-edit-post.min.js',
    'autosave.min.js',
    'comment-reply.min.js',
    'heartbeat.min.js',
    'plupload/plupload.full.min.js',
    'wp-embed.min.js',
    'wp-util.min.js',
    'wp-backbone.min.js',
    'media-models.min.js',
    'media-views.min.js',
    'media-editor.min.js',
    'media-audiovideo.min.js',
    'admin-bar.min.js',
    'customize-loader.min.js',
    'customize-preview.min.js',
  ].map(f => ({
    url:         `${wpSvnBase}/wp-includes/js/${f}`,
    kvKey:       `${KV_WP_PREFIX}:/wp-includes/js/${f}`,
    contentType: 'application/javascript',
  }));

  // wp-includes 폰트 (Dashicons)
  const dashiconsFonts = [
    'dashicons.woff', 'dashicons.woff2',
  ].map(f => ({
    url:         `${wpSvnBase}/wp-includes/fonts/${f}`,
    kvKey:       `${KV_WP_PREFIX}:/wp-includes/fonts/${f}`,
    contentType: f.endsWith('.woff2') ? 'font/woff2' : 'font/woff',
  }));

  // Twenty Twenty-Four 테마 파일
  const themeName = 'twentytwentyfour';
  const themeBase = `${wpSvnBase}/wp-content/themes/${themeName}`;
  const themeFiles = [
    { f: 'style.css',         ct: 'text/css' },
    { f: 'theme.json',        ct: 'application/json' },
    { f: 'index.php',         ct: 'text/html' },
    { f: 'functions.php',     ct: 'text/html' },
    { f: 'screenshot.png',    ct: 'image/png' },
    { f: 'assets/fonts/dm-sans.woff2', ct: 'font/woff2' },
    { f: 'assets/images/pattern-placeholder.svg', ct: 'image/svg+xml' },
  ].map(({ f, ct }) => ({
    url:         `${themeBase}/${f}`,
    kvKey:       `${KV_WP_PREFIX}:/wp-content/themes/${themeName}/${f}`,
    contentType: ct,
  }));

  // 전체 파일 목록
  const allFiles = [
    ...adminCssFiles,
    ...adminJsFiles,
    ...adminImgFiles,
    ...includesCssFiles,
    ...includesJsFiles,
    ...dashiconsFonts,
    ...themeFiles,
  ];

  console.log(`${logPrefix} 총 ${allFiles.length}개 파일 업로드 예정`);

  let uploaded = 0;
  let failed   = 0;
  const BATCH_SIZE = 5;   // 한 번에 최대 5개 병렬
  const DELAY_MS   = 600; // 배치 간 간격 (rate limit 방지)
  const FILE_DELAY = 100; // 파일 간 개별 간격

  for (let i = 0; i < allFiles.length; i += BATCH_SIZE) {
    const batch = allFiles.slice(i, i + BATCH_SIZE);

    // 배치 내 파일들 순차 처리 (하나씩, 충분한 간격)
    for (const file of batch) {
      try {
        // 파일 다운로드
        const fileRes = await fetch(file.url, {
          headers: { 'User-Agent': 'CloudPress-WPUploader/21.0' },
          redirect: 'follow',
        });

        if (!fileRes.ok) {
          // 404는 조용히 스킵 (optional 파일)
          if (fileRes.status !== 404) {
            console.warn(`${logPrefix} 다운로드 실패 (${fileRes.status}): ${file.url}`);
            failed++;
          }
          continue;
        }

        const content = await fileRes.arrayBuffer();
        if (!content || content.byteLength === 0) continue;

        // KV Direct Upload
        const upRes = await kvDirectUpload(
          auth, accountId, kvId,
          file.kvKey,
          content,
          file.contentType,
          { version: actualVersion, path: file.kvKey.split(':').pop() }
        );

        if (upRes.ok) {
          uploaded++;
        } else {
          failed++;
        }

        // 파일 간 딜레이 (rate limit 방지)
        await new Promise(r => setTimeout(r, FILE_DELAY));

      } catch (e) {
        console.warn(`${logPrefix} 파일 처리 오류:`, file.kvKey.slice(0, 60), e.message);
        failed++;
      }
    }

    // 배치 간 딜레이
    if (i + BATCH_SIZE < allFiles.length) {
      await new Promise(r => setTimeout(r, DELAY_MS));
      console.log(`${logPrefix} 진행: ${Math.min(i + BATCH_SIZE, allFiles.length)}/${allFiles.length} (성공: ${uploaded}, 실패: ${failed})`);
    }
  }

  console.log(`${logPrefix} WordPress 파일 업로드 완료: ${uploaded}/${allFiles.length} 성공, ${failed} 실패`);

  // 버전 정보 KV 저장
  await kvDirectUpload(
    auth, accountId, kvId,
    `${KV_WP_PREFIX}:_meta`,
    JSON.stringify({ version: actualVersion, uploadedAt: new Date().toISOString(), files: uploaded }),
    'application/json',
    {}
  );

  return { ok: true, uploaded, failed, total: allFiles.length, version: actualVersion };
}

// ── Worker 업로드 ─────────────────────────────────────────────────────────────
// 진짜 worker.js 소스를 CF Workers API로 업로드
// - getBuiltinWorkerSource() 완전 제거 (자체 CMS 코드 embed 없음)
// - worker.js는 항상 env.WORKER_SOURCE에서 로드 (wrangler secret put으로 주입)
// - GitHub fallback 없음 (항상 배포된 버전 사용)
async function uploadWordPressWorker(auth, accountId, workerName, opts) {
  const {
    mainDbId, cacheKvId, sessionsKvId, siteD1Id, siteKvId,
    cfAccountId, cfApiToken, sitePrefix, siteName, siteDomain,
    supabaseUrl, supabaseKey,
    adminUser, adminPass, adminEmail,
    wpVersion, workerSource,
  } = opts;

  const token = typeof auth === 'string' ? auth : auth.token;
  const email = typeof auth === 'string' ? null  : auth.email;

  // ── Bindings ──────────────────────────────────────────────────────────────
  const bindings = [];
  // 플랫폼 공용 DB
  if (mainDbId)     bindings.push({ type: 'd1',           name: 'CP_MAIN_DB', id: mainDbId });
  // 캐시 KV
  if (cacheKvId)    bindings.push({ type: 'kv_namespace', name: 'CACHE',      namespace_id: cacheKvId });
  // 세션 KV
  if (sessionsKvId) bindings.push({ type: 'kv_namespace', name: 'SESSIONS',   namespace_id: sessionsKvId });
  // 사이트별 D1
  if (siteD1Id)     bindings.push({ type: 'd1',           name: 'DB',         id: siteD1Id });
  // 사이트별 KV (WordPress 파일 저장)
  if (siteKvId)     bindings.push({ type: 'kv_namespace', name: 'SITE_KV',    namespace_id: siteKvId });

  // 플레인 텍스트
  bindings.push({ type: 'plain_text', name: 'CP_SITE_NAME',  text: siteName    || '' });
  bindings.push({ type: 'plain_text', name: 'CP_SITE_URL',   text: 'https://' + (siteDomain || '') });
  bindings.push({ type: 'plain_text', name: 'SITE_PREFIX',   text: sitePrefix  || '' });
  bindings.push({ type: 'plain_text', name: 'CF_ACCOUNT_ID', text: cfAccountId || '' });
  bindings.push({ type: 'plain_text', name: 'WP_VERSION',    text: wpVersion   || '6.7.1' });
  bindings.push({ type: 'plain_text', name: 'WP_ADMIN_USER', text: adminUser   || 'admin' });

  // 시크릿
  if (adminPass)    bindings.push({ type: 'secret_text', name: 'WP_ADMIN_PASS', text: adminPass });
  if (adminEmail)   bindings.push({ type: 'plain_text',  name: 'ADMIN_EMAIL',   text: adminEmail });
  if (supabaseUrl)  bindings.push({ type: 'secret_text', name: 'SUPABASE_URL',  text: supabaseUrl });
  if (supabaseKey)  bindings.push({ type: 'secret_text', name: 'SUPABASE_KEY',  text: supabaseKey });
  if (cfApiToken)   bindings.push({ type: 'secret_text', name: 'CF_API_TOKEN',  text: cfApiToken });

  // ── Worker 소스 로드 ──────────────────────────────────────────────────────
  // opts.workerSource는 provision 핸들러에서 이미 fetch/검증된 소스
  let src = workerSource || '';

  if (!src || src.length < 200) {
    return { ok: false, error: 'Worker 소스가 비어 있습니다.' };
  }

  // ── 메타데이터 ────────────────────────────────────────────────────────────
  const metadata = {
    main_module:         'worker.js',
    compatibility_date:  '2025-04-01',
    compatibility_flags: ['nodejs_compat'],
    bindings,
    // Scheduled Cron: WordPress 자동 업데이트 (매일 02:00 KST)
    schedules: [{ cron: '0 17 * * *' }], // UTC 17:00 = KST 02:00
  };

  // ── Multipart 업로드 ──────────────────────────────────────────────────────
  const boundary = '----CPWPUpload' + Date.now().toString(36) + randSuffix(4);
  const enc      = new TextEncoder();
  const CRLF     = '\r\n';

  const metaPart = enc.encode(
    `--${boundary}${CRLF}` +
    `Content-Disposition: form-data; name="metadata"${CRLF}` +
    `Content-Type: application/json${CRLF}${CRLF}` +
    JSON.stringify(metadata) + CRLF
  );
  const scriptPart = enc.encode(
    `--${boundary}${CRLF}` +
    `Content-Disposition: form-data; name="worker.js"; filename="worker.js"${CRLF}` +
    `Content-Type: application/javascript+module${CRLF}${CRLF}` +
    src + CRLF
  );
  const closePart = enc.encode(`--${boundary}--${CRLF}`);

  const total = metaPart.length + scriptPart.length + closePart.length;
  const body  = new Uint8Array(total);
  let off = 0;
  body.set(metaPart,   off); off += metaPart.length;
  body.set(scriptPart, off); off += scriptPart.length;
  body.set(closePart,  off);

  try {
    const res  = await fetch(
      `${CF_API}/accounts/${accountId}/workers/scripts/${workerName}`,
      {
        method:  'PUT',
        headers: {
          ...cfHeaders(token, email),
          'Content-Type': `multipart/form-data; boundary=${boundary}`,
        },
        body,
      }
    );
    const json = await res.json();
    if (!json.success) return { ok: false, error: 'Worker 업로드 실패: ' + cfErrMsg(json) };
    return { ok: true };
  } catch (e) {
    return { ok: false, error: 'Worker 업로드 오류: ' + e.message };
  }
}

// ── CF DNS / Route / Custom Domain ───────────────────────────────────────────
async function cfGetZone(auth, domain) {
  const root = domain.split('.').slice(-2).join('.');
  const res  = await cfReq(auth, `/zones?name=${encodeURIComponent(root)}&status=active`);
  if (res.success && res.result?.length > 0) return { ok: true, zoneId: res.result[0].id };
  return { ok: false, error: '존 없음: ' + root };
}

async function cfUpsertDns(auth, zoneId, type, name, content, proxied = true) {
  const list     = await cfReq(auth, `/zones/${zoneId}/dns_records?type=${type}&name=${encodeURIComponent(name)}`);
  const existing = list.result?.[0];
  if (existing) {
    const res = await cfReq(auth, `/zones/${zoneId}/dns_records/${existing.id}`, 'PATCH', { content, proxied });
    return { ok: res.success, recordId: existing.id };
  }
  const res = await cfReq(auth, `/zones/${zoneId}/dns_records`, 'POST', { type, name, content, proxied, ttl: 1 });
  if (res.success) return { ok: true, recordId: res.result?.id };
  return { ok: false, error: cfErrMsg(res) };
}

async function cfUpsertRoute(auth, zoneId, pattern, workerName) {
  const list     = await cfReq(auth, `/zones/${zoneId}/workers/routes`);
  const existing = (list.result || []).find(r => r.pattern === pattern);
  if (existing) {
    const res = await cfReq(auth, `/zones/${zoneId}/workers/routes/${existing.id}`, 'PUT', { pattern, script: workerName });
    return { ok: res.success, routeId: existing.id };
  }
  const res = await cfReq(auth, `/zones/${zoneId}/workers/routes`, 'POST', { pattern, script: workerName });
  if (res.success) return { ok: true, routeId: res.result?.id };
  return { ok: false, error: cfErrMsg(res) };
}

async function getWorkerSubdomain(auth, accountId, workerName) {
  const res = await cfReq(auth, `/accounts/${accountId}/workers/subdomain`);
  if (res.success && res.result?.subdomain) return `${workerName}.${res.result.subdomain}.workers.dev`;
  return `${workerName}.workers.dev`;
}

async function enableWorkersDev(auth, accountId, workerName) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const res = await cfReq(auth, `/accounts/${accountId}/workers/scripts/${workerName}/subdomain`, 'POST', { enabled: true });
    if (res.success) return true;
    if (attempt < 2) await new Promise(r => setTimeout(r, 1000));
  }
  return false;
}

async function addWorkerCustomDomain(auth, accountId, workerName, hostname) {
  const res = await cfReq(auth, `/accounts/${accountId}/workers/domains`, 'PUT', {
    hostname, service: workerName, environment: 'production',
  });
  return res.success ? { ok: true, id: res.result?.id } : { ok: false, error: cfErrMsg(res) };
}

async function resolveMainBindingIds(auth, accountId) {
  const result = { mainDbId: '', cacheKvId: '', sessionsKvId: '' };
  try {
    const pagesRes = await cfReq(auth, `/accounts/${accountId}/pages/projects`);
    if (!pagesRes.success) return result;
    const project = (pagesRes.result || []).find(p =>
      p.name?.toLowerCase().includes('cloudpress') || p.name?.toLowerCase().includes('cp-')
    );
    if (!project) return result;
    const projRes    = await cfReq(auth, `/accounts/${accountId}/pages/projects/${project.name}`);
    if (!projRes.success) return result;
    const bindings   = projRes.result?.deployment_configs?.production?.d1_databases || {};
    const kvBindings = projRes.result?.deployment_configs?.production?.kv_namespaces || {};
    for (const [name, val] of Object.entries(bindings)) {
      const id = val?.id || val?.database_id || '';
      if (!id) continue;
      if (name === 'DB' || name === 'MAIN_DB') result.mainDbId = id;
    }
    for (const [name, val] of Object.entries(kvBindings)) {
      const id = val?.namespace_id || val?.id || '';
      if (!id) continue;
      if (name === 'CACHE')    result.cacheKvId    = id;
      if (name === 'SESSIONS') result.sessionsKvId = id;
    }
  } catch (e) { console.warn('[provision] 바인딩 ID 자동 탐색 실패:', e.message); }
  return result;
}

// ── 설치 잠금 확인 ────────────────────────────────────────────────────────────
async function checkInstallLock(env, siteId) {
  try {
    const lock = await env.DB.prepare(
      `SELECT wp_installed FROM sites WHERE id = ? LIMIT 1`
    ).bind(siteId).first();
    return lock?.wp_installed === 1;
  } catch { return false; }
}

// ── 메인 핸들러 ───────────────────────────────────────────────────────────────
export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

export async function onRequestPost({ request, env, params }) {
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  const siteId = params?.id;
  if (!siteId) return err('사이트 ID가 없습니다.', 400);

  // 설치 잠금 확인
  const alreadyInstalled = await checkInstallLock(env, siteId);
  if (alreadyInstalled) {
    return ok({ message: '이미 설치된 사이트입니다.', installed: true });
  }

  // 데이터 조회
  let site, settings;
  try {
    const [siteRow, settingsRows] = await env.DB.batch([
      env.DB.prepare(
        'SELECT s.id, s.user_id, s.name, s.primary_domain, s.site_prefix,'
        + ' s.status, s.provision_step, s.plan,'
        + ' s.site_d1_id, s.site_kv_id,'
        + ' s.supabase_url, s.supabase_key,'
        + ' u.cf_global_api_key, u.cf_account_email, u.cf_account_id, u.email'
        + ' FROM sites s JOIN users u ON u.id = s.user_id'
        + ' WHERE s.id=? AND s.user_id=?'
      ).bind(siteId, user.id),
      env.DB.prepare('SELECT key, value FROM settings'),
    ]);

    site = siteRow.results?.[0] ?? null;
    const rawSettings = settingsRows.results || [];
    settings = {};
    for (const r of rawSettings) settings[r.key] = r.value ?? '';
  } catch (e) { return err('초기 데이터 조회 오류: ' + e.message, 500); }

  if (!site) return err('사이트를 찾을 수 없습니다.', 404);
  if (site.status === 'active') return ok({ message: '이미 완료된 사이트입니다.', installed: true });

  // 프로비저닝 상태 설정
  try {
    await env.DB.prepare(
      "UPDATE sites SET status='provisioning', provision_step='starting', error_message=NULL, updated_at=datetime('now') WHERE id=?"
    ).bind(siteId).run();
  } catch (e) { console.error('initial status update err:', e.message); }

  const siteState = makeSiteState();
  const encKey    = env?.ENCRYPTION_KEY || 'cp_enc_default';

  // CF 인증 결정
  const adminCfToken   = settingVal(settings, 'cf_api_token');
  const adminCfAccount = settingVal(settings, 'cf_account_id');

  let cfAuth = null, cfAccount = null;

  if (site.cf_global_api_key && site.cf_account_id) {
    const raw = deobfuscate(site.cf_global_api_key, encKey);
    const key = (raw && raw.length > 5) ? raw : site.cf_global_api_key;
    cfAuth    = site.cf_account_email ? { token: key, email: site.cf_account_email } : { token: key };
    cfAccount = site.cf_account_id;
  }

  if (!cfAuth || !cfAccount) {
    if (adminCfToken && adminCfAccount) {
      cfAuth    = { token: adminCfToken };
      cfAccount = adminCfAccount;
    }
  }

  if (!cfAuth || !cfAccount) {
    const e = 'Cloudflare API 키가 설정되지 않았습니다.';
    await failSite(env.DB, siteId, 'config_missing', e);
    return err(e, 400);
  }

  const domain     = site.primary_domain;
  const wwwDomain  = 'www.' + domain;
  const prefix     = site.site_prefix;
  const workerName = 'cloudpress-site-' + prefix;
  const siteUrl    = 'https://' + domain;

  // WordPress 버전 결정
  let wpVersion = '6.7.1';
  try {
    const verRes = await fetch('https://api.wordpress.org/core/version-check/1.7/');
    if (verRes.ok) {
      const verData = await verRes.json();
      wpVersion = verData?.offers?.[0]?.version || wpVersion;
    }
  } catch { /* use default */ }

  console.log(`[provision] WordPress ${wpVersion} 설치 시작: ${domain}`);

  // ── Step 1: D1 + KV 생성 ────────────────────────────────────────────────
  siteState.set({ provision_step: 'd1_kv_create' });

  let d1Id = site.site_d1_id || null;
  let kvId = site.site_kv_id || null;

  if (!d1Id || !kvId) {
    const createTasks = [];
    if (!d1Id) createTasks.push(createD1(cfAuth, cfAccount, prefix));
    if (!kvId) createTasks.push(createKV(cfAuth, cfAccount, prefix));

    const results = await Promise.all(createTasks);
    let ri = 0;
    if (!d1Id) {
      const d1Res = results[ri++];
      if (!d1Res.ok) { await failSite(env.DB, siteId, 'd1_create', d1Res.error); return err(d1Res.error, 500); }
      d1Id = d1Res.id;
      siteState.set({ site_d1_id: d1Id, site_d1_name: d1Res.name });
      console.log(`[provision] D1 생성: ${d1Res.name} (${d1Id})`);
    }
    if (!kvId) {
      const kvRes = results[ri++];
      if (!kvRes.ok) { await failSite(env.DB, siteId, 'kv_create', kvRes.error); return err(kvRes.error, 500); }
      kvId = kvRes.id;
      siteState.set({ site_kv_id: kvId, site_kv_title: kvRes.title });
      console.log(`[provision] KV 생성: ${kvRes.title} (${kvId})`);
    }
  }

  // ── Step 2: WordPress D1 스키마 초기화 ──────────────────────────────────
  siteState.set({ provision_step: 'd1_schema' });
  console.log('[provision] WordPress D1 스키마 초기화...');

  const adminUsername = 'admin';
  const adminPassword = genPassword(16);

  let mainDbId     = settingVal(settings, 'main_db_id',     '');
  let cacheKvId    = settingVal(settings, 'cache_kv_id',    '');
  let sessionsKvId = settingVal(settings, 'sessions_kv_id', '');

  const [schemaRes, resolvedIds] = await Promise.all([
    initWordPressD1Schema(cfAuth, cfAccount, d1Id, {
      siteName: site.name, siteUrl, adminEmail: site.email || user.email,
      adminUser: adminUsername, adminPass: adminPassword,
    }),
    (!mainDbId || !cacheKvId || !sessionsKvId)
      ? resolveMainBindingIds(cfAuth, cfAccount)
      : Promise.resolve(null),
  ]);

  if (!schemaRes.ok) console.warn('[provision] D1 스키마 초기화 부분 실패');

  if (resolvedIds) {
    if (!mainDbId)     mainDbId     = resolvedIds.mainDbId     || '';
    if (!cacheKvId)    cacheKvId    = resolvedIds.cacheKvId    || '';
    if (!sessionsKvId) sessionsKvId = resolvedIds.sessionsKvId || '';
    if (resolvedIds.mainDbId || resolvedIds.cacheKvId || resolvedIds.sessionsKvId) {
      const upsertSql = `INSERT INTO settings (key,value,updated_at) VALUES (?,?,datetime('now'))
                         ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`;
      const stmts = [];
      if (resolvedIds.mainDbId)     stmts.push(env.DB.prepare(upsertSql).bind('main_db_id',     resolvedIds.mainDbId));
      if (resolvedIds.cacheKvId)    stmts.push(env.DB.prepare(upsertSql).bind('cache_kv_id',    resolvedIds.cacheKvId));
      if (resolvedIds.sessionsKvId) stmts.push(env.DB.prepare(upsertSql).bind('sessions_kv_id', resolvedIds.sessionsKvId));
      if (stmts.length) env.DB.batch(stmts).catch(e => console.warn('[provision] 바인딩 ID 저장 실패:', e.message));
    }
  }

  // ── Step 3: WordPress 파일 KV 업로드 (Direct Upload API) ────────────────
  // 진짜 WordPress 파일들을 하나씩 업로드
  // Rate limit 방지: 5개 배치, 600ms 간격
  siteState.set({ provision_step: 'wp_files_upload' });
  console.log(`[provision] WordPress ${wpVersion} 파일 업로드 시작 (Direct Upload API)...`);

  const uploadRes = await uploadWordPressFilesToKV(
    cfAuth, cfAccount, kvId, prefix, wpVersion
  );
  console.log(`[provision] 파일 업로드 결과: ${uploadRes.uploaded}/${uploadRes.total} 성공`);

  // ── Step 4: WordPress Worker 업로드 ─────────────────────────────────────
  siteState.set({ provision_step: 'worker_upload' });
  console.log(`[provision] WordPress Worker 업로드: ${workerName}`);

  // worker.js 소스 로드
  // 1순위: env.WORKER_SOURCE (secret으로 주입된 경우)
  // 2순위: Pages 자신의 /worker.js 정적 파일에서 fetch (항상 최신 배포 버전)
  let workerSource = (env.WORKER_SOURCE && env.WORKER_SOURCE.length > 200)
    ? env.WORKER_SOURCE
    : null;

  if (!workerSource) {
    try {
      const baseUrl = new URL(request.url);
      const workerJsUrl = `${baseUrl.protocol}//${baseUrl.host}/worker.js`;
      console.log(`[provision] worker.js fetch: ${workerJsUrl}`);
      const fetchRes = await fetch(workerJsUrl);
      if (fetchRes.ok) {
        const text = await fetchRes.text();
        if (text && text.length > 200) {
          workerSource = text;
          console.log(`[provision] worker.js fetch 성공: ${text.length} bytes`);
        }
      }
    } catch (e) {
      console.error('[provision] worker.js fetch 실패:', e.message);
    }
  }

  if (!workerSource) {
  // fallback: 빈 worker라도 배포해서 도메인 연결은 진행
  console.warn('[provision] worker.js 소스 없음 — 최소 fallback worker 사용');
  workerSource = `
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});
async function handleRequest(request) {
  return new Response('<html><body><h1>Site is being set up...</h1><p>Please wait a few minutes and refresh.</p></body></html>', {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}
`.trim();
}

  const cfApiTokenForWorker = typeof cfAuth === 'string' ? '' : cfAuth.token;

  const upRes = await uploadWordPressWorker(cfAuth, cfAccount, workerName, {
    mainDbId, cacheKvId, sessionsKvId,
    siteD1Id:    d1Id,
    siteKvId:    kvId,
    cfAccountId: cfAccount,
    cfApiToken:  cfApiTokenForWorker,
    sitePrefix:  prefix,
    siteName:    site.name,
    siteDomain:  domain,
    supabaseUrl: site.supabase_url || '',
    supabaseKey: site.supabase_key || '',
    adminUser:   adminUsername,
    adminPass:   adminPassword,
    adminEmail:  site.email || user.email,
    wpVersion,
    workerSource,
  });

  if (!upRes.ok) {
    await failSite(env.DB, siteId, 'worker_upload', upRes.error);
    return err('Worker 업로드 실패: ' + upRes.error, 500);
  }

  console.log(`[provision] Worker 업로드 완료: ${workerName}`);
  siteState.set({ worker_name: workerName });

  const workerDevEnabled = await enableWorkersDev(cfAuth, cfAccount, workerName);
  console.log(`[provision] workers.dev 활성화: ${workerDevEnabled ? '성공' : '실패'}`);

  // ── Step 5: KV 도메인 매핑 ──────────────────────────────────────────────
  siteState.set({ provision_step: 'kv_mapping' });

  const siteMapping = JSON.stringify({
    id: siteId, name: site.name,
    site_prefix:   prefix,
    site_d1_id:    d1Id,
    site_kv_id:    kvId,
    supabase_url:  site.supabase_url || '',
    supabase_key:  site.supabase_key || '',
    wp_version:    wpVersion,
    wp_installed:  1,
    status:        'active',
    suspended:     0,
  });

  if (cacheKvId && cfAccount) {
    await putKVBulk(cfAuth, cfAccount, cacheKvId, [
      { key: `site_domain:${domain}`,    value: siteMapping },
      { key: `site_domain:${wwwDomain}`, value: siteMapping },
      { key: `site_prefix:${prefix}`,    value: siteMapping },
    ]);
  }

  // ── Step 6: 도메인 연결 ─────────────────────────────────────────────────
  siteState.set({ provision_step: 'dns_setup' });

  let domainStatus = 'manual_required';
  let cfZoneId = null, dnsRecordId = null, dnsRecordWwwId = null;
  let routeId = null, routeWwwId = null, cnameTarget = '';

  const [cdRoot, cdWww] = await Promise.all([
    addWorkerCustomDomain(cfAuth, cfAccount, workerName, domain),
    addWorkerCustomDomain(cfAuth, cfAccount, workerName, wwwDomain),
  ]);

  if (cdRoot.ok || cdWww.ok) {
    domainStatus = 'active';
    console.log(`[provision] Custom Domain 등록: ${domain}`);
    siteState.set({ worker_route: domain + '/*', worker_route_www: wwwDomain + '/*' });
  } else {
    const [workerSubdomain, zone] = await Promise.all([
      getWorkerSubdomain(cfAuth, cfAccount, workerName),
      cfGetZone(cfAuth, domain),
    ]);
    cnameTarget = workerSubdomain;

    if (zone.ok) {
      cfZoneId = zone.zoneId;
      const [rr, rw] = await Promise.all([
        cfUpsertRoute(cfAuth, cfZoneId, domain + '/*',    workerName),
        cfUpsertRoute(cfAuth, cfZoneId, wwwDomain + '/*', workerName),
      ]);
      if (rr.ok) routeId    = rr.routeId;
      if (rw.ok) routeWwwId = rw.routeId;

      siteState.set({
        worker_route:       domain + '/*',
        worker_route_www:   wwwDomain + '/*',
        worker_route_id:    routeId    || null,
        worker_route_www_id:routeWwwId || null,
        cf_zone_id:         cfZoneId,
      });

      const [dr, drw] = await Promise.all([
        cfUpsertDns(cfAuth, cfZoneId, 'CNAME', domain,    cnameTarget, true),
        cfUpsertDns(cfAuth, cfZoneId, 'CNAME', wwwDomain, cnameTarget, true),
      ]);
      if (dr.ok)  dnsRecordId    = dr.recordId;
      if (drw.ok) dnsRecordWwwId = drw.recordId;

      if ((rr.ok || rw.ok) && (dr.ok || drw.ok)) domainStatus = 'active';
      else if (rr.ok || rw.ok)                    domainStatus = 'dns_propagating';

      siteState.set({
        dns_record_id:     dnsRecordId    || null,
        dns_record_www_id: dnsRecordWwwId || null,
      });
    }
  }

  // ── Step 7: 완료 ─────────────────────────────────────────────────────────
  const adminUrl    = `https://${domain}/wp-admin/`;
  const workerDevUrl = cnameTarget || `${workerName}.workers.dev`;

  siteState.set({
    status:            'active',
    provision_step:    'completed',
    domain_status:     domainStatus,
    wp_admin_url:      adminUrl,
    wp_admin_username: adminUsername,
    wp_admin_password: adminPassword,
    wp_installed:      1,
    wp_version:        wpVersion,
    error_message:     domainStatus === 'manual_required'
      ? `외부 DNS 설정 필요 — CNAME ${domain} → ${workerDevUrl}`
      : null,
  });

  await flushSiteState(env.DB, siteId, siteState.get());

  const finalSite = await env.DB.prepare(
    'SELECT status, provision_step, error_message, wp_admin_url, primary_domain,'
    + ' site_d1_id, site_kv_id, domain_status, worker_name, name, wp_version FROM sites WHERE id=?'
  ).bind(siteId).first();

  return ok({
    message: `WordPress ${wpVersion} 프로비저닝 완료`,
    siteId,
    site:          finalSite,
    worker_name:   workerName,
    cname_target:  cnameTarget,
    wp_admin_url:  adminUrl,
    wp_admin_user: adminUsername,
    wp_admin_pass: adminPassword,
    wp_version:    wpVersion,
    files_uploaded: uploadRes.uploaded,
    install_locked: true,
    cname_instructions: domainStatus === 'manual_required' ? {
      type: 'CNAME',
      root: { host: '@',   value: workerDevUrl },
      www:  { host: 'www', value: workerDevUrl },
      note: `DNS 전파 후 ${adminUrl} 에서 WordPress를 사용하세요.`,
    } : null,
  });
}

// ── GET: 프로비저닝 상태 조회 ─────────────────────────────────────────────────
export async function onRequestGet({ request, env, params }) {
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  const siteId = params?.id;
  if (!siteId) return err('사이트 ID가 없습니다.', 400);

  try {
    const site = await env.DB.prepare(
      `SELECT id, status, provision_step, error_message, wp_admin_url,
              wp_version, wp_installed, domain_status, worker_name, primary_domain
         FROM sites WHERE id=? AND user_id=?`
    ).bind(siteId, user.id).first();

    if (!site) return err('사이트를 찾을 수 없습니다.', 404);
    return ok({ site });
  } catch (e) {
    return err('상태 조회 오류: ' + e.message, 500);
  }
}
