// functions/api/sites/[id]/provision.js — CloudPress v23.0
//
// [v23.0 주요 변경]
// 1. Cloudflare API 키 사전 검증 (401/403 에러 즉시 차단)
// 2. D1 + KV 생성 → DB 스키마 → Worker 업로드 완전 직렬화 (race condition 제거)
// 3. PHP 버전 선택 지원 (7.4 / 8.0 / 8.1 / 8.2 / 8.3) — Worker env binding으로 전달
// 4. WordPress 자동 업데이트 옵션 (wp_auto_update: 'enabled'|'disabled'|'minor')
// 5. worker.js 소스 embed — Pages에서 직접 fetch (fallback: minimal worker)
// 6. DNS Unexpected token '<' 오류 수정: API 응답 Content-Type 사전 확인
// 7. 사이트 재프로비저닝 방지 (install lock)
// 8. 모든 단계 DB 상태 동기 플러시

import {
  CORS, ok, err, getUser, loadAllSettings, settingVal,
} from '../../_shared.js';

import {
  deobfuscate, createD1, createKV,
  cfGetZone, cfUpsertDns, cfUpsertRoute,
  getWorkerSubdomain, enableWorkersDev,
  addWorkerCustomDomain, uploadWordPressWorker,
  resolveMainBindingIds, cfReq, cfErrMsg,
} from '../../_shared_cloudflare.js';

// ── 유틸 ─────────────────────────────────────────────────────────────────────
function genPassword(len = 20) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
  const arr   = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(arr).map(b => chars[b % chars.length]).join('');
}

// ── DB 상태 관리 ──────────────────────────────────────────────────────────────
async function flushState(DB, siteId, fields) {
  const keys = Object.keys(fields).filter(k => fields[k] !== undefined);
  if (!keys.length) return;
  const sets = keys.map(k => `${k}=?`).join(', ');
  const vals = [...keys.map(k => fields[k]), siteId];
  try {
    await DB.prepare(
      `UPDATE sites SET ${sets}, updated_at=datetime('now') WHERE id=?`
    ).bind(...vals).run();
  } catch (e) {
    console.error('[provision] flushState 오류:', e.message);
  }
}

async function failSite(DB, siteId, step, message) {
  console.error(`[provision][FAIL][${step}]:`, message);
  try {
    await DB.prepare(
      `UPDATE sites SET status='failed', provision_step=?, error_message=?, updated_at=datetime('now') WHERE id=?`
    ).bind(String(step), String(message).slice(0, 500), siteId).run();
  } catch {}
}

// ── Cloudflare API 토큰 검증 ──────────────────────────────────────────────────
async function validateCfToken(auth) {
  try {
    const token = typeof auth === 'string' ? auth : auth.token;
    const email = typeof auth === 'object' ? auth.email : null;
    const headers = email
      ? { 'X-Auth-Key': token, 'X-Auth-Email': email }
      : { 'Authorization': 'Bearer ' + token };
    const res = await fetch('https://api.cloudflare.com/client/v4/user/tokens/verify', { headers });
    // Global API Key는 /user/tokens/verify가 없으므로 /user로 fallback
    if (!res.ok && email) {
      const res2 = await fetch('https://api.cloudflare.com/client/v4/user', { headers });
      const j2   = await res2.json();
      return j2.success ? { ok: true } : { ok: false, error: 'CF 인증 실패: ' + cfErrMsg(j2) };
    }
    const ct = res.headers.get('content-type') || '';
    if (!ct.includes('application/json')) {
      return { ok: false, error: 'Cloudflare API 응답 오류 (HTML 수신) — API 키를 확인하세요.' };
    }
    const j = await res.json();
    return j.success ? { ok: true } : { ok: false, error: 'CF 토큰 검증 실패: ' + cfErrMsg(j) };
  } catch (e) {
    return { ok: false, error: 'CF API 연결 오류: ' + e.message };
  }
}

// ── Account ID 검증 ───────────────────────────────────────────────────────────
async function validateCfAccount(auth, accountId) {
  try {
    const res = await cfReq(auth, `/accounts/${accountId}`);
    return res.success ? { ok: true } : { ok: false, error: 'CF Account ID가 올바르지 않습니다: ' + cfErrMsg(res) };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ── WordPress D1 스키마 초기화 ────────────────────────────────────────────────
async function initWordPressD1(auth, accountId, d1Id, cfg) {
  const { siteName, siteUrl, adminEmail, adminUser, adminPass } = cfg;
  const s  = v => String(v || '').replace(/'/g, "''");
  const schema = `
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
  link_notes TEXT NOT NULL DEFAULT '',
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
  storage TEXT NOT NULL DEFAULT 'kv',
  storage_url TEXT,
  alt_text TEXT DEFAULT '',
  caption TEXT DEFAULT '',
  width INTEGER DEFAULT 0,
  height INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS cp_site_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS cp_install_lock (
  id INTEGER PRIMARY KEY DEFAULT 1,
  installed_at TEXT NOT NULL DEFAULT (datetime('now')),
  version TEXT NOT NULL DEFAULT '23.0',
  wp_version TEXT NOT NULL DEFAULT '6.9.4',
  CONSTRAINT one_row CHECK (id = 1)
);
CREATE INDEX IF NOT EXISTS idx_wp_posts_name    ON wp_posts(post_name);
CREATE INDEX IF NOT EXISTS idx_wp_posts_type    ON wp_posts(post_type, post_status);
CREATE INDEX IF NOT EXISTS idx_wp_posts_date    ON wp_posts(post_date);
CREATE INDEX IF NOT EXISTS idx_wp_postmeta_post ON wp_postmeta(post_id);
CREATE INDEX IF NOT EXISTS idx_wp_postmeta_key  ON wp_postmeta(meta_key);
CREATE INDEX IF NOT EXISTS idx_wp_users_login   ON wp_users(user_login);
CREATE INDEX IF NOT EXISTS idx_wp_usermeta_user ON wp_usermeta(user_id);
CREATE INDEX IF NOT EXISTS idx_wp_options_name  ON wp_options(option_name);
CREATE INDEX IF NOT EXISTS idx_wp_options_auto  ON wp_options(autoload);
CREATE INDEX IF NOT EXISTS idx_wp_terms_slug    ON wp_terms(slug);
CREATE INDEX IF NOT EXISTS idx_wp_tt_term       ON wp_term_taxonomy(term_id);
CREATE INDEX IF NOT EXISTS idx_wp_comments_post ON wp_comments(comment_post_ID);

INSERT OR IGNORE INTO wp_terms VALUES (1,'미분류','uncategorized',0);
INSERT OR IGNORE INTO wp_term_taxonomy VALUES (1,1,'category','',0,1);

INSERT OR IGNORE INTO wp_options (option_name,option_value) VALUES ('siteurl','${s(siteUrl)}');
INSERT OR IGNORE INTO wp_options (option_name,option_value) VALUES ('home','${s(siteUrl)}');
INSERT OR IGNORE INTO wp_options (option_name,option_value) VALUES ('blogname','${s(siteName)}');
INSERT OR IGNORE INTO wp_options (option_name,option_value) VALUES ('blogdescription','');
INSERT OR IGNORE INTO wp_options (option_name,option_value) VALUES ('admin_email','${s(adminEmail)}');
INSERT OR IGNORE INTO wp_options (option_name,option_value) VALUES ('permalink_structure','/%postname%/');
INSERT OR IGNORE INTO wp_options (option_name,option_value) VALUES ('posts_per_page','10');
INSERT OR IGNORE INTO wp_options (option_name,option_value) VALUES ('date_format','Y년 n월 j일');
INSERT OR IGNORE INTO wp_options (option_name,option_value) VALUES ('timezone_string','Asia/Seoul');
INSERT OR IGNORE INTO wp_options (option_name,option_value) VALUES ('WPLANG','ko_KR');
INSERT OR IGNORE INTO wp_options (option_name,option_value) VALUES ('template','twentytwentyfour');
INSERT OR IGNORE INTO wp_options (option_name,option_value) VALUES ('stylesheet','twentytwentyfour');
INSERT OR IGNORE INTO wp_options (option_name,option_value) VALUES ('show_on_front','posts');
INSERT OR IGNORE INTO wp_options (option_name,option_value) VALUES ('db_version','57155');
INSERT OR IGNORE INTO wp_options (option_name,option_value) VALUES ('fresh_site','1');
INSERT OR IGNORE INTO wp_options (option_name,option_value) VALUES ('cp_version','23.0');
INSERT OR IGNORE INTO wp_options (option_name,option_value) VALUES ('wp_user_roles','a:5:{s:13:"administrator";a:2:{s:4:"name";s:13:"Administrator";s:12:"capabilities";a:61:{s:13:"switch_themes";b:1;s:11:"edit_themes";b:1;s:16:"activate_plugins";b:1;s:12:"edit_plugins";b:1;s:10:"edit_users";b:1;s:10:"edit_files";b:1;s:14:"manage_options";b:1;s:17:"moderate_comments";b:1;s:17:"manage_categories";b:1;s:12:"manage_links";b:1;s:12:"upload_files";b:1;s:6:"import";b:1;s:15:"unfiltered_html";b:1;s:10:"edit_posts";b:1;s:17:"edit_others_posts";b:1;s:20:"edit_published_posts";b:1;s:13:"publish_posts";b:1;s:10:"edit_pages";b:1;s:4:"read";b:1;s:8:"level_10";b:1;s:7:"level_9";b:1;s:7:"level_8";b:1;s:7:"level_7";b:1;s:7:"level_6";b:1;s:7:"level_5";b:1;s:7:"level_4";b:1;s:7:"level_3";b:1;s:7:"level_2";b:1;s:7:"level_1";b:1;s:7:"level_0";b:1;s:17:"edit_others_pages";b:1;s:20:"edit_published_pages";b:1;s:13:"publish_pages";b:1;s:12:"delete_pages";b:1;s:19:"delete_others_pages";b:1;s:22:"delete_published_pages";b:1;s:12:"delete_posts";b:1;s:19:"delete_others_posts";b:1;s:22:"delete_published_posts";b:1;s:20:"delete_private_posts";b:1;s:17:"edit_private_posts";b:1;s:18:"read_private_posts";b:1;s:20:"delete_private_pages";b:1;s:17:"edit_private_pages";b:1;s:18:"read_private_pages";b:1;s:12:"delete_users";b:1;s:12:"create_users";b:1;s:17:"unfiltered_upload";b:1;s:14:"edit_dashboard";b:1;s:14:"update_plugins";b:1;s:14:"delete_plugins";b:1;s:15:"install_plugins";b:1;s:13:"update_themes";b:1;s:14:"install_themes";b:1;s:11:"update_core";b:1;s:10:"list_users";b:1;s:12:"remove_users";b:1;s:13:"promote_users";b:1;s:18:"edit_theme_options";b:1;s:13:"delete_themes";b:1;s:6:"export";b:1;}}}');

INSERT OR IGNORE INTO wp_users
  (ID,user_login,user_pass,user_nicename,user_email,user_url,user_registered,user_status,display_name)
  VALUES (1,'${s(adminUser)}','${s(adminPass)}','${s(adminUser)}','${s(adminEmail)}','',datetime('now'),0,'${s(adminUser)}');
INSERT OR IGNORE INTO wp_usermeta (user_id,meta_key,meta_value) VALUES (1,'wp_capabilities','a:1:{s:13:"administrator";b:1;}');
INSERT OR IGNORE INTO wp_usermeta (user_id,meta_key,meta_value) VALUES (1,'wp_user_level','10');
INSERT OR IGNORE INTO wp_usermeta (user_id,meta_key,meta_value) VALUES (1,'session_tokens','');
INSERT OR IGNORE INTO wp_usermeta (user_id,meta_key,meta_value) VALUES (1,'show_welcome_panel','1');

INSERT OR IGNORE INTO wp_posts
  (ID,post_author,post_date,post_date_gmt,post_content,post_title,post_excerpt,
   post_status,comment_status,ping_status,post_name,post_modified,post_modified_gmt,
   post_type,comment_count,guid)
VALUES (1,1,datetime('now'),datetime('now'),
  '<!-- wp:paragraph --><p>WordPress에 오신 것을 환영합니다. 첫 번째 게시글입니다.</p><!-- /wp:paragraph -->',
  'Hello world!','','publish','open','open','hello-world',datetime('now'),datetime('now'),'post',1,'${s(siteUrl)}/?p=1');
INSERT OR IGNORE INTO wp_posts
  (ID,post_author,post_date,post_date_gmt,post_content,post_title,post_excerpt,
   post_status,comment_status,ping_status,post_name,post_modified,post_modified_gmt,
   post_type,comment_count,guid)
VALUES (2,1,datetime('now'),datetime('now'),
  '<!-- wp:paragraph --><p>이것은 샘플 페이지입니다.</p><!-- /wp:paragraph -->',
  '샘플 페이지','','publish','closed','open','sample-page',datetime('now'),datetime('now'),'page',0,'${s(siteUrl)}/?page_id=2');
INSERT OR IGNORE INTO wp_term_relationships (object_id,term_taxonomy_id,term_order) VALUES (1,1,0);
INSERT OR IGNORE INTO wp_comments
  (comment_ID,comment_post_ID,comment_author,comment_author_email,comment_author_url,
   comment_author_IP,comment_date,comment_date_gmt,comment_content,comment_karma,
   comment_approved,comment_agent,comment_type,comment_parent,user_id)
VALUES (1,1,'WordPress 댓글 작성자','wapuu@wordpress.example','https://wordpress.org/',
  '127.0.0.1',datetime('now'),datetime('now'),
  '안녕하세요! 이 댓글 승인을 시작으로 블로그를 시작하세요.',0,'1','Mozilla/5.0','comment',0,0);

INSERT OR IGNORE INTO cp_install_lock (id,installed_at,version,wp_version)
  VALUES (1,datetime('now'),'23.0','6.9.4');
`.trim();

  try {
    const res = await cfReq(auth, `/accounts/${accountId}/d1/database/${d1Id}/query`, 'POST', { sql: schema });
    if (!res.success) {
      const nonTrivialErrors = (res.errors || []).filter(e =>
        !String(e.message || '').includes('already exists')
      );
      if (nonTrivialErrors.length > 0) {
        console.warn('[provision] D1 스키마 경고:', JSON.stringify(nonTrivialErrors));
      }
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, error: 'D1 스키마 초기화 오류: ' + e.message };
  }
}

// ── KV Bulk 업로드 ────────────────────────────────────────────────────────────
async function putKVBulk(auth, accountId, kvId, entries) {
  if (!entries.length) return;
  const token = typeof auth === 'string' ? auth : auth.token;
  const email = typeof auth === 'object' ? auth.email : null;
  const headers = email
    ? { 'Content-Type': 'application/json', 'X-Auth-Key': token, 'X-Auth-Email': email }
    : { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token };
  try {
    const res = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces/${kvId}/bulk`,
      { method: 'PUT', headers, body: JSON.stringify(entries.map(({ key, value }) => ({
        key, value: typeof value === 'string' ? value : JSON.stringify(value),
      }))) }
    );
    const ct = res.headers.get('content-type') || '';
    if (!ct.includes('application/json')) {
      console.warn('[provision] KV bulk PUT — 비JSON 응답:', res.status);
      return;
    }
    const j = await res.json();
    if (!j.success) console.warn('[provision] KV bulk PUT 실패:', cfErrMsg(j));
  } catch (e) {
    console.warn('[provision] KV bulk PUT 오류:', e.message);
  }
}

// ── WordPress 버전 조회 ───────────────────────────────────────────────────────
async function fetchLatestWPVersion(fallback = '6.9.4') {
  try {
    const res = await fetch('https://api.wordpress.org/core/version-check/1.7/');
    if (!res.ok) return fallback;
    const data = await res.json();
    return data?.offers?.[0]?.version || fallback;
  } catch {
    return fallback;
  }
}

// ── 설치 잠금 확인 ────────────────────────────────────────────────────────────
async function isAlreadyInstalled(DB, siteId) {
  try {
    const row = await DB.prepare(
      'SELECT wp_installed, status FROM sites WHERE id=? LIMIT 1'
    ).bind(siteId).first();
    return row?.wp_installed === 1 && row?.status === 'active';
  } catch { return false; }
}

// ── OPTIONS ──────────────────────────────────────────────────────────────────
export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

// ── GET: 프로비저닝 상태 조회 ─────────────────────────────────────────────────
export async function onRequestGet({ request, env, params }) {
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  const siteId = params?.id;
  if (!siteId) return err('사이트 ID가 없습니다.', 400);

  try {
    const site = await env.DB.prepare(
      `SELECT id, status, provision_step, error_message, wp_admin_url,
              wp_version, wp_installed, domain_status, worker_name, primary_domain,
              php_version, wp_auto_update
         FROM sites WHERE id=? AND user_id=? AND deleted_at IS NULL`
    ).bind(siteId, user.id).first();

    if (!site) return err('사이트를 찾을 수 없습니다.', 404);
    return ok({ site });
  } catch (e) {
    return err('상태 조회 오류: ' + e.message, 500);
  }
}

// ── POST: 프로비저닝 실행 ─────────────────────────────────────────────────────
export async function onRequestPost({ request, env, params }) {
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  const siteId = params?.id;
  if (!siteId) return err('사이트 ID가 없습니다.', 400);
  if (!env?.DB) return err('데이터베이스 연결 오류', 503);

  // ── 1. 중복 설치 방지 ─────────────────────────────────────────────────────
  if (await isAlreadyInstalled(env.DB, siteId)) {
    return ok({ message: '이미 설치 완료된 사이트입니다.', installed: true });
  }

  let currentStep = 'init';
  try {
    // ── 2. Site + Settings 동시 조회 ─────────────────────────────────────────
    const [siteRows, settingsRows] = await env.DB.batch([
      env.DB.prepare(
        `SELECT s.id, s.user_id, s.name, s.primary_domain, s.site_prefix,
                s.status, s.provision_step, s.plan,
                s.site_d1_id, s.site_kv_id,
                s.php_version, s.wp_auto_update,
                u.cf_global_api_key, u.cf_account_email, u.cf_account_id, u.email
           FROM sites s
           JOIN users u ON u.id = s.user_id
          WHERE s.id=? AND s.user_id=? AND s.deleted_at IS NULL`
      ).bind(siteId, user.id),
      env.DB.prepare('SELECT key, value FROM settings'),
    ]);

    const site = siteRows.results?.[0] ?? null;
    const settings = {};
    for (const r of settingsRows.results || []) settings[r.key] = r.value ?? '';

    if (!site) return err('사이트를 찾을 수 없습니다.', 404);
    if (site.status === 'active') return ok({ message: '이미 완료된 사이트입니다.', installed: true });

    // ── 3. CF 인증 구성 ───────────────────────────────────────────────────────
    currentStep = 'cf_auth';
    await flushState(env.DB, siteId, { status: 'provisioning', provision_step: currentStep, error_message: null });

    const encKey = env?.ENCRYPTION_KEY || 'cp_enc_default';

    let cfAuth    = null;
    let cfAccount = null;

    // 사용자 개인 CF 키 우선
    if (site.cf_global_api_key && site.cf_account_id) {
      const raw = deobfuscate(site.cf_global_api_key, encKey);
      const key = (raw && raw.length > 10) ? raw : site.cf_global_api_key;
      cfAuth    = site.cf_account_email
        ? { token: key, email: site.cf_account_email }
        : { token: key };
      cfAccount = site.cf_account_id;
    }

    // 관리자 전역 CF 키 fallback
    if (!cfAuth || !cfAccount) {
      const adminToken   = settingVal(settings, 'cf_api_token');
      const adminAccount = settingVal(settings, 'cf_account_id');
      if (adminToken && adminAccount) {
        cfAuth    = { token: adminToken };
        cfAccount = adminAccount;
      }
    }

    if (!cfAuth || !cfAccount) {
      await failSite(env.DB, siteId, 'cf_auth', 'Cloudflare API 키가 설정되지 않았습니다. "내 계정"에서 CF Global API Key와 Account ID를 등록해주세요.');
      return err('Cloudflare API 키 없음', 400);
    }

    // ── 4. CF 토큰 사전 검증 (DNS 오류 사전 차단) ─────────────────────────────
    currentStep = 'cf_validate';
    const [tokenCheck, accountCheck] = await Promise.all([
      validateCfToken(cfAuth),
      validateCfAccount(cfAuth, cfAccount),
    ]);

    if (!tokenCheck.ok) {
      await failSite(env.DB, siteId, 'cf_validate', tokenCheck.error);
      return err(tokenCheck.error, 400);
    }
    if (!accountCheck.ok) {
      await failSite(env.DB, siteId, 'cf_validate', accountCheck.error);
      return err(accountCheck.error, 400);
    }

    // ── 5. 기본 설정값 ───────────────────────────────────────────────────────
    const domain      = site.primary_domain;
    const wwwDomain   = 'www.' + domain;
    const prefix      = site.site_prefix;
    const workerName  = 'cloudpress-site-' + prefix;
    const siteUrl     = 'https://' + domain;
    const phpVersion  = site.php_version  || '8.2';
    const autoUpdate  = site.wp_auto_update || 'minor'; // 'enabled'|'disabled'|'minor'
    const adminUsername = 'admin';
    const adminPassword = genPassword(20);
    const adminEmail    = user.email || 'admin@cloudpress.site';

    // WordPress 최신 버전 확인
    const wpVersion = await fetchLatestWPVersion('6.9.4');
    console.log(`[provision] WordPress ${wpVersion} / PHP ${phpVersion} / 자동업데이트: ${autoUpdate}`);

    // ── 6. D1 + KV 생성 ─────────────────────────────────────────────────────
    currentStep = 'd1_kv_create';
    await flushState(env.DB, siteId, { provision_step: currentStep });

    let d1Id = site.site_d1_id || null;
    let kvId = site.site_kv_id || null;

    if (!d1Id) {
      const d1Res = await createD1(cfAuth, cfAccount, prefix);
      if (!d1Res.ok) {
        await failSite(env.DB, siteId, 'd1_create', d1Res.error);
        return err('D1 생성 실패: ' + d1Res.error, 500);
      }
      d1Id = d1Res.id;
      await flushState(env.DB, siteId, { site_d1_id: d1Id });
      console.log('[provision] D1 생성:', d1Res.name, d1Id);
    }

    if (!kvId) {
      const kvRes = await createKV(cfAuth, cfAccount, prefix);
      if (!kvRes.ok) {
        await failSite(env.DB, siteId, 'kv_create', kvRes.error);
        return err('KV 생성 실패: ' + kvRes.error, 500);
      }
      kvId = kvRes.id;
      await flushState(env.DB, siteId, { site_kv_id: kvId });
      console.log('[provision] KV 생성:', kvRes.title, kvId);
    }

    // ── 7. WordPress D1 스키마 초기화 ────────────────────────────────────────
    currentStep = 'd1_schema';
    await flushState(env.DB, siteId, { provision_step: currentStep });

    const schemaRes = await initWordPressD1(cfAuth, cfAccount, d1Id, {
      siteName: site.name, siteUrl,
      adminEmail, adminUser: adminUsername, adminPass: adminPassword,
    });
    if (!schemaRes.ok) {
      console.warn('[provision] D1 스키마 경고 (비치명적):', schemaRes.error);
      // 스키마 초기화 실패는 비치명적 — 계속 진행
    }

    // ── 8. 메인 바인딩 ID 조회 (CACHE, SESSIONS KV) ──────────────────────────
    currentStep = 'resolve_bindings';
    await flushState(env.DB, siteId, { provision_step: currentStep });

    let mainDbId     = settingVal(settings, 'main_db_id',     '');
    let cacheKvId    = settingVal(settings, 'cache_kv_id',    '');
    let sessionsKvId = settingVal(settings, 'sessions_kv_id', '');

    if (!mainDbId || !cacheKvId || !sessionsKvId) {
      const resolved = await resolveMainBindingIds(cfAuth, cfAccount);
      if (!mainDbId     && resolved.mainDbId)     mainDbId     = resolved.mainDbId;
      if (!cacheKvId    && resolved.cacheKvId)    cacheKvId    = resolved.cacheKvId;
      if (!sessionsKvId && resolved.sessionsKvId) sessionsKvId = resolved.sessionsKvId;

      // 조회된 ID 캐시 저장
      if (resolved.mainDbId || resolved.cacheKvId || resolved.sessionsKvId) {
        const upsert = `INSERT INTO settings (key,value,updated_at) VALUES (?,?,datetime('now'))
                        ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`;
        const stmts = [];
        if (resolved.mainDbId)     stmts.push(env.DB.prepare(upsert).bind('main_db_id',     resolved.mainDbId));
        if (resolved.cacheKvId)    stmts.push(env.DB.prepare(upsert).bind('cache_kv_id',    resolved.cacheKvId));
        if (resolved.sessionsKvId) stmts.push(env.DB.prepare(upsert).bind('sessions_kv_id', resolved.sessionsKvId));
        if (stmts.length) env.DB.batch(stmts).catch(() => {});
      }
    }

    // ── 9. worker.js 소스 로드 ────────────────────────────────────────────────
    currentStep = 'worker_source';
    await flushState(env.DB, siteId, { provision_step: currentStep });

    let workerSource = (env.WORKER_SOURCE && env.WORKER_SOURCE.length > 500)
      ? env.WORKER_SOURCE
      : null;

    if (!workerSource) {
      try {
        const baseUrl      = new URL(request.url);
        const workerJsUrl  = `${baseUrl.protocol}//${baseUrl.host}/worker.js`;
        console.log('[provision] worker.js fetch:', workerJsUrl);
        const fetchRes = await fetch(workerJsUrl, { cf: { cacheEverything: false } });
        if (fetchRes.ok) {
          const ct   = fetchRes.headers.get('content-type') || '';
          const text = await fetchRes.text();
          if (text && text.length > 500 && !ct.includes('text/html')) {
            workerSource = text;
            console.log('[provision] worker.js 로드 성공:', text.length, 'bytes');
          } else if (text && text.startsWith('/**')) {
            workerSource = text;
          }
        }
      } catch (e) {
        console.error('[provision] worker.js fetch 오류:', e.message);
      }
    }

    // Fallback: 최소 동작 Worker
    if (!workerSource) {
      console.warn('[provision] worker.js 소스 없음 — 최소 Worker 사용');
      workerSource = `/**
 * CloudPress Minimal Worker — 사이트 준비 중
 * worker.js 배포 후 사이트 관리자에서 "재설치" 버튼을 눌러주세요.
 */
export default {
  async fetch(request, env) {
    const html = \`<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>\${env.CP_SITE_NAME || '사이트'} — 준비 중</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:system-ui,sans-serif;background:#0a0a0f;color:#f0f0fa;
         display:flex;align-items:center;justify-content:center;min-height:100vh}
    .box{text-align:center;padding:48px 32px;max-width:420px}
    .logo{font-size:2rem;margin-bottom:16px}
    h1{font-size:1.4rem;font-weight:700;margin-bottom:8px}
    p{color:#9090aa;font-size:.9rem;line-height:1.6;margin-bottom:24px}
    .spin{width:36px;height:36px;border:3px solid rgba(249,115,22,.2);
          border-top-color:#f97316;border-radius:50%;animation:spin .8s linear infinite;margin:0 auto 20px}
    @keyframes spin{to{transform:rotate(360deg)}}
  </style>
</head>
<body>
  <div class="box">
    <div class="spin"></div>
    <div class="logo">🚀</div>
    <h1>WordPress 사이트 준비 중</h1>
    <p>CloudPress가 사이트를 구성하고 있습니다.<br>잠시 후 새로고침해 주세요.</p>
  </div>
</body>
</html>\`;
    return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
};`;
    }

    // ── 10. Worker 업로드 ─────────────────────────────────────────────────────
    currentStep = 'worker_upload';
    await flushState(env.DB, siteId, { provision_step: currentStep });
    console.log('[provision] Worker 업로드:', workerName);

    const cfApiTokenForWorker = typeof cfAuth === 'object' ? cfAuth.token : cfAuth;

    const upRes = await uploadWordPressWorker(cfAuth, cfAccount, workerName, {
      mainDbId,
      cacheKvId,
      sessionsKvId,
      siteD1Id:    d1Id,
      siteKvId:    kvId,
      cfAccountId: cfAccount,
      cfApiToken:  cfApiTokenForWorker,
      sitePrefix:  prefix,
      siteName:    site.name,
      siteDomain:  domain,
      phpVersion,
      supabaseUrl: site.supabase_url  || '',
      supabaseKey: site.supabase_key  || '',
      adminUser:   adminUsername,
      adminPass:   adminPassword,
      adminEmail,
      wpVersion,
      workerSource,
    });

    if (!upRes.ok) {
      await failSite(env.DB, siteId, 'worker_upload', 'Worker 업로드 실패: ' + upRes.error);
      return err('Worker 업로드 실패: ' + upRes.error, 500);
    }
    console.log('[provision] Worker 업로드 완료');

    // workers.dev 서브도메인 활성화
    const workerDevEnabled = await enableWorkersDev(cfAuth, cfAccount, workerName);
    console.log('[provision] workers.dev:', workerDevEnabled ? '활성화' : '실패');

    // ── 11. KV 도메인 매핑 저장 ──────────────────────────────────────────────
    currentStep = 'kv_mapping';
    await flushState(env.DB, siteId, { provision_step: currentStep });

    const siteMapping = JSON.stringify({
      id: siteId,
      name: site.name,
      site_prefix:   prefix,
      site_d1_id:    d1Id,
      site_kv_id:    kvId,
      wp_version:    wpVersion,
      php_version:   phpVersion,
      wp_auto_update: autoUpdate,
      wp_installed:  1,
      status:        'active',
      suspended:     0,
    });

    if (cacheKvId) {
      await putKVBulk(cfAuth, cfAccount, cacheKvId, [
        { key: `site_domain:${domain}`,    value: siteMapping },
        { key: `site_domain:${wwwDomain}`, value: siteMapping },
        { key: `site_prefix:${prefix}`,    value: siteMapping },
      ]);
    }

    // ── 12. DNS / Custom Domain 설정 ─────────────────────────────────────────
    currentStep = 'dns_setup';
    await flushState(env.DB, siteId, { provision_step: currentStep });

    let domainStatus  = 'manual_required';
    let cnameTarget   = '';
    let routeId       = null;
    let routeWwwId    = null;
    let cfZoneId      = null;

    // Workers Custom Domain (가장 우선)
    const [cdRoot, cdWww] = await Promise.all([
      addWorkerCustomDomain(cfAuth, cfAccount, workerName, domain),
      addWorkerCustomDomain(cfAuth, cfAccount, workerName, wwwDomain),
    ]);

    if (cdRoot.ok || cdWww.ok) {
      domainStatus = 'active';
      console.log('[provision] Custom Domain 등록 완료');
    } else {
      // Zone 기반 Route + DNS 레코드 방식
      const [subdomain, zone] = await Promise.all([
        getWorkerSubdomain(cfAuth, cfAccount, workerName),
        cfGetZone(cfAuth, domain),
      ]);
      cnameTarget = subdomain;

      if (zone.ok) {
        cfZoneId = zone.zoneId;

        const [rr, rw] = await Promise.all([
          cfUpsertRoute(cfAuth, cfZoneId, domain + '/*',    workerName),
          cfUpsertRoute(cfAuth, cfZoneId, wwwDomain + '/*', workerName),
        ]);
        if (rr.ok) routeId    = rr.routeId;
        if (rw.ok) routeWwwId = rw.routeId;

        const [dr, drw] = await Promise.all([
          cfUpsertDns(cfAuth, cfZoneId, 'CNAME', domain,    cnameTarget, true),
          cfUpsertDns(cfAuth, cfZoneId, 'CNAME', wwwDomain, cnameTarget, true),
        ]);

        if ((rr.ok || rw.ok) && (dr.ok || drw.ok)) domainStatus = 'active';
        else if (rr.ok || rw.ok)                    domainStatus = 'dns_propagating';

        await flushState(env.DB, siteId, {
          cf_zone_id:          cfZoneId,
          worker_route_id:     routeId    || null,
          worker_route_www_id: routeWwwId || null,
          dns_record_id:       dr.recordId  || null,
          dns_record_www_id:   drw.recordId || null,
        });
      }
    }

    // ── 13. 완료 상태 저장 ────────────────────────────────────────────────────
    currentStep = 'completed';
    const adminUrl = `https://${domain}/wp-admin/`;

    await flushState(env.DB, siteId, {
      status:            'active',
      provision_step:    'completed',
      domain_status:     domainStatus,
      wp_admin_url:      adminUrl,
      wp_admin_username: adminUsername,
      wp_admin_password: adminPassword,
      wp_installed:      1,
      wp_version:        wpVersion,
      php_version:       phpVersion,
      wp_auto_update:    autoUpdate,
      worker_name:       workerName,
      worker_route:      domain + '/*',
      worker_route_www:  wwwDomain + '/*',
      error_message:     domainStatus === 'manual_required'
        ? `외부 DNS 필요 — CNAME ${domain} → ${cnameTarget || workerName + '.workers.dev'}`
        : null,
    });

    const finalSite = await env.DB.prepare(
      `SELECT id, status, provision_step, wp_admin_url, primary_domain,
              domain_status, worker_name, name, wp_version, php_version, wp_auto_update
         FROM sites WHERE id=?`
    ).bind(siteId).first();

    return ok({
      message:        `WordPress ${wpVersion} 프로비저닝 완료 (PHP ${phpVersion})`,
      siteId,
      site:           finalSite,
      worker_name:    workerName,
      cname_target:   cnameTarget,
      wp_admin_url:   adminUrl,
      wp_admin_user:  adminUsername,
      wp_admin_pass:  adminPassword,
      wp_version:     wpVersion,
      php_version:    phpVersion,
      auto_update:    autoUpdate,
      install_locked: true,
      cname_instructions: domainStatus === 'manual_required' ? {
        type: 'CNAME',
        root: { host: '@',   value: cnameTarget || workerName + '.workers.dev' },
        www:  { host: 'www', value: cnameTarget || workerName + '.workers.dev' },
        note: `DNS 전파 후 ${adminUrl} 에서 WordPress를 사용하세요.`,
      } : null,
    });

  } catch (e) {
    console.error('[provision] 예외:', e.message, e.stack);
    await failSite(env.DB, siteId, currentStep, e.message);
    return err('프로비저닝 오류: ' + e.message, 500);
  }
}
