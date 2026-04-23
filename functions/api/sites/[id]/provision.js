// functions/api/sites/[id]/provision.js — CloudPress v20.0
//
// [v20.0 주요 변경]
// 1. 자체 CMS 완전 제거 → WordPress on Cloudflare Workers 방식
// 2. 사이트 생성 시 Supabase 계정 자동 생성 + 2개 스토리지 버킷 생성
//    - Primary 버킷: 미디어 기본 스토리지
//    - Secondary 버킷: Primary 소진 시 자동 전환 (failover)
//    - 모두 소진 시: D1 + KV fallback
// 3. KV는 기본으로 항상 사용 (이중 캐시 레이어)
// 4. 한 번 설치 후 재설치 방지 (cp_install_lock)
// 5. GitHub tarball 1회 fetch → WordPress worker 코드 변환 + 업로드
// 6. WAF + DDoS 방어 내장 Worker 배포

import { CORS, _j, ok, err, getToken, getUser, loadAllSettings, settingVal } from '../../_shared.js';

const CF_API = 'https://api.cloudflare.com/client/v4';

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
  const opts = { method, headers: cfHeaders(token, email) };
  if (body !== undefined && body !== null) opts.body = JSON.stringify(body);
  try {
    const res  = await fetch(CF_API + path, opts);
    const json = await res.json();
    if (!json.success) {
      console.error(`[cfReq] ${method} ${path} failed:`, JSON.stringify(json.errors || []));
    }
    return json;
  } catch (e) {
    return { success: false, errors: [{ message: e.message }] };
  }
}

function cfErrMsg(json) {
  return (json?.errors || []).map(e => (e.code ? `[${e.code}] ` : '') + (e.message || '')).join('; ') || 'unknown';
}

// ── Supabase 관리 API ─────────────────────────────────────────────────────────
const SUPABASE_MGMT_API = 'https://api.supabase.com';

async function supabaseMgmtReq(supabaseToken, path, method = 'GET', body) {
  const opts = {
    method,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${supabaseToken}`,
    },
  };
  if (body) opts.body = JSON.stringify(body);
  try {
    const res = await fetch(SUPABASE_MGMT_API + path, opts);
    if (!res.ok) {
      const txt = await res.text().catch(() => '');
      return { ok: false, status: res.status, error: txt };
    }
    const json = await res.json().catch(() => ({}));
    return { ok: true, data: json };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// Supabase 프로젝트 생성 (관리 API)
async function createSupabaseProject(supabaseToken, orgId, projectName, dbPassword) {
  // 사용 가능한 지역 중 가장 가까운 것 선택 (ap-northeast-1 = Tokyo, 한국에 가장 가까움)
  const region = 'ap-northeast-1';
  const res = await supabaseMgmtReq(supabaseToken, '/v1/projects', 'POST', {
    name: projectName,
    organization_id: orgId,
    plan: 'free',
    region,
    db_pass: dbPassword,
  });
  if (!res.ok) return { ok: false, error: 'Supabase 프로젝트 생성 실패: ' + (res.error || res.status) };
  const project = res.data;
  return {
    ok: true,
    projectId: project.id,
    projectRef: project.ref,
    anonKey: project.anon_key,
    serviceRoleKey: project.service_role_key,
    url: `https://${project.ref}.supabase.co`,
  };
}

// Supabase Storage 버킷 생성
async function createSupabaseBucket(supabaseUrl, serviceRoleKey, bucketName) {
  try {
    const res = await fetch(`${supabaseUrl}/storage/v1/bucket`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': serviceRoleKey,
        'Authorization': `Bearer ${serviceRoleKey}`,
      },
      body: JSON.stringify({
        id: bucketName,
        name: bucketName,
        public: true,           // 공개 버킷 (미디어 직접 서빙)
        file_size_limit: 52428800, // 50MB
        allowed_mime_types: [
          'image/*', 'video/*', 'audio/*',
          'application/pdf', 'application/zip',
          'text/plain', 'application/json',
          'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        ],
      }),
    });
    if (res.ok || res.status === 200 || res.status === 201) {
      return { ok: true, bucket: bucketName };
    }
    // 이미 존재하면 OK
    if (res.status === 409) return { ok: true, bucket: bucketName, existed: true };
    const txt = await res.text().catch(() => '');
    return { ok: false, error: `버킷 생성 실패 (${res.status}): ${txt}` };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// Supabase Storage Public Policy 설정
async function setSupabaseBucketPublicPolicy(supabaseUrl, serviceRoleKey, bucketName) {
  // RLS 정책: 공개 읽기, 인증 업로드
  const policies = [
    {
      name: 'Public read',
      definition: `bucket_id = '${bucketName}'`,
      check: null,
      command: 'SELECT',
      roles: [],
    },
  ];
  for (const policy of policies) {
    try {
      await fetch(`${supabaseUrl}/storage/v1/policy`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'apikey': serviceRoleKey,
          'Authorization': `Bearer ${serviceRoleKey}`,
        },
        body: JSON.stringify({ ...policy, bucket_id: bucketName }),
      });
    } catch {}
  }
}

// ── 상태 관리 헬퍼 ────────────────────────────────────────────────────────────
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

function randSuffix(len = 6) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let out = '';
  for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

function genPassword(len = 24) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%';
  const arr = crypto.getRandomValues(new Uint8Array(len));
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

// ── CF 리소스 ─────────────────────────────────────────────────────────────────
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

// ── D1 WordPress 스키마 초기화 ────────────────────────────────────────────────
async function initWordPressD1Schema(auth, accountId, d1Id, siteConfig) {
  const { siteName, siteUrl, adminEmail } = siteConfig;

  // WordPress 완전 호환 스키마
  const schema = getWPSchema(siteName, siteUrl, adminEmail);

  const res = await cfReq(auth, `/accounts/${accountId}/d1/database/${d1Id}/query`, 'POST', {
    sql: schema,
  });

  if (!res.success) {
    const errors = (res.errors || []).filter(e => !String(e.message).includes('already exists'));
    if (errors.length > 0) {
      console.warn('[provision] D1 스키마 일부 오류:', JSON.stringify(errors));
    }
  }

  return { ok: true };
}

function getWPSchema(siteName, siteUrl, adminEmail) {
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
CREATE TABLE IF NOT EXISTS wp_cron_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp INTEGER NOT NULL,
  schedule TEXT,
  hook TEXT NOT NULL,
  args TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS cp_install_lock (
  id INTEGER PRIMARY KEY DEFAULT 1,
  installed_at TEXT NOT NULL DEFAULT (datetime('now')),
  version TEXT NOT NULL DEFAULT '20.0',
  CONSTRAINT one_row CHECK (id = 1)
);
CREATE INDEX IF NOT EXISTS idx_wp_posts_name ON wp_posts(post_name);
CREATE INDEX IF NOT EXISTS idx_wp_posts_type ON wp_posts(post_type, post_status);
CREATE INDEX IF NOT EXISTS idx_wp_posts_date ON wp_posts(post_date);
CREATE INDEX IF NOT EXISTS idx_wp_postmeta_post ON wp_postmeta(post_id);
CREATE INDEX IF NOT EXISTS idx_wp_postmeta_key ON wp_postmeta(meta_key);
CREATE INDEX IF NOT EXISTS idx_wp_users_login ON wp_users(user_login);
CREATE INDEX IF NOT EXISTS idx_wp_usermeta_user ON wp_usermeta(user_id);
CREATE INDEX IF NOT EXISTS idx_wp_options_auto ON wp_options(autoload);
CREATE INDEX IF NOT EXISTS idx_wp_terms_slug ON wp_terms(slug);
CREATE INDEX IF NOT EXISTS idx_wp_tt_term ON wp_term_taxonomy(term_id);
CREATE INDEX IF NOT EXISTS idx_wp_tt_tax ON wp_term_taxonomy(taxonomy);
CREATE INDEX IF NOT EXISTS idx_wp_tr_tax ON wp_term_relationships(term_taxonomy_id);
CREATE INDEX IF NOT EXISTS idx_wp_comments_post ON wp_comments(comment_post_ID);
CREATE INDEX IF NOT EXISTS idx_wp_cron_ts ON wp_cron_events(timestamp);
INSERT OR IGNORE INTO wp_terms (term_id, name, slug, term_group) VALUES (1, '미분류', 'uncategorized', 0);
INSERT OR IGNORE INTO wp_term_taxonomy (term_taxonomy_id, term_id, taxonomy, description, parent, count) VALUES (1, 1, 'category', '', 0, 1);
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('siteurl', '${siteUrl}');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('home', '${siteUrl}');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('blogname', '${siteName.replace(/'/g, "''")}');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('blogdescription', '');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('admin_email', '${adminEmail || 'admin@example.com'}');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('permalink_structure', '/%postname%/');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('posts_per_page', '10');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('date_format', 'Y년 n월 j일');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('timezone_string', 'Asia/Seoul');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('WPLANG', 'ko_KR');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('template', 'twentytwentyfour');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('stylesheet', 'twentytwentyfour');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('show_on_front', 'posts');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('db_version', '57155');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('cp_installed', '1');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('cp_version', '20.0');
INSERT OR IGNORE INTO wp_options (option_name, option_value) VALUES ('fresh_site', '1');
INSERT OR IGNORE INTO cp_install_lock (id, installed_at, version) VALUES (1, datetime('now'), '20.0');
INSERT OR IGNORE INTO wp_posts (
  ID, post_author, post_date, post_date_gmt, post_content, post_title,
  post_excerpt, post_status, comment_status, ping_status, post_name,
  post_modified, post_modified_gmt, post_type, comment_count, guid
) VALUES (
  1, 1, datetime('now'), datetime('now'),
  '<p>WordPress에 오신 것을 환영합니다. 이것은 첫 번째 게시글입니다.</p>',
  'Hello world!', '',
  'publish', 'open', 'open', 'hello-world',
  datetime('now'), datetime('now'), 'post', 0, '${siteUrl}/?p=1'
);
INSERT OR IGNORE INTO wp_term_relationships (object_id, term_taxonomy_id, term_order) VALUES (1, 1, 0);
`.trim();
}

// ── KV Bulk 업로드 ────────────────────────────────────────────────────────────
async function putCacheKVBulk(auth, accountId, kvId, entries) {
  if (!entries.length) return;
  const token = typeof auth === 'string' ? auth : auth.token;
  const email = typeof auth === 'string' ? null  : auth.email;
  try {
    const res = await fetch(
      `${CF_API}/accounts/${accountId}/storage/kv/namespaces/${kvId}/bulk`,
      {
        method: 'PUT',
        headers: cfHeaders(token, email),
        body: JSON.stringify(entries.map(({ key, value }) => ({ key, value }))),
      }
    );
    if (!res.ok) console.warn('[provision] CACHE KV bulk put 오류:', res.status);
  } catch (e) {
    console.warn('[provision] CACHE KV bulk put 오류:', e.message);
  }
}

// ── Worker 업로드 ─────────────────────────────────────────────────────────────
// WordPress Edge Worker 코드를 직접 번들해서 업로드
// GitHub에서 worker.js 가져오거나 내장 코드 사용
async function uploadWordPressWorker(auth, accountId, workerName, opts) {
  const {
    mainDbId, cacheKvId, sessionsKvId, siteD1Id, siteKvId,
    cfAccountId, cfApiToken, sitePrefix, siteName, siteDomain,
    supabaseUrl, supabaseKey, supabaseUrl2, supabaseKey2,
    storageBucket, storageBucket2,
  } = opts;

  const token = typeof auth === 'string' ? auth : auth.token;
  const email = typeof auth === 'string' ? null  : auth.email;

  const bindings = [];
  if (mainDbId)     bindings.push({ type: 'd1',           name: 'CP_MAIN_DB',   id: mainDbId });
  if (cacheKvId)    bindings.push({ type: 'kv_namespace', name: 'CACHE',         namespace_id: cacheKvId });
  if (sessionsKvId) bindings.push({ type: 'kv_namespace', name: 'SESSIONS',      namespace_id: sessionsKvId });
  if (siteD1Id)     bindings.push({ type: 'd1',           name: 'DB',            id: siteD1Id });
  if (siteKvId)     bindings.push({ type: 'kv_namespace', name: 'SITE_KV',       namespace_id: siteKvId });

  // 플레인 텍스트 바인딩
  bindings.push({ type: 'plain_text', name: 'CP_SITE_NAME',      text: siteName    || '' });
  bindings.push({ type: 'plain_text', name: 'CP_SITE_URL',       text: 'https://' + (siteDomain || '') });
  bindings.push({ type: 'plain_text', name: 'SITE_PREFIX',       text: sitePrefix  || '' });
  bindings.push({ type: 'plain_text', name: 'CF_ACCOUNT_ID',     text: cfAccountId || '' });
  bindings.push({ type: 'plain_text', name: 'STORAGE_BUCKET',    text: storageBucket  || 'media' });
  bindings.push({ type: 'plain_text', name: 'STORAGE_BUCKET2',   text: storageBucket2 || 'media-backup' });

  // Supabase 시크릿 바인딩
  if (supabaseUrl)  bindings.push({ type: 'secret_text', name: 'SUPABASE_URL',  text: supabaseUrl });
  if (supabaseKey)  bindings.push({ type: 'secret_text', name: 'SUPABASE_KEY',  text: supabaseKey });
  if (supabaseUrl2) bindings.push({ type: 'secret_text', name: 'SUPABASE_URL2', text: supabaseUrl2 });
  if (supabaseKey2) bindings.push({ type: 'secret_text', name: 'SUPABASE_KEY2', text: supabaseKey2 });
  if (cfApiToken)   bindings.push({ type: 'secret_text', name: 'CF_API_TOKEN',  text: cfApiToken });

  const metadata = {
    main_module: 'worker.js',
    compatibility_date: '2025-04-01',
    compatibility_flags: ['nodejs_compat'],
    bindings,
  };

  // worker.js 소스: env.WORKER_SOURCE → KV → GitHub → 내장 fallback
  let workerSource = '';
  // [1] 환경변수 직접 주입 (wrangler secrets으로 WORKER_SOURCE 배포 시)
  if (opts.workerSourceEnv && opts.workerSourceEnv.length > 500) {
    workerSource = opts.workerSourceEnv;
  }
  // [2] GitHub에서 최신 worker.js 가져오기
  if (!workerSource || workerSource.length < 500) {
    try {
      const ghUrl = 'https://raw.githubusercontent.com/cloudpress-wp/cloudpress-wp/main/worker.js';
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 8000);
      const ghRes = await fetch(ghUrl, {
        headers: { 'User-Agent': 'CloudPress-Provision/20' },
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (ghRes.ok) {
        const src = await ghRes.text();
        if (src && src.length > 1000) workerSource = src;
      }
    } catch {}
  }
  // [3] 내장 fallback (최소 동작 보장)
  if (!workerSource || workerSource.length < 500) {
    workerSource = getBuiltinWorkerSource(opts);
  }

  if (!workerSource || workerSource.length < 100) {
    return { ok: false, error: 'Worker 소스가 비어 있습니다.' };
  }

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
    workerSource + CRLF
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
        method: 'PUT',
        headers: {
          ...cfHeaders(token, email),
          'Content-Type': `multipart/form-data; boundary=${boundary}`,
        },
        body,
      }
    );
    const json = await res.json();
    if (!json.success) {
      return { ok: false, error: 'Worker 업로드 실패: ' + cfErrMsg(json) };
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, error: 'Worker 업로드 오류: ' + e.message };
  }
}

// ── 내장 WordPress Worker 소스 생성 ──────────────────────────────────────────
// GitHub fetch 실패 시 또는 직접 배포 시 사용
// 실제 worker.js의 핵심 로직을 직접 번들
function getBuiltinWorkerSource(opts) {
  // worker.js 전체 내용을 번들 (외부에서 읽어서 그대로 전달)
  // provision.js 실행 시 env에서 WORKER_SOURCE를 읽거나
  // 플랫폼 배포 시 wrangler secrets로 주입
  // 여기서는 기본 WordPress Edge Worker 최소 소스를 반환
  return `
// WordPress Edge Worker — CloudPress v20.0 (auto-generated)
// Site: ${opts.siteDomain}
// Prefix: ${opts.sitePrefix}

const CACHE_TTL = 300;
const SITE_PREFIX = '${opts.sitePrefix}';
const SITE_NAME = ${JSON.stringify(opts.siteName || '')};
const SITE_URL = 'https://${opts.siteDomain}';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method = request.method;

    // WAF: 기본 보안
    const wafBlock = basicWAF(url, request);
    if (wafBlock) return new Response('Forbidden', { status: 403 });

    // Rate Limiting
    const ip = request.headers.get('cf-connecting-ip') || '0.0.0.0';
    const rl = await rateLimit(env, ip, method);
    if (!rl.allowed) return new Response('Too Many Requests', { status: 429, headers: { 'Retry-After': '60' } });

    // REST API
    if (pathname.startsWith('/wp-json/')) return handleRestAPI(env, request, url);

    // robots.txt
    if (pathname === '/robots.txt') return new Response('User-agent: *\\nDisallow: /wp-admin/\\nSitemap: ' + SITE_URL + '/wp-sitemap.xml\\n', { headers: { 'Content-Type': 'text/plain' } });

    // 캐시 확인
    const cacheKey = request;
    const cached = await caches.default.match(cacheKey);
    if (cached) {
      const r = new Response(cached.body, { status: cached.status, headers: cached.headers });
      r.headers.set('x-cp-hit', 'edge');
      return r;
    }

    // KV 캐시
    const kvKey = 'page:' + SITE_PREFIX + ':' + pathname;
    const kvHit = env.CACHE ? await env.CACHE.get(kvKey, { type: 'text' }).catch(() => null) : null;
    if (kvHit) {
      const resp = new Response(kvHit, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'public, max-age=' + CACHE_TTL, 'x-cp-hit': 'kv' } });
      ctx.waitUntil(caches.default.put(cacheKey, resp.clone()));
      return resp;
    }

    // Edge SSR
    const html = await renderPage(env, pathname, url);
    const resp = new Response(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'public, max-age=' + CACHE_TTL } });
    ctx.waitUntil(caches.default.put(cacheKey, resp.clone()));
    if (env.CACHE) ctx.waitUntil(env.CACHE.put(kvKey, html, { expirationTtl: 86400 }));
    return resp;
  }
};

function basicWAF(url, request) {
  const p = url.pathname;
  if (/\\.\.(\\/|\\\\)/.test(p)) return true;
  if (p === '/xmlrpc.php') return true;
  const ua = request.headers.get('user-agent') || '';
  if (/sqlmap|nikto|masscan/i.test(ua)) return true;
  return false;
}

async function rateLimit(env, ip, method) {
  if (!env.CACHE) return { allowed: true };
  const key = 'rl:' + ip + ':' + Math.floor(Date.now() / 60000);
  try {
    const cur = parseInt(await env.CACHE.get(key) || '0', 10);
    if (cur > 300) return { allowed: false };
    env.CACHE.put(key, String(cur + 1), { expirationTtl: 65 }).catch(() => {});
    return { allowed: true };
  } catch { return { allowed: true }; }
}

async function renderPage(env, pathname, url) {
  let posts = [];
  try {
    if (pathname === '/' || pathname === '') {
      const res = await env.DB.prepare('SELECT ID, post_title, post_content, post_excerpt, post_date, post_name FROM wp_posts WHERE post_type=\\'post\\' AND post_status=\\'publish\\' ORDER BY post_date DESC LIMIT 10').all();
      posts = res.results || [];
    }
  } catch {}

  // Twenty Twenty-Five 스타일 포스트 HTML 빌드
  const postsHtml = posts.map(p => {
    const excerpt = (p.post_excerpt || p.post_content || '').replace(/<[^>]+>/g,'').slice(0,200);
    return '<div class="wp-block-post">' +
      '<div class="wp-block-post-date"><time datetime="' + (p.post_date||'') + '">' + (p.post_date ? p.post_date.slice(0,10) : '') + '</time></div>' +
      '<h2 class="wp-block-post-title"><a href="' + SITE_URL + '/' + (p.post_name||'') + '/">' + (p.post_title||'') + '</a></h2>' +
      (excerpt ? '<p class="wp-block-post-excerpt__excerpt">' + excerpt + (excerpt.length >= 200 ? '…' : '') + '</p>' : '') +
      '</div>';
  }).join('');

  // Twenty Twenty-Five 디자인 토큰 기반 초기 홈페이지
  return '<!DOCTYPE html><html lang="ko" class="no-js"><head>' +
    '<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<meta name="generator" content="WordPress 6.9">' +
    '<title>' + SITE_NAME + '</title>' +
    '<link rel="preconnect" href="https://fonts.bunny.net">' +
    '<link href="https://fonts.bunny.net/css?family=manrope:300,400,500,600,700&display=swap" rel="stylesheet">' +
    '<style>' +
    ':root{--base:#FFFFFF;--contrast:#111111;--accent-4:#686868;--sp-30:20px;--sp-40:30px;--sp-50:clamp(30px,5vw,50px);--sp-60:clamp(30px,7vw,70px);--fs-sm:0.875rem;--fs-md:clamp(1rem,2vw,1.125rem);--fs-lg:clamp(1.125rem,2.5vw,1.375rem);--fs-xl:clamp(1.75rem,3vw,2rem);}' +
    '@media(prefers-color-scheme:dark){:root{--base:#111111;--contrast:#FFFFFF;--accent-4:#aaaaaa;}}' +
    '*,::after,::before{box-sizing:border-box}html{font-size:16px}' +
    'body{margin:0;background:var(--base);color:var(--contrast);font-family:"Manrope",-apple-system,sans-serif;font-size:var(--fs-lg);font-weight:300;line-height:1.4;letter-spacing:-0.1px}' +
    'a{color:inherit;text-underline-offset:.1em}a:hover{opacity:.7}' +
    '.wp-site-blocks{display:flex;flex-direction:column;min-height:100vh}' +
    '.site-header{background:var(--base);border-bottom:1px solid rgba(0,0,0,.08);position:sticky;top:0;z-index:100}' +
    '.h-inner{max-width:1340px;margin:0 auto;padding:var(--sp-30) var(--sp-50);display:flex;align-items:center;justify-content:space-between}' +
    '.site-title{margin:0;font-size:var(--fs-lg);font-weight:700;letter-spacing:-.5px}' +
    '.site-title a{text-decoration:none;color:var(--contrast)}' +
    '.site-nav{list-style:none;margin:0;padding:0;display:flex;gap:var(--sp-40)}' +
    '.site-nav a{font-size:var(--fs-sm);text-decoration:none;font-weight:400}' +
    '.site-content{flex:1;max-width:780px;margin:0 auto;padding:var(--sp-60) var(--sp-50);width:100%}' +
    '.wp-block-post{padding:var(--sp-50) 0;border-top:1px solid rgba(0,0,0,.08)}' +
    '.wp-block-post:first-child{border-top:none}' +
    '.wp-block-post-date{font-size:var(--fs-sm);color:var(--accent-4);margin-bottom:8px}' +
    '.wp-block-post-title{margin:0 0 10px;font-size:var(--fs-xl);font-weight:300;line-height:1.2}' +
    '.wp-block-post-title a{text-decoration:none;color:var(--contrast)}' +
    '.wp-block-post-excerpt__excerpt{font-size:var(--fs-md);color:var(--accent-4);line-height:1.6;margin:0}' +
    '.site-footer{background:var(--contrast);color:var(--base);padding:var(--sp-60) var(--sp-50);text-align:center}' +
    '.footer-title{display:block;font-size:var(--fs-xl);font-weight:400;text-transform:uppercase;letter-spacing:.05em;margin-bottom:10px;color:var(--base);text-decoration:none}' +
    '.footer-info{font-size:var(--fs-sm);opacity:.5}' +
    '</style></head>' +
    '<body class="wp-site-blocks home blog">' +
    '<header class="site-header"><div class="h-inner">' +
    '<p class="site-title"><a href="' + SITE_URL + '/" rel="home">' + SITE_NAME + '</a></p>' +
    '<nav><ul class="site-nav"><li><a href="' + SITE_URL + '/wp-admin/">관리자</a></li><li><a href="' + SITE_URL + '/wp-login.php">로그인</a></li></ul></nav>' +
    '</div></header>' +
    '<div class="site-content"><main>' + postsHtml + '</main></div>' +
    '<footer class="site-footer">' +
    '<a href="' + SITE_URL + '/" class="footer-title">' + SITE_NAME + '</a>' +
    '<div class="footer-info">WordPress로 제작 &nbsp;|&nbsp; Powered by CloudPress</div>' +
    '</footer>' +
    '<script>document.documentElement.className=document.documentElement.className.replace("no-js","js");</script>' +
    '</body></html>';}

async function handleRestAPI(env, request, url) {
  const path = url.pathname.replace('/wp-json', '');
  const headers = { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' };
  if (path.match(/^\\/wp\\/v2\\/posts\\/?$/)) {
    try {
      const res = await env.DB.prepare('SELECT ID, post_title, post_content, post_excerpt, post_date, post_name, post_status, post_type FROM wp_posts WHERE post_type=\\'post\\' AND post_status=\\'publish\\' ORDER BY post_date DESC LIMIT 10').all();
      return new Response(JSON.stringify((res.results||[]).map(p => ({ id: p.ID, title: { rendered: p.post_title }, content: { rendered: p.post_content }, excerpt: { rendered: p.post_excerpt }, slug: p.post_name, date: p.post_date, status: p.post_status }))), { headers });
    } catch { return new Response('[]', { headers }); }
  }
  return new Response(JSON.stringify({ code: 'rest_no_route', message: 'No route' }), { status: 404, headers });
}
`.trim();
}

// ── CF DNS / Route / Custom Domain ───────────────────────────────────────────
async function cfGetZone(auth, domain) {
  const root = domain.split('.').slice(-2).join('.');
  const res  = await cfReq(auth, `/zones?name=${encodeURIComponent(root)}&status=active`);
  if (res.success && res.result?.length > 0) {
    return { ok: true, zoneId: res.result[0].id };
  }
  return { ok: false, error: '존 없음: ' + root };
}

async function cfUpsertDns(auth, zoneId, type, name, content, proxied = true) {
  const list = await cfReq(auth, `/zones/${zoneId}/dns_records?type=${type}&name=${encodeURIComponent(name)}`);
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
  const list = await cfReq(auth, `/zones/${zoneId}/workers/routes`);
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
  if (res.success && res.result?.subdomain) {
    return `${workerName}.${res.result.subdomain}.workers.dev`;
  }
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
    const projRes = await cfReq(auth, `/accounts/${accountId}/pages/projects/${project.name}`);
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
  } catch (e) {
    console.warn('[provision] 바인딩 ID 자동 탐색 실패:', e.message);
  }
  return result;
}

// ── 설치 잠금 확인 ────────────────────────────────────────────────────────────
async function checkInstallLock(env, siteId) {
  try {
    const lock = await env.DB.prepare(
      `SELECT s.wp_installed FROM sites s WHERE s.id = ? LIMIT 1`
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

  // ── [설치 잠금] 이미 설치된 사이트는 재설치 차단 ─────────────────────────
  const alreadyInstalled = await checkInstallLock(env, siteId);
  if (alreadyInstalled) {
    return ok({ message: '이미 설치된 사이트입니다. 재설치는 지원되지 않습니다.', installed: true });
  }

  // ── 데이터 조회 ──────────────────────────────────────────────────────────
  let site, settings;
  try {
    const [siteRow, settingsRows] = await env.DB.batch([
      env.DB.prepare(
        'SELECT s.id, s.user_id, s.name, s.primary_domain, s.site_prefix,'
        + ' s.status, s.provision_step, s.plan,'
        + ' s.site_d1_id, s.site_kv_id,'
        + ' s.supabase_url, s.supabase_key, s.supabase_url2, s.supabase_key2,'
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
  if (site.status === 'active') {
    return ok({ message: '이미 완료된 사이트입니다.', installed: true });
  }

  // 프로비저닝 시작
  try {
    await env.DB.prepare(
      "UPDATE sites SET status='provisioning', provision_step='starting', error_message=NULL, updated_at=datetime('now') WHERE id=?"
    ).bind(siteId).run();
  } catch (e) { console.error('initial status update err:', e.message); }

  const siteState = makeSiteState();
  const encKey = env?.ENCRYPTION_KEY || 'cp_enc_default';

  // CF 인증
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

  const domain    = site.primary_domain;
  const wwwDomain = 'www.' + domain;
  const prefix    = site.site_prefix;
  const workerName = 'cloudpress-site-' + prefix;
  const siteUrl    = 'https://' + domain;

  // ── Step 1: Supabase 계정 + 스토리지 2개 생성 ───────────────────────────
  siteState.set({ provision_step: 'supabase_setup' });
  console.log('[provision] Supabase 설정 시작...');

  let supabaseUrl  = site.supabase_url  || '';
  let supabaseKey  = site.supabase_key  || '';
  let supabaseUrl2 = site.supabase_url2 || '';
  let supabaseKey2 = site.supabase_key2 || '';
  let storageBucket  = 'media';
  let storageBucket2 = 'media-backup';

  const supabaseToken  = settingVal(settings, 'supabase_mgmt_token');
  const supabaseOrgId  = settingVal(settings, 'supabase_org_id');

  // Supabase 관리 API 토큰이 있으면 자동 생성
  if (supabaseToken && supabaseOrgId && !supabaseUrl) {
    console.log('[provision] Supabase 프로젝트 자동 생성...');

    const projectName1 = `cp-${prefix}-primary`;
    const projectName2 = `cp-${prefix}-backup`;
    const dbPass1 = genPassword(20);
    const dbPass2 = genPassword(20);

    // Primary 프로젝트 생성
    const [proj1, proj2] = await Promise.all([
      createSupabaseProject(supabaseToken, supabaseOrgId, projectName1, dbPass1),
      createSupabaseProject(supabaseToken, supabaseOrgId, projectName2, dbPass2),
    ]);

    if (proj1.ok) {
      supabaseUrl = proj1.url;
      supabaseKey = proj1.serviceRoleKey;
      console.log(`[provision] Supabase Primary 생성: ${supabaseUrl}`);

      // 버킷 생성 (프로젝트 준비까지 잠시 대기)
      await new Promise(r => setTimeout(r, 5000));
      const [b1, b2] = await Promise.all([
        createSupabaseBucket(supabaseUrl, supabaseKey, storageBucket),
        createSupabaseBucket(supabaseUrl, supabaseKey, 'thumbnails'),
      ]);
      if (b1.ok) await setSupabaseBucketPublicPolicy(supabaseUrl, supabaseKey, storageBucket);
      if (!b1.ok) console.warn('[provision] Primary 버킷 생성 실패:', b1.error);
    }

    if (proj2.ok) {
      supabaseUrl2 = proj2.url;
      supabaseKey2 = proj2.serviceRoleKey;
      console.log(`[provision] Supabase Secondary 생성: ${supabaseUrl2}`);

      await new Promise(r => setTimeout(r, 3000));
      const b3 = await createSupabaseBucket(supabaseUrl2, supabaseKey2, storageBucket2);
      if (b3.ok) await setSupabaseBucketPublicPolicy(supabaseUrl2, supabaseKey2, storageBucket2);
    }

    siteState.set({
      supabase_url: supabaseUrl, supabase_key: supabaseKey,
      supabase_url2: supabaseUrl2, supabase_key2: supabaseKey2,
      storage_bucket: storageBucket, storage_bucket2: storageBucket2,
    });
  } else if (supabaseUrl && !supabaseUrl2) {
    // Primary만 있는 경우: 버킷 2개 생성
    console.log('[provision] 기존 Supabase에 Secondary 버킷 생성...');
    const [b1, b2] = await Promise.all([
      createSupabaseBucket(supabaseUrl, supabaseKey, storageBucket),
      createSupabaseBucket(supabaseUrl, supabaseKey, storageBucket2),
    ]);
    console.log('[provision] 버킷 생성:', b1.ok ? '✓' : b1.error, b2.ok ? '✓' : b2.error);
  } else if (!supabaseUrl) {
    // Supabase 없음 → D1 + KV 스토리지 모드로 계속
    console.log('[provision] Supabase 미설정 — D1+KV 스토리지 모드로 진행');
  }

  // ── Step 2: D1 + KV 생성 ────────────────────────────────────────────────
  siteState.set({ provision_step: 'd1_kv_create' });

  let d1Id = site.site_d1_id || null;
  let kvId = site.site_kv_id || null;

  if (!d1Id && !kvId) {
    const [d1Res, kvRes] = await Promise.all([
      createD1(cfAuth, cfAccount, prefix),
      createKV(cfAuth, cfAccount, prefix),
    ]);
    if (!d1Res.ok) { await failSite(env.DB, siteId, 'd1_create', d1Res.error); return err(d1Res.error, 500); }
    if (!kvRes.ok) { await failSite(env.DB, siteId, 'kv_create', kvRes.error); return err(kvRes.error, 500); }
    d1Id = d1Res.id; kvId = kvRes.id;
    siteState.set({ site_d1_id: d1Id, site_d1_name: d1Res.name, site_kv_id: kvId, site_kv_title: kvRes.title });
    console.log(`[provision] D1: ${d1Res.name} (${d1Id}), KV: ${kvRes.title} (${kvId})`);
  } else if (!d1Id) {
    const d1Res = await createD1(cfAuth, cfAccount, prefix);
    if (!d1Res.ok) { await failSite(env.DB, siteId, 'd1_create', d1Res.error); return err(d1Res.error, 500); }
    d1Id = d1Res.id;
    siteState.set({ site_d1_id: d1Id, site_d1_name: d1Res.name });
  } else if (!kvId) {
    const kvRes = await createKV(cfAuth, cfAccount, prefix);
    if (!kvRes.ok) { await failSite(env.DB, siteId, 'kv_create', kvRes.error); return err(kvRes.error, 500); }
    kvId = kvRes.id;
    siteState.set({ site_kv_id: kvId, site_kv_title: kvRes.title });
  }

  // ── Step 3: WordPress D1 스키마 초기화 ──────────────────────────────────
  siteState.set({ provision_step: 'd1_schema' });
  console.log('[provision] WordPress D1 스키마 초기화...');

  let mainDbId     = settingVal(settings, 'main_db_id',     '');
  let cacheKvId    = settingVal(settings, 'cache_kv_id',    '');
  let sessionsKvId = settingVal(settings, 'sessions_kv_id', '');

  const [schemaRes, resolvedIds] = await Promise.all([
    initWordPressD1Schema(cfAuth, cfAccount, d1Id, {
      siteName: site.name, siteUrl, adminEmail: site.email || user.email,
    }),
    (!mainDbId || !cacheKvId || !sessionsKvId)
      ? resolveMainBindingIds(cfAuth, cfAccount)
      : Promise.resolve(null),
  ]);

  if (!schemaRes.ok) {
    console.warn('[provision] D1 스키마 초기화 부분 실패 (계속 진행)');
  }

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

  // ── Step 4: WordPress Worker 업로드 ─────────────────────────────────────
  siteState.set({ provision_step: 'worker_upload' });
  console.log(`[provision] WordPress Worker 업로드: ${workerName}`);

  const cfApiTokenForWorker = cfAuth.email ? '' : cfAuth.token;

  const upRes = await uploadWordPressWorker(cfAuth, cfAccount, workerName, {
    mainDbId, cacheKvId, sessionsKvId,
    siteD1Id:       d1Id,
    siteKvId:       kvId,
    cfAccountId:    cfAccount,
    cfApiToken:     cfApiTokenForWorker,
    sitePrefix:     prefix,
    siteName:       site.name,
    siteDomain:     domain,
    supabaseUrl, supabaseKey, supabaseUrl2, supabaseKey2,
    storageBucket, storageBucket2,
    // WORKER_SOURCE: 환경변수로 실제 worker.js 소스를 주입 가능
    // wrangler secret put WORKER_SOURCE < worker.js 로 배포 시 사용
    workerSourceEnv: (env.WORKER_SOURCE && env.WORKER_SOURCE.length > 500) ? env.WORKER_SOURCE : '',
    cacheKv:        cacheKvId,
    cfAuth,
    cfAccountId:    cfAccount,
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
    site_prefix: prefix,
    site_d1_id: d1Id, site_kv_id: kvId,
    supabase_url: supabaseUrl, supabase_key: supabaseKey,
    supabase_url2: supabaseUrl2, supabase_key2: supabaseKey2,
    storage_bucket: storageBucket, storage_bucket2: storageBucket2,
    status: 'active', suspended: 0,
  });

  if (cacheKvId && cfAccount) {
    await putCacheKVBulk(cfAuth, cfAccount, cacheKvId, [
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
        worker_route: domain + '/*', worker_route_www: wwwDomain + '/*',
        worker_route_id: routeId || null, worker_route_www_id: routeWwwId || null,
        cf_zone_id: cfZoneId,
      });

      const [dr, drw] = await Promise.all([
        cfUpsertDns(cfAuth, cfZoneId, 'CNAME', domain,    cnameTarget, true),
        cfUpsertDns(cfAuth, cfZoneId, 'CNAME', wwwDomain, cnameTarget, true),
      ]);
      if (dr.ok)  dnsRecordId    = dr.recordId;
      if (drw.ok) dnsRecordWwwId = drw.recordId;

      if ((rr.ok || rw.ok) && (dr.ok || drw.ok)) domainStatus = 'active';
      else if (rr.ok || rw.ok) domainStatus = 'dns_propagating';

      siteState.set({ dns_record_id: dnsRecordId || null, dns_record_www_id: dnsRecordWwwId || null });
    }
  }

  // ── Step 7: 완료 ─────────────────────────────────────────────────────────
  const adminUrl   = `https://${domain}/wp-admin/`;
  const workerDevUrl = cnameTarget || `${workerName}.workers.dev`;

  siteState.set({
    status: 'active',
    provision_step: 'completed',
    domain_status: domainStatus,
    wp_admin_url: adminUrl,
    wp_installed: 1,   // 설치 잠금
    error_message: domainStatus === 'manual_required'
      ? `외부 DNS 설정 필요 — CNAME ${domain} → ${workerDevUrl}`
      : null,
  });

  await flushSiteState(env.DB, siteId, siteState.get());

  const finalSite = await env.DB.prepare(
    'SELECT status, provision_step, error_message, wp_admin_url, primary_domain,'
    + ' site_d1_id, site_kv_id, domain_status, worker_name, name, supabase_url, supabase_url2 FROM sites WHERE id=?'
  ).bind(siteId).first();

  return ok({
    message: 'WordPress 프로비저닝 완료',
    siteId,
    site: finalSite,
    worker_name: workerName,
    cname_target: cnameTarget,
    wp_admin_url: adminUrl,
    storage: {
      primary: supabaseUrl ? { url: supabaseUrl, bucket: storageBucket } : null,
      secondary: supabaseUrl2 ? { url: supabaseUrl2, bucket: storageBucket2 } : null,
      fallback: 'd1+kv',
    },
    install_locked: true,
    cname_instructions: domainStatus === 'manual_required' ? {
      type: 'CNAME',
      root: { host: '@',   value: workerDevUrl },
      www:  { host: 'www', value: workerDevUrl },
      note: `DNS 전파 후 ${adminUrl} 에서 WordPress를 사용하세요.`,
    } : null,
  });
}
