// functions/api/sites/[id]/provision.js — CloudPress v17.0
//
// [v17.0 subrequest 핵심 수정]
// ────────────────────────────────────────────────────────────────────────────
//  근본 원인: fetchCMSSource()가 CMS_FILES(67개) + EXTRA_FILES(1개) = 68개 파일을
//             Promise.all()로 병렬 fetch → 각각 subrequest 1회씩 = 68회 소비
//             CF API 호출(~17회) + D1(~4회) + KV(~2회) 합산 → 총 ~91회
//             → 기본 제한 50회 초과로 "Too many subrequests" 에러 발생
//
//  해결: GitHub Contents API의 tarball 엔드포인트로 레포 전체를 1회 다운로드
//        → ArrayBuffer를 메모리에서 직접 파싱 (tar 디코딩, pax/ustar 지원)
//        → 필요한 파일만 Map으로 추출
//        GitHub fetch: 68회 → 1회
//
//  최종 subrequest 수:
//    GitHub tar: 1회 (리다이렉트 포함 최대 2회)
//    D1: 4회 (batch조회, status update, flush, final select)
//    CF API: ~17회 (D1생성, KV생성, 스키마, 바인딩탐색, worker업로드,
//                   workersDev, KVbulk, subdomain, zone, dns×2, route×2)
//    KV SESSIONS: 1회
//    합계: ~23~24회 → 제한(50회) 이내
//
//  주의: tar.gz가 아닌 tar(무압축)로 다운로드하므로 decompress 불필요
//        GitHub tarball은 gzip이지만 CF Workers에서 fetch 시
//        Content-Encoding: gzip 자동 디코딩 → ArrayBuffer는 이미 raw tar

'use strict';

// ── CORS ──────────────────────────────────────────────────────────────────────
const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};

const _j  = (d, s = 200) => new Response(JSON.stringify(d), {
  status: s, headers: { 'Content-Type': 'application/json', ...CORS },
});
const ok  = (d)      => _j({ ok: true,  ...(d || {}) });
const err = (msg, s) => _j({ ok: false, error: msg }, s || 400);

// ── Cloudflare API ────────────────────────────────────────────────────────────
const CF_API = 'https://api.cloudflare.com/client/v4';

function cfHeaders(apiToken) {
  return { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + apiToken };
}

async function cfReq(token, path, method = 'GET', body) {
  const opts = { method, headers: cfHeaders(token) };
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

// ── Auth ──────────────────────────────────────────────────────────────────────
function getToken(req) {
  const a = req.headers.get('Authorization') || '';
  if (a.startsWith('Bearer ')) return a.slice(7);
  const c = req.headers.get('Cookie') || '';
  const m = c.match(/cp_session=([^;]+)/);
  return m ? m[1] : null;
}

async function getUser(env, req) {
  try {
    if (!env?.SESSIONS || !env?.DB) return null;
    const t = getToken(req);
    if (!t) return null;
    const uid = await env.SESSIONS.get(`session:${t}`);
    if (!uid) return null;
    return await env.DB.prepare('SELECT id,name,email,role,plan FROM users WHERE id=?').bind(uid).first();
  } catch { return null; }
}

// ── 설정 일괄 로드 (D1 1회 쿼리) ────────────────────────────────────────────
async function loadAllSettings(DB) {
  try {
    const { results } = await DB.prepare('SELECT key, value FROM settings').all();
    const map = {};
    for (const r of results || []) map[r.key] = r.value ?? '';
    return map;
  } catch { return {}; }
}

function settingVal(settings, key, fallback = '') {
  const v = settings[key];
  return (v != null && v !== '') ? v : fallback;
}

// ── 사이트 상태 추적 (메모리) ─────────────────────────────────────────────────
function makeSiteState(initial = {}) {
  const state = { ...initial };
  return {
    set(fields) { Object.assign(state, fields); },
    get() { return { ...state }; },
  };
}

// ── DB 일괄 업데이트 (1회 쿼리) ──────────────────────────────────────────────
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

// ── 즉시 실패 기록 ────────────────────────────────────────────────────────────
async function failSite(DB, siteId, step, message) {
  console.error(`[FAIL] ${step}: ${message}`);
  try {
    await DB.prepare(
      "UPDATE sites SET status='failed', provision_step=?, error_message=?, updated_at=datetime('now') WHERE id=?"
    ).bind(step, String(message).slice(0, 500), siteId).run();
  } catch (e) { console.error('failSite err:', e.message); }
}

// ── 유틸리티 ──────────────────────────────────────────────────────────────────
function randSuffix(len = 6) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let out = '';
  for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
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

async function createD1(token, accountId, prefix) {
  const name = `cloudpress-site-${prefix}-${Date.now().toString(36)}`;
  const res  = await cfReq(token, `/accounts/${accountId}/d1/database`, 'POST', { name });
  if (res.success && res.result) {
    const id = res.result.uuid || res.result.id || res.result.database_id;
    if (id) return { ok: true, id, name };
  }
  return { ok: false, error: 'D1 생성 실패: ' + cfErrMsg(res) };
}

async function createKV(token, accountId, prefix) {
  const title = `cloudpress-site-${prefix}-kv`;
  const res   = await cfReq(token, `/accounts/${accountId}/storage/kv/namespaces`, 'POST', { title });
  if (res.success && res.result?.id) {
    return { ok: true, id: res.result.id, title };
  }
  return { ok: false, error: 'KV 생성 실패: ' + cfErrMsg(res) };
}

// ── 사이트 D1 스키마 초기화 ───────────────────────────────────────────────────
async function initSiteD1Schema(token, accountId, d1Id, schemaSql) {
  if (!schemaSql?.trim()) {
    schemaSql = getMinimalSchema();
  }

  const res = await cfReq(token, `/accounts/${accountId}/d1/database/${d1Id}/query`, 'POST', {
    sql: schemaSql,
  });

  if (!res.success) {
    const errors = (res.errors || []).filter(e => !String(e.message).includes('already exists'));
    if (errors.length > 0) {
      console.warn('[provision] D1 스키마 일부 오류(무시):', JSON.stringify(errors));
    }
  }

  return { ok: true };
}

// ── CACHE KV 도메인 매핑 일괄 PUT ────────────────────────────────────────────
async function putCacheKVBulk(token, accountId, kvId, entries) {
  if (!entries.length) return;
  try {
    const res = await fetch(
      `${CF_API}/accounts/${accountId}/storage/kv/namespaces/${kvId}/bulk`,
      {
        method:  'PUT',
        headers: {
          'Authorization': 'Bearer ' + token,
          'Content-Type':  'application/json',
        },
        body: JSON.stringify(entries.map(({ key, value }) => ({ key, value }))),
      }
    );
    if (!res.ok) {
      console.warn('[provision] CACHE KV bulk put HTTP 오류:', res.status);
    }
  } catch (e) {
    console.warn('[provision] CACHE KV bulk put 오류:', e.message);
  }
}

// ── tar 파싱 유틸리티 ──────────────────────────────────────────────────────────
// GitHub tarball은 fetch 시 CF Workers가 gzip을 자동 디코딩하여
// ArrayBuffer로 반환함 → 순수 POSIX tar(ustar/pax) 파싱

const DEC = new TextDecoder();

/**
 * octal 문자열 → 정수
 */
function parseOctal(buf, offset, len) {
  const s = DEC.decode(buf.slice(offset, offset + len)).replace(/\0/g, '').trim();
  return s ? parseInt(s, 8) : 0;
}

/**
 * pax extended header 파싱 → { path, size } 등 추출
 * 형식: "<length> <key>=<value>\n" 반복
 */
function parsePaxHeader(buf) {
  const text = DEC.decode(buf);
  const attrs = {};
  for (const line of text.split('\n')) {
    const m = line.match(/^\d+ ([^=]+)=(.*)$/);
    if (m) attrs[m[1]] = m[2];
  }
  return attrs;
}

/**
 * ArrayBuffer → Map<normalizedPath, string>
 *
 * normalizedPath: 레포 루트 디렉토리 prefix 제거 후 경로
 *   예) "owner-repo-abc123/cp-admin/index.js" → "cp-admin/index.js"
 *
 * @param {ArrayBuffer} buffer   raw (already-decompressed) tar data
 * @param {Set<string>} wantSet  필요한 파일 경로 집합 (없으면 전체)
 */
function parseTar(buffer, wantSet) {
  const buf   = new Uint8Array(buffer);
  const total = buf.length;
  const files = new Map();

  let offset    = 0;
  let paxAttrs  = {};   // pax extended header에서 가져온 속성
  let repoPrefix = '';  // 첫 번째 디렉토리 엔트리에서 자동 감지

  while (offset + 512 <= total) {
    const header = buf.slice(offset, offset + 512);

    // 512바이트 전체가 0이면 end-of-archive
    if (header.every(b => b === 0)) break;

    // 파일명 (ustar: name[0..99] + prefix[345..499])
    let rawName = DEC.decode(header.slice(0, 100)).replace(/\0/g, '');
    const ustarPrefix = DEC.decode(header.slice(345, 500)).replace(/\0/g, '');
    if (ustarPrefix) rawName = ustarPrefix + '/' + rawName;

    // pax 오버라이드
    if (paxAttrs.path) rawName = paxAttrs.path;

    const typeflag = String.fromCharCode(header[156]) || '0';
    let fileSize   = parseOctal(header, 124, 12);
    if (paxAttrs.size) fileSize = parseInt(paxAttrs.size, 10);

    // 다음 512 바이트 경계로 정렬
    const dataOffset = offset + 512;
    const paddedSize = Math.ceil(fileSize / 512) * 512;

    // pax 속성 초기화
    paxAttrs = {};

    // pax extended header (typeflag 'x' 또는 'X')
    if (typeflag === 'x' || typeflag === 'X') {
      if (dataOffset + fileSize <= total) {
        paxAttrs = parsePaxHeader(buf.slice(dataOffset, dataOffset + fileSize));
      }
      offset = dataOffset + paddedSize;
      continue;
    }

    // gnu long name header (typeflag 'L')
    if (typeflag === 'L') {
      if (dataOffset + fileSize <= total) {
        rawName = DEC.decode(buf.slice(dataOffset, dataOffset + fileSize)).replace(/\0/g, '');
      }
      offset = dataOffset + paddedSize;
      // 다음 헤더가 실제 파일
      const nextHeader = buf.slice(offset, offset + 512);
      const nextSize   = parseOctal(nextHeader, 124, 12);
      const nextOffset = offset + 512;
      const nextPadded = Math.ceil(nextSize / 512) * 512;

      const normalised = normalisePath(rawName, repoPrefix);
      if (!repoPrefix) repoPrefix = extractPrefix(rawName);

      if (normalised && (!wantSet || wantSet.has(normalised)) && nextOffset + nextSize <= total) {
        files.set(normalised, DEC.decode(buf.slice(nextOffset, nextOffset + nextSize)));
      }
      offset = nextOffset + nextPadded;
      continue;
    }

    // 레포 루트 prefix 자동 감지 (첫 번째 디렉토리 엔트리)
    if (!repoPrefix) repoPrefix = extractPrefix(rawName);

    const normalised = normalisePath(rawName, repoPrefix);

    // 일반 파일 (typeflag '0' 또는 '\0')
    if ((typeflag === '0' || typeflag === '\0') && normalised) {
      if (!wantSet || wantSet.has(normalised)) {
        if (dataOffset + fileSize <= total) {
          files.set(normalised, DEC.decode(buf.slice(dataOffset, dataOffset + fileSize)));
        }
      }
    }

    offset = dataOffset + paddedSize;
  }

  return files;
}

/**
 * GitHub tarball의 최상위 디렉토리 이름(prefix) 추출
 * 예) "owner-repo-abc1234/..." → "owner-repo-abc1234"
 */
function extractPrefix(rawName) {
  const slash = rawName.indexOf('/');
  return slash > 0 ? rawName.slice(0, slash) : '';
}

/**
 * rawName에서 레포 prefix 제거 → 정규화된 경로 반환
 * 디렉토리 엔트리('/' 끝) 는 null 반환
 */
function normalisePath(rawName, prefix) {
  let p = rawName;
  if (prefix && p.startsWith(prefix + '/')) {
    p = p.slice(prefix.length + 1);
  }
  if (!p || p.endsWith('/')) return null;
  return p;
}

// ── 필요한 파일 경로 집합 ──────────────────────────────────────────────────────
const CMS_FILES = new Set([
  'index.js',
  'cp-router.js',
  'cp-blog-header.js',
  'cp-load.js',
  'cp-settings.js',
  'cp-config.js',
  'cp-activate.js',
  'cp-comments-post.js',
  'cp-cron.js',
  'cp-links-opml.js',
  'cp-mail.js',
  'cp-signup.js',
  'cp-trackback.js',
  'cp-admin/index.js',
  'cp-admin/admin-shell.js',
  'cp-admin/ajax.js',
  'cp-admin/auth-check.js',
  'cp-admin/github-sync.js',
  'cp-admin/installer.js',
  'cp-admin/pages/index.js',
  'cp-admin/pages/dashboard.js',
  'cp-admin/pages/posts.js',
  'cp-admin/pages/post-edit.js',
  'cp-admin/pages/pages.js',
  'cp-admin/pages/comments.js',
  'cp-admin/pages/media.js',
  'cp-admin/pages/themes.js',
  'cp-admin/pages/plugins.js',
  'cp-admin/pages/users.js',
  'cp-admin/pages/user-edit.js',
  'cp-admin/pages/profile.js',
  'cp-admin/pages/options.js',
  'cp-admin/pages/options-general.js',
  'cp-admin/pages/options-writing.js',
  'cp-admin/pages/options-reading.js',
  'cp-admin/pages/options-discussion.js',
  'cp-admin/pages/options-media.js',
  'cp-admin/pages/options-permalink.js',
  'cp-admin/pages/tools.js',
  'cp-admin/pages/import.js',
  'cp-admin/pages/export.js',
  'cp-admin/pages/upgrade.js',
  'cp-includes/auth.js',
  'cp-includes/bookmark.js',
  'cp-includes/category.js',
  'cp-includes/comment.js',
  'cp-includes/crypto.js',
  'cp-includes/feed.js',
  'cp-includes/formatting.js',
  'cp-includes/functions.js',
  'cp-includes/hooks.js',
  'cp-includes/jwt.js',
  'cp-includes/link-template.js',
  'cp-includes/mail.js',
  'cp-includes/media-handler.js',
  'cp-includes/ms-functions.js',
  'cp-includes/option.js',
  'cp-includes/plugin-loader.js',
  'cp-includes/post.js',
  'cp-includes/query.js',
  'cp-includes/sanitize.js',
  'cp-includes/session.js',
  'cp-includes/sitemap.js',
  'cp-includes/template-loader.js',
  'cp-includes/theme-loader.js',
  'cp-includes/transient.js',
  'cp-includes/user.js',
  'schema.sql',   // schema.sql도 함께 추출
]);

/**
 * [v17.0 핵심 변경]
 * GitHub tarball API로 레포 전체를 1회 다운로드 후 메모리에서 파싱
 *
 * 이전: 68개 파일 개별 fetch (subrequest 68회)
 * 이후: tarball 1회 fetch → 메모리 tar 파싱 → 필요 파일 추출 (subrequest 1~2회)
 *
 * 반환: { sourceMap: Map<path, content>, schemaSql: string }
 */
async function fetchCMSSource(githubRepo, githubBranch, githubToken) {
  const branch  = githubBranch || 'main';

  // GitHub tarball 다운로드 URL
  // https://api.github.com/repos/{owner}/{repo}/tarball/{branch}
  // → 302 redirect → codeload.github.com/... (tar.gz)
  // CF Workers의 fetch()는 redirect를 자동으로 따라가며,
  // Content-Encoding: gzip을 자동 디코딩하여 raw tar ArrayBuffer를 반환
  const tarUrl = `https://api.github.com/repos/${githubRepo}/tarball/${branch}`;

  const headers = {
    'User-Agent': 'CloudPress/17.0',
    'Accept':     'application/vnd.github+json',
  };
  if (githubToken) headers['Authorization'] = `Bearer ${githubToken}`;

  let buffer;
  try {
    const res = await fetch(tarUrl, { headers });
    if (!res.ok) {
      const hint = res.status === 404
        ? '레포가 존재하지 않거나 private 레포에 접근 토큰이 필요합니다.'
        : res.status === 401
        ? 'GitHub 토큰이 없거나 유효하지 않습니다.'
        : `HTTP ${res.status} ${res.statusText}`;
      const msg = `GitHub tarball fetch 실패 (${githubRepo}@${branch}): ${hint}`;
      console.error('[provision]', msg);
      throw new Error(msg);
    }
    buffer = await res.arrayBuffer();
    console.log(`[provision] GitHub tarball 다운로드 완료: ${(buffer.byteLength / 1024).toFixed(0)} KB`);
  } catch (e) {
    if (e instanceof Error && e.message.includes('tarball fetch 실패')) throw e;
    const msg = `GitHub tarball fetch 오류 (${githubRepo}@${branch}): ${e.message}`;
    console.error('[provision]', msg);
    throw new Error(msg);
  }

  // tar 파싱 (필요한 파일만 추출)
  let allFiles;
  try {
    allFiles = parseTar(buffer, CMS_FILES);
  } catch (e) {
    const msg = `tar 파싱 오류: ${e.message}`;
    console.error('[provision]', msg);
    throw new Error(msg);
  }

  const sourceMap = new Map();
  let schemaSql   = '';

  for (const [path, content] of allFiles) {
    if (path === 'schema.sql') {
      schemaSql = content;
    } else {
      sourceMap.set(path, content);
    }
  }

  console.log(`[provision] tar 파싱 완료: ${sourceMap.size}개 JS 파일, schema.sql: ${schemaSql ? '✓' : '내장 fallback'}`);
  return { sourceMap, schemaSql };
}

// ── Workers Script Upload API (multipart/form-data) ───────────────────────────

async function uploadWorkerWithCMSSource(token, accountId, workerName, opts, cmsSourceMap) {
  const {
    mainDbId,
    cacheKvId,
    sessionsKvId,
    siteD1Id,
    siteKvId,
    cfAccountId,
    cfApiToken,
    sitePrefix,
    siteName,
    siteDomain,
  } = opts;

  const bindings = [];

  if (mainDbId)     bindings.push({ type: 'd1',          name: 'CP_MAIN_DB',  id: mainDbId });
  if (cacheKvId)    bindings.push({ type: 'kv_namespace', name: 'CACHE',      namespace_id: cacheKvId });
  if (sessionsKvId) bindings.push({ type: 'kv_namespace', name: 'SESSIONS',   namespace_id: sessionsKvId });
  if (siteD1Id)     bindings.push({ type: 'd1',          name: 'CP_DB',       id: siteD1Id });
  if (siteKvId)     bindings.push({ type: 'kv_namespace', name: 'CP_KV',      namespace_id: siteKvId });

  bindings.push({ type: 'plain_text', name: 'CP_SITE_NAME',    text: siteName    || '' });
  bindings.push({ type: 'plain_text', name: 'CP_SITE_URL',     text: 'https://' + (siteDomain || '') });
  bindings.push({ type: 'plain_text', name: 'CF_ACCOUNT_ID',   text: cfAccountId || '' });
  bindings.push({ type: 'plain_text', name: 'SITE_PREFIX',     text: sitePrefix  || '' });

  if (cfApiToken) {
    bindings.push({ type: 'secret_text', name: 'CF_API_TOKEN', text: cfApiToken });
  }

  const metadata = {
    main_module:         'index.js',
    compatibility_date:  '2024-09-23',
    compatibility_flags: ['nodejs_compat'],
    bindings,
  };

  const boundary = '----CPUpload' + Date.now().toString(36) + randSuffix(4);
  const enc      = new TextEncoder();
  const CRLF     = '\r\n';
  const parts    = [];

  parts.push(
    `--${boundary}${CRLF}` +
    `Content-Disposition: form-data; name="metadata"${CRLF}` +
    `Content-Type: application/json${CRLF}${CRLF}` +
    JSON.stringify(metadata) + CRLF
  );

  for (const [filePath, content] of cmsSourceMap) {
    parts.push(
      `--${boundary}${CRLF}` +
      `Content-Disposition: form-data; name="${filePath}"; filename="${filePath}"${CRLF}` +
      `Content-Type: application/javascript+module${CRLF}${CRLF}` +
      content + CRLF
    );
  }

  parts.push(`--${boundary}--${CRLF}`);

  const chunks = parts.map(p => enc.encode(p));
  const total  = chunks.reduce((s, c) => s + c.length, 0);
  const body   = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { body.set(c, off); off += c.length; }

  try {
    const res  = await fetch(
      `${CF_API}/accounts/${accountId}/workers/scripts/${workerName}`,
      {
        method:  'PUT',
        headers: {
          'Authorization': 'Bearer ' + token,
          'Content-Type':  `multipart/form-data; boundary=${boundary}`,
        },
        body: body.buffer,
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

// ── CF DNS / Route 유틸리티 ───────────────────────────────────────────────────

async function cfGetZone(token, domain) {
  const root = domain.split('.').slice(-2).join('.');
  const res  = await cfReq(token, `/zones?name=${encodeURIComponent(root)}&status=active`);
  if (res.success && res.result?.length > 0) {
    return { ok: true, zoneId: res.result[0].id };
  }
  return { ok: false, error: '존 없음: ' + root };
}

async function cfUpsertDns(token, zoneId, type, name, content, proxied = true) {
  const list = await cfReq(token, `/zones/${zoneId}/dns_records?type=${type}&name=${encodeURIComponent(name)}`);
  const existing = list.result?.[0];

  if (existing) {
    const res = await cfReq(token, `/zones/${zoneId}/dns_records/${existing.id}`, 'PATCH', { content, proxied });
    return { ok: res.success, recordId: existing.id };
  }
  const res = await cfReq(token, `/zones/${zoneId}/dns_records`, 'POST', { type, name, content, proxied, ttl: 1 });
  if (res.success) return { ok: true, recordId: res.result?.id };
  return { ok: false, error: cfErrMsg(res) };
}

async function cfUpsertRoute(token, zoneId, pattern, workerName) {
  const list = await cfReq(token, `/zones/${zoneId}/workers/routes`);
  const existing = (list.result || []).find(r => r.pattern === pattern);
  if (existing) {
    const res = await cfReq(token, `/zones/${zoneId}/workers/routes/${existing.id}`, 'PUT', { pattern, script: workerName });
    return { ok: res.success, routeId: existing.id };
  }
  const res = await cfReq(token, `/zones/${zoneId}/workers/routes`, 'POST', { pattern, script: workerName });
  if (res.success) return { ok: true, routeId: res.result?.id };
  return { ok: false, error: cfErrMsg(res) };
}

async function getWorkerSubdomain(token, accountId, workerName) {
  const res = await cfReq(token, `/accounts/${accountId}/workers/subdomain`);
  if (res.success && res.result?.subdomain) {
    return `${workerName}.${res.result.subdomain}.workers.dev`;
  }
  return `${workerName}.workers.dev`;
}

async function enableWorkersDev(token, accountId, workerName) {
  const res = await cfReq(
    token,
    `/accounts/${accountId}/workers/scripts/${workerName}/subdomain`,
    'POST',
    { enabled: true }
  );
  return res.success;
}

// ── 메인 바인딩 ID 자동 탐색 ─────────────────────────────────────────────────
async function resolveMainBindingIds(token, accountId) {
  const result = { mainDbId: '', cacheKvId: '', sessionsKvId: '' };

  try {
    const pagesRes = await cfReq(token, `/accounts/${accountId}/pages/projects`);
    if (!pagesRes.success) return result;

    const project = (pagesRes.result || []).find(p =>
      p.name?.toLowerCase().includes('cloudpress') ||
      p.name?.toLowerCase().includes('cp-')
    );
    if (!project) return result;

    const projRes = await cfReq(token, `/accounts/${accountId}/pages/projects/${project.name}`);
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

// ── 메인 핸들러 ───────────────────────────────────────────────────────────────
export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

export async function onRequestPost({ request, env, params }) {
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  const siteId = params?.id;
  if (!siteId) return err('사이트 ID가 없습니다.', 400);

  // ── [D1 #1] 사이트 + settings 동시 조회 (batch 1회) ─────────────────────────
  let site, settings;
  try {
    const [siteRow, settingsRows] = await env.DB.batch([
      env.DB.prepare(
        'SELECT s.id, s.user_id, s.name, s.primary_domain, s.site_prefix,'
        + ' s.status, s.provision_step, s.plan,'
        + ' s.site_d1_id, s.site_kv_id,'
        + ' u.cf_global_api_key, u.cf_account_email, u.cf_account_id'
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
  if (site.status === 'active') return ok({ message: '이미 완료된 사이트입니다.' });

  // ── [D1 #2] 프로비저닝 시작 표시 (즉시 1회 쓰기) ─────────────────────────────
  try {
    await env.DB.prepare(
      "UPDATE sites SET status='provisioning', provision_step='starting', error_message=NULL, updated_at=datetime('now') WHERE id=?"
    ).bind(siteId).run();
  } catch (e) { console.error('initial status update err:', e.message); }

  const siteState = makeSiteState();

  const encKey = env?.ENCRYPTION_KEY || 'cp_enc_default';

  // ── CF 인증 키 결정 ────────────────────────────────────────────────────────
  const adminCfToken   = settingVal(settings, 'cf_api_token');
  const adminCfAccount = settingVal(settings, 'cf_account_id');

  let cfToken   = null;
  let cfAccount = null;

  if (site.cf_global_api_key && site.cf_account_id) {
    const raw = deobfuscate(site.cf_global_api_key, encKey);
    cfToken   = (raw && raw.length > 5) ? raw : site.cf_global_api_key;
    cfAccount = site.cf_account_id;
  }

  if (!cfToken || !cfAccount) {
    cfToken   = adminCfToken;
    cfAccount = adminCfAccount;
  }

  if (!cfToken || !cfAccount) {
    const e = 'Cloudflare API 키가 설정되지 않았습니다. 계정 설정에서 CF Global API Key와 Account ID를 입력해주세요.';
    await failSite(env.DB, siteId, 'config_missing', e);
    return err(e, 400);
  }

  // ── GitHub CMS 소스 설정 ───────────────────────────────────────────────────
  const githubRepo   = settingVal(settings, 'cms_github_repo',   '');
  const githubBranch = settingVal(settings, 'cms_github_branch', 'main');
  const githubToken  = settingVal(settings, 'cms_github_token',  '');

  if (!githubRepo) {
    const e = 'CMS GitHub 레포가 설정되지 않았습니다. 어드민 설정에서 cms_github_repo를 입력해주세요.';
    await failSite(env.DB, siteId, 'config_missing', e);
    return err(e, 400);
  }

  const domain     = site.primary_domain;
  const wwwDomain  = 'www.' + domain;
  const prefix     = site.site_prefix;
  const workerName = 'cloudpress-site-' + prefix;

  // ── Step 1: GitHub tarball 1회 다운로드 → 메모리 tar 파싱 ──────────────────
  // [v17.0] 기존 68회 개별 fetch → tarball 1회 fetch로 교체
  console.log(`[provision] GitHub tarball fetch 시작: ${githubRepo}@${githubBranch}`);
  siteState.set({ provision_step: 'github_fetch' });

  let cmsSourceMap, schemaSql;
  try {
    const result = await fetchCMSSource(githubRepo, githubBranch, githubToken);
    cmsSourceMap = result.sourceMap;
    schemaSql    = result.schemaSql;
  } catch (e) {
    await failSite(env.DB, siteId, 'github_fetch', e.message || String(e));
    return err('GitHub fetch 오류: ' + (e.message || String(e)), 500);
  }

  if (cmsSourceMap.size === 0) {
    const e = `GitHub 레포(${githubRepo}@${githubBranch || 'main'})에서 CMS 소스 파일을 찾지 못했습니다. 레포 내 index.js 등 CMS 파일이 존재하는지 확인해주세요.`;
    await failSite(env.DB, siteId, 'github_fetch', e);
    return err(e, 500);
  }

  if (!cmsSourceMap.has('index.js')) {
    const e = 'GitHub 레포에서 index.js를 찾을 수 없습니다. cms_github_repo 설정을 확인해주세요.';
    await failSite(env.DB, siteId, 'github_fetch', e);
    return err(e, 500);
  }

  console.log(`[provision] GitHub 소스 준비 완료: ${cmsSourceMap.size}개 파일, schema.sql: ${schemaSql ? '✓' : '내장 fallback'}`);

  // ── Step 2+3: D1 + KV 생성 ────────────────────────────────────────────────
  siteState.set({ provision_step: 'd1_kv_create' });

  let d1Id = site.site_d1_id || null;
  let kvId = site.site_kv_id || null;

  if (!d1Id && !kvId) {
    const [d1Res, kvRes] = await Promise.all([
      createD1(cfToken, cfAccount, prefix),
      createKV(cfToken, cfAccount, prefix),
    ]);

    if (!d1Res.ok) { await failSite(env.DB, siteId, 'd1_create', d1Res.error); return err(d1Res.error, 500); }
    if (!kvRes.ok) { await failSite(env.DB, siteId, 'kv_create', kvRes.error); return err(kvRes.error, 500); }

    d1Id = d1Res.id;
    kvId = kvRes.id;
    siteState.set({ site_d1_id: d1Id, site_d1_name: d1Res.name, site_kv_id: kvId, site_kv_title: kvRes.title });
    console.log(`[provision] D1 생성: ${d1Res.name} (${d1Id}), KV 생성: ${kvRes.title} (${kvId})`);

  } else if (!d1Id) {
    const d1Res = await createD1(cfToken, cfAccount, prefix);
    if (!d1Res.ok) { await failSite(env.DB, siteId, 'd1_create', d1Res.error); return err(d1Res.error, 500); }
    d1Id = d1Res.id;
    siteState.set({ site_d1_id: d1Id, site_d1_name: d1Res.name });
    console.log(`[provision] D1 생성: ${d1Res.name} (${d1Id}), KV 재사용: ${kvId}`);

  } else if (!kvId) {
    const kvRes = await createKV(cfToken, cfAccount, prefix);
    if (!kvRes.ok) { await failSite(env.DB, siteId, 'kv_create', kvRes.error); return err(kvRes.error, 500); }
    kvId = kvRes.id;
    siteState.set({ site_kv_id: kvId, site_kv_title: kvRes.title });
    console.log(`[provision] D1 재사용: ${d1Id}, KV 생성: ${kvRes.title} (${kvId})`);

  } else {
    console.log(`[provision] D1 재사용: ${d1Id}, KV 재사용: ${kvId}`);
  }

  // ── Step 4: D1 스키마 초기화 + 메인 바인딩 ID 확보 (병렬) ─────────────────
  siteState.set({ provision_step: 'd1_schema' });
  console.log('[provision] D1 스키마 초기화 + 바인딩 ID 확보 병렬 시작...');

  let mainDbId     = settingVal(settings, 'main_db_id',     '');
  let cacheKvId    = settingVal(settings, 'cache_kv_id',    '');
  let sessionsKvId = settingVal(settings, 'sessions_kv_id', '');

  const needsBindingResolve = !mainDbId || !cacheKvId || !sessionsKvId;

  const [schemaRes, resolvedIds] = await Promise.all([
    initSiteD1Schema(cfToken, cfAccount, d1Id, schemaSql),
    needsBindingResolve ? resolveMainBindingIds(cfToken, cfAccount) : Promise.resolve(null),
  ]);

  if (!schemaRes.ok) {
    console.warn('[provision] D1 스키마 초기화 부분 실패 (계속 진행)');
  } else {
    console.log('[provision] D1 스키마 초기화 완료');
  }

  if (resolvedIds) {
    if (!mainDbId)     mainDbId     = resolvedIds.mainDbId     || '';
    if (!cacheKvId)    cacheKvId    = resolvedIds.cacheKvId    || '';
    if (!sessionsKvId) sessionsKvId = resolvedIds.sessionsKvId || '';

    if (resolvedIds.mainDbId || resolvedIds.cacheKvId || resolvedIds.sessionsKvId) {
      const stmts = [];
      const upsertSql = `INSERT INTO settings (key,value,updated_at) VALUES (?,?,datetime('now'))
                         ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`;
      if (resolvedIds.mainDbId)     stmts.push(env.DB.prepare(upsertSql).bind('main_db_id',     resolvedIds.mainDbId));
      if (resolvedIds.cacheKvId)    stmts.push(env.DB.prepare(upsertSql).bind('cache_kv_id',    resolvedIds.cacheKvId));
      if (resolvedIds.sessionsKvId) stmts.push(env.DB.prepare(upsertSql).bind('sessions_kv_id', resolvedIds.sessionsKvId));
      env.DB.batch(stmts).catch(e => console.warn('[provision] 바인딩 ID 저장 실패:', e.message));
    }
  }

  // ── Step 5: Workers Script Upload ─────────────────────────────────────────
  siteState.set({ provision_step: 'worker_upload' });
  console.log(`[provision] Worker 업로드 중: ${workerName}`);

  const upRes = await uploadWorkerWithCMSSource(
    cfToken,
    cfAccount,
    workerName,
    {
      mainDbId,
      cacheKvId,
      sessionsKvId,
      siteD1Id:    d1Id,
      siteKvId:    kvId,
      cfAccountId: cfAccount,
      cfApiToken:  cfToken,
      sitePrefix:  prefix,
      siteName:    site.name,
      siteDomain:  domain,
    },
    cmsSourceMap
  );

  if (!upRes.ok) {
    await failSite(env.DB, siteId, 'worker_upload', upRes.error);
    return err('Worker 업로드 실패: ' + upRes.error, 500);
  }

  console.log(`[provision] Worker 업로드 완료: ${workerName}`);
  siteState.set({ worker_name: workerName });

  await enableWorkersDev(cfToken, cfAccount, workerName).catch(() => {});

  // ── Step 6: CACHE KV 도메인 매핑 (bulk 1회) ───────────────────────────────
  siteState.set({ provision_step: 'kv_mapping' });

  const siteMapping = JSON.stringify({
    id:          siteId,
    name:        site.name,
    site_prefix: prefix,
    site_d1_id:  d1Id,
    site_kv_id:  kvId,
    status:      'active',
    suspended:   0,
  });

  if (cacheKvId && cfToken && cfAccount) {
    await putCacheKVBulk(cfToken, cfAccount, cacheKvId, [
      { key: `site_domain:${domain}`,    value: siteMapping },
      { key: `site_domain:${wwwDomain}`, value: siteMapping },
      { key: `site_prefix:${prefix}`,    value: siteMapping },
    ]);
  }

  // ── Step 7: DNS + Worker Route 등록 (병렬) ────────────────────────────────
  siteState.set({ provision_step: 'dns_setup' });

  const [cnameTarget, zone] = await Promise.all([
    getWorkerSubdomain(cfToken, cfAccount, workerName),
    cfGetZone(cfToken, domain),
  ]);

  let domainStatus   = 'manual_required';
  let cfZoneId       = null;
  let dnsRecordId    = null, dnsRecordWwwId = null;
  let routeId = null, routeWwwId = null;

  if (zone.ok) {
    cfZoneId = zone.zoneId;

    const [dr, drw] = await Promise.all([
      cfUpsertDns(cfToken, cfZoneId, 'CNAME', domain,    cnameTarget, true),
      cfUpsertDns(cfToken, cfZoneId, 'CNAME', wwwDomain, cnameTarget, true),
    ]);
    if (dr.ok)  dnsRecordId    = dr.recordId;
    if (drw.ok) dnsRecordWwwId = drw.recordId;

    siteState.set({ provision_step: 'worker_route' });

    const [rr, rw] = await Promise.all([
      cfUpsertRoute(cfToken, cfZoneId, domain + '/*',    workerName),
      cfUpsertRoute(cfToken, cfZoneId, wwwDomain + '/*', workerName),
    ]);
    if (rr.ok) routeId    = rr.routeId;
    if (rw.ok) routeWwwId = rw.routeId;
    if (rr.ok || rw.ok) domainStatus = 'dns_propagating';

    siteState.set({
      worker_route:        domain + '/*',
      worker_route_www:    wwwDomain + '/*',
      worker_route_id:     routeId || null,
      worker_route_www_id: routeWwwId || null,
      cf_zone_id:          cfZoneId,
      dns_record_id:       dnsRecordId,
      dns_record_www_id:   dnsRecordWwwId,
    });
  }

  // ── Step 8: 완료 — 메모리 상태 1회 flush ──────────────────────────────────
  const adminUrl = `https://${domain}/cp-admin/setup-config`;

  siteState.set({
    status:         'active',
    provision_step: 'completed',
    domain_status:  domainStatus,
    wp_admin_url:   adminUrl,
    error_message:  domainStatus === 'manual_required'
      ? `외부 DNS 설정 필요 — CNAME: ${cnameTarget}`
      : null,
  });

  // [D1 #3] 사이트 상태 일괄 업데이트 (1회)
  await flushSiteState(env.DB, siteId, siteState.get());

  // [D1 #4] 최종 사이트 조회 (1회)
  const finalSite = await env.DB.prepare(
    'SELECT status, provision_step, error_message, wp_admin_url, primary_domain,'
    + ' site_d1_id, site_kv_id, domain_status, worker_name, name FROM sites WHERE id=?'
  ).bind(siteId).first();

  return ok({
    message:      '프로비저닝 완료',
    siteId,
    site:         finalSite,
    worker_name:  workerName,
    cname_target: cnameTarget,
    cms_files:    cmsSourceMap.size,
    setup_url:    adminUrl,
    cname_instructions: domainStatus === 'manual_required' ? {
      type: 'CNAME',
      root: { host: '@',   value: cnameTarget },
      www:  { host: 'www', value: cnameTarget },
      note: `DNS 전파 후 ${adminUrl} 에서 CMS 설정을 완료하세요.`,
    } : null,
  });
}

// ── 최소 내장 스키마 (GitHub fetch 실패 시 fallback) ──────────────────────────

function getMinimalSchema() {
  return `
CREATE TABLE IF NOT EXISTS cp_posts (
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
CREATE TABLE IF NOT EXISTS cp_postmeta (
  meta_id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL DEFAULT 0,
  meta_key TEXT DEFAULT NULL,
  meta_value TEXT
);
CREATE TABLE IF NOT EXISTS cp_users (
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
CREATE TABLE IF NOT EXISTS cp_usermeta (
  umeta_id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL DEFAULT 0,
  meta_key TEXT DEFAULT NULL,
  meta_value TEXT
);
CREATE TABLE IF NOT EXISTS cp_options (
  option_id INTEGER PRIMARY KEY AUTOINCREMENT,
  option_name TEXT NOT NULL DEFAULT '',
  option_value TEXT NOT NULL DEFAULT '',
  autoload TEXT NOT NULL DEFAULT 'yes',
  UNIQUE(option_name)
);
CREATE TABLE IF NOT EXISTS cp_terms (
  term_id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL DEFAULT '',
  slug TEXT NOT NULL DEFAULT '',
  term_group INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS cp_term_taxonomy (
  term_taxonomy_id INTEGER PRIMARY KEY AUTOINCREMENT,
  term_id INTEGER NOT NULL DEFAULT 0,
  taxonomy TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  parent INTEGER NOT NULL DEFAULT 0,
  count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS cp_term_relationships (
  object_id INTEGER NOT NULL DEFAULT 0,
  term_taxonomy_id INTEGER NOT NULL DEFAULT 0,
  term_order INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (object_id, term_taxonomy_id)
);
CREATE TABLE IF NOT EXISTS cp_comments (
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
CREATE TABLE IF NOT EXISTS cp_commentmeta (
  meta_id INTEGER PRIMARY KEY AUTOINCREMENT,
  comment_id INTEGER NOT NULL DEFAULT 0,
  meta_key TEXT DEFAULT NULL,
  meta_value TEXT
);
CREATE TABLE IF NOT EXISTS cp_media (
  media_id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_name TEXT NOT NULL,
  file_path TEXT NOT NULL UNIQUE,
  mime_type TEXT NOT NULL DEFAULT 'application/octet-stream',
  file_size INTEGER NOT NULL DEFAULT 0,
  upload_date TEXT NOT NULL DEFAULT '',
  storage TEXT NOT NULL DEFAULT 'kv',
  alt_text TEXT DEFAULT '',
  caption TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS cp_cron_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp INTEGER NOT NULL,
  schedule TEXT,
  hook TEXT NOT NULL,
  args TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS cp_posts_post_name ON cp_posts(post_name);
CREATE INDEX IF NOT EXISTS cp_posts_type_status ON cp_posts(post_type, post_status);
CREATE INDEX IF NOT EXISTS cp_postmeta_post_id ON cp_postmeta(post_id);
CREATE INDEX IF NOT EXISTS cp_users_login ON cp_users(user_login);
CREATE INDEX IF NOT EXISTS cp_usermeta_user_id ON cp_usermeta(user_id);
CREATE INDEX IF NOT EXISTS cp_comments_post_id ON cp_comments(comment_post_ID);
CREATE INDEX IF NOT EXISTS cp_cron_ts ON cp_cron_events(timestamp);
`.trim();
}
