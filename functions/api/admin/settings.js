// functions/api/admin/settings.js — CloudPress v16.0
//
// [v16.0 변경사항]
// - wp_origin_url / wp_origin_secret / wp_admin_base_url 제거 (VP 방식 폐지)
// - clone_vp_*, hosting_*, puppeteer_* 제거 (레거시 호환 삭제)
// - cms_github_repo / cms_github_branch / cms_github_token 추가 (GitHub HTTP fetch)
// - cms_versions 관리 (add / delete / set_latest)

// ── tar 파싱 헬퍼 (verify_github 전용) ───────────────────────────────────────
// provision.js의 parseTar()와 동일한 ustar/pax 파싱 로직.
// wantSet에 있는 파일만 찾고, 모두 찾으면 조기 종료.
import { CORS, _j, ok, err, requireAdmin } from '../_shared.js';

const _TAR_DEC = new TextDecoder('utf-8', { fatal: false });

function _tarOctal(buf, offset, len) {
  const s = _TAR_DEC.decode(buf.slice(offset, offset + len)).replace(/\0/g, '').trim();
  return s ? parseInt(s, 8) : 0;
}

function _tarPax(buf) {
  const attrs = {};
  for (const line of _TAR_DEC.decode(buf).split('\n')) {
    const m = line.match(/^\d+ ([^=]+)=(.*)$/);
    if (m) attrs[m[1]] = m[2];
  }
  return attrs;
}

/**
 * raw tar ArrayBuffer를 파싱해서 wantSet 파일 중 발견된 것의 Set을 반환.
 * @param {ArrayBuffer} buffer   gzip 해제된 raw tar 데이터
 * @param {Set<string>} wantSet  찾을 파일 경로 집합
 * @returns {Set<string>}        발견된 파일 경로 집합
 */
function _verifyTarFiles(buffer, wantSet) {
  const buf    = new Uint8Array(buffer);
  const total  = buf.length;
  const found  = new Set();
  let offset   = 0;
  let pax      = {};
  let prefix   = '';  // 레포 최상위 디렉토리 이름 (예: "cloudflare-cms-main")

  while (offset + 512 <= total) {
    const hdr = buf.slice(offset, offset + 512);
    if (hdr.every(b => b === 0)) break;

    // 파일명 조합 (ustar long name 지원)
    let name = _TAR_DEC.decode(hdr.slice(0, 100)).replace(/\0/g, '');
    const up = _TAR_DEC.decode(hdr.slice(345, 500)).replace(/\0/g, '');
    if (up) name = up + '/' + name;
    if (pax.path) name = pax.path;

    const type = String.fromCharCode(hdr[156]) || '0';
    let size   = _tarOctal(hdr, 124, 12);
    if (pax.size) size = parseInt(pax.size, 10);

    const dataOff    = offset + 512;
    const paddedSize = Math.ceil(size / 512) * 512;
    pax = {};

    // pax extended header
    if (type === 'x' || type === 'X') {
      if (dataOff + size <= total) pax = _tarPax(buf.slice(dataOff, dataOff + size));
      offset = dataOff + paddedSize;
      continue;
    }

    // GNU long name
    if (type === 'L') {
      if (dataOff + size <= total) name = _TAR_DEC.decode(buf.slice(dataOff, dataOff + size)).replace(/\0/g, '');
      offset = dataOff + paddedSize;
      // 다음 헤더가 실제 파일
      const nh     = buf.slice(offset, offset + 512);
      const nsize  = _tarOctal(nh, 124, 12);
      const noff   = offset + 512;
      const norm   = _normalise(name, prefix || _repoPrefix(name));
      if (norm && wantSet.has(norm)) found.add(norm);
      offset = noff + Math.ceil(nsize / 512) * 512;
      continue;
    }

    // 레포 prefix 첫 감지
    if (!prefix) prefix = _repoPrefix(name);

    const norm = _normalise(name, prefix);
    if (norm && (type === '0' || type === '\0') && wantSet.has(norm)) {
      found.add(norm);
      if (found.size >= wantSet.size) break; // 모두 찾으면 조기 종료
    }

    offset = dataOff + paddedSize;
  }
  return found;
}

function _repoPrefix(name) {
  const i = name.indexOf('/');
  return i > 0 ? name.slice(0, i) : '';
}

function _normalise(name, prefix) {
  let p = name;
  if (prefix && p.startsWith(prefix + '/')) p = p.slice(prefix.length + 1);
  return (!p || p.endsWith('/')) ? null : p;
}
// 저장 가능한 모든 키 목록
const ALLOWED_KEYS = [
  // Cloudflare
  'cf_api_token',
  'cf_account_id',
  'cf_worker_name',
  'worker_cname_target',
  'main_db_id',
  'cache_kv_id',
  'sessions_kv_id',
  'cloudflare_cdn_enabled',

  // GitHub CMS 소스 (v16.0 — VP 방식 대체)
  'cms_github_repo',
  'cms_github_branch',
  'cms_github_token',
  'cms_versions',

  // 플랜별 사이트 수
  'plan_free_sites',
  'plan_starter_sites',
  'plan_pro_sites',
  'plan_enterprise_sites',
  'plan_starter_price',
  'plan_pro_price',
  'plan_enterprise_price',

  // 결제
  'toss_client_key',
  'toss_secret_key',

  // 일반
  'maintenance_mode',
  'site_name',
  'site_domain',
  'admin_email',

  // 자동화 기본값
  'auto_ssl',
];

// 마스킹 처리 키 (GET 응답에서 가려줌)
const MASK_KEYS = new Set([
  'cf_api_token',
  'cms_github_token',
  'toss_secret_key',
]);

async function saveSettingsObject(env, settings) {
  const entries = Object.entries(settings);
  for (const [key, value] of entries) {
    if (!ALLOWED_KEYS.includes(key)) continue;
    // 마스킹 플레이스홀더는 저장하지 않음
    if (typeof value === 'string' && value.startsWith('••••')) continue;
    await env.DB.prepare(
      `INSERT INTO settings (key,value,updated_at) VALUES (?,?,datetime('now'))
       ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`
    ).bind(key, String(value)).run();
  }
}

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

export async function onRequest({ request, env }) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  const admin = await requireAdmin(env, request);
  if (!admin) return err('관리자 권한이 필요합니다.', 403);

  // ── GET: 설정 조회 ──────────────────────────────────────────────
  if (request.method === 'GET') {
    try {
      const { results } = await env.DB.prepare('SELECT key, value FROM settings').all();
      const settings = Object.fromEntries((results || []).map(r => [r.key, r.value]));
      for (const k of MASK_KEYS) {
        if (settings[k]) settings[k] = '••••••••';
      }
      return ok({ settings });
    } catch (e) { return err('설정 조회 실패: ' + e.message); }
  }

  // ── POST: 설정 저장 ─────────────────────────────────────────────
  if (request.method === 'POST') {
    try {
      let body;
      try { body = await request.json(); } catch { return err('요청 형식 오류'); }
      const { settings } = body;
      if (!settings || typeof settings !== 'object') return err('settings 객체가 필요합니다.');

      await saveSettingsObject(env, settings);
      return ok({ message: '설정이 저장되었습니다.' });
    } catch (e) { return err('설정 저장 실패: ' + e.message); }
  }

  // ── PUT: 다양한 액션 처리 ────────────────────────────────────────
  if (request.method === 'PUT') {
    let body;
    try { body = await request.json(); } catch { return err('요청 형식 오류'); }

    const { action } = body || {};

    // PUT { settings: {...} } — 일반 설정 저장
    if (!action) {
      const { settings } = body;
      if (!settings || typeof settings !== 'object') return err('settings 객체가 필요합니다.');
      try {
        await saveSettingsObject(env, settings);
        return ok({ message: '설정이 저장되었습니다.' });
      } catch (e) { return err('설정 저장 실패: ' + e.message); }
    }

    // PUT { action: 'add_cms_version', version, label?, is_latest? }
    if (action === 'add_cms_version') {
      const { version, label, is_latest } = body;
      if (!version?.trim()) return err('버전 정보가 필요합니다.');
      try {
        const versionId = 'ver_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
        const existing  = await env.DB.prepare("SELECT value FROM settings WHERE key='cms_versions'").first();
        let versions = [];
        if (existing?.value) { try { versions = JSON.parse(existing.value); } catch { versions = []; } }
        const entry = {
          id:         versionId,
          version:    version.trim(),
          label:      label?.trim() || version.trim(),
          is_latest:  !!is_latest,
          created_at: new Date().toISOString(),
        };
        if (entry.is_latest) versions = versions.map(v => ({ ...v, is_latest: false }));
        versions.unshift(entry);
        await env.DB.prepare(
          `INSERT INTO settings (key,value,updated_at) VALUES ('cms_versions',?,datetime('now'))
           ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`
        ).bind(JSON.stringify(versions)).run();
        return ok({ message: 'CMS 버전이 추가되었습니다.', version: entry, versions });
      } catch (e) { return err('버전 추가 실패: ' + e.message, 500); }
    }

    // PUT { action: 'delete_cms_version', version_id }
    if (action === 'delete_cms_version') {
      const { version_id } = body;
      if (!version_id) return err('version_id가 필요합니다.');
      try {
        const existing = await env.DB.prepare("SELECT value FROM settings WHERE key='cms_versions'").first();
        let versions = [];
        if (existing?.value) { try { versions = JSON.parse(existing.value); } catch { versions = []; } }
        versions = versions.filter(v => v.id !== version_id);
        await env.DB.prepare(
          `INSERT INTO settings (key,value,updated_at) VALUES ('cms_versions',?,datetime('now'))
           ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`
        ).bind(JSON.stringify(versions)).run();
        return ok({ message: '버전이 삭제되었습니다.', versions });
      } catch (e) { return err('버전 삭제 실패: ' + e.message, 500); }
    }

    // PUT { action: 'set_latest_version', version_id }
    if (action === 'set_latest_version') {
      const { version_id } = body;
      if (!version_id) return err('version_id가 필요합니다.');
      try {
        const existing = await env.DB.prepare("SELECT value FROM settings WHERE key='cms_versions'").first();
        let versions = [];
        if (existing?.value) { try { versions = JSON.parse(existing.value); } catch { versions = []; } }
        versions = versions.map(v => ({ ...v, is_latest: v.id === version_id }));
        await env.DB.prepare(
          `INSERT INTO settings (key,value,updated_at) VALUES ('cms_versions',?,datetime('now'))
           ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`
        ).bind(JSON.stringify(versions)).run();
        return ok({ message: '최신 버전이 설정되었습니다.', versions });
      } catch (e) { return err('최신 버전 설정 실패: ' + e.message, 500); }
    }

    // PUT { action: 'verify_github', repo, branch?, token? }
    // GitHub 레포 접근 + CMS 필수 파일 존재 여부 사전 검증.
    // provision.js fetchCMSSource()와 동일하게 tarball을 실제 다운로드·파싱한다.
    //
    // [주의] GitHub tarball은 Content-Encoding 이 아닌 실제 gzip 파일(Content-Type:
    // application/x-gzip)로 내려온다. CF Workers의 fetch()는 Content-Encoding: gzip만
    // 자동 해제하고 실제 gzip 바이너리는 그대로 반환한다.
    // → ArrayBuffer를 DecompressionStream('gzip')으로 명시적으로 해제한 후 tar 파싱.
    if (action === 'verify_github') {
      const { repo, branch, token } = body;
      if (!repo?.trim()) return err('repo가 필요합니다.');
      try {
        const br      = (branch || 'main').trim();
        const repoStr = repo.trim();
        const tarUrl  = `https://api.github.com/repos/${repoStr}/tarball/${br}`;
        const headers = {
          'User-Agent': 'CloudPress/17.0',
          'Accept':     'application/vnd.github+json',
        };
        if (token) headers['Authorization'] = `Bearer ${token}`;

        const res = await fetch(tarUrl, { headers });

        if (!res.ok) {
          const hint = res.status === 404
            ? '레포가 존재하지 않거나 private 레포에 접근 토큰이 필요합니다.'
            : res.status === 401
            ? '토큰이 없거나 유효하지 않습니다.'
            : `HTTP ${res.status} ${res.statusText}`;
          return ok({ message: `레포 접근 실패 — ${hint}`, accessible: false, status: res.status });
        }

        // GitHub tarball은 실제 gzip 바이너리이므로 명시적으로 해제
        let buffer;
        try {
          const compressed = await res.arrayBuffer();

          // DecompressionStream으로 gzip 해제 (CF Workers 지원)
          const ds     = new DecompressionStream('gzip');
          const writer = ds.writable.getWriter();
          const reader = ds.readable.getReader();

          writer.write(compressed);
          writer.close();

          const chunks = [];
          let totalLen = 0;
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            chunks.push(value);
            totalLen += value.length;
          }

          const merged = new Uint8Array(totalLen);
          let off = 0;
          for (const c of chunks) { merged.set(c, off); off += c.length; }
          buffer = merged.buffer;
        } catch (decompErr) {
          // gzip 해제 실패 → 이미 raw tar일 수 있으므로 원본으로 재시도
          console.warn('[verify_github] DecompressionStream 실패, raw buffer 사용:', decompErr.message);
          buffer = await res.clone().arrayBuffer().catch(() => null);
          if (!buffer) {
            return ok({ message: 'tarball 압축 해제 실패: ' + decompErr.message, accessible: false });
          }
        }

        // tar 파싱하여 핵심 CMS 파일 존재 확인
        const REQUIRED_FILES = new Set([
          'index.js', 'cp-router.js', 'cp-load.js',
          'cp-admin/index.js', 'cp-includes/functions.js',
        ]);
        const found = _verifyTarFiles(buffer, REQUIRED_FILES);

        if (!found.has('index.js')) {
          return ok({
            message: `레포에 접근했지만 CMS 파일(index.js)이 없습니다. ` +
                     `레포(${repoStr}@${br})에 CloudPress CMS 소스가 올바르게 있는지 확인해주세요. ` +
                     `(확인된 필수 파일: ${found.size}개)`,
            accessible: false,
            cms_files_found: found.size,
            missing_index: true,
          });
        }

        return ok({
          message:         `레포 접근 및 CMS 파일 확인 성공 (${repoStr}@${br}, ${found.size}개 핵심 파일 확인)`,
          accessible:      true,
          cms_files_found: found.size,
        });

      } catch (e) {
        return ok({ message: 'GitHub 접근 오류: ' + e.message, accessible: false });
      }
    }

    return err('알 수 없는 action');
  }

  return err('지원하지 않는 메서드', 405);
}
