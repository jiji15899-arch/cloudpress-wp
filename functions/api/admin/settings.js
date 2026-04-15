// functions/api/admin/settings.js — CloudPress v16.0
//
// [v16.0 변경사항]
// - wp_origin_url / wp_origin_secret / wp_admin_base_url 제거 (VP 방식 폐지)
// - clone_vp_*, hosting_*, puppeteer_* 제거 (레거시 호환 삭제)
// - cms_github_repo / cms_github_branch / cms_github_token 추가 (GitHub HTTP fetch)
// - cms_versions 관리 (add / delete / set_latest)

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};
const _j  = (d, s = 200) => new Response(JSON.stringify(d), {
  status: s, headers: { 'Content-Type': 'application/json', ...CORS },
});
const ok  = (d = {}) => _j({ ok: true,  ...d });
const err = (msg, s = 400) => _j({ ok: false, error: msg }, s);

async function requireAdmin(env, req) {
  try {
    const a = req.headers.get('Authorization') || '';
    const t = a.startsWith('Bearer ') ? a.slice(7) : null;
    if (!t) return null;
    const uid = await env.SESSIONS.get(`session:${t}`);
    if (!uid) return null;
    const user = await env.DB.prepare('SELECT id,role FROM users WHERE id=?').bind(uid).first();
    return user?.role === 'admin' ? user : null;
  } catch { return null; }
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
    // GitHub 레포 접근 가능 여부 사전 검증
    // provision.js의 fetchCMSSource()와 동일한 tarball API를 사용해야
    // "접근 가능"이지만 실제 사이트 생성 시 실패하는 문제를 방지할 수 있음
    if (action === 'verify_github') {
      const { repo, branch, token } = body;
      if (!repo?.trim()) return err('repo가 필요합니다.');
      try {
        const br      = (branch || 'main').trim();
        const repoStr = repo.trim();
        // tarball API: provision.js의 fetchCMSSource()와 동일한 엔드포인트 사용
        const tarUrl  = `https://api.github.com/repos/${repoStr}/tarball/${br}`;
        const headers = {
          'User-Agent': 'CloudPress/17.0',
          'Accept':     'application/vnd.github+json',
        };
        if (token) headers['Authorization'] = `Bearer ${token}`;

        // redirect: 'manual' 로 tarball URL만 확인 (실제 다운로드 불필요)
        const res = await fetch(tarUrl, { headers, redirect: 'manual' });

        // tarball 엔드포인트는 성공 시 302 redirect를 반환
        if (res.ok || res.status === 302) {
          return ok({ message: `레포 접근 성공 (${repoStr}@${br})`, accessible: true });
        }

        // 401: 토큰 없음 / 잘못된 토큰, 404: 레포 없음 / private 접근 불가
        const hint = res.status === 404
          ? '레포가 존재하지 않거나 private 레포에 토큰이 필요합니다.'
          : res.status === 401
          ? '토큰이 없거나 유효하지 않습니다.'
          : `HTTP ${res.status}`;
        return ok({
          message: `레포 접근 실패 — ${hint}`,
          accessible: false,
          status: res.status,
        });
      } catch (e) {
        return ok({ message: 'GitHub 접근 오류: ' + e.message, accessible: false });
      }
    }

    return err('알 수 없는 action');
  }

  return err('지원하지 않는 메서드', 405);
}
