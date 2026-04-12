// functions/api/admin/settings.js — CloudPress v12.0 (fixed)
//
// [수정] PUT 메서드 핸들러 추가:
//   app.js의 adminSaveSettings()  → CP.put('/admin/settings', { settings: b })
//   app.js의 adminAddCmsVersion() → CP.put('/admin/settings', { action: 'add_cms_version', ... })
//   app.js의 adminDeleteCmsVersion() → CP.put('/admin/settings', { action: 'delete_cms_version', ... })
//   app.js의 adminSetLatestVersion() → CP.put('/admin/settings', { action: 'set_latest_version', ... })
//   위 네 가지 호출이 모두 PUT 메서드를 사용하지만 기존 코드는 POST만 처리하여 405 오류 발생
//
// Access-Control-Allow-Methods에도 PUT 추가

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};
const _j  = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { 'Content-Type': 'application/json', ...CORS } });
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

const ALLOWED_KEYS = [
  // ★ 핵심: 단일 WP Origin
  'wp_origin_url',        // 예: https://origin.cloudpress.site
  'wp_origin_secret',     // WP mu-plugin 공유 시크릿
  'wp_admin_base_url',    // origin WP admin URL

  // Cloudflare
  'cf_api_token',
  'cf_account_id',
  'cf_worker_name',       // 배포된 Worker 이름 (단일 Worker)
  'worker_cname_target',  // CNAME 수동 설정 안내용

  // 플랜별 사이트 수
  'plan_free_sites', 'plan_starter_sites', 'plan_pro_sites', 'plan_enterprise_sites',
  'plan_starter_price', 'plan_pro_price', 'plan_enterprise_price',

  // 결제
  'toss_client_key', 'toss_secret_key',

  // 일반
  'maintenance_mode', 'site_name', 'site_domain', 'admin_email',
];

const MASK_KEYS = new Set(['wp_origin_secret', 'cf_api_token', 'toss_secret_key']);

/* settings 객체를 DB에 저장하는 공통 함수 */
async function saveSettingsObject(env, settings) {
  for (const [key, value] of Object.entries(settings)) {
    if (!ALLOWED_KEYS.includes(key)) continue;
    // 마스킹된 값은 저장하지 않음
    if (value === '••••••••') continue;
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

  // ── GET: 설정 조회 ──────────────────────────────────────────
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

  // ── POST: 설정 저장 (admin-settings.html 직접 fetch 방식) ──
  if (request.method === 'POST') {
    try {
      let body;
      try { body = await request.json(); } catch { return err('요청 형식 오류'); }
      const { settings } = body;
      if (!settings || typeof settings !== 'object') return err('settings 객체가 필요합니다.');

      await saveSettingsObject(env, settings);

      const updatedKeys = Object.keys(settings).filter(k => ALLOWED_KEYS.includes(k));
      const needsWorkerUpdate = updatedKeys.some(k => ['wp_origin_url','wp_origin_secret','cf_worker_name'].includes(k));

      return ok({
        message: '설정이 저장되었습니다.',
        notice: needsWorkerUpdate ? 'Worker 환경변수(WP_ORIGIN_URL, WP_ORIGIN_SECRET)를 wrangler.toml에도 업데이트하고 Worker를 재배포해주세요.' : null,
      });
    } catch (e) { return err('설정 저장 실패: ' + e.message); }
  }

  // ── PUT: app.js CP.put('/admin/settings', ...) 방식 ─────────
  // adminSaveSettings(b)        → { settings: b }
  // adminAddCmsVersion(b)       → { action: 'add_cms_version', ... }
  // adminDeleteCmsVersion(id)   → { action: 'delete_cms_version', version_id: id }
  // adminSetLatestVersion(id)   → { action: 'set_latest_version', version_id: id }
  if (request.method === 'PUT') {
    let body;
    try { body = await request.json(); } catch { return err('요청 형식 오류'); }

    const { action } = body || {};

    // PUT { settings: {...} } — adminSaveSettings와 동일한 처리
    if (!action) {
      const { settings } = body;
      if (!settings || typeof settings !== 'object') return err('settings 객체가 필요합니다.');

      try {
        await saveSettingsObject(env, settings);

        const updatedKeys = Object.keys(settings).filter(k => ALLOWED_KEYS.includes(k));
        const needsWorkerUpdate = updatedKeys.some(k => ['wp_origin_url','wp_origin_secret','cf_worker_name'].includes(k));

        return ok({
          message: '설정이 저장되었습니다.',
          notice: needsWorkerUpdate ? 'Worker 환경변수를 wrangler.toml에도 업데이트하고 재배포해주세요.' : null,
        });
      } catch (e) { return err('설정 저장 실패: ' + e.message); }
    }

    // PUT { action: 'add_cms_version', version, label?, is_latest? }
    if (action === 'add_cms_version') {
      const { version, label, is_latest } = body;
      if (!version?.trim()) return err('버전 정보가 필요합니다.');
      try {
        const versionId = 'ver_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
        const existing = await env.DB.prepare("SELECT value FROM settings WHERE key='cms_versions'").first();
        let versions = [];
        if (existing?.value) {
          try { versions = JSON.parse(existing.value); } catch { versions = []; }
        }
        const entry = {
          id: versionId,
          version: version.trim(),
          label: label?.trim() || version.trim(),
          is_latest: !!is_latest,
          created_at: new Date().toISOString(),
        };
        if (entry.is_latest) {
          versions = versions.map(v => ({ ...v, is_latest: false }));
        }
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
        if (existing?.value) {
          try { versions = JSON.parse(existing.value); } catch { versions = []; }
        }
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
        if (existing?.value) {
          try { versions = JSON.parse(existing.value); } catch { versions = []; }
        }
        versions = versions.map(v => ({ ...v, is_latest: v.id === version_id }));
        await env.DB.prepare(
          `INSERT INTO settings (key,value,updated_at) VALUES ('cms_versions',?,datetime('now'))
           ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`
        ).bind(JSON.stringify(versions)).run();
        return ok({ message: '최신 버전이 설정되었습니다.', versions });
      } catch (e) { return err('최신 버전 설정 실패: ' + e.message, 500); }
    }

    return err('알 수 없는 action');
  }

  return err('지원하지 않는 메서드', 405);
}
