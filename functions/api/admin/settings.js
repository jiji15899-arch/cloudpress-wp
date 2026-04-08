// functions/api/admin/settings.js — 관리자 설정 API (Cloudflare CMS 패키지 제거됨)

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};
const _j = (d, s = 200) => new Response(JSON.stringify(d), {
  status: s, headers: { 'Content-Type': 'application/json', ...CORS },
});
const ok = (d = {}) => _j({ ok: true, ...d });
const err = (msg, s = 400) => _j({ ok: false, error: msg }, s);

async function requireAdmin(env, req) {
  try {
    const a = req.headers.get('Authorization') || '';
    const token = a.startsWith('Bearer ') ? a.slice(7) : null;
    if (!token) return null;
    const uid = await env.SESSIONS.get(`session:${token}`);
    if (!uid) return null;
    const user = await env.DB.prepare('SELECT id,role FROM users WHERE id=?').bind(uid).first();
    return user?.role === 'admin' ? user : null;
  } catch { return null; }
}

export async function onRequest({ request, env }) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  const admin = await requireAdmin(env, request);
  if (!admin) return err('관리자 권한이 필요합니다.', 403);

  // GET — 모든 설정 조회
  if (request.method === 'GET') {
    try {
      const { results } = await env.DB.prepare('SELECT key, value FROM settings').all();
      const settings = Object.fromEntries((results || []).map(r => [r.key, r.value]));
      // 민감한 값은 마스킹
      if (settings.cf_api_token) settings.cf_api_token = '••••••••';
      if (settings.puppeteer_worker_secret) settings.puppeteer_worker_secret = '••••••••';
      return ok({ settings });
    } catch (e) {
      return err('설정 조회 실패: ' + e.message);
    }
  }

  // POST — 설정 저장
  if (request.method === 'POST') {
    try {
      let body;
      try { body = await request.json(); } catch { return err('요청 형식 오류'); }
      
      const { settings } = body;
      if (!settings || typeof settings !== 'object') return err('settings 객체가 필요합니다.');

      // 허용된 설정 키
      const ALLOWED_KEYS = [
        'plan_free_sites', 'plan_starter_sites', 'plan_pro_sites', 'plan_enterprise_sites',
        'puppeteer_worker_url', 'puppeteer_worker_secret',
        'cf_api_token', 'cf_account_id', 'cloudflare_cdn_enabled',
        'auto_ssl', 'auto_breeze',
        'maintenance_mode', 'active_providers',
        'site_name', 'admin_email',
      ];

      for (const [key, value] of Object.entries(settings)) {
        if (!ALLOWED_KEYS.includes(key)) continue;
        await env.DB.prepare(
          'INSERT INTO settings (key, value, updated_at) VALUES (?,?,datetime(\'now\')) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at'
        ).bind(key, String(value)).run();
      }

      return ok({ message: '설정이 저장되었습니다.' });
    } catch (e) {
      return err('설정 저장 실패: ' + e.message);
    }
  }

  return err('지원하지 않는 메서드', 405);
}
