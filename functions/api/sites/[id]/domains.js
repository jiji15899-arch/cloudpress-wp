// functions/api/sites/[id]/domains.js — CloudPress v11.0
// schema.sql 기준: sites 테이블의 primary_domain, domain_status 컬럼만 사용
// domain_verifications 테이블로 도메인 이력 관리

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};
const _j = (d, s = 200) => new Response(JSON.stringify(d), {
  status: s,
  headers: { 'Content-Type': 'application/json', ...CORS },
});
const ok  = (d = {}) => _j({ ok: true, ...d });
const err = (msg, s = 400) => _j({ ok: false, error: msg }, s);

function getToken(req) {
  const a = req.headers.get('Authorization') || '';
  if (a.startsWith('Bearer ')) return a.slice(7);
  const c = req.headers.get('Cookie') || '';
  const m = c.match(/cp_session=([^;]+)/);
  return m ? m[1] : null;
}

async function getUser(env, req) {
  try {
    const t = getToken(req);
    if (!t) return null;
    const uid = await env.SESSIONS.get(`session:${t}`);
    if (!uid) return null;
    return await env.DB.prepare(
      'SELECT id,name,email,role,plan FROM users WHERE id=?'
    ).bind(uid).first();
  } catch { return null; }
}

async function getSetting(env, key, fallback = '') {
  try {
    const r = await env.DB.prepare('SELECT value FROM settings WHERE key=?').bind(key).first();
    return r?.value ?? fallback;
  } catch { return fallback; }
}

function genId() {
  return 'dv_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

/* DNS-over-HTTPS로 CNAME 검증 */
async function verifyCname(domain, expectedTarget) {
  const check = async (url, headers = {}) => {
    const res = await fetch(url, { headers });
    const data = await res.json();
    const rec = (data.Answer || []).find(a => a.type === 5);
    if (!rec) return { verified: false, found: null };
    const found = rec.data.replace(/\.$/, '').toLowerCase();
    const target = expectedTarget.toLowerCase().replace(/\.$/, '');
    return { verified: found === target || found.endsWith('.' + target), found };
  };

  try {
    return await check(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=CNAME`,
      { Accept: 'application/dns-json' }
    );
  } catch {
    try {
      return await check(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=CNAME`);
    } catch (e) {
      return { verified: false, found: null, error: e.message };
    }
  }
}

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

export async function onRequest({ request, env, params }) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  const siteId = params.id;

  // schema.sql 기준 컬럼만 SELECT
  const site = await env.DB.prepare(
    `SELECT id, user_id, name, primary_domain, domain_status, status
     FROM sites WHERE id=? AND user_id=? AND deleted_at IS NULL`
  ).bind(siteId, user.id).first();

  if (!site) return err('사이트를 찾을 수 없습니다.', 404);

  const cnameTarget = await getSetting(env, 'worker_cname_target', 'cloudpress-proxy.workers.dev');
  const url = new URL(request.url);
  const action = url.searchParams.get('action');

  /* ── GET: 도메인 정보 조회 ── */
  if (request.method === 'GET') {
    try {
      const { results: verifications } = await env.DB.prepare(
        `SELECT id, domain, method, verified, verified_at, created_at
         FROM domain_verifications WHERE site_id=? ORDER BY created_at DESC`
      ).bind(siteId).all();

      return ok({
        primary_domain: site.primary_domain,
        domain_status: site.domain_status,
        cnameTarget,
        verifications: verifications || [],
      });
    } catch (e) {
      return err('도메인 조회 실패: ' + e.message, 500);
    }
  }

  let body;
  try { body = await request.json(); } catch { return err('요청 형식 오류'); }

  /* ── POST?action=verify: CNAME 인증 확인 ── */
  if (request.method === 'POST' && action === 'verify') {
    const domain = site.primary_domain;
    if (!domain) return err('연결된 도메인이 없습니다.');

    const result = await verifyCname(domain, cnameTarget);

    if (result.verified) {
      await env.DB.prepare(
        `UPDATE sites SET domain_status='active', updated_at=datetime('now') WHERE id=?`
      ).bind(siteId).run();

      // KV 캐시 갱신
      try {
        const siteData = JSON.stringify({ id: siteId, name: site.name, status: 'active', suspended: 0 });
        await env.CACHE.put(`site_domain:${domain}`, siteData, { expirationTtl: 86400 });
        await env.CACHE.put(`site_domain:www.${domain}`, siteData, { expirationTtl: 86400 });
      } catch (_) {}

      // 검증 이력 기록
      try {
        await env.DB.prepare(
          `INSERT INTO domain_verifications (id, site_id, domain, method, verified, verified_at)
           VALUES (?,?,?,'cname',1,datetime('now'))`
        ).bind(genId(), siteId, domain).run();
      } catch (_) {}

      return ok({ verified: true, domain, message: `✅ CNAME 인증 성공! "${domain}" 도메인이 활성화되었습니다.` });
    }

    return ok({
      verified: false,
      domain,
      found: result.found,
      message: '⏳ CNAME이 아직 전파되지 않았습니다.',
      instructions: { type: 'CNAME', host: '@', value: cnameTarget, ttl: '3600' },
    });
  }

  /* ── PUT?action=set-domain: 도메인 변경 ── */
  if (request.method === 'PUT' && action === 'set-domain') {
    const { domain } = body || {};
    if (!domain) return err('domain이 필요합니다.');

    const domainClean = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '').replace(/^www\./, '');
    if (!/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/.test(domainClean)) {
      return err('올바른 도메인 형식이 아닙니다. (예: myblog.com)');
    }

    // 다른 사이트가 이미 사용 중인지 확인
    const dup = await env.DB.prepare(
      `SELECT id FROM sites WHERE primary_domain=? AND id!=? AND deleted_at IS NULL`
    ).bind(domainClean, siteId).first();
    if (dup) return err('이미 다른 사이트에서 사용 중인 도메인입니다.');

    await env.DB.prepare(
      `UPDATE sites SET primary_domain=?, domain_status='pending', updated_at=datetime('now') WHERE id=?`
    ).bind(domainClean, siteId).run();

    return ok({
      domain: domainClean,
      message: `도메인이 설정되었습니다. CNAME을 등록 후 인증해주세요.`,
      instructions: { type: 'CNAME', host: '@', value: cnameTarget, ttl: '3600' },
    });
  }

  return err('지원하지 않는 요청', 405);
}
