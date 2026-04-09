// functions/api/sites/[id]/domains.js
// CloudPress v4.0 — 사이트별 도메인 관리 API
// ✅ 수정6: 도메인 추가, CNAME 인증, 주도메인 설정

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

function genId(prefix = 'dom') {
  return `${prefix}_` + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

async function getCnameTarget(env) {
  try {
    const row = await env.DB.prepare(
      "SELECT value FROM settings WHERE key='cname_target'"
    ).first();
    return row?.value || env.CNAME_TARGET || 'proxy.cloudpress.site';
  } catch {
    return env.CNAME_TARGET || 'proxy.cloudpress.site';
  }
}

async function getPuppeteerWorkerUrl(env) {
  try {
    const row = await env.DB.prepare(
      "SELECT value FROM settings WHERE key='puppeteer_worker_url'"
    ).first();
    return row?.value || env.PUPPETEER_WORKER_URL || '';
  } catch {
    return env.PUPPETEER_WORKER_URL || '';
  }
}

async function getPuppeteerWorkerSecret(env) {
  try {
    const row = await env.DB.prepare(
      "SELECT value FROM settings WHERE key='puppeteer_worker_secret'"
    ).first();
    return row?.value || env.PUPPETEER_WORKER_SECRET || '';
  } catch {
    return env.PUPPETEER_WORKER_SECRET || '';
  }
}

/* DNS-over-HTTPS로 CNAME 검증 */
async function verifyCnameRecord(domain, expectedTarget) {
  try {
    // Cloudflare DoH
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=CNAME`,
      { headers: { Accept: 'application/dns-json' } }
    );
    if (!res.ok) throw new Error('DoH 요청 실패');
    const data = await res.json();
    const answers = data.Answer || [];
    const cnameRecord = answers.find(a => a.type === 5); // CNAME = type 5
    if (!cnameRecord) {
      return { verified: false, found: null, message: 'CNAME 레코드 없음' };
    }
    const recordData = cnameRecord.data.replace(/\.$/, '').toLowerCase();
    const target = expectedTarget.toLowerCase().replace(/\.$/, '');
    const verified = recordData === target || recordData.endsWith('.' + target);
    return { verified, found: recordData, message: verified ? 'CNAME 인증 성공' : `CNAME 불일치: ${recordData} ≠ ${target}` };
  } catch (e) {
    // Google DoH fallback
    try {
      const res2 = await fetch(
        `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=CNAME`
      );
      const data2 = await res2.json();
      const answers2 = (data2.Answer || []);
      const cnameRecord2 = answers2.find(a => a.type === 5);
      if (!cnameRecord2) {
        return { verified: false, found: null, message: 'CNAME 레코드 없음 (Google DoH)' };
      }
      const recordData2 = cnameRecord2.data.replace(/\.$/, '').toLowerCase();
      const target2 = expectedTarget.toLowerCase().replace(/\.$/, '');
      const verified2 = recordData2 === target2 || recordData2.endsWith('.' + target2);
      return { verified: verified2, found: recordData2, message: verified2 ? 'CNAME 인증 성공' : `CNAME 불일치: ${recordData2}` };
    } catch (e2) {
      return { verified: false, found: null, message: 'DNS 조회 실패: ' + e2.message };
    }
  }
}

/* ── Worker를 통한 CNAME 검증 (fallback) ── */
async function verifyCnameViaWorker(env, domain, cnameTarget) {
  const workerUrl    = await getPuppeteerWorkerUrl(env);
  const workerSecret = await getPuppeteerWorkerSecret(env);
  if (!workerUrl) return { verified: false, message: 'Worker 미설정' };

  try {
    const res = await fetch(`${workerUrl}/api/verify-cname`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Worker-Secret': workerSecret,
      },
      body: JSON.stringify({ domain, cnameTarget }),
    });
    return await res.json();
  } catch (e) {
    return { verified: false, message: 'Worker 오류: ' + e.message };
  }
}

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

export async function onRequest({ request, env, params }) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }

  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  const siteId = params.id;
  const site = await env.DB.prepare(
    `SELECT id, user_id, name, wp_url, wp_admin_url, hosting_domain,
            primary_domain, custom_domain, domain_status, cname_target, status
     FROM sites WHERE id=? AND user_id=?`
  ).bind(siteId, user.id).first();

  if (!site) return err('사이트를 찾을 수 없습니다.', 404);
  if (site.status !== 'active') return err('사이트가 활성화된 후 도메인을 관리할 수 있습니다.');

  const cnameTarget = site.cname_target || await getCnameTarget(env);
  const url = new URL(request.url);
  const action = url.searchParams.get('action');

  /* ── GET: 도메인 목록 조회 ── */
  if (request.method === 'GET') {
    try {
      const { results: domains } = await env.DB.prepare(
        `SELECT id, domain, cname_target, cname_verified, is_primary, status, verified_at, created_at
         FROM domains WHERE site_id=? ORDER BY is_primary DESC, created_at ASC`
      ).bind(siteId).all();

      return ok({
        domains: domains || [],
        subdomain: site.hosting_domain || site.wp_url,
        primaryDomain: site.primary_domain || site.hosting_domain || site.wp_url,
        cnameTarget,
      });
    } catch (e) {
      return err('도메인 목록 조회 실패: ' + e.message, 500);
    }
  }

  let body;
  try { body = await request.json(); } catch { return err('요청 형식 오류'); }

  /* ── POST: 도메인 추가 ── */
  if (request.method === 'POST' && action !== 'verify' && action !== 'set-primary') {
    const { domain } = body || {};
    if (!domain) return err('도메인을 입력해주세요.');

    // 도메인 형식 검증 (www 포함 허용, 한국 IDN 허용)
    const domainClean = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '');
    if (!/^[a-z0-9\-\.]+\.[a-z]{2,}$/.test(domainClean) && !/^xn--/.test(domainClean)) {
      return err('올바른 도메인 형식이 아닙니다. (예: example.com, www.example.com)');
    }

    // 이미 등록된 도메인 확인
    const existing = await env.DB.prepare(
      'SELECT id FROM domains WHERE domain=?'
    ).bind(domainClean).first();
    if (existing) return err('이미 등록된 도메인입니다.');

    // 도메인 추가
    const domainId = genId('dom');
    try {
      await env.DB.prepare(
        `INSERT INTO domains (id, site_id, user_id, domain, cname_target, status)
         VALUES (?,?,?,?,?,'pending')`
      ).bind(domainId, siteId, user.id, domainClean, cnameTarget).run();
    } catch (e) {
      return err('도메인 추가 실패: ' + e.message, 500);
    }

    return ok({
      domainId,
      domain: domainClean,
      cnameTarget,
      status: 'pending',
      message: `도메인이 추가되었습니다. 아래 CNAME 레코드를 DNS에 등록해주세요.`,
      instructions: {
        type: 'CNAME',
        host: domainClean.startsWith('www.') ? 'www' : '@',
        value: cnameTarget,
        ttl: '3600 (또는 Auto)',
        note: 'DNS 전파는 최대 48시간 소요됩니다. 보통 1~2시간 내 적용됩니다.',
      },
    });
  }

  /* ── POST?action=verify: CNAME 인증 확인 ── */
  if (request.method === 'POST' && action === 'verify') {
    const { domainId } = body || {};
    if (!domainId) return err('domainId가 필요합니다.');

    const domainRow = await env.DB.prepare(
      'SELECT * FROM domains WHERE id=? AND site_id=?'
    ).bind(domainId, siteId).first();
    if (!domainRow) return err('도메인을 찾을 수 없습니다.');

    // CNAME 직접 검증
    let verifyResult = await verifyCnameRecord(domainRow.domain, domainRow.cname_target);

    // 직접 검증 실패 시 Worker 통해 재시도
    if (!verifyResult.verified) {
      verifyResult = await verifyCnameViaWorker(env, domainRow.domain, domainRow.cname_target);
    }

    if (verifyResult.verified) {
      // 인증 성공 → DB 업데이트
      await env.DB.prepare(
        `UPDATE domains SET cname_verified=1, status='active', verified_at=datetime('now'), updated_at=datetime('now')
         WHERE id=?`
      ).bind(domainId).run();

      return ok({
        verified: true,
        domain: domainRow.domain,
        message: `✅ CNAME 인증 성공! "${domainRow.domain}" 도메인이 활성화되었습니다.`,
        canSetPrimary: true,
      });
    } else {
      // 인증 실패
      await env.DB.prepare(
        `UPDATE domains SET status='pending', updated_at=datetime('now') WHERE id=?`
      ).bind(domainId).run();

      return ok({
        verified: false,
        domain: domainRow.domain,
        found: verifyResult.found,
        message: `⏳ CNAME 레코드가 아직 전파되지 않았습니다. DNS에 아래 CNAME을 등록 후 다시 확인해주세요.`,
        instructions: {
          type: 'CNAME',
          host: domainRow.domain.startsWith('www.') ? 'www' : '@',
          value: domainRow.cname_target,
          ttl: '3600',
          note: 'DNS 전파는 최대 48시간 소요됩니다.',
        },
      });
    }
  }

  /* ── PUT?action=set-primary: 주도메인 설정 ── */
  if (request.method === 'PUT' && action === 'set-primary') {
    const { domainId } = body || {};
    if (!domainId) return err('domainId가 필요합니다.');

    const domainRow = await env.DB.prepare(
      'SELECT * FROM domains WHERE id=? AND site_id=?'
    ).bind(domainId, siteId).first();
    if (!domainRow) return err('도메인을 찾을 수 없습니다.');
    if (!domainRow.cname_verified) return err('CNAME이 인증된 도메인만 주도메인으로 설정할 수 있습니다.');

    // 기존 주도메인 해제
    await env.DB.prepare(
      'UPDATE domains SET is_primary=0 WHERE site_id=?'
    ).bind(siteId).run();

    // 새 주도메인 설정
    await env.DB.prepare(
      `UPDATE domains SET is_primary=1, updated_at=datetime('now') WHERE id=?`
    ).bind(domainId).run();

    // 사이트 primary_domain 업데이트
    const newPrimaryUrl = `https://${domainRow.domain}`;
    await env.DB.prepare(
      `UPDATE sites SET primary_domain=?, custom_domain=?, domain_status='active', updated_at=unixepoch() WHERE id=?`
    ).bind(domainRow.domain, domainRow.domain, siteId).run();

    return ok({
      domain: domainRow.domain,
      primaryUrl: newPrimaryUrl,
      message: `✅ "${domainRow.domain}"이(가) 주도메인으로 설정되었습니다.`,
    });
  }

  /* ── DELETE: 도메인 삭제 ── */
  if (request.method === 'DELETE') {
    const { domainId } = body || {};
    if (!domainId) return err('domainId가 필요합니다.');

    const domainRow = await env.DB.prepare(
      'SELECT * FROM domains WHERE id=? AND site_id=?'
    ).bind(domainId, siteId).first();
    if (!domainRow) return err('도메인을 찾을 수 없습니다.');

    // 주도메인이면 삭제 불가 (서브도메인으로 먼저 변경해야)
    if (domainRow.is_primary) {
      return err('주도메인은 삭제할 수 없습니다. 다른 도메인을 주도메인으로 설정 후 삭제해주세요.');
    }

    await env.DB.prepare('DELETE FROM domains WHERE id=?').bind(domainId).run();

    return ok({ message: `"${domainRow.domain}" 도메인이 삭제되었습니다.` });
  }

  return err('지원하지 않는 요청', 405);
}
