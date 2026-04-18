// functions/api/sites/[id]/domains.js — CloudPress v12.0 (fixed)
// schema.sql 기준: sites 테이블의 primary_domain, domain_status 컬럼만 사용
// domain_verifications 테이블로 도메인 이력 관리
//
// [수정] 누락된 라우트 핸들러 3개 추가:
//   POST   /api/sites/:id/domains              → 도메인 추가 (site.html addDomain)
//   DELETE /api/sites/:id/domains              → 도메인 삭제 (site.html removeDomain)
//   PUT    /api/sites/:id/domains?action=set-primary → 주도메인 설정 (site.html setPrimaryDomain)

import { CORS, _j, ok, err, getToken, getUser, genId } from '../_shared.js';


async function getSetting(env, key, fallback = '') {
  try {
    const r = await env.DB.prepare('SELECT value FROM settings WHERE key=?').bind(key).first();
    return r?.value ?? fallback;
  } catch { return fallback; }
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

/* 도메인 문자열 정규화 */
function cleanDomain(raw) {
  return raw.trim().toLowerCase()
    .replace(/^https?:\/\//, '').replace(/\/$/, '').replace(/^www\./, '');
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

  // CNAME 타겟: settings에 저장된 값 우선, 없으면 워커 이름으로 구성
  let cnameTarget = await getSetting(env, 'worker_cname_target', '');
  if (!cnameTarget) {
    const workerName = await getSetting(env, 'cf_worker_name', 'cloudpress-proxy');
    cnameTarget = workerName + '.workers.dev';
  }
  const url = new URL(request.url);
  const action = url.searchParams.get('action');

  /* ── GET: 도메인 정보 조회 ── */
  if (request.method === 'GET') {
    try {
      const { results: verifications } = await env.DB.prepare(
        `SELECT id, domain, method, verified, verified_at, created_at
         FROM domain_verifications WHERE site_id=? ORDER BY created_at DESC`
      ).bind(siteId).all();

      // site.html이 data.domains 배열과 data.primaryDomain을 사용하므로
      // domain_verifications에서 도메인 목록 구성
      const domains = (verifications || []).map(v => ({
        id: v.id,
        domain: v.domain,
        verified: !!v.verified,
        verified_at: v.verified_at,
        created_at: v.created_at,
        isPrimary: v.domain === site.primary_domain,
      }));

      return ok({
        primary_domain: site.primary_domain,
        primaryDomain: site.primary_domain,
        domain_status: site.domain_status,
        cnameTarget,
        cname_instructions: {
          type: 'CNAME',
          root: { host: '@',   value: cnameTarget, ttl: 3600 },
          www:  { host: 'www', value: cnameTarget, ttl: 3600 },
          note: '외부 DNS(가비아, 후이즈 등)에서 위 값으로 CNAME 레코드를 추가하세요.',
        },
        domains,
        verifications: verifications || [],
      });
    } catch (e) {
      return err('도메인 조회 실패: ' + e.message, 500);
    }
  }

  let body = {};
  if (request.method !== 'DELETE' || request.headers.get('Content-Length') !== '0') {
    try { body = await request.json(); } catch { /* body 없어도 OK */ }
  }

  /* ── POST (action 없음): 도메인 추가 ── */
  // site.html addDomain(): POST /api/sites/:id/domains { domain }
  if (request.method === 'POST' && !action) {
    const { domain } = body || {};
    if (!domain) return err('domain이 필요합니다.');

    const domainClean = cleanDomain(domain);
    if (!/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/.test(domainClean)) {
      return err('올바른 도메인 형식이 아닙니다. (예: myblog.com)');
    }

    // 다른 사이트가 이미 사용 중인지 확인
    const dup = await env.DB.prepare(
      `SELECT id FROM sites WHERE primary_domain=? AND id!=? AND deleted_at IS NULL`
    ).bind(domainClean, siteId).first();
    if (dup) return err('이미 다른 사이트에서 사용 중인 도메인입니다.');

    // domain_verifications에 추가 (미인증 상태)
    const dvId = genId();
    try {
      await env.DB.prepare(
        `INSERT OR IGNORE INTO domain_verifications (id, site_id, domain, method, verified)
         VALUES (?, ?, ?, 'cname', 0)`
      ).bind(dvId, siteId, domainClean).run();
    } catch (e) {
      return err('도메인 추가 실패: ' + e.message, 500);
    }

    // primary_domain이 없으면 자동으로 설정
    if (!site.primary_domain) {
      await env.DB.prepare(
        `UPDATE sites SET primary_domain=?, domain_status='pending', updated_at=datetime('now') WHERE id=?`
      ).bind(domainClean, siteId).run();
    }

    return ok({
      domainId: dvId,
      domain: domainClean,
      message: `도메인이 추가되었습니다. CNAME을 등록 후 인증해주세요.`,
      cnameTarget,
      instructions: { type: 'CNAME', host: '@', value: cnameTarget, ttl: '3600' },
    });
  }

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

      // 검증 이력 갱신
      try {
        await env.DB.prepare(
          `UPDATE domain_verifications SET verified=1, verified_at=datetime('now')
           WHERE site_id=? AND domain=?`
        ).bind(siteId, domain).run();
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

  /* ── PUT?action=set-primary: 주도메인 설정 ── */
  // site.html setPrimaryDomain(): PUT /api/sites/:id/domains?action=set-primary { domainId }
  if (request.method === 'PUT' && action === 'set-primary') {
    const { domainId } = body || {};
    if (!domainId) return err('domainId가 필요합니다.');

    const dv = await env.DB.prepare(
      `SELECT domain FROM domain_verifications WHERE id=? AND site_id=?`
    ).bind(domainId, siteId).first();
    if (!dv) return err('도메인을 찾을 수 없습니다.', 404);

    await env.DB.prepare(
      `UPDATE sites SET primary_domain=?, domain_status='pending', updated_at=datetime('now') WHERE id=?`
    ).bind(dv.domain, siteId).run();

    // 이전 캐시 무효화
    try {
      if (site.primary_domain) {
        await env.CACHE.delete(`site_domain:${site.primary_domain}`);
        await env.CACHE.delete(`site_domain:www.${site.primary_domain}`);
      }
    } catch (_) {}

    return ok({
      domain: dv.domain,
      message: `"${dv.domain}"이(가) 주도메인으로 설정되었습니다.`,
    });
  }

  /* ── PUT?action=set-domain: 도메인 변경 (기존 호환 유지) ── */
  if (request.method === 'PUT' && action === 'set-domain') {
    const { domain } = body || {};
    if (!domain) return err('domain이 필요합니다.');

    const domainClean = cleanDomain(domain);
    if (!/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/.test(domainClean)) {
      return err('올바른 도메인 형식이 아닙니다. (예: myblog.com)');
    }

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

  /* ── DELETE: 도메인 삭제 ── */
  // site.html removeDomain(): DELETE /api/sites/:id/domains { domainId }
  if (request.method === 'DELETE') {
    const { domainId } = body || {};
    if (!domainId) return err('domainId가 필요합니다.');

    const dv = await env.DB.prepare(
      `SELECT domain FROM domain_verifications WHERE id=? AND site_id=?`
    ).bind(domainId, siteId).first();
    if (!dv) return err('도메인을 찾을 수 없습니다.', 404);

    // 주도메인은 삭제 불가
    if (dv.domain === site.primary_domain) {
      return err('주도메인은 삭제할 수 없습니다. 다른 도메인을 주도메인으로 설정한 후 삭제해주세요.');
    }

    await env.DB.prepare(
      `DELETE FROM domain_verifications WHERE id=? AND site_id=?`
    ).bind(domainId, siteId).run();

    // KV 캐시 삭제
    try {
      await env.CACHE.delete(`site_domain:${dv.domain}`);
      await env.CACHE.delete(`site_domain:www.${dv.domain}`);
    } catch (_) {}

    return ok({ message: `"${dv.domain}" 도메인이 삭제되었습니다.` });
  }

  return err('지원하지 않는 요청', 405);
}
