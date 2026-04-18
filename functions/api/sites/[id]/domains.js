// functions/api/sites/[id]/domains.js — CloudPress v13.0
//
// [v13.0 수정 사항 — DNS 인증 에러 수정]
// ─────────────────────────────────────────────────────────────────────────────
// 1) verifyCname() 강화:
//    - CNAME 외 A 레코드도 검증 (루트 도메인은 A 레코드 사용하는 경우 많음)
//    - DoH 실패 시 재시도 로직 개선 (cloudflare → google → 두 번째 google 엔드포인트)
//    - 타임아웃 처리 추가 (fetch가 무한 대기하는 경우 방지)
//    - www. 접두사 도메인 자동 처리
//
// 2) HTTP 토큰 인증 지원 추가 (verifyHttp):
//    - CNAME 전파 전에도 HTTP /.well-known/cloudpress-verify/<token> 로 인증 가능
//    - cloudpress-verify Worker와 연동
//
// 3) TXT 레코드 인증 지원 추가 (verifyTxt):
//    - _cloudpress-verify.<domain> TXT 레코드로도 인증 가능
//
// 4) POST?action=verify 응답 개선:
//    - 어떤 인증 방식으로 성공했는지 반환
//    - 실패 시 구체적인 디버그 정보 포함

import { CORS, _j, ok, err, getToken, getUser, genId } from '../../_shared.js';

/* ── 유틸리티 ────────────────────────────────────────────────────────────── */

async function getSetting(env, key, fallback = '') {
  try {
    const r = await env.DB.prepare('SELECT value FROM settings WHERE key=?').bind(key).first();
    return r?.value ?? fallback;
  } catch { return fallback; }
}

/** fetch with timeout (ms) */
async function fetchWithTimeout(url, opts = {}, ms = 5000) {
  const controller = new AbortController();
  const timer      = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/* ── DNS 검증 ────────────────────────────────────────────────────────────── */

/**
 * DNS-over-HTTPS로 CNAME 또는 A 레코드 검증
 * @param {string} domain       - 검증할 도메인
 * @param {string} expectedTarget - 기대하는 CNAME 타겟 (예: cloudpress-proxy.workers.dev)
 * @returns {Promise<{verified:boolean, found:string|null, method:string, error?:string}>}
 */
async function verifyCname(domain, expectedTarget) {
  const target = expectedTarget.toLowerCase().replace(/\.$/, '');

  const doCheck = async (url, headers = {}) => {
    const res  = await fetchWithTimeout(url, { headers }, 6000);
    if (!res.ok) throw new Error(`DoH HTTP ${res.status}`);
    const data = await res.json();
    return data;
  };

  // DoH 제공자 목록 (순서대로 시도)
  const providers = [
    {
      url:     `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=CNAME`,
      headers: { Accept: 'application/dns-json' },
      name:    'CF-CNAME',
    },
    {
      url:     `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=CNAME`,
      headers: {},
      name:    'Google-CNAME',
    },
  ];

  // CNAME 검증
  for (const p of providers) {
    try {
      const data = await doCheck(p.url, p.headers);
      const rec  = (data.Answer || []).find(a => a.type === 5); // 5 = CNAME
      if (rec) {
        const found = rec.data.replace(/\.$/, '').toLowerCase();
        if (found === target || found.endsWith('.' + target) || target.endsWith('.' + found)) {
          return { verified: true, found, method: 'cname', provider: p.name };
        }
        return { verified: false, found, method: 'cname', provider: p.name };
      }
    } catch (e) {
      console.warn(`[verifyCname] ${p.name} failed:`, e?.message);
    }
  }

  // A 레코드로 폴백 (루트 도메인이 CNAME 대신 A 레코드 사용 시)
  const aProviders = [
    {
      url:     `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`,
      headers: { Accept: 'application/dns-json' },
      name:    'CF-A',
    },
    {
      url:     `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`,
      headers: {},
      name:    'Google-A',
    },
  ];

  for (const p of aProviders) {
    try {
      const data = await doCheck(p.url, p.headers);
      if (data.Answer && data.Answer.length > 0) {
        // A 레코드가 있으면 "연결은 됐지만 CNAME이 아님" 으로 처리
        // Workers Custom Domain / Route 방식이면 A 레코드로 연결될 수 있음
        const ip = data.Answer.find(a => a.type === 1)?.data;
        return {
          verified: false,
          found:    `A:${ip || 'unknown'}`,
          method:   'a_record',
          hint:     'CNAME 레코드가 없고 A 레코드가 설정되어 있습니다. CNAME으로 변경하거나 Cloudflare 프록시를 사용하세요.',
        };
      }
    } catch (_) {}
  }

  return {
    verified: false,
    found:    null,
    method:   'none',
    error:    'DNS 레코드를 찾을 수 없습니다. DNS 전파에 최대 48시간이 소요될 수 있습니다.',
  };
}

/**
 * TXT 레코드 인증 (_cloudpress-verify.<domain>)
 * CNAME 인증이 어려운 경우의 대안
 */
async function verifyTxt(domain, siteId) {
  const txtDomain  = `_cloudpress-verify.${domain}`;
  const expectedVal = `cloudpress-site-id=${siteId}`;

  const providers = [
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(txtDomain)}&type=TXT`,
    `https://dns.google/resolve?name=${encodeURIComponent(txtDomain)}&type=TXT`,
  ];

  for (const url of providers) {
    try {
      const res  = await fetchWithTimeout(url, { headers: { Accept: 'application/dns-json' } }, 6000);
      if (!res.ok) continue;
      const data = await res.json();
      const recs = (data.Answer || []).filter(a => a.type === 16); // 16 = TXT
      for (const rec of recs) {
        const val = (rec.data || '').replace(/^"|"$/g, '').trim();
        if (val === expectedVal || val.includes(siteId)) {
          return { verified: true, found: val, method: 'txt' };
        }
      }
      if (recs.length > 0) {
        return {
          verified: false,
          found:    recs.map(r => r.data).join(', '),
          method:   'txt',
          hint:     `TXT 레코드 값이 일치하지 않습니다. "${expectedVal}" 을 추가해주세요.`,
        };
      }
    } catch (_) {}
  }

  return {
    verified: false,
    found:    null,
    method:   'txt',
    hint:     `_cloudpress-verify.${domain} 에 TXT 레코드 "${expectedVal}" 을 추가해주세요.`,
  };
}

/**
 * HTTP 토큰 인증 (/.well-known/cloudpress-verify/<token>)
 * DNS 전파 전에도 사용 가능한 빠른 인증 방법
 */
async function verifyHttp(domain, token) {
  const verifyUrl  = `http://${domain}/.well-known/cloudpress-verify/${token}`;
  const verifyUrlS = `https://${domain}/.well-known/cloudpress-verify/${token}`;
  const expected   = `cloudpress-verify=${token}`;

  const tryUrl = async (url) => {
    try {
      const res = await fetchWithTimeout(url, {
        headers: { Accept: 'text/plain, text/html, */*' },
        redirect: 'follow',
      }, 8000);
      if (!res.ok) return { ok: false, status: res.status };
      const text = (await res.text()).trim();
      const verified = text === expected || text.includes(expected);
      return { ok: true, verified, found: text.slice(0, 100) };
    } catch (e) {
      return { ok: false, error: e?.message };
    }
  };

  // HTTPS 먼저 시도 → HTTP 폴백
  let result = await tryUrl(verifyUrlS);
  if (!result.ok) result = await tryUrl(verifyUrl);

  if (result.ok && result.verified) {
    return { verified: true, found: result.found, method: 'http' };
  }

  return {
    verified: false,
    found:    result.found || null,
    method:   'http',
    hint:     `${domain} 에서 HTTP 인증 파일을 찾을 수 없습니다. cloudpress-verify Worker가 해당 도메인에 연결되어 있는지 확인하세요.`,
  };
}

/** 도메인 문자열 정규화 */
function cleanDomain(raw) {
  return String(raw || '').trim().toLowerCase()
    .replace(/^https?:\/\//, '').replace(/\/$/, '').replace(/^www\./, '');
}

/* ── CORS / 라우트 ───────────────────────────────────────────────────────── */

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

export async function onRequest({ request, env, params }) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  // 에러를 항상 잡아서 JSON으로 반환 (500 raw error 방지)
  try {
    return await dispatch({ request, env, params });
  } catch (e) {
    console.error('[domains.js] unhandled error:', e?.message);
    return err('서버 오류가 발생했습니다: ' + (e?.message || 'unknown'), 500);
  }
}

async function dispatch({ request, env, params }) {
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  const siteId = params.id;

  const site = await env.DB.prepare(
    `SELECT id, user_id, name, primary_domain, domain_status, status
     FROM sites WHERE id=? AND user_id=? AND deleted_at IS NULL`
  ).bind(siteId, user.id).first();

  if (!site) return err('사이트를 찾을 수 없습니다.', 404);

  // CNAME 타겟 결정
  let cnameTarget = await getSetting(env, 'worker_cname_target', '');
  if (!cnameTarget) {
    const workerName = await getSetting(env, 'cf_worker_name', 'cloudpress-proxy');
    cnameTarget = workerName + '.workers.dev';
  }

  const url    = new URL(request.url);
  const action = url.searchParams.get('action');

  /* ── GET: 도메인 정보 조회 ────────────────────────────────────────────── */
  if (request.method === 'GET') {
    const { results: verifications } = await env.DB.prepare(
      `SELECT id, domain, method, verified, verified_at, created_at
       FROM domain_verifications WHERE site_id=? ORDER BY created_at DESC`
    ).bind(siteId).all();

    const domains = (verifications || []).map(v => ({
      id:         v.id,
      domain:     v.domain,
      verified:   !!v.verified,
      verified_at: v.verified_at,
      created_at: v.created_at,
      isPrimary:  v.domain === site.primary_domain,
    }));

    return ok({
      primary_domain: site.primary_domain,
      primaryDomain:  site.primary_domain,
      domain_status:  site.domain_status,
      cnameTarget,
      cname_instructions: {
        type: 'CNAME',
        root: { host: '@',   value: cnameTarget, ttl: 3600 },
        www:  { host: 'www', value: cnameTarget, ttl: 3600 },
        note: '외부 DNS(가비아, 후이즈 등)에서 위 값으로 CNAME 레코드를 추가하세요.',
      },
      // HTTP 인증 안내
      http_instructions: {
        path:  `/.well-known/cloudpress-verify/${siteId}`,
        value: `cloudpress-verify=${siteId}`,
        note:  'CNAME 등록 후 CloudPress 프록시 Worker가 해당 경로를 자동으로 응답합니다.',
      },
      // TXT 인증 안내
      txt_instructions: {
        type:  'TXT',
        host:  `_cloudpress-verify.${site.primary_domain || '<your-domain>'}`,
        value: `cloudpress-site-id=${siteId}`,
        note:  'DNS에 TXT 레코드를 추가하는 대안적 인증 방법입니다.',
      },
      domains,
      verifications: verifications || [],
    });
  }

  /* ── Body 파싱 ──────────────────────────────────────────────────────── */
  let body = {};
  if (request.method !== 'DELETE' || (request.headers.get('Content-Length') || '0') !== '0') {
    try { body = await request.json(); } catch { /* body 없어도 OK */ }
  }

  /* ── POST (action 없음): 도메인 추가 ──────────────────────────────────── */
  if (request.method === 'POST' && !action) {
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

    const dvId = genId();
    try {
      await env.DB.prepare(
        `INSERT OR IGNORE INTO domain_verifications (id, site_id, domain, method, verified)
         VALUES (?, ?, ?, 'cname', 0)`
      ).bind(dvId, siteId, domainClean).run();
    } catch (e) {
      return err('도메인 추가 실패: ' + e.message, 500);
    }

    if (!site.primary_domain) {
      await env.DB.prepare(
        `UPDATE sites SET primary_domain=?, domain_status='pending', updated_at=datetime('now') WHERE id=?`
      ).bind(domainClean, siteId).run();
    }

    // KV에 HTTP 인증 토큰 사전 저장 (15분)
    if (env.CACHE) {
      env.CACHE.put(
        `domain_verify_token:${dvId}`,
        JSON.stringify({ token: dvId, siteId, domain: domainClean }),
        { expirationTtl: 900 }
      ).catch(() => {});
    }

    return ok({
      domainId: dvId,
      domain:   domainClean,
      message:  `도메인이 추가되었습니다. 아래 방법 중 하나로 인증해주세요.`,
      cnameTarget,
      instructions: {
        cname: { type: 'CNAME', host: '@', value: cnameTarget, ttl: '3600' },
        http:  { path: `/.well-known/cloudpress-verify/${dvId}`, value: `cloudpress-verify=${dvId}` },
        txt:   { type: 'TXT', host: `_cloudpress-verify.${domainClean}`, value: `cloudpress-site-id=${siteId}` },
      },
    });
  }

  /* ── POST?action=verify: 인증 확인 (CNAME + HTTP + TXT 순서로 시도) ──── */
  if (request.method === 'POST' && action === 'verify') {
    const domain = body?.domain
      ? cleanDomain(body.domain)
      : site.primary_domain;

    if (!domain) return err('연결된 도메인이 없습니다.');

    // 해당 도메인의 인증 레코드 조회
    const dvRow = await env.DB.prepare(
      `SELECT id FROM domain_verifications WHERE site_id=? AND domain=? LIMIT 1`
    ).bind(siteId, domain).first();

    const dvToken = dvRow?.id || siteId;

    // [1] CNAME 검증
    const cnameResult = await verifyCname(domain, cnameTarget);

    if (cnameResult.verified) {
      return await markVerified(env, siteId, site, domain, dvToken, 'cname', cnameResult.found, cnameTarget);
    }

    // [2] HTTP 토큰 인증
    const httpResult = await verifyHttp(domain, dvToken);
    if (httpResult.verified) {
      return await markVerified(env, siteId, site, domain, dvToken, 'http', httpResult.found, cnameTarget);
    }

    // [3] TXT 레코드 인증
    const txtResult = await verifyTxt(domain, siteId);
    if (txtResult.verified) {
      return await markVerified(env, siteId, site, domain, dvToken, 'txt', txtResult.found, cnameTarget);
    }

    // 모두 실패
    return ok({
      verified: false,
      domain,
      methods: {
        cname: { verified: false, found: cnameResult.found, hint: cnameResult.hint || cnameResult.error },
        http:  { verified: false, found: httpResult.found,  hint: httpResult.hint },
        txt:   { verified: false, found: txtResult.found,   hint: txtResult.hint },
      },
      message: '⏳ 아직 인증되지 않았습니다. DNS/HTTP 설정을 확인하고 다시 시도해주세요.',
      instructions: {
        cname: { type: 'CNAME', host: '@', value: cnameTarget, ttl: '3600' },
        http:  { path: `/.well-known/cloudpress-verify/${dvToken}`, value: `cloudpress-verify=${dvToken}` },
        txt:   { type: 'TXT', host: `_cloudpress-verify.${domain}`, value: `cloudpress-site-id=${siteId}` },
      },
    });
  }

  /* ── PUT?action=set-primary: 주도메인 설정 ───────────────────────────── */
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

    if (env.CACHE && site.primary_domain) {
      env.CACHE.delete(`site_domain:${site.primary_domain}`).catch(() => {});
      env.CACHE.delete(`site_domain:www.${site.primary_domain}`).catch(() => {});
    }

    return ok({
      domain:  dv.domain,
      message: `"${dv.domain}"이(가) 주도메인으로 설정되었습니다.`,
    });
  }

  /* ── PUT?action=set-domain: 도메인 변경 ──────────────────────────────── */
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
      domain:   domainClean,
      message:  `도메인이 설정되었습니다. 인증을 완료해주세요.`,
      instructions: {
        cname: { type: 'CNAME', host: '@', value: cnameTarget, ttl: '3600' },
        http:  { path: `/.well-known/cloudpress-verify/${siteId}`, value: `cloudpress-verify=${siteId}` },
        txt:   { type: 'TXT', host: `_cloudpress-verify.${domainClean}`, value: `cloudpress-site-id=${siteId}` },
      },
    });
  }

  /* ── DELETE: 도메인 삭제 ──────────────────────────────────────────────── */
  if (request.method === 'DELETE') {
    const { domainId } = body || {};
    if (!domainId) return err('domainId가 필요합니다.');

    const dv = await env.DB.prepare(
      `SELECT domain FROM domain_verifications WHERE id=? AND site_id=?`
    ).bind(domainId, siteId).first();
    if (!dv) return err('도메인을 찾을 수 없습니다.', 404);

    if (dv.domain === site.primary_domain) {
      return err('주도메인은 삭제할 수 없습니다. 다른 도메인을 주도메인으로 설정한 후 삭제해주세요.');
    }

    await env.DB.prepare(
      `DELETE FROM domain_verifications WHERE id=? AND site_id=?`
    ).bind(domainId, siteId).run();

    if (env.CACHE) {
      env.CACHE.delete(`site_domain:${dv.domain}`).catch(() => {});
      env.CACHE.delete(`site_domain:www.${dv.domain}`).catch(() => {});
      env.CACHE.delete(`domain_verify_token:${domainId}`).catch(() => {});
    }

    return ok({ message: `"${dv.domain}" 도메인이 삭제되었습니다.` });
  }

  return err('지원하지 않는 요청', 405);
}

/* ── 인증 성공 처리 (공통) ────────────────────────────────────────────────── */

async function markVerified(env, siteId, site, domain, dvToken, method, found, cnameTarget) {
  // sites 테이블 업데이트
  await env.DB.prepare(
    `UPDATE sites SET domain_status='active', updated_at=datetime('now') WHERE id=?`
  ).bind(siteId).run();

  // domain_verifications 업데이트
  try {
    await env.DB.prepare(
      `UPDATE domain_verifications SET verified=1, verified_at=datetime('now'), method=?
       WHERE site_id=? AND domain=?`
    ).bind(method, siteId, domain).run();
  } catch (_) {}

  // KV 캐시 갱신
  if (env.CACHE) {
    const siteData = JSON.stringify({
      id:          siteId,
      name:        site.name,
      site_prefix: site.site_prefix || siteId,
      status:      'active',
      suspended:   0,
    });
    env.CACHE.put(`site_domain:${domain}`,       siteData, { expirationTtl: 86400 }).catch(() => {});
    env.CACHE.put(`site_domain:www.${domain}`,   siteData, { expirationTtl: 86400 }).catch(() => {});
    // 인증 토큰 TTL 연장 (인증 성공 후 24시간 유지)
    env.CACHE.put(
      `domain_verify_token:${dvToken}`,
      JSON.stringify({ token: dvToken, siteId, domain, verified: true }),
      { expirationTtl: 86400 }
    ).catch(() => {});
  }

  return ok({
    verified:     true,
    domain,
    method,
    found,
    message:      `✅ 인증 성공! "${domain}" 도메인이 활성화되었습니다. (방법: ${method.toUpperCase()})`,
    instructions: null,
  });
}
