// functions/api/sites/[id]/domains.js — CloudPress
// 사이트 도메인 관리 (GET/POST/PUT/DELETE)

import { ok, err, getUser, loadAllSettings, settingVal } from '../../_shared.js';

export const onRequestOptions = () => new Response(null, { status: 204, headers: {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
}});

// GET: 도메인 목록 조회
export async function onRequestGet(ctx) {
  const { id: siteId } = ctx.params;
  const { env, request } = ctx;

  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  try {
    // 사이트 소유권 확인
    const site = await env.DB.prepare(
      `SELECT id, primary_domain, site_prefix, worker_name, cf_zone_id
       FROM sites WHERE id=? AND (user_id=? OR ?='admin') AND deleted_at IS NULL`
    ).bind(siteId, user.id, user.role).first();
    if (!site) return err('사이트를 찾을 수 없습니다.', 404);

    const settings = await loadAllSettings(env.DB);
    const workerName = site.worker_name || '';
    const workerSubdomain = workerName ? `${workerName}.workers.dev` : '';

    // 도메인 목록 구성 (primary_domain 기반)
    const domains = [];
    if (site.primary_domain) {
      domains.push({
        id: 'primary',
        domain: site.primary_domain,
        status: 'active',
        is_primary: true,
        type: 'custom',
      });
    }

    return ok({
      domains,
      subdomain: workerSubdomain,
      primaryDomain: site.primary_domain || null,
      sitePrefix: site.site_prefix || '',
    });
  } catch (e) {
    return err('도메인 목록 조회 실패: ' + e.message, 500);
  }
}

// POST: 도메인 추가 또는 DNS 레코드 추가
export async function onRequestPost(ctx) {
  const { id: siteId } = ctx.params;
  const { env, request } = ctx;

  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  let body;
  try { body = await request.json(); } catch { return err('잘못된 요청'); }

  const { action, domain, type, content } = body || {};

  // 사이트 소유권 확인
  const site = await env.DB.prepare(
    `SELECT id, primary_domain, site_prefix, worker_name, cf_zone_id, user_id
     FROM sites WHERE id=? AND (user_id=? OR ?='admin') AND deleted_at IS NULL`
  ).bind(siteId, user.id, user.role).first();
  if (!site) return err('사이트를 찾을 수 없습니다.', 404);

  const settings = await loadAllSettings(env.DB);

  // DNS 레코드 직접 추가
  if (action === 'add_dns_record') {
    const cfToken = settingVal(settings, 'cf_api_token');
    if (!cfToken) return err('Cloudflare API 토큰이 설정되지 않았습니다.', 400);
    if (!domain || !type || !content) return err('domain, type, content 필수');

    const zoneRes = await fetch(
      `https://api.cloudflare.com/client/v4/zones?name=${domain.split('.').slice(-2).join('.')}`,
      { headers: { 'Authorization': `Bearer ${cfToken}`, 'Content-Type': 'application/json' } }
    );
    const zoneData = await zoneRes.json();
    if (!zoneData.success || !zoneData.result?.length) return err('Cloudflare Zone을 찾을 수 없습니다.');

    const zoneId = zoneData.result[0].id;
    const dnsRes = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${cfToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, name: domain, content, proxied: true }),
    });
    const dnsData = await dnsRes.json();
    if (dnsData.success) return ok({ message: 'DNS 레코드가 추가되었습니다.', result: dnsData.result });
    return err('DNS 반영 실패: ' + (dnsData.errors?.[0]?.message || '알 수 없는 오류'));
  }

  // 도메인 추가 (primary_domain 변경)
  if (action === 'add' || !action) {
    const newDomain = (domain || '').trim().toLowerCase().replace(/^https?:\/\//,'').replace(/\/.*$/,'');
    if (!newDomain || !newDomain.includes('.')) return err('올바른 도메인을 입력해주세요.');

    // 중복 확인
    const dup = await env.DB.prepare(
      "SELECT id FROM sites WHERE primary_domain=? AND id!=? AND deleted_at IS NULL"
    ).bind(newDomain, siteId).first();
    if (dup) return err('이미 사용 중인 도메인입니다.');

    await env.DB.prepare(
      "UPDATE sites SET primary_domain=?, domain_status='pending', updated_at=datetime('now') WHERE id=?"
    ).bind(newDomain, siteId).run();

    return ok({ domain: newDomain, auto_connected: false, message: '도메인이 추가되었습니다.' });
  }

  // 도메인 연결 확인 (verify)
  if (action === 'verify') {
    return ok({ verified: false, message: 'DNS 전파 확인 중입니다. 잠시 후 다시 시도해주세요.' });
  }

  return err('지원하지 않는 action입니다.', 400);
}

// PUT: 주도메인 설정
export async function onRequestPut(ctx) {
  const { id: siteId } = ctx.params;
  const { env, request } = ctx;

  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  let body;
  try { body = await request.json(); } catch { return err('잘못된 요청'); }

  const { action, domain } = body || {};

  if (action === 'set-primary' && domain) {
    await env.DB.prepare(
      "UPDATE sites SET primary_domain=?, updated_at=datetime('now') WHERE id=? AND (user_id=? OR ?='admin')"
    ).bind(domain, siteId, user.id, user.role).run();
    return ok({ message: '주도메인이 변경되었습니다.' });
  }

  return err('지원하지 않는 요청입니다.', 400);
}

// DELETE: 도메인 삭제
export async function onRequestDelete(ctx) {
  const { id: siteId } = ctx.params;
  const { env, request } = ctx;

  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  // primary_domain만 있으므로 NULL로 초기화
  await env.DB.prepare(
    "UPDATE sites SET primary_domain=NULL, domain_status='pending', updated_at=datetime('now') WHERE id=? AND (user_id=? OR ?='admin')"
  ).bind(siteId, user.id, user.role).run();

  return ok({ message: '도메인이 삭제되었습니다.' });
}
