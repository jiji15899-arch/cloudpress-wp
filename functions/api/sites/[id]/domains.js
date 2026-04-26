import { 
  CORS, ok, err, getUser, 
  cfUpsertDns, getWorkerSubdomain 
} from '../../_shared.js';

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

export async function onRequestPost({ request, env, params }) {
  const { id: siteId } = params;
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  let body;
  try { body = await request.json(); } catch { return err('잘못된 요청'); }

  const { action, domain } = body || {};
  if (!domain) return err('도메인을 입력해주세요.');

  if (action === 'add_alias') {
    // 1. 사이트 및 사용자 CF 정보 조회
    const site = await env.DB.prepare(
      "SELECT s.*, u.cf_global_api_key, u.cf_account_email FROM sites s JOIN users u ON s.user_id = u.id WHERE s.id = ?"
    ).bind(siteId).first();

    if (!site) return err('존재하지 않는 사이트입니다.', 404);
    if (site.user_id !== user.id && user.role !== 'admin') return err('권한이 없습니다.', 403);

    // 2. DB 업데이트 (JSON 배열 관리)
    let aliases = [];
    try { aliases = JSON.parse(site.alias_domains || '[]'); } catch(e) { aliases = []; }

    if (!aliases.includes(domain)) {
      aliases.push(domain);
      await env.DB.prepare("UPDATE sites SET alias_domains = ? WHERE id = ?")
        .bind(JSON.stringify(aliases), siteId).run();
    }

    // 3. Cloudflare DNS 레코드 자동 생성 (CNAME)
    if (site.cf_global_api_key && site.cf_zone_id) {
      try {
        const targetHost = getWorkerSubdomain(env);
        await cfUpsertDns(env, site, site.cf_zone_id, {
          type: 'CNAME',
          name: domain,
          content: targetHost,
          proxied: true
        });
      } catch (dnsErr) {
        console.error('DNS 생성 실패:', dnsErr.message);
        return ok({ message: '도메인은 추가되었으나 DNS 설정에 실패했습니다. (수동 설정 필요)', error: dnsErr.message });
      }
    }

    return ok({ message: 'Alias 도메인이 추가되었으며 DNS 레코드가 생성되었습니다.', aliases });
  }

  if (action === 'remove_alias') {
    const site = await env.DB.prepare("SELECT alias_domains, user_id FROM sites WHERE id = ?")
      .bind(siteId).first();

    if (!site) return err('존재하지 않는 사이트입니다.', 404);
    if (site.user_id !== user.id && user.role !== 'admin') return err('권한이 없습니다.', 403);

    let aliases = [];
    try { aliases = JSON.parse(site.alias_domains || '[]'); } catch(e) { aliases = []; }

    const newAliases = aliases.filter(a => a !== domain);
    await env.DB.prepare("UPDATE sites SET alias_domains = ? WHERE id = ?")
      .bind(JSON.stringify(newAliases), siteId).run();

    return ok({ message: '도메인이 삭제되었습니다.', aliases: newAliases });
  }

  if (action === 'set_primary') {
    const site = await env.DB.prepare("SELECT user_id FROM sites WHERE id = ?").bind(siteId).first();

    if (!site) return err('존재하지 않는 사이트입니다.', 404);
    if (site.user_id !== user.id && user.role !== 'admin') return err('권한이 없습니다.', 403);

    await env.DB.prepare("UPDATE sites SET primary_domain = ? WHERE id = ?")
      .bind(domain, siteId).run();

    return ok({ message: '기본 도메인이 변경되었습니다.' });
  }

  return err('지원되지 않는 액션입니다.', 400);
}
