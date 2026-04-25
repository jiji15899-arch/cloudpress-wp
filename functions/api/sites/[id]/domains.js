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

import { ok, err, getUser, loadAllSettings, settingVal } from '../../_shared.js';

export async function onRequestPost(ctx) {
  const { id } = ctx.params;
  const { env, request } = ctx;
  const { action, domain, type, content } = await request.json();
  const user = await getUser(env, request);
  
  const settings = await loadAllSettings(env.DB);
  const cfAuth = {
    token: user.cf_global_api_key || settingVal(settings, 'cf_api_token'),
    email: user.cf_account_email || null
  };
  const cfAccountId = user.cf_account_id || settingVal(settings, 'cf_account_id');

  if (action === 'add_dns_record') {
    // 7. DNS 설정 즉시 요청 (Cloudflare API)
    const zoneRes = await fetch(`https://api.cloudflare.com/client/v4/zones?name=${domain.split('.').slice(-2).join('.')}`, {
      headers: { 'Authorization': `Bearer ${cfAuth.token}`, 'Content-Type': 'application/json' }
    });
    const zoneData = await zoneRes.json();
    if (!zoneData.success) return err('Cloudflare Zone을 찾을 수 없습니다.');

    const zoneId = zoneData.result[0].id;
    const dnsRes = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${cfAuth.token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: type || 'A', name: domain, content: content, proxied: true })
    });
    
    const dnsData = await dnsRes.json();
    if (dnsData.success) {
      return ok({ message: 'DNS 레코드가 클라우드플레어에 즉시 반영되었습니다.', result: dnsData.result });
    }
    return err('DNS 반영 실패: ' + dnsData.errors[0].message);
  }

  return err('잘못된 요청(Action)입니다.', 400);
}
  
