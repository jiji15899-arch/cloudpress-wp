// functions/api/dns/zones.js — CloudPress DNS 관리 API v22.0
// 수정: CF 자격증명 없을 때 명확한 에러 반환, 존 추가 시 사용자 자격증명 우선

import { CORS, _j, ok, err, getUser, loadAllSettings, settingVal } from '../_shared.js';

const CF_API = 'https://api.cloudflare.com/client/v4';

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

function cfHeaders(token, email) {
  if (email) return { 'Content-Type': 'application/json', 'X-Auth-Key': token, 'X-Auth-Email': email };
  return { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token };
}

async function cfReq(auth, path, method = 'GET', body) {
  const opts = { method, headers: cfHeaders(auth.token, auth.email) };
  if (body !== undefined) opts.body = JSON.stringify(body);
  try {
    const res = await fetch(CF_API + path, opts);
    const contentType = res.headers.get('content-type') || '';
    
    if (!contentType.includes('application/json')) {
      const text = await res.text();
      console.error('Cloudflare API returned HTML:', text.substring(0, 200));
      return { success: false, errors: [{ message: 'Cloudflare API가 HTML 응답을 반환했습니다. API 토큰 권한을 확인하세요.' }] };
    }
    
    return await res.json();
  } catch (e) {
    return { success: false, errors: [{ message: 'Cloudflare 통신 오류: ' + e.message }] };
  }
}
