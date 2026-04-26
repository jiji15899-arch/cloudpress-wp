// functions/api/dns/zones.js — CloudPress DNS 관리 API v22.1
// 수정: 누락된 onRequestGet/onRequestPost 핸들러 복원,
//       cfReq dead-code 제거 및 빈 응답 방어 로직 추가

import { CORS, ok, err, getUser, loadAllSettings, settingVal } from '../_shared.js';

const CF_API = 'https://api.cloudflare.com/client/v4';

// CF 키 복호화 (user/index.js의 obfuscate와 동일한 XOR 방식)
function deobfuscate(str, salt) {
  if (!str) return '';
  try {
    const key = salt || 'cp_enc_v1';
    const decoded = atob(str);
    let result = '';
    for (let i = 0; i < decoded.length; i++) {
      result += String.fromCharCode(decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    }
    return result;
  } catch { return str; } // 복호화 실패 시 원문 그대로 (평문 키 호환)
}

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

function cfHeaders(token, email) {
  if (email) return { 'Content-Type': 'application/json', 'X-Auth-Key': token, 'X-Auth-Email': email };
  return { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token };
}

// Cloudflare API 공통 요청 — 빈 body / HTML 응답 방어
async function cfReq(auth, path, method = 'GET', body) {
  const opts = { method, headers: cfHeaders(auth.token, auth.email) };
  if (body !== undefined) opts.body = JSON.stringify(body);
  try {
    const res = await fetch(CF_API + path, opts);
    const ct = res.headers.get('content-type') || '';
    if (!ct.includes('application/json')) {
      return { success: false, errors: [{ message: `Cloudflare API가 JSON이 아닌 응답을 반환했습니다 (Status: ${res.status})` }] };
    }
    const text = await res.text();
    if (!text || !text.trim()) {
      return { success: res.ok };
    }
    try {
      return JSON.parse(text);
    } catch {
      return { success: false, errors: [{ message: 'Cloudflare 응답 파싱 오류: ' + text.slice(0, 100) }] };
    }
  } catch (e) {
    return { success: false, errors: [{ message: 'Cloudflare 통신 오류: ' + e.message }] };
  }
}

function cfErrMsg(json) {
  return (json?.errors || []).map(e => (e.code ? `[${e.code}] ` : '') + (e.message || '')).join('; ') || '알 수 없는 오류';
}

async function getAuth(env, userId) {
  let userRow;
  try {
    userRow = await env.DB.prepare(
      'SELECT cf_global_api_key, cf_account_email, cf_account_id FROM users WHERE id=?'
    ).bind(userId).first();
  } catch {}

  let settings = {};
  try {
    settings = await loadAllSettings(env.DB);
  } catch {}

  // DB에 저장된 키는 XOR 난독화된 상태 — 복호화 후 사용
  const rawToken = userRow?.cf_global_api_key || settingVal(settings, 'cf_api_token');
  const token = rawToken ? deobfuscate(rawToken, env.ENCRYPTION_KEY || 'cp_enc_default') : null;
  const email = userRow?.cf_account_email  || settingVal(settings, 'cf_account_email');
  const accountId = userRow?.cf_account_id || settingVal(settings, 'cf_account_id');

  if (!token) return null;
  return { token, email: email || undefined, accountId: accountId || undefined };
}

// ── GET /api/dns/zones ─────────────────────────────────────────────────────────
export async function onRequestGet({ request, env }) {
  if (!env?.DB) return err('서버 설정 오류', 503);

  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  const auth = await getAuth(env, user.id);
  if (!auth) return err('Cloudflare API 키가 설정되지 않았습니다. 내 계정에서 Global API Key를 등록해주세요.', 400);

  const url = new URL(request.url);
  const domainFilter = url.searchParams.get('domain');

  try {
    let page = 1;
    let allZones = [];
    while (true) {
      const qs = domainFilter
        ? `/zones?name=${encodeURIComponent(domainFilter)}&per_page=50&page=${page}`
        : `/zones?per_page=50&page=${page}`;
      const res = await cfReq(auth, qs);
      if (!res.success) {
        const cfMsg = cfErrMsg(res);
        // 인증 오류인 경우 더 명확한 안내
        const isAuthErr = (res.errors || []).some(e => e.code === 9103 || e.code === 10000 || String(e.message).toLowerCase().includes('auth'));
        if (isAuthErr) return err('Cloudflare 인증 실패: API 키 또는 이메일을 확인해주세요. (' + cfMsg + ')', 401);
        return err('Cloudflare 존 목록 조회 실패: ' + cfMsg, 502);
      }
      const zones = res.result || [];
      allZones = allZones.concat(zones.map(z => ({
        id: z.id,
        name: z.name,
        status: z.status,
        nameservers: z.name_servers || [],
        plan: z.plan?.name || '',
        created_on: z.created_on,
      })));
      if (zones.length < 50) break;
      page++;
      if (page > 20) break;
    }

    if (domainFilter && allZones.length > 0) {
      return ok({ nameservers: allZones[0].nameservers, zone: allZones[0] });
    }

    return ok({ zones: allZones });
  } catch (e) {
    return err('존 목록 조회 중 오류: ' + e.message, 500);
  }
}

// ── POST /api/dns/zones ────────────────────────────────────────────────────────
export async function onRequestPost({ request, env }) {
  if (!env?.DB) return err('서버 설정 오류', 503);

  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  let body;
  try { body = await request.json(); } catch { return err('잘못된 요청 형식입니다.', 400); }

  const name = (body.name || '').trim().toLowerCase().replace(/^https?:\/\//i, '').replace(/\/.*/,'');
  if (!name || !name.includes('.')) return err('올바른 도메인 이름을 입력해주세요. (예: example.com)', 400);

  const auth = await getAuth(env, user.id);
  if (!auth) return err('Cloudflare API 키가 설정되지 않았습니다. 내 계정에서 Global API Key를 등록해주세요.', 400);

  if (!auth.accountId) return err('Cloudflare Account ID가 설정되지 않았습니다. 내 계정에서 Account ID를 등록해주세요.', 400);

  try {
    const res = await cfReq(auth, '/zones', 'POST', {
      name,
      account: { id: auth.accountId },
      jump_start: true,
      type: 'full',
    });

    if (!res.success) {
      const errMsg = cfErrMsg(res);
      // 이미 존재하는 존이면 기존 네임서버 반환
      if ((res.errors || []).some(e => e.code === 1061 || String(e.message).includes('already exists'))) {
        const existing = await cfReq(auth, `/zones?name=${encodeURIComponent(name)}`);
        if (existing.success && existing.result?.length > 0) {
          const zone = existing.result[0];
          return ok({
            zone: { id: zone.id, name: zone.name, status: zone.status },
            nameservers: zone.name_servers || [],
            message: '이미 등록된 도메인입니다. 네임서버 정보를 반환합니다.',
          });
        }
      }
      return err('도메인 추가 실패: ' + errMsg, 502);
    }

    const zone = res.result;
    return ok({
      zone: { id: zone.id, name: zone.name, status: zone.status },
      nameservers: zone.name_servers || [],
    }, 201);
  } catch (e) {
    return err('도메인 추가 중 오류: ' + e.message, 500);
  }
}
