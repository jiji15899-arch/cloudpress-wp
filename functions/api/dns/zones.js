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
    const text = await res.text();
    try {
      return JSON.parse(text);
    } catch {
      return { success: false, errors: [{ code: 0, message: 'Cloudflare API가 JSON이 아닌 응답을 반환했습니다. API 키를 확인해주세요.' }] };
    }
  } catch (e) {
    return { success: false, errors: [{ code: 0, message: e.message }] };
  }
}

// Cloudflare 에러 코드 한국어 매핑
const CF_ERROR_MAP = {
  '1061': '이미 Cloudflare에 등록된 도메인입니다.',
  '1049': '올바른 도메인 형식이 아니거나 권한이 없는 도메인입니다.',
  '10000': '인증 오류: API 키를 다시 확인해주세요.',
  '6003': '잘못된 이메일 또는 API 키 형식입니다.',
  '81057': '동일한 이름의 레코드가 이미 존재합니다.',
  'default': 'Cloudflare 통신 중 오류가 발생했습니다.'
};

function cfErrMsg(json) {
  if (!json?.errors?.length) return CF_ERROR_MAP.default;
  return json.errors.map(e => {
    return CF_ERROR_MAP[String(e.code)] || e.message || CF_ERROR_MAP.default;
  }).join(', ');
}

export async function onRequest({ request, env }) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  // 사용자 CF 자격증명 조회 + 설정 병렬 조회
  let userRow, settings = {};
  try {
    const [userRes, settingsRes] = await env.DB.batch([
      env.DB.prepare('SELECT cf_global_api_key, cf_account_email, cf_account_id FROM users WHERE id=?').bind(user.id),
      env.DB.prepare('SELECT key, value FROM settings'),
    ]);
    userRow = userRes.results?.[0] ?? null;
    for (const r of settingsRes.results || []) settings[r.key] = r.value;
  } catch (e) {
    return err('DB 조회 오류: ' + e.message, 500);
  }

  const cfToken = userRow?.cf_global_api_key || settingVal(settings, 'cf_api_token') || '';
  const cfEmail = userRow?.cf_account_email  || settingVal(settings, 'cf_account_email') || '';
  const cfAccId = userRow?.cf_account_id     || settingVal(settings, 'cf_account_id') || '';

  if (!cfToken) {
    return err('Cloudflare API 키가 설정되지 않았습니다. "내 계정 > Cloudflare 설정"에서 Global API Key와 Account ID를 등록해주세요.', 400);
  }
  if (!cfAccId) {
    return err('Cloudflare Account ID가 설정되지 않았습니다. "내 계정 > Cloudflare 설정"에서 Account ID를 등록해주세요.', 400);
  }

  const auth = { token: cfToken, email: cfEmail || undefined };

  // ── GET: 존 목록 조회 ─────────────────────────────────────────────────────
  if (request.method === 'GET') {
    let allZones = [];
    let page = 1;
    while (true) {
      const res = await cfReq(auth, `/zones?per_page=50&page=${page}&account.id=${encodeURIComponent(cfAccId)}`);
      if (!res.success) return err('Cloudflare 존 조회 실패: ' + cfErrMsg(res), 502);
      const items = res.result || [];
      allZones = allZones.concat(items.map(z => ({
        id: z.id,
        name: z.name,
        status: z.status,
        plan: { name: z.plan?.name || 'Free' },
        nameservers: z.name_servers || [],
        original_nameservers: z.original_name_servers || [],
        paused: z.paused,
        type: z.type,
        created_on: z.created_on,
      })));
      if (items.length < 50) break;
      page++;
      if (page > 10) break;
    }
    return ok({ zones: allZones, account_id: cfAccId });
  }

  // ── POST: 새 도메인(존) 추가 ──────────────────────────────────────────────
  if (request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return err('잘못된 요청 형식', 400); }
    const { name, plan = 'free' } = body;
    if (!name || !name.includes('.')) return err('올바른 도메인을 입력해주세요.', 400);

    const planMap = { free: { id: 'free' }, pro: { id: 'pro' }, business: { id: 'business' } };
    const res = await cfReq(auth, '/zones', 'POST', {
      name: name.toLowerCase().trim(),
      account: { id: cfAccId },
      jump_start: true,
      plan: planMap[plan] || { id: 'free' },
    });

    if (!res.success) {
      const errMsg = cfErrMsg(res);
      // 이미 존재하는 존이면 OK
      if (res.errors?.some(e => e.code === 1061 || String(e.code) === '1061')) {
        const listRes = await cfReq(auth, `/zones?name=${encodeURIComponent(name)}`);
        if (listRes.success && listRes.result?.[0]) {
          const z = listRes.result[0];
          return ok({ zone: { id: z.id, name: z.name, status: z.status }, nameservers: z.name_servers || [], existed: true });
        }
      }
      return err('도메인 추가 실패: ' + errMsg, 502);
    }

    const z = res.result;
    return ok({
      zone: { id: z.id, name: z.name, status: z.status },
      nameservers: z.name_servers || [],
    }, 201);
  }

  return err('허용되지 않는 메서드', 405);
}
