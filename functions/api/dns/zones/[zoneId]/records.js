// functions/api/dns/zones/[zoneId]/records.js — CloudPress DNS 레코드 API
// DNS 레코드 조회 / 추가 / 수정 / 삭제

import { CORS, ok, err, getUser } from '../../../_shared.js';

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
    const ct = res.headers.get('content-type') || '';
    if (!ct.includes('application/json')) {
      return { success: false, errors: [{ message: `Cloudflare API가 JSON이 아닌 응답을 반환했습니다 (Status: ${res.status})` }] };
    }
    const text = await res.text();
    if (!text || !text.trim()) return { success: res.ok };
    try { return JSON.parse(text); } catch {
      return { success: false, errors: [{ message: 'Cloudflare 응답 파싱 오류: ' + text.slice(0, 100) }] };
    }
  } catch (e) {
    return { success: false, errors: [{ message: e.message }] };
  }
}

function cfErrMsg(json) {
  return (json?.errors || []).map(e => (e.code ? `[${e.code}] ` : '') + (e.message || '')).join('; ') || 'unknown';
}

async function getAuth(env, userId) {
  let userRow;
  try {
    userRow = await env.DB.prepare(
      'SELECT cf_global_api_key, cf_account_email FROM users WHERE id=?'
    ).bind(userId).first();
  } catch {}

  let settings = {};
  try {
    const rows = await env.DB.prepare('SELECT key,value FROM settings').all();
    for (const r of rows.results || []) settings[r.key] = r.value;
  } catch {}

  const token = userRow?.cf_global_api_key || settings['cf_api_token'] || '';
  const email = userRow?.cf_account_email  || settings['cf_account_email'] || '';
  if (!token) return null;
  return { token, email: email || undefined };
}

export async function onRequest({ request, env, params }) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  const { zoneId } = params;
  if (!zoneId) return err('Zone ID가 필요합니다.', 400);

  const auth = await getAuth(env, user.id);
  if (!auth) return err('Cloudflare API 키가 설정되지 않았습니다.', 400);

  const url = new URL(request.url);
  // recordId는 URL에서 추출 (경로: /api/dns/zones/:zoneId/records/:recordId)
  const pathParts = url.pathname.split('/');
  const recordId = pathParts[pathParts.length - 1] !== 'records' ? pathParts[pathParts.length - 1] : null;

  // ── GET: 레코드 목록 ───────────────────────────────────────────────────────
  if (request.method === 'GET' && !recordId) {
    let all = [];
    let page = 1;
    while (true) {
      const res = await cfReq(auth, `/zones/${zoneId}/dns_records?per_page=100&page=${page}`);
      if (!res.success) return err('레코드 조회 실패: ' + cfErrMsg(res), 502);
      const items = res.result || [];
      all = all.concat(items.map(r => ({
        id: r.id,
        type: r.type,
        name: r.name,
        content: r.content,
        ttl: r.ttl,
        proxied: r.proxied,
        proxiable: r.proxiable,
        priority: r.priority,
        modified_on: r.modified_on,
      })));
      if (items.length < 100) break;
      page++;
      if (page > 10) break;
    }
    return ok({ records: all });
  }

  // ── POST: 레코드 추가 ──────────────────────────────────────────────────────
  if (request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return err('잘못된 요청', 400); }

    const { type, name, content, ttl = 1, proxied = false, priority } = body;
    if (!type || !name || !content) return err('type, name, content가 필요합니다.', 400);

    const record = { type, name, content, ttl };
    if (['A','AAAA','CNAME'].includes(type)) record.proxied = proxied;
    if (['MX','SRV','CAA'].includes(type) && priority !== undefined) record.priority = priority;

    const res = await cfReq(auth, `/zones/${zoneId}/dns_records`, 'POST', record);
    if (!res.success) return err('레코드 추가 실패: ' + cfErrMsg(res), 502);
    return ok({ record: res.result }, 201);
  }

  // ── PUT: 레코드 수정 ───────────────────────────────────────────────────────
  if (request.method === 'PUT' && recordId) {
    let body;
    try { body = await request.json(); } catch { return err('잘못된 요청', 400); }

    const { type, name, content, ttl = 1, proxied = false, priority } = body;
    if (!type || !name || !content) return err('type, name, content가 필요합니다.', 400);

    const record = { type, name, content, ttl };
    if (['A','AAAA','CNAME'].includes(type)) record.proxied = proxied;
    if (['MX','SRV','CAA'].includes(type) && priority !== undefined) record.priority = priority;

    const res = await cfReq(auth, `/zones/${zoneId}/dns_records/${recordId}`, 'PUT', record);
    if (!res.success) return err('레코드 수정 실패: ' + cfErrMsg(res), 502);
    return ok({ record: res.result });
  }

  // ── DELETE: 레코드 삭제 ────────────────────────────────────────────────────
  if (request.method === 'DELETE' && recordId) {
    const res = await cfReq(auth, `/zones/${zoneId}/dns_records/${recordId}`, 'DELETE');
    if (!res.success) return err('레코드 삭제 실패: ' + cfErrMsg(res), 502);
    return ok({ deleted: recordId });
  }

  return err('허용되지 않는 메서드', 405);
}
