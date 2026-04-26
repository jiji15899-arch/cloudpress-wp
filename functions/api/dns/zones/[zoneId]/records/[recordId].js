// functions/api/dns/zones/[zoneId]/records/[recordId].js
// PUT(수정) / DELETE(삭제) — recordId 라우팅 파일
// records.js에서 URL 파싱으로 처리하던 것을 Cloudflare Pages 파일 라우팅으로 올바르게 분리

import { CORS, ok, err, getUser } from '../../../../_shared.js';

const CF_API = 'https://api.cloudflare.com/client/v4';

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
  } catch { return str; }
}

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
      return { success: false, errors: [{ message: `CF API 비JSON 응답 (${res.status})` }] };
    }
    const text = await res.text();
    if (!text || !text.trim()) return { success: res.ok };
    try { return JSON.parse(text); } catch {
      return { success: false, errors: [{ message: 'CF 응답 파싱 오류: ' + text.slice(0, 100) }] };
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

  const rawToken = userRow?.cf_global_api_key || settings['cf_api_token'] || '';
  const token = rawToken ? deobfuscate(rawToken, env.ENCRYPTION_KEY || 'cp_enc_default') : '';
  const email = userRow?.cf_account_email || settings['cf_account_email'] || '';
  if (!token) return null;
  return { token, email: email || undefined };
}

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

export async function onRequest({ request, env, params }) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  const { zoneId, recordId } = params;
  if (!zoneId) return err('Zone ID가 필요합니다.', 400);
  if (!recordId) return err('Record ID가 필요합니다.', 400);

  const auth = await getAuth(env, user.id);
  if (!auth) return err('Cloudflare API 키가 설정되지 않았습니다.', 400);

  // ── PUT: 레코드 수정 ───────────────────────────────────────────────────────
  if (request.method === 'PUT') {
    let body;
    try { body = await request.json(); } catch {
      return err('잘못된 JSON 형식입니다.', 400);
    }
    const { type, name, content, ttl = 1, proxied = false, priority } = body;
    if (!type || !name || !content) return err('type, name, content가 필요합니다.', 400);

    const record = { type, name, content, ttl };
    if (['A', 'AAAA', 'CNAME'].includes(type)) record.proxied = !!proxied;
    if (['MX', 'SRV', 'CAA'].includes(type) && priority !== undefined) record.priority = priority;

    const res = await cfReq(auth, `/zones/${zoneId}/dns_records/${recordId}`, 'PUT', record);
    if (!res.success) return err('레코드 수정 실패: ' + cfErrMsg(res), 502);
    return ok({ record: res.result });
  }

  // ── DELETE: 레코드 삭제 ────────────────────────────────────────────────────
  if (request.method === 'DELETE') {
    const res = await cfReq(auth, `/zones/${zoneId}/dns_records/${recordId}`, 'DELETE');
    if (!res.success) return err('레코드 삭제 실패: ' + cfErrMsg(res), 502);
    return ok({ deleted: recordId });
  }

  return err('허용되지 않는 메서드', 405);
}
