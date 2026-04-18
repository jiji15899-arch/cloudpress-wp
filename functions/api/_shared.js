// functions/api/_shared.js — CloudPress 공통 유틸리티
// 모든 API 함수에서 import해서 사용합니다.

// ── CORS ─────────────────────────────────────────────────────────────────────
export const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};

// ── 응답 헬퍼 ────────────────────────────────────────────────────────────────
export const _j  = (d, s = 200) => new Response(JSON.stringify(d), {
  status: s, headers: { 'Content-Type': 'application/json', ...CORS },
});
export const ok  = (d = {}) => _j({ ok: true,  ...d });
export const err = (msg, s = 400) => _j({ ok: false, error: msg }, s);
export const handleOptions = () => new Response(null, { status: 204, headers: CORS });

// ── 인증 ─────────────────────────────────────────────────────────────────────
export function getToken(req) {
  const a = req.headers.get('Authorization') || '';
  if (a.startsWith('Bearer ')) return a.slice(7);
  const c = req.headers.get('Cookie') || '';
  const m = c.match(/cp_session=([^;]+)/);
  return m ? m[1] : null;
}

/**
 * 기본 사용자 정보 조회 (대부분의 API에서 사용)
 */
export async function getUser(env, req) {
  try {
    const t = getToken(req);
    if (!t) return null;
    const uid = await env.SESSIONS.get(`session:${t}`);
    if (!uid) return null;
    return await env.DB.prepare(
      'SELECT id,name,email,role,plan FROM users WHERE id=?'
    ).bind(uid).first();
  } catch { return null; }
}

/**
 * 확장 사용자 정보 조회 (user/index.js 전용 — 추가 컬럼 포함)
 */
export async function getUserFull(env, req) {
  try {
    const t = getToken(req);
    if (!t) return null;
    const uid = await env.SESSIONS.get(`session:${t}`);
    if (!uid) return null;
    return await env.DB.prepare(
      'SELECT id,name,email,role,plan,plan_expires_at,twofa_enabled,twofa_type,cf_account_email FROM users WHERE id=?'
    ).bind(uid).first();
  } catch { return null; }
}

export async function requireAuth(env, req) {
  return getUser(env, req);
}

export async function requireAdmin(env, req) {
  try {
    const t = getToken(req);
    if (!t) return null;
    const uid = await env.SESSIONS.get(`session:${t}`);
    if (!uid) return null;
    const user = await env.DB.prepare(
      'SELECT id,role FROM users WHERE id=?'
    ).bind(uid).first();
    return user?.role === 'admin' ? user : null;
  } catch { return null; }
}

export async function requireAdminOrMgr(env, req) {
  try {
    const t = getToken(req);
    if (!t) return null;
    const uid = await env.SESSIONS.get(`session:${t}`);
    if (!uid) return null;
    const user = await env.DB.prepare(
      'SELECT id,role FROM users WHERE id=?'
    ).bind(uid).first();
    return (user?.role === 'admin' || user?.role === 'manager') ? user : null;
  } catch { return null; }
}

// ── 암호화 ───────────────────────────────────────────────────────────────────
export async function hashPw(p) {
  const buf = await crypto.subtle.digest(
    'SHA-256', new TextEncoder().encode(p + ':cloudpress_salt_v3')
  );
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── ID 생성 ──────────────────────────────────────────────────────────────────
export function genId() {
  const ts  = Date.now().toString(36);
  const arr = crypto.getRandomValues(new Uint8Array(8));
  const rnd = Array.from(arr).map(b => b.toString(36).padStart(2, '0')).join('').slice(0, 10);
  return ts + rnd;
}

export function gen6() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// ── 설정 ─────────────────────────────────────────────────────────────────────
export async function loadAllSettings(DB) {
  try {
    const { results } = await DB.prepare('SELECT key, value FROM settings').all();
    const map = {};
    for (const r of results || []) map[r.key] = r.value ?? '';
    return map;
  } catch { return {}; }
}

export function settingVal(settings, key, fallback = '') {
  const v = settings[key];
  return (v != null && v !== '') ? v : fallback;
}
