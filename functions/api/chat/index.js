// functions/api/chat/index.js — CloudPress 상담봇 API
// 사용자 문의 접수, 어드민 조회/답변/종료

import { CORS, ok, err, getUser, requireAdmin } from '../_shared.js';

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

function genId() {
  return 'tkt_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

export async function onRequest({ request, env }) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  const url = new URL(request.url);
  const type = url.searchParams.get('type');

  // ── 어드민 전용: 전체 문의 목록 ───────────────────────────────────────────
  if (type === 'admin') {
    const admin = await requireAdmin(env, request);
    if (!admin) return err('관리자 권한이 필요합니다.', 403);

    try {
      const res = await env.DB.prepare(`
        SELECT t.id, t.message, t.reply, t.status, t.created_at, t.replied_at,
               u.name AS user_name, u.email AS user_email
        FROM chat_tickets t
        LEFT JOIN users u ON t.user_id = u.id
        ORDER BY t.created_at DESC
        LIMIT 200
      `).all();
      return ok({ tickets: res.results || [] });
    } catch (e) {
      return err('DB 오류: ' + e.message, 500);
    }
  }

  // ── 사용자: 내 문의 목록 ─────────────────────────────────────────────────
  if (type === 'tickets' || (request.method === 'GET' && !type)) {
    const user = await getUser(env, request);
    if (!user) return err('로그인이 필요합니다.', 401);
    try {
      const res = await env.DB.prepare(`
        SELECT id, message, reply, status, created_at, replied_at
        FROM chat_tickets WHERE user_id=?
        ORDER BY created_at DESC LIMIT 50
      `).bind(user.id).all();
      return ok({ tickets: res.results || [] });
    } catch (e) {
      return err('DB 오류: ' + e.message, 500);
    }
  }

  // ── POST: 새 문의 접수 ────────────────────────────────────────────────────
  if (request.method === 'POST') {
    const user = await getUser(env, request);
    if (!user) return err('로그인이 필요합니다.', 401);

    let body;
    try { body = await request.json(); } catch { return err('잘못된 요청', 400); }

    const { message } = body;
    if (!message || message.trim().length < 2) return err('문의 내용을 입력해주세요.', 400);
    if (message.length > 2000) return err('문의 내용은 2000자 이하로 입력해주세요.', 400);

    const id = genId();
    try {
      await env.DB.prepare(`
        INSERT INTO chat_tickets (id, user_id, message, status, created_at)
        VALUES (?, ?, ?, 'open', datetime('now'))
      `).bind(id, user.id, message.trim()).run();

      // KV에 미읽음 카운트 증가 (어드민 알림용)
      if (env.SESSIONS) {
        try {
          const cur = parseInt(await env.SESSIONS.get('admin:unread_tickets') || '0', 10);
          await env.SESSIONS.put('admin:unread_tickets', String(cur + 1), { expirationTtl: 86400 * 7 });
        } catch {}
      }

      return ok({ ticketId: id }, 201);
    } catch (e) {
      return err('문의 접수 실패: ' + e.message, 500);
    }
  }

  return err('허용되지 않는 메서드', 405);
}
