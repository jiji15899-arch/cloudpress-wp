// functions/api/support.js
import { ok, err, getUser, loadAllSettings, settingVal } from '../../_shared.js';

export async function onRequestPost(ctx) {
  const { request, env } = ctx;
  const user = await getUser(env, request); // User might be logged in or not
  const { subject, message, email } = await request.json();

  if (!subject || !message || !email) {
    return err('제목, 내용, 이메일 주소를 모두 입력해주세요.', 400);
  }

  try {
    const userId = user ? user.id : null;

    await env.DB.prepare(
      'INSERT INTO support_tickets (user_id, subject, message, email, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)'
    ).bind(userId, subject, message, email).run();

    // --- Email Notification to Admin ---
    const settings = await loadAllSettings(env.DB);
    const adminEmail = settingVal(settings, 'admin_contact_email', 'admin@cloudpress.site');

    await fetch('https://your-email-sending-service.workers.dev/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        to: adminEmail,
        from: 'no-reply@cloudpress.site',
        subject: `[CloudPress 문의] ${subject}`,
        body: `새로운 문의가 접수되었습니다:\n\n발신자: ${email} (User ID: ${userId || 'Guest'})\n제목: ${subject}\n내용:\n${message}\n\n관리자 페이지에서 확인해주세요.`,
      }),
    });
    // --- End Email Notification ---

    return ok({ message: '문의가 성공적으로 접수되었습니다. 빠른 시일 내에 답변드리겠습니다.' });
  } catch (e) {
    console.error('문의 접수 오류:', e);
    return err('문의 접수 중 오류가 발생했습니다: ' + e.message, 500);
  }
}
