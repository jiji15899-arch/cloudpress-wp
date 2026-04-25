// functions/api/support.js
import { ok, err, getUser, loadAllSettings, settingVal } from '../_shared.js';

export async function onRequestPost(ctx) {
  const { request, env, db } = ctx;
  const user = await getUser(env, request); // User might be logged in or not

  const { subject, message, email } = await request.json();

  if (!subject || !message || !email) {
    return err('제목, 내용, 이메일 주소를 모두 입력해주세요.', 400);
  }

  try {
    const userId = user ? user.id : null;
    await db.prepare(
      'INSERT INTO support_tickets (user_id, subject, message, email, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)'
    ).bind(userId, subject, message, email).run();

    // --- Email Notification to Admin ---
    const settings = await loadAllSettings(db);
    // 'admin_contact_email' 설정 키를 추가하여 관리자 이메일을 가져옵니다.
    const adminEmail = settingVal(settings, 'admin_contact_email', 'admin@cloudpress.site'); 

    // 이메일 발송 서비스 (예: SendGrid, Mailgun) 또는 별도의 이메일 발송 Worker를 통해 이메일을 보냅니다.
    // 아래 코드는 예시이며, 실제 이메일 서비스 API 호출 로직으로 대체해야 합니다.
    await fetch('https://your-email-sending-service.workers.dev/send', { // 가상의 이메일 발송 서비스 URL
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        to: adminEmail,
        from: 'no-reply@cloudpress.site', // 발신 이메일 주소
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
