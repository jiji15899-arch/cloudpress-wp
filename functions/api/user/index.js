// functions/api/user/index.js
// 사용자 프로필 + CF Global API 키 + 2FA 관리

import { _j, ok, err, handleOptions, getUserFull as getUser, hashPw } from '../_shared.js';

/* 간단한 XOR 기반 API 키 난독화 (실제 암호화는 KV 또는 외부 서비스 사용 권장) */
function obfuscate(str, salt) {
  if (!str) return '';
  const key = salt || 'cp_enc_v1';
  let result = '';
  for (let i = 0; i < str.length; i++) {
    result += String.fromCharCode(str.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return btoa(result);
}
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
  } catch { return ''; }
}

/* Cloudflare Global API 키 유효성 검증 + 실제 Account ID 획득 */
async function verifyCfApiKey(apiKey, email) {
  try {
    const headers = {
      'X-Auth-Email': email,
      'X-Auth-Key': apiKey,
      'Content-Type': 'application/json',
    };

    // Step 1: 사용자 인증 확인
    const userResp = await fetch('https://api.cloudflare.com/client/v4/user', { headers });
    const userData = await userResp.json();
    if (!userData.success) {
      return { valid: false, error: userData.errors?.[0]?.message || '인증 실패' };
    }

    // Step 2: 실제 Account ID 가져오기 (user.id ≠ account.id)
    const accountsResp = await fetch('https://api.cloudflare.com/client/v4/accounts?per_page=1', { headers });
    const accountsData = await accountsResp.json();

    let accountId = null;
    if (accountsData.success && accountsData.result?.length > 0) {
      accountId = accountsData.result[0].id;
    }

    // Account ID가 없으면 실패 처리
    if (!accountId) {
      return { valid: false, error: 'Cloudflare Account ID를 가져올 수 없습니다. 계정 권한을 확인해주세요.' };
    }

    return { valid: true, accountId, userEmail: userData.result?.email };
  } catch (e) {
    return { valid: false, error: e.message };
  }
}

export const onRequestOptions = () => handleOptions();

export async function onRequestGet({ request, env }) {
  try {
    const user = await getUser(env, request);
    if (!user) return err('인증 필요', 401);

    const countRow = await env.DB.prepare("SELECT COUNT(*) cnt FROM sites WHERE user_id=? AND status!='deleted'").bind(user.id).first();
    const cfRow = await env.DB.prepare('SELECT cf_global_api_key,cf_account_id,cf_account_email FROM users WHERE id=?').bind(user.id).first();

    return ok({
      user: {
        ...user,
        site_count: countRow?.cnt ?? 0,
        has_cf_api: !!(cfRow?.cf_global_api_key),
        cf_account_id: cfRow?.cf_account_id || null,
        cf_account_email: cfRow?.cf_account_email || null,
      }
    });
  } catch (e) {
    return err('프로필 로딩 실패: ' + (e?.message ?? e), 500);
  }
}

// POST와 PUT 모두 동일하게 처리 (app.js의 updateProfile/saveCfApi 등은 POST로 호출)
export const onRequestPost = ({ request, env }) => onRequestPut({ request, env });

export async function onRequestPut({ request, env }) {
  try {
    const user = await getUser(env, request);
    if (!user) return err('인증 필요', 401);

    let body;
    try { body = await request.json(); } catch { return err('잘못된 요청'); }

    const { name, current_password, new_password, action } = body || {};

    /* ── 비밀번호 변경 ── */
    if (action === 'change_password' || (current_password && new_password)) {
      if (!current_password || !new_password) return err('현재 비밀번호와 새 비밀번호를 입력해주세요.');
      if (new_password.length < 8) return err('새 비밀번호는 8자 이상이어야 합니다.');
      const full = await env.DB.prepare('SELECT password_hash FROM users WHERE id=?').bind(user.id).first();
      if (!full || await hashPw(current_password) !== full.password_hash) return err('현재 비밀번호가 올바르지 않습니다.');
      await env.DB.prepare('UPDATE users SET password_hash=? WHERE id=?').bind(await hashPw(new_password), user.id).run();
      return ok({ message: '비밀번호가 변경되었습니다.' });
    }

    /* ── CF Global API 키 저장 ── */
    if (action === 'save_cf_api') {
      const { cf_global_api_key, cf_account_email } = body;
      if (!cf_global_api_key || !cf_account_email) return err('API 키와 이메일을 모두 입력해주세요.');
      if (!cf_account_email.includes('@')) return err('올바른 이메일 형식을 입력해주세요.');

      // API 키 검증
      const verify = await verifyCfApiKey(cf_global_api_key, cf_account_email);
      if (!verify.valid) return err('Cloudflare API 키 검증 실패. 키와 이메일을 확인해주세요.');

      const encKey = obfuscate(cf_global_api_key, env.ENCRYPTION_KEY || 'cp_enc_default');
      await env.DB.prepare('UPDATE users SET cf_global_api_key=?,cf_account_email=?,cf_account_id=? WHERE id=?')
        .bind(encKey, cf_account_email, verify.accountId || '', user.id).run();

      return ok({ message: 'Cloudflare API 키가 저장되었습니다.', account_id: verify.accountId });
    }

    /* ── CF Global API 키 삭제 ── */
    if (action === 'remove_cf_api') {
      await env.DB.prepare('UPDATE users SET cf_global_api_key=NULL,cf_account_email=NULL,cf_account_id=NULL WHERE id=?').bind(user.id).run();
      return ok({ message: 'API 키가 삭제되었습니다.' });
    }

    /* ── 2FA 설정 ── */
    if (action === 'setup_2fa') {
      const { twofa_type, twofa_code, second_password, force } = body;

      if (!twofa_type || !['email','second_password'].includes(twofa_type)) {
        return err('올바른 2단계 인증 방식을 선택해주세요.');
      }

      if (twofa_type === 'email') {
        // 이메일 인증 코드 검증
        const stored = await env.SESSIONS.get(`2fa_setup:${user.id}`);
        if (!stored || stored !== twofa_code) return err('인증 코드가 올바르지 않거나 만료되었습니다.');
        await env.SESSIONS.delete(`2fa_setup:${user.id}`);
        await env.DB.prepare('UPDATE users SET twofa_type=?,twofa_enabled=1,twofa_secret=NULL WHERE id=?')
          .bind('email', user.id).run();
        return ok({ message: '이메일 2단계 인증이 활성화되었습니다.' });
      }

      if (twofa_type === 'second_password') {
        if (!second_password || second_password.length < 6) return err('2차 비밀번호는 6자 이상이어야 합니다.');

        // 개인정보 감지
        if (/19\d{6}|20\d{6}/.test(second_password.replace(/[-\/\.]/g,'')) ||
            /^\d{6,8}$/.test(second_password.trim())) {
          if (!force) {
            return _j({
              ok: false,
              warn_personal_info: true,
              message: '⚠️ 입력하신 2차 비밀번호가 생년월일 등 개인정보처럼 보입니다. 보안에 취약할 수 있습니다. 다른 비밀번호를 사용하시기를 강력히 권장합니다.',
              can_force: true
            }, 200);
          }
          // force=true 인 경우 경고와 함께 진행
        }

        const secretHash = await hashPw(second_password);
        await env.DB.prepare('UPDATE users SET twofa_type=?,twofa_enabled=1,twofa_secret=? WHERE id=?')
          .bind('second_password', secretHash, user.id).run();
        return ok({ message: force ? '⚠️ 경고: 개인정보를 포함한 2차 비밀번호로 설정되었습니다. 보안에 취약합니다.' : '2차 비밀번호 인증이 활성화되었습니다.' });
      }
    }

    /* ── 2FA 비활성화 ── */
    if (action === 'disable_2fa') {
      const { password } = body;
      const full = await env.DB.prepare('SELECT password_hash FROM users WHERE id=?').bind(user.id).first();
      if (!full || await hashPw(password) !== full.password_hash) return err('비밀번호가 올바르지 않습니다.');
      await env.DB.prepare('UPDATE users SET twofa_enabled=0,twofa_type=NULL,twofa_secret=NULL WHERE id=?').bind(user.id).run();
      return ok({ message: '2단계 인증이 비활성화되었습니다.' });
    }

    /* ── 프로필 이름 변경 ── */
    if (name && name.trim()) {
      await env.DB.prepare('UPDATE users SET name=? WHERE id=?').bind(name.trim(), user.id).run();
      const updated = await env.DB.prepare('SELECT id,name,email,role,plan FROM users WHERE id=?').bind(user.id).first();
      return ok({ user: updated, message: '저장 완료' });
    }

    return err('변경할 항목을 입력해주세요.');
  } catch (e) {
    return err('업데이트 실패: ' + (e?.message ?? e), 500);
  }
}

/* CF API 키 복호화 헬퍼 (사이트 생성 시 내부 사용) */
export async function getCfApiKey(env, userId) {
  try {
    const row = await env.DB.prepare('SELECT cf_global_api_key,cf_account_email,cf_account_id FROM users WHERE id=?').bind(userId).first();
    if (!row?.cf_global_api_key) return null;
    return {
      apiKey: deobfuscate(row.cf_global_api_key, env.ENCRYPTION_KEY || 'cp_enc_default'),
      email: row.cf_account_email,
      accountId: row.cf_account_id,
    };
  } catch { return null; }
}
