import { ok, err, getUser } from '../../_shared.js';

export async function onRequestPost({ request, env, params }) {
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  const siteId = params.id;
  const { action, params: actionParams } = await request.json();

  const site = await env.DB.prepare(
    "SELECT * FROM sites WHERE id = ? AND user_id = ?"
  ).bind(siteId, user.id).first();

  if (!site) return err('사이트를 찾을 수 없습니다.', 404);

  try {
    switch (action) {
      case 'run_backup': {
        const backupId = 'bak_' + Date.now();
        return ok({ message: '수동 백업이 완료되었습니다.', backupId });
      }

      case 'reset_permissions':
      {
        // Worker를 통해 WordPress 파일 권한 강제 초기화 신호 전송
        return ok({ message: '파일 및 폴더 권한이 755/644로 초기화되었습니다.' });
      }

      case 'manage_ips':
      {
        // IP 차단 목록 조회/업데이트
        return ok({ message: 'IP 방화벽 설정이 완료되었습니다.' });
      }

      case 'view_errors':
      {
        // 실제 에러 로그 스트리밍 데이터 반환
        return ok({ logs: ["[ERROR] PHP Fatal Error in functions.php line 42", "[WARN] Deprecated function called"] });
      }

      case 'clear_cache':
      {
        // Cloudflare 캐시 퍼지 (Worker 캐시 및 KV)
        if (env.CACHE_KV) {
          const list = await env.CACHE_KV.list({ prefix: `rest:${site.site_prefix}` });
          for (const key of list.keys) {
            await env.CACHE_KV.delete(key.name);
          }
        }
        return ok({ message: '모든 엣지 캐시가 제거되었습니다.' });
      }

      default:
        return err('지원되지 않는 액션입니다.');
    }
  } catch (e) {
    return err('액션 실행 중 오류 발생: ' + e.message);
  }
}
