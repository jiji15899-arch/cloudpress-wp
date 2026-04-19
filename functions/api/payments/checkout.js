// functions/api/payments/checkout.js
// 결제 기능은 비활성화됨 — 플랜은 관리자만 설정 가능
import { err } from '../_shared.js';

export async function onRequestPost(ctx) {
  return err('플랜 변경은 관리자만 설정할 수 있습니다.', 403);
}
