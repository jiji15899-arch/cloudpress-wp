#!/usr/bin/env bash
# CloudPress 배포 스크립트 (자동 KV/D1 ID 주입)
# 실행: bash deploy.sh
#
# wrangler.toml / wrangler.worker.toml 의 *_PLACEHOLDER 값을
# 실제 계정의 KV namespace ID / D1 database_id 로 자동 교체 후 배포합니다.

set -euo pipefail

PAGES_PROJECT="${PAGES_PROJECT:-cloudpress-wp}"
WORKER_NAME="${WORKER_NAME:-cloudpress-proxy}"
D1_NAME="cloudpress-db"

echo "▶ CloudPress 배포 시작"

# ── 헬퍼: KV ID 조회 또는 생성 ────────────────────────────────────────────
get_or_create_kv() {
  local name="$1"
  local id
  id=$(wrangler kv namespace list 2>/dev/null \
    | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for ns in data:
        if ns.get('title') == '${name}':
            print(ns['id'])
            break
except: pass
" 2>/dev/null || true)

  if [[ -z "$id" ]]; then
    echo "  KV '${name}' 없음 → 생성 중..." >&2
    local out
    out=$(wrangler kv namespace create "${name}" 2>&1)
    id=$(echo "$out" | grep -oE '[0-9a-f]{32}' | head -1)
  fi
  echo "$id"
}

# ── 헬퍼: D1 database_id 조회 또는 생성 ───────────────────────────────────
get_or_create_d1() {
  local name="$1"
  local id
  id=$(wrangler d1 list 2>/dev/null \
    | grep "$name" \
    | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
    | head -1 || true)

  if [[ -z "$id" ]]; then
    echo "  D1 '${name}' 없음 → 생성 중..." >&2
    local out
    out=$(wrangler d1 create "${name}" 2>&1)
    id=$(echo "$out" | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1)
  fi
  echo "$id"
}

# ── ID 획득 ───────────────────────────────────────────────────────────────
echo "▶ KV / D1 ID 조회 중..."
SESSIONS_ID=$(get_or_create_kv "SESSIONS")
CACHE_ID=$(get_or_create_kv "CACHE")
D1_ID=$(get_or_create_d1 "$D1_NAME")

if [[ -z "$SESSIONS_ID" || -z "$CACHE_ID" || -z "$D1_ID" ]]; then
  echo "❌ ID 획득 실패. wrangler 로그인 여부를 확인하세요: wrangler login"
  exit 1
fi

echo "  SESSIONS  : $SESSIONS_ID"
echo "  CACHE     : $CACHE_ID"
echo "  D1        : $D1_ID"

# ── toml 패치 (플레이스홀더 → 실제 ID) ───────────────────────────────────
patch_toml() {
  local file="$1"
  [[ -f "$file" ]] || return
  echo "▶ $file 패치 중..."
  sed -i \
    -e "s|SESSIONS_ID_PLACEHOLDER|${SESSIONS_ID}|g" \
    -e "s|CACHE_ID_PLACEHOLDER|${CACHE_ID}|g" \
    -e "s|D1_ID_PLACEHOLDER|${D1_ID}|g" \
    "$file"
}

patch_toml "wrangler.toml"
patch_toml "wrangler.worker.toml"

# ── D1 스키마 적용 ────────────────────────────────────────────────────────
echo "▶ D1 스키마 적용 중..."
wrangler d1 execute "$D1_NAME" --file=schema.sql --remote || true

# ── Pages 배포 ────────────────────────────────────────────────────────────
echo "▶ Cloudflare Pages 배포 중..."
wrangler pages deploy . \
  --project-name="$PAGES_PROJECT" \
  --commit-dirty=true

# ── WORKER_SOURCE secret 주입 ─────────────────────────────────────────────
# [text_blobs]는 ES Module format Worker에서 지원되지 않으므로
# worker.js 파일 전체를 Pages secret으로 주입합니다.
echo "▶ WORKER_SOURCE secret 주입 중..."
wrangler pages secret put WORKER_SOURCE \
  --project-name="$PAGES_PROJECT" \
  < worker.js
echo "  WORKER_SOURCE 주입 완료"

# ── Worker 배포 ───────────────────────────────────────────────────────────
echo "▶ cloudpress-proxy Worker 배포 중..."
wrangler deploy --config wrangler.worker.toml

echo ""
echo "✅ 배포 완료!"
echo "   Pages  → https://${PAGES_PROJECT}.pages.dev"
echo "   Worker → https://${WORKER_NAME}.workers.dev"
