# CloudPress v11.0 배포 가이드
## 아키텍처: 단일 WP Origin + Cloudflare Worker 프록시 + D1/KV 격리

---

## 1. WP Origin 서버 설정

### mu-plugins 배포
```
wp-content/mu-plugins/cloudpress-origin.php   ← 격리 핵심
wp-content/mu-plugins/cloudpress-rest-api.php ← REST 엔드포인트
```

### wp-config.php에 추가
```php
define('CP_ORIGIN_SECRET', 'your-secret-here');  // wrangler secret과 동일
```

또는 서버 환경변수:
```
CP_ORIGIN_SECRET=your-secret-here
```

### 확인
```
curl -X GET https://origin.cloudpress.site/wp-json/cloudpress/v1/site-status \
  -H "X-CloudPress-Secret: your-secret-here" \
  -H "X-CloudPress-Site: test"
```

---

## 2. Cloudflare Pages + Worker 배포

### D1, KV 생성
```bash
wrangler d1 create cloudpress-db
wrangler kv namespace create SESSIONS
wrangler kv namespace create CACHE
```
→ 출력된 ID를 wrangler.toml과 wrangler.worker.toml에 입력

### D1 스키마 적용
```bash
wrangler d1 execute cloudpress-db --file=schema.sql
```

### 시크릿 설정
```bash
# Pages Functions용
wrangler secret put WP_ORIGIN_URL      # https://origin.cloudpress.site
wrangler secret put WP_ORIGIN_SECRET   # mu-plugin과 동일한 시크릿

# Worker용 (별도)
wrangler secret put WP_ORIGIN_URL    --config wrangler.worker.toml
wrangler secret put WP_ORIGIN_SECRET --config wrangler.worker.toml
```

### Worker 배포 (단일 cloudpress-proxy)
```bash
wrangler deploy --config wrangler.worker.toml
```

### Pages 배포
```bash
wrangler pages deploy . --project-name=cloudpress-wp
```

---

## 3. 관리자 설정 (대시보드 → 설정)

| 항목 | 값 |
|------|-----|
| WP Origin URL | https://origin.cloudpress.site |
| WP Origin Secret | (mu-plugin과 동일) |
| CF API Token | (Edit DNS + Worker Routes 권한) |
| CF Account ID | (Cloudflare 대시보드에서 확인) |
| CF Worker Name | cloudpress-proxy |
| Worker CNAME Target | cloudpress-proxy.YOUR_SUBDOMAIN.workers.dev |

---

## 4. 사이트 생성 흐름

1. 사용자: 사이트 이름 + 개인 도메인 입력
2. `POST /api/sites` → site_prefix(s_xxxxx) 생성 + DB 레코드
3. `POST /api/sites/{id}/provision`:
   - WP origin에 `POST /wp-json/cloudpress/v1/init-site` (테이블 생성)
   - CF DNS API로 CNAME 추가 (proxied=true)
   - CF Worker Route 등록 (`myblog.com/*` → `cloudpress-proxy`)
   - KV에 도메인→사이트 매핑 저장
4. Worker가 요청 수신 → D1/KV에서 사이트 조회 → WP origin 프록시
5. WP mu-plugin이 `X-CloudPress-Site` 헤더로 prefix 결정 → 격리 실행

---

## 5. 각 사이트 격리 범위

| 항목 | 격리 방식 |
|------|----------|
| DB 테이블 | `wp_{prefix}_posts`, `wp_{prefix}_options` 등 완전 분리 |
| 업로드 파일 | `/wp-content/uploads/cloudpress_sites/{prefix}/` |
| 관리자 URL | `origin/wp-admin/?cp_site={prefix}` |
| 크론 | `?cp_site={prefix}` 파라미터로 개별 실행 |
| REST API | site prefix 없는 요청 403 차단 |
| 이메일 From | `noreply@{개인도메인}` |
| KV 캐시 | `page:{prefix}:...` 키로 분리 |
| 세션/쿠키 | 도메인별 자동 분리 |

---

## 6. 도메인 연결 방식

### 자동 (도메인이 Cloudflare에 있는 경우)
- provision.js가 CF DNS API로 CNAME 자동 추가
- Worker Route 자동 등록 (`myblog.com/*` → `cloudpress-proxy`)
- CF 프록시(주황불) 자동 활성화
- **루트 도메인 완전 덮어씌우기**: `myblog.com` + `www.myblog.com` 둘 다

### 수동 (다른 DNS 제공업체)
사용자가 DNS에 추가:
```
CNAME  @    cloudpress-proxy.YOUR_SUBDOMAIN.workers.dev
CNAME  www  cloudpress-proxy.YOUR_SUBDOMAIN.workers.dev
```
→ Cloudflare로 도메인 이전 후 Worker Route 자동 설정됨

---

## 7. 사이트 삭제 시
- CF Worker Route 삭제
- KV 캐시 삭제
- WP origin 테이블 DROP (`DELETE /wp-json/cloudpress/v1/delete-site`)
- D1 sites 레코드 soft delete
