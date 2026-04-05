# CloudPress 사이트 생성 API 감사 보고서

## ✅ 실제 Cloudflare API 호출 검증

### 1. Cloudflare API 인증 (`GET /accounts/{accountId}`)
- **엔드포인트**: `https://api.cloudflare.com/client/v4/accounts/{accountId}`
- **실제 호출**: ✅ YES — `provisionCmsSite()` Step 1
- **인증 헤더**: `X-Auth-Email` + `X-Auth-Key` (Global API Key)
- **실패 시 처리**: Account ID 재조회 fallback 포함

### 2. Pages 프로젝트 생성 (`POST /pages/projects`)
- **엔드포인트**: `https://api.cloudflare.com/client/v4/accounts/{id}/pages/projects`
- **실제 호출**: ✅ YES — Step 2
- **요청 바디**: `{name: "cp-{slug}", production_branch: "main"}`
- **중복 처리**: 최대 3회 재시도, 새 이름 자동 생성
- **결과**: `https://{projectName}.pages.dev` 생성됨

### 3. KV Namespace 생성 (`POST /storage/kv/namespaces`)
- **엔드포인트**: `https://api.cloudflare.com/client/v4/accounts/{id}/storage/kv/namespaces`
- **실제 호출**: ✅ YES — Step 3
- **요청 바디**: `{title: "cp-kv-{projectName}"}`
- **실패 시**: 경고 로그만 출력, 계속 진행

### 4. D1 데이터베이스 생성 (`POST /d1/database`)
- **엔드포인트**: `https://api.cloudflare.com/client/v4/accounts/{id}/d1/database`
- **실제 호출**: ✅ YES — Step 4
- **요청 바디**: `{name: "cp-db-{projectName}"}`
- **실패 시**: 경고 로그만 출력, 계속 진행

### 5. D1 스키마 초기화 (`POST /d1/database/{id}/query`)
- **엔드포인트**: `https://api.cloudflare.com/client/v4/accounts/{id}/d1/database/{dbId}/query`
- **실제 호출**: ✅ YES — Step 5
- **15개 SQL 실행**: CREATE TABLE × 9, INSERT OR IGNORE × 6
- **사용자 정의 어드민**: adminLogin, adminEmail, adminPassword 반영

### 6. KV 설정 저장 (`PUT /storage/kv/namespaces/{id}/values/site_config`)
- **엔드포인트**: `https://api.cloudflare.com/client/v4/accounts/{id}/storage/kv/namespaces/{kvId}/values/site_config`
- **실제 호출**: ✅ YES — Step 6
- **저장 내용**: site_name, site_url, admin_url, cms_version, 설정값

### 7. Pages 배포 (`POST /pages/projects/{name}/deployments`)
- **엔드포인트**: `https://api.cloudflare.com/client/v4/accounts/{id}/pages/projects/{name}/deployments`
- **실제 호출**: ✅ YES — Step 7 (ZIP 또는 fallback)
- **1순위**: KV에서 CMS 패키지(ZIP) 로드 → multipart 배포
- **2순위**: 기본 HTML 3개 fallback 배포
- **결과**: 실제 사이트 파일이 Pages에 배포됨

### 8. Pages 바인딩 자동 설정 (`PATCH /pages/projects/{name}`)
- **엔드포인트**: `https://api.cloudflare.com/client/v4/accounts/{id}/pages/projects/{name}`
- **실제 호출**: ✅ YES — 배포 직후 자동 실행
- **설정 내용**: CMS_DB(D1), CMS_KV(KV), SITE_URL, CMS_VERSION, ADMIN_LOGIN 환경변수
- **기존 문제**: ❌ 이전 버전에서 바인딩이 안 되는 버그 → ✅ 수정됨

## ✅ 백그라운드 처리

### ctx.waitUntil 지원
- **구현 방식**: `export async function onRequestPost({request,env,ctx})`
- **ctx 있을 때**: `ctx.waitUntil(provisionJob)` → 즉시 202 응답, 백그라운드 계속 실행
- **ctx 없을 때**: 동기 실행 (테스트/로컬 환경 폴백)
- **백그라운드 응답**: `{background: true, site_url, admin_url, cms_password}` 즉시 반환
- **폴링 지원**: 프론트엔드에서 `/api/sites/{id}/status`로 10초마다 상태 확인

## ✅ 수정된 버그 목록

| 버그 | 상태 |
|------|------|
| adminPassword 변수 중복/충돌 | ✅ 수정 |
| DB UPDATE 중복 실행 | ✅ 수정 (provisionCmsSite 내부 1회만) |
| Pages 바인딩 설정 안 됨 | ✅ 수정 |
| 사이트 이름이 항상 "CloudPress" | ✅ 수정 |
| 사이트 생성 시 어드민 정보 미반영 | ✅ 수정 |
| 비밀번호 보기 버튼 미작동 | ✅ 수정 |
| CMS footer 관리자/사이트맵/RSS | ✅ 제거 |
| 무료 플랜 제거 | ✅ 수정 |
| 가격 어드민 설정 미반영 | ✅ 수정 |

## ⚠️ 전제 조건 (사용자 설정 필요)

1. **Cloudflare Global API 키** — 내 계정 → Cloudflare API 설정
2. **CMS 패키지 업로드** — 어드민 → CMS 버전 관리 → ZIP 업로드
3. **플랜 구독** — 스타터/프로/엔터프라이즈

## 실제 생성되는 Cloudflare 리소스

```
사용자의 Cloudflare 계정에 자동 생성:
├── Pages Project: cp-{sitename}-{random}.pages.dev
│   ├── 배포된 CMS 파일 (HTML/CSS/JS/Functions)
│   ├── D1 바인딩: CMS_DB → cp-db-{projectName}
│   ├── KV 바인딩: CMS_KV → cp-kv-{projectName}
│   └── 환경변수: SITE_URL, CMS_VERSION, ADMIN_LOGIN
├── D1 Database: cp-db-{projectName}
│   └── 테이블: wp_users, wp_posts, wp_options, wp_terms...
└── KV Namespace: cp-kv-{projectName}
    └── site_config, admin_info
```
