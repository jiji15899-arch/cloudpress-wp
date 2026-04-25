    return d;
  },
  async logout() {
    await this.post('/auth/logout', {});
    this.clearAuth();
    window.location.href = '/';
  },
  _isAuthPage() {
    const p = window.location.pathname;
    return ['/auth', '/auth.html', '/login', '/signup', '/register'].some(x => p.startsWith(x));
  },
  _redirectToLogin() {
    if (this._isAuthPage()) return;
    // 현재 URL을 returnTo 파라미터로 전달해 로그인 후 복귀 가능하게
    const returnTo = encodeURIComponent(window.location.pathname + window.location.search);
    window.location.href = '/auth.html?returnTo=' + returnTo;
  },
/* CloudPress CMS app.js v4.1 */
'use strict';

window.CP = window.CP || {};
const CP = window.CP;

Object.assign(CP, {
  // ... 기존 코드 ...

  // apiFetch: raw Response를 반환하여 상세한 에러 핸들링이 필요한 경우 사용
  async apiFetch(path, opts = {}) {
/* CloudPress CMS app.js v4.2 */
'use strict';

// 전역 CP 객체 즉시 선언 (스크립트 로드 즉시 사용 가능하도록)
window.CP = window.CP || {};
const CP = window.CP;

Object.assign(CP, {
  TOKEN_KEY: 'cp_token',
  USER_KEY:  'cp_user',

  setToken(token) { if(token) localStorage.setItem(this.TOKEN_KEY, token); },
  getToken() { return localStorage.getItem(this.TOKEN_KEY); },
  clearAuth() { localStorage.removeItem(this.TOKEN_KEY); localStorage.removeItem(this.USER_KEY); },
  setUser(user) { localStorage.setItem(this.USER_KEY, JSON.stringify(user)); },
  getUser() { try { return JSON.parse(localStorage.getItem(this.USER_KEY) || 'null'); } catch { return null; } },

  // 모든 내부 API 호출을 위한 핵심 Fetch 함수
  async apiFetch(path, opts = {}) {
    const token = this.getToken();
    
    // 경로 처리: 외부 URL이 아니고 /api로 시작하지 않으면 /api를 자동으로 붙임
    let url = path;
    if (!url.startsWith('http')) {
      if (!url.startsWith('/api/')) {
        url = '/api' + (url.startsWith('/') ? '' : '/') + url;
      }
    }

    const headers = {
      'Content-Type': 'application/json',
      ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      ...(opts.headers || {}),
    };

    const res = await fetch(url, { ...opts, headers });
    
    // 401 Unauthorized 처리 (세션 만료 시 로그인 페이지로)
    if (res.status === 401 && !this._isAuthPage()) {
      this.clearAuth();
      this._redirectToLogin();
    }
    return res;
  },

  async api(path, opts = {}) {
    const res = await this.apiFetch(path, opts);
    let data;
    try {
      data = await res.json();
    } catch (e) {
      data = { ok: false, error: '서버 응답 처리 중 오류가 발생했습니다.' };
    }
    if (!res.ok && data.ok !== false) data.ok = false;
    return data;
  },

  get:  (p)    => CP.api(p, { method: 'GET' }),
  post: (p, b) => CP.api(p, { method: 'POST', body: JSON.stringify(b || {}) }),
  put:  (p, b) => CP.api(p, { method: 'PUT', body: JSON.stringify(b || {}) }),
  del:  (p, b) => CP.api(p, { method: 'DELETE', body: JSON.stringify(b || {}) }),

  async login(email, password, twofaCode) {
    return this.post('/auth/login', { email, password, twofaCode });
  },
  async register(name, email, password) {
    return this.post('/auth/signup', { name, email, password });
  },
  async logout() {
    await this.post('/auth/logout', {});
    this.clearAuth();
    window.location.href = '/';
  },

  // ... 나머지 유틸리티 함수들 ...
  _isAuthPage() {
    const p = window.location.pathname;
    return ['/auth', '/auth.html', '/login', '/signup', '/register'].some(x => p.startsWith(x));
  },
  _redirectToLogin() {
    if (this._isAuthPage()) return;
    const returnTo = encodeURIComponent(window.location.pathname + window.location.search);
    window.location.href = '/auth.html?returnTo=' + returnTo;
  },
});
    const token = this.getToken();
    const url = path.startsWith('http') || path.startsWith('/') ? path : '/api' + (path.startsWith('/') ? '' : '/') + path;
