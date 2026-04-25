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
    const token = this.getToken();
    const url = path.startsWith('http') || path.startsWith('/') ? path : '/api' + (path.startsWith('/') ? '' : '/') + path;
    const headers = {
      'Content-Type': 'application/json',
      ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      ...(opts.headers || {}),
    };
    const res = await fetch(url, { ...opts, headers });
    if (res.status === 401) { this.clearAuth(); this._redirectToLogin(); }
    return res;
  },

  async requireAuth() {
    if (!this.getToken()) { this._redirectToLogin(); return null; }
    const cached = this.getUser();
