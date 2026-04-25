  createSite:  (b)     => CP.post('/sites', b),
  deleteSite:  (id)    => CP.del(`/sites/${id}`),
  updateSite:  (id, b) => CP.put(`/sites/${id}`, b),
  updateSiteSettings: (id, b) => CP.put(`/sites/${id}/settings`, b),
  pollSite:    (id)    => CP.get(`/sites/${id}`),
  getMetrics:  (id)    => CP.get(`/sites/${id}/action?action=get_metrics`),
  initLogTail: (id)    => CP.post(`/sites/${id}/action`, { action: 'init_log_tail' }),
  addDomain:   (id, domain) => CP.post(`/sites/${id}/action`, { action: 'add_domain', params: { domain } }),
  verifyDomain: (id, domain) => CP.post(`/sites/${id}/action`, { action: 'verify_domain_connection', params: { domain } }),

  // [사이트 상세 20+ 기능 핵심 API]
  siteAction: (id, action, params = {}) => CP.post(`/sites/${id}/action`, { action, ...params }),
  // 아래 기능들은 siteAction('restart_php'), siteAction('clear_cache') 등으로 호출됨
  // 1. PHP 버전 변경 2. 서버 재시작 3. 캐시 삭제 4. SSL 강제화 5. WAF 설정 6. IP 차단 7. 백업 생성 
  // 8. DB 최적화 9. SFTP 계정 관리 10. SSH 키 등록 11. Cron 작업 설정 12. 스테이징 생성 
  // 13. Git 배포 설정 14. 실시간 모니터링 15. 에러 로그 보기 16. 접속 로그 분석 17. 디스크 정리 
  // 18. New Relic 연동 19. Redis 캐시 관리 20. Varnish 설정 21. CDN 퍼지

  // DNS 관리
  addDnsRecord: (domain, data) => CP.post(`/dns/${domain}/records`, data),
  deleteDnsRecord: (domain, recordId) => CP.del(`/dns/${domain}/records/${recordId}`),
  
  // [DNS 정책] 
  // 1. DNS 페이지: Cloudflare Nameserver 연동 (Global API 사용)
  async setupNameservers(domain) {
    return this.post('/dns/setup', { domain, method: 'nameserver' });
  },
  // 2. 사이트 상세: A 레코드 방식
  async setupARecord(id, domain) {
    return this.post(`/sites/${id}/dns`, { domain, method: 'a_record' });
