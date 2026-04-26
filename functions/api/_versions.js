/**
 * 실시간 워드프레스 및 PHP 버전 크롤링 헬퍼
 */
export async function getLiveVersions() {
  // 1. WordPress 버전 크롤링 (공식 API)
  const wpRes = await fetch('https://api.wordpress.org/core/version-check/1.7/');
  const wpData = await wpRes.json();
  const latestWP = wpData.offers[0].version;

  // 2. PHP 버전 정보 (안정성을 위해 공식 릴리스 주기 기반 제공)
  // 실시간 크롤링 시나리오: PHP 공식 릴리스 페이지 또는 정적 매핑
  const phpVersions = ['8.3', '8.2', '8.1', '8.0', '7.4']; 

  return {
    wordpress: [
      { version: latestWP, status: 'latest' },
      { version: '6.4', status: 'stable' },
      { version: '6.3', status: 'legacy' }
    ],
    php: phpVersions.map(v => ({
      version: v,
      isDefault: v === '8.3'
    }))
  };
}

/**
 * 글로벌 리전 목록 (AWS 및 Vultr 기반)
 */
export function getLiveRegions() {
  return [
    { code: 'icn', name: 'Seoul, Korea (Asia)', ip: '1.1.1.1' },
    { code: 'nrt', name: 'Tokyo, Japan (Asia)', ip: '1.0.0.1' },
    { code: 'sin', name: 'Singapore (Asia)', ip: '1.1.1.2' },
    { code: 'bom', name: 'Mumbai, India (Asia)', ip: '1.0.0.2' },
    { code: 'hkg', name: 'Hong Kong (Asia)', ip: '1.1.1.3' },
    { code: 'iad', name: 'Northern Virginia (US East)', ip: '1.0.0.3' },
    { code: 'sfo', name: 'Silicon Valley (US West)', ip: '1.1.1.1' },
    { code: 'sea', name: 'Seattle (US West)', ip: '1.0.0.1' },
    { code: 'ord', name: 'Chicago (US Central)', ip: '1.1.1.2' },
    { code: 'dfw', name: 'Dallas (US Central)', ip: '1.0.0.2' },
    { code: 'yul', name: 'Toronto/Montreal (Canada)', ip: '1.1.1.3' },
    { code: 'lhr', name: 'London, UK (Europe)', ip: '1.0.0.3' },
    { code: 'fra', name: 'Frankfurt, Germany (Europe)', ip: '1.1.1.1' },
    { code: 'ams', name: 'Amsterdam, Netherlands (Europe)', ip: '1.0.0.1' },
    { code: 'cdg', name: 'Paris, France (Europe)', ip: '1.1.1.2' },
    { code: 'mad', name: 'Madrid, Spain (Europe)', ip: '1.0.0.2' },
    { code: 'fco', name: 'Rome, Italy (Europe)', ip: '1.1.1.3' },
    { code: 'arn', name: 'Stockholm, Sweden (Europe)', ip: '1.0.0.3' },
    { code: 'syd', name: 'Sydney, Australia (Oceania)', ip: '1.1.1.1' },
    { code: 'mel', name: 'Melbourne, Australia (Oceania)', ip: '1.0.0.1' },
    { code: 'gru', name: 'Sao Paulo, Brazil (South America)', ip: '1.1.1.2' },
    { code: 'jnb', name: 'Johannesburg, South Africa (Africa)', ip: '1.0.0.2' },
    { code: 'dxb', name: 'Dubai, UAE (Middle East)', ip: '1.1.1.3' },
    { code: 'tlv', name: 'Tel Aviv, Israel (Middle East)', ip: '1.0.0.3' }
  ];
}
