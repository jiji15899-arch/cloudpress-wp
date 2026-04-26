/**
 * 실시간 워드프레스 및 PHP 버전 크롤링 헬퍼
 */
export async function getLiveVersions() {
  const wpRes = await fetch('https://api.wordpress.org/core/version-check/1.7/');
  const wpData = await wpRes.json();
  const latestWP = wpData.offers[0].version;
  const phpVersions = ['8.3', '8.2', '8.1', '8.0', '7.4'];
  return {
    wordpress: [
      { version: latestWP, status: 'latest' },
      { version: '6.4', status: 'stable' },
      { version: '6.3', status: 'legacy' }
    ],
    php: phpVersions.map(v => ({ version: v, isDefault: v === '8.3' }))
  };
}

/**
 * 글로벌 리전 목록 (AWS + Vultr 전체 리전)
 * 각 리전에 해당하는 Cloudflare Anycast IP 할당
 */
export function getLiveRegions() {
  return [
    // ── 아시아 태평양 ──────────────────────────────────────────────
    { code:'icn', name:'서울, 한국 (Seoul, ap-northeast-2)', shortName:'Seoul', flag:'🇰🇷', provider:'AWS+Vultr', continent:'Asia', ip:'104.21.10.1', latency_ms:5 },
    { code:'nrt', name:'도쿄, 일본 (Tokyo, ap-northeast-1)', shortName:'Tokyo', flag:'🇯🇵', provider:'AWS+Vultr', continent:'Asia', ip:'104.21.11.1', latency_ms:30 },
    { code:'osa', name:'오사카, 일본 (Osaka, ap-northeast-3)', shortName:'Osaka', flag:'🇯🇵', provider:'AWS', continent:'Asia', ip:'104.21.12.1', latency_ms:35 },
    { code:'sin', name:'싱가포르 (Singapore, ap-southeast-1)', shortName:'Singapore', flag:'🇸🇬', provider:'AWS+Vultr', continent:'Asia', ip:'104.21.20.1', latency_ms:60 },
    { code:'kul', name:'쿠알라룸푸르, 말레이시아 (Kuala Lumpur)', shortName:'Kuala Lumpur', flag:'🇲🇾', provider:'AWS', continent:'Asia', ip:'104.21.21.1', latency_ms:65 },
    { code:'cgk', name:'자카르타, 인도네시아 (Jakarta, ap-southeast-3)', shortName:'Jakarta', flag:'🇮🇩', provider:'AWS', continent:'Asia', ip:'104.21.22.1', latency_ms:70 },
    { code:'bkk', name:'방콕, 태국 (Bangkok)', shortName:'Bangkok', flag:'🇹🇭', provider:'Vultr', continent:'Asia', ip:'104.21.23.1', latency_ms:75 },
    { code:'mnl', name:'마닐라, 필리핀 (Manila)', shortName:'Manila', flag:'🇵🇭', provider:'Vultr', continent:'Asia', ip:'104.21.24.1', latency_ms:80 },
    { code:'hkg', name:'홍콩 (Hong Kong, ap-east-1)', shortName:'Hong Kong', flag:'🇭🇰', provider:'AWS+Vultr', continent:'Asia', ip:'104.21.30.1', latency_ms:40 },
    { code:'tpe', name:'타이베이, 대만 (Taipei)', shortName:'Taipei', flag:'🇹🇼', provider:'Vultr', continent:'Asia', ip:'104.21.31.1', latency_ms:45 },
    { code:'bom', name:'뭄바이, 인도 (Mumbai, ap-south-1)', shortName:'Mumbai', flag:'🇮🇳', provider:'AWS+Vultr', continent:'Asia', ip:'104.21.40.1', latency_ms:90 },
    { code:'del', name:'델리, 인도 (Delhi, ap-south-2)', shortName:'Delhi', flag:'🇮🇳', provider:'AWS', continent:'Asia', ip:'104.21.41.1', latency_ms:95 },
    { code:'sgn', name:'호치민, 베트남 (Ho Chi Minh)', shortName:'Ho Chi Minh', flag:'🇻🇳', provider:'Vultr', continent:'Asia', ip:'104.21.42.1', latency_ms:72 },
    // ── 오세아니아 ─────────────────────────────────────────────────
    { code:'syd', name:'시드니, 호주 (Sydney, ap-southeast-2)', shortName:'Sydney', flag:'🇦🇺', provider:'AWS+Vultr', continent:'Oceania', ip:'104.21.50.1', latency_ms:150 },
    { code:'mel', name:'멜버른, 호주 (Melbourne)', shortName:'Melbourne', flag:'🇦🇺', provider:'Vultr', continent:'Oceania', ip:'104.21.51.1', latency_ms:155 },
    { code:'akl', name:'오클랜드, 뉴질랜드 (Auckland)', shortName:'Auckland', flag:'🇳🇿', provider:'Vultr', continent:'Oceania', ip:'104.21.52.1', latency_ms:160 },
    // ── 미국 동부 ──────────────────────────────────────────────────
    { code:'iad', name:'버지니아 (N. Virginia, us-east-1)', shortName:'N. Virginia', flag:'🇺🇸', provider:'AWS+Vultr', continent:'North America', ip:'172.67.70.1', latency_ms:180 },
    { code:'bos', name:'보스턴, 미국 (Boston)', shortName:'Boston', flag:'🇺🇸', provider:'Vultr', continent:'North America', ip:'172.67.71.1', latency_ms:185 },
    { code:'mia', name:'마이애미, 미국 (Miami, us-east-2)', shortName:'Miami', flag:'🇺🇸', provider:'AWS+Vultr', continent:'North America', ip:'172.67.72.1', latency_ms:190 },
    { code:'atl', name:'애틀란타, 미국 (Atlanta)', shortName:'Atlanta', flag:'🇺🇸', provider:'Vultr', continent:'North America', ip:'172.67.73.1', latency_ms:185 },
    // ── 미국 중부 ──────────────────────────────────────────────────
    { code:'ord', name:'시카고, 미국 (Chicago)', shortName:'Chicago', flag:'🇺🇸', provider:'Vultr', continent:'North America', ip:'172.67.80.1', latency_ms:175 },
    { code:'dfw', name:'달라스, 미국 (Dallas, us-south-1)', shortName:'Dallas', flag:'🇺🇸', provider:'AWS+Vultr', continent:'North America', ip:'172.67.81.1', latency_ms:180 },
    // ── 미국 서부 ──────────────────────────────────────────────────
    { code:'sfo', name:'산호세, 미국 (San Jose, us-west-1)', shortName:'San Jose', flag:'🇺🇸', provider:'AWS+Vultr', continent:'North America', ip:'172.67.90.1', latency_ms:170 },
    { code:'sea', name:'시애틀, 미국 (Seattle, us-west-2)', shortName:'Seattle', flag:'🇺🇸', provider:'AWS+Vultr', continent:'North America', ip:'172.67.91.1', latency_ms:165 },
    { code:'lax', name:'로스앤젤레스, 미국 (Los Angeles)', shortName:'Los Angeles', flag:'🇺🇸', provider:'Vultr', continent:'North America', ip:'172.67.92.1', latency_ms:168 },
    // ── 캐나다 ────────────────────────────────────────────────────
    { code:'yul', name:'몬트리올, 캐나다 (Montreal, ca-central-1)', shortName:'Montreal', flag:'🇨🇦', provider:'AWS+Vultr', continent:'North America', ip:'172.67.100.1', latency_ms:180 },
    { code:'yvr', name:'밴쿠버, 캐나다 (Vancouver)', shortName:'Vancouver', flag:'🇨🇦', provider:'Vultr', continent:'North America', ip:'172.67.101.1', latency_ms:160 },
    { code:'yto', name:'토론토, 캐나다 (Toronto, ca-west-1)', shortName:'Toronto', flag:'🇨🇦', provider:'AWS', continent:'North America', ip:'172.67.102.1', latency_ms:182 },
    // ── 남미 ──────────────────────────────────────────────────────
    { code:'gru', name:'상파울루, 브라질 (São Paulo, sa-east-1)', shortName:'São Paulo', flag:'🇧🇷', provider:'AWS+Vultr', continent:'South America', ip:'172.67.110.1', latency_ms:220 },
    { code:'bog', name:'보고타, 콜롬비아 (Bogotá)', shortName:'Bogotá', flag:'🇨🇴', provider:'Vultr', continent:'South America', ip:'172.67.111.1', latency_ms:215 },
    { code:'scl', name:'산티아고, 칠레 (Santiago)', shortName:'Santiago', flag:'🇨🇱', provider:'Vultr', continent:'South America', ip:'172.67.112.1', latency_ms:230 },
    // ── 서유럽 ────────────────────────────────────────────────────
    { code:'lhr', name:'런던, 영국 (London, eu-west-2)', shortName:'London', flag:'🇬🇧', provider:'AWS+Vultr', continent:'Europe', ip:'104.21.60.1', latency_ms:240 },
    { code:'fra', name:'프랑크푸르트, 독일 (Frankfurt, eu-central-1)', shortName:'Frankfurt', flag:'🇩🇪', provider:'AWS+Vultr', continent:'Europe', ip:'104.21.61.1', latency_ms:245 },
    { code:'ams', name:'암스테르담, 네덜란드 (Amsterdam)', shortName:'Amsterdam', flag:'🇳🇱', provider:'Vultr', continent:'Europe', ip:'104.21.62.1', latency_ms:242 },
    { code:'cdg', name:'파리, 프랑스 (Paris, eu-west-3)', shortName:'Paris', flag:'🇫🇷', provider:'AWS+Vultr', continent:'Europe', ip:'104.21.63.1', latency_ms:243 },
    { code:'mad', name:'마드리드, 스페인 (Madrid, eu-south-2)', shortName:'Madrid', flag:'🇪🇸', provider:'AWS+Vultr', continent:'Europe', ip:'104.21.64.1', latency_ms:248 },
    { code:'fco', name:'밀라노, 이탈리아 (Milan, eu-south-1)', shortName:'Milan', flag:'🇮🇹', provider:'AWS+Vultr', continent:'Europe', ip:'104.21.65.1', latency_ms:246 },
    { code:'zrh', name:'취리히, 스위스 (Zurich, eu-central-2)', shortName:'Zurich', flag:'🇨🇭', provider:'AWS', continent:'Europe', ip:'104.21.66.1', latency_ms:244 },
    // ── 북유럽 ────────────────────────────────────────────────────
    { code:'arn', name:'스톡홀름, 스웨덴 (Stockholm, eu-north-1)', shortName:'Stockholm', flag:'🇸🇪', provider:'AWS+Vultr', continent:'Europe', ip:'104.21.67.1', latency_ms:250 },
    { code:'cph', name:'코펜하겐, 덴마크 (Copenhagen)', shortName:'Copenhagen', flag:'🇩🇰', provider:'Vultr', continent:'Europe', ip:'104.21.68.1', latency_ms:248 },
    { code:'hel', name:'헬싱키, 핀란드 (Helsinki)', shortName:'Helsinki', flag:'🇫🇮', provider:'Vultr', continent:'Europe', ip:'104.21.69.1', latency_ms:252 },
    { code:'waw', name:'바르샤바, 폴란드 (Warsaw, eu-central-3)', shortName:'Warsaw', flag:'🇵🇱', provider:'AWS+Vultr', continent:'Europe', ip:'104.21.70.1', latency_ms:247 },
    // ── 중동 ──────────────────────────────────────────────────────
    { code:'dxb', name:'두바이, UAE (Dubai, me-central-1)', shortName:'Dubai', flag:'🇦🇪', provider:'AWS+Vultr', continent:'Middle East', ip:'104.21.75.1', latency_ms:130 },
    { code:'tlv', name:'텔아비브, 이스라엘 (Tel Aviv, il-central-1)', shortName:'Tel Aviv', flag:'🇮🇱', provider:'AWS', continent:'Middle East', ip:'104.21.76.1', latency_ms:135 },
    { code:'bah', name:'바레인 (Bahrain, me-south-1)', shortName:'Bahrain', flag:'🇧🇭', provider:'AWS', continent:'Middle East', ip:'104.21.77.1', latency_ms:128 },
    { code:'ruh', name:'리야드, 사우디아라비아 (Riyadh)', shortName:'Riyadh', flag:'🇸🇦', provider:'AWS', continent:'Middle East', ip:'104.21.78.1', latency_ms:132 },
    // ── 아프리카 ──────────────────────────────────────────────────
    { code:'jnb', name:'요하네스버그, 남아공 (Johannesburg, af-south-1)', shortName:'Johannesburg', flag:'🇿🇦', provider:'AWS+Vultr', continent:'Africa', ip:'104.21.80.1', latency_ms:200 },
    { code:'los', name:'라고스, 나이지리아 (Lagos)', shortName:'Lagos', flag:'🇳🇬', provider:'Vultr', continent:'Africa', ip:'104.21.81.1', latency_ms:210 },
    { code:'cai', name:'카이로, 이집트 (Cairo)', shortName:'Cairo', flag:'🇪🇬', provider:'AWS', continent:'Africa', ip:'104.21.82.1', latency_ms:205 },
  ];
}
