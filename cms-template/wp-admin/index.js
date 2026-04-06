/* CloudPress CMS — wp-admin/index.js */
'use strict';

(async()=>{
  const ctx=await CMS.initAdminPage('dashboard');
  if(!ctx)return;
  const{user,settings}=ctx;
  const siteUrl=settings?.url||location.origin;
  const siteName=settings?.title||settings?.blogname||'내 사이트';

  // 통계 로드
  const[postsD,pagesD,commentsD,usersD]=await Promise.all([
    CMS.apiGet('/wp-json/wp/v2/posts?per_page=1&status=publish'),
    CMS.apiGet('/wp-json/wp/v2/pages?per_page=1&status=publish'),
    CMS.apiGet('/wp-json/wp/v2/posts?per_page=5&status=publish'),
    CMS.apiGet('/wp-json/wp/v2/users?per_page=1'),
  ]).catch(()=>[{},{},{},{}]);

  const getTotal=d=>Array.isArray(d)?d.length:0;

  document.getElementById('widgets').innerHTML=`
    <div class="postbox">
      <h2>사이트 개요</h2>
      <div class="postbox-body">
        <div class="stat-grid">
          <div class="stat-item" onclick="location.href='/wp-admin/edit.html'"><div class="stat-num" id="cntPosts">—</div><div class="stat-label">글</div></div>
          <div class="stat-item" onclick="location.href='/wp-admin/edit.html?post_type=page'"><div class="stat-num" id="cntPages">—</div><div class="stat-label">페이지</div></div>
          <div class="stat-item"><div class="stat-num" id="cntComments">—</div><div class="stat-label">댓글</div></div>
          <div class="stat-item" onclick="location.href='/wp-admin/users.html'"><div class="stat-num" id="cntUsers">—</div><div class="stat-label">사용자</div></div>
        </div>
        <hr style="margin:14px 0;border:none;border-top:1px solid #dcdcde">
        <div style="font-size:.82rem;color:#646970">
          <div style="margin-bottom:6px">WordPress 버전: <strong>CloudPress CMS 1.0.0</strong></div>
          <div>현재 테마: <strong>${CMS.esc(settings?.active_theme||'default')}</strong></div>
        </div>
      </div>
    </div>

    <div class="postbox">
      <h2>빠른 작성</h2>
      <div class="postbox-body">
        <div style="margin-bottom:10px"><input type="text" id="qpTitle" placeholder="제목" style="width:100%;margin-bottom:8px" class="regular-text"><textarea id="qpContent" placeholder="내용..." style="width:100%;min-height:100px;padding:8px;border:1px solid #c3c4c7;border-radius:3px;font-size:.9rem;resize:vertical;font-family:inherit"></textarea></div>
        <button class="button button-primary" onclick="quickPost()">초안으로 저장</button>
        <a href="/wp-admin/post-new.html" class="button" style="margin-left:6px">전체 에디터 →</a>
        <div id="qpMsg" style="margin-top:8px;font-size:.82rem"></div>
      </div>
    </div>

    <div class="postbox">
      <h2>최근 글</h2>
      <div class="postbox-body" id="recentPosts"><div style="color:#646970;font-size:.85rem">로딩 중...</div></div>
    </div>

    <div class="postbox">
      <h2>CloudPress 소식</h2>
      <div class="postbox-body">
        <div style="font-size:.85rem;color:#646970;line-height:1.8">
          <p style="margin-bottom:8px">✅ <strong>CloudPress CMS 1.0.0</strong> — 워드프레스 100% 호환</p>
          <p style="margin-bottom:8px">🚀 Cloudflare Pages + D1 + KV 자동 배포</p>
          <p style="margin-bottom:8px">🛡️ 자동 DDoS 방어 · 글로벌 CDN 300+</p>
          <p>🔗 <a href="${CMS.esc(siteUrl)}" target="_blank" style="color:var(--primary)">${CMS.esc(siteName)} 방문</a></p>
        </div>
      </div>
    </div>`;

  // 통계 채우기
  const fetchTotal=async(url)=>{const r=await fetch(location.origin+url,{credentials:'include',headers:CMS.cmsHeaders?.()});return parseInt(r.headers.get('X-WP-Total')||'0');};
  fetchTotal('/wp-json/wp/v2/posts?per_page=1&status=publish').then(n=>{const el=document.getElementById('cntPosts');if(el)el.textContent=n;});
  fetchTotal('/wp-json/wp/v2/pages?per_page=1&status=publish').then(n=>{const el=document.getElementById('cntPages');if(el)el.textContent=n;});
  fetchTotal('/wp-json/wp/v2/posts?per_page=1').then(n=>{const el=document.getElementById('cntComments');if(el)el.textContent=0;}); // comments별도
  fetchTotal('/wp-json/wp/v2/users?per_page=1').then(n=>{const el=document.getElementById('cntUsers');if(el)el.textContent=n||1;});

  // 최근 글
  CMS.apiGet('/wp-json/wp/v2/posts?per_page=5&status=any').then(posts=>{
    const el=document.getElementById('recentPosts');if(!el)return;
    if(!Array.isArray(posts)||!posts.length){el.innerHTML='<div style="color:#646970;font-size:.85rem">글이 없습니다.</div>';return;}
    el.innerHTML=posts.map(p=>`<div style="padding:6px 0;border-bottom:1px solid #f0f0f1;font-size:.85rem"><a href="/wp-admin/post.html?id=${p.id}" style="font-weight:600">${CMS.esc(p.title?.rendered||'(제목 없음)')}</a><br><span style="color:#646970;font-size:.78rem">${CMS.formatDate(p.date)} · ${p.status==='publish'?'발행':'임시저장'}</span></div>`).join('');
  });
})();

async function quickPost(){
  const title=document.getElementById('qpTitle').value.trim();
  const content=document.getElementById('qpContent').value.trim();
  const msg=document.getElementById('qpMsg');
  if(!title){msg.textContent='제목을 입력해주세요.';msg.style.color='#d63638';return;}
  msg.textContent='저장 중...';msg.style.color='#646970';
  const r=await CMS.apiPost('/wp-json/wp/v2/posts',{title,content,status:'draft'});
  if(r.id){msg.innerHTML=`✅ 저장됨 — <a href="/wp-admin/post.html?id=${r.id}">편집하기</a>`;msg.style.color='#00a32a';document.getElementById('qpTitle').value='';document.getElementById('qpContent').value='';}
  else{msg.textContent='저장 실패: '+(r.message||'알 수 없는 오류');msg.style.color='#d63638';}
}
