/* CloudPress CMS — wp-admin/edit.js */
'use strict';

let currentPage=1,totalPages=1,currentStatus='any',postType='post';
const params=new URLSearchParams(location.search);
if(params.get('post_type')==='page'){postType='page';document.title='페이지 목록 — CloudPress CMS';}

(async()=>{
  const ctx=await CMS.initAdminPage(postType==='page'?'pages':'edit');
  if(!ctx)return;
  if(postType==='page')document.getElementById('pageTitle').textContent='페이지 목록';
  renderStatusFilter();
  await loadPosts(1);
})();

function renderStatusFilter(){
  const statuses=[{v:'any',l:'전체'},{v:'publish',l:'발행'},{v:'draft',l:'임시저장'},{v:'trash',l:'휴지통'}];
  document.getElementById('statusFilter').innerHTML=statuses.map(s=>`<a href="#" class="button${s.v===currentStatus?' button-primary':''}" onclick="setStatus('${s.v}');return false;">${s.l}</a>`).join('');
}
function setStatus(s){currentStatus=s;renderStatusFilter();loadPosts(1);}

async function loadPosts(page){
  currentPage=page;
  const search=document.getElementById('searchInput').value.trim();
  let url=`/wp-json/wp/v2/${postType==='page'?'pages':'posts'}?per_page=20&page=${page}&status=${currentStatus}`;
  if(search)url+=`&search=${encodeURIComponent(search)}`;
  const tbody=document.getElementById('postsList');
  tbody.innerHTML='<tr><td colspan="6" style="text-align:center;padding:24px"><div class="spinner"></div></td></tr>';
  const resp=await fetch(location.origin+url,{credentials:'include',headers:{'Authorization':'Bearer '+CMS.getCmsToken(),'X-WP-Nonce':'cloudpress-nonce'}});
  const posts=await resp.json().catch(()=>[]);
  const total=parseInt(resp.headers.get('X-WP-Total')||'0');
  totalPages=parseInt(resp.headers.get('X-WP-TotalPages')||'1');
  if(!Array.isArray(posts)||!posts.length){tbody.innerHTML=`<tr><td colspan="6" style="text-align:center;padding:24px;color:#646970">글이 없습니다.</td></tr>`;renderPagination(total);return;}
  tbody.innerHTML=posts.map(p=>`
    <tr>
      <td class="column-cb"><input type="checkbox" class="post-cb" value="${p.id}"/></td>
      <td><strong><a href="/wp-admin/post.html?id=${p.id}">${CMS.esc(p.title?.rendered||'(제목 없음)')}</a></strong>
        <div class="row-actions">
          <span><a href="/wp-admin/post.html?id=${p.id}">편집</a></span>
          <span class="trash"><a href="#" onclick="trashPost(${p.id},this)">휴지통</a></span>
          <span><a href="${CMS.esc(p.link)}" target="_blank">보기</a></span>
        </div>
      </td>
      <td>${CMS.esc(p.author_name||'—')}</td>
      <td>미분류</td>
      <td><abbr title="${CMS.esc(p.date)}">${CMS.formatDate(p.date)}</abbr></td>
      <td><span class="status-${p.status}">${{publish:'발행',draft:'임시저장',trash:'휴지통',pending:'검토 대기'}[p.status]||p.status}</span></td>
    </tr>`).join('');
  renderPagination(total);
  updateSelectedCount();
}

function renderPagination(total){
  const el=document.getElementById('pagination');
  el.innerHTML=`<span style="font-size:.82rem;color:#646970">총 ${total}개</span>`;
  if(totalPages<=1)return;
  if(currentPage>1)el.innerHTML+=`<button class="button" onclick="loadPosts(${currentPage-1})">← 이전</button>`;
  el.innerHTML+=`<span style="font-size:.82rem;padding:0 8px">${currentPage} / ${totalPages}</span>`;
  if(currentPage<totalPages)el.innerHTML+=`<button class="button" onclick="loadPosts(${currentPage+1})">다음 →</button>`;
}

function toggleAll(cb){document.querySelectorAll('.post-cb').forEach(c=>c.checked=cb.checked);updateSelectedCount();}
function updateSelectedCount(){const n=document.querySelectorAll('.post-cb:checked').length;document.getElementById('selectedCount').textContent=n?`${n}개 선택됨`:'';}
document.addEventListener('change',e=>{if(e.target.classList.contains('post-cb'))updateSelectedCount();});

async function trashPost(id,a){
  if(!confirm('이 글을 휴지통으로 이동하시겠습니까?'))return;
  a.textContent='삭제 중...';
  await CMS.apiDelete(`/wp-json/wp/v2/posts/${id}`);
  CMS.showToast('휴지통으로 이동했습니다','success');
  loadPosts(currentPage);
}

async function applyBulk(){
  const action=document.getElementById('bulkAction').value;
  const ids=[...document.querySelectorAll('.post-cb:checked')].map(c=>c.value);
  if(!action||!ids.length){CMS.showToast('작업과 글을 선택해주세요','warning');return;}
  for(const id of ids){
    if(action==='trash')await CMS.apiDelete(`/wp-json/wp/v2/posts/${id}`);
    else await CMS.apiPut(`/wp-json/wp/v2/posts/${id}`,{status:action});
  }
  CMS.showToast(`${ids.length}개 글 처리 완료`,'success');
  loadPosts(currentPage);
}
