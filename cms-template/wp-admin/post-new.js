/* CloudPress CMS — wp-admin/post-new.js */
'use strict';

let editingId=null;
let sourceMode=false;
const params=new URLSearchParams(location.search);
const editId=params.get('id');

(async()=>{
  const ctx=await CMS.initAdminPage('post-new');if(!ctx)return;
  // 날짜 기본값
  const now=new Date();now.setMinutes(now.getMinutes()-now.getTimezoneOffset());
  document.getElementById('post_date').value=now.toISOString().slice(0,16);
  await loadCategories();
  if(editId)await loadPost(editId);
  // 제목 → slug 미리보기
  document.getElementById('title').addEventListener('input',updateSlug);
})();

async function loadPost(id){
  const p=await CMS.apiGet(`/wp-json/wp/v2/posts/${id}`);
  if(!p.id){CMS.showToast('글을 찾을 수 없습니다','error');return;}
  editingId=id;
  document.getElementById('title').textContent=p.title?.raw||p.title?.rendered||'';
  document.getElementById('title').value=p.title?.raw||p.title?.rendered||'';
  document.getElementById('content').innerHTML=p.content?.rendered||p.content?.raw||'';
  document.getElementById('excerpt').value=p.excerpt?.raw||p.excerpt?.rendered||'';
  document.getElementById('post_status').value=p.status||'draft';
  document.getElementById('pageHeading').textContent='글 편집';
  document.title=`글 편집 — CloudPress CMS`;
  updateSlug();
}

function updateSlug(){
  const t=document.getElementById('title').value.trim();
  const slug=t.toLowerCase().replace(/[^a-z0-9가-힣]/g,'-').replace(/-+/g,'-').replace(/^-+|-+$/g,'').slice(0,80);
  const box=document.getElementById('slugbox');
  const prev=document.getElementById('slugPreview');
  if(t){box.style.display='';prev.textContent=location.origin+'/'+slug+'/';prev.href=location.origin+'/'+slug+'/';}
  else box.style.display='none';
}
function editSlug(){const s=prompt('고유주소 변경:',document.getElementById('slugPreview').textContent.replace(location.origin+'/','').replace('/',''));if(s!==null)document.getElementById('slugPreview').textContent=location.origin+'/'+s+'/';}

async function loadCategories(){
  const cats=await CMS.apiGet('/wp-json/wp/v2/categories').catch(()=>[]);
  const el=document.getElementById('categoryBox');
  if(!Array.isArray(cats)||!cats.length){el.innerHTML='<div style="font-size:.85rem;color:#646970">카테고리 없음</div><a href="/wp-admin/edit.html?taxonomy=category" style="font-size:.82rem">+ 새 카테고리</a>';return;}
  el.innerHTML=cats.map(c=>`<label style="display:flex;align-items:center;gap:6px;margin-bottom:6px;font-size:.88rem;cursor:pointer"><input type="checkbox" class="cat-cb" value="${c.id}" ${c.slug==='uncategorized'?'checked':''}/>${CMS.esc(c.name)}</label>`).join('')+'<a href="/wp-admin/edit.html?taxonomy=category" style="font-size:.82rem;display:block;margin-top:8px">+ 새 카테고리 추가</a>';
}

function fmt(cmd){document.getElementById('content').focus();document.execCommand(cmd,false,null);}
function fmtBlock(tag){document.getElementById('content').focus();document.execCommand('formatBlock',false,tag);}
function insertLink(){const url=prompt('URL 입력:');if(url){document.getElementById('content').focus();document.execCommand('createLink',false,url);}}
function insertImg(){const url=prompt('이미지 URL 입력:');if(url){document.getElementById('content').focus();document.execCommand('insertImage',false,url);}}

function toggleSource(){
  sourceMode=!sourceMode;
  const vis=document.getElementById('content');
  const src=document.getElementById('content-source');
  const btn=document.getElementById('sourceBtn');
  if(sourceMode){src.value=vis.innerHTML;vis.style.display='none';src.style.display='';btn.style.background='#2271b1';btn.style.color='#fff';}
  else{vis.innerHTML=src.value;src.style.display='none';vis.style.display='';btn.style.background='';btn.style.color='';}
}

function getContent(){return sourceMode?document.getElementById('content-source').value:document.getElementById('content').innerHTML;}

async function savePost(status){
  const title=document.getElementById('title').value.trim();
  const content=getContent();
  const excerpt=document.getElementById('excerpt').value.trim();
  const postDate=document.getElementById('post_date').value;
  const cats=[...document.querySelectorAll('.cat-cb:checked')].map(c=>parseInt(c.value));
  if(!title){CMS.showToast('제목을 입력해주세요','warning');return null;}
  const msg=document.getElementById('saveMsg');msg.textContent='저장 중...';
  const data={title,content,excerpt,status,categories:cats.length?cats:[1]};
  if(postDate)data.date=new Date(postDate).toISOString();
  let r;
  if(editingId){r=await CMS.apiPut(`/wp-json/wp/v2/posts/${editingId}`,data);}
  else{r=await CMS.apiPost('/wp-json/wp/v2/posts',data);}
  if(r.id){
    if(!editingId){editingId=r.id;history.replaceState(null,'',`/wp-admin/post-new.html?id=${r.id}`);}
    msg.innerHTML=`✅ 저장됨 (<a href="${CMS.esc(r.link)}" target="_blank">보기</a>)`;msg.style.color='#00a32a';
    CMS.showToast(status==='publish'?'발행되었습니다':'임시저장 완료','success');
    return r;
  }
  msg.textContent='저장 실패: '+(r.message||'알 수 없는 오류');msg.style.color='#d63638';
  CMS.showToast('저장 실패','error');return null;
}
async function saveDraft(){await savePost('draft');}
async function publishPost(){const r=await savePost('publish');if(r&&r.link)window.open(r.link,'_blank');}
function openMediaPicker(){CMS.showToast('미디어 라이브러리에서 이미지를 선택하세요','info');}
