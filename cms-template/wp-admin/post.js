/* CloudPress CMS — wp-admin/post.js */
'use strict';

const API=`${location.origin}/wp-json/wp/v2`;
const qs=new URLSearchParams(location.search);
const postId=qs.get('post');
const postType=qs.get('post_type')||'post';
const ep=postType==='page'?'pages':'posts';
let savedStatus='draft';

// 날짜 기본값
document.getElementById('postDate').value=new Date().toISOString().slice(0,16);

async function init(){
  const r=await fetch(`${API}/users/me`,{credentials:'include',headers:{'X-WP-Nonce':'cloudpress-nonce'}});
  if(!r.ok){location.href='/wp-login/';return;}
  const u=await r.json();document.getElementById('abUser').textContent=u.name;
  loadCategories();
  if(postId) loadPost(postId);
}

async function loadPost(id){
  try{
    const r=await fetch(`${API}/${ep}/${id}`,{credentials:'include',headers:{'X-WP-Nonce':'cloudpress-nonce'}});
    if(!r.ok)return;
    const p=await r.json();
    document.getElementById('postTitle').value=p.title?.raw||p.title?.rendered||'';
    document.getElementById('editorContent').innerHTML=p.content?.rendered||p.content?.raw||'';
    document.getElementById('postExcerpt').value=p.excerpt?.raw||'';
    document.getElementById('slugInput').value=p.slug||'';
    document.getElementById('slugPreview').textContent=p.slug||'—';
    document.getElementById('postStatus').value=p.status||'draft';
    savedStatus=p.status||'draft';
    updateStatusPill(p.status);
    document.title=`"${(p.title?.raw||'').slice(0,20)}" 편집 — CloudPress 관리자`;
    autoResize(document.getElementById('postTitle'));
  }catch(e){}
}

async function loadCategories(){
  try{
    const r=await fetch(`${API}/categories?per_page=50`);
    const cats=await r.json();
    const list=document.getElementById('catList');
    if(!Array.isArray(cats)||!cats.length){list.innerHTML='<li style="color:var(--muted)">카테고리 없음</li>';return;}
    list.innerHTML=cats.map(c=>`<li><label><input type="checkbox" class="cat-check" value="${c.id}" ${c.slug==='uncategorized'?'checked':''}/> ${esc(c.name)} (${c.count})</label></li>`).join('');
  }catch(e){}
}

async function savePost(status){
  const title=document.getElementById('postTitle').value.trim();
  const content=document.getElementById('editorContent').innerHTML;
  const excerpt=document.getElementById('postExcerpt').value.trim();
  const slug=document.getElementById('slugInput').value.trim()||title.toLowerCase().replace(/[^a-z0-9가-힣]/g,'-').replace(/-+/g,'-').slice(0,80);
  const cats=[...document.querySelectorAll('.cat-check:checked')].map(c=>parseInt(c.value));
  const tags=document.getElementById('tagsInput').value.split(',').map(t=>t.trim()).filter(Boolean);
  const dateVal=document.getElementById('postDate').value;
  const msgEl=document.getElementById('saveMsg');
  msgEl.className='';msgEl.textContent='저장 중...';

  const body={title,content,excerpt,slug,status,categories:cats.length?cats:[1]};
  if(dateVal) body.date=new Date(dateVal).toISOString();

  try{
    let r;
    if(postId&&postId!=='new'){
      r=await fetch(`${API}/${ep}/${postId}`,{method:'PUT',credentials:'include',headers:{'Content-Type':'application/json','X-WP-Nonce':'cloudpress-nonce'},body:JSON.stringify(body)});
    }else{
      r=await fetch(`${API}/${ep}`,{method:'POST',credentials:'include',headers:{'Content-Type':'application/json','X-WP-Nonce':'cloudpress-nonce'},body:JSON.stringify(body)});
    }
    const d=await r.json();
    if(r.ok){
      msgEl.className='ok';msgEl.textContent=status==='publish'?'발행됨 ✓':'임시 저장됨 ✓';
      savedStatus=status;updateStatusPill(status);
      if(!postId||postId==='new') history.replaceState(null,'',`?post=${d.id}&post_type=${postType}`);
      setTimeout(()=>{msgEl.textContent='';},3000);
    }else{msgEl.className='err';msgEl.textContent=d.message||'저장 실패';}
  }catch(e){msgEl.className='err';msgEl.textContent='오류: '+e.message;}
}

function updateStatusPill(status){
  const pill=document.getElementById('statusPill');
  pill.textContent=status==='publish'?'발행됨':status==='draft'?'임시글':'비공개';
  pill.className='status-pill'+(status==='publish'?' pub':'');
}

function fmt(cmd){document.execCommand(cmd,false,null);document.getElementById('editorContent').focus();}
function insertBlock(tag){
  const sel=window.getSelection();if(!sel.rangeCount)return;
  const range=sel.getRangeAt(0);
  const el=document.createElement(tag==='hr'?'hr':tag);
  if(tag!=='hr') el.innerHTML='<br>';
  range.insertNode(el);
  if(tag!=='hr'){const r=document.createRange();r.setStart(el,0);r.collapse(true);sel.removeAllRanges();sel.addRange(r);}
  document.getElementById('editorContent').focus();
}
function insertLink(){
  const url=prompt('링크 URL을 입력하세요:');
  if(url) document.execCommand('createLink',false,url);
}
function insertImage(){
  const url=prompt('이미지 URL을 입력하세요:');
  if(url) document.execCommand('insertImage',false,url);
}

function autoResize(el){el.style.height='auto';el.style.height=el.scrollHeight+'px';}
function updateSlug(){
  const t=document.getElementById('postTitle').value;
  const s=t.toLowerCase().replace(/[^a-z0-9가-힣]/g,'-').replace(/-+/g,'-').slice(0,80);
  if(!document.getElementById('slugInput').value){document.getElementById('slugPreview').textContent=s||'—';}
}
function editSlug(){const s=prompt('고유주소(slug)를 입력하세요:',document.getElementById('slugInput').value);if(s!==null){document.getElementById('slugInput').value=s;document.getElementById('slugPreview').textContent=s||'—';}}
function togglePanel(h){const b=h.nextElementSibling;b.style.display=b.style.display==='none'?'':'none';}
function previewFeatured(input){const f=input.files[0];if(!f)return;const r=new FileReader();r.onload=e=>{const img=document.getElementById('featuredPreview');img.src=e.target.result;img.style.display='block';document.getElementById('featuredArea').querySelector('div').style.display='none';};r.readAsDataURL(f);}
function addCat(){const n=prompt('새 카테고리 이름:');if(!n)return;fetch(`${API}/categories`,{method:'POST',credentials:'include',headers:{'Content-Type':'application/json','X-WP-Nonce':'cloudpress-nonce'},body:JSON.stringify({name:n})}).then(r=>r.json()).then(c=>{if(c.id)loadCategories();});}
function esc(s){return String(s||'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));}
init();
