/* CloudPress CMS — wp-admin/users.js */
'use strict';

const API=`${location.origin}/wp-json/wp/v2`;
function esc(s){return String(s||'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));}
async function init(){
  const r=await fetch(`${API}/users/me`,{credentials:'include',headers:{'X-WP-Nonce':'cloudpress-nonce'}});
  if(!r.ok){location.href='/wp-login/';return;}
  const u=await r.json();document.getElementById('abUser').textContent=u.name;
  loadUsers();
}
async function loadUsers(){
  try{
    const r=await fetch(`${API}/users?per_page=50`,{credentials:'include',headers:{'X-WP-Nonce':'cloudpress-nonce'}});
    const users=await r.json();
    const tbody=document.getElementById('usersTbody');
    if(!Array.isArray(users)||!users.length){tbody.innerHTML='<tr><td colspan="6" style="padding:20px;text-align:center;color:var(--muted)">사용자가 없습니다.</td></tr>';return;}
    tbody.innerHTML=users.map(u=>`
      <tr>
        <td><div class="avatar">${(u.name||u.username||'U')[0].toUpperCase()}</div></td>
        <td><strong><a href="/wp-admin/user-edit.html?user_id=${u.id}">${esc(u.username)}</a></strong>
          <div class="row-actions">
            <span><a href="/wp-admin/user-edit.html?user_id=${u.id}">편집</a></span>
            <span>|</span><span class="delete"><a href="#" onclick="deleteUser(${u.id},'${esc(u.username)}');return false">삭제</a></span>
          </div></td>
        <td>${esc(u.name)}</td>
        <td>${esc(u.email)}</td>
        <td>${(u.roles||[]).map(r=>`<span class="role-badge role-${r}">${r==='administrator'?'관리자':r==='editor'?'편집자':r==='author'?'작성자':r==='subscriber'?'구독자':r}</span>`).join(' ')}</td>
        <td>0</td>
      </tr>`).join('');
  }catch(e){document.getElementById('usersTbody').innerHTML=`<tr><td colspan="6" style="color:var(--err);padding:14px">불러오기 실패: ${esc(e.message)}</td></tr>`;}
}
function showAddUser(){alert('사용자 추가 기능은 wp-admin/user-new.html 에서 사용 가능합니다.');}
function deleteUser(id,name){if(!confirm(`"${name}" 사용자를 삭제하시겠습니까?`))return;alert('사용자 삭제 API를 구현해야 합니다.');}
init();
