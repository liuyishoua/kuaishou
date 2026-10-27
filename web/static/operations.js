const $=s=>document.querySelector(s),esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const names={queued:'等待检查',paused:'已暂停',active:'已启动',running:'正在检查',attention:'需要处理',completed:'完成',failed:'未完成',draft:'草稿',sending:'提交中',submitted:'平台已接受',uncertain:'结果待核对'};
const date=n=>n?new Date(n*1000).toLocaleString('zh-CN'):'尚未执行';
const url=v=>{try{const u=new URL(v);return u.protocol==='https:'?u.href:''}catch{return ''}};
let state,locked=false,refreshing=false;
const draftBodies=new Map();
document.addEventListener("input",e=>{const f=e.target.closest("form[data-draft]");if(f)draftBodies.set(f.dataset.draft,e.target.value)});
async function api(path,data){
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),15000);
 try{const r=await fetch(path,{signal:controller.signal,...(data?{method:'POST',headers:{'Content-Type':'application/json','X-App-Request':'1'},body:JSON.stringify(data)}:{})});
 const value=await r.json();if(r.status===401){location.assign('https://d.58nft.net:9461/platform-select');throw Error('请先登录应用中心')}
 if(!r.ok)throw Error(value.error||'操作未完成');return value;
 }catch(e){if(e.name==='AbortError')throw Error('请求超时，请刷新查看结果；已提交的操作可能仍在后台执行');throw e}finally{clearTimeout(timer)}
}
function render(){
 const caps=state.capabilities;
 $('#platform-name').textContent=state.platform_name+' / 定时采集与待办';document.title=state.platform_name+' · 定时采集';
 $('#purpose').textContent=caps.purpose;
 $('#worker-status').textContent=state.worker?.running?'后台检查服务运行中':'后台检查服务未运行，计划暂不能执行';
 $('#capability-note').textContent='支持：'+caps.kinds.map(k=>k.name).join('、')+'。'+(caps.comment_send?'B站评论可保存草稿，逐条确认后提交。':'互动在原文处理。')+' Agent 分析需要手动选择条目发起。';
 $('#account-help').hidden=!!state.account;
 $('#comment-panel').hidden=!caps.comment_send;
 $('#account-name').textContent=state.account?state.account.name+' · '+state.account.id:'未连接平台账号';
 $('#notice').textContent=state.demo?'离线演示模式：所有结果为演示数据，不会联系真实平台。':'';
 $('#summary').innerHTML=[['采集计划',state.plans.length],['运行中',state.plans.filter(p=>['active','running'].includes(p.state)).length],['待处理',state.event_counts?.new||0],['需要关注',state.plans.filter(p=>p.state==='attention').length]].map(([t,n])=>`<div class="stat"><span>${t}</span><strong>${n}</strong></div>`).join('');
 if(!$('#kind').options.length)$('#kind').innerHTML=caps.kinds.map(k=>`<option value="${esc(k.id)}">${esc(k.name)}</option>`).join('');
 $('#plan-form button').disabled=!state.account||!caps.kinds.length;
 $('#plans').innerHTML=state.plans.map(p=>`<article class="operation-row"><div class="row"><strong class="grow">${esc(p.name)}</strong><span>${names[p.state]||esc(p.state)}</span></div><p>${esc(p.target)} · 每 ${p.interval/60} 分钟<br>上次：${date(p.last_run)}${p.state==='active'?'<br>下次：'+date(p.due):''}${p.error.trim()?'<br>'+esc(p.error):''}</p><div class="row"><button data-act="check" data-plan="${p.id}" ${['queued','running'].includes(p.state)?'disabled':''}>${p.state==='running'?'检查中…':p.state==='queued'?'已排队':'立即检查'}</button><button data-act="${['active','running','queued'].includes(p.state)?'pause':'start'}" data-plan="${p.id}">${['active','running','queued'].includes(p.state)?'暂停':'启动定时采集'}</button><button data-act="delete" data-plan="${p.id}">删除计划</button></div></article>`).join('')||'<p class="hint">还没有计划。创建后先点“立即检查”验证结果，再决定是否启动定时采集。</p>';
 const events=state.events.filter(e=>$('#event-filter').value==='all'||e.state==='new');
 if(!document.activeElement?.matches('#events textarea'))$('#events').innerHTML=events.map(e=>{const p=e.payload,canComment=caps.comment_send&&(p.aid||p.parent?.aid);return `<article class="operation-row"><div class="row"><strong class="grow">${esc(p.title||p.author||'新增内容')}</strong><small>${date(e.created)}</small></div><p>${esc(p.text||'')}<br>${esc(p.author||'')}</p><div class="row">${url(p.url)?`<a href="${esc(url(p.url))}" target="_blank" rel="noopener noreferrer">查看原文 ↗</a>`:''}<button data-agent="${e.id}">交给 Agent 分析</button><button data-act="collect" data-event="${e.id}">收藏资料</button><button data-act="${e.state==='new'?'done':'new'}" data-event="${e.id}">${e.state==='new'?'标记处理完成':'重新待办'}</button></div>${canComment?`<form data-draft="${e.id}"><label>评论正文<textarea name="body" required maxlength="1000" placeholder="结合这条内容写下评论；保存后核对账号与目标再提交">${esc(draftBodies.get(e.id)||'')}</textarea></label><button>保存评论草稿</button></form>`:''}</article>`}).join('')||'<p class="hint">当前没有待处理结果。点击计划的“立即检查”读取一次；重复内容不会再次进入待办。</p>';
 $('#comments').innerHTML=state.comments.map(c=>`<article class="operation-row"><strong>${names[c.state]||esc(c.state)}</strong><p>${esc(c.body)}</p>${c.state==='draft'?`<button data-review="${c.id}">核对并发布</button>`:c.state==='uncertain'?'<p>请到平台核对结果，这条草稿不会自动重发。</p>':''}</article>`).join('')||`<p class="hint">${caps.comment_send?'从待处理内容保存评论草稿，核对后可发布。':'此平台尚未接入评论发送，可收藏资料并在原文处理互动。'}</p>`;
 $('#runs').innerHTML=state.runs.slice(0,20).map(r=>`<article class="operation-row">${date(r.created)} · ${esc(state.plans.find(p=>p.id===r.plan_id)?.name||'已删除计划')} · ${names[r.status]} · 新增 ${r.added} 条${r.error?'<p>'+esc(r.error)+'</p>':''}</article>`).join('')||'<p class="hint">还没有执行记录。</p>';
 $('#capabilities').textContent=caps.coverage+' '+caps.inbox_notice;
}
async function refresh(){if(refreshing)return;refreshing=true;try{state=await api('/api/operations');render()}finally{refreshing=false}}

async function act(work){if(locked)return;locked=true;$('#error').textContent='';try{await work();await refresh()}catch(e){$('#error').textContent=e.message}finally{locked=false}}
$('#refresh').onclick=()=>act(async()=>{});$('#event-filter').onchange=render;
$('#plan-form').onsubmit=e=>{e.preventDefault();const d=Object.fromEntries(new FormData(e.target));act(async()=>{await api('/api/operations/plans',{...d,interval:Number(d.interval)});e.target.reset()})};
document.addEventListener('submit',e=>{const f=e.target;if(!f.dataset.draft)return;e.preventDefault();act(()=>api('/api/operations/events/'+f.dataset.draft,{action:'draft',body:new FormData(f).get('body')}))});
document.addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;
 if(b.dataset.agent)void openAgent(b.dataset.agent);
 if(b.dataset.plan){if(b.dataset.act==='delete'&&!confirm('删除这个计划？已有结果与提交记录将保留。'))return;act(()=>api('/api/operations/plans/'+b.dataset.plan+'/'+b.dataset.act,{}))}
 if(b.dataset.event)act(()=>api('/api/operations/events/'+b.dataset.event,{action:b.dataset.act}));
 if(b.dataset.review){const c=state.comments.find(x=>x.id===b.dataset.review),event=state.events.find(x=>x.id===c.event_id);$('#review-content').innerHTML=`<h2>核对这条评论</h2><p>账号：${esc(state.account?.name)} · ${esc(state.account?.id)}<br>目标：${esc(event?.payload.title||event?.source_id||'原内容')}<br>可见性：公开</p><p>${esc(c.body)}</p><label><input type="checkbox" id="confirm-comment">确认向以上目标发布这条评论</label><div class="form-actions"><button id="send-comment">确认发布</button></div>`;$('#review-dialog').showModal();const accountId=state.account?.id;$('#send-comment').onclick=()=>{if(!$('#confirm-comment').checked)return;$('#review-dialog').close();act(()=>api('/api/operations/comments/'+c.id+'/send',{confirm:true,account_id:String(accountId)}))}}
});
await act(async()=>{});
// Only read stored state. Polling never executes a plan or calls a platform.
setInterval(()=>{if(!document.hidden&&!locked&&state)refresh().catch(e=>{$('#error').textContent=e.message})},5000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden&&!locked)refresh().catch(e=>{$('#error').textContent=e.message})});

async function openAgent(eid){
 try {
  const event=state.events.find(e=>e.id===eid),accountId=String(state.account?.id||'');
  $('#review-content').innerHTML=`<h2>交给 Agent</h2><p>${esc(event.payload.title||event.payload.text||'当前内容')}</p><label>选择 Agent<select id="agent-select" disabled><option value="">正在读取 Agent 目录…</option></select></label><label>处理要求<textarea id="agent-prompt" maxlength="4000">分析内容与评论，提炼值得跟进的观点，给出具体互动建议与评论草稿。只提供建议，不执行发布。</textarea></label><button id="agent-send" disabled>提交分析</button><div id="agent-result" role="status"></div>`;
  $('#review-dialog').showModal();
  const picker=$('#agent-select'),sendButton=$('#agent-send'),output=$('#agent-result');
  let catalog;
  try{catalog=await api('/api/channel/catalog')}catch(e){if($('#agent-select')===picker)output.textContent=e.message;return}
  if(!$('#review-dialog').open||$('#agent-select')!==picker)return;
  picker.innerHTML='<option value="">请选择一个 Agent</option>'+catalog.agents.map(a=>`<option value="${esc(a.id)}">${esc(a.name)}</option>`).join('');
  picker.disabled=false;sendButton.disabled=!catalog.agents.length;
  if(!catalog.agents.length)output.textContent='还没有可用 Agent，请在 Multica 配置后重新打开。';
  const messageId='operations-event-'+eid+'-'+crypto.randomUUID();
  $('#agent-send').onclick=async()=>{
   const button=$('#agent-send');if(!picker.value){output.textContent='请选择一个 Agent';return}button.disabled=true;
   try{
    const task=await api('/api/channel/messages',{account_id:accountId,agent_id:$('#agent-select').value,message_id:messageId,category:event.payload.parent?'comment_analysis':'content_analysis',text:$('#agent-prompt').value,context:{item:event.payload},conversation_id:'operations:'+eid});
    const taskId=task.id||task.event_id;
    output.textContent='任务已提交，分析结果保存在 Agent 任务记录中。';
    const check=document.createElement('button');check.textContent='查看分析结果';output.append(check);
    check.onclick=async()=>{check.disabled=true;try{const r=await api('/api/channel/messages/'+encodeURIComponent(taskId));const output=r.result?.output;const text=document.createElement('p');text.style.whiteSpace='pre-wrap';text.textContent=typeof output==='string'?output:output?.structured?.reply||output?.text||('任务状态：'+(r.state||r.status||'等待返回'));output.append(text)}catch(e){$('#error').textContent=e.message}finally{check.disabled=false}};
   }catch(e){output.textContent=e.message;button.disabled=false}
  };
 }catch(e){$('#error').textContent=e.message}
}
