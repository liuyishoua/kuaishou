"""Persistent, account-scoped read plans and a deduplicated local work queue.

The worker only observes platforms. Outbound comments have a separate explicit
review endpoint; unknown outcomes remain frozen and are never replayed.
"""
import hashlib
import json
import threading
import time
import uuid
from flask import request
from .service import PlatformError


class Operations:
    def __init__(self, service, config):
        self.s, self.config = service, config
        self.stop = threading.Event()
        self.wake = threading.Event()
        self.worker_thread = None
        self.worker_guard = threading.Lock()
        self.last_tick = 0
        with service.db() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS operating_plans(uid TEXT,id TEXT PRIMARY KEY,name TEXT,kind TEXT,target TEXT,interval INTEGER,state TEXT,due REAL,last_run REAL DEFAULT 0,error TEXT DEFAULT '');
            CREATE TABLE IF NOT EXISTS operating_events(uid TEXT,id TEXT PRIMARY KEY,plan_id TEXT,source_id TEXT,payload TEXT,state TEXT DEFAULT 'new',created REAL,UNIQUE(uid,plan_id,source_id));
            CREATE TABLE IF NOT EXISTS operating_runs(uid TEXT,id TEXT PRIMARY KEY,plan_id TEXT,status TEXT,added INTEGER,error TEXT,created REAL);
            CREATE TABLE IF NOT EXISTS operating_comments(uid TEXT,id TEXT PRIMARY KEY,event_id TEXT,body TEXT,state TEXT,result TEXT DEFAULT '{}',created REAL);
            ''')
            db.execute("UPDATE operating_comments SET state='uncertain' WHERE state='sending'")
            db.execute("UPDATE operating_plans SET state='attention',error='执行被中断，请检查后恢复' WHERE state='running'")

    def capabilities(self):
        kinds=[]
        if self.config['search']: kinds.append({'id':'discover','name':'关键词定时采集','hint':'定时搜索关键词，新的结果自动进入待处理区'})
        if self.config['comments']: kinds.append({'id':'comments','name':'评论监听','hint':'读取指定内容当前页评论，去重汇总新增评论'})
        if self.config['slug']=='zhihu': kinds.append({'id':'zhihu_comments','name':'知乎评论监听','hint':'定时采集指定文章或回答的前两页评论'})
        return {'kinds':kinds,'comment_send':self.config['slug']=='bilibili','inbox':False,'automatic_agent':False,
                'purpose':'定时读取关键词结果或指定内容的评论，去重后加入待办；Agent 分析由你选择条目后发起。',
                'inbox_notice':'此工作台尚未接入私信接口；抖音、闲鱼和小红书可在各自工作台监听私信。',
                'coverage':'按间隔检查有限页数；高频新增可能超出采集窗口，不代表完整历史。'}

    def owned(self,db,table,key,uid=None):
        row=db.execute(f'SELECT * FROM {table} WHERE uid=? AND id=?',(self.s.uid() if uid is None else uid,key)).fetchone()
        if not row: raise LookupError('记录不存在')
        return dict(row)

    def snapshot(self):
        # Network reads hold the platform lock. Viewing stored results must not
        # wait for that lock, and must use one consistent account identity.
        account=self.s.platform.identity()
        uid=str(account['id']) if account else 'anonymous'
        with self.s.db() as db:
            def rows(table):return [dict(r) for r in db.execute(f'SELECT * FROM {table} WHERE uid=? ORDER BY rowid DESC LIMIT 100',(uid,))]
            events=[dict(row) for row in db.execute("SELECT * FROM operating_events WHERE uid=? ORDER BY (state='new') DESC,created DESC,rowid DESC LIMIT 100",(uid,))]
            for e in events:e['payload']=json.loads(e['payload'])
            counts={row['state']:row['n'] for row in db.execute('SELECT state,count(*) AS n FROM operating_events WHERE uid=? GROUP BY state',(uid,))}
            return {'platform_name':self.config['name'],'slug':self.config['slug'],'account':account,'capabilities':self.capabilities(),'plans':rows('operating_plans'),'events':events,'runs':rows('operating_runs'),'comments':rows('operating_comments'),
                    'event_counts':counts,'worker':{'running':bool(self.worker_thread and self.worker_thread.is_alive()),'last_check':self.last_tick},
                    'demo':bool(getattr(self.s.platform,'demo',False))}

    def create(self,data):
        kind=data.get('kind');name=data.get('name');target=data.get('target');interval=data.get('interval',1800)
        if kind not in {k['id'] for k in self.capabilities()['kinds']}:raise PlatformError('此平台不支持该计划类型')
        if not isinstance(name,str) or not 1<=len(name.strip())<=80:raise PlatformError('请填写 1–80 字计划名称')
        if not isinstance(target,str) or not 1<=len(target.strip())<=500:raise PlatformError('请填写关键词或内容链接，最多 500 字')
        if kind=='discover' and len(target.strip())>100:raise PlatformError('关键词最多 100 字')
        if type(interval) is not int or not 300<=interval<=604800:raise PlatformError('执行间隔为 5 分钟至 7 天')
        with self.s.lock,self.s.db() as db:
            uid=self.s.uid()
            if uid=='anonymous':raise PlatformError('请先连接平台账号')
            if db.execute('SELECT count(*) FROM operating_plans WHERE uid=?',(uid,)).fetchone()[0]>=20:raise PlatformError('每个账号最多 20 个计划，请删除不用的计划')
            pid=uuid.uuid4().hex
            db.execute('INSERT INTO operating_plans(uid,id,name,kind,target,interval,state,due) VALUES(?,?,?,?,?,?,?,?)',(uid,pid,name.strip(),kind,target.strip(),interval,'paused',0))
        return {'id':pid,'state':'paused'}

    def change(self,pid,action):
        if action not in ('start','pause','delete','check'):raise PlatformError('计划操作无效')
        # Plan controls only change local scheduling state. They must remain
        # available while a platform call is in flight.
        with self.s.db() as db:
            row=self.owned(db,'operating_plans',pid)
            if action=='delete':
                db.execute('DELETE FROM operating_plans WHERE id=?',(pid,))
            elif action=='pause':
                db.execute("UPDATE operating_plans SET state='paused',error='' WHERE id=?",(pid,))
            else:
                if row['state']=='running' or (action=='start' and row['state']=='active'):
                    return {'ok':True,'state':row['state']}
                if self.s.uid()=='anonymous':raise PlatformError('请先连接平台账号')
                state='active' if action=='start' or row['state']=='active' else 'queued'
                db.execute('UPDATE operating_plans SET state=?,due=?,error=? WHERE id=?',(state,time.time(),'',pid))
        self.wake.set()
        return {'ok':True,'state':state if action in ('start','check') else 'paused' if action=='pause' else 'deleted'}

    def tick(self):
        # Shares the account lock with connect/disconnect and ordinary platform work.
        # SQLite claim also prevents two worker instances executing the same plan.
        with self.s.lock:
            uid=self.s.uid()
            if uid=='anonymous':return
            with self.s.db() as db:
                row=db.execute("SELECT * FROM operating_plans WHERE uid=? AND state IN ('active','queued') AND due<=? ORDER BY due LIMIT 1",(uid,time.time())).fetchone()
                if not row:return
                plan=dict(row)
                claim=db.execute("UPDATE operating_plans SET state='running' WHERE id=? AND state=?",(plan['id'],plan['state']))
                if claim.rowcount!=1:return
            added=0;error='';status='completed';resume_state='paused' if plan['state']=='queued' else 'active'
            try:
                target=plan['target'];kind=plan['kind']
                if kind=='discover':
                    result=self.s.platform.search(target,1,self.config['orders'][0][0]);items=result.get('items',[])[:50]
                elif kind=='comments':
                    parent=self.s.platform.detail(target)
                    self.s.put('result',parent,uid)
                    items=[{**c,'title':parent.get('title',''),'url':parent.get('url',''),'parent':parent} for c in self.s.platform.comments(parent).get('comments',[])[:100]]
                else:
                    result=self.s.platform.tool('collect',{'value':target,'kind':'article' if '/p/' in target else 'answer','pages':2,'children':'no'})
                    items=result.get('items',[])[:100]
                if kind=='discover':
                    for item in items:self.s.put('result',item,uid)
                now=time.time()
                with self.s.db() as db:
                    for item in items:
                        source=str(item.get('id') or '')
                        if not source:continue
                        eid=hashlib.sha256((uid+'\0'+plan['id']+'\0'+source).encode()).hexdigest()
                        inserted=db.execute('INSERT OR IGNORE INTO operating_events(uid,id,plan_id,source_id,payload,created) VALUES(?,?,?,?,?,?)',(uid,eid,plan['id'],source,json.dumps(item,ensure_ascii=False),now))
                        added+=inserted.rowcount
                    # Retain bounded event history per account, preserving pending comments separately.
                    db.execute('DELETE FROM operating_events WHERE uid=? AND id NOT IN (SELECT id FROM operating_events WHERE uid=? ORDER BY created DESC,rowid DESC LIMIT 2000)',(uid,uid))
            except PlatformError as exc:
                status='failed';error=str(exc)[:240]
            except Exception:
                status='failed';error='读取未完成：请检查登录、目标链接或平台限制，再手动恢复。'
            with self.s.db() as db:
                db.execute('UPDATE operating_plans SET state=?,last_run=?,due=?,error=? WHERE id=? AND state=\'running\'',(resume_state if status=='completed' else 'attention',time.time(),time.time()+plan['interval'],error,plan['id']))
                db.execute('INSERT INTO operating_runs VALUES(?,?,?,?,?,?,?)',(uid,uuid.uuid4().hex,plan['id'],status,added,error,time.time()))
                db.execute('DELETE FROM operating_runs WHERE uid=? AND id NOT IN (SELECT id FROM operating_runs WHERE uid=? ORDER BY created DESC LIMIT 500)',(uid,uid))

    def start_worker(self):
        with self.worker_guard:
            if self.worker_thread and self.worker_thread.is_alive():return self.worker_thread
            def run():
                while not self.stop.is_set():
                    self.wake.wait(10);self.wake.clear()
                    if self.stop.is_set():break
                    self.last_tick=time.time()
                    try:self.tick()
                    except Exception:pass  # No outbound writes; retry local scheduling next tick.
            self.worker_thread=threading.Thread(target=run,name='operating-observer',daemon=True)
            self.worker_thread.start()
            return self.worker_thread

    def event_action(self,eid,data):
        action=data.get('action')
        uid=self.s.uid()
        with self.s.db() as db:
            event=self.owned(db,'operating_events',eid,uid)
            if action in ('done','new'):
                db.execute('UPDATE operating_events SET state=? WHERE id=?',(action,eid));return {'ok':True}
            if action=='collect':
                payload=json.loads(event['payload'])
                parent=payload.get('parent')
                if parent:
                    payload={**payload,'id':'comment-'+str(payload.get('id','')),'kind':'comment',
                             'title':('评论 · '+str(parent.get('title','')))[:160],'parent_id':str(parent.get('id',''))}
                try:previous=self.s.record('item',payload['id'],uid)
                except LookupError:previous={}
                payload.update({key:previous[key] for key in ('note','tags') if key in previous})
                self.s.put('item',payload,uid);return {'ok':True}
            if action=='draft':
                body=data.get('body','')
                if not isinstance(body,str) or not 1<=len(body.strip())<=1000:raise PlatformError('评论正文需要 1–1000 字')
                payload=json.loads(event['payload'])
                if self.config['slug']!='bilibili' or not (payload.get('aid') or payload.get('parent',{}).get('aid')):raise PlatformError('当前条目不支持发布评论，可收藏后作为研究资料')
                cid=uuid.uuid4().hex
                db.execute('INSERT INTO operating_comments(uid,id,event_id,body,state,created) VALUES(?,?,?,?,?,?)',(uid,cid,eid,body.strip(),'draft',time.time()))
                return {'id':cid}
            raise PlatformError('处理方式无效')

    def send(self,cid,data):
        with self.s.lock:
            if data.get('confirm') is not True or data.get('account_id')!=self.s.uid():raise PlatformError('请核对账号后确认发布这条评论')
            with self.s.db() as db:
                draft=self.owned(db,'operating_comments',cid)
                if draft['state']!='draft':return {'state':draft['state'],'result':json.loads(draft['result'])}
                event=self.owned(db,'operating_events',draft['event_id'])
                payload=json.loads(event['payload']);parent=payload.get('parent') or payload
                db.execute("UPDATE operating_comments SET state='sending' WHERE id=?",(cid,))
            try:
                result=self.s.platform.post_comment(parent,draft['body'],payload['id'] if payload.get('parent') else '')
                state='submitted'  # Platform acknowledgement is not independent visibility verification.
            except Exception:
                result={'notice':'结果未确认，请到平台核对；不会重发此草稿。'};state='uncertain'
            with self.s.db() as db:db.execute('UPDATE operating_comments SET state=?,result=? WHERE id=?',(state,json.dumps(result,ensure_ascii=False),cid))
            return {'state':state,'result':result}


def register_operations(app,service,config):
    ops=Operations(service,config);app.extensions['operations']=ops
    app.add_url_rule('/operations','operations_page',lambda:app.send_static_file('operations.html'))
    app.add_url_rule('/api/operations','operations_snapshot',ops.snapshot)
    app.add_url_rule('/api/operations/plans','operations_create',lambda:ops.create(request.json),methods=['POST'])
    app.add_url_rule('/api/operations/plans/<pid>/<action>','operations_change',ops.change,methods=['POST'])
    app.add_url_rule('/api/operations/events/<eid>','operations_event',lambda eid:ops.event_action(eid,request.json),methods=['POST'])
    app.add_url_rule('/api/operations/comments/<cid>/send','operations_send',lambda cid:ops.send(cid,request.json),methods=['POST'])
