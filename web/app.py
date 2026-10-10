"""Independent workspace authentication, API and same-origin protection."""
from pathlib import Path
import json
import csv
import io
import os
import secrets
import time
from urllib.parse import urlsplit
from flask import Flask, jsonify, request, session, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException
from .config import CONFIG
from .platform import Platform
from .service import Service, PlatformError

ROOT = Path(__file__).resolve().parents[1]


def private_file(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as out: out.write(content)


def create_app(directory=None, platform=None, auth=True, public_origin=None):
    directory = Path(directory or ROOT / '.local' / 'web')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, value in [('session-key',secrets.token_hex(32)),('admin-password',secrets.token_urlsafe(18))]:
        if not (directory/name).exists(): private_file(directory/name, value)
    app = Flask(__name__, static_folder='static')
    app.config.update(SECRET_KEY=(directory/'session-key').read_text(), MAX_CONTENT_LENGTH=100*1024,
        SESSION_COOKIE_NAME=CONFIG['slug']+'_console', SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Strict', SESSION_COOKIE_SECURE=bool(public_origin and public_origin.startswith('https:')),
        PERMANENT_SESSION_LIFETIME=12*3600)
    password_hash = generate_password_hash((directory/'admin-password').read_text().strip())
    service = Service(directory, platform or Platform(directory))
    app.extensions['workspace'] = service
    from .channel_bridge import register_channel
    def channel_record(item_id, owner):
        try: return service.record('result', item_id, uid=owner)
        except LookupError: return service.record('item', item_id, uid=owner)
    register_channel(app, service, directory/'channel.json', channel_record)
    attempts = {}

    @app.before_request
    def guard():
        if request.method not in ('GET','HEAD','OPTIONS'):
            expected = (public_origin or request.host_url.rstrip('/')).rstrip('/')
            if request.headers.get('Origin','').rstrip('/') != expected or request.headers.get('X-App-Request') != '1':
                return jsonify(error='请求来源无效，请从工作台操作'),403
            if not request.is_json or not isinstance(request.get_json(silent=True),dict):
                return jsonify(error='请求内容必须是 JSON 对象'),400
        if request.path in ('/login','/api/login') or request.path.startswith('/static/'): return
        if auth and not session.get('authenticated'):
            if request.path.startswith('/api/'): return jsonify(error='请先登录工作台'),401
            return redirect('/login')

    @app.after_request
    def headers(response):
        response.headers['Cache-Control']='no-store'
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['Referrer-Policy']='no-referrer'
        response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' https: data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        return response

    @app.errorhandler(Exception)
    def error(exc):
        if isinstance(exc, LookupError): return jsonify(error='记录不存在'),404
        if isinstance(exc,PlatformError): return jsonify(error=str(exc)),400
        if isinstance(exc,ValueError): return jsonify(error='请求参数无效，请检查输入内容'),400
        if isinstance(exc,HTTPException): return jsonify(error='请求无效'),exc.code
        app.logger.error('Workspace error: %s',type(exc).__name__)
        return jsonify(error='操作未完成，请检查平台状态和网络'),502

    @app.get('/login')
    def login_page(): return app.send_static_file('login.html')

    @app.post('/api/login')
    def login():
        now=time.time(); ip=request.remote_addr
        attempts[ip]=[at for at in attempts.get(ip,[]) if now-at<60]
        if len(attempts[ip])>=8: return jsonify(error='尝试过于频繁，请稍后重试'),429
        if auth and not check_password_hash(password_hash,str(request.json.get('password',''))):
            attempts[ip].append(now)
            return jsonify(error='访问密码不正确'),401
        session.clear(); session['authenticated']=True; session.permanent=True
        return {'ok':True}

    @app.post('/api/logout')
    def logout(): session.clear(); return {'ok':True}

    @app.get('/')
    def index(): return app.send_static_file('index.html')

    @app.get('/api/meta')
    def meta(): return {**CONFIG,'account':service.platform.identity(),'demo':bool(getattr(service.platform,'demo',False))}

    @app.get('/api/overview')
    def overview():
        return {'library':service.records('item'),'drafts':service.records('draft'),'jobs':service.jobs()[:8]}

    @app.get('/api/library')
    def library(): return {'items':service.records('item')}

    @app.post('/api/library/<item_id>')
    def save_item(item_id):
        with service.lock:
            return service.collect([item_id])[0]

    @app.post('/api/library/batch')
    def collect_batch():
        with service.lock: return {'items':service.collect(request.json.get('ids'))}

    @app.patch('/api/library/<item_id>')
    def annotate(item_id):
        with service.lock:
            value=service.record('item',item_id)
            value.update(note=str(request.json.get('note',''))[:2000],tags=str(request.json.get('tags',''))[:150])
            return service.put('item',value)

    @app.delete('/api/library/<item_id>')
    def remove(item_id):
        with service.lock: service.remove('item',item_id)
        return {'ok':True}

    @app.post('/api/tools/<name>')
    def tool(name):
        if name not in {x['id'] for x in CONFIG.get('tools',[])}: raise LookupError('工具不存在')
        data=dict(request.json)
        def work(uid):
            result=service.platform.tool(name,data)
            for item in result.get('items',[]): service.put('result',item,uid)
            return result
        return jsonify(service.submit(CONFIG['name']+' · '+name,data.get('request_id'),work)),202

    @app.get('/api/library/<item_id>/history')
    def history(item_id):
        return {'items':[x for x in service.records('snapshot') if x.get('item_id')==item_id]}

    @app.post('/api/searches')
    def search():
        d=request.json; keyword=str(d.get('keyword','')).strip()
        if not keyword or len(keyword)>100: raise PlatformError('请填写 1–100 字的关键词')
        page=integer(d.get('page',1),1,50)
        order=str(d.get('order','default'))
        if order not in {x[0] for x in CONFIG['orders']}: raise PlatformError('排序方式无效')
        def work(uid):
            result=service.platform.search(keyword,page,order)
            for item in result['items']: service.put('result',item,uid)
            return {**result,'keyword':keyword,'page':page,'order':order}
        return jsonify(service.submit('搜索内容',d.get('request_id'),work)),202

    @app.post('/api/details')
    def detail():
        d=request.json; value=str(d.get('value','')).strip()
        if not value or len(value)>500: raise PlatformError('请填写内容 ID 或平台链接')
        def work(uid):
            item=service.platform.detail(value)
            service.put('result',item,uid)
            return {'items':[item]}
        return jsonify(service.submit('获取详情',d.get('request_id'),work)),202

    @app.post('/api/comments')
    def comments():
        d=request.json; item_id=str(d.get('id',''))
        with service.lock: item=service.record('result',item_id)
        return jsonify(service.submit('读取评论',d.get('request_id'),lambda uid:service.platform.comments(item))),202

    @app.post('/api/users')
    def user():
        d=request.json; uid=str(d.get('uid','')).strip(); page=integer(d.get('page',1),1,50)
        import re
        if CONFIG['slug']=='kuaishou':
            if not re.fullmatch(r'[A-Za-z0-9_-]{5,40}',uid): raise PlatformError('请输入有效的快手 EID')
        elif not uid.isdigit() or len(uid)>24: raise PlatformError('请输入数字用户 UID')
        def work(owner):
            result=service.platform.user(uid,page)
            for item in result['items']: service.put('result',item,owner)
            return {**result,'user':True,'uid':uid,'page':page}
        return jsonify(service.submit('用户作品',d.get('request_id'),work)),202

    @app.get('/api/export')
    def export():
        items=service.records('item');format=request.args.get('format','json')
        if format=='csv':
            columns=['id','title','text','author','uid','price','views','likes','comments','source','parent_id','comment_id','tags','note','url']
            buffer=io.StringIO();writer=csv.writer(buffer);writer.writerow(columns)
            def safe(value):
                value=str(value if value is not None else '')
                return "'"+value if value.lstrip().startswith(('=','+','-','@')) else value
            writer.writerows([[safe(item.get(column,'')) for column in columns] for item in items])
            response=app.response_class('\ufeff'+buffer.getvalue(),mimetype='text/csv')
        elif format=='json':
            response=app.response_class(json.dumps(items,ensure_ascii=False,indent=2),mimetype='application/json')
        else: raise PlatformError('导出格式需要 json 或 csv')
        response.headers['Content-Disposition']='attachment; filename="'+CONFIG['slug']+'-library.'+format+'"'
        return response

    @app.get('/api/drafts')
    def drafts(): return {'items':service.records('draft')}

    @app.post('/api/drafts')
    def save_draft():
        with service.lock:
            d=request.json; text=str(d.get('text','')).strip(); draft_id=str(d.get('id',''))
            if not text or len(text)>2000: raise PlatformError('正文需要 1–2000 字')
            previous=service.record('draft',draft_id) if draft_id else {}
            if previous.get('status') in ('publishing','published','uncertain'): raise PlatformError('该草稿已提交，请新建草稿')
            return service.put('draft',{'id':draft_id,'title':str(d.get('title',''))[:80],'text':text,'status':'draft'})

    @app.delete('/api/drafts/<draft_id>')
    def delete_draft(draft_id):
        with service.lock:
            draft=service.record('draft',draft_id)
            if draft.get('status') in ('publishing','uncertain'): raise PlatformError('请先确认平台发布结果')
            service.remove('draft',draft_id)
        return {'ok':True}

    @app.post('/api/drafts/<draft_id>/publish')
    def publish(draft_id):
        d=request.json
        if not CONFIG.get('publish'): raise PlatformError('此平台只支持保存本地草稿')
        if d.get('confirm') is not True: raise PlatformError('请确认发布到当前平台账号')
        with service.lock:
            if not service.platform.identity(): raise PlatformError('请先连接平台账号')
            draft=service.record('draft',draft_id)
            # Check deduplication before checking the draft's new state.
            with service.db() as db:
                existing=db.execute('SELECT * FROM jobs WHERE uid=? AND request_id=?',(service.uid(),d.get('request_id'))).fetchone()
            if existing:return jsonify(service.project(existing)),202
            if draft.get('status')!='draft': raise PlatformError('该草稿已提交，请先查看任务及平台记录')
            draft['status']='publishing'; service.put('draft',draft)
            def work(uid):
                try:
                    result=service.platform.publish(draft['text'])
                except Exception:
                    draft['status']='uncertain'; service.put('draft',draft,uid)
                    from .service import UncertainError
                    raise UncertainError()
                draft.update(status='published',published=result); service.put('draft',draft,uid)
                return result
            try: job=service.submit('发布文字内容',d.get('request_id'),work)
            except Exception:
                draft['status']='draft'; service.put('draft',draft); raise
        return jsonify(job),202

    @app.get('/api/jobs')
    def jobs(): return {'items':service.jobs()}

    @app.get('/api/jobs/<job_id>')
    def job(job_id): return service.get_job(job_id)

    @app.post('/api/account/import')
    def import_cookie():
        value=str(request.json.get('cookie','')).strip()
        if not value or len(value)>20000 or any(c in value for c in '\r\n'): raise PlatformError('请输入完整的单行登录 Cookie')
        with service.lock: return {'account':service.platform.connect(value)}

    @app.post('/api/account/check')
    def check_account():
        with service.lock: return {'account':service.platform.check()}

    @app.post('/api/account/disconnect')
    def disconnect():
        with service.lock: service.platform.disconnect()
        return {'ok':True}

    @app.post('/api/account/qr')
    def qr():
        with service.lock: return service.platform.qr_start()

    @app.post('/api/account/qr/<token>')
    def qr_poll(token):
        with service.lock: return service.platform.qr_poll(token)

    return app


def integer(value,low,high):
    try: value=int(value)
    except (TypeError,ValueError): raise PlatformError('页码无效')
    if not low<=value<=high: raise PlatformError('页码超出范围')
    return value
