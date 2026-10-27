"""Workspace adapter for cv-cat/KuaiShou-Spider."""
import base64
import json
import os
from pathlib import Path
import re
import secrets
import threading
import time
from html import unescape
from urllib.parse import urlsplit
from loguru import logger
from builder.auth import KuaishouAuth
from ks_apis.kuaishou_api import KuaishouAPI, UnverifiedBrowserContractError
from ks_apis.login_api import KuaishouLoginAPI
from ks_apis.live_api import KuaishouLiveAPI
from utils import transport
from .service import PlatformError
logger.disable('')
_tls=threading.local()

def _thread_session():
    if not hasattr(_tls,'session'):
        _tls.session=transport.new_session();_tls.session._ks_shared_transport=True
        original=_tls.session.request
        def bounded(method,url,**kwargs):
            kwargs['verify']=True;kwargs.setdefault('timeout',(8,20))
            _tls.session.cookies.clear()
            return original(method,url,**kwargs)
        _tls.session.request=bounded
    return _tls.session
transport.shared_session=_thread_session


def text(value):return unescape(re.sub('<[^>]+>','',str(value or '')))


def image(value):
    value=str(value or '')
    if value.startswith('//'):value='https:'+value
    return value if value.startswith('https://') else ''


def checked(raw):
    if not isinstance(raw,dict) or raw.get('result',1)!=1 or raw.get('errors'):
        raise PlatformError('快手接口未确认请求，请检查登录或在官网完成验证后重试')
    return raw


def projection(raw):
    photo=raw.get('photo') or raw;author=raw.get('author') or raw.get('user') or {}
    item_id=str(photo.get('id') or photo.get('photoId') or raw.get('photoId') or '')
    return {'id':item_id,'title':text(photo.get('caption') or raw.get('caption')),'text':text(photo.get('caption')),
        'author':text(author.get('name') or author.get('userName') or raw.get('userName')),'uid':str(author.get('id') or author.get('eid') or author.get('userId') or ''),
        'cover':image(photo.get('coverUrl') or photo.get('cover')),'url':'https://www.kuaishou.com/short-video/'+item_id,
        'views':photo.get('viewCount',0),'likes':photo.get('likeCount',0),'comments':photo.get('commentCount',0),'tags':'','note':''}


class Platform:
    def __init__(self,directory):
        self.directory=Path(directory);self.path=self.directory/'account.json';self.auth=None;self.qr={};self.cursors={}

    def identity(self):return json.loads(self.path.read_text())['account'] if self.path.exists() else None

    def persist(self,auth,account):
        tmp=self.path.with_suffix('.tmp');fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,'w') as f:json.dump({'state':auth.export_state(),'account':account},f,ensure_ascii=False)
        os.replace(tmp,self.path);self.auth=auth;self.cursors.clear();return account

    def client(self):
        if self.auth is None:
            self.auth=KuaishouAuth()
            if self.path.exists():self.auth.prepare_state(json.loads(self.path.read_text())['state'])
            else:self.auth.prepare_auth('')
        return self.auth

    @staticmethod
    def account(auth):
        if not KuaishouAPI.check_login(auth):raise PlatformError('快手账号未登录，请重新扫码或导入完整 Cookie')
        raw=KuaishouAPI.get_user_info(auth)
        uid=str(raw.get('userId') or raw.get('id') or auth.userId or '')
        if not uid:raise PlatformError('没有读取到快手用户标识')
        return {'id':uid,'name':text(raw.get('userName') or raw.get('name') or uid),'status':'connected','checked_at':time.time()}

    def connect(self,cookie):
        auth=KuaishouAuth().prepare_auth(cookie)
        return self.persist(auth,self.account(auth))

    def check(self):
        if not self.identity():raise PlatformError('请先连接快手账号')
        return self.persist(self.client(),self.account(self.client()))

    def disconnect(self):self.path.unlink(missing_ok=True);self.auth=None;self.qr.clear();self.cursors.clear()

    def search(self,keyword,page,order):
        # Cursor paging must reuse the exact first-page session and response cursor.
        if page==1:self.cursors[keyword]={1:('', '')}
        cursor=(self.cursors.get(keyword) or {}).get(page)
        if cursor is None:raise PlatformError('快手搜索需要顺序翻页，请先搜索第一页')
        raw=checked(KuaishouAPI.search_feed(self.client(),keyword,pcursor=cursor[0],search_session_id=cursor[1]))
        items=[projection(x) for x in raw.get('feeds') or raw.get('list') or []]
        next_cursor=str(raw.get('pcursor') or '');sid=str(raw.get('searchSessionId') or cursor[1])
        more=bool(items and next_cursor not in ('','no_more','-1'))
        if more:self.cursors[keyword][page+1]=(next_cursor,sid)
        return {'items':items,'total':len(items),'has_more':more}

    @staticmethod
    def resolve(value):
        if re.fullmatch(r'[A-Za-z0-9_-]{6,40}',value):return value
        u=urlsplit(value)
        if u.scheme!='https' or u.hostname not in ('www.kuaishou.com','kuaishou.com') or u.port not in (None,443) or u.username or u.password:raise PlatformError('请输入快手作品 ID 或完整 short-video 链接')
        match=re.fullmatch(r'/short-video/([A-Za-z0-9_-]{6,40})/?',u.path)
        if not match:raise PlatformError('链接中没有有效快手作品 ID')
        return match.group(1)

    def detail(self,value):return projection(KuaishouAPI.get_video_detail(self.client(),self.resolve(value)))

    def comments(self,item):
        raw=checked(KuaishouAPI.get_comment_list(self.client(),item['id']))
        rows=raw.get('rootCommentsV2') or raw.get('comments') or []
        return {'comments':[{'id':str(x.get('commentId') or x.get('id') or ''),'author':text(x.get('authorName') or (x.get('author') or {}).get('name')),
            'text':text(x.get('content')),'likes':x.get('likedCount',0)} for x in rows],'notice':'展示当前页评论'}

    def user(self,uid,page):
        key='user:'+uid
        if page==1:self.cursors[key]={1:''}
        cursor=(self.cursors.get(key) or {}).get(page)
        if cursor is None:raise PlatformError('用户作品需要顺序翻页，请先读取第一页')
        raw=checked(KuaishouAPI.get_profile_feed(self.client(),uid,pcursor=cursor))
        items=[projection(x) for x in raw.get('feeds') or []]
        next_cursor=str(raw.get('pcursor') or '')
        more=bool(items and next_cursor not in ('','no_more','-1') and next_cursor!=cursor)
        if more:self.cursors[key][page+1]=next_cursor
        return {'items':items,'has_more':more,'page':page}

    def publish(self,content):raise PlatformError('快手需要图片或视频素材，请使用官方创作者入口发布；本地草稿不会发布')

    def tool(self,name,data):
        if name=='live':
            eid=str(data.get('eid','')).strip()
            if not re.fullmatch(r'[A-Za-z0-9_-]{5,40}',eid):raise PlatformError('请输入直播间 EID')
            raw=KuaishouLiveAPI.get_room_state(self.client(),eid)
            author=raw.get('author') or {}
            return {'items':[{'id':'live-'+eid,'kind':'live','title':text(raw.get('caption') or '快手直播间'),'text':'正在直播' if raw.get('isLiving') else '未开播',
                'author':text(author.get('name') if isinstance(author,dict) else author),'url':'https://live.kuaishou.com/u/'+eid,
                'uid':eid,'views':'—','likes':'—','comments':0,'cover':'','tags':'','note':''}], 'notice':'直播间状态由当前平台发现列表确认'}
        if name in ('liked','collected','history'):
            method={'liked':KuaishouAPI.get_liked_list,'collected':KuaishouAPI.get_collect_list,'history':KuaishouAPI.get_history_list}[name]
            raw=checked(method(self.client()))
            return {'items':[projection(x) for x in raw.get('feeds') or raw.get('list') or []],'notice':'展示当前账号列表的首屏结果'}
        raise PlatformError('工具不存在')

    def qr_start(self):
        token=secrets.token_urlsafe(24);ready=threading.Event();auth=KuaishouAuth().prepare_auth('')
        pending={'status':'waiting','expires':time.time()+160,'image':'','auth':auth};self.qr={token:pending}
        path=self.directory/('qr-'+secrets.token_hex(8)+'.png')
        def on_qr(png,_):
            pending['image']='data:image/png;base64,'+base64.b64encode(Path(png).read_bytes()).decode();ready.set()
        def work():
            try:
                raw=KuaishouLoginAPI.login_browser_session(auth,qr_path=str(path),timeout=150,poll_interval=3,on_qr=on_qr)
                if raw.get('ok'):pending.update(status='ready',account=self.account(auth))
                else:pending['status']='expired'
            except Exception:pending['status']='expired'
            finally:path.unlink(missing_ok=True);ready.set()
        threading.Thread(target=work,daemon=True).start();ready.wait(20)
        if not pending['image']:raise PlatformError('快手二维码申请未完成，请稍后重试或导入 Cookie')
        return {'token':token,'image':pending['image'],'status':'waiting'}

    def qr_poll(self,token):
        pending=self.qr.get(token)
        if not pending or time.time()>pending['expires']:return {'status':'expired'}
        if pending['status']=='ready':
            account=self.persist(pending['auth'],pending['account']);self.qr.clear()
            return {'status':'connected','account':account}
        return {'status':pending['status'],'image':pending['image']}
