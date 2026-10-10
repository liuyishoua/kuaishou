"""Account-scoped local records and bounded background operations."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
import json
import sqlite3
import threading
import time
import uuid


class PlatformError(ValueError):
    pass


class UncertainError(Exception):
    pass


class Service:
    def __init__(self, directory, platform):
        self.directory = Path(directory)
        self.platform = platform
        self.lock = threading.RLock()
        self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix='workspace')
        self.db_path = self.directory / 'workspace.sqlite3'
        with self.db() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS records (
                uid TEXT, kind TEXT, id TEXT, data TEXT, PRIMARY KEY(uid,kind,id));
                CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY, uid TEXT, request_id TEXT, operation TEXT,
                status TEXT, data TEXT, created REAL, UNIQUE(uid,request_id));''')
            for row in db.execute("SELECT uid,id,data FROM records WHERE kind='draft'").fetchall():
                value=json.loads(row['data'])
                if value.get('status')=='publishing':
                    value['status']='uncertain'
                    db.execute("UPDATE records SET data=? WHERE uid=? AND kind='draft' AND id=?",(json.dumps(value,ensure_ascii=False),row['uid'],row['id']))
            db.execute("UPDATE jobs SET status='uncertain',data=? WHERE status='running'", (json.dumps({'error':'服务重启，结果未确认；请先检查平台记录'}),))

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.db_path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        finally:
            db.close()

    def uid(self):
        account = self.platform.identity()
        return str(account['id']) if account else 'anonymous'

    def records(self, kind, uid=None):
        with self.db() as db:
            rows = db.execute('SELECT data FROM records WHERE uid=? AND kind=? ORDER BY rowid DESC', (uid or self.uid(), kind)).fetchall()
        return [json.loads(row['data']) for row in rows]

    def record(self, kind, record_id, uid=None):
        with self.db() as db:
            row = db.execute('SELECT data FROM records WHERE uid=? AND kind=? AND id=?', (uid or self.uid(), kind, record_id)).fetchone()
        if not row: raise LookupError('记录不存在')
        return json.loads(row['data'])

    def put(self, kind, value, uid=None):
        value = {**value, 'id':str(value.get('id') or uuid.uuid4().hex), 'saved_at':time.time()}
        with self.db() as db:
            db.execute('INSERT OR REPLACE INTO records VALUES(?,?,?,?)', (uid or self.uid(), kind, value['id'], json.dumps(value, ensure_ascii=False)))
        if kind=='result' and value.get('price'):
            self.put('snapshot',{'item_id':value['id'],'price':value['price'],'at':time.time()},uid)
        return value

    def collect(self, ids):
        if not isinstance(ids,list) or not 1<=len(ids)<=1000 or any(not isinstance(x,str) for x in ids):
            raise PlatformError('每次收藏需要 1–1000 个有效结果编号')
        uid=self.uid();values=[]
        with self.db() as db:
            for item_id in dict.fromkeys(ids):
                row=db.execute("SELECT data FROM records WHERE uid=? AND kind='result' AND id=?",(uid,item_id)).fetchone()
                if not row:raise PlatformError('部分结果不存在或属于其他账号，请重新查询')
                value=json.loads(row['data'])
                previous=db.execute("SELECT data FROM records WHERE uid=? AND kind='item' AND id=?",(uid,item_id)).fetchone()
                if previous:
                    saved=json.loads(previous['data'])
                    for key in ('tags','note'):value[key]=saved.get(key,'')
                value['saved_at']=time.time();values.append(value)
            for value in values:
                db.execute('INSERT OR REPLACE INTO records VALUES(?,?,?,?)',(uid,'item',value['id'],json.dumps(value,ensure_ascii=False)))
        return values

    def remove(self, kind, record_id):
        with self.db() as db:
            db.execute('DELETE FROM records WHERE uid=? AND kind=? AND id=?', (self.uid(), kind, record_id))

    def jobs(self):
        with self.db() as db:
            rows = db.execute('SELECT * FROM jobs WHERE uid=? ORDER BY created DESC LIMIT 100', (self.uid(),)).fetchall()
        return [self.project(row) for row in rows]

    @staticmethod
    def project(row):
        return {'id':row['id'], 'operation':row['operation'], 'status':row['status'], 'created':row['created'], **json.loads(row['data'])}

    def get_job(self, job_id):
        with self.db() as db:
            row = db.execute('SELECT * FROM jobs WHERE id=? AND uid=?', (job_id, self.uid())).fetchone()
        if not row: raise LookupError('任务不存在')
        return self.project(row)

    def submit(self, operation, request_id, work):
        if not isinstance(request_id, str) or not 8 <= len(request_id) <= 100:
            raise ValueError('请求编号无效，请刷新页面后重试')
        with self.lock:
            uid = self.uid()
            with self.db() as db:
                existing = db.execute('SELECT * FROM jobs WHERE uid=? AND request_id=?', (uid, request_id)).fetchone()
                if existing: return self.project(existing)
                job_id = uuid.uuid4().hex
                db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?)', (job_id,uid,request_id,operation,'running','{}',time.time()))
            def run():
                with self.lock:
                    try:
                        if self.uid() != uid: raise PlatformError('账号已切换，请在当前账号重新操作')
                        def progress(value):
                            with self.db() as db:
                                db.execute('UPDATE jobs SET data=? WHERE id=?',(json.dumps({'progress':value},ensure_ascii=False),job_id))
                        self.platform.progress=progress
                        result = work(uid)
                        status, payload = 'completed', {'result':result}
                    except UncertainError:
                        status, payload = 'uncertain', {'error':'平台未确认结果，请先检查平台记录；该请求不会自动重试'}
                    except PlatformError as exc:
                        status, payload = 'failed', {'error':str(exc)}
                    except ValueError:
                        status, payload = 'failed', {'error':'平台参数无效，请检查输入或重新连接账号'}
                    except Exception:
                        status, payload = 'failed', {'error':'平台请求失败，请检查网络、账号或平台限制后重试'}
                    with self.db() as db:
                        db.execute('UPDATE jobs SET status=?,data=? WHERE id=?', (status,json.dumps(payload,ensure_ascii=False),job_id))
            self.pool.submit(run)
            return self.get_job(job_id)
