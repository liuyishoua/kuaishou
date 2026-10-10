"""Offline-only fixtures. No real network, login or platform writes."""
import time
from .config import CONFIG
from .service import PlatformError


class DemoPlatform:
    demo=True
    def __init__(self):self.account={'id':'demo-10001','name':'演示账号','status':'connected','checked_at':time.time()};self.publish_calls=0
    def identity(self):return self.account
    def connect(self,cookie):raise PlatformError('演示模式不接收真实 Cookie')
    def check(self):return self.account
    def disconnect(self):self.account=None
    def qr_start(self):raise PlatformError('演示模式禁止真实扫码登录')
    def qr_poll(self,token):raise PlatformError('演示模式禁止真实扫码登录')
    def search(self,keyword,page,order):return {'items':fixtures(keyword,page),'has_more':page<3,'total':18}
    def detail(self,value):return fixtures('内容详情')[0]
    def comments(self,item):return {'comments':[{'id':'1','author':'研究同学','text':'这是一条离线演示评论，方便验证采集、展示与导出流程。','likes':23}],'notice':'离线演示评论'}
    def user(self,uid,page):return {'items':fixtures('创作者作品'),'has_more':False}
    def tool(self,name,data):return {'items':fixtures('专项查询'),'notice':'离线演示结果，没有联系真实平台'}
    def publish(self,content):self.publish_calls+=1;raise PlatformError('演示模式禁止真实发布')


def fixtures(keyword='值得收藏的内容',page=1):
    texts=['从零搭建自己的工作流：把好想法一点点变成实际成果。','关于最近这个话题，有哪些值得关注的细节？这次一起看看。','为日常工作做一份简单、可靠的记录，让每次探索都有迹可循。','一次小小的体验，发现了意料之外的收获。','记录学习过程，比只记录答案更有价值。','今天也留一点时间，看看不同的人在想什么。']
    return [{'id':f'demo-{page}-{i}','aid':str(i),'title':keyword+' · '+['实用指南','话题观察','日常记录','精选推荐','学习笔记','新鲜发现'][i],
        'text':content,'author':['一颗栗子','好奇实验室','日常研究员','阿白的笔记','认真生活','自由探索'][i],
        'uid':'1000'+str(i),'cover':'','url':CONFIG['source'],'views':12000+i*1700,'likes':365+i*123,'comments':23+i*7,
        'price':str(199+i*60) if CONFIG['slug']=='jd' else '', 'tags':'灵感 / 参考','note':'','created':time.time()} for i,content in enumerate(texts)]


def seed(service):
    if service.records('item'):return
    for item in fixtures()[:3]:service.put('result',item);service.put('item',item)
    service.put('draft',{'title':'下一篇内容的灵感','text':'把今天收集到的有趣观点，整理成自己的研究笔记。','status':'draft'})
