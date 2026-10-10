#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""数据处理：handle_work_info / save_to_xlsx / download_work（对齐 DouYin_Spider/utils/data_util.py）。

快手作品字段来源（www.kuaishou.com feed 结构）：
    feeds[].photo  : id/caption/coverUrl/photoUrl/manifest/duration/viewCount/likeCount/commentCount/timestamp
    feeds[].author : id/name/headerUrl
作品链接：https://www.kuaishou.com/short-video/{photoId}
"""

import json
import os
import re
import time

import openpyxl
import requests
from loguru import logger
from retry import retry
from utils.transport import http_proxy

requests = http_proxy(requests)   # get/post 走 Chrome TLS/ALPN 共享会话


def norm_str(s):
    new_str = re.sub(r"|[\\/:*?\"<>| ]+", "", str(s)).replace('\n', '').replace('\r', '')
    return new_str


def norm_text(text):
    ILLEGAL_CHARACTERS_RE = re.compile(r'[\000-\010]|[\013-\014]|[\016-\037]')
    return ILLEGAL_CHARACTERS_RE.sub(r'', str(text))


def timestamp_to_str(timestamp):
    try:
        time_local = time.localtime(int(timestamp) / 1000)
        return time.strftime("%Y-%m-%d %H:%M:%S", time_local)
    except Exception:
        return str(timestamp)


def _first(d, *keys, default=''):
    """从 dict 里按序取第一个存在的键。"""
    for k in keys:
        if isinstance(d, dict) and k in d and d[k] not in (None, ''):
            return d[k]
    return default


def parse_count(value, default=0):
    """把计数字段归一成整数。

    GraphQL 侧（``visionShortVideoReco``）的 ``likeCount`` 是**给人看的缩写字符串**
    （实抓到 ``"74万"``），而 REST 侧（``feed/hot``）同名字段是数字。
    直接当数字用会在排序/累加时炸掉，所以这里统一还原成整数。

    支持 ``74万`` / ``1.2万`` / ``3亿`` / ``1,234`` / ``12345`` / ``12.3k``。
    还原不了就返回 default（不抛异常，避免一条脏数据毁掉整次抓取）。
    """
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value or '').strip().replace(',', '')
    if not text:
        return default
    unit = {'万': 10000, 'w': 10000, 'W': 10000,
            '亿': 100000000, 'k': 1000, 'K': 1000}
    for suffix, mul in unit.items():
        if text.endswith(suffix):
            head = text[:-len(suffix)]
            try:
                return int(float(head) * mul)
            except ValueError:
                return default
    try:
        return int(float(text))
    except ValueError:
        return default


def handle_work_info(data):
    """归一化快手一条 feed（含 photo + author）为统一 work_info。

    :param data: 单条 feed（包含 photo/author，或已展开的作品 dict）。
    :return: 归一化 work_info dict。
    """
    photo = data.get('photo', data) if isinstance(data, dict) else {}
    author = data.get('author', {}) if isinstance(data, dict) else {}

    photo_id = str(_first(photo, 'id', 'photoId', 'photo_id', default=''))
    caption = _first(photo, 'caption', 'title', default='')
    cover_url = _first(photo, 'coverUrl', 'coverUrls', default='')
    if isinstance(cover_url, list) and cover_url:
        cover_url = cover_url[0].get('url', '') if isinstance(cover_url[0], dict) else cover_url[0]
    video_addr = _first(photo, 'photoUrl', 'mainMvUrls', default='')
    if not video_addr:
        # manifest 是一个嵌套结构，取第一个可用流的 url
        manifest = photo.get('manifest') or photo.get('manifestH265') or {}
        if isinstance(manifest, dict):
            for rep in ((manifest.get('adaptationSet') or [{}])[0].get('representation') or []):
                url = rep.get('url') or ''
                if url:
                    video_addr = url
                    break
        elif isinstance(manifest, list) and manifest:
            video_addr = manifest[0].get('url', '') if isinstance(manifest[0], dict) else manifest[0]
    if isinstance(video_addr, list) and video_addr:
        video_addr = video_addr[0].get('url', '') if isinstance(video_addr[0], dict) else video_addr[0]

    # 图文（atlas）作品：photo.ext_params.atlas 或 photo.atlas
    images = []
    atlas = _first(photo, 'atlas', default=None)
    if isinstance(atlas, dict):
        cdn = atlas.get('cdn', '') or ''
        cdn = cdn[0] if isinstance(cdn, list) and cdn else cdn
        for p in atlas.get('list', []) or []:
            images.append(f'https://{cdn}{p}' if cdn else p)
    work_type = '图文' if images else '视频'

    duration = _first(photo, 'duration', default=0)
    # 计数类字段统一过 parse_count：GraphQL 侧给的是 "74万" 这种缩写串，
    # REST 侧给的是数字，两边都要能吃（见 parse_count 的说明）。
    view_count = parse_count(_first(photo, 'viewCount', 'view_count', default=0))
    like_count = parse_count(_first(photo, 'likeCount', 'realLikeCount',
                                    'like_count', default=0))
    # 实抓的 feed/hot 里 photo 节点**没有** commentCount，评论数在顶层 comment.us_c；
    # profile/feed 与 GraphQL 侧才可能带 photo.commentCount，所以两处都兜。
    comment_count = _first(photo, 'commentCount', 'comment_count', default=None)
    if comment_count is None:
        comment_node = data.get('comment') if isinstance(data, dict) else None
        comment_count = _first(comment_node or {}, 'us_c', 'commentCount', default=0)
    comment_count = parse_count(comment_count)
    collect_count = parse_count(_first(photo, 'collectCount', 'collect_count', default=0))
    share_count = parse_count(_first(photo, 'shareCount', 'share_count', default=0))
    create_time = _first(photo, 'timestamp', 'create_time', default=0)

    author_id = str(_first(author, 'id', 'authorId', 'user_id', default=''))
    nickname = _first(author, 'name', 'user_name', 'nickname', default='')
    author_avatar = _first(author, 'headerUrl', 'headurl', 'avatar', default='')
    if isinstance(author_avatar, list) and author_avatar:
        author_avatar = author_avatar[0].get('url', '') if isinstance(author_avatar[0], dict) else author_avatar[0]

    return {
        'work_id': photo_id,
        'work_url': f'https://www.kuaishou.com/short-video/{photo_id}',
        'work_type': work_type,
        'title': caption,
        'desc': caption,
        'duration': duration,
        'view_count': view_count,
        'like_count': like_count,
        'comment_count': comment_count,
        'collect_count': collect_count,
        'share_count': share_count,
        'video_addr': video_addr,
        'images': images,
        'create_time': create_time,
        'video_cover': cover_url,
        'user_url': f'https://www.kuaishou.com/profile/{author_id}',
        'user_id': author_id,
        'nickname': nickname,
        'author_avatar': author_avatar,
    }


def save_to_xlsx(datas, file_path):
    """把归一化后的 work_info 列表存成 xlsx。

    **按键名取值**，不依赖 dict 的插入顺序 —— 之前是 ``list(row.values())``，
    往 handle_work_info 里插一个字段就会让后面所有列整体错位（收藏数落到分享数那列）。
    """
    wb = openpyxl.Workbook()
    ws = wb.active
    # (表头, work_info 里的键)，顺序即列序
    columns = [
        ('作品id', 'work_id'), ('作品url', 'work_url'), ('作品类型', 'work_type'),
        ('作品标题', 'title'), ('描述', 'desc'), ('时长', 'duration'),
        ('播放数量', 'view_count'), ('点赞数量', 'like_count'),
        ('评论数量', 'comment_count'), ('收藏数量', 'collect_count'),
        ('分享数量', 'share_count'), ('视频地址url', 'video_addr'),
        ('图片地址url列表', 'images'), ('上传时间', 'create_time'),
        ('视频封面url', 'video_cover'), ('用户主页url', 'user_url'),
        ('用户id', 'user_id'), ('昵称', 'nickname'), ('头像url', 'author_avatar'),
    ]
    ws.append([title for title, _ in columns])
    for data in datas:
        ws.append([norm_text(str(data.get(key, ''))) for _, key in columns])
    wb.save(file_path)
    logger.info(f'数据保存至 {file_path}')


def download_media(path, name, url, media_type):
    if not url:
        return
    if media_type == 'image':
        content = requests.get(url, verify=False).content
        with open(path + '/' + name + '.jpg', mode="wb") as f:
            f.write(content)
    elif media_type == 'video':
        res = requests.get(url, stream=True, verify=False)
        chunk_size = 1024 * 1024
        with open(path + '/' + name + '.mp4', mode="wb") as f:
            for chunk in res.iter_content(chunk_size=chunk_size):
                f.write(chunk)


def save_work_detail(work, path):
    with open(f'{path}/detail.txt', mode="w", encoding="utf-8") as f:
        f.write(f"作品id: {work['work_id']}\n")
        f.write(f"作品url: {work['work_url']}\n")
        f.write(f"作品类型: {work['work_type']}\n")
        f.write(f"作品标题: {work['title']}\n")
        f.write(f"描述: {work['desc']}\n")
        f.write(f"时长: {work['duration']}\n")
        f.write(f"播放数量: {work['view_count']}\n")
        f.write(f"点赞数量: {work['like_count']}\n")
        f.write(f"评论数量: {work['comment_count']}\n")
        f.write(f"分享数量: {work['share_count']}\n")
        f.write(f"视频地址url: {work['video_addr']}\n")
        f.write(f"图片地址url列表: {', '.join(work['images'])}\n")
        f.write(f"上传时间: {timestamp_to_str(work['create_time'])}\n")
        f.write(f"视频封面url: {work['video_cover']}\n")
        f.write(f"用户主页url: {work['user_url']}\n")
        f.write(f"用户id: {work['user_id']}\n")
        f.write(f"昵称: {work['nickname']}\n")
        f.write(f"头像url: {work['author_avatar']}\n")


@retry(tries=3, delay=1)
def download_work(work_info, path, save_choice):
    work_id = work_info['work_id']
    user_id = work_info['user_id']
    title = norm_str(work_info['title'])[:40] or '无标题'
    nickname = norm_str(work_info['nickname'])[:20]
    save_path = f'{path}/{nickname}_{user_id}/{title}_{work_id}'
    check_and_create_path(save_path)
    with open(f'{save_path}/info.json', mode='w', encoding='utf-8') as f:
        f.write(json.dumps(work_info, ensure_ascii=False) + '\n')
    work_type = work_info['work_type']
    save_work_detail(work_info, save_path)
    if work_type == '图文' and save_choice in ['media', 'media-image', 'all']:
        for img_index, img_url in enumerate(work_info['images']):
            download_media(save_path, f'image_{img_index}', img_url, 'image')
    elif work_type == '视频' and save_choice in ['media', 'media-video', 'all']:
        download_media(save_path, 'cover', work_info['video_cover'], 'image')
        download_media(save_path, 'video', work_info['video_addr'], 'video')
    logger.info(f'作品 {work_id} 下载完成，保存路径: {save_path}')
    return save_path


def check_and_create_path(path):
    if not os.path.exists(path):
        os.makedirs(path)
