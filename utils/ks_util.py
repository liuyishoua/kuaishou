#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""快手工具 & 签名门面（对齐 DouYin_Spider/utils/dy_util.py 的职责）。

- cookie/url 基础工具：trans_cookies / splice_url / generate_millisecond。
- 签名门面：generate_kww / generate_hxfalcon / generate_sig3，内部委托 utils.sign.* 纯算实现。
"""

import time
import urllib.parse

import requests

requests.packages.urllib3.disable_warnings()

from utils.sign.falcon_pure import (HxFalconSigner, build_sign_input, need_sign,
                                    cp_need_sign, CAVER, CP_PROJECT_INFO)
from utils.sign.sig3_pure import Sig3Signer, need_sig3
from utils.sign.kww_pure import KwwSigner


# --------------------------------------------------------------------------- #
# 基础工具                                                                      #
# --------------------------------------------------------------------------- #
def trans_cookies(cookies_str: str) -> dict:
    """cookie 字符串转 dict。"""
    cookies = {}
    # Accept both ``;`` and ``; `` separators and never create a bogus empty
    # cookie when the caller starts from a cold (empty) browser jar.
    for item in (cookies_str or "").split(";"):
        item = item.strip()
        if not item or "=" not in item:
            continue
        key, value = item.split("=", 1)
        key = key.strip()
        if key:
            cookies[key] = value.strip()
    return cookies


def splice_url(params: dict) -> str:
    """dict 拼接为 url query 字符串（value 做 urlencode）。"""
    splice_url_str = ''
    for key, value in params.items():
        if value is None:
            value = ''
        splice_url_str += key + '=' + urllib.parse.quote(str(value)) + '&'
    return splice_url_str[:-1]


def generate_millisecond() -> int:
    """毫秒时间戳。"""
    return int(round(time.time() * 1000))


# --------------------------------------------------------------------------- #
# 签名门面（进程级单例，惰性初始化）                                              #
# --------------------------------------------------------------------------- #
_hxfalcon_signer = None
_hxfalcon_live_signer = None       # 直播站单独一套（SDK 版本号与计数器都不同）
_hxfalcon_login_signer = None      # 登录站单独一套（form 参与签名）
_sig3_signer = None
_kww_signer = None


def _hxfalcon():
    global _hxfalcon_signer
    if _hxfalcon_signer is None:
        _hxfalcon_signer = HxFalconSigner()
    return _hxfalcon_signer


def _sig3():
    global _sig3_signer
    if _sig3_signer is None:
        _sig3_signer = Sig3Signer()
    return _sig3_signer


def _kww(kwfv1: str = "", **options):
    global _kww_signer
    options = {k: v for k, v in options.items() if v}   # 空值不要覆盖 KwwSigner 的默认参数
    if _kww_signer is None:
        _kww_signer = KwwSigner(kwfv1, **options)
    else:
        if kwfv1:
            _kww_signer.set_kwfv1(kwfv1)
        for key, value in options.items():
            if value:
                setattr(_kww_signer, key, value)
    return _kww_signer


def configure_kww(kwfv1: str = "", href: str = "", did: str = "", product_name: str = "",
                  kwscode: str = "", kwssectoken: str = ""):
    """配置 webweapon 会话（由 KuaishouAuth 在解析 cookie 后调用）。

    ``kwscode`` / ``kwssectoken`` 有就透传（源码只在缺失时才生成），没有才本地造。
    """
    return _kww(kwfv1, href=href, did=did, product_name=product_name,
                kwscode=kwscode, kwssectoken=kwssectoken)


def generate_kww(kwfv1: str = "") -> str:
    """返回当前页面初始化时冻结的 ``kww`` 请求头快照。

    :param kwfv1: 当前 Cookie ``kwfv1``；仅在新页面尚未冻结快照时作为初始来源。
    :return: kww 值。
    """
    return _kww(kwfv1).sign()


def weapon_cookies() -> dict:
    """webweapon 三件套 cookie；``kwscode`` / ``kwssectoken`` 只活 6 分钟，过期自动续期。"""
    return _kww().cookies()


def reset_hxfalcon_session():
    """重置 sig4 会话（等价于浏览器刷新页面：重取 startupRandom、各计数器归 100）。"""
    global _hxfalcon_signer, _hxfalcon_live_signer, _hxfalcon_login_signer
    _hxfalcon_signer = None
    _hxfalcon_live_signer = None
    _hxfalcon_login_signer = None


def _hxfalcon_live():
    """直播站单独一个引擎实例。

    live 的 SDK 版本号是 43469，www/cp 是 43468（实抓），而计数器也是各页面独立的，
    所以不能和 www 共用同一个签名器。
    """
    global _hxfalcon_live_signer
    if _hxfalcon_live_signer is None:
        from utils.sign.falcon_pure import SDK_VERSION_LIVE
        _hxfalcon_live_signer = HxFalconSigner(sdk_version=SDK_VERSION_LIVE)
    return _hxfalcon_live_signer


def _hxfalcon_login():
    """登录站（id.kuaishou.com）单独一个引擎实例。"""
    global _hxfalcon_login_signer
    if _hxfalcon_login_signer is None:
        _hxfalcon_login_signer = HxFalconSigner()
    return _hxfalcon_login_signer


def generate_hxfalcon_login(path: str, method: str = "POST", query: dict = None,
                            body=None,
                            content_type: str = "application/x-www-form-urlencoded") -> str:
    """生成登录站的 ``__NS_hxfalcon``。

    与直播站的关键差别：**登录站把 form body 算进签名**。sig4 适配器原文
    （login-app.js）::

        form: contentType === 'application/x-www-form-urlencoded' && data ? wi(data) : {}
        requestBody: contentType === 'application/json' && data ? wi(data) : {}

    直播站那两个字段恒空，这里不是。

    :param path: pathname，如 /rest/c/infra/ks/qr/start。
    :param method: 请求方法。
    :param query: query（不含 __NS_hxfalcon / caver）。
    :param body: form 字典或已编码的 form 串。
    :param content_type: 默认 form。
    """
    sign_input = build_sign_input(path, method, query, body, content_type)
    return _hxfalcon_login().sign(sign_input)


def generate_hxfalcon_live(path: str, method: str = "GET", query: dict = None,
                           body=None, content_type: str = "application/json") -> str:
    """生成直播站的 ``__NS_hxfalcon``（与 www 分开维护会话与 SDK 版本号）。

    :param path: pathname，如 /live_api/liveroom/websocketinfo。
    :param method: 请求方法。
    :param query: 合并后的 query（不含 __NS_hxfalcon / caver）。
    :param body: 请求体。
    :param content_type: 内容类型。
    :return: ``HUDR_...$HE_...``。
    """
    sign_input = build_sign_input(path, method, query, body, content_type)
    return _hxfalcon_live().sign(sign_input)


def generate_hxfalcon(path: str, method: str = "POST", query: dict = None,
                      body=None, content_type: str = "application/json",
                      project_info: dict = None) -> str:
    """生成 ``__NS_hxfalcon``（sig4，www 数据侧 + cp 少量接口）。

    模块级单例 ``_hxfalcon_signer`` 对应浏览器里的一个引擎实例：进程首次调用时记下
    ``startupRandom``（当前 unix 毫秒），``count`` 与 ``KsGuard.count`` 从 100 起逐次自增，
    三者都进签名。需要模拟「刷新页面」时调 :func:`reset_hxfalcon_session`。

    :param path: pathname，如 /rest/v/profile/get。
    :param method: 请求方法。
    :param query: 合并后的 query（不含 __NS_hxfalcon）。
    :param body: 请求体（dict / json 字符串）。
    :param content_type: 内容类型，决定 body 归入 form 还是 requestBody。
    :param project_info: cp 侧传 CP_PROJECT_INFO；www 侧留空。
    :return: ``HUDR_...$HE_...`` 签名串。
    """
    # www/cp：没 body 就不带 form/requestBody 键（profile/get 实测，见 notes 17）
    sign_input = build_sign_input(path, method, query, body, content_type, project_info,
                                  omit_empty_body=True)
    return _hxfalcon().sign(sign_input)


def reset_sig3_session():
    """重置 sig3 会话（等价于浏览器刷新页面：重取 startupRandom、count 归 100）。"""
    global _sig3_signer
    _sig3_signer = None


def generate_sig3(url: str, query: dict = None, body=None, req_type: str = "json") -> str:
    """生成 ``__NS_sig3``（cp 发布侧）。

    签名输入只有 query + body，**不含 path 与 method**（见 utils/sign/sig3_pure 源码还原）；
    url 仅用于判断该请求是否属于 sig3 作用域。

    模块级单例 ``_sig3_signer`` 对应浏览器里的一个引擎实例：进程首次调用时记下
    ``startupRandom``（当前 unix 秒），``count`` 从 100 起逐次自增，两者都进签名明文。
    需要模拟「刷新页面」时调用 :func:`reset_sig3_session`。

    :param url: 请求 url 或 pathname，如 /rest/cp/works/v2/common/pc/current/user。
    :param query: url 上的 query dict（不含 __NS_sig3）。
    :param body: 请求体（cp 侧恒为 dict，且已并入 kuaishou.web.cp.api_ph）。
    :param req_type: ``json``（POST JSON）或 ``form-data``（postFormUrlencoded）。
    :return: 56 位小写 hex 签名串。
    """
    sign_input = {
        "query": dict(query or {}),
        "body": body if body is not None else {},
        "type": req_type,
    }
    return _sig3().sign(sign_input)
