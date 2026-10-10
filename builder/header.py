#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""HeaderBuilder / HeaderType（对齐 DouYin_Spider/builder/header.py）。

字段与顺序按 **Chrome DevTools 实抓**对齐；仓库只保留脱敏后的协议和令牌
fixture，不保存包含会话信息的原始请求导出。

实抓结论（2026-08-15，www + live 各两条）：

- 浏览器 XHR **不发** ``cache-control`` / ``pragma`` / ``priority`` /
  ``sec-ch-ua`` / ``sec-ch-ua-mobile`` / ``sec-ch-ua-platform``。之前这几个是凭印象加的，已删。
- ``accept``：www 侧是 ``application/json``；live 侧是 axios 默认的
  ``application/json, text/plain, */*``。
- **GET 没有 ``origin`` 也没有 ``content-type``**，只有 POST 才有。
- ``accept-encoding`` 含 ``br`` 与 ``zstd``（所以 requirements 里装了 brotli / zstandard，
  否则声明了却解不开）。
- live 站额外带两个 sentry 头（``sentry-trace`` / ``baggage``），属应用层埋点。
"""

import secrets
from enum import Enum

from utils.fingerprint import get_profile

# 实抓值：与浏览器语言设置相关，别改成 en-US 那种
ACCEPT_LANGUAGE = "zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,ja;q=0.6"
ACCEPT_ENCODING = "gzip, deflate, br, zstd"
ACCEPT_WWW = "application/json"                        # www 侧实抓
ACCEPT_AXIOS = "application/json, text/plain, */*"     # live 侧实抓（axios 默认）
ACCEPT_ANY = "*/*"                                     # cp 发布应用实抓
CONTENT_TYPE_JSON = "application/json"
CONTENT_TYPE_CP = "application/json;charset=UTF-8"     # cp 侧带 charset
CONTENT_TYPE_FORM = "application/x-www-form-urlencoded"   # passport 扫码登录实抓
PRIORITY_XHR = "u=1, i"        # Chrome 对 XHR/fetch 发的 priority（实测线序末位）


def _new_nonzero_hex(byte_length: int) -> str:
    """Generate a lowercase non-zero browser trace identifier."""
    while True:
        value = secrets.token_hex(byte_length)
        if int(value, 16):
            return value


class HeaderType(Enum):
    DOC = 'DOC'
    POST = 'POST'
    FORM = 'FORM'
    GET = 'GET'


# 当前重新登录后的同源 www / CP / live Network 都没有 ``priority``。
# 只有明确抓到该字段的跨站 profile 才允许发送。
_DOC_ONLY = (
    "cache-control", "pragma", "sec-ch-ua", "sec-ch-ua-mobile",
    "sec-ch-ua-platform", "sec-fetch-user", "upgrade-insecure-requests",
)

# 顺序直接按 2026-08-25 当前 Chrome DevTools Network 保存；
# connection / host / content-length 是传输层字段，不进入应用层字典。
HEADER_ORDER_WWW = (
    "profile_referer", "sentry-trace", "referer", "user-agent", "accept",
    "content-type", "kww", "baggage", "accept-encoding", "accept-language",
    "cache-control", "cookie", "origin", "pragma", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
) + _DOC_ONLY
HEADER_ORDER_CP = (
    "referer", "user-agent", "content-type", "kww", "accept",
    "accept-encoding", "accept-language", "cookie", "origin",
    "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
) + _DOC_ONLY
# Current private video submit reqid 1316.  Unlike the generic helper contract,
# DevTools retained the HTTP/1.1 transport fields for this request, so they are
# represented explicitly instead of being left to implicit library defaults.
HEADER_ORDER_CP_SUBMIT = (
    "referer", "user-agent", "content-type", "kww", "accept",
    "accept-encoding", "accept-language", "connection", "content-length",
    "cookie", "host", "origin", "sec-fetch-dest", "sec-fetch-mode",
    "sec-fetch-site",
) + _DOC_ONLY
# cp 创作者中心外壳的请求与发布 iframe 不是同一套 axios 默认头：
# 外壳请求不带 kww，且会带 returnsetrootdomainloginurl；大多数请求还带
# x-requested-with。字段来自 2026-08-24 Chrome Network 实抓。
HEADER_ORDER_CP_CREATOR_JSON = (
    "referer", "user-agent", "accept", "content-type",
    "returnsetrootdomainloginurl", "accept-encoding", "accept-language",
    "cache-control",
    "cookie", "origin", "pragma", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
) + _DOC_ONLY
HEADER_ORDER_CP_CREATOR_AXIOS = (
    "referer", "x-requested-with", "user-agent", "accept", "content-type",
    "returnsetrootdomainloginurl", "accept-encoding", "accept-language",
    "cache-control",
    "cookie", "origin", "pragma", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
) + _DOC_ONLY
HEADER_ORDER_CP_CREATOR_MANAGE_JSON = (
    "referer", "user-agent", "accept", "content-type",
    "returnsetrootdomainloginurl", "accept-encoding", "accept-language",
    "cache-control", "cookie", "origin", "pragma", "sec-fetch-dest",
    "sec-fetch-mode", "sec-fetch-site",
) + _DOC_ONLY
HEADER_ORDER_CP_CREATOR_MANAGE_AXIOS = (
    "referer", "x-requested-with", "user-agent", "accept", "content-type",
    "returnsetrootdomainloginurl", "accept-encoding", "accept-language",
    "cache-control", "cookie", "origin", "pragma", "sec-fetch-dest",
    "sec-fetch-mode", "sec-fetch-site",
) + _DOC_ONLY
HEADER_ORDER_CP_CREATOR_ANY = (
    "referer", "user-agent", "content-type", "accept", "accept-encoding",
    "accept-language", "cookie", "origin", "sec-fetch-dest", "sec-fetch-mode",
    "sec-fetch-site",
) + _DOC_ONLY
HEADER_ORDER_CP_UPLOAD_GET = (
    "user-agent", "kww", "referer", "accept", "accept-encoding",
    "accept-language", "cookie", "sec-fetch-dest", "sec-fetch-mode",
    "sec-fetch-site",
) + _DOC_ONLY
HEADER_ORDER_ONVIDEO = (
    "user-agent", "kww", "referer", "accept", "accept-encoding",
    "accept-language", "cookie", "origin", "priority", "sec-fetch-dest",
    "sec-fetch-mode", "sec-fetch-site",
) + _DOC_ONLY
HEADER_ORDER_LOGIN = (
    "user-agent", "content-type", "kww", "accept", "origin",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer",
    "accept-encoding", "accept-language", "cookie", "priority",
) + _DOC_ONLY
# Current live-home passToken request (Chrome reqid 110) is not shaped like
# the QR form requests: it has no kww/priority, and referer precedes accept.
HEADER_ORDER_LOGIN_PASS_TOKEN = (
    "user-agent", "content-type", "referer", "accept", "accept-encoding",
    "accept-language", "cookie", "origin", "sec-fetch-dest",
    "sec-fetch-mode", "sec-fetch-site",
) + _DOC_ONLY
HEADER_ORDER = HEADER_ORDER_WWW          # 兼容旧引用


class Header:
    def __init__(self, order=HEADER_ORDER_WWW):
        self.headers = {}
        self.order = order

    def set_header(self, key, value):
        self.headers[key] = value
        return self

    def with_sentry(self, release: str = "ab256f1", environment: str = "prod",
                    trace_id: str = None, span_id: str = None):
        """补 live 站的 Sentry 埋点头（实抓里有，纯业务请求不需要）。

        ``sentry-trace`` 形如 ``<32hex>-<16hex>-0``。当前 Chrome 证据表明
        同一次页面加载共享 32-hex trace id，每个请求只轮换 16-hex span id。
        调用方不传 id 时仍可生成一个独立的合法单请求 transaction。
        """
        trace = _new_nonzero_hex(16) if trace_id is None else str(trace_id)
        span = _new_nonzero_hex(8) if span_id is None else str(span_id)
        for label, value, size in (("trace_id", trace, 32), ("span_id", span, 16)):
            if (len(value) != size or value.lower() != value
                    or any(ch not in "0123456789abcdef" for ch in value)
                    or not int(value, 16)):
                raise ValueError(
                    f"Sentry {label} must be {size} lowercase non-zero hex chars")
        self.set_header("sentry-trace", f"{trace}-{span}-0")
        self.set_header("baggage", f"sentry-environment={environment},sentry-release={release}")
        return self

    def set_referer(self, url):
        self.set_header('referer', url)
        return self

    def set_origin(self, url):
        self.set_header('origin', url)
        return self

    def with_kww(self, auth):
        """注入页面本地 ``kww``；它与共享 Cookie ``kwfv1`` 可阶段性不同。"""
        kww = getattr(auth, "kww", "") or ""
        if kww:
            self.set_header('kww', kww)
        return self

    def remove_header(self, key):
        if key in self.headers:
            del self.headers[key]
        return self

    def get(self):
        """按实抓顺序输出。

        ``cookie`` / ``host`` / ``content-length`` 由 requests 自行追加，最终线上顺序
        受 urllib3 影响，这里只保证我们可控的这部分与浏览器同序。
        """
        ordered = {k: self.headers[k] for k in self.order if k in self.headers}
        for key, value in self.headers.items():          # 兜住不在清单里的自定义头
            ordered.setdefault(key, value)
        return ordered

    def __call__(self):
        return self.get()


class HeaderBuilder:
    ua = get_profile()["ua"]
    sec_ch_ua = get_profile()["sec_ch_ua"]
    sec_ch_ua_platform = get_profile()["sec_ch_ua_platform"]

    @staticmethod
    def build(header_type, accept: str = None, style: str = "www"):
        """按实抓顺序产出请求头。

        :param header_type: POST / GET / FORM / DOC。
        :param accept: 不传则按 style 取实抓默认值。
        :param style: ``www`` / ``cp``（发布应用）/ ``live``（axios）/ ``login``
            （passport 扫码登录）。各站的 accept 取值与头顺序都不同，实抓印证过。
            ``login`` 的顺序与 cp 相同，但 accept 是 ``*/*``、请求体是 form。
        """
        if style == "cp":
            order, default_accept, ctype = HEADER_ORDER_CP, ACCEPT_ANY, CONTENT_TYPE_CP
        elif style == "cp_submit":
            order, default_accept, ctype = HEADER_ORDER_CP_SUBMIT, ACCEPT_ANY, CONTENT_TYPE_CP
        elif style == "cp_creator_json":
            order, default_accept, ctype = HEADER_ORDER_CP_CREATOR_JSON, ACCEPT_WWW, CONTENT_TYPE_CP
        elif style == "cp_creator_axios":
            order, default_accept, ctype = HEADER_ORDER_CP_CREATOR_AXIOS, ACCEPT_AXIOS, CONTENT_TYPE_CP
        elif style == "cp_creator_manage_json":
            order, default_accept, ctype = HEADER_ORDER_CP_CREATOR_MANAGE_JSON, ACCEPT_WWW, CONTENT_TYPE_CP
        elif style == "cp_creator_manage_axios":
            order, default_accept, ctype = HEADER_ORDER_CP_CREATOR_MANAGE_AXIOS, ACCEPT_AXIOS, CONTENT_TYPE_CP
        elif style == "cp_creator_any":
            order, default_accept, ctype = HEADER_ORDER_CP_CREATOR_ANY, ACCEPT_ANY, CONTENT_TYPE_CP
        elif style == "cp_upload_get":
            order, default_accept, ctype = HEADER_ORDER_CP_UPLOAD_GET, ACCEPT_ANY, CONTENT_TYPE_CP
        elif style == "onvideo":
            order, default_accept, ctype = HEADER_ORDER_ONVIDEO, ACCEPT_ANY, CONTENT_TYPE_CP
        elif style == "login":
            order, default_accept, ctype = HEADER_ORDER_LOGIN, ACCEPT_ANY, CONTENT_TYPE_FORM
        elif style == "login_pass_token":
            order = HEADER_ORDER_LOGIN_PASS_TOKEN
            default_accept, ctype = ACCEPT_ANY, CONTENT_TYPE_FORM
        elif style == "live":
            order, default_accept, ctype = HEADER_ORDER_WWW, ACCEPT_AXIOS, CONTENT_TYPE_JSON
        else:
            order, default_accept, ctype = HEADER_ORDER_WWW, ACCEPT_WWW, CONTENT_TYPE_JSON

        header = Header(order=order)
        header.set_header('user-agent', HeaderBuilder.ua)
        header.set_header('accept', accept or default_accept)
        if header_type in (HeaderType.POST, HeaderType.FORM):
            header.set_header('content-type',
                              ctype if header_type == HeaderType.POST
                              else 'application/x-www-form-urlencoded')
        # kww 由 with_kww 注入；最终位置由 order 决定，不受调用顺序影响
        header.set_header('accept-encoding', ACCEPT_ENCODING)
        header.set_header('accept-language', ACCEPT_LANGUAGE)
        # 不设 connection：h2 禁止该头，Chrome 也不发（见 HEADER_ORDER_WWW 上方注释）
        header.set_header('sec-fetch-dest', 'empty')
        header.set_header('sec-fetch-mode', 'cors')
        header.set_header('sec-fetch-site', 'same-origin')
        if style in {"onvideo", "login"}:
            header.set_header('priority', PRIORITY_XHR)
        if header_type == HeaderType.DOC:
            header = Header()
            h = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': ACCEPT_LANGUAGE,
                'cache-control': 'no-cache',
                'pragma': 'no-cache',
                'priority': 'u=0, i',
                'sec-ch-ua': HeaderBuilder.sec_ch_ua,
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': HeaderBuilder.sec_ch_ua_platform,
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'none',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': HeaderBuilder.ua,
            }
            header.headers.update(h)
        return header
