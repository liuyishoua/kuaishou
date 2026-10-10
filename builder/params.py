#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Params 构造器（对齐 DouYin_Spider/builder/params.py）。

链式 ``.add_param()`` / ``.with_xxx()`` 组织 query；签名（``__NS_hxfalcon`` / ``__NS_sig3``）
通过 ``with_hxfalcon``（www 数据侧）/ ``with_cp_sign``（cp 发布侧，自动选 sig4 或 sig3）注入。
"""

import urllib.parse

from utils.ks_util import generate_hxfalcon, generate_sig3
from utils.sign.falcon_pure import CAVER, CP_PROJECT_INFO, cp_need_sign, need_sign
from utils.sign.jsval import js_to_string
from utils.sign.sig3_pure import need_sig3

# axios encode 在 encodeURIComponent 基础上放行的字符
_AXIOS_UNRESERVED = "-_.!~*'()" + ":$,[]"


def axios_encode(value) -> str:
    """axios 的 query 编码：encodeURIComponent 后把 ``: $ , [ ]`` 还原、``%20`` 换成 ``+``。"""
    return urllib.parse.quote(js_to_string(value), safe=_AXIOS_UNRESERVED,
                              encoding="utf-8").replace("%20", "+")


class Params:
    def __init__(self):
        self.params = {}

    def add_param(self, key, value):
        self.params[key] = value
        return self

    def update_params(self, params):
        self.params.update(params)
        return self

    def get(self):
        return self.params

    def with_kpn(self):
        """www.kuaishou.com 通用 query（部分接口带 kpn/kpf/subBiz）。"""
        self.params.update({
            'kpn': 'KUAISHOU_VISION',
        })
        return self

    def with_hxfalcon(self, path, method="POST", body=None,
                      content_type="application/json", force=False):
        """注入 www 数据侧 sig4 签名（``__NS_hxfalcon`` + ``caver``）。

        仅当 path 命中白名单或 force=True 时注入。签名器为进程级单例（一个爬虫会话
        对应浏览器的一个页面会话），计数器逐次自增，勿每次请求新建。

        :param path: pathname。
        :param method: 请求方法。
        :param body: 请求体（用于 form/requestBody 归类）。
        :param content_type: 内容类型。
        :param force: 强制签名（忽略白名单判断）。
        """
        if not (force or need_sign(path)):
            return self
        sig = generate_hxfalcon(path, method, dict(self.params), body, content_type)
        if sig:
            self.params['__NS_hxfalcon'] = sig
            self.params['caver'] = CAVER
        return self

    def with_cp_sign(self, path, body=None, req_type="json"):
        """注入 cp 发布侧签名，按接口自动选择 sig4 / sig3。

        cp 侧绝大多数 ``/rest/cp/*`` 走 ``__NS_sig3``，但 nearby / ip2poi / edit/info /
        poi/search / **video/pc/submit** 这几个改走 ``__NS_hxfalcon``（见 CP_SIG4_INTERFACES）。

        :param path: pathname，如 /rest/cp/works/v2/common/pc/current/user。
        :param body: 请求体（已并入 api_ph 基座）。
        :param req_type: ``json`` 或 ``form-data``。
        """
        if cp_need_sign(path):
            sig = generate_hxfalcon(path, "POST", dict(self.params), body,
                                    "application/json", CP_PROJECT_INFO)
            if sig:
                self.params['__NS_hxfalcon'] = sig
                self.params['caver'] = CAVER
        elif need_sig3(path):
            sig = generate_sig3(path, dict(self.params), body, req_type)
            if sig:
                self.params['__NS_sig3'] = sig
        return self

    def to_query_string(self):
        """按 axios 的口径序列化 query，与浏览器发出的 url 逐字符一致。

        站点用 axios，它的 encode 是（index-main 明文）::

            encodeURIComponent(v).replace(/%3A/gi,":").replace(/%24/g,"$")
              .replace(/%2C/gi,",").replace(/%20/g,"+")
              .replace(/%5B/gi,"[").replace(/%5D/gi,"]")

        不能直接用 requests 的 ``params=``：它会把 ``$`` 编成 ``%24``，而
        ``__NS_hxfalcon`` 的值里恰好带 ``$``（``...$HE_...``），URL 就和浏览器不一样了。
        """
        return "&".join(f"{axios_encode(k)}={axios_encode(v)}" for k, v in self.params.items())

    def to_string(self):
        """兼容旧调用；等价于 :meth:`to_query_string`。"""
        return self.to_query_string()

    # 兼容抖音仓库命名
    toString = to_string
