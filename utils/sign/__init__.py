#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""快手 Web 纯算签名包。

三个签名产物（全部由同一套混淆安全 SDK "falcon / wg" 引擎产出）：
    - ``__NS_hxfalcon`` : www.kuaishou.com 部分 /rest/v/* 的 query 签名（sig4），配套 ``caver=2``。
    - ``__NS_sig3``     : cp.kuaishou.com 大量 /rest/cp/*、/rest/v2/* 的 query 签名（hex 串）。
    - ``kww``           : 两站通用请求头，是页面初始化时从 localStorage/Cookie 冻结的
      ``kwfv1`` 快照；后续 Cookie ``kwfv1`` 轮换不会覆盖这个页面快照。

对外统一门面在 ``utils.ks_util``：``generate_hxfalcon`` / ``generate_sig3`` / ``generate_kww``。
每个签名器实现 ``sign(sign_input) -> str``。三者都已完成纯算，并对真实抓包与离线引擎基准
逐字节校验：``__NS_sig3``、``__NS_hxfalcon``，以及 webweapon 的页面 ``kww`` 快照与
Cookie ``kwfv1``（两者独立持有），连同 6 分钟过期的 ``kwscode`` / ``kwssectoken``。

三个签名器都是**有状态**的（会话启动时间、调用计数、cookie 有效期都进签名/请求），
由 ``utils.ks_util`` 持有进程级单例，等价于浏览器的一个页面会话。

``jsval`` 收敛所有 JS 值语义（数字格式化、JSON 键序、UTF-16 排序、encodeURI），
两个签名器共用 —— 这些地方只要和浏览器差一个字符，签名就是错的。
"""

from utils.sign.falcon_pure import HxFalconSigner
from utils.sign.sig3_pure import Sig3Signer
from utils.sign.kww_pure import KwwSigner

__all__ = ["HxFalconSigner", "Sig3Signer", "KwwSigner"]
