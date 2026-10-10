#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""``kww`` / ``kwfv1`` / ``kwscode`` / ``kwssectoken`` 纯算实现（webweapon SDK）。

请求头 ``kww`` 的取值（index-main 明文）::

    var ut$1 = function(){
        var t={}, n="";
        n = localStorage.getItem("kwfv1") || cookie("kwfv1") || "";
        if (!n && window.kwpsec) n = window.kwpsec.getData();
        return n && (t.kww = n), t;
    };

而 ``kwfv1`` 本身不是服务端下发的，是 SDK 本地算的（``getDefaultData``）::

    var e = Date.now(), n = localStorage.getItem("kwfv1"),
        r = cookie("kwscode"), o = cookie("kwssectoken"),
        i = location.href.slice(0, 80);
    if (!n) {                                          // 指纹：只算一次，永久缓存
        var a = encodeURI(i)+"|"+did+"|"+productName+"|"+e+"|"+rand(8);
        var s = st$1(a, "K8wm5PvY9nX7qJc2");
        n = "K"+s.slice(0,4)+"W"+s.slice(4,-2)+"F"+s.slice(-2);
        localStorage.setItem("kwfv1", n);
    }
    if (!r || !o) {                                    // 这两个 cookie 只活 6 分钟
        o = rand(64);
        var c = encodeURI(i)+"|"+did+"|"+productName+"|"+e+"|"+o.slice(0,8);
        var l = st$1(c, "H4tL6rNd3vB9xM5k");
        r = "K"+l.slice(0,4)+"W"+l.slice(4,-2)+"S"+l.slice(-2);
        setCookie("kwssectoken", o, {expires: 6/1440});
        setCookie("kwscode",     r, {expires: 6/1440});
    }

``st$1`` 是 CryptoJS 口径的 **AES-128-CBC + PKCS7，IV 等于 key，输出 base64**。

**注意 6 分钟有效期**：``kwscode`` / ``kwssectoken`` 透传抓来的 cookie 撑不过几分钟，必须本地续期。

**kwfv1 有两种形态，服务端都收**（2026-08-15 live.kuaishou.com 实抓）：

1. **首次访问**：localStorage 为空，SDK 本地算出 ``K..W..F..`` 外壳并写进去，``kww`` 就用它。
   实抓到的一条是 ``K408WWQK1WMvAnj5...FN1``，用 ``FINGERPRINT_KEY`` 解开正是::

       https://live.kuaishou.com/|web_fbf4abc0...|PCLive|1786809590431|goG2elf1

   该请求服务端返回 ``result:1`` —— 说明本地生成的值是被接受的，本模块的实现即复刻这条路径。
2. **之后**：官方 kwf 脚本把真实值写入 localStorage/Cookie（已抓到 174 与 218 字符两代，
   都不符合 ``K..W..F..`` 外壳）。新页面会冻结当时的值作为 ``kww``；同一页面后续
   Cookie ``kwfv1`` 轮换时，已经冻结的 ``kww`` 不随之覆盖。

所以策略是：**cookie 里有 kwfv1 就原样透传**（等于回访浏览器的行为），没有才本地生成第 1 种。

``did`` 必须与 cookie 里的 ``did`` 一致（实抓印证），``productName`` 随站点不同：
www 为 ``kuaishou-vision``，cp 为 ``onvideo-cp``，直播为 ``PCLive``。
"""

from __future__ import annotations

import base64
import random
import string
import time

from Crypto.Cipher import AES

from utils.sign.jsval import encode_uri

# SDK 常量（index-main 明文）
FINGERPRINT_KEY = "K8wm5PvY9nX7qJc2"      # h$6，算 kwfv1
TOKEN_KEY = "H4tL6rNd3vB9xM5k"            # u$5，算 kwscode
DEFAULT_KEY = "webweaponconfigs"          # l$4，st$1 的缺省 key
COOKIE_TTL = 6 * 60                       # kwscode / kwssectoken：6/1440 天 = 6 分钟
PRODUCT_NAME_WWW = "kuaishou-vision"
PRODUCT_NAME_CP = "onvideo-cp"
PRODUCT_NAME_LIVE = "PCLive"                 # live.kuaishou.com 实抓
PRODUCT_NAME_CAPTCHA = "verification-captcha"
HREF_WWW = "https://www.kuaishou.com/new-reco"
# Current Chrome creator page URL.  ``kwfv1``/``kwscode`` generation uses the
# first 80 characters of location.href; adding the historical NewReco query
# changes the generated cookie and is therefore not interchangeable.
HREF_CP = "https://cp.kuaishou.com/article/publish/video?origin=www.kuaishou.com"
HREF_LIVE = "https://live.kuaishou.com/"     # live.kuaishou.com 实抓
# captcha iframe 是独立页面生命周期；保留完整 URL（而不是只写 host），
# 这样首次本地 bootstrap 的 kwf/kws 输入与浏览器 location.href 口径一致。
HREF_CAPTCHA = "https://captcha.zt.kuaishou.com/iframe/index.html"

_RAND_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits  # 62 个，顺序同源码


def weapon_encrypt(plain: str, key: str = DEFAULT_KEY) -> str:
    """``st$1``：AES-128-CBC + PKCS7，IV 等于 key，输出 base64。"""
    key_bytes = key.encode("utf-8")
    data = plain.encode("utf-8")
    pad = 16 - len(data) % 16
    data += bytes([pad]) * pad
    return base64.b64encode(AES.new(key_bytes, AES.MODE_CBC, key_bytes).encrypt(data)).decode()


def random_string(n: int) -> str:
    """``rt$1``：从 62 字符表里取 n 个（大写 + 小写 + 数字，顺序同源码）。"""
    return "".join(random.choice(_RAND_ALPHABET) for _ in range(n))


def _wrap(cipher_b64: str, tag: str) -> str:
    """SDK 的加壳：``"K" + s[:4] + "W" + s[4:-2] + <tag> + s[-2:]``。"""
    return f"K{cipher_b64[:4]}W{cipher_b64[4:-2]}{tag}{cipher_b64[-2:]}"


def looks_like_shell(value: str, tag: str = "F") -> bool:
    """是否是本地兜底生成的 ``K..W..<tag>..`` 外壳形态。

    真实 SDK（kwf/kws 脚本）产出的不长这样：``kwfv1`` 是已抓到的 174/218 字符
    官方脚本形态，``kwscode`` 是 64 位小写 hex。用它来判断
    当前值是「真实形态」还是「没有 SDK 时的兜底形态」。

    :param value: 待判断的值。
    :param tag: ``F``（kwfv1）或 ``S``（kwscode）。
    """
    return (bool(value) and len(value) > 9 and value[0] == "K"
            and value[5] == "W" and value[-3] == tag)


def build_kwfv1(href: str, did: str = "", product_name: str = PRODUCT_NAME_WWW,
                now_ms: int = None, nonce: str = None) -> str:
    """生成 ``kwfv1`` 设备指纹（对应源码里 ``!n`` 分支）。"""
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    nonce = random_string(8) if nonce is None else nonce
    plain = f"{encode_uri(href[:80])}|{did}|{product_name}|{now_ms}|{nonce}"
    return _wrap(weapon_encrypt(plain, FINGERPRINT_KEY), "F")


def build_kwscode(href: str, sec_token: str, did: str = "",
                  product_name: str = PRODUCT_NAME_WWW, now_ms: int = None) -> str:
    """生成 ``kwscode``（对应源码里 ``!r || !o`` 分支，取 secToken 前 8 位入明文）。"""
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    plain = f"{encode_uri(href[:80])}|{did}|{product_name}|{now_ms}|{sec_token[:8]}"
    return _wrap(weapon_encrypt(plain, TOKEN_KEY), "S")


class KwwSigner:
    """页面级 ``kww`` 快照与当前 webweapon Cookie 的独立持有者。

    Chrome Network 已确认：页面初始化会把当时 localStorage 的 ``kwfv1``
    冻结成该页的 ``kww``；kwf 随后可以轮换 localStorage/Cookie ``kwfv1``，
    但已经冻结的 ``kww`` 不跟着改变。因此二者必须是两个状态槽，不能用
    赋值维持恒等。
    """

    def __init__(self, kwfv1: str = "", href: str = HREF_WWW, did: str = "",
                 product_name: str = PRODUCT_NAME_WWW,
                 kwscode: str = "", kwssectoken: str = "",
                 kww_snapshot: str = None, kwfcv1: str = ""):
        """:param kwfv1: Cookie/localStorage 里的浏览器值；空则走 exact bootstrap。
        :param kwscode: Cookie 里已有的值直接透传；空则执行 exact signUrl。
        :param kwssectoken: 同上。
        """
        self.href = href
        self.did = did or ""
        self.product_name = product_name
        self.kwfv1 = kwfv1 or ""
        # None 表示新建页面：浏览器会读取当前 localStorage/Cookie 值作为
        # 页面快照；显式空串用于恢复“尚未初始化页面”的持久化状态。
        self._kww_snapshot = self.kwfv1 if kww_snapshot is None else (kww_snapshot or "")
        # kwf branches on this persistent localStorage counter. Resetting it
        # for each Node call changes the output length (174 before the observed
        # threshold, 218 afterwards), so it is part of program-owned state.
        self.kwfcv1 = str(kwfcv1 or "")
        # 源码是 `if (!r || !o)` —— 只在缺失时才生成，有就一直用着（直到 6 分钟后 cookie 过期）
        self._kwscode = kwscode or ""
        self._sec_token = kwssectoken or ""
        self._from_cookie = bool(kwscode and kwssectoken)
        self._issued_at = time.time() if self._from_cookie else 0.0

    def set_kwfv1(self, kwfv1: str, update_snapshot: bool = False):
        """更新当前 Cookie ``kwfv1``，默认不改页面 ``kww`` 快照。"""
        if kwfv1:
            self.kwfv1 = kwfv1
            if update_snapshot:
                self._kww_snapshot = kwfv1
        return self

    def set_kww_snapshot(self, value: str):
        """显式设置页面初始化时冻结的 ``kww``。"""
        self._kww_snapshot = value or ""
        return self

    def begin_page(self, snapshot: str = None):
        """开始一个新页面生命周期，冻结当前 Cookie/localStorage 值。"""
        if snapshot is None:
            if not self.kwfv1:
                self._refresh_if_needed()
            if not self.kwfv1:
                raise RuntimeError("exact kwfv1 缺失，禁止生成非浏览器兜底外壳")
            snapshot = self.kwfv1
        self._kww_snapshot = snapshot or ""
        return self

    def sign(self, sign_input: dict = None) -> str:
        """返回当前页面冻结的 ``kww``，不随 Cookie 轮换。

        取值优先级，与浏览器行为一一对应：

        1. cookie / localStorage 里已有的（回访浏览器就是这样）；
        2. 缺失时执行完整 ``/s/w/c -> exact fpUrl/signUrl`` 引导链；任何未知
           脚本或环境漂移都 fail-closed，不生成格式兼容外壳。
        """
        if not self._kww_snapshot:
            self.begin_page()
        return self._kww_snapshot

    def _oracle_kwfv1(self) -> str:
        """跑 kwf 预言机现算一个 kwfv1；没有 node / 脚本时返回空串。"""
        try:
            from utils.sign import weapon_oracle
            if not weapon_oracle.oracle_available():
                return ""
            state = weapon_oracle.gen_kwfv1(
                did=self.did, href=self.href, kwfcv1=self.kwfcv1,
                current_kwfv1=self.kwfv1, return_state=True)
            self.kwfcv1 = str(state.get("kwfcv1") or self.kwfcv1)
            return str(state.get("value") or "")
        except Exception:                                  # noqa: BLE001
            return ""

    def _refresh_if_needed(self):
        """对齐源码 ``if (!r || !o)``：有值就用着，缺失或超过 6 分钟才重算。

        ``kwssectoken`` 必须是 gdfp ``/s/w/c`` 下发的 88 字符 secToken；
        ``kwscode`` 必须来自本次 exact signUrl。缺失或失败禁止本地伪造。
        """
        if (self.kwfv1 and self._kwscode and self._sec_token
                and (time.time() - self._issued_at) < COOKIE_TTL):
            return
        if self._try_bootstrap():
            return
        raise RuntimeError("webweapon exact bootstrap 失败，禁止生成替代 Cookie")

    def _try_bootstrap(self) -> bool:
        """真去 gdfp 换一次票，然后用 kwf/kws 预言机产出真实形态的 kwfv1 和 kwscode。

        完整流程（对应浏览器 SDK 启动时的行为）::

            /s/w/c 换票  ->  {fpUrl, signUrl, secToken}
            loadScript(fpUrl)    # kwf 脚本产出 kwfv1
            loadScript(signUrl)  # kws 脚本产出 kwscode
            setCookie("kwssectoken", secToken, {expires: 6/1440})
            setCookie("kwscode",     kwscode,   {expires: 6/1440})
            localStorage["kwfv1"] = kwfv1

        """
        if not self.did:
            return False
        try:
            from utils.sign import webweapon_boot, weapon_oracle
            cfg = webweapon_boot.fetch_config(
                self.did, self.product_name or webweapon_boot.PRODUCT_WWW,
                referer=self.href or "https://www.kuaishou.com/")
        except Exception:                              # noqa: BLE001
            return False
        if not (cfg.fp_url and cfg.sign_url and cfg.sec_token):
            raise RuntimeError("gdfp /s/w/c 缺少 fpUrl/signUrl/secToken")
        if len(cfg.sec_token) != 88:
            raise RuntimeError("gdfp secToken 长度偏离浏览器合同")
        if not weapon_oracle.oracle_available():
            raise RuntimeError("缺少 Node/官方脚本预言机，禁止降级生成 Cookie")

        # kwf 预言机按服务端 fpUrl 产出真实 174/218 字符形态，与浏览器同源同算法。
        state = weapon_oracle.gen_kwfv1(
            did=self.did,
            href=self.href or "https://www.kuaishou.com/new-reco",
            kwfcv1=self.kwfcv1, current_kwfv1=self.kwfv1,
            script_path=cfg.fp_url,
            return_state=True)
        kwfv1 = str(state.get("value") or "")
        self.kwfcv1 = str(state.get("kwfcv1") or self.kwfcv1)
        if not kwfv1:
            raise RuntimeError("exact fpUrl 未产出 kwfv1")
        self.kwfv1 = kwfv1

        # kws 预言机产出 kwscode（64 位小写 hex，真实形态）
        kwscode = weapon_oracle.gen_kwscode(
            sec_token=cfg.sec_token, sign_url=cfg.sign_url, did=self.did,
            href=self.href or "https://www.kuaishou.com/new-reco")
        if not kwscode:
            raise RuntimeError("exact signUrl 未产出 kwscode")

        self._sec_token = cfg.sec_token
        self._kwscode = kwscode
        self._boot_config = cfg
        self._from_cookie = False
        self._issued_at = time.time()
        return True

    def cookies(self) -> dict:
        """webweapon 的三个 cookie；``kwscode`` / ``kwssectoken`` 缺失或过期才重算。"""
        self._refresh_if_needed()
        if not self.kwfv1:
            raise RuntimeError("exact kwfv1 缺失，禁止生成替代 Cookie")
        return {
            "kwfv1": self.kwfv1,
            "kwscode": self._kwscode,
            "kwssectoken": self._sec_token,
            "kwpsecproductname": self.product_name,
        }

    def export_state(self) -> dict:
        """导出可持久化状态；页面快照不能只靠 Cookie mapping 反推。"""
        boot = getattr(self, "_boot_config", None)
        return {
            "href": self.href,
            "did": self.did,
            "product_name": self.product_name,
            "kww_snapshot": self._kww_snapshot,
            "kwfv1": self.kwfv1,
            "kwfcv1": self.kwfcv1,
            "kwscode": self._kwscode,
            "kwssectoken": self._sec_token,
            "issued_at": self._issued_at,
            "from_cookie": self._from_cookie,
            "fp_url": getattr(boot, "fp_url", "") if boot is not None else "",
            "sign_url": getattr(boot, "sign_url", "") if boot is not None else "",
        }
