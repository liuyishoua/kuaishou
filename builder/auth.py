#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""KuaishouAuth：会话认证信息（对齐 DouYin_Spider/builder/auth.py 的 DouyinAuth）。

快手 Web 的鉴权核心是 cookie，其中：
    - ``kwfv1``           : 指纹 token Cookie。``kww`` 来自页面本地 webweapon 状态；
      当前跨标签实抓证明二者可能阶段性不同，不能再无条件视为恒等。
    - ``kwscode`` / ``kwssectoken`` : 安全 SDK 配套 cookie，**只有 6 分钟有效期**，
      浏览器端由 SDK 本地续期。所以 :attr:`KuaishouAuth.cookie` 会用现算值覆盖抓包里那份。
    - ``kwpsecproductname``: www 为 ``kuaishou-vision``，cp 为 ``onvideo-cp``。
    - ``userId`` / ``did`` 等：账号/设备标识（``did`` 参与 kwfv1/kwscode 的明文）。

    用法：
    auth = KuaishouAuth()
    auth.prepare_auth(cookie_str)          # 解析 cookie，配置 webweapon 会话
    KuaishouAPI.get_feed_hot(auth)         # 传入接口

    # 统一入口：有用户 CK 就直接恢复；为空则自动走一次扫码登录并把
    # www/CP/设备指纹状态合并到同一个 auth 对象。
    auth = KuaishouAuth().initialize(cookie_str)
"""

import secrets
import time

from utils.ks_util import trans_cookies
from utils.sign.kww_pure import (HREF_CAPTCHA, HREF_CP, HREF_LIVE, HREF_WWW,
                                 PRODUCT_NAME_CAPTCHA, PRODUCT_NAME_CP,
                                 PRODUCT_NAME_LIVE, PRODUCT_NAME_WWW, KwwSigner)


DEFAULT_DID_PREFIX = "web_"
DEFAULT_PRODUCT = PRODUCT_NAME_WWW
DEFAULT_HREF = HREF_WWW


def _site_defaults(product_name: str):
    """按浏览器站点选择 webweapon 的 href/product（不能跨站共用状态）。"""
    if product_name == PRODUCT_NAME_CAPTCHA:
        return HREF_CAPTCHA, PRODUCT_NAME_CAPTCHA
    if product_name == PRODUCT_NAME_CP:
        return HREF_CP, PRODUCT_NAME_CP
    if product_name == PRODUCT_NAME_LIVE:
        return HREF_LIVE, PRODUCT_NAME_LIVE
    return HREF_WWW, PRODUCT_NAME_WWW


def looks_like_local_fingerprint(value: str) -> bool:
    """是否是 SDK 本地生成的指纹外壳 ``"K" + s[:4] + "W" + s[4:-2] + "F" + s[-2:]``。

    服务端下发的那份不长这样（实抓形如 ``PnGU+9+Y...``），两种都能用，这里只用于辨形。
    """
    return bool(value) and len(value) > 9 and value[0] == "K" and value[5] == "W" and value[-3] == "F"


class KuaishouAuth:
    def __init__(self):
        self._cookie = {}             # 登录 cookie（静态部分）
        self.cookie_str = None        # 归一化后的 cookie 字符串
        self.kwfv1 = ""               # 指纹 token Cookie（不保证等于当前页面 kww）
        self.kww_snapshot = ""         # 页面初始化时冻结的 kww（独立于 Cookie kwfv1）
        self.kwfcv1 = ""               # kwf localStorage 调用计数器（决定 174/218 分支）
        self.did = ""                 # 设备标识，进 kwfv1/kwscode 的明文
        # Browser business requests carry a second device cookie, ``didv``.
        # Network captures show a 13-digit millisecond timestamp; unlike ``wid``
        # it is not returned by gdfp, so preserve one value for the lifetime of
        # this program-owned browser session instead of regenerating per request.
        self.didv = ""
        self.userId = None            # 账号 ID（部分接口需要）
        self.cp_api_ph = ""           # cp 侧 kuaishou.web.cp.api_ph（发布接口 body 基座）
        self._uid = None
        # Chrome keeps path/domain-scoped webweapon cookies after a refresh,
        # so a later Network Cookie header can contain an old quartet followed
        # by the newly issued quartet. Keep that history separately from the
        # mapping API, which intentionally exposes one value per cookie name.
        self._wire_cookie_history = []
        # www 页面仍保留“首屏/交互”状态；重新扫码并完成文档引导后，
        # 进入 relogin 阶段。该阶段不是简单的 initial/refreshed 二分：
        # 当前 Chrome Network 对首屏、liked、collect、private 分别出现四套
        # path-scoped Cookie/值合同，必须按具体接口选择。它们会随真实
        # webweapon 轮换继续变化，运行时只能序列化已经持有的轮换历史。
        self._www_cookie_phase = "initial"
        # A forced DevTools ignore-cache navigation is a distinct browser
        # request mode.  Keep it explicit so ordinary reload/XHR requests do
        # not inherit cache-control/pragma merely because the session was
        # re-logged in.
        self._www_ignore_cache = False
        # 账号限制后的本人 profile 是一套独立 Network 合同：Cookie 尾序和
        # kww/kwfv1 相等关系都不同于正常重新登录首屏。只有 CP 权限接口
        # 119120 或 www profile/feed 208007 的真实响应才能推进此状态。
        self._www_account_restricted = False
        self._cp_account_restricted = False
        self._cp_publish_authority_response = None
        self._cp_last_video_finish = None
        self._cp_publish_refresh_ids = None
        # 当前 CP 普通刷新在首批外壳请求后会刷新 webweapon quartet，Cookie
        # 创建顺序随之改变。最新 Network 明确有 initial -> warmed -> refreshed
        # 三段，这个阶段是线级合同的一部分。
        self._cp_cookie_phase = "initial"
        self._cp_ignore_cache = False
        # live 首页和房间在同一次普通加载中都经过四段可观测状态：
        # initial -> login -> authenticated_1 -> authenticated_2。首页/房间
        # 的 Cookie 线序并不相同，不能再用一套 live_initial/live_authenticated
        # 近似。这里分别保存两条页面状态机；只有真实请求链推进它们。
        self._live_cookie_phase = {
            "home": "initial", "room": "initial", "profile": "initial"}
        self._live_home_login_pay_count = 0
        self._live_room_login_pay_count = 0
        # Sentry's browser SDK creates one trace id for a page-load transaction
        # and a new span id for every instrumented fetch/XHR. Keep this
        # ephemeral page state separate from cookies and persisted login state.
        self._live_sentry_transactions = {}
        # onvideo 的“响应刚 Set-Cookie”与“已有 token 后热刷新”线序不同。
        self._onvideo_cookie_phase = "bootstrap"
        # webweapon 是页面/站点会话状态，不能使用进程级全局 signer；否则
        # www、cp、live 或多个账号交替请求时会互相覆盖 kwfv1/kwscode。
        self._kww_signer = None
        self._last_login_result = None
        self._live_bootstrap_enabled = False
        # Optional real browser captcha fingerprint captured from the iframe.
        # Keep it separate from webweapon cookies so a refreshed ticket does
        # not silently reintroduce the package's stale default fingerprint.
        self.captcha_fingerprint = None

    def set_captcha_fingerprint(self, fingerprint: dict):
        """Use a browser-captured fingerprint for automatic slider submits.

        ``fingerprint`` is the object returned by ``utils.captcha_fp``'s
        ``capture_js`` snippet: ``gpuInfo`` plus ``captchaExtraParam``.  The
        value is retained for this auth session and is intentionally not
        serialized into cookies or exported auth state.
        """
        if fingerprint is not None and not isinstance(fingerprint, dict):
            raise TypeError("captcha fingerprint must be a dict or None")
        self.captcha_fingerprint = dict(fingerprint) if fingerprint else None
        return self

    def prepare_auth(self, cookie_str: str):
        """解析 cookie 字符串，抽取关键字段并配置 webweapon 会话。

        :param cookie_str: 浏览器复制的完整 cookie 字符串。
        """
        self._last_login_result = None
        self._live_bootstrap_enabled = False
        self._cookie = trans_cookies(cookie_str or "")
        self._www_cookie_phase = "initial"
        self._www_ignore_cache = False
        self._www_account_restricted = False
        self._cp_account_restricted = False
        self._cp_publish_authority_response = None
        self._cp_last_video_finish = None
        self._cp_publish_refresh_ids = None
        self._cp_cookie_phase = "initial"
        self._cp_ignore_cache = False
        self._live_cookie_phase = {
            "home": "initial", "room": "initial", "profile": "initial"}
        self._live_home_login_pay_count = 0
        self._live_room_login_pay_count = 0
        self._live_sentry_transactions = {}
        self._onvideo_cookie_phase = (
            "warm" if self._cookie.get("ks_onvideo_token") else "bootstrap")
        # Match the browser cold start: create a web device id before the
        # webweapon SDK obtains kwfv1/kwscode/kwssectoken.  Without this,
        # prepare_auth("") produced an empty cookie key and local fallback
        # tokens with lengths different from the browser values.
        if not self._cookie.get("did"):
            self._cookie["did"] = DEFAULT_DID_PREFIX + secrets.token_hex(16)
        product = self._cookie.get("kwpsecproductname") or DEFAULT_PRODUCT
        href, product = _site_defaults(product)
        self._cookie["kwpsecproductname"] = product
        self.cookie_str = "; ".join([f"{k}={v}" for k, v in self._cookie.items()])
        # kwfv1 有两种形态，服务端都收（2026-08-15 live.kuaishou.com 实抓）：
        #   1. 首次访问 SDK 本地生成的 "K..W..F.." 外壳（那次请求服务端返回 result:1）
        #   2. 之后被服务端下发值替换（形如 "PnGU+9+Y..."，写进 localStorage 与 cookie）
        # 有 cookie 就原样透传（= 回访浏览器的行为，最贴近真实）；没有才本地生成第 1 种。
        self.kwfv1 = self._cookie.get("kwfv1", "")
        # Cookie 本身不含 localStorage.kwfcv1。新会话从空值开始；通过
        # export_state/prepare_state 恢复时再加载程序自己的持久状态。
        self.kwfcv1 = ""
        self.did = self._cookie.get("did", "")
        self.didv = self._cookie.get("didv", "") or str(int(time.time() * 1000))
        self._cookie["didv"] = self.didv
        self.userId = self._cookie.get("userId") or self._cookie.get("userid")
        # cp 发布侧接口 body 基座（几乎所有 /rest/cp/* 的 body 都带此字段）
        self.cp_api_ph = self._cookie.get("kuaishou.web.cp.api_ph", "")
        # kwscode / kwssectoken 有就透传；缺失时由 exact /s/w/c signUrl 生成，
        # 未知脚本或执行漂移必须 fail-closed，不能本地拼兼容外壳。
        self._kww_signer = KwwSigner(
            self.kwfv1,
            href=href,
            did=self.did,
            product_name=product,
            kwscode=self._cookie.get("kwscode", ""),
            kwssectoken=self._cookie.get("kwssectoken", ""),
            kww_snapshot=self.kwfv1,
            kwfcv1=self.kwfcv1,
        )
        self.kww_snapshot = self.kwfv1
        return self

    def initialize(self, cookie_str: str = "", *, qr_path: str = "qrcode.png",
                   timeout: float = 600.0, poll_interval: float = 1.0,
                   on_qr=None, login_if_empty: bool = True,
                   mobile_phone: str = "", mobile_sms_code: str = "",
                   mobile_country_code: str = "+86"):
        """统一建立一次程序自持会话。

        - ``cookie_str`` 非空：解析用户提供的 CK，立即物化官方 JS
          webweapon Cookie；若缺少合法 ``wid``，补跑 CP 页的
          ``kwf getData(1) -> /s/w/p``，但不会擅自发起二维码登录。
        - ``cookie_str`` 为空且提供 ``mobile_phone`` + ``mobile_sms_code``：
          走手机号验证码登录，再在同一个对象上完成 www/CP STS、文档引导
          和设备指纹初始化。短信申请请先调用
          :meth:`ks_apis.login_api.KuaishouLoginAPI.request_mobile_code`。
        - ``cookie_str`` 为空且未提供手机号：走完整 QR 登录、www/CP STS
          与文档引导，并接收服务端下发的 ``wid``。

        低层 :meth:`prepare_auth` 仍保持“只解析、不出网”的兼容语义；新
        代码应优先使用本方法，避免业务 API 各自临时加载 JS Cookie。
        失败会抛出 ``RuntimeError``，成功返回 ``self``。
        """
        self.prepare_auth(cookie_str or "")
        self._live_bootstrap_enabled = True
        self._ensure_browser_defaults()
        supplied = bool(str(cookie_str or "").strip())
        mobile_phone = str(mobile_phone or "").strip()
        mobile_sms_code = str(mobile_sms_code or "").strip()
        if supplied and (mobile_phone or mobile_sms_code):
            raise ValueError("cookie_str 与手机号验证码登录参数不能同时提供")
        if mobile_phone or mobile_sms_code:
            if not mobile_phone or not mobile_sms_code:
                raise ValueError("手机号验证码登录需要同时提供 mobile_phone 和 mobile_sms_code")
            from ks_apis.login_api import KuaishouLoginAPI
            result = KuaishouLoginAPI.login_by_mobile_code(
                self, mobile_phone, mobile_sms_code,
                country_code=mobile_country_code)
            self._last_login_result = dict(result or {})
            if not result.get("ok"):
                detail = result.get("detail") or {}
                code = detail.get("result") if isinstance(detail, dict) else None
                message = detail.get("error_msg") if isinstance(detail, dict) else None
                raise RuntimeError(
                    f"快手手机号会话初始化失败 stage={result.get('stage')}: "
                    f"result={code!r} {message or '请检查验证码或官方风控提示'}")
            self.update_cookies(result.get("cookies") or {})
            self._ensure_browser_defaults()
            return self
        if supplied:
            # Materialize kwfv1/kwscode/kwssectoken once at the session
            # boundary.  Existing user-provided values are reused until the
            # normal six-minute signer TTL requires an exact refresh.
            self.cookie
            from ks_apis.login_api import KuaishouLoginAPI
            previous_product = self._cookie.get("kwpsecproductname", DEFAULT_PRODUCT)
            fingerprint = KuaishouLoginAPI.bootstrap_device_fingerprint(self)
            # Keep the caller's original site context after a CP-only report.
            if previous_product == PRODUCT_NAME_CP:
                self.use_site("https://cp.kuaishou.com")
            elif previous_product == PRODUCT_NAME_LIVE:
                self.use_site("https://live.kuaishou.com")
            else:
                self.use_site("https://www.kuaishou.com")
            self._last_login_result = {
                "ok": True, "stage": "cookie", "cookies": dict(self._cookie),
                "fingerprint": fingerprint,
            }
            return self
        if not login_if_empty:
            self.cookie
            self._last_login_result = {
                "ok": True, "stage": "prepared", "cookies": dict(self._cookie),
            }
            return self

        from ks_apis.login_api import KuaishouLoginAPI
        result = KuaishouLoginAPI.login_browser_session(
            self, qr_path=qr_path, timeout=timeout,
            poll_interval=poll_interval, on_qr=on_qr)
        self._last_login_result = dict(result or {})
        if not result.get("ok"):
            raise RuntimeError(
                f"快手扫码会话初始化失败 stage={result.get('stage')}: "
                f"{result.get('detail')}")
        self.update_cookies(result.get("cookies") or {})
        self._ensure_browser_defaults()
        return self

    def _ensure_browser_defaults(self):
        """Fill only stable browser defaults that are absent from user CK.

        Values explicitly supplied by the user always win.  The low-level
        ``prepare_auth`` path intentionally does not add these fields because
        offline wire fixtures rely on its parse-only semantics.
        """
        product = self._cookie.get("kwpsecproductname", DEFAULT_PRODUCT)
        self._cookie.setdefault("kpf", "PC_WEB")
        self._cookie.setdefault("clientid", "3")
        self._cookie.setdefault(
            "kpn", "GAME_ZONE" if product == PRODUCT_NAME_LIVE else "KUAISHOU_VISION")
        self.cookie_str = "; ".join(
            f"{key}={value}" for key, value in self._cookie.items())
        return self

    def request_mobile_code(self, phone: str, country_code: str = "+86") -> dict:
        """在当前 ``auth`` 会话上申请手机号登录短信。

        调用前可用 ``initialize("", login_if_empty=False)`` 创建冷启动会话；
        如果是新建的空对象，本方法会只初始化本地设备/webweapon 状态，不会
        发起二维码登录。官方 CAPTCHA/风控挑战仍需用户在页面完成。
        """
        if self._kww_signer is None:
            self.prepare_auth("")
            self._live_bootstrap_enabled = True
            self._ensure_browser_defaults()
        from ks_apis.login_api import KuaishouLoginAPI
        return KuaishouLoginAPI.request_mobile_code(
            self, phone=phone, country_code=country_code)

    def login_by_mobile_code(self, phone: str, sms_code: str,
                             country_code: str = "+86"):
        """用短信验证码完成登录，并在当前对象内补齐业务会话。"""
        if self._kww_signer is None:
            self.prepare_auth("")
            self._live_bootstrap_enabled = True
            self._ensure_browser_defaults()
        from ks_apis.login_api import KuaishouLoginAPI
        result = KuaishouLoginAPI.login_by_mobile_code(
            self, phone=phone, sms_code=sms_code,
            country_code=country_code)
        self._last_login_result = dict(result or {})
        if not result.get("ok"):
            detail = result.get("detail") or {}
            code = detail.get("result") if isinstance(detail, dict) else None
            message = detail.get("error_msg") if isinstance(detail, dict) else None
            raise RuntimeError(
                f"快手手机号会话初始化失败 stage={result.get('stage')}: "
                f"result={code!r} {message or '请检查验证码或官方风控提示'}")
        self.update_cookies(result.get("cookies") or {})
        self._ensure_browser_defaults()
        return self

    def initialize_state(self, state: dict, *, ensure_device: bool = True):
        """恢复程序自持状态，并按需补齐 CP 设备指纹票据。

        这是 ``export_state`` 的高层对应入口，供复用会话流程使用；它不
        读取浏览器数据，也不会因为状态已有 ``wid`` 而重复上报。
        """
        self.prepare_state(state)
        self._live_bootstrap_enabled = True
        self._ensure_browser_defaults()
        self.cookie
        fingerprint = None
        if ensure_device:
            from ks_apis.login_api import KuaishouLoginAPI
            previous_product = self._cookie.get("kwpsecproductname", DEFAULT_PRODUCT)
            fingerprint = KuaishouLoginAPI.bootstrap_device_fingerprint(self)
            if previous_product == PRODUCT_NAME_CP:
                self.use_site("https://cp.kuaishou.com")
            elif previous_product == PRODUCT_NAME_LIVE:
                self.use_site("https://live.kuaishou.com")
            else:
                self.use_site("https://www.kuaishou.com")
            self._ensure_browser_defaults()
        self._last_login_result = {
            "ok": True, "stage": "state", "cookies": dict(self._cookie),
            "fingerprint": fingerprint,
        }
        return self

    @property
    def cookie(self) -> dict:
        """发请求用的 cookie。

        ``kwscode`` / ``kwssectoken`` 在浏览器里只有 6 分钟有效期（SDK 本地续期），
        所以这里用现算的值覆盖抓包里那份，避免跑几分钟后带着过期 token 发请求。
        """
        if self._kww_signer is None:
            # 兼容直接给 auth.cookie 的旧调用；正常路径由 prepare_auth 初始化。
            product = self._cookie.get("kwpsecproductname", DEFAULT_PRODUCT)
            href, product = _site_defaults(product)
            self._kww_signer = KwwSigner(
                self._cookie.get("kwfv1", ""), href=href, did=self._cookie.get("did", ""),
                product_name=product, kwscode=self._cookie.get("kwscode", ""),
                kwssectoken=self._cookie.get("kwssectoken", ""),
                kwfcv1=self.kwfcv1,
            )
        generated = self._kww_signer.cookies()
        quartet = ("kwpsecproductname", "kwfv1", "kwssectoken", "kwscode")
        previous = tuple(self._cookie.get(key, "") for key in quartet)
        current = tuple(generated.get(key, "") for key in quartet)
        if all(previous) and previous != current:
            # Store one old snapshot per distinct refresh. This is the same
            # observable shape as Chrome's stale path-scoped cookies and does
            # not fabricate a duplicate before a real local refresh occurs.
            if previous not in self._wire_cookie_history:
                self._wire_cookie_history.append(previous)
            # 当前 profile Network 在标签阶段又完成一次短期票据轮换后，
            # kwfv1 与 kws* 的创建顺序再次改变。只有实际观察到 signer 输出
            # 变化才推进，不能按接口名凭空切换。
            if self._www_cookie_phase == "refreshed" and previous[2:] != current[2:]:
                self._www_cookie_phase = "security_refreshed"
        for key in quartet:
            if generated.get(key):
                self._cookie[key] = generated[key]
        if generated.get("kwfv1"):
            self.kwfv1 = generated["kwfv1"]
        self.kwfcv1 = str(getattr(self._kww_signer, "kwfcv1", self.kwfcv1) or "")
        # Keep a deterministic browser-like order for the webweapon quartet.
        # Cookie order is not semantic, but this makes wire captures stable.
        merged = {}
        for key, value in self._cookie.items():
            if key and key not in {"kwpsecproductname", "kwfv1", "kwscode", "kwssectoken"}:
                merged[key] = value
        product = self._cookie.get("kwpsecproductname") or generated.get("kwpsecproductname")
        if product:
            merged["kwpsecproductname"] = product
        for key in ("kwfv1", "kwssectoken", "kwscode"):
            value = generated.get(key) or self._cookie.get(key)
            if value:
                merged[key] = value
        return merged

    def cookie_header(self, site: str = "www") -> str:
        """Serialize the exact site-specific Cookie header seen in Chrome.

        A mapping is not enough for this job: Chrome currently sends duplicate
        cookie names on www/live because the values have different domain/path
        scopes.  It also sends a different order to the CP shell, the CP publish
        iframe, and ``onvideoapi.kuaishou.com``.  The sequences below come from
        the current re-login Network capture; cookies for unrelated domains
        (for example passport-only ``passToken``) are intentionally *not*
        appended to business requests.

        ``site`` accepts the concrete wire profiles used by the API modules:
        ``www``, ``www_relogin_initial``, ``www_relogin_liked``,
        ``www_relogin_collect``, ``www_relogin_private``,
        ``www_relogin_profile_self_restricted``,
        ``www_relogin_profile_self_ignore_cache`` and
        ``www_relogin_profile_tabs_ignore_cache``,
        ``www_relogin_reco_initial``,
        ``www_relogin_reco_comment_phase_a``,
        ``www_relogin_reco_comment_phase_b``, ``www_relogin_reco_page``,
        ``www_relogin_relation_following``, ``www_relogin_relation_fans``,
        ``www_relogin_search_*``, ``www_relogin_profile_other_*``,
        ``cp_creator``, ``cp``, ``cp_upload``, ``cp_video_submit``,
        ``cp_post_publish_manage``,
        ``cp_atlas``,
        ``onvideo_bootstrap``, ``onvideo``,
        ``live_pass_token_home``, ``live_pass_token_room``,
        ``live_pass_token_profile``, ``live_home_*``, ``live_room_*`` and
        ``live_profile_*``, ``live_logout_*``,
        ``captcha``/``captcha_config``/``captcha_image``/
        ``captcha_verify``,
        ``www_graphql`` and ``www_graphql_detail*``.
        """
        profile = str(site or "www").lower()
        if profile == "www":
            if self._www_cookie_phase == "relogin":
                profile = "www_relogin_initial"
            else:
                profile = ("www_security_refreshed"
                           if self._www_cookie_phase == "security_refreshed"
                           else "www_refreshed" if self._www_cookie_phase == "refreshed"
                           else "www_initial")
        elif profile == "www_relogin":
            profile = "www_relogin_initial"
        elif profile == "www_graphql_detail":
            profile = "www_graphql_detail_initial"
        elif profile == "cp_creator":
            profile = ("cp_creator_refreshed"
                       if self._cp_cookie_phase == "refreshed"
                       else "cp_creator_warmed"
                       if self._cp_cookie_phase == "warmed"
                       else "cp_creator_historical"
                       if self._cp_cookie_phase == "historical"
                       else "cp_creator_initial")
        elif profile == "cp_creator_manage":
            profile = ("cp_creator_manage_refreshed"
                       if self._cp_cookie_phase == "refreshed"
                       else "cp_creator_manage_warmed"
                       if self._cp_cookie_phase == "warmed"
                       else "cp_creator_manage_initial")
        elif profile == "cp" and self._cp_cookie_phase == "historical":
            profile = "cp_historical"
        elif profile == "onvideo":
            profile = ("onvideo_post_bootstrap"
                       if self._onvideo_cookie_phase == "post_bootstrap"
                       else "onvideo_warm")
        elif profile == "www_graphql":
            # 当前 myFollow Network 的 GraphQL 请求有独立的 Cookie 线序：
            # 首批请求把 kwfv1 放在第二个 product 后，后续 webweapon 轮换
            # 则把 kwfv1 放到末尾。不能复用 REST www_initial 序列。
            profile = ("www_graphql_refreshed"
                       if self._www_cookie_phase not in {"initial", "relogin"}
                             else ("www_graphql_relogin_initial" if self._www_cookie_phase == "relogin"
                             else "www_graphql_initial"))
        elif profile in {"captcha", "captcha_config", "captcha_image",
                         "captcha_verify"}:
            # The captcha iframe is a separate path-scoped webweapon page.
            # All of its config/image/verify calls use the same Cookie order;
            # only the request headers differ (notably kww on config).
            profile = "captcha"

        # The creator shell is emitted before its page webweapon instance has
        # refreshed. Reading ``self.cookie`` here would mutate that observable
        # state and move the quartet to the publish-iframe shape.
        if profile in {"www_initial", "www_relogin_initial",
                       "www_relogin_profile_self_initial",
                       "www_relogin_profile_self_restricted", "www_relogin_liked",
                       "www_relogin_collect", "www_relogin_private",
                       "www_relogin_profile_self_ignore_cache",
                       "www_relogin_profile_tabs_ignore_cache",
                       "www_relogin_collection", "www_relogin_reco_initial",
                       "www_relogin_relation_following",
                       "www_relogin_relation_fans",
                       "www_relogin_reco_comment_phase_a",
                       "www_relogin_reco_comment_phase_b", "www_relogin_reco_page",
                       "www_relogin_search_initial", "www_relogin_search_feed_page",
                       "www_relogin_search_user_page_first",
                       "www_relogin_search_user_page_following",
                       "www_relogin_profile_other_initial",
                       "www_relogin_profile_other_page_first",
                       "www_relogin_profile_other_page_following",
                       "cp_creator_initial", "cp_creator_warmed",
                       "cp_creator_refreshed", "cp_creator_historical",
                       "cp_creator_restricted_probe",
                       "cp_creator_manage_initial", "cp_creator_manage_warmed",
                       "cp_creator_manage_refreshed",
                       "cp_post_publish_manage",
                       "www_graphql_initial", "www_graphql_relogin_initial",
                       "www_graphql_relogin_refreshed",
                       "www_graphql_detail_bootstrap",
                       "www_graphql_detail_initial",
                       "www_graphql_detail_video_success",
                       "www_graphql_detail_refreshed",
                       "www_graphql_comment_initial",
                       "www_graphql_subcomment_initial"}:
            # Relogin profiles still need to observe a real webweapon rotation
            # before serializing duplicate path-scoped tickets.  The legacy
            # www_initial profile intentionally keeps its historical behavior.
            values = (self.cookie if (profile.startswith("www_relogin_")
                                     or profile.startswith("www_graphql_relogin_")
                                     or profile.startswith("www_graphql_detail_")
                                     or profile.startswith("www_graphql_comment_"))
                      else dict(self._cookie))
        elif profile in {"live_home_initial", "live_home_current_initial",
                         "live_room_initial",
                         "live_room_assets_initial", "live_profile_initial"}:
            values = dict(self._cookie)
        elif profile == "captcha":
            # ``self.cookie`` refreshes the current base webweapon quartet if
            # needed, but the duplicate product cookie is supplied below as
            # the captcha iframe's own path-scoped value.
            values = self.cookie
        else:
            values = self.cookie

        sequences = {
            # Chrome reqids 1992/1994/1995/1996（2026-08-25 最新普通刷新）。
            "www_initial": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "ktrace-context", "kpn", "kwpsecproductname", "kwssectoken",
                "kwscode", "kwfv1",
            ),
            # Chrome reqids 2006/2007/2010/2011/2014（点赞、收藏、私密）。
            "www_refreshed": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "ktrace-context", "kpn", "kwpsecproductname", "kwssectoken",
                "kwscode", "kwfv1",
            ),
            # 兼容显式旧状态名；最新 Network 与 www_refreshed 同序。
            "www_security_refreshed": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "ktrace-context", "kpn", "kwpsecproductname", "kwssectoken",
                "kwscode", "kwfv1",
            ),
            # Chrome DevTools page-10 ordinary reload reqids 468/470/471/472.
            # The current path-scoped tickets are interleaved exactly as the
            # Cookie header shows: stale code/sec, current code, trace/kpn,
            # second product, current sec, then kwfv1.
            "www_relogin_initial": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwscode", "kwssectoken", "kwscode", "ktrace-context", "kpn",
                "kwpsecproductname", "kwssectoken", "kwfv1",
            ),
            # Current fresh-login Chrome profile reload reqids 74/76/77/78.
            # Both real scoped ticket pairs precede kwfv1; trace/kpn are last.
            "www_relogin_profile_self_initial": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "kwssectoken", "kwscode", "kwssectoken",
                "kwscode", "kwfv1", "ktrace-context", "kpn",
            ),
            # Chrome page-23 latest ordinary reload reqids 468/470/471/472
            # after the same account became restricted.  The second product
            # precedes the first scoped ticket pair; the 174-char kwfv1 then
            # precedes trace/kpn and the second pair.  The page kww remains
            # 218 chars and is independent from the Cookie kwfv1.
            "www_relogin_profile_self_restricted": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "kwssectoken", "kwscode", "kwfv1",
                "ktrace-context", "kpn", "kwssectoken", "kwscode",
            ),
            # Current Chrome reqids 90/91 (liked): the first real scoped pair
            # precedes trace/kpn; kwfv1 separates it from the second pair.
            "www_relogin_liked": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "kwssectoken", "kwscode",
                "ktrace-context", "kpn", "kwfv1", "kwssectoken", "kwscode",
            ),
            # Compatibility alias for the previous combined contract. No
            # current endpoint selects it; collect/private below are distinct.
            "www_relogin_collection": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwssectoken", "kwscode", "ktrace-context", "kpn",
                "kwpsecproductname", "kwssectoken", "kwscode", "kwfv1",
            ),
            # Current Chrome reqids 94/95 (collect): both real scoped ticket
            # pairs precede the final kwfv1.
            "www_relogin_collect": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "kwssectoken", "kwscode",
                "ktrace-context", "kpn", "kwssectoken", "kwscode", "kwfv1",
            ),
            # Current Chrome reqid 98 (private): trace/kpn precede both real
            # scoped ticket pairs; kwfv1 is last.
            "www_relogin_private": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "ktrace-context", "kpn", "kwssectoken",
                "kwscode", "kwssectoken", "kwscode", "kwfv1",
            ),
            # Current explicit ignore-cache profile reload reqids 188/190/191/192.
            # The 174-char kwfv1 precedes both real scoped ticket pairs; trace/kpn
            # are last. This is distinct from ordinary-navigation reqids 74--78.
            "www_relogin_profile_self_ignore_cache": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "kwfv1", "kwssectoken", "kwscode",
                "kwssectoken", "kwscode", "ktrace-context", "kpn",
            ),
            # Current post-ignore-cache UI reqids 203/204/207/208/211. Liked,
            # collect and private all use the same observed order and 174 branch.
            "www_relogin_profile_tabs_ignore_cache": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "ktrace-context", "kpn", "kwssectoken",
                "kwscode", "kwssectoken", "kwscode", "kwfv1",
            ),
            # Current self-profile relation/fol reqids 335/336. The page opens
            # the following tab first; kwfv1 separates the two ticket pairs.
            "www_relogin_relation_following": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "ktrace-context", "kpn", "kwpsecproductname", "kwssectoken",
                "kwscode", "kwfv1", "kwssectoken", "kwscode",
            ),
            # Switching the same panel to fans emits reqids 340/341; kwfv1
            # moves after both ticket pairs.
            "www_relogin_relation_fans": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "ktrace-context", "kpn", "kwpsecproductname", "kwssectoken",
                "kwscode", "kwssectoken", "kwscode", "kwfv1",
            ),
            # Fresh new-reco initial reqids 70/72/73. Both scoped ticket pairs
            # precede kwfv1; trace/kpn are the final two fields.
            "www_relogin_reco_initial": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "kwssectoken", "kwscode", "kwssectoken",
                "kwscode", "kwfv1", "ktrace-context", "kpn",
            ),
            # Fresh new-reco comment phase A, reqids 97/105/111/114.
            "www_relogin_reco_comment_phase_a": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "kwssectoken", "kwscode", "ktrace-context",
                "kpn", "kwssectoken", "kwscode", "kwfv1",
            ),
            # Fresh new-reco comment phase B begins at reqid 119; kwfv1 is
            # between the two scoped ticket pairs.
            "www_relogin_reco_comment_phase_b": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "ktrace-context", "kpn", "kwssectoken",
                "kwscode", "kwfv1", "kwssectoken", "kwscode",
            ),
            # Fresh new-reco feed/hot continuations reqids 195/201/207/213.
            "www_relogin_reco_page": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "ktrace-context", "kpn", "kwssectoken",
                "kwscode", "kwssectoken", "kwscode", "kwfv1",
            ),
            # Current search first screen reqids 980/982/983/984.
            "www_relogin_search_initial": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "kwssectoken", "kwscode", "ktrace-context",
                "kpn", "kwssectoken", "kwscode", "kwfv1",
            ),
            # Fresh re-login search/feed cursor=1..7, reqids
            # 1454/1489/1529/1563/1599/1636/1672.  The scoped product is
            # followed by trace/kpn, then the stale/current ticket pairs.
            "www_relogin_search_feed_page": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "ktrace-context", "kpn", "kwssectoken",
                "kwscode", "kwssectoken", "kwscode", "kwfv1",
            ),
            # Fresh search/user cursor=1..3, reqids 1738/1768/1799, uses the
            # same observed order as search/feed but remains a separate wire
            # profile so a later phase change cannot leak across endpoints.
            "www_relogin_search_user_page_first": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "ktrace-context", "kpn", "kwssectoken",
                "kwscode", "kwssectoken", "kwscode", "kwfv1",
            ),
            # Fresh search/user cursor=4..8, reqids
            # 1832/1863/1895/1927/1958.  kwfv1 moves between the stale and
            # current ticket pairs; this is not interchangeable with feed.
            "www_relogin_search_user_page_following": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "ktrace-context", "kpn", "kwssectoken",
                "kwscode", "kwfv1", "kwssectoken", "kwscode",
            ),
            # Latest ordinary reload, other-user profile reqids
            # 273/275/276/277.  The first ticket pair precedes trace/kpn;
            # the second product and kwfv1 then precede the refreshed pair.
            "www_relogin_profile_other_initial": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwssectoken", "kwscode", "ktrace-context", "kpn",
                "kwpsecproductname", "kwfv1", "kwssectoken", "kwscode",
            ),
            # First continuation reqid 306.  trace/kpn and the second product
            # move before the two ticket pairs; kwfv1 separates those pairs.
            "www_relogin_profile_other_page_first": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "ktrace-context", "kpn", "kwpsecproductname", "kwssectoken",
                "kwscode", "kwfv1", "kwssectoken", "kwscode",
            ),
            # Following continuations reqids 336/349.  Both ticket pairs now
            # precede kwfv1; this is a distinct observed wire phase.
            "www_relogin_profile_other_page_following": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "ktrace-context", "kpn", "kwpsecproductname", "kwssectoken",
                "kwscode", "kwssectoken", "kwscode", "kwfv1",
            ),
            # Chrome reqids 2249--2254/2259：myFollow GraphQL 首批请求。
            # Network 明确保留第二个 kwpsecproductname，且 kpn 在末尾。
            "www_graphql_initial": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "ktrace-context", "kwpsecproductname", "kwfv1", "kwssectoken",
                "kwscode", "kpn",
            ),
            # Chrome reqids 2260/2261：同一关注页 webweapon 轮换后的请求。
            "www_graphql_refreshed": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "ktrace-context", "kwpsecproductname", "kwssectoken", "kwscode",
                "kpn", "kwfv1",
            ),
            # Current fresh /myFollow reqids 33--38.  The second product and
            # trace precede both ticket pairs; kpn/kwfv1 are the final fields.
            "www_graphql_relogin_initial": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "kwssectoken", "kwscode", "ktrace-context",
                "kwssectoken", "kwscode", "kwfv1", "kpn",
            ),
            # Current fresh /myFollow reqids 58--60.  kpn/kwfv1 move between
            # the stale/current ticket pairs after the page rotation.
            "www_graphql_relogin_refreshed": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "ktrace-context", "kwssectoken", "kwscode",
                "kpn", "kwssectoken", "kwscode", "kwfv1",
            ),
            # Fresh Chrome short-video detail direct-navigation reqids
            # 17798--17802/17813.  The active page emitted this exact
            # path-scoped order; visionVideoDetail was not emitted.
            "www_graphql_detail_initial": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "ktrace-context", "kwssectoken", "kwscode",
                "kpn", "kwfv1", "kwssectoken", "kwscode",
            ),
            # Fresh direct-navigation short-video bootstrap requests
            # (Chrome reqids 365--369).  These requests are public and the
            # current browser session has no account-scoped tickets; optional
            # login fields remain in their normal positions when present.
            "www_graphql_detail_bootstrap": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "ktrace-context", "kwpsecproductname", "kwssectoken", "kwscode",
                "kwfv1", "kwssectoken", "kwscode", "kpn",
            ),
            # Current successful ``visionVideoDetail`` request (Chrome
            # reqid=416; JSReverser reqid=43).  After the page webweapon
            # rotation, kpn precedes both scoped ticket pairs and kwfv1 is
            # last.  Account-scoped fields are omitted naturally for a
            # public/anonymous detail request.
            "www_graphql_detail_video_success": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "ktrace-context", "kwpsecproductname", "kpn", "kwssectoken",
                "kwscode", "kwssectoken", "kwscode", "kwfv1",
            ),
            # Fresh visionConfigQuery reqid 17838.  The page-local rotation
            # puts kpn before the refreshed ticket pair and keeps kwfv1
            # before that pair.
            "www_graphql_detail_refreshed": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "ktrace-context", "kwssectoken", "kwscode",
                "kpn", "kwfv1", "kwssectoken", "kwscode",
            ),
            # Chrome reqids 14832/14841/14849/14858 and 15500: commentListQuery
            # keeps kpn before the second scoped product and carries two real
            # kwssectoken/kwscode pairs before the shared kwfv1.
            "www_graphql_comment_initial": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "ktrace-context", "kpn", "kwpsecproductname", "kwssectoken",
                "kwscode", "kwssectoken", "kwscode", "kwfv1",
            ),
            # Current logged-in Chrome reqid 26926 after clicking
            # “查看更多回复”; distinct from root-comment pagination.
            "www_graphql_subcomment_initial": (
                "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
                "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "ktrace-context", "kwssectoken", "kwscode",
                "kpn", "kwfv1", "kwssectoken", "kwscode",
            ),
            # Latest ordinary Chrome refresh reqids 675--677.
            "cp_creator_initial": (
                "did", "wid", "didv", "userId", "bUserId",
                "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "kwssectoken", "kwscode", "kwfv1",
            ),
            # Current restricted-account authority probe, Chrome reqid 2170.
            # It uses the publish-page creator headers but this later cookie
            # creation order; keep it separate from earlier result=1 probes.
            "cp_creator_restricted_probe": (
                "did", "wid", "didv", "userId", "bUserId",
                "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwssectoken", "kwscode", "kwfv1", "kwpsecproductname",
            ),
            "cp_creator_manage_initial": (
                "did", "wid", "didv", "userId", "bUserId",
                "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwssectoken", "kwscode", "kwfv1", "kwpsecproductname",
            ),
            "cp_creator_manage_warmed": (
                "did", "wid", "didv", "userId", "bUserId",
                "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwssectoken", "kwscode", "kwfv1", "kwpsecproductname",
            ),
            "cp_creator_manage_refreshed": (
                "did", "wid", "didv", "userId", "bUserId",
                "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "kwssectoken", "kwscode", "kwfv1",
            ),
            # Latest ordinary Chrome refresh reqids 682--689: the kwscode
            # cookie is created before kwssectoken after the first rotation.
            "cp_creator_warmed": (
                "did", "wid", "didv", "userId", "bUserId",
                "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "kwscode", "kwssectoken", "kwfv1",
            ),
            # Latest ordinary Chrome refresh reqids 691--718.
            "cp_creator_refreshed": (
                "did", "wid", "didv", "userId", "bUserId",
                "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "kwscode", "kwssectoken", "kwfv1",
            ),
            # Preserved only for the separate 2026-08-24 source=NewReco fixture.
            "cp_creator_historical": (
                "did", "wid", "didv", "userId", "bUserId",
                "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwfv1", "kwssectoken", "kwscode", "kwpsecproductname",
            ),
            # Latest ordinary Chrome publish iframe reqids 742--770.
            "cp": (
                "did", "wid", "didv", "userId", "bUserId",
                "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "kwscode", "kwssectoken", "kwfv1",
            ),
            # Chrome reqids 1519--1588 after selecting a local video.
            "cp_upload": (
                "did", "wid", "didv", "userId", "bUserId",
                "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "kwfv1", "kwssectoken", "kwscode",
            ),
            # Current successful private video submit reqid 1316.  It has the
            # upload Cookie order, but remains a named profile so endpoint
            # guards can enforce its own kww/kwfv1 lengths and relationship.
            "cp_video_submit": (
                "did", "wid", "didv", "userId", "bUserId",
                "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "kwfv1", "kwssectoken", "kwscode",
            ),
            # Chrome post-submit manage page reqids 1328/1331.  The order is
            # the refreshed manage-page order, but the page retains the video
            # upload product (kuaishou-vision), so it cannot reuse the normal
            # onvideo-cp creator-manage profile.
            "cp_post_publish_manage": (
                "did", "wid", "didv", "userId", "bUserId",
                "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "kwssectoken", "kwscode", "kwfv1",
            ),
            # Chrome page 12 reqids 124/136--165 after switching to the
            # atlas editor.  The order matches the video-upload profile, but
            # the product emphatically does not: atlas keeps ``onvideo-cp``.
            "cp_atlas": (
                "did", "wid", "didv", "userId", "bUserId",
                "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "kwfv1", "kwssectoken", "kwscode",
            ),
            "cp_historical": (
                "did", "wid", "didv", "userId", "bUserId",
                "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "kwfv1", "kwssectoken", "kwscode",
            ),
            # Chrome reqid 749：host-only token 不存在的首次请求。
            "onvideo_bootstrap": (
                "did", "wid", "didv", "userId", "bUserId",
                "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "kwfv1", "kwssectoken", "kwscode",
            ),
            # Chrome reqid 870：刚由 bootstrap 响应 Set-Cookie 后的下一发。
            "onvideo_post_bootstrap": (
                "did", "wid", "didv", "userId", "bUserId",
                "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "ks_onvideo_token", "kwssectoken",
                "kwscode", "kwfv1",
            ),
            # Latest ordinary Chrome onvideo request reqid 760.
            "onvideo_warm": (
                "did", "wid", "didv", "userId", "bUserId",
                "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "ks_onvideo_token", "kwpsecproductname", "kwscode",
                "kwssectoken", "kwfv1",
            ),
            # Current ordinary live-home reload reqids 4741/4754. The live
            # passport page now emits kwfv1/product before the scoped
            # kwssectoken/kwscode pair; preserve this exact Cookie order.
            "live_pass_token_home": (
                "did", "wid", "didv", "userId", "userId", "bUserId",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "passToken", "kwfv1", "kwpsecproductname", "kwssectoken",
                "kwscode",
            ),
            # Chrome live 房间 getCdns/passToken reqids 8720/8728。
            "live_pass_token_room": (
                "did", "wid", "didv", "userId", "userId", "bUserId",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "passToken", "kwssectoken", "kwscode",
                "kwfv1",
            ),
            # Fresh Chrome live profile getCdns/passToken reqids 17/26.
            "live_pass_token_profile": (
                "did", "wid", "didv", "userId", "userId", "bUserId",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kwpsecproductname", "passToken", "kwssectoken", "kwscode",
                "kwfv1",
            ),
            # Current live-room logout, Chrome reqid 920.  This request is
            # sent to id.kuaishou.com after the page has already narrowed the
            # Cookie line to the passport-visible device/security fields.
            "live_logout_passport_authenticated": (
                "did", "wid", "didv", "bUserId", "kwfv1",
                "kwssectoken", "kwscode", "kwpsecproductname",
            ),
            # Repeating logout after the first successful cleanup (reqid
            # 1064) uses the same fields but the current scoped product moves
            # before the security pair and kwfv1 moves to the end.
            "live_logout_passport_clean": (
                "did", "wid", "didv", "bUserId", "kwpsecproductname",
                "kwssectoken", "kwscode", "kwfv1",
            ),
            # Fresh Chrome live home initial reqids 115--121.
            "live_home_initial": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "userId", "bUserId", "kuaishou.web.cp.api_st",
                "kuaishou.web.cp.api_ph", "kuaishou.live.bfb1s", "userId",
                "kuaishou.live.web_st", "kuaishou.live.web_ph", "kwfv1",
                "kwpsecproductname", "kwssectoken", "kwscode",
            ),
            # Direct live-page passToken/getCdns before CP is ever visited.
            "live_pass_token_home_direct": (
                "did", "wid", "didv", "bUserId", "kwpsecproductname", "userId",
                "userId", "passToken", "kwfv1", "kwssectoken", "kwscode",
            ),
            "live_pass_token_room_direct": (
                "did", "wid", "didv", "bUserId", "kwpsecproductname", "userId",
                "userId", "passToken", "kwfv1", "kwssectoken", "kwscode",
            ),
            "live_pass_token_profile_direct": (
                "did", "wid", "didv", "bUserId", "kwpsecproductname", "userId",
                "userId", "passToken", "kwfv1", "kwssectoken", "kwscode",
            ),
            # Current ordinary reload userLogin reqid 4770 moves the scoped
            # product before kwssectoken/kwscode and keeps kwfv1 last.
            "live_home_login": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "userId", "bUserId", "kuaishou.web.cp.api_st",
                "kuaishou.web.cp.api_ph", "kuaishou.live.bfb1s", "userId",
                "kuaishou.live.web_st", "kuaishou.live.web_ph",
                "kwpsecproductname", "kwssectoken", "kwscode", "kwfv1",
            ),
            # First mobile/passToken live userLogin may not yet have web_ph;
            # the response establishes it for the authenticated phases.
            "live_home_login_bootstrap": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "userId", "bUserId", "kuaishou.web.cp.api_st",
                "kuaishou.web.cp.api_ph", "kuaishou.live.bfb1s", "userId",
                "kuaishou.live.web_st", "kwpsecproductname", "kwssectoken",
                "kwscode", "kwfv1",
            ),
            "live_home_current_initial": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "bUserId", "kuaishou.live.bfb1s", "kwpsecproductname", "userId",
                "userId", "kuaishou.live.web_st", "kuaishou.live.web_ph",
                "kwssectoken", "kwscode", "kwfv1",
            ),
            "live_home_current_login": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "bUserId", "kuaishou.live.bfb1s", "kwpsecproductname", "userId",
                "userId", "kuaishou.live.web_st", "kuaishou.live.web_ph",
                "kwssectoken", "kwscode", "kwfv1",
            ),
            "live_home_current_login_bootstrap": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "bUserId", "kuaishou.live.bfb1s", "kwpsecproductname", "userId",
                "userId", "kuaishou.live.web_st", "kwssectoken", "kwscode", "kwfv1",
            ),
            "live_home_current_authenticated_1": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "bUserId", "kuaishou.live.bfb1s", "kwpsecproductname", "userId",
                "userId", "kwssectoken", "kwscode", "kwfv1",
                "kuaishou.live.web_st", "kuaishou.live.web_ph",
            ),
            "live_home_current_authenticated_2": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "bUserId", "kuaishou.live.bfb1s", "kwpsecproductname", "userId",
                "userId", "kwfv1", "kuaishou.live.web_st", "kuaishou.live.web_ph",
                "kwssectoken", "kwscode",
            ),
            "live_home_current_authenticated_3": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "bUserId", "kuaishou.live.bfb1s", "kwpsecproductname", "userId",
                "userId", "kuaishou.live.web_st", "kuaishou.live.web_ph",
                "kwssectoken", "kwscode", "kwfv1",
            ),
            # Fresh Chrome live home first pay after userLogin reqid 130.
            "live_home_authenticated_1": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "userId", "bUserId", "kuaishou.web.cp.api_st",
                "kuaishou.web.cp.api_ph", "kuaishou.live.bfb1s", "userId",
                "kuaishou.live.web_st", "kuaishou.live.web_ph",
                "kwpsecproductname", "kwssectoken", "kwscode", "kwfv1",
            ),
            # Fresh Chrome live home later userinfo/pay/category reqids
            # 131/138/304.
            "live_home_authenticated_2": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "userId", "bUserId", "kuaishou.web.cp.api_st",
                "kuaishou.web.cp.api_ph", "kuaishou.live.bfb1s", "userId",
                "kwpsecproductname", "kwssectoken", "kwscode", "kwfv1",
                "kuaishou.live.web_st", "kuaishou.live.web_ph",
            ),
            # Fresh Chrome live home delayed userFollowCount reqids 440/446.
            "live_home_delayed": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "userId", "bUserId", "kuaishou.web.cp.api_st",
                "kuaishou.web.cp.api_ph", "kuaishou.live.bfb1s", "userId",
                "kwpsecproductname", "kuaishou.live.web_st",
                "kuaishou.live.web_ph", "kwfv1", "kwssectoken", "kwscode",
            ),
            # Chrome live 房间 reqids 8729--8735。
            "live_room_initial": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "userId", "bUserId", "kuaishou.web.cp.api_st",
                "kuaishou.web.cp.api_ph", "kuaishou.live.bfb1s", "userId",
                "kwpsecproductname", "kuaishou.live.web_st",
                "kuaishou.live.web_ph", "kwssectoken", "kwscode", "kwfv1",
            ),
            "live_room_current_initial": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "bUserId", "kuaishou.live.bfb1s", "kwpsecproductname", "userId",
                "userId", "kwfv1", "kwssectoken", "kwscode",
                "kuaishou.live.web_st", "kuaishou.live.web_ph",
            ),
            # Chrome 151 room reload reqids 912/913 (2026-08-27).  The page's
            # bootstrap emoji dictionaries use a narrower path-scoped line:
            # no CP tickets, one userId, kwfv1 before the security pair, and
            # the PCLive product last.
            "live_room_assets_initial": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "bUserId", "kuaishou.live.bfb1s", "userId",
                "kuaishou.live.web_st", "kuaishou.live.web_ph", "kwfv1",
                "kwssectoken", "kwscode", "kwpsecproductname",
            ),
            # Latest active-room Chrome userLogin/pay reqids 363/365/366。
            "live_room_login": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "userId", "bUserId", "kuaishou.web.cp.api_st",
                "kuaishou.web.cp.api_ph", "kuaishou.live.bfb1s", "userId",
                "kwpsecproductname", "kuaishou.live.web_st",
                "kuaishou.live.web_ph", "kwssectoken", "kwscode", "kwfv1",
            ),
            "live_room_login_bootstrap": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv", "userId",
                "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                "kuaishou.live.bfb1s", "userId", "kwpsecproductname",
                "kuaishou.live.web_st", "kwssectoken", "kwscode", "kwfv1",
            ),
            "live_room_current_login": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "bUserId", "kuaishou.live.bfb1s", "kwpsecproductname", "userId",
                "userId", "kwssectoken", "kwscode", "kuaishou.live.web_st",
                "kuaishou.live.web_ph", "kwfv1",
            ),
            "live_room_current_login_bootstrap": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "bUserId", "kuaishou.live.bfb1s", "kwpsecproductname", "userId",
                "userId", "kwssectoken", "kwscode", "kuaishou.live.web_st", "kwfv1",
            ),
            # Latest active-room authenticated userinfo/pay/recall/ws/gift/panel
            # and delayed follow requests keep the same order.
            "live_room_authenticated": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "userId", "bUserId", "kuaishou.web.cp.api_st",
                "kuaishou.web.cp.api_ph", "kuaishou.live.bfb1s", "userId",
                "kwpsecproductname", "kuaishou.live.web_st",
                "kuaishou.live.web_ph", "kwssectoken", "kwscode", "kwfv1",
            ),
            "live_room_current_authenticated": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "bUserId", "kuaishou.live.bfb1s", "kwpsecproductname", "userId",
                "userId", "kwfv1", "kuaishou.live.web_st", "kuaishou.live.web_ph",
                "kwssectoken", "kwscode",
            ),
            # The live userLogout call is narrower than ordinary room APIs:
            # no CP tickets, one userId, and no duplicate userId.  Chrome
            # reqid 922 still sends the live path-scoped session cookies even
            # though the preceding passport logout has completed.
            "live_room_logout_authenticated": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "bUserId", "kuaishou.live.bfb1s", "userId",
                "kuaishou.live.web_st", "kuaishou.live.web_ph",
                "kwpsecproductname", "kwssectoken", "kwscode", "kwfv1",
            ),
            # Chrome reqid 1066: a second logout after the session cookies
            # have already been deleted.  Unknown partially-clean states are
            # intentionally not represented by a profile.
            "live_room_logout_clean": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "bUserId", "kuaishou.live.bfb1s", "kwpsecproductname",
                "kwssectoken", "kwscode", "kwfv1",
            ),
            # Fresh Chrome /profile/3xxtfm5hgbcdd2c reqids 27--36.
            "live_profile_initial": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "userId", "bUserId", "kuaishou.web.cp.api_st",
                "kuaishou.web.cp.api_ph", "kuaishou.live.bfb1s", "userId",
                "kwpsecproductname", "kuaishou.live.web_st",
                "kuaishou.live.web_ph", "kwssectoken", "kwscode", "kwfv1",
            ),
            # Fresh Chrome profile userLogin/pay reqids 41/45.
            "live_profile_login": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "userId", "bUserId", "kuaishou.web.cp.api_st",
                "kuaishou.web.cp.api_ph", "kuaishou.live.bfb1s", "userId",
                "kwpsecproductname", "kuaishou.live.web_st",
                "kuaishou.live.web_ph", "kwssectoken", "kwscode", "kwfv1",
            ),
            # Fresh Chrome profile interestlist/pay reqids 1958/1960 still
            # use the login-order Cookie before the next userinfo rotation.
            "live_profile_authenticated_1": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "userId", "bUserId", "kuaishou.web.cp.api_st",
                "kuaishou.web.cp.api_ph", "kuaishou.live.bfb1s", "userId",
                "kwpsecproductname", "kuaishou.live.web_st",
                "kuaishou.live.web_ph", "kwssectoken", "kwscode", "kwfv1",
            ),
            # Fresh Chrome profile userinfo/interest/pay reqids 49/55/57.
            "live_profile_authenticated": (
                "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
                "userId", "bUserId", "kuaishou.web.cp.api_st",
                "kuaishou.web.cp.api_ph", "kuaishou.live.bfb1s", "userId",
                "kwpsecproductname", "kwssectoken", "kwscode", "kwfv1",
                "kuaishou.live.web_st", "kuaishou.live.web_ph",
            ),
            # Current Chrome captcha config/image requests (reqids 1232,
            # 1238/1239) keep a path-scoped verification product before the
            # base www product.  The same line is used by verify; kww is a
            # request-header concern and is intentionally not represented in
            # this Cookie contract.
            "captcha": (
                "did", "wid", "kwpsecproductname", "didv", "bUserId",
                "kwpsecproductname", "kwssectoken", "kwscode", "kwfv1",
            ),
        }
        sequence = sequences.get(profile, sequences["www_initial"])

        quartet = ("kwpsecproductname", "kwfv1", "kwssectoken", "kwscode")
        stale = self._wire_cookie_history[-1] if self._wire_cookie_history else None
        # 旧页面曾观察到 stale quartet 整组重复；当前最新 profile 导航没有。
        # 只给显式历史 profile 保留该形状，避免把旧证据混入当前请求。
        stale_map = (dict(zip(quartet, stale))
                     if stale and profile == "www_historical_duplicate" else {})
        occurrences = {}
        out = []
        for key in sequence:
            value = values.get(key)
            if value in (None, ""):
                continue
            occurrences[key] = occurrences.get(key, 0) + 1
            if profile == "captcha" and key == "kwpsecproductname":
                # The iframe sets ``verification-captcha`` on its own path;
                # the second product is the parent www page's
                # ``kuaishou-vision`` cookie.  A mapping cannot represent
                # duplicate names, so encode the observed pair explicitly.
                value = ("verification-captcha" if occurrences[key] == 1
                         else (self._cookie.get("kwpsecproductname")
                               or "kuaishou-vision"))
            # 详情页同时保留两组 path-scoped 安全票据：第一次出现的
            # kwssectoken/kwscode 是实际观察到的旧值，第二次是刷新后的值。
            # 只有 auth.cookie() 真正观察到 quartet 变化后才使用 history；
            # 未发生轮换时不凭空制造旧字段。
            if (stale and (profile in {"www_graphql_detail_bootstrap",
                                       "www_graphql_detail_initial",
                                       "www_graphql_detail_video_success",
                                       "www_graphql_detail_refreshed",
                                       "www_graphql_comment_initial",
                                       "www_graphql_subcomment_initial",
                                       "www_graphql_relogin_initial",
                                       "www_graphql_relogin_refreshed"}
                           or profile in {"www_relogin_initial",
                                          "www_relogin_profile_self_initial",
                                          "www_relogin_profile_self_restricted",
                                          "www_relogin_liked",
                                           "www_relogin_collection",
                                           "www_relogin_collect",
                                           "www_relogin_private",
                                          "www_relogin_profile_self_ignore_cache",
                                          "www_relogin_profile_tabs_ignore_cache",
                                          "www_relogin_relation_following",
                                          "www_relogin_relation_fans",
                                          "www_relogin_reco_initial",
                                          "www_relogin_reco_comment_phase_a",
                                          "www_relogin_reco_comment_phase_b",
                                          "www_relogin_reco_page",
                                          "www_relogin_search_initial",
                                          "www_relogin_search_feed_page",
                                          "www_relogin_search_user_page_first",
                                          "www_relogin_search_user_page_following",
                                          "www_relogin_profile_other_initial",
                                          "www_relogin_profile_other_page_first",
                                          "www_relogin_profile_other_page_following"})
                    and key in {"kwssectoken", "kwscode"}
                    and occurrences[key] % 2 == 1):
                value = dict(zip(quartet, stale)).get(key, value)
            if (stale and profile.startswith(("www_relogin_", "www_graphql_"))
                    and key == "kwpsecproductname"
                    and occurrences[key] == 2
                    and stale[0]):
                # Current cross-tab Network can retain a path-scoped PCLive
                # product after a live page refresh while the base www cookie
                # is already back to kuaishou-vision. Preserve that observed
                # second occurrence only when a real site switch created it.
                value = stale[0]
            if stale_map:
                if key == "kwpsecproductname":
                    # First scoped product is the stale page value; the second
                    # is the current cookie value, matching the refresh capture.
                    value = (stale_map[key] if occurrences[key] == 1 else value)
                elif key in {"kwfv1", "kwssectoken", "kwscode"}:
                    value = stale_map.get(key, value)
            out.append(f"{key}={value}")

        if stale_map:
            # A real SDK refresh can leave the old scoped quartet and append
            # the new one. Do this only after a refresh was actually observed.
            for key in ("kwfv1", "kwssectoken", "kwscode"):
                if values.get(key):
                    out.append(f"{key}={values[key]}")
        return "; ".join(out)

    def prepare_captcha_context(self, iframe_url: str) -> dict:
        """Run the captcha iframe's independent exact webweapon bootstrap.

        The iframe starts a second SDK instance with productName
        ``verification-captcha``.  It freezes the current ``kwfv1`` as its
        page ``kww``, then executes that ticket's exact ``fpUrl``/``signUrl``
        and overwrites the root-domain ``kwfv1/kws*`` cookies.  The captcha
        product cookie remains path-scoped and coexists with the base www
        product, which is why :meth:`cookie_header` has a duplicate-name
        ``captcha`` profile.

        The parent page's frozen ``kww`` is deliberately preserved when the
        newly issued captcha cookies are merged back into this auth session.
        """
        iframe_url = str(iframe_url or "")
        if not iframe_url.startswith("https://captcha.zt.kuaishou.com/iframe/"):
            raise ValueError("验证码 iframe URL 不属于当前浏览器合同，拒绝 bootstrap")

        current = self.cookie
        snapshot = str(current.get("kwfv1") or "")
        if not snapshot:
            raise RuntimeError("验证码 iframe 初始化前缺少当前 kwfv1，拒绝降级")
        signer = KwwSigner(
            snapshot,
            href=iframe_url,
            did=self.did,
            product_name=PRODUCT_NAME_CAPTCHA,
            # The captcha page receives a fresh server secToken and executes
            # the exact signUrl even when the parent has a valid ticket pair.
            kwscode="",
            kwssectoken="",
            kww_snapshot=snapshot,
            kwfcv1="",
        )
        issued = signer.cookies()
        if issued.get("kwpsecproductname") != PRODUCT_NAME_CAPTCHA:
            raise RuntimeError("验证码 webweapon productName 漂移，拒绝继续")
        if len(issued.get("kwssectoken", "")) != 88:
            raise RuntimeError("验证码 webweapon secToken 长度偏离浏览器合同")
        code = issued.get("kwscode", "")
        if len(code) != 64 or any(ch not in "0123456789abcdef" for ch in code):
            raise RuntimeError("验证码 exact signUrl 未产出 64 位小写 hex kwscode")

        # Root-domain security cookies are now the captcha SDK's values.  Do
        # not replace the base path-scoped product cookie or the parent page's
        # independent kww snapshot.
        self.update_cookies({key: issued[key] for key in
                             ("kwfv1", "kwssectoken", "kwscode")})
        # Materialize the freshly issued webweapon cookies before serializing
        # the captcha Cookie header; the property call is intentionally kept
        # for its side effect.
        self.cookie
        cookie_line = self.cookie_header("captcha")
        pairs = [tuple(part.split("=", 1)) for part in cookie_line.split("; ")
                 if part and "=" in part]
        expected_keys = (
            "did", "wid", "kwpsecproductname", "didv", "bUserId",
            "kwpsecproductname", "kwssectoken", "kwscode", "kwfv1",
        )
        if tuple(key for key, _ in pairs) != expected_keys:
            raise RuntimeError(
                "验证码 Cookie 字段缺失或顺序偏离当前 Chrome，拒绝出网: "
                f"actual={tuple(key for key, _ in pairs)}")
        grouped = {}
        for key, value in pairs:
            grouped.setdefault(key, []).append(value)
        if grouped.get("kwpsecproductname") != [
                PRODUCT_NAME_CAPTCHA, PRODUCT_NAME_WWW]:
            raise RuntimeError("验证码重复 product Cookie 值/顺序漂移，拒绝出网")
        if ([len(value) for value in grouped.get("kwssectoken", [])] != [88]
                or [len(value) for value in grouped.get("kwscode", [])] != [64]
                or [len(value) for value in grouped.get("kwfv1", [])]
                not in ([174], [218])):
            raise RuntimeError("验证码 webweapon Cookie 长度偏离当前官方脚本输出")
        # gdfp's document.cookie parser collapses the duplicate product to
        # the later base value, but otherwise retains only cookies visible to
        # the captcha path.  Passing the full www auth mapping would leak
        # kpf/clientid/userId/STS/CP fields that are absent from reqids
        # 1251/1256 module_section.7.
        telemetry_cookies = {}
        for key, value in pairs:
            telemetry_cookies[key] = value
        weapon_state = signer.export_state()
        return {
            "kww": signer.sign(),
            "cookies": telemetry_cookies,
            "cookie_header": cookie_line,
            "script_urls": [url for url in
                            (weapon_state.get("fp_url"),
                             weapon_state.get("sign_url")) if url],
            "webweapon": weapon_state,
        }

    @cookie.setter
    def cookie(self, value):
        self._cookie = dict(value or {})

    def update_cookies(self, issued: dict):
        """并入服务端新下发的 cookie（换票、续期都走这里）。

        ``kwfv1`` 只更新当前 Cookie；页面已冻结的 ``kww`` 必须保留。

        :param issued: 形如 ``{"kuaishou.live.web_st": "...", "passToken": "..."}``。
        """
        if not issued:
            return self
        self._cookie.update({k: str(v) for k, v in issued.items() if v is not None})
        # 派生字段要跟着走：登录换票时 userId 只出现在这里，不刷新的话
        # auth.userId 一直是 None，需要它的接口（profile/feed 等）就无从下手。
        self.userId = self._cookie.get("userId") or self._cookie.get("userid") or self.userId
        self._uid = None
        self.did = self._cookie.get("did", "") or self.did
        self.cp_api_ph = self._cookie.get("kuaishou.web.cp.api_ph", "") or self.cp_api_ph
        previous_kww = ""
        if self._kww_signer is not None:
            previous_kww = self._kww_signer.export_state().get("kww_snapshot", "")
        if issued.get("kwfv1"):
            self.kwfv1 = str(issued["kwfv1"])
        if issued.get("ks_onvideo_token") and self._onvideo_cookie_phase == "bootstrap":
            self._onvideo_cookie_phase = "post_bootstrap"
        product = self._cookie.get("kwpsecproductname", DEFAULT_PRODUCT)
        href, product = _site_defaults(product)
        self._kww_signer = KwwSigner(
            self.kwfv1,
            href=href,
            did=self.did,
            product_name=product,
            kwscode=self._cookie.get("kwscode", ""),
            kwssectoken=self._cookie.get("kwssectoken", ""),
            kww_snapshot=previous_kww,
            kwfcv1=self.kwfcv1,
        )
        self.kww_snapshot = previous_kww
        self.cookie_str = "; ".join(
            f"{key}={value}" for key, value in self._cookie.items())
        return self

    def apply_live_logout(self, *, passport: bool = False, live: bool = False):
        """Apply only the cookie deletions proven by the current logout responses.

        The live application performs passport logout first and ``userLogout``
        second.  Their ``Set-Cookie`` headers delete different scoped names;
        callers therefore apply each half only after that response matches its
        retained contract.  Device identifiers and the JS-generated webweapon
        quartet deliberately survive, exactly as they do in Chrome.
        """
        if passport:
            for key in ("userId", "userid", "passToken"):
                self._cookie.pop(key, None)
        if live:
            for key in ("userId", "userid", "kuaishou.live.web_st",
                        "kuaishou.live.web_ph"):
                self._cookie.pop(key, None)
        self.userId = self._cookie.get("userId") or self._cookie.get("userid")
        self._uid = None
        self.cookie_str = "; ".join(
            f"{key}={value}" for key, value in self._cookie.items())
        if live:
            self._live_cookie_phase["room"] = "initial"
            self._live_cookie_phase["home"] = "initial"
            self._live_home_login_pay_count = 0
            self._live_room_login_pay_count = 0
        return self

    def _remember_current_quartet(self):
        """Retain a real pre-switch scoped quartet for duplicate Cookie lines."""
        quartet = ("kwpsecproductname", "kwfv1", "kwssectoken", "kwscode")
        current = tuple(self._cookie.get(key, "") for key in quartet)
        if all(current) and current not in self._wire_cookie_history:
            self._wire_cookie_history.append(current)
        return current

    def advance_cp_cookie_phase(self, phase: str = "refreshed"):
        """推进 CP 外壳的 current-Network Cookie 线序阶段。"""
        if phase not in {"initial", "warmed", "refreshed", "historical"}:
            raise ValueError(f"unknown CP cookie phase: {phase}")
        self._cp_cookie_phase = phase
        return self

    def set_cp_ignore_cache(self, enabled: bool = True):
        """Mark the CP session as an explicit DevTools ignore-cache flow."""
        self._cp_ignore_cache = bool(enabled)
        return self

    def advance_www_cookie_phase(self, phase: str = "refreshed", *, ignore_cache: bool = False):
        """推进 www 页面 Cookie 线序阶段。

        ``relogin`` 表示当前扫码后完成文档引导的会话；其首屏、liked、
        collect、private 由 API 路径分别选择显式 profile。
        """
        if phase not in {"initial", "relogin", "refreshed", "security_refreshed"}:
            raise ValueError(f"unknown www cookie phase: {phase}")
        self._www_cookie_phase = phase
        self._www_ignore_cache = bool(ignore_cache)
        return self

    def mark_account_restricted(self, restricted: bool = True):
        """记录服务端已经明确返回的账号限制状态，不从页面或代码猜测。"""
        value = bool(restricted)
        self._www_account_restricted = value
        self._cp_account_restricted = value
        return self

    def advance_live_cookie_phase(self, context: str, phase: str):
        """Advance a browser-observed live home/room/profile Cookie stage."""
        context = str(context or "").lower()
        phase = str(phase or "").lower()
        if context not in {"home", "room", "profile"}:
            raise ValueError(f"unknown live context: {context}")
        allowed = {
            "home": {"initial", "login", "authenticated_1", "authenticated_2",
                     "authenticated_3"},
            "room": {"initial", "login", "authenticated"},
            "profile": {"initial", "login", "authenticated_1", "authenticated"},
        }[context]
        if phase not in allowed:
            raise ValueError(f"unknown live {context} cookie phase: {phase}")
        self._live_cookie_phase[context] = phase
        return self

    @staticmethod
    def _new_nonzero_hex(byte_length: int) -> str:
        """Return a lowercase non-zero Sentry/W3C identifier."""
        while True:
            value = secrets.token_hex(byte_length)
            if int(value, 16):
                return value

    def begin_live_page_transaction(self, referer: str, trace_id: str = None) -> str:
        """Start/reset the Sentry transaction for one live page navigation.

        Current Chrome Network shows that all instrumented requests from one
        ordinary page load share the same 32-hex trace id while each request
        has its own 16-hex span id. A reload of the same URL starts a new trace.
        """
        page = str(referer or "")
        if not page.startswith("https://live.kuaishou.com/"):
            raise ValueError(f"invalid live Sentry page referer: {referer!r}")
        value = self._new_nonzero_hex(16) if trace_id is None else str(trace_id)
        if (len(value) != 32 or value.lower() != value
                or any(ch not in "0123456789abcdef" for ch in value)
                or not int(value, 16)):
            raise ValueError("live Sentry trace_id must be 32 lowercase non-zero hex chars")
        self._live_sentry_transactions[page] = {
            "trace_id": value,
            "span_ids": set(),
        }
        return value

    def next_live_sentry_ids(self, referer: str) -> tuple:
        """Return ``(page trace id, fresh request span id)`` for live fetch/XHR."""
        page = str(referer or "")
        state = self._live_sentry_transactions.get(page)
        if state is None:
            # Direct API use has no separately observable navigation call. Its
            # first instrumented request is the observable beginning of the
            # same page transaction; getCdns explicitly resets it when the full
            # browser bootstrap chain is used.
            self.begin_live_page_transaction(page)
            state = self._live_sentry_transactions[page]
        while True:
            span_id = self._new_nonzero_hex(8)
            if span_id not in state["span_ids"]:
                state["span_ids"].add(span_id)
                return state["trace_id"], span_id

    def use_site(self, site: str):
        """切换当前 webweapon 会话到一个已抓包确认的站点产品。

        www / CP / live 使用同一设备指纹 ``kwfv1``，但 SDK 计算短期
        ``kwscode`` 时会把站点 product 与 href 一并纳入明文。浏览器切换到
        创作者中心后会把 ``kwpsecproductname`` 变为 ``onvideo-cp``；不能继续
        用 www 的 product 生成 CP 请求。
        """
        value = str(site or "").lower()
        previous_product = self._cookie.get("kwpsecproductname", "")
        if "cp.kuaishou.com" in value or value in {"cp", PRODUCT_NAME_CP}:
            product = PRODUCT_NAME_CP
            self._cp_cookie_phase = "initial"
        elif "live.kuaishou.com" in value or value in {"live", PRODUCT_NAME_LIVE}:
            product = PRODUCT_NAME_LIVE
        else:
            product = PRODUCT_NAME_WWW
            self._www_cookie_phase = "initial"
        if previous_product and previous_product != product:
            # Webweapon security cookies are path/product scoped.  A CP page's
            # ``onvideo-cp`` quartet must not become the stale duplicate of a
            # later www request (and vice versa); doing so produces a mixed
            # ``kwpsecproductname`` line that Chrome never sends.  Same-site
            # rotations are still recorded by ``cookie`` when the signer
            # actually changes, so this only clears cross-site history.
            self._wire_cookie_history = []
        self._cookie["kwpsecproductname"] = product
        if product == PRODUCT_NAME_LIVE:
            self._live_cookie_phase = {
                "home": "initial", "room": "initial", "profile": "initial"}
            self._live_home_login_pay_count = 0
            self._live_room_login_pay_count = 0
        href, product = _site_defaults(product)
        # 新页面从导航开始时的当前 Cookie/localStorage 值建立自己的快照。
        page_snapshot = self.kwfv1 or self._cookie.get("kwfv1", "")
        self._kww_signer = KwwSigner(
            self.kwfv1,
            href=href,
            did=self.did,
            product_name=product,
            kwscode=self._cookie.get("kwscode", ""),
            kwssectoken=self._cookie.get("kwssectoken", ""),
            kww_snapshot=page_snapshot,
            kwfcv1=self.kwfcv1,
        )
        self.kww_snapshot = page_snapshot
        self.cookie_str = "; ".join(f"{k}={v}" for k, v in self._cookie.items())
        return self

    def use_cp_upload(self):
        """切换到当前 Chrome 选择视频后的 CP 上传 webweapon 上下文。

        上传仍位于 CP publish URL，但当前 Network 的 product 已从
        ``onvideo-cp`` 变为 ``kuaishou-vision``。因此既不能复用普通 CP
        product，也不能调用 ``use_site('www')`` 后错误使用 new-reco href。
        """
        product = PRODUCT_NAME_WWW
        previous_state = (self._kww_signer.export_state()
                          if self._kww_signer is not None else {})
        if self._cookie.get("kwpsecproductname") != product:
            self._remember_current_quartet()
        self._cookie["kwpsecproductname"] = product
        # Selecting a video changes the scoped product inside the same CP page;
        # reqid 1316 proves the page kww can stay at 174 while Cookie kwfv1 has
        # rotated to 218. Preserve an existing CP-page snapshot.
        page_snapshot = (previous_state.get("kww_snapshot", "")
                         if previous_state.get("href") == HREF_CP
                         else self.kwfv1 or self._cookie.get("kwfv1", ""))
        # The current verified upload contract is deliberately dual-generation:
        # page ``kww`` stays at 174 while the upload Cookie ``kwfv1`` is the
        # 218-character output of CP's 0.1.1 kwf.  A fresh QR session starts at
        # the low generation, so perform one exact CP webweapon bootstrap when
        # entering the video-upload context.  The high counter is an explicit
        # captured-generation boundary, never a length pad/truncate operation.
        if (getattr(self, "_live_bootstrap_enabled", False)
                and len(self.kwfv1 or "") != 218):
            upload_signer = KwwSigner(
                "", href=HREF_CP, did=self.did,
                # Fetch CP's 0.1.1 fpUrl while the resulting Cookie product is
                # switched back to kuaishou-vision below for the upload wire.
                product_name=PRODUCT_NAME_CP,
                kwscode="", kwssectoken="",
                kww_snapshot=page_snapshot, kwfcv1="999",
            )
            upload_signer._try_bootstrap()
            upload_signer.product_name = product
            self._kww_signer = upload_signer
            generated = upload_signer.cookies()
            self.kwfv1 = upload_signer.kwfv1
            self.kwfcv1 = upload_signer.kwfcv1
            for key in ("kwfv1", "kwssectoken", "kwscode"):
                if generated.get(key):
                    self._cookie[key] = generated[key]
        else:
            self._kww_signer = KwwSigner(
                self.kwfv1,
                href=HREF_CP,
                did=self.did,
                product_name=product,
                kwscode=self._cookie.get("kwscode", ""),
                kwssectoken=self._cookie.get("kwssectoken", ""),
                kww_snapshot=page_snapshot,
                kwfcv1=self.kwfcv1,
            )
        self.kww_snapshot = page_snapshot
        self.cookie_str = "; ".join(f"{k}={v}" for k, v in self._cookie.items())
        return self

    def use_cp_atlas(self):
        """切换到当前 Chrome 图文编辑/上传的 webweapon 上下文。

        2026-08-25 page 12 Network 明确表明，图文与视频上传虽然使用相同的
        Cookie 字段顺序，却使用不同 product：图文保持 ``onvideo-cp``，视频才是
        ``kuaishou-vision``。两者都位于当前 CP publish URL，不能只看路径后缀合并。
        """
        product = PRODUCT_NAME_CP
        previous_state = (self._kww_signer.export_state()
                          if self._kww_signer is not None else {})
        if self._cookie.get("kwpsecproductname") != product:
            self._remember_current_quartet()
        self._cookie["kwpsecproductname"] = product
        page_snapshot = (previous_state.get("kww_snapshot", "")
                         if previous_state.get("href") == HREF_CP
                         else self.kwfv1 or self._cookie.get("kwfv1", ""))
        self._kww_signer = KwwSigner(
            self.kwfv1,
            href=HREF_CP,
            did=self.did,
            product_name=product,
            kwscode=self._cookie.get("kwscode", ""),
            kwssectoken=self._cookie.get("kwssectoken", ""),
            kww_snapshot=page_snapshot,
            kwfcv1=self.kwfcv1,
        )
        self.kww_snapshot = page_snapshot
        self.cookie_str = "; ".join(f"{k}={v}" for k, v in self._cookie.items())
        return self

    # 兼容抖音仓库拼写（perepare_auth）习惯，提供同名别名
    perepare_auth = prepare_auth

    @property
    def kww(self) -> str:
        """请求头 ``kww`` 的页面本地 webweapon 值。

        当前 Chrome 跨标签抓包里它可与共享 Cookie ``kwfv1`` 不同；调用方必须
        分别序列化 header 与 Cookie，不能用其中一个覆盖另一个。
        """
        if self._kww_signer is None:
            self.prepare_auth(self.cookie_str or "")
        self.kww_snapshot = self._kww_signer.sign()
        self.kwfcv1 = str(getattr(self._kww_signer, "kwfcv1", self.kwfcv1) or "")
        return self.kww_snapshot

    def export_state(self) -> dict:
        """导出程序自持登录态，包括不能从 Cookie 反推的页面 ``kww``。"""
        return {
            "version": 2,
            "cookies": dict(self._cookie),
            "wire_cookie_history": [list(item) for item in self._wire_cookie_history],
            "phases": {
                "www": self._www_cookie_phase,
                "cp": self._cp_cookie_phase,
                "onvideo": self._onvideo_cookie_phase,
                "live": dict(self._live_cookie_phase),
                "live_home_login_pay_count": self._live_home_login_pay_count,
                "live_room_login_pay_count": self._live_room_login_pay_count,
            },
            "account_restricted": {
                "www": bool(self._www_account_restricted),
                "cp": bool(self._cp_account_restricted),
            },
            "webweapon": (self._kww_signer.export_state()
                          if self._kww_signer is not None else None),
            "userId": self.userId,
            "cp_api_ph": self.cp_api_ph,
        }

    def prepare_state(self, state: dict):
        """恢复 :meth:`export_state`；不复制浏览器 Cookie，也不丢页面快照。"""
        self._last_login_result = None
        state = dict(state or {})
        self._live_bootstrap_enabled = False
        self._cookie = {str(k): str(v) for k, v in (state.get("cookies") or {}).items()}
        self.cookie_str = "; ".join(f"{k}={v}" for k, v in self._cookie.items())
        self._wire_cookie_history = [tuple(item) for item in
                                     (state.get("wire_cookie_history") or [])]
        phases = state.get("phases") or {}
        self._www_cookie_phase = phases.get("www", "initial")
        self._cp_cookie_phase = phases.get("cp", "initial")
        self._onvideo_cookie_phase = phases.get("onvideo", "bootstrap")
        restricted = state.get("account_restricted") or {}
        self._www_account_restricted = bool(restricted.get("www", False))
        self._cp_account_restricted = bool(restricted.get("cp", False))
        self._cp_publish_authority_response = None
        self._cp_last_video_finish = None
        self._cp_publish_refresh_ids = None
        self._live_cookie_phase = dict(
            phases.get("live") or {
                "home": "initial", "room": "initial", "profile": "initial"})
        self._live_cookie_phase.setdefault("profile", "initial")
        self._live_home_login_pay_count = int(
            phases.get("live_home_login_pay_count", 0) or 0)
        self._live_room_login_pay_count = int(
            phases.get("live_room_login_pay_count", 0) or 0)
        # A restored login state is not a restored browser page-load span.
        self._live_sentry_transactions = {}
        self.did = self._cookie.get("did", "")
        self.didv = self._cookie.get("didv", "") or str(int(time.time() * 1000))
        self._cookie["didv"] = self.didv
        self.userId = (state.get("userId") or self._cookie.get("userId")
                       or self._cookie.get("userid"))
        self.cp_api_ph = (state.get("cp_api_ph")
                          or self._cookie.get("kuaishou.web.cp.api_ph", ""))
        weapon = state.get("webweapon") or {}
        product = (weapon.get("product_name")
                   or self._cookie.get("kwpsecproductname") or DEFAULT_PRODUCT)
        href, product = _site_defaults(product)
        self.kwfv1 = str(weapon.get("kwfv1") or self._cookie.get("kwfv1", ""))
        self.kwfcv1 = str(weapon.get("kwfcv1") or "")
        self.kww_snapshot = str(weapon.get("kww_snapshot") or "")
        self._kww_signer = KwwSigner(
            self.kwfv1,
            href=str(weapon.get("href") or href),
            did=str(weapon.get("did") or self.did),
            product_name=product,
            kwscode=str(weapon.get("kwscode") or self._cookie.get("kwscode", "")),
            kwssectoken=str(weapon.get("kwssectoken")
                            or self._cookie.get("kwssectoken", "")),
            kww_snapshot=self.kww_snapshot,
            kwfcv1=self.kwfcv1,
        )
        if weapon.get("issued_at") is not None:
            self._kww_signer._issued_at = float(weapon.get("issued_at") or 0.0)
        self._kww_signer._from_cookie = bool(weapon.get("from_cookie", False))
        return self

    def get_uid(self):
        """获取当前登录用户 ID（惰性）。"""
        if self._uid is None:
            self._uid = self.userId
        return self._uid
