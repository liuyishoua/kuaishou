#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""快手扫码登录（passport.kuaishou.com / id.kuaishou.com），纯算签名。

链路（2026-08-16 Chrome DevTools 实抓）::

    1. POST id.kuaishou.com/rest/c/infra/ks/qr/start        需 sig4
       body: sid=<sid>&channelType=PC_PAGE&isWebSig4=true
       -> {result:1, qrLoginToken, qrLoginSignature, qrUrl, imageData(base64 PNG), expireTime}

    2. POST /rest/c/infra/ks/qr/scanResult                  需 sig4，**长轮询**
       body: qrLoginToken=..&qrLoginSignature=..&channelType=PC_PAGE&isWebSig4=true
       服务端挂住直到「已扫码」或超时

    3. POST /rest/c/infra/ks/qr/acceptResult                需 sig4，**长轮询**
       同样的 body，挂住直到用户在手机上点了确认 -> 返回 qrToken

    4. POST /pass/kuaishou/login/qr/callback                不签名
       用 qrToken 换正式登录态（Set-Cookie 下发 *_st / *_ph / passToken）

站点差异（都实抓印证过）：

- 请求体是 **form-urlencoded**，不是 JSON；``accept`` 是 ``*/*``。
- 头顺序与 cp 发布站相同（``content-type`` 在 ``kww`` 之前），和 www/live 不同。
- ``origin`` / ``referer`` 是 ``https://passport.kuaishou.com``，但 ``host`` 是
  ``id.kuaishou.com``，所以 ``sec-fetch-site`` 是 ``same-site`` 而非 ``same-origin``。
- **form body 参与签名**（直播站不参与），见 ``generate_hxfalcon_login``。
- 名单是 login-app.js 里明写的 8 条，见 ``LOGIN_SIG4_INTERFACES``。
"""

import base64
import json
import re
import time
import urllib.parse

import requests

requests.packages.urllib3.disable_warnings()
from loguru import logger

from builder.header import HeaderBuilder, HeaderType
from utils.ks_util import generate_hxfalcon_login
from utils.sign.falcon_pure import CAVER, login_need_sign
from utils.transport import http_proxy, response_cookies

requests = http_proxy(requests)   # get/post 走 Chrome TLS/ALPN 共享会话

# 扫码轮询是长轮询，读超时要比业务接口宽
TIMEOUT = (10, 70)
# 短信接口不是长轮询；单独设置较短的等待时间，避免 quick demo 在网络
# 或风控无响应时静默卡住近 70 秒。这个值只影响本地 socket 等待，不改变
# 请求字段、header 或签名合同。
MOBILE_TIMEOUT = (10, 30)

ID_HOST = "https://id.kuaishou.com"
PASSPORT = "https://passport.kuaishou.com"

# 各站点用哪个 sid（cookie 名也跟着变：kuaishou.live.web_st / kuaishou.web.cp.api_st ...）
SID_LIVE = "kuaishou.live.web"
# passport 手机号登录接口使用独立的默认 sid；登录成功后再通过 STS
# 换成 www/CP 各自的站点会话票据。
SID_WEB_API = "kuaishou.web.api"
# www 站认的是 kuaishou.server.webday7_st（实抓的 cookie 名，见 fixtures/www_flow.json）。
# 早先按 pageInfo 里出现过的 kuaishou.web.api 猜，换出来的 _st 服务端不认，
# profile/get 一律 result:109（需登录）。
SID_WWW = "kuaishou.server.webday7"
SID_CP = "kuaishou.web.cp.api"

CHANNEL_PC = "PC_PAGE"
CHANNEL_UNKNOWN = "UNKNOWN"
# 实抓：直播站扫码全程 channelType=PC_PAGE，www 站是 UNKNOWN（qr/start 与 callback 都是）
CHANNEL_BY_SID = {SID_WWW: CHANNEL_UNKNOWN}
# 各 sid 对应的站点（STS 换票要往这个域名打，cookie 也落在它上面）
SITE_BY_SID = {
    SID_WWW: "https://www.kuaishou.com",
    SID_CP: "https://cp.kuaishou.com",
    SID_LIVE: "https://live.kuaishou.com",
}
# 站点侧的 STS 换票入口：把 <sid>.at 换成该域名下的 <sid>_st / <sid>_ph
STS_PATH = "/rest/infra/sts"

_LOGIN_FORM_KEY_CONTRACTS = {
    "/rest/c/infra/ks/qr/start": ("sid", "channelType", "isWebSig4"),
    "/rest/c/infra/ks/qr/scanResult": (
        "qrLoginToken", "qrLoginSignature", "channelType", "isWebSig4"),
    "/rest/c/infra/ks/qr/acceptResult": (
        "qrLoginToken", "qrLoginSignature", "sid", "channelType", "isWebSig4"),
    "/pass/kuaishou/login/qr/callback": (
        "qrToken", "sid", "channelType", "isWebSig4"),
    # 真实手机号登录页（2026-08-29 Chrome Network）。字段按浏览器实际
    # form 序列化顺序保留；countryCode 的 ``+`` 在线上编码为 ``%2B``。
    "/pass/kuaishou/sms/requestMobileCode": (
        "channelType", "countryCode", "isWebSig4", "phone", "sid", "type"),
    "/pass/kuaishou/login/mobileCode": (
        "channelType", "countryCode", "createId", "isWebSig4", "phone",
        "setCookie", "sid", "smsCode"),
}

_LIVE_ID_COOKIE_KEYS = {
    "live_pass_token_home": (
        "did", "wid", "didv", "userId", "userId", "bUserId", "bUserId",
        "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "passToken", "kwfv1", "kwpsecproductname", "kwssectoken", "kwscode",
    ),
    "live_pass_token_room": (
        "did", "wid", "didv", "userId", "userId", "bUserId", "bUserId",
        "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kwpsecproductname", "passToken", "kwssectoken", "kwscode", "kwfv1",
    ),
    "live_pass_token_profile": (
        "did", "wid", "didv", "userId", "userId", "bUserId", "bUserId",
        "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kwpsecproductname", "passToken", "kwssectoken", "kwscode", "kwfv1",
    ),
}

# A live page opened directly does not necessarily carry CP creator cookies.
# Chrome's passToken/getCdns requests then use this shorter cookie line.
_LIVE_ONLY_ID_COOKIE_KEYS = {
    "live_pass_token_home": (
        "did", "wid", "didv", "bUserId", "kwpsecproductname", "userId",
        "userId", "passToken", "kwfv1", "kwssectoken", "kwscode",
    ),
    "live_pass_token_room": (
        "did", "wid", "didv", "bUserId", "kwpsecproductname", "userId",
        "userId", "passToken", "kwfv1", "kwssectoken", "kwscode",
    ),
    "live_pass_token_profile": (
        "did", "wid", "didv", "bUserId", "kwpsecproductname", "userId",
        "userId", "passToken", "kwfv1", "kwssectoken", "kwscode",
    ),
}
for _name, _keys in tuple(_LIVE_ONLY_ID_COOKIE_KEYS.items()):
    _LIVE_ONLY_ID_COOKIE_KEYS[_name + "_direct"] = _keys

_CURRENT_LIVE_PROFILE_PATH = "/profile/3xxtfm5hgbcdd2c"


def _live_referer(site: str, referer: str = None) -> tuple[str, str]:
    """Return the exact current live home/room/profile Referer and Cookie profile."""
    site = str(site or "").rstrip("/")
    value = str(referer or f"{site}/")
    if value == f"{site}/":
        return value, "live_pass_token_home"
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme == "https" and parsed.netloc == "live.kuaishou.com"
            and re.fullmatch(r"/u/[^/?#]+", parsed.path or "")):
        return value, "live_pass_token_room"
    if (parsed.scheme == "https" and parsed.netloc == "live.kuaishou.com"
            and parsed.path == _CURRENT_LIVE_PROFILE_PATH
            and not parsed.query and not parsed.fragment):
        return value, "live_pass_token_profile"
    raise RuntimeError(
        f"live 换票 Referer={value!r} 没有当前 Chrome Network 成功合同，拒绝出网")


def _validate_live_id_cookie(raw_cookie: str, profile: str) -> None:
    cookie_keys = tuple(
        part.split("=", 1)[0] for part in raw_cookie.split("; ") if part)
    direct = profile.startswith("live_pass_token_") \
        and "kuaishou.web.cp.api_st" not in cookie_keys
    expected = (_LIVE_ONLY_ID_COOKIE_KEYS if direct else _LIVE_ID_COOKIE_KEYS)[profile]
    if cookie_keys != expected:
        raise RuntimeError(
            f"{profile} Cookie profile 不完整或顺序错误，拒绝出网: "
            f"{cookie_keys} != {expected}")
    cookie_values = {}
    for part in raw_cookie.split("; "):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        cookie_values.setdefault(key, []).append(value)
    if (cookie_values.get("kwpsecproductname") != ["PCLive"]
            or len(set(cookie_values.get("userId", []))) != 1
            or len(cookie_values.get("userId", [])) != 2
            or len(set(cookie_values.get("bUserId", []))) != 1
            or len(cookie_values.get("bUserId", [])) != (1 if direct else 2)):
        raise RuntimeError(
            f"{profile} 固定 product/重复身份字段与当前 Chrome Network "
            f"不一致，拒绝出网: {cookie_values}")


def _live_id_profile(auth, profile: str) -> str:
    """Select the shorter direct-live Cookie contract when CP is absent."""
    cookie = getattr(auth, "_cookie", {}) or {}
    if profile.startswith("live_pass_token_") and not cookie.get(
            "kuaishou.web.cp.api_st"):
        return profile + "_direct"
    return profile


def _qr_page_origin(sid: str = "", channel_type: str = "") -> str:
    """Return the page origin actually observed for the QR flow."""
    if sid == SID_WWW or (not sid and channel_type == CHANNEL_UNKNOWN):
        return SITE_BY_SID[SID_WWW]
    # Current live QR evidence was captured from the passport page.
    if sid in {"", SID_LIVE, SID_WEB_API}:
        return PASSPORT
    raise RuntimeError(f"sid={sid!r} 没有当前 QR Network 成功合同，拒绝出网")


def _assert_login_form_contract(api: str, fields: dict, host: str) -> None:
    expected = _LOGIN_FORM_KEY_CONTRACTS.get(api)
    if expected is None or host != ID_HOST:
        raise RuntimeError(f"登录 POST {host}{api} 没有当前 Chrome Network 成功合同，拒绝出网")
    actual = tuple(fields.keys())
    if actual != expected:
        raise ValueError(
            f"登录 {api} body 字段/顺序不符合 Chrome Network: "
            f"actual={actual}, expected={expected}")
    if str(fields.get("isWebSig4")) != "true":
        raise ValueError(f"登录 {api} 必须发送 isWebSig4=true")
    sid = str(fields.get("sid") or "")
    channel = str(fields.get("channelType") or "")
    if sid:
        if sid not in {SID_WWW, SID_LIVE, SID_WEB_API}:
            raise RuntimeError(f"sid={sid!r} 没有当前 QR Network 成功合同，拒绝出网")
        if channel != channel_for(sid):
            raise ValueError(
                f"登录 {api} channelType={channel!r} 与 sid={sid!r} 的 Chrome "
                f"合同不符，应为 {channel_for(sid)!r}")
    elif channel not in {CHANNEL_UNKNOWN, CHANNEL_PC}:
        raise ValueError(f"登录 {api} 未抓到 channelType={channel!r} 的成功合同")
    for key in ("qrLoginToken", "qrLoginSignature", "qrToken"):
        if key in fields and not str(fields[key]):
            raise ValueError(f"登录 {api} 的 {key} 不能为空")


def channel_for(sid: str) -> str:
    """该 sid 扫码时用的 channelType（实抓，见 CHANNEL_BY_SID）。"""
    return CHANNEL_BY_SID.get(sid, CHANNEL_PC)


class KuaishouLoginAPI:
    PUBLIC_METHOD_REGISTRY = (
        "bootstrap_device_fingerprint", "bootstrap_document", "get_cdns", "login_browser_session",
        "login_by_mobile_code", "request_mobile_code",
        "login_by_qr", "pass_token_login", "qr_accept_result", "qr_callback",
        "qr_scan_result", "qr_start", "refresh_site_session", "save_qr_png",
        "sts_login",
    )
    """扫码登录。整条链只依赖 did/cookie 里的设备标识，不需要已登录态。"""

    # ------------------------------------------------------------------ #
    @staticmethod
    def _headers(auth, host_referer: str = PASSPORT):
        header = HeaderBuilder().build(HeaderType.POST, style="login")
        header.set_referer(f"{host_referer}/")
        header.set_origin(host_referer)
        # 跨子域（passport -> id），浏览器发的是 same-site
        header.set_header("sec-fetch-site", "same-site")
        header.with_kww(auth)
        return header

    @staticmethod
    def _post_form(auth, api: str, fields: dict, host: str = ID_HOST,
                   page_origin: str = None, timeout=None) -> dict:
        """发一个 form-urlencoded POST，命中名单时注入 ``__NS_hxfalcon`` + ``caver``。

        字段顺序**按传入顺序**保留（实抓 qr/start 是 sid、channelType、isWebSig4，
        不是字典序），签名输入用同一份 form。
        """
        _assert_login_form_contract(api, fields, host)
        body = "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}"
                        for k, v in fields.items())
        url = f"{host}{api}"
        if login_need_sign(api):
            sig = generate_hxfalcon_login(api, "POST", {}, fields)
            url = f"{url}?__NS_hxfalcon={sig}&caver={CAVER}"
        headers = KuaishouLoginAPI._headers(
            auth, page_origin or _qr_page_origin(
                str(fields.get("sid") or ""), str(fields.get("channelType") or "")))
        resp = requests.post(url, headers=headers.get(), cookies=auth.cookie,
                             data=body.encode("utf-8"), verify=False,
                             timeout=TIMEOUT if timeout is None else timeout)
        return _safe_json(resp), resp

    # ------------------------------------------------------------------ #
    @staticmethod
    def qr_start(auth, sid: str = SID_LIVE, channel_type: str = CHANNEL_PC,
                 **kwargs) -> dict:
        """第 1 步：申请二维码。

        :param auth: KuaishouAuth（未登录也可，只要有 did）。
        :param sid: 目标站点，见 ``SID_*``。
        :return: ``{qrLoginToken, qrLoginSignature, qrUrl, imageData, expireTime, ...}``。
        """
        data, _ = KuaishouLoginAPI._post_form(auth, "/rest/c/infra/ks/qr/start", {
            "sid": sid,
            "channelType": channel_type,
            "isWebSig4": "true",
        }, page_origin=_qr_page_origin(sid, channel_type))
        if data.get("result") != 1:
            logger.warning(f"[login] qr/start 失败：{data}")
        return data

    @staticmethod
    def qr_scan_result(auth, qr_login_token: str, qr_login_signature: str,
                       channel_type: str = CHANNEL_PC, **kwargs) -> dict:
        """第 2 步：轮询「是否已扫码」。服务端长轮询，未扫会挂住到超时。

        :return: ``result==1`` 表示已扫；``expireTime`` 到了要重新 ``qr_start``。
        """
        data, _ = KuaishouLoginAPI._post_form(auth, "/rest/c/infra/ks/qr/scanResult", {
            "qrLoginToken": qr_login_token,
            "qrLoginSignature": qr_login_signature,
            "channelType": channel_type,
            "isWebSig4": "true",
        }, page_origin=_qr_page_origin("", channel_type))
        return data

    @staticmethod
    def qr_accept_result(auth, qr_login_token: str, qr_login_signature: str,
                         sid: str = SID_LIVE, channel_type: str = CHANNEL_PC,
                         **kwargs) -> dict:
        """第 3 步：轮询「用户是否在手机上确认」。确认后返回 ``qrToken``。

        注意 body 比 ``scanResult`` **多一个 ``sid``**（实抓，位置在 signature 之后）。

        :return: ``{"result":1,"qrToken":"…","callback":"","sid":"…"}``。
        """
        data, _ = KuaishouLoginAPI._post_form(auth, "/rest/c/infra/ks/qr/acceptResult", {
            "qrLoginToken": qr_login_token,
            "qrLoginSignature": qr_login_signature,
            "sid": sid,
            "channelType": channel_type,
            "isWebSig4": "true",
        }, page_origin=_qr_page_origin(sid, channel_type))
        return data

    # 登录成功后要保存的字段：cookie 不只来自 Set-Cookie，正文里也带
    SESSION_KEYS = ("passToken", "userId", "ssecurity", "bUserId")

    @staticmethod
    def qr_callback(auth, qr_token: str, sid: str = SID_LIVE,
                    channel_type: str = CHANNEL_PC, **kwargs) -> tuple:
        """第 4 步：用 ``qrToken`` 换登录态。**这一步也要签名。**

        实抓 body：``qrToken=..&sid=..&channelType=PC_PAGE&isWebSig4=true``
        （键名是 ``qrToken`` 不是 ``qr_token``）。

        响应正文里直接给出登录票据，**不能只看 Set-Cookie**：
        ``{result, ssecurity, passToken, stsUrl, followUrl, bUserId,
        "<sid>_st": "...", userId, "<sid>.at": "...", sid}``
        其中 ``<sid>_st``（如 ``kuaishou.live.web_st``）才是各站要的会话 cookie。

        :return: ``(响应 JSON, 可直接当 cookie 用的 dict)``。
        """
        data, resp = KuaishouLoginAPI._post_form(
            auth, "/pass/kuaishou/login/qr/callback",
            {"qrToken": qr_token, "sid": sid,
             "channelType": channel_type, "isWebSig4": "true"}, host=ID_HOST,
            page_origin=_qr_page_origin(sid, channel_type))

        cookies = response_cookies(resp)
        for key in KuaishouLoginAPI.SESSION_KEYS:
            if data.get(key):
                cookies[key] = str(data[key])
        # 正文里形如 kuaishou.live.web_st / kuaishou.live.web.at 的票据
        for key, value in data.items():
            if isinstance(value, str) and value and (
                    key.endswith("_st") or key.endswith(".at")):
                cookies[key] = value
        if not cookies:
            logger.warning(f"[login] callback 没拿到任何登录票据：{data}")
        return data, cookies

    # ------------------------------------------------------------------ #
    @staticmethod
    def request_mobile_code(auth, phone: str, country_code: str = "+86",
                            sid: str = SID_WEB_API, **kwargs) -> dict:
        """申请手机号登录短信验证码。

        这是 2026-08-29 Chrome 手机号登录页的真实 form 合同：

        ``channelType=PC_PAGE&countryCode=+86&isWebSig4=true&phone=...``
        ``&sid=kuaishou.web.api&type=53``

        ``+`` 会由 form 编码为 ``%2B``；签名输入使用同一组字段。验证码或
        风控挑战由官方页面完成，库只负责发送已确认的接口请求，不尝试绕过
        CAPTCHA。手机号只作为调用参数使用，不写日志、不保存到仓库。
        """
        phone = str(phone or "").strip()
        country_code = str(country_code or "+86")
        if not phone:
            raise ValueError("request_mobile_code 需要 phone")
        if sid != SID_WEB_API:
            raise RuntimeError(
                f"手机号短信接口 sid={sid!r} 没有当前 Chrome Network 成功合同")
        fields = {
            "channelType": CHANNEL_PC,
            "countryCode": country_code,
            "isWebSig4": "true",
            "phone": phone,
            "sid": sid,
            "type": "53",              # LOGIN（前端 Qo.LOGIN）
        }
        data, _ = KuaishouLoginAPI._post_form(
            auth, "/pass/kuaishou/sms/requestMobileCode", fields,
            host=ID_HOST, page_origin=PASSPORT,
            timeout=kwargs.get("timeout", MOBILE_TIMEOUT))
        return data

    @staticmethod
    def _mobile_session_cookies(data: dict, response) -> dict:
        """合并手机号登录响应的 Set-Cookie 与正文票据。"""
        cookies = response_cookies(response)
        for key in KuaishouLoginAPI.SESSION_KEYS:
            if data.get(key):
                cookies[key] = str(data[key])
        # 手机号登录正文会同时返回 kuaishou.web.api_st/.at；后续 www/CP
        # STS 换票需要保留这两个服务端票据，不能只依赖 Set-Cookie。
        for key, value in data.items():
            if isinstance(value, str) and value and (
                    key.endswith("_st") or key.endswith(".at")):
                cookies[key] = value
        return cookies

    @staticmethod
    def _finish_mobile_browser_session(auth, initial_cookies: dict,
                                       with_sts: bool = True,
                                       with_document: bool = True) -> dict:
        """把 mobileCode 的 passport 票据补齐为 www + CP 程序会话。

        手机号接口签发的是 ``kuaishou.web.api`` 票据，而业务页面使用
        ``kuaishou.server.webday7``（www）和 ``kuaishou.web.cp.api``（CP）。
        因此必须复用与扫码登录相同的 STS、文档 Cookie 和 CP 设备指纹链。
        """
        issued = dict(initial_cookies or {})
        auth.update_cookies(issued)
        if not with_sts:
            return {"ok": True, "stage": "passport", "cookies": issued,
                    "cp_ready": False}

        # www STS：手机号登录的 kuaishou.web.api.at 是第一张可用 authToken。
        try:
            www_issued = KuaishouLoginAPI.sts_login(
                auth, sid=SID_WWW, site=SITE_BY_SID[SID_WWW])
            issued.update(www_issued or {})
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "stage": "www/sts", "detail": str(exc),
                    "cookies": issued}

        if with_document:
            try:
                www_doc = KuaishouLoginAPI.bootstrap_document(
                    auth, site=SITE_BY_SID[SID_WWW], path="/new-reco")
                issued.update(www_doc.get("cookies") or {})
                if hasattr(auth, "advance_www_cookie_phase"):
                    auth.advance_www_cookie_phase("relogin")
            except Exception as exc:  # noqa: BLE001
                return {"ok": False, "stage": "www/document", "detail": str(exc),
                        "cookies": issued}

        try:
            cp_issued = KuaishouLoginAPI.sts_login(
                auth, sid=SID_CP, site=SITE_BY_SID[SID_CP])
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "stage": "cp/sts", "detail": str(exc),
                    "cookies": issued}
        issued.update(cp_issued or {})
        if not cp_issued.get(f"{SID_CP}_ph"):
            return {
                "ok": False, "stage": "cp/sts",
                "detail": f"CP STS 未下发 {SID_CP}_ph，拿到 {sorted(cp_issued)}",
                "cookies": issued,
            }

        try:
            cp_doc = KuaishouLoginAPI.bootstrap_document(
                auth, site=SITE_BY_SID[SID_CP],
                path="/article/publish/video?origin=www.kuaishou.com")
            issued.update(cp_doc.get("cookies") or {})
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "stage": "cp/document", "detail": str(exc),
                    "cookies": issued}

        try:
            fingerprint = KuaishouLoginAPI.bootstrap_device_fingerprint(auth)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "stage": "cp/fingerprint", "detail": str(exc),
                    "cookies": issued}

        # 发布前回到 www webweapon 页面上下文，并补最后一次文档导航产生的
        # ktrace-context；这和 login_browser_session 的返回状态一致。
        auth.use_site(SITE_BY_SID[SID_WWW])
        if with_document:
            try:
                www_doc = KuaishouLoginAPI.bootstrap_document(
                    auth, site=SITE_BY_SID[SID_WWW], path="/new-reco")
                issued.update(www_doc.get("cookies") or {})
            except Exception as exc:  # noqa: BLE001
                return {"ok": False, "stage": "www/document-final",
                        "detail": str(exc), "cookies": issued}
        issued.update({"wid": fingerprint["wid"], "didv": fingerprint["didv"]})
        return {"ok": True, "stage": "done", "cookies": issued,
                "cp_ready": True, "fingerprint": fingerprint}

    @staticmethod
    def login_by_mobile_code(auth, phone: str, sms_code: str,
                             country_code: str = "+86", sid: str = SID_WEB_API,
                             create_id: bool = True, set_cookie: bool = True,
                             with_sts: bool = True,
                             with_document: bool = True, **kwargs) -> dict:
        """用手机号 + 短信验证码登录，并建立完整程序会话。

        登录请求的真实字段顺序为：
        ``channelType,countryCode,createId,isWebSig4,phone,setCookie,sid,smsCode``。
        返回值中的敏感票据仅供调用方继续更新同一个 ``auth``，示例程序不应
        直接打印；本方法不会读取浏览器 Cookie，也不会把手机号/验证码写盘。
        """
        phone = str(phone or "").strip()
        sms_code = str(sms_code or "").strip()
        country_code = str(country_code or "+86")
        if not phone or not sms_code:
            raise ValueError("login_by_mobile_code 需要 phone 与 sms_code")
        if sid != SID_WEB_API:
            raise RuntimeError(
                f"手机号登录 sid={sid!r} 没有当前 Chrome Network 成功合同")
        fields = {
            "channelType": CHANNEL_PC,
            "countryCode": country_code,
            "createId": "true" if create_id else "false",
            "isWebSig4": "true",
            "phone": phone,
            "setCookie": "true" if set_cookie else "false",
            "sid": sid,
            "smsCode": sms_code,
        }
        data, response = KuaishouLoginAPI._post_form(
            auth, "/pass/kuaishou/login/mobileCode", fields,
            host=ID_HOST, page_origin=PASSPORT)
        issued = KuaishouLoginAPI._mobile_session_cookies(data, response)
        ok = data.get("result") == 1 and bool(data.get("passToken"))
        if not ok:
            return {"ok": False, "stage": "mobileCode", "detail": data,
                    "cookies": issued}
        auth.update_cookies(issued)
        if not with_sts and not with_document:
            return {"ok": True, "stage": "passport", "detail": data,
                    "cookies": issued, "cp_ready": False}
        finished = KuaishouLoginAPI._finish_mobile_browser_session(
            auth, issued, with_sts=with_sts, with_document=with_document)
        finished["detail"] = data
        return finished

    # ------------------------------------------------------------------ #
    @staticmethod
    def get_cdns(auth, sid: str = SID_LIVE,
                 site: str = "https://live.kuaishou.com",
                 referer: str = None, **kwargs) -> dict:
        """Current live page preflight that always precedes ``passToken``.

        Chrome reqids 1871/8720 send exactly::

            POST https://id.kuaishou.com/pass/kuaishou/getCdns
            {"sid":"kuaishou.live.web","did":"<did>"}

        The home and room requests have different scoped Cookie tail order, so
        the full Referer participates in selecting the wire profile.
        """
        site = str(site or "").rstrip("/")
        if sid != SID_LIVE or site != SITE_BY_SID[SID_LIVE]:
            raise RuntimeError(
                f"getCdns sid/site 没有当前 Chrome Network 成功合同: "
                f"sid={sid!r}, site={site!r}")
        if not str(getattr(auth, "did", "") or ""):
            raise RuntimeError("getCdns 必须发送程序设备 did，缺失时拒绝出网")
        page_referer, profile = _live_referer(site, referer)
        profile = _live_id_profile(auth, profile)
        begin_transaction = getattr(auth, "begin_live_page_transaction", None)
        if not callable(begin_transaction):
            raise RuntimeError("getCdns 需要 live 页面 Sentry transaction 状态机")
        # getCdns is the first current-Network request after a live page
        # navigation and therefore the exact boundary for a new page-load trace.
        begin_transaction(page_referer)
        serializer = getattr(auth, "cookie_header", None)
        if not callable(serializer):
            raise RuntimeError("getCdns 需要精确保留重复字段的 Cookie serializer")
        raw_cookie = serializer(site=profile)
        _validate_live_id_cookie(raw_cookie, profile)

        header = HeaderBuilder().build(HeaderType.POST, style="login_pass_token")
        header.set_header("content-type", "application/json")
        header.set_referer(page_referer)
        header.set_origin(site)
        header.set_header("sec-fetch-site", "same-site")
        header.set_header("cookie", raw_cookie)
        body = json.dumps(
            {"sid": sid, "did": str(auth.did)},
            ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        resp = requests.post(f"{ID_HOST}/pass/kuaishou/getCdns",
                             headers=header.get(), data=body,
                             verify=False, timeout=TIMEOUT)
        return _safe_json(resp)

    @staticmethod
    def pass_token_login(auth, sid: str = SID_LIVE, site: str = "https://live.kuaishou.com",
                         channel_type: str = "UNKNOWN", referer: str = None,
                         with_cdn_preflight: bool = True, **kwargs) -> tuple:
        """用 ``passToken`` cookie 换某个站点的**新鲜会话票据**。不签名。

        这是各站页面加载时都会跑的一步（实抓 live.kuaishou.com 首页），也是登录态的
        「续期/换站」入口：只要 cookie 里有 ``passToken``，就能给任意 sid 铸一份
        ``<sid>_st`` / ``<sid>.at``。

        实抓请求::

            POST id.kuaishou.com/pass/kuaishou/login/passToken
            content-type: application/x-www-form-urlencoded
            referer/origin: <调用方站点>          host: id.kuaishou.com
            body: sid=kuaishou.live.web&channelType=UNKNOWN&encryptHeaders=

        典型用途：直播的 ``websocketinfo`` 返回 ``{"data":{"result":2}}`` 没有 token 时，
        多半就是该站会话过期了（比如刚在别处重新登录过），跑一次这个就能恢复。

        :param auth: KuaishouAuth（cookie 里要有 passToken）。
        :param sid: 目标站点，见 ``SID_*``。
        :param site: 调用方站点，用于 Referer / Origin。
        :param channel_type: 实抓是 ``UNKNOWN``（注意不是 PC_PAGE）。
        :return: ``(响应 JSON, 可直接并入 cookie 的 dict)``。
        """
        expected_site = SITE_BY_SID.get(sid)
        site = str(site or "").rstrip("/")
        if (sid != SID_LIVE or not expected_site or site != expected_site
                or channel_type != CHANNEL_UNKNOWN):
            raise RuntimeError(
                "passToken 登录的 sid/site/channelType 没有当前 Chrome Network "
                f"成功合同，拒绝出网: sid={sid!r}, site={site!r}, "
                f"channelType={channel_type!r}")
        page_referer, profile = _live_referer(site, referer)
        profile = _live_id_profile(auth, profile)
        if with_cdn_preflight:
            KuaishouLoginAPI.get_cdns(
                auth, sid=sid, site=site, referer=page_referer)
        header = HeaderBuilder().build(HeaderType.POST, style="login_pass_token")
        header.set_referer(page_referer)
        header.set_origin(site)
        header.set_header("sec-fetch-site", "same-site")
        serializer = getattr(auth, "cookie_header", None)
        if not callable(serializer):
            raise RuntimeError("passToken 登录需要精确保留重复字段的 Cookie serializer")
        raw_cookie = serializer(site=profile)
        _validate_live_id_cookie(raw_cookie, profile)
        header.set_header("cookie", raw_cookie)
        body = (f"sid={urllib.parse.quote(sid, safe='')}"
                f"&channelType={urllib.parse.quote(channel_type, safe='')}"
                "&encryptHeaders=")
        resp = requests.post(f"{ID_HOST}/pass/kuaishou/login/passToken",
                             headers=header.get(),
                             data=body.encode("utf-8"), verify=False, timeout=TIMEOUT)
        data = _safe_json(resp)
        cookies = response_cookies(resp)
        for key in KuaishouLoginAPI.SESSION_KEYS:
            if data.get(key):
                cookies[key] = str(data[key])
        for key, value in data.items():
            if isinstance(value, str) and value and (
                    key.endswith("_st") or key.endswith(".at")):
                cookies[key] = value
        if data.get("result") != 1:
            logger.warning(f"[login] passToken 换票失败：{data}")
        return data, cookies

    @staticmethod
    def _nav_headers(auth, referer: str) -> dict:
        """iframe 导航用的头（STS 两跳是导航不是 XHR，头形状完全不同）。

        实抓（2026-08-17，Chrome 走 www 扫码登录）：没有 ``content-type`` / ``origin``，
        多了 ``upgrade-insecure-requests``，``sec-fetch-dest`` 是 ``iframe``、
        ``mode`` 是 ``navigate``、``site`` 是 ``same-site``，``accept`` 是文档那套。
        """
        return {
            "user-agent": HeaderBuilder.ua,
            "upgrade-insecure-requests": "1",
            "accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                       "image/avif,image/webp,image/apng,*/*;q=0.8,"
                       "application/signed-exchange;v=b3;q=0.7"),
            "sec-fetch-site": "same-site",
            "sec-fetch-mode": "navigate",
            "sec-fetch-dest": "iframe",
            "referer": referer,
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "zh-CN,zh;q=0.9",
        }

    @staticmethod
    def bootstrap_document(auth, site: str = "https://www.kuaishou.com",
                           path: str = "/new-reco", referer: str = None) -> dict:
        """加载站点文档并接收页面级 ``Set-Cookie``。

        个人页的真实 Network 证据显示，动态 ``ktrace-context`` 是由页面
        ``GET`` 响应下发的；它不会从扫码 callback 或 STS 响应中出现。只打
        XHR 会漏掉这个 cookie，首次可能能过、连续请求却会进入风控。
        该方法只做一次文档导航，不解析 HTML；cookie 由程序自己的会话接收
        并持久化。
        """
        site = (site or "https://www.kuaishou.com").rstrip("/")
        path = str(path or "/")
        allowed = {
            (SITE_BY_SID[SID_WWW], "/new-reco"),
            (SITE_BY_SID[SID_CP], "/article/publish/video?origin=www.kuaishou.com"),
            (SITE_BY_SID[SID_LIVE], "/"),
        }
        if (site, path) not in allowed or referer is not None:
            raise RuntimeError(
                f"文档导航 {site}{path} 没有当前 Chrome Network 成功合同，拒绝出网")
        url = f"{site}{path if path.startswith('/') else '/' + path}"
        header = HeaderBuilder.build(HeaderType.DOC).get()
        if referer:
            header["referer"] = referer
            header["sec-fetch-site"] = "same-site"
        else:
            # Chrome 地址栏导航没有 Referer，且 sec-fetch-site=none。
            header.pop("referer", None)
            header["sec-fetch-site"] = "none"
        resp = requests.get(url, headers=header, cookies=auth.cookie,
                            verify=False, timeout=TIMEOUT)
        issued = response_cookies(resp)
        auth.update_cookies(issued)
        # A www document navigation is the boundary after which Chrome's
        # current re-login page uses the three path-scoped REST Cookie
        # profiles.  Mark it here as well as in login_by_qr so callers that
        # explicitly bootstrap a saved program session get the same wire
        # behavior without manually advancing an internal phase.
        if site.startswith("https://www.kuaishou.com") and hasattr(auth, "advance_www_cookie_phase"):
            auth.advance_www_cookie_phase("relogin")
        return {"status": getattr(resp, "status_code", 0), "cookies": issued}

    @staticmethod
    def bootstrap_device_fingerprint(auth, *, force: bool = False) -> dict:
        """Run the CP page's official ``kwf getData(1) -> /s/w/p`` chain.

        ``wid`` is a server-issued device ticket.  It must never be generated
        locally or copied from an unrelated browser session.  The method is
        intentionally idempotent: a valid program-owned ``wid`` together with
        the session's 13-digit ``didv`` is reused until the caller explicitly
        asks for ``force=True``.

        The call is made after the CP publish document has been bootstrapped,
        so the report uses the CP page's current ``onvideo-cp`` webweapon
        context and Cookie values.  The returned ticket is merged into
        ``auth`` and included in the result for persistence by callers.
        """
        def valid_wid(value) -> bool:
            value = str(value or "")
            return len(value) == 17 and value.isdigit()

        def valid_didv(value) -> bool:
            value = str(value or "")
            return len(value) == 13 and value.isdigit()

        # ``prepare_auth`` / ``prepare_state`` normally establish didv.  Keep
        # this helper safe for legacy callers that construct an auth object and
        # inject cookies directly.
        didv = str(getattr(auth, "didv", "") or "")
        raw_cookie = getattr(auth, "_cookie", None)
        if not isinstance(raw_cookie, dict):
            raw_cookie = {}
        if not valid_didv(didv):
            didv = str(raw_cookie.get("didv") or "")
        if not valid_didv(didv):
            didv = str(int(time.time() * 1000))
            if hasattr(auth, "update_cookies"):
                auth.update_cookies({"didv": didv})
            else:  # pragma: no cover - defensive compatibility for auth fakes
                auth.didv = didv
        else:
            auth.didv = didv

        existing = str(raw_cookie.get("wid") or "")
        if not existing and not raw_cookie:
            existing = str((getattr(auth, "cookie", {}) or {}).get("wid") or "")
        if valid_wid(existing) and not force:
            return {"ok": True, "wid": existing, "didv": didv, "reused": True}

        did = str(getattr(auth, "did", "") or "")
        if not did:
            did = str((getattr(auth, "cookie", {}) or {}).get("did") or "")
        if not did:
            raise RuntimeError("设备指纹上报缺少 did，拒绝生成 wid")

        # A report is a CP-page operation.  Switching the signer here is safe:
        # login_browser_session calls this before returning to www, while the
        # saved-session flow can call it immediately before CP authority.
        if hasattr(auth, "use_site"):
            auth.use_site(SITE_BY_SID[SID_CP])
        cookie_map = dict(getattr(auth, "cookie", {}) or {})
        cookie_line = "; ".join(
            f"{key}={value}" for key, value in cookie_map.items()
            if key and value is not None
        )
        from utils.sign import webweapon_boot
        wid = webweapon_boot.report_fingerprint(
            did=did,
            product_name="onvideo-cp",
            referer="https://cp.kuaishou.com/",
            href="https://cp.kuaishou.com/article/publish/video?origin=www.kuaishou.com",
            cookie=cookie_line,
            kwfcv1=str(getattr(auth, "kwfcv1", "") or ""),
            current_kwfv1=str(getattr(auth, "kwfv1", "") or ""),
        )
        if not valid_wid(wid):  # report_fingerprint already validates; keep the API contract explicit
            raise RuntimeError(f"/s/w/p 返回非法 wid: {wid!r}")
        if hasattr(auth, "update_cookies"):
            auth.update_cookies({"wid": wid, "didv": didv})
        else:  # pragma: no cover - defensive compatibility for auth fakes
            auth.didv = didv
            auth.cookie["wid"] = wid
        return {"ok": True, "wid": wid, "didv": didv, "reused": False}

    @staticmethod
    def sts_login(auth, sid: str = SID_WWW, site: str = None, **kwargs) -> dict:
        """用 ``passToken`` 换**站点域名下**的 ``<sid>_st`` / ``<sid>_ph``（STS 两跳）。

        为什么必须有这一步：扫码 ``qr/callback`` 的正文虽然给了 ``<sid>_st`` 和
        ``<sid>.at``，但那份 ``_st`` **www 不认**（`profile/get` 回 2、`profile/feed`
        回 109），而实抓的 www cookie 里还有一个 ``<sid>_ph`` —— 它只由这一步下发。
        109 响应里的 ``loginUrl`` 就是在告诉你走这条路。

        实抓的两跳（都是 302，iframe 导航）::

            GET id.kuaishou.com/pass/kuaishou/login/passToken
                ?callback=<urlencode(<site>/rest/infra/sts?followUrl=…&failUrl=…&setRootDomain=false)>
                &__loginPage=…&sid=<sid>
              -> 302 Location: 上面那个 sts url，**服务端给它补上 &authToken=<sid>.at&sid=**

            GET <那个 Location>
              -> 302，Set-Cookie: <sid>_st（HttpOnly）+ <sid>_ph + userId

        注意 ``authToken`` 是服务端在第一跳里补的，客户端不要自己拼
        （自己拼只带 authToken+followUrl 实测回 ``307690069 服务器忙``）。

        :param auth: KuaishouAuth（cookie 里要有 passToken）。
        :param sid: 目标站点的 sid，见 ``SID_*``。
        :param site: 站点根地址；默认按 sid 从 ``SITE_BY_SID`` 取。
        :return: 下发的 cookie dict（已并入 auth）。
        """
        site = str(site or SITE_BY_SID.get(sid) or "").rstrip("/")
        if sid not in {SID_WWW, SID_CP} or site != SITE_BY_SID.get(sid):
            raise RuntimeError(
                f"STS sid/site 没有当前 Chrome Network 成功合同，拒绝出网: "
                f"sid={sid!r}, site={site!r}")
        # 页面切换站点时，浏览器同步切换 webweapon 的 product/href。
        if hasattr(auth, "use_site"):
            auth.use_site(site)
        quote = urllib.parse.quote

        # followUrl / failUrl 是 sts 成功/失败后要跳去的页面，浏览器用 passport 的结果页，
        # 那个 SSO_<毫秒> 是它自己生成的关联 id。
        sso_id = f"SSO_{int(time.time() * 1000)}"
        result = (f"{PASSPORT}/pc/account/passToken/result"
                  "?successful=%s&id=" + sso_id + "&for=passTokenSuccess")
        root_domain = kwargs.get("set_root_domain")
        if root_domain is None:
            # Chrome CP creator 页面实抓为 true；www 的登录页实抓为 false。
            root_domain = sid == SID_CP
        if bool(root_domain) != (sid == SID_CP):
            raise RuntimeError(
                f"STS setRootDomain={root_domain!r} 与当前 {sid} Chrome 合同不符，拒绝出网")
        root_value = "true" if root_domain else "false"
        sts_url = (f"{site}{STS_PATH}"
                   f"?followUrl={quote(result % 'true', safe='')}"
                   f"&failUrl={quote(result % 'false', safe='')}"
                   f"&setRootDomain={root_value}")
        login_page = (f"{PASSPORT}/pc/account/passToken/result"
                      f"?successful=false&id={sso_id}&for=pullTokenFail")
        url = (f"{ID_HOST}/pass/kuaishou/login/passToken"
               f"?callback={quote(sts_url, safe='')}"
               f"&__loginPage={quote(login_page, safe='')}"
               f"&sid={quote(sid, safe='')}")

        headers = KuaishouLoginAPI._nav_headers(auth, f"{site}/")
        first = requests.get(url, headers=headers, cookies=auth.cookie, verify=False,
                             timeout=TIMEOUT, allow_redirects=False)
        issued = response_cookies(first)
        location = (first.headers.get("location") or first.headers.get("Location") or "")
        if not location:
            logger.warning(f"[login] STS 第一跳没给 Location：HTTP {first.status_code} "
                           f"{(first.text or '')[:200]}")
            auth.update_cookies(issued)
            return issued

        second = requests.get(location, headers=headers, cookies=auth.cookie, verify=False,
                              timeout=TIMEOUT, allow_redirects=False)
        issued.update(response_cookies(second))
        auth.update_cookies(issued)
        if not issued.get(f"{sid}_ph"):
            logger.warning(f"[login] STS 没下发 {sid}_ph：HTTP {second.status_code} "
                           f"拿到 {sorted(issued)} {(second.text or '')[:160]}")
        else:
            logger.info(f"[login] STS 换票成功，{site} 拿到 {sid}_st / _ph")
        return issued

    @staticmethod
    def refresh_site_session(auth, sid: str = SID_LIVE,
                             site: str = "https://live.kuaishou.com", **kwargs) -> bool:
        """完整重建某个站点的会话，浏览器每次加载直播页都会走这两步。

        1. ``passToken`` 换票 —— 拿到 ``<sid>.at``（这就是下一步要的 authToken）
           和一份 ``<sid>_st``；
        2. 该站的 ``userLogin(authToken)`` —— 服务端 Set-Cookie 下发**真正可用**的
           ``<sid>_st`` / ``<sid>_ph``。

        只做第 1 步是不够的：实测直播 ``websocketinfo`` 仍返回 ``{"result":2}`` 拿不到
        token，必须补上第 2 步。cookie 里要有 ``passToken`` 才能启动
        （注意 passToken 是 SameSite=None 的跨站 cookie，从站内请求复制 cookie 时容易漏掉）。

        :return: 是否成功。
        """
        site = str(site or "").rstrip("/")
        referer, _ = _live_referer(site, kwargs.get("referer"))
        parsed = urllib.parse.urlsplit(referer)
        eid = (parsed.path.split("/", 2)[2]
               if parsed.path.startswith("/u/") else "")
        # pass_token_login owns the single browser-observed getCdns preflight.
        # Do not call getCdns separately here or the wire order becomes
        # getCdns -> getCdns -> passToken, which Chrome never sent.
        data, cookies = KuaishouLoginAPI.pass_token_login(
            auth, sid=sid, site=site, referer=referer,
            with_cdn_preflight=True)
        if data.get("result") != 1:
            return False
        auth.update_cookies(cookies)

        auth_token = data.get(f"{sid}.at") or cookies.get(f"{sid}.at") or ""
        if not auth_token:
            logger.warning(f"[login] passToken 没返回 {sid}.at，无法完成 userLogin")
            return False

        if sid == SID_LIVE:
            from ks_apis.live_api import KuaishouLiveAPI
            done, issued = KuaishouLiveAPI.user_login_session(
                auth, auth_token, sid, eid=eid, referer=referer)
            if not done:
                return False
            auth.update_cookies(issued)
        logger.info(f"[login] 已重建 {sid} 会话")
        return True

    @staticmethod
    def save_qr_png(start_result: dict, path: str = "qrcode.png") -> str:
        """把 ``imageData``（base64 PNG）落盘，用手机扫这张图。"""
        raw = start_result.get("imageData") or ""
        if not raw:
            raise ValueError("qr/start 没返回 imageData")
        with open(path, "wb") as fp:
            fp.write(base64.b64decode(raw))
        return path

    @staticmethod
    def login_by_qr(auth, sid: str = SID_LIVE, qr_path: str = "qrcode.png",
                    timeout: float = 120.0, poll_interval: float = 1.0,
                    on_qr=None, with_sts: bool = True,
                    with_document: bool = True, **kwargs) -> dict:
        """走完整条扫码链，阻塞直到登录成功或超时。

        :param auth: KuaishouAuth。
        :param sid: 目标站点。
        :param qr_path: 二维码落盘路径。
        :param timeout: 总超时（秒）。二维码本身也有 ``expireTime``，过期需重新申请。
        :param poll_interval: 两次轮询之间的间隔（长轮询本身就会阻塞，这里只是兜底）。
        :param on_qr: 回调 ``on_qr(png_path, qr_url)``，用于展示二维码。
        :param with_sts: 登录成功后是否补 :meth:`sts_login`（www / cp 必需，见该方法）。
        :param with_document: 登录后是否加载一次目标站点文档，以接收页面级
            ``Set-Cookie``（包括动态 ``ktrace-context``）。
        :return: ``{"ok":bool, "cookies":{...}, "stage":"...", "detail":...}``。
        """
        deadline = time.time() + timeout
        channel = channel_for(sid)
        state = {}

        def issue_qr():
            """申请（或过期后重新申请）二维码。实测有效期只有 60 秒。"""
            start = KuaishouLoginAPI.qr_start(auth, sid, channel_type=channel)
            if start.get("result") != 1:
                return None
            state["token"] = start["qrLoginToken"]
            state["signature"] = start["qrLoginSignature"]
            KuaishouLoginAPI.save_qr_png(start, qr_path)
            logger.info(f"[login] 二维码已更新 {qr_path}（60 秒内有效），"
                        f"扫码链接 {start.get('qrUrl')}")
            if on_qr:
                on_qr(qr_path, start.get("qrUrl"))
            return start

        start = issue_qr()
        if not start:
            return {"ok": False, "stage": "qr/start", "detail": "申请二维码失败", "cookies": {}}

        def poll(step_name, func, allow_refresh, **extra):
            """轮询一个阶段。

            :param allow_refresh: 二维码过期(707)时是否重新申请。等扫码阶段要续，
                已经扫过之后就不能再换码了（会把用户已扫的那张作废）。
            """
            while time.time() < deadline:
                try:
                    data = func(auth, state["token"], state["signature"], **extra)
                except requests.exceptions.ReadTimeout:
                    continue                      # 长轮询读超时是正常的，接着轮
                result = data.get("result")
                if result == 1:
                    return data
                if result == 707:                 # 二维码已过期
                    if not allow_refresh or not issue_qr():
                        logger.warning(f"[login] {step_name} 终止：二维码过期")
                        return None
                    continue
                if result in (711, 712):           # 被取消 / 拒绝
                    logger.warning(f"[login] {step_name} 终止：{data}")
                    return None
                time.sleep(poll_interval)
            return None

        scanned = poll("scanResult", KuaishouLoginAPI.qr_scan_result, allow_refresh=True,
                       channel_type=channel)
        if not scanned:
            return {"ok": False, "stage": "scanResult", "detail": "未扫码或超时", "cookies": {}}
        logger.info("[login] 已扫码，等手机上确认")

        accepted = poll("acceptResult", KuaishouLoginAPI.qr_accept_result,
                        allow_refresh=False, sid=sid, channel_type=channel)
        if not accepted:
            return {"ok": False, "stage": "acceptResult", "detail": "未确认或超时", "cookies": {}}
        qr_token = accepted.get("qrToken") or accepted.get("qr_token") or ""
        if not qr_token:
            return {"ok": False, "stage": "acceptResult", "detail": accepted, "cookies": {}}

        data, issued = KuaishouLoginAPI.qr_callback(auth, qr_token, sid,
                                                   channel_type=channel)
        ok = bool(issued) and data.get("result") == 1

        # callback 给的 <sid>_st 站点侧不认，还得走一趟 STS 才有 <sid>_ph（见 sts_login）
        if ok and with_sts and sid != SID_LIVE:
            auth.update_cookies(issued)
            issued.update(KuaishouLoginAPI.sts_login(auth, sid))

        # Chrome 页面在业务 XHR 之前会先导航文档；个人页实抓的
        # ``ktrace-context`` 就是在这一步下发。把它纳入程序会话，避免扫码
        # callback + XHR 的“少 cookie”路径。
        if ok and with_document:
            site = SITE_BY_SID.get(sid) or "https://www.kuaishou.com"
            path = "/new-reco"
            if sid == SID_CP:
                path = "/article/publish/video?origin=www.kuaishou.com"
            elif sid == SID_LIVE:
                path = "/"
            try:
                doc = KuaishouLoginAPI.bootstrap_document(auth, site=site, path=path)
                issued.update(doc.get("cookies") or {})
                # A fresh www QR session has the three path-scoped Cookie
                # sequences observed in the current Chrome re-login capture.
                # Keep this phase in the program-owned state so subsequent
                # profile APIs do not fall back to the old initial/refreshed
                # approximation.
                if sid == SID_WWW and hasattr(auth, "advance_www_cookie_phase"):
                    auth.advance_www_cookie_phase("relogin")
            except Exception as exc:                  # noqa: BLE001
                logger.warning(f"[login] 文档引导失败，保留已有票据：{exc}")

        return {"ok": ok, "stage": "done" if ok else "callback",
                "detail": data, "cookies": issued}

    @staticmethod
    def login_browser_session(auth, qr_path: str = "qrcode.png",
                              timeout: float = 120.0, poll_interval: float = 1.0,
                              on_qr=None, **kwargs) -> dict:
        """一次扫码建立当前浏览器形状的 www + CP 程序自持会话。

        当前 Chrome 的 www 业务请求同时携带 www 登录票据、CP 登录票据和
        文档下发的 ``ktrace-context``。只完成 ``SID_WWW`` 扫码就立刻调用
        ``profile/get`` 会缺 ``kuaishou.web.cp.api_st/_ph``，不符合当前 Network。

        此方法只要求用户扫一次码，随后由程序完成：

        1. www callback + STS + 文档引导；
        2. 用同一个程序 ``passToken`` 完成 CP STS + CP 文档引导；
        3. 切回 www 页面 webweapon 状态并再次文档引导。

        全程不读取或复制 Chrome Cookie。发布前仍应调用 ``auth.use_site('cp')``
        或重新执行 CP STS，使 ``kww``/短期安全票据进入 CP 页面状态。
        """
        result = KuaishouLoginAPI.login_by_qr(
            auth, sid=SID_WWW, qr_path=qr_path, timeout=timeout,
            poll_interval=poll_interval, on_qr=on_qr,
            with_sts=True, with_document=True, **kwargs)
        if not result.get("ok"):
            return result

        cp_issued = KuaishouLoginAPI.sts_login(
            auth, sid=SID_CP, site=SITE_BY_SID[SID_CP])
        if not cp_issued.get(f"{SID_CP}_ph"):
            return {
                "ok": False,
                "stage": "cp/sts",
                "detail": f"CP STS 未下发 {SID_CP}_ph，拿到 {sorted(cp_issued)}",
                "cookies": dict(result.get("cookies") or {}),
            }
        try:
            cp_doc = KuaishouLoginAPI.bootstrap_document(
                auth, site=SITE_BY_SID[SID_CP],
                path="/article/publish/video?origin=www.kuaishou.com")
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "stage": "cp/document", "detail": str(exc),
                    "cookies": dict(result.get("cookies") or {})}

        # The CP page reports its browser fingerprint after the document
        # bootstrap.  /s/w/p returns the server-issued root-domain ``wid``;
        # without this step every subsequent www/CP/live business Cookie line
        # is missing a mandatory device ticket.  Keep this fail-closed: a
        # partial login must never be advertised as a browser-shaped session.
        try:
            fingerprint = KuaishouLoginAPI.bootstrap_device_fingerprint(auth)
        except Exception as exc:  # noqa: BLE001
            issued = dict(result.get("cookies") or {})
            issued.update(cp_issued)
            issued.update(cp_doc.get("cookies") or {})
            return {"ok": False, "stage": "cp/fingerprint", "detail": str(exc),
                    "cookies": issued}

        # CP 预热完后回到 www；否则后面的 www 请求会带 onvideo-cp 的 kww。
        auth.use_site(SITE_BY_SID[SID_WWW])
        try:
            www_doc = KuaishouLoginAPI.bootstrap_document(
                auth, site=SITE_BY_SID[SID_WWW], path="/new-reco")
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "stage": "www/document-final", "detail": str(exc),
                    "cookies": dict(result.get("cookies") or {})}

        issued = dict(result.get("cookies") or {})
        issued.update(cp_issued)
        issued.update(cp_doc.get("cookies") or {})
        issued.update({"wid": fingerprint["wid"], "didv": fingerprint["didv"]})
        issued.update(www_doc.get("cookies") or {})
        return {"ok": True, "stage": "done", "detail": result.get("detail"),
                "cookies": issued, "cp_ready": True}


def _safe_json(resp) -> dict:
    try:
        return resp.json()
    except Exception:
        logger.warning(f"[login] 响应非 JSON: {resp.status_code} {(resp.text or '')[:200]}")
        return {}
