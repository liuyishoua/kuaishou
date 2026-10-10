#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""快手直播接口（live.kuaishou.com），风格对齐 douyin 框架。

站点：``https://live.kuaishou.com``，接口前缀 ``/live_api/*``。请求头/顺序按 Chrome
DevTools 实抓对齐；仓库不携带含登录态的原始 Network 导出。要点：

- ``accept`` 是 axios 默认的 ``application/json, text/plain, */*``；POST 的
  ``content-type`` 是 ``application/json``，当前 GET Network 不发送该字段。
- 额外带 sentry 埋点头 ``sentry-trace`` / ``baggage``（``Header.with_sentry()``）。
- **GET 不发 ``origin``**，POST 才发。
- 只有少数接口需要 ``__NS_hxfalcon``（见 ``LIVE_SIG4_INTERFACES``）：实抓到的是
  ``baseuser/userLogin`` 与 ``liveroom/websocketinfo``；其余 cookie 直连。
- 直播站的 SDK 版本号是 43469（www/cp 是 43468），所以签名器是独立实例，
  见 ``utils.ks_util.generate_hxfalcon_live``。

``liveStreamId`` 不是 url 里的 eid：房间页 URL 是 ``/u/<eid>``，而接口要的是
``liveStreamId``（形如 ``d_5RccxXoFE``）。它由 SSR 注入在页面的
``window.__INITIAL_STATE__.liveroom.playList[0].liveStream.id``，
所以 :meth:`KuaishouLiveAPI.get_room_state` 直接抓 HTML 解析，不需要浏览器。
"""

import json
import re
from urllib.parse import parse_qsl, urlsplit

import requests

requests.packages.urllib3.disable_warnings()
from loguru import logger

from builder.header import HeaderBuilder, HeaderType
from builder.params import Params, axios_encode
from utils.gdfp_manmachine import game_live_init as _game_live_init
from utils.ks_util import generate_hxfalcon_live
from utils.sign.falcon_pure import CAVER, live_need_sign, live_sign_url
from utils.transport import http_proxy, response_cookies

requests = http_proxy(requests)   # get/post 走 Chrome TLS/ALPN 共享会话

# 不设超时的话，服务端挂住连接会让调用方无限期卡死（实测发评论时踩到过）
TIMEOUT = (10, 30)

_STATE_MARKER = "window.__INITIAL_STATE__"
# SSR 出来的不是严格 JSON：里面有裸 undefined（实抓见 "authToken":undefined）
_UNDEFINED_RE = re.compile(r"(?<![\w\"'])(?:undefined|void 0)(?![\w])")


_LIVE_COOKIE_KEY_CONTRACTS = {
    "live_home_initial": (
        "did", "wid", "clientid", "did", "client_key", "kpn", "didv", "userId",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kuaishou.live.bfb1s", "userId", "kuaishou.live.web_st",
        "kuaishou.live.web_ph", "kwfv1", "kwpsecproductname",
        "kwssectoken", "kwscode",
    ),
    "live_home_login": (
        "did", "wid", "clientid", "did", "client_key", "kpn", "didv", "userId",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kuaishou.live.bfb1s", "userId", "kuaishou.live.web_st",
        "kuaishou.live.web_ph", "kwpsecproductname", "kwssectoken",
        "kwscode", "kwfv1",
    ),
    # Fresh mobile/passToken sessions can have live.web_st but not yet
    # live.web_ph.  The first userLogin request is the browser-equivalent
    # bootstrap that issues web_ph; subsequent requests use live_home_login.
    "live_home_login_bootstrap": (
        "did", "wid", "clientid", "did", "client_key", "kpn", "didv", "userId",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kuaishou.live.bfb1s", "userId", "kuaishou.live.web_st",
        "kwpsecproductname", "kwssectoken", "kwscode", "kwfv1",
    ),
    # Current Chrome 151 direct live-home requests (no CP STS cookies).
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
    "live_home_authenticated_1": (
        "did", "wid", "clientid", "did", "client_key", "kpn", "didv", "userId",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kuaishou.live.bfb1s", "userId", "kuaishou.live.web_st",
        "kuaishou.live.web_ph", "kwpsecproductname", "kwssectoken",
        "kwscode", "kwfv1",
    ),
    "live_home_authenticated_2": (
        "did", "wid", "clientid", "did", "client_key", "kpn", "didv", "userId",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kuaishou.live.bfb1s", "userId", "kwpsecproductname", "kwssectoken",
        "kwscode", "kwfv1", "kuaishou.live.web_st", "kuaishou.live.web_ph",
    ),
    "live_home_delayed": (
        "did", "wid", "clientid", "did", "client_key", "kpn", "didv", "userId",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kuaishou.live.bfb1s", "userId", "kwpsecproductname",
        "kuaishou.live.web_st", "kuaishou.live.web_ph", "kwfv1",
        "kwssectoken", "kwscode",
    ),
    "live_room_initial": (
        "did", "wid", "clientid", "did", "client_key", "kpn", "didv", "userId",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kuaishou.live.bfb1s", "userId", "kwpsecproductname",
        "kuaishou.live.web_st", "kuaishou.live.web_ph", "kwssectoken", "kwscode",
        "kwfv1",
    ),
    "live_room_assets_initial": (
        "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
        "bUserId", "kuaishou.live.bfb1s", "userId", "kuaishou.live.web_st",
        "kuaishou.live.web_ph", "kwfv1", "kwssectoken", "kwscode",
        "kwpsecproductname",
    ),
    "live_room_login": (
        "did", "wid", "clientid", "did", "client_key", "kpn", "didv", "userId",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kuaishou.live.bfb1s", "userId", "kwpsecproductname",
        "kuaishou.live.web_st", "kuaishou.live.web_ph", "kwssectoken",
        "kwscode", "kwfv1",
    ),
    "live_room_authenticated": (
        "did", "wid", "clientid", "did", "client_key", "kpn", "didv", "userId",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kuaishou.live.bfb1s", "userId", "kwpsecproductname",
        "kuaishou.live.web_st", "kuaishou.live.web_ph", "kwssectoken",
        "kwscode", "kwfv1",
    ),
    # Current Chrome 151 live-only room requests (2026-08-30). A direct
    # live-page session can legitimately have no CP STS cookies.
    "live_room_current_initial": (
        "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
        "bUserId", "kuaishou.live.bfb1s", "kwpsecproductname", "userId",
        "userId", "kwfv1", "kwssectoken", "kwscode", "kuaishou.live.web_st",
        "kuaishou.live.web_ph",
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
    "live_room_login_bootstrap": (
        "did", "wid", "clientid", "did", "client_key", "kpn", "didv", "userId",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kuaishou.live.bfb1s", "userId", "kwpsecproductname",
        "kuaishou.live.web_st", "kwssectoken", "kwscode", "kwfv1",
    ),
    "live_room_current_authenticated": (
        "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
        "bUserId", "kuaishou.live.bfb1s", "kwpsecproductname", "userId",
        "userId", "kwfv1", "kuaishou.live.web_st", "kuaishou.live.web_ph",
        "kwssectoken", "kwscode",
    ),
    "live_room_logout_authenticated": (
        "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
        "bUserId", "kuaishou.live.bfb1s", "userId",
        "kuaishou.live.web_st", "kuaishou.live.web_ph",
        "kwpsecproductname", "kwssectoken", "kwscode", "kwfv1",
    ),
    "live_room_logout_clean": (
        "did", "wid", "clientid", "did", "client_key", "kpn", "didv",
        "bUserId", "kuaishou.live.bfb1s", "kwpsecproductname",
        "kwssectoken", "kwscode", "kwfv1",
    ),
    "live_profile_initial": (
        "did", "wid", "clientid", "did", "client_key", "kpn", "didv", "userId",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kuaishou.live.bfb1s", "userId", "kwpsecproductname",
        "kuaishou.live.web_st", "kuaishou.live.web_ph", "kwssectoken",
        "kwscode", "kwfv1",
    ),
    "live_profile_login": (
        "did", "wid", "clientid", "did", "client_key", "kpn", "didv", "userId",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kuaishou.live.bfb1s", "userId", "kwpsecproductname",
        "kuaishou.live.web_st", "kuaishou.live.web_ph", "kwssectoken",
        "kwscode", "kwfv1",
    ),
    "live_profile_authenticated_1": (
        "did", "wid", "clientid", "did", "client_key", "kpn", "didv", "userId",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kuaishou.live.bfb1s", "userId", "kwpsecproductname",
        "kuaishou.live.web_st", "kuaishou.live.web_ph", "kwssectoken",
        "kwscode", "kwfv1",
    ),
    "live_profile_authenticated": (
        "did", "wid", "clientid", "did", "client_key", "kpn", "didv", "userId",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kuaishou.live.bfb1s", "userId", "kwpsecproductname", "kwssectoken",
        "kwscode", "kwfv1", "kuaishou.live.web_st", "kuaishou.live.web_ph",
    ),
}

_CURRENT_LIVE_PROFILE_EID = "3xxtfm5hgbcdd2c"
_CURRENT_LIVE_LOGOUT_EID = "3xtgiecv6inq83i"
_LIVE_LOGOUT_REFERER = f"https://live.kuaishou.com/u/{_CURRENT_LIVE_LOGOUT_EID}"
_LIVE_PASSPORT_LOGOUT_URL = "https://id.kuaishou.com/pass/kuaishou/login/logout"
_LIVE_USER_LOGOUT_PATH = "/live_api/baseuser/userLogout"
_LIVE_PASSPORT_LOGOUT_BODY = (
    b"sid=kuaishou.live.web&channelType=UNKNOWN&encryptHeaders=")
_LIVE_PASSPORT_LOGOUT_COOKIES = {
    "live_logout_passport_authenticated": (
        "did", "wid", "didv", "bUserId", "kwfv1",
        "kwssectoken", "kwscode", "kwpsecproductname",
    ),
    "live_logout_passport_clean": (
        "did", "wid", "didv", "bUserId", "kwpsecproductname",
        "kwssectoken", "kwscode", "kwfv1",
    ),
}
_LIVE_LOGOUT_SET_COOKIE = {
    "passport": ("userId", "userId", "passToken"),
    "live": ("kuaishou.live.web_st", "kuaishou.live.web_ph", "userId"),
}

_LIVE_CURRENT_PATHS = {
    "/live_api/baseuser/userinfo",
    "/live_api/category/classify",
    "/live_api/web/pay/get-pay",
    "/live_api/baseuser/userFollowCount",
    "/live_api/category/simple",
    "/live_api/interestMask/list",
    "/live_api/emoji/gift-list",
    "/live_api/emoji/icon",
    "/live_api/emoji/allgifts",
    "/live_api/liveroom/reco",
    "/live_api/baseuser/userLogin",
    _LIVE_USER_LOGOUT_PATH,
    "/live_api/liveroom/recall",
    "/live_api/liveroom/websocketinfo",
    "/live_api/emoji/panel",
    "/live_api/home/list",
    "/live_api/home/category",
    "/live_api/profile/public",
    "/live_api/baseuser/userinfo/byid",
    "/live_api/baseuser/userinfo/sensitive",
    "/live_api/profileInterestMask/list",
    "/live_api/profile/interestlist",
}

_LIVE_RECO_BODY = {
    "followingParam": {"queryFollowing": True, "followingWeight": 50},
    "gameFavour": [
        {"gameId": 1, "totalStayLength": 100},
        {"gameId": 25, "totalStayLength": 100},
        {"gameId": 1001, "totalStayLength": 100},
        {"gameId": 22008, "totalStayLength": 100},
        {"gameId": 22146, "totalStayLength": 100},
        {"gameId": 22181, "totalStayLength": 100},
    ],
}


def _cookie_names(raw: str) -> tuple:
    return tuple(part.split("=", 1)[0] for part in (raw or "").split("; ") if part)


def _cookie_pairs(raw: str) -> list:
    return [tuple(part.split("=", 1)) for part in (raw or "").split("; ")
            if part and "=" in part]


def _exact_keys(value: dict | None) -> tuple:
    return tuple((value or {}).keys())


def _cookie_value_groups(raw: str) -> dict:
    values = {}
    for key, value in _cookie_pairs(raw):
        values.setdefault(key, []).append(value)
    return values


def _assert_passport_logout_cookie(raw: str, profile: str) -> None:
    expected = _LIVE_PASSPORT_LOGOUT_COOKIES.get(profile)
    actual = _cookie_names(raw)
    if expected is None or actual != expected:
        raise RuntimeError(
            f"{profile} Cookie 字段/顺序不符合当前 Chrome logout: "
            f"{actual} != {expected}")
    values = _cookie_value_groups(raw)
    if (values.get("kwpsecproductname") != ["PCLive"]
            or [len(value) for value in values.get("kwfv1", [])] != [174]
            or [len(value) for value in values.get("kwssectoken", [])] != [88]
            or not re.fullmatch(r"[0-9a-f]{64}",
                                (values.get("kwscode") or [""])[0])):
        raise RuntimeError(
            f"{profile} JS webweapon Cookie 值形态偏离当前 Chrome，拒绝登出")


def _response_header(resp, name: str) -> str:
    headers = getattr(resp, "headers", None)
    if not headers:
        return ""
    try:
        return str(headers.get(name, "") or "")
    except TypeError:
        return str(headers.get(name) or "")


def _response_set_cookie_names(resp) -> tuple:
    headers = getattr(resp, "headers", None)
    if not headers:
        return ()
    values = []
    getter = getattr(headers, "get_list", None)
    if callable(getter):
        try:
            values = list(getter("set-cookie") or getter("Set-Cookie") or [])
        except Exception:  # pragma: no cover - library-version compatibility
            values = []
    if not values:
        value = _response_header(resp, "set-cookie")
        if value:
            values = [value]
    names = []
    for value in values:
        names.extend(re.findall(
            r"(?:^|,\s*)([A-Za-z0-9._-]+)=", str(value)))
    return tuple(names)


def _response_set_cookie_values(resp) -> tuple:
    """Return Set-Cookie lines without collapsing duplicate names."""
    headers = getattr(resp, "headers", None)
    if not headers:
        return ()
    getter = getattr(headers, "get_list", None)
    if callable(getter):
        try:
            values = list(getter("set-cookie") or getter("Set-Cookie") or [])
            if values:
                return tuple(str(value) for value in values)
        except Exception:  # pragma: no cover - library-version compatibility
            pass
    value = _response_header(resp, "set-cookie")
    return (value,) if value else ()


def _assert_logout_set_cookie_attributes(resp, kind: str) -> None:
    """Check the deletion attributes, not only cookie names/order.

    Chrome's retained responses show two different scopes on passport's
    duplicate ``userId`` deletion (one Domain cookie and one host-only cookie)
    and lower-case path/httponly attributes on the live response.  Flattening
    this to names alone would permit a materially different browser state.
    """
    raw = ", ".join(_response_set_cookie_values(resp))
    normalized = re.sub(r"\s+", " ", raw.strip().lower())
    if kind == "passport":
        expected = (
            "userid=; path=/; domain=kuaishou.com; max-age=0; "
            "expires=thu, 01 jan 1970 00:00:00 gmt; secure; samesite=none, "
            "userid=; path=/; max-age=0; expires=thu, 01 jan 1970 00:00:00 gmt; "
            "secure; samesite=none, passtoken=; path=/; max-age=0; "
            "expires=thu, 01 jan 1970 00:00:00 gmt; secure; samesite=none")
    else:
        expected = (
            "kuaishou.live.web_st=; path=/; expires=thu, 01 jan 1970 "
            "00:00:00 gmt; httponly, kuaishou.live.web_ph=; path=/; expires="
            "thu, 01 jan 1970 00:00:00 gmt; httponly, userid=; path=/; "
            "expires=thu, 01 jan 1970 00:00:00 gmt; httponly")
    if normalized != expected:
        raise RuntimeError(
            f"live {kind} logout Set-Cookie 属性/作用域偏离当前 Chrome")


def _assert_http11_response(resp, label: str) -> None:
    from utils.transport import is_http11
    raw_version = getattr(resp, "http_version", "")
    if not is_http11(raw_version):
        raise RuntimeError(
            f"{label} 当前 Chrome 合同是 HTTP/1.1；实际 http_version="
            f"{raw_version or 'unknown'}")


def _assert_logout_response(resp, payload: dict, kind: str,
                            require_body: bool) -> None:
    if getattr(resp, "status_code", None) != 200:
        raise RuntimeError(f"live {kind} logout HTTP 状态不是当前成功样本 200")
    _assert_http11_response(resp, f"live {kind} logout")
    expected_type = ("application/json;charset=utf-8" if kind == "passport"
                     else "application/json; charset=utf-8")
    if _response_header(resp, "content-type").lower() != expected_type:
        raise RuntimeError(f"live {kind} logout Content-Type 偏离当前 Chrome")
    names = _response_set_cookie_names(resp)
    if names != _LIVE_LOGOUT_SET_COOKIE[kind]:
        raise RuntimeError(
            f"live {kind} logout Set-Cookie 顺序漂移: "
            f"{names} != {_LIVE_LOGOUT_SET_COOKIE[kind]}")
    _assert_logout_set_cookie_attributes(resp, kind)
    if require_body:
        expected = ({"result": 1} if kind == "passport"
                    else {"data": {"result": 1}})
        if payload != expected:
            raise RuntimeError(
                f"live {kind} clean-state logout 响应体偏离当前成功样本")


def _live_context(referer: str) -> str:
    if referer == "https://live.kuaishou.com/":
        return "home"
    parsed = urlsplit(str(referer or ""))
    if (parsed.scheme == "https" and parsed.netloc == "live.kuaishou.com"
            and re.fullmatch(r"/u/[^/?#]+", parsed.path or "")):
        return "room"
    if (parsed.scheme == "https" and parsed.netloc == "live.kuaishou.com"
            and parsed.path == f"/profile/{_CURRENT_LIVE_PROFILE_EID}"
            and not parsed.query and not parsed.fragment):
        return "profile"
    raise RuntimeError(
        f"缺少当前首页/房间/profile 完整 Referer，拒绝出网: {referer}")


def _live_only_session(auth) -> bool:
    """Whether the auth jar is the direct live-page session shape.

    Chrome can open a live room without first visiting the creator/www pages;
    that session has no CP STS cookies. Keep the historical CP-backed
    contracts for the QR flow, while selecting the current live-only contracts
    for this equally valid browser state.
    """
    cookie = getattr(auth, "_cookie", {}) or {}
    return not (cookie.get("kuaishou.web.cp.api_st")
                or cookie.get("kuaishou.web.cp.api_ph"))


def _room_cookie_profile(auth, phase: str) -> str:
    phase = str(phase or "initial")
    if _live_only_session(auth) and phase in {"initial", "login", "authenticated"}:
        return f"live_room_current_{phase}"
    return f"live_room_{phase}"


def _home_cookie_profile(auth, phase: str) -> str:
    phase = str(phase or "initial")
    if _live_only_session(auth) and phase in {
            "initial", "login", "login_bootstrap", "authenticated_1",
            "authenticated_2", "authenticated_3"}:
        return f"live_home_current_{phase}"
    return f"live_home_{phase}"


def _current_live_profile(auth, referer: str) -> str:
    context = _live_context(referer)
    phases = getattr(auth, "_live_cookie_phase", {}) or {}
    phase = str(phases.get(context) or "initial")
    if context == "room":
        profile = _room_cookie_profile(auth, phase)
    elif context == "home":
        profile = _home_cookie_profile(auth, phase)
    else:
        profile = f"live_{context}_{phase}"
    if profile not in _LIVE_COOKIE_KEY_CONTRACTS:
        raise RuntimeError(
            f"live {context} Cookie phase={phase!r} 没有当前 Chrome 合同，拒绝出网")
    return profile


def _assert_live_contract(auth, method: str, api: str, query: dict | None,
                          body: dict | None, cookie_profile: str,
                          sentry: bool, referer: str) -> None:
    """Fail closed unless the request matches a successful current capture."""
    if api not in _LIVE_CURRENT_PATHS:
        # Historical comparison scripts are offline and explicitly opt in;
        # normal runtime callers cannot send those old code-derived shapes.
        if getattr(auth, "_allow_historical_live_contract", False):
            return
        raise RuntimeError(f"{api} 尚无当前 Chrome Network 成功证据，拒绝出网")

    q = query or {}
    context = _live_context(referer)
    is_home = context == "home"

    if is_home:
        if api == "/live_api/baseuser/userinfo":
            ok = (method == "POST" and body == {} and not q and sentry
                  and cookie_profile in {"live_home_initial",
                                         "live_home_authenticated_2",
                                         "live_home_current_initial",
                                         "live_home_current_authenticated_1",
                                         "live_home_current_authenticated_2",
                                         "live_home_current_authenticated_3"})
        elif api == "/live_api/category/classify":
            ok = (method == "GET"
                  and _exact_keys(q) == ("type", "source", "page", "pageSize")
                  and list(q.values()) == [4, 2, 1, 20] and body is None and sentry
                  and cookie_profile in {"live_home_initial",
                                         "live_home_current_initial"})
        elif api in {"/live_api/home/list", "/live_api/category/simple",
                     "/live_api/interestMask/list"}:
            ok = (method == "GET" and not q and body is None and sentry
                  and cookie_profile in {"live_home_initial",
                                         "live_home_current_initial"})
        elif api == "/live_api/baseuser/userFollowCount":
            initial = (method == "GET" and not q and body is None and sentry
                       and cookie_profile in {"live_home_initial",
                                              "live_home_current_initial"})
            delayed = (method == "GET" and not q and body is None and not sentry
                       and cookie_profile == "live_home_delayed")
            ok = initial or delayed
        elif api == "/live_api/web/pay/get-pay":
            ok = (method == "GET" and not q and body is None and sentry
                  and cookie_profile in {"live_home_initial",
                                         "live_home_authenticated_1",
                                         "live_home_authenticated_2",
                                         "live_home_current_initial",
                                         "live_home_current_authenticated_1",
                                         "live_home_current_authenticated_2",
                                         "live_home_current_authenticated_3"})
        elif api == "/live_api/baseuser/userLogin":
            info = (body or {}).get("userLoginInfo") if isinstance(body, dict) else None
            ok = (method == "POST" and not q
                  and _exact_keys(body) == ("userLoginInfo",)
                  and _exact_keys(info) == ("authToken", "sid")
                  and bool((info or {}).get("authToken"))
                  and (info or {}).get("sid") == "kuaishou.live.web"
                  and sentry and cookie_profile in {
                      "live_home_login", "live_home_login_bootstrap",
                      "live_home_current_login",
                      "live_home_current_login_bootstrap"})
        elif api == "/live_api/home/category":
            ok = (method == "GET" and not q and body is None and sentry
                  and cookie_profile in {"live_home_authenticated_2",
                                         "live_home_current_authenticated_2",
                                         "live_home_current_authenticated_3"})
        else:
            ok = False
        if not ok:
            raise ValueError(
                f"{api} 首页 method/query/body/Cookie阶段/sentry 与当前 "
                "Chrome Network 不一致，拒绝出网")
        return

    if context == "profile":
        target = _CURRENT_LIVE_PROFILE_EID
        if api == "/live_api/baseuser/userinfo":
            ok = (method == "POST" and body == {} and not q and sentry
                  and cookie_profile in {"live_profile_initial",
                                         "live_profile_authenticated"})
        elif api == "/live_api/category/classify":
            ok = (method == "GET"
                  and _exact_keys(q) == ("type", "source", "page", "pageSize")
                  and list(q.values()) == [4, 2, 1, 20] and body is None and sentry
                  and cookie_profile == "live_profile_initial")
        elif api in {"/live_api/baseuser/userFollowCount",
                     "/live_api/category/simple", "/live_api/interestMask/list"}:
            ok = (method == "GET" and not q and body is None and sentry
                  and cookie_profile == "live_profile_initial")
        elif api == "/live_api/web/pay/get-pay":
            ok = (method == "GET" and not q and body is None and sentry
                  and cookie_profile in {"live_profile_initial", "live_profile_login",
                                         "live_profile_authenticated_1",
                                         "live_profile_authenticated"})
        elif api == "/live_api/profile/public":
            ok = (method == "GET"
                  and _exact_keys(q) == (
                      "count", "hasMore", "pcursor", "principalId", "privacy")
                  and list(q.values()) == [12, "true", "", target, "public"]
                  and body is None and sentry
                  and cookie_profile == "live_profile_initial")
        elif api in {"/live_api/baseuser/userinfo/byid",
                     "/live_api/baseuser/userinfo/sensitive"}:
            ok = (method == "GET" and _exact_keys(q) == ("principalId",)
                  and q.get("principalId") == target and body is None and sentry
                  and cookie_profile == "live_profile_initial")
        elif api == "/live_api/profileInterestMask/list":
            ok = (method == "GET"
                  and _exact_keys(q) == ("principalId", "source")
                  and list(q.values()) == [target, 2] and body is None and sentry
                  and cookie_profile == "live_profile_initial")
        elif api == "/live_api/profile/interestlist":
            ok = (method == "GET" and _exact_keys(q) == ("limit", "principalId")
                  and list(q.values()) == [4, target] and body is None and sentry
                  and cookie_profile in {"live_profile_authenticated_1",
                                         "live_profile_authenticated"})
        elif api == "/live_api/baseuser/userLogin":
            info = (body or {}).get("userLoginInfo") if isinstance(body, dict) else None
            ok = (method == "POST" and not q
                  and _exact_keys(body) == ("userLoginInfo",)
                  and _exact_keys(info) == ("authToken", "sid")
                  and bool((info or {}).get("authToken"))
                  and (info or {}).get("sid") == "kuaishou.live.web"
                  and sentry and cookie_profile == "live_profile_login")
        else:
            ok = False
        if not ok:
            raise ValueError(
                f"{api} profile method/query/body/Cookie阶段/sentry 与当前 "
                "Chrome Network 不一致，拒绝出网")
        return

    if api == "/live_api/baseuser/userinfo":
        ok = (method == "POST" and body == {} and not q and sentry
              and cookie_profile in {"live_room_initial", "live_room_authenticated",
                                     "live_room_current_initial",
                                     "live_room_current_authenticated"})
    elif api == "/live_api/category/classify":
        ok = (method == "GET" and _exact_keys(q) == ("type", "source", "page", "pageSize")
              and list(q.values()) == [4, 2, 1, 20] and body is None and sentry
              and cookie_profile == "live_room_initial")
    elif api == "/live_api/web/pay/get-pay":
        ok = (method == "GET" and not q and body is None and sentry
              and cookie_profile in {"live_room_initial", "live_room_login",
                                     "live_room_authenticated", "live_room_current_initial",
                                     "live_room_current_login",
                                     "live_room_current_login_bootstrap",
                                     "live_room_login_bootstrap",
                                     "live_room_current_authenticated"})
    elif api in {"/live_api/baseuser/userFollowCount", "/live_api/category/simple",
                 "/live_api/interestMask/list"}:
        initial = (method == "GET" and not q and body is None and sentry
                   and cookie_profile in {"live_room_initial", "live_room_current_initial"})
        delayed = (api == "/live_api/baseuser/userFollowCount"
                   and method == "GET" and not q and body is None and not sentry
                   and cookie_profile in {"live_room_authenticated",
                                          "live_room_current_authenticated"})
        ok = initial or delayed
    elif api in {"/live_api/emoji/icon", "/live_api/emoji/allgifts"}:
        ok = (method == "GET" and not q and body is None and sentry
              and cookie_profile == "live_room_assets_initial")
    elif api == "/live_api/emoji/gift-list":
        initial = (method == "GET" and _exact_keys(q) == ("liveStreamId",)
                   and bool(q.get("liveStreamId")) and body is None and sentry
                   and cookie_profile in {"live_room_initial", "live_room_current_initial"})
        expanded = (method == "GET" and _exact_keys(q) == ("liveStreamId", "sortType")
                    and bool(q.get("liveStreamId")) and q.get("sortType") == 0
                    and body is None and not sentry
                    and cookie_profile in {"live_room_authenticated",
                                           "live_room_current_authenticated"})
        ok = initial or expanded
    elif api == "/live_api/liveroom/reco":
        ok = (method == "POST" and not q and body == _LIVE_RECO_BODY
              and _exact_keys(body) == ("followingParam", "gameFavour") and sentry
              and cookie_profile in {"live_room_initial", "live_room_current_initial"})
    elif api == "/live_api/baseuser/userLogin":
        info = (body or {}).get("userLoginInfo") if isinstance(body, dict) else None
        ok = (method == "POST" and not q and _exact_keys(body) == ("userLoginInfo",)
              and _exact_keys(info) == ("authToken", "sid")
              and bool((info or {}).get("authToken"))
              and (info or {}).get("sid") == "kuaishou.live.web" and sentry
              and cookie_profile in {"live_room_login", "live_room_current_login",
                                     "live_room_current_login_bootstrap"})
    elif api == _LIVE_USER_LOGOUT_PATH:
        ok = (method == "POST" and not q and body is None and sentry
              and cookie_profile in {"live_room_logout_authenticated",
                                     "live_room_logout_clean"})
    elif api == "/live_api/liveroom/recall":
        cursors = (body or {}).get("feedTypeCursorMap") if isinstance(body, dict) else None
        ok = (method == "POST" and not q
              and _exact_keys(body) == ("liveStreamId", "feedTypeCursorMap")
              and bool((body or {}).get("liveStreamId"))
              and _exact_keys(cursors) == ("1", "2") and list((cursors or {}).values()) == [0, 0]
              and sentry and cookie_profile in {"live_room_authenticated",
                                                "live_room_current_authenticated"})
    elif api == "/live_api/liveroom/websocketinfo":
        ok = (method == "GET" and _exact_keys(q) == ("liveStreamId",)
              and bool(q.get("liveStreamId")) and body is None and sentry
              and cookie_profile in {"live_room_authenticated",
                                     "live_room_current_authenticated"})
    else:  # /live_api/emoji/panel
        ok = (method == "GET" and not q and body is None and not sentry
              and cookie_profile in {"live_room_authenticated",
                                     "live_room_current_authenticated"})

    if not ok:
        raise ValueError(
            f"{api} method/query/body/Cookie阶段/sentry 与当前 Chrome Network 不一致，拒绝出网")


def _assert_live_url_contract(api: str, url: str) -> None:
    pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    names = tuple(k for k, _ in pairs)
    values = dict(pairs)
    signed = live_need_sign(api)
    if signed:
        if names[:2] != ("__NS_hxfalcon", "caver"):
            raise RuntimeError(f"{api} sig4/caver query 顺序错误: {names}")
        if len(values.get("__NS_hxfalcon", "")) != 267 or values.get("caver") != "2":
            raise RuntimeError(f"{api} 必须严格使用 267 字符 sig4 + caver=2")
    elif "__NS_hxfalcon" in values or "caver" in values:
        raise RuntimeError(f"{api} 当前 Chrome Network 不带 sig4/caver")


def _assert_live_headers(method: str, sentry: bool, headers: dict,
                         cookie_profile: str = "") -> None:
    expected = []
    if sentry:
        expected.append("sentry-trace")
    expected += ["referer", "user-agent", "accept"]
    if method == "POST":
        expected.append("content-type")
    expected.append("kww")
    if sentry:
        expected.append("baggage")
    expected += ["accept-encoding", "accept-language", "cookie"]
    if method == "POST":
        expected.append("origin")
    expected += [
        "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
    ]
    if tuple(headers) != tuple(expected):
        raise RuntimeError(
            f"live header 字段/顺序不符合 Chrome Network: {tuple(headers)} != {tuple(expected)}")
    if sentry:
        value = str(headers.get("sentry-trace") or "")
        match = re.fullmatch(r"([0-9a-f]{32})-([0-9a-f]{16})-0", value)
        if not match or not int(match.group(1), 16) or not int(match.group(2), 16):
            raise RuntimeError(
                f"live sentry-trace 不符合当前 Chrome 32/16/0 形态: {value!r}")
        if headers.get("baggage") != "sentry-environment=prod,sentry-release=ab256f1":
            raise RuntimeError("live baggage 不符合当前 Chrome release/environment 合同")
    if cookie_profile.startswith("live_profile_") and len(headers.get("kww", "")) != 174:
        raise RuntimeError(
            f"{cookie_profile} 当前 Chrome kww 必须是 174 字符，拒绝出网")


def _assert_passport_logout_headers(headers: dict, profile: str) -> None:
    expected = (
        "user-agent", "content-type", "referer", "accept",
        "accept-encoding", "accept-language", "cookie", "origin",
        "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
    )
    if tuple(headers) != expected:
        raise RuntimeError(
            f"passport logout header 顺序偏离 Chrome: {tuple(headers)} != {expected}")
    if (headers.get("content-type") != "application/x-www-form-urlencoded"
            or headers.get("referer") != _LIVE_LOGOUT_REFERER
            or headers.get("origin") != KuaishouLiveAPI.live_url
            or headers.get("accept") != "*/*"
            or headers.get("sec-fetch-site") != "same-site"):
        raise RuntimeError("passport logout 固定 header 值偏离当前 Chrome")
    _assert_passport_logout_cookie(headers.get("cookie", ""), profile)


def _assert_live_logout_headers(headers: dict, profile: str) -> None:
    expected = (
        "sentry-trace", "referer", "user-agent", "accept", "kww", "baggage",
        "accept-encoding", "accept-language", "cookie", "origin",
        "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
    )
    if tuple(headers) != expected:
        raise RuntimeError(
            f"live userLogout header 顺序偏离 Chrome: {tuple(headers)} != {expected}")
    if (headers.get("referer") != _LIVE_LOGOUT_REFERER
            or headers.get("origin") != KuaishouLiveAPI.live_url
            or headers.get("accept") != "application/json, text/plain, */*"
            or "content-type" in headers):
        raise RuntimeError("live userLogout 固定 header 值偏离当前 Chrome")
    _assert_live_headers("GET", True, {
        key: value for key, value in headers.items() if key != "origin"
    }, profile)
    values = _cookie_value_groups(headers.get("cookie", ""))
    expected_cookie = _LIVE_COOKIE_KEY_CONTRACTS.get(profile)
    actual_cookie = _cookie_names(headers.get("cookie", ""))
    expected_user_count = expected_cookie.count("userId") if expected_cookie else -1
    if (expected_cookie is None or actual_cookie != expected_cookie
            or values.get("clientid") != ["3"]
            or values.get("client_key") != ["65890b29"]
            or values.get("kpn") != ["GAME_ZONE"]
            or values.get("kwpsecproductname") != ["PCLive"]
            or len(values.get("did", [])) != 2
            or len(set(values.get("did", []))) != 1
            or len(values.get("userId", [])) != expected_user_count
            or len(set(values.get("userId", []))) > 1
            or [len(value) for value in values.get("kwfv1", [])] != [174]
            or [len(value) for value in values.get("kwssectoken", [])] != [88]
            or not re.fullmatch(r"[0-9a-f]{64}",
                                (values.get("kwscode") or [""])[0])):
        raise RuntimeError(
            f"{profile} live userLogout Cookie 合同漂移，拒绝出网")
    if values.get("kwfv1") != [headers.get("kww")]:
        raise RuntimeError(
            "live userLogout 当前 Chrome 要求页面 kww 与 Cookie kwfv1 完全相同")


def _extract_initial_state(html: str) -> dict:
    """从房间页 HTML 里取出 ``window.__INITIAL_STATE__``。

    两个坑，都是实抓踩出来的：

    1. 不能用非贪婪正则配 ``{...};`` —— 对象内部就有 ``};``，会截断（实测断在 34602 字符处）。
       必须做括号配平，且跳过字符串里的括号。
    2. 值里有裸 ``undefined``，不是合法 JSON，要先换成 ``null``。
    """
    idx = html.find(_STATE_MARKER)
    if idx < 0:
        return {}
    start = html.find("{", idx)
    if start < 0:
        return {}
    depth, in_str, esc, end = 0, None, False, None
    for i in range(start, len(html)):
        ch = html[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == in_str:
                in_str = None
            continue
        if ch in "\"'":
            in_str = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end is None:
        return {}
    try:
        return json.loads(_UNDEFINED_RE.sub("null", html[start:end]))
    except json.JSONDecodeError as exc:
        logger.warning(f"[live] __INITIAL_STATE__ 解析失败：{exc}")
        return {}


class KuaishouLiveAPI:
    PUBLIC_METHOD_REGISTRY = (
        "category_classify", "category_simple", "comment_add", "comment_like",
        "comment_list", "emoji_all_gifts", "emoji_icon", "emoji_panel",
        "find_live_room", "find_live_rooms", "game_live_sdk_init", "get_room_state", "gift_list",
        "home_category", "home_list", "interest_mask_list", "is_risk_controlled",
        "liveroom_recall", "liveroom_reco", "liveroom_status", "logout_session", "pay_get",
        "photo_comment_list", "profile_feed", "profile_feed_by_id",
        "profile_interest_list", "profile_interest_mask", "profile_like",
        "profile_referer", "room_referer", "user_follow_count", "user_info", "user_info_by_id",
        "user_info_sensitive", "user_login", "user_login_session",
        "websocket_info", "work_referer",
    )
    live_url = 'https://live.kuaishou.com'
    # Current room-navigation Network reqids 1379--1518 all carry the active
    # Sentry transaction headers. Interaction-only endpoints remain opt-in.
    page_load_sentry_paths = {
        "/live_api/baseuser/userinfo",
        "/live_api/category/classify",
        "/live_api/web/pay/get-pay",
        "/live_api/baseuser/userFollowCount",
        "/live_api/category/simple",
        "/live_api/interestMask/list",
        "/live_api/emoji/gift-list",
        "/live_api/emoji/icon",
        "/live_api/emoji/allgifts",
        "/live_api/liveroom/reco",
        "/live_api/baseuser/userLogin",
        "/live_api/liveroom/recall",
        "/live_api/liveroom/websocketinfo",
        "/live_api/home/list",
        "/live_api/home/category",
        "/live_api/profile/public",
        "/live_api/baseuser/userinfo/byid",
        "/live_api/baseuser/userinfo/sensitive",
        "/live_api/profileInterestMask/list",
        "/live_api/profile/interestlist",
    }

    @staticmethod
    def room_referer(eid: str) -> str:
        """房间页 Referer。"""
        return f'{KuaishouLiveAPI.live_url}/u/{eid}'

    @staticmethod
    def profile_referer(eid: str) -> str:
        """主播资料页 Referer；当前只放行 fresh Network 中的精确 eid。"""
        return f'{KuaishouLiveAPI.live_url}/profile/{eid}'

    @staticmethod
    def work_referer(eid: str, photo_id: str) -> str:
        """作品页 Referer（``/u/<作者eid>/<photoId>``，评论相关接口用这个）。"""
        return f'{KuaishouLiveAPI.live_url}/u/{eid}/{photo_id}'

    # ------------------------------------------------------------------ #
    # 内部通用请求器                                                        #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _wire_headers(auth, headers, cookie_profile: str):
        """Attach Chrome's scoped live Cookie header without collapsing names."""
        serializer = getattr(auth, "cookie_header", None)
        if callable(serializer):
            raw = serializer(site=cookie_profile)
            headers.set_header("cookie", raw)
            expected = _LIVE_COOKIE_KEY_CONTRACTS.get(cookie_profile)
            actual = _cookie_names(raw)
            if (expected and actual != expected
                    and not getattr(auth, "_allow_historical_live_contract", False)):
                raise RuntimeError(
                    f"Cookie profile {cookie_profile} 不完整或顺序错误，拒绝出网: "
                    f"{actual} != {expected}")
            if not getattr(auth, "_allow_historical_live_contract", False):
                pairs = _cookie_pairs(raw)
                values = {}
                for key, value in pairs:
                    values.setdefault(key, []).append(value)
                fixed = {
                    "clientid": "3",
                    "client_key": "65890b29",
                    "kpn": "GAME_ZONE",
                    "kwpsecproductname": "PCLive",
                }
                bad = {key: values.get(key) for key, value in fixed.items()
                       if values.get(key) != [value]}
                expected_did_count = expected.count("did") if expected else 2
                expected_user_count = expected.count("userId") if expected else 2
                if (len(values.get("did", [])) != expected_did_count
                        or len(set(values.get("did", []))) != 1
                        or len(values.get("userId", [])) != expected_user_count
                        or len(set(values.get("userId", []))) != 1):
                    bad["duplicate_identity"] = {
                        "did": values.get("did"), "userId": values.get("userId")}
                if bad:
                    raise RuntimeError(
                        f"Cookie profile {cookie_profile} 固定值/重复身份字段不符合当前 "
                        f"Chrome Network，拒绝出网: {bad}")
            # live 页面也会在 Cookie 轮换后继续使用页面冻结的 kww。
        return headers

    @staticmethod
    def _headers(auth, referer: str, header_type, sentry: bool = False):
        """直播站请求头。

        :param sentry: 是否带 ``sentry-trace`` / ``baggage``。**默认不带**：实抓表明这两个头
            不是按接口固定的，而是 sentry 的 tracing transaction 存续期间才注入——
            页面加载期的请求（如 ``liveroom/reco``）带，用户交互期的请求
            （如 ``comment/list`` / ``comment/add``）不带。纯埋点，服务端不校验。
        """
        header = HeaderBuilder().build(header_type, style="live")
        header.set_referer(referer)
        if header_type == HeaderType.POST:
            header.set_origin(KuaishouLiveAPI.live_url)
        if sentry:
            next_ids = getattr(auth, "next_live_sentry_ids", None)
            if not callable(next_ids):
                raise RuntimeError("live page-load 请求缺少 Sentry transaction 状态机")
            trace_id, span_id = next_ids(referer)
            header.with_sentry(trace_id=trace_id, span_id=span_id)
        header.with_kww(auth)
        return header

    @staticmethod
    def _url(api: str, query: dict, method: str = "GET", body=None) -> str:
        """拼 url；命中签名名单时注入 ``__NS_hxfalcon`` + ``caver``。

        完全照抄 live-app.js 的 axios 请求拦截器 ``k`` + 签名助手 ``m``：

        - 只有精确命中 ``LIVE_URL_MAP`` 才签（``v.find(e => e.url === t.url)``）。
        - **签名输入的 url 用网关背后的 realUrl**（``/rest/k/*``），发出去的仍是 ``/live_api/*``。
        - 未签名接口保留调用方顺序：当前 Chrome reqid 1380 是
          ``type, source, page, pageSize``。
        - 命中签名名单的接口由拦截器按键名排序：历史实抓 comment/list 是
          ``count, page, pcursor, photoId``。两条规则不能混用。
        - ``form`` / ``requestBody`` 恒空：直播站的 POST body 不参与签名。
        - 最终顺序：``__NS_hxfalcon``、``caver``、再按序排列的业务 query。
        """
        params = Params()
        signed = live_need_sign(api)
        # Unsigned axios requests keep insertion order; the live signing
        # interceptor sorts only signed request params before both signing and
        # replacing the outgoing URL params.
        ordered = ({k: query[k] for k in sorted(query)} if signed and query
                   else dict(query or {}))
        if signed:
            sig = generate_hxfalcon_live(live_sign_url(api), method, ordered, body=None)
            params.add_param("__NS_hxfalcon", sig).add_param("caver", CAVER)
        params.update_params(ordered)
        qs = params.to_query_string()
        return f'{KuaishouLiveAPI.live_url}{api}?{qs}' if qs else f'{KuaishouLiveAPI.live_url}{api}'

    @staticmethod
    def _get(auth, api: str, query: dict = None, eid: str = "", **kwargs) -> dict:
        """通用 GET。"""
        sentry = kwargs.get("sentry", api in KuaishouLiveAPI.page_load_sentry_paths)
        referer = kwargs.get("referer") or KuaishouLiveAPI.room_referer(eid)
        headers = KuaishouLiveAPI._headers(
            auth, referer, HeaderType.GET, sentry=sentry)
        profile = kwargs.get("cookie_profile") or _current_live_profile(auth, referer)
        _assert_live_contract(auth, "GET", api, query or {}, None, profile, sentry, referer)
        KuaishouLiveAPI._wire_headers(
            auth, headers, profile)
        url = KuaishouLiveAPI._url(api, query or {}, method="GET")
        wire_headers = headers.get()
        _assert_live_url_contract(api, url)
        _assert_live_headers("GET", sentry, wire_headers, profile)
        resp = requests.get(url, headers=wire_headers, verify=False,
                            timeout=TIMEOUT)
        return _safe_json(resp)

    @staticmethod
    def _post(auth, api: str, body: dict = None, query: dict = None, eid: str = "",
              **kwargs) -> dict:
        """通用 POST（JSON body）。"""
        sentry = kwargs.get("sentry", api in KuaishouLiveAPI.page_load_sentry_paths)
        referer = kwargs.get("referer") or KuaishouLiveAPI.room_referer(eid)
        headers = KuaishouLiveAPI._headers(
            auth, referer, HeaderType.POST, sentry=sentry)
        profile = kwargs.get("cookie_profile") or _current_live_profile(auth, referer)
        _assert_live_contract(auth, "POST", api, query or {}, body, profile, sentry, referer)
        KuaishouLiveAPI._wire_headers(
            auth, headers, profile)
        url = KuaishouLiveAPI._url(api, query or {}, method="POST", body=body)
        # 必须编成 bytes 再发：传 str 的话 requests 按**字符数**算 Content-Length，
        # 中文是多字节，长度就报小了，服务端会一直等剩下的字节 —— 表现为请求挂死而不是报错。
        data = (json.dumps(body, ensure_ascii=False, separators=(',', ':')).encode("utf-8")
                if body is not None else None)
        wire_headers = headers.get()
        _assert_live_url_contract(api, url)
        _assert_live_headers("POST", sentry, wire_headers, profile)
        resp = requests.post(url, headers=wire_headers, data=data,
                             verify=False, timeout=TIMEOUT)
        return _safe_json(resp)

    # ------------------------------------------------------------------ #
    # 房间状态（liveStreamId 的来源）                                        #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _rooms_from_home_payload(payload: dict) -> list:
        """Extract rooms only from the current ``home/list`` response shape."""
        sections = ((payload or {}).get("data") or {}).get("list") or []
        rooms = []
        for section in sections:
            for group in (section or {}).get("gameLiveInfo") or []:
                for item in (group or {}).get("liveInfo") or []:
                    author = (item or {}).get("author") or {}
                    stream_id = (item or {}).get("id") or ""
                    eid = author.get("id") or ""
                    if not (stream_id and eid):
                        continue
                    rooms.append({
                        "eid": eid,
                        "liveStreamId": stream_id,
                        "name": author.get("name", ""),
                        "caption": (item or {}).get("caption", ""),
                        "living": bool((item or {}).get("living")
                                       or author.get("living")),
                        "author": author,
                    })
        return rooms

    @staticmethod
    def get_room_state(auth, eid: str, **kwargs) -> dict:
        """Use the current successful ``home/list`` contract to resolve a room.

        The former implementation fetched a document with a generic Cookie
        mapping.  That collapsed duplicate cookies and was never byte-aligned
        with the current room navigation, so it is no longer allowed to send.

        :param auth: KuaishouAuth。
        :param eid: 房间 url 里的 eid，如 ``<eid>``。
        :return: ``{"liveStreamId":…, "author":…, "caption":…, "isLiving":bool, "state": <完整 dict>}``。
        """
        payload = KuaishouLiveAPI.home_list(auth)
        for room in KuaishouLiveAPI._rooms_from_home_payload(payload):
            if room["eid"] == str(eid):
                return {
                    "liveStreamId": room["liveStreamId"],
                    "author": room["author"],
                    "caption": room["caption"],
                    "isLiving": room["living"],
                    "state": payload,
                }
        raise RuntimeError(
            f"当前成功 home/list 未包含 eid={eid!r}；直接房间 document 的精确 "
            "Cookie/header 合同尚未接入，拒绝猜测出网")

    @staticmethod
    def find_live_room(auth, prefer_living: bool = True, **kwargs) -> dict:
        """从直播首页挑一个**当前在播**的房间。

        房间接口都依赖 liveStreamId；当前只使用成功抓到的 ``home/list`` JSON。

        :param prefer_living: 只挑 ``living`` 明确为真的（首页列表里有下播残留项，
            拿到会连不上弹幕）。都不满足时退回第一个候选。
        :return: ``{"eid":…, "liveStreamId":…, "name":…, "caption":…}``，找不到返回 {}。
        """
        candidates = KuaishouLiveAPI.find_live_rooms(auth)
        if not candidates:
            logger.warning("[live] home/list 数据里没找到房间")
            return {}
        if prefer_living:
            for room in candidates:
                if room["living"]:
                    return room
        return candidates[0]

    @staticmethod
    def find_live_rooms(auth, **kwargs) -> list:
        """返回首页所有候选房间（在播的排前面），供调用方逐个尝试。"""
        payload = KuaishouLiveAPI.home_list(auth)
        rooms = KuaishouLiveAPI._rooms_from_home_payload(payload)
        rooms.sort(key=lambda r: not r["living"])
        return rooms

    @staticmethod
    def game_live_sdk_init(auth, eid: str, **kwargs) -> dict:
        """房间首屏 gdfp ``gameLive`` SDK_INIT（当前 reqids 918/1062）。

        当前 Network 只证明 SDK_INIT，没有证明 gameLive 后续 ``/n/a/b`` body；
        因此这里只发送已观察到的一步，未知上报分支继续 fail-closed。
        """
        expected_referer = KuaishouLiveAPI.room_referer(eid)
        referer = kwargs.get("referer") or expected_referer
        if not eid or referer != expected_referer:
            raise ValueError(
                "gameLive SDK_INIT 仅支持当前精确房间 Referer，拒绝猜测其他页面")
        return _game_live_init(
            getattr(auth, "did", ""), referer,
            session=kwargs.get("session"),
            ts_seconds=kwargs.get("ts_seconds"),
            timeout=kwargs.get("timeout", 15.0))

    # ------------------------------------------------------------------ #
    # 弹幕：握手信息（需 sig4）                                              #
    # ------------------------------------------------------------------ #
    # websocketinfo 的 result 语义（实抓）：1=正常，2=被风控挡住（不是会话过期，
    # 也不是签名错——这接口连垃圾签名都放行，见 notes 12.6）。
    # 2026-08-16 实测：出现 result:2 时，**浏览器打开同一直播间也会弹滑块验证码**，
    # 所以这是账号/IP 级的风控，得先过验证码。
    WS_RESULT_RISK_CONTROL = 2

    @staticmethod
    def is_risk_controlled(ws_info: dict) -> bool:
        """websocketinfo 是否被风控挡住（需要先过滑块验证码）。"""
        data = (ws_info or {}).get("data") or {}
        return data.get("result") == KuaishouLiveAPI.WS_RESULT_RISK_CONTROL \
            and not data.get("token")

    @staticmethod
    def websocket_info(auth, live_stream_id: str, eid: str = "", **kwargs) -> dict:
        """取弹幕 WebSocket 的连接信息（``__NS_hxfalcon`` 必带）。

        :param auth: KuaishouAuth。
        :param live_stream_id: get_room_state 拿到的 liveStreamId。
        :param eid: 房间 eid，仅用于 Referer。
        :return: JSON ``data:{result, token, websocketUrls:[wss://...]}``。
        """
        return KuaishouLiveAPI._get(auth, "/live_api/liveroom/websocketinfo",
                                    {"liveStreamId": live_stream_id}, eid=eid,
                                    cookie_profile=_room_cookie_profile(
                                        auth, "authenticated"))

    @staticmethod
    def user_login(auth, auth_token: str, sid: str = "kuaishou.live.web", eid: str = "",
                   **kwargs) -> dict:
        """直播站换取登录态（``__NS_hxfalcon`` 必带）。

        实抓 body：``{"userLoginInfo":{"authToken":"...","sid":"kuaishou.live.web"}}``。

        :param auth: KuaishouAuth。
        :param auth_token: passToken 流程拿到的 authToken。
        :param sid: 固定 ``kuaishou.live.web``。
        :param eid: 仅用于 Referer。
        :return: JSON ``data:{result}``。
        """
        body = {"userLoginInfo": {"authToken": auth_token, "sid": sid}}
        referer = kwargs.get("referer") or (
            KuaishouLiveAPI.room_referer(eid) if eid else f'{KuaishouLiveAPI.live_url}/')
        context = _live_context(referer)
        profile = (_room_cookie_profile(auth, "login") if context == "room"
                   else _home_cookie_profile(auth, "login") if context == "home"
                   else f"live_{context}_login")
        if (context == "room" and
                not getattr(auth, "_cookie", {}).get("kuaishou.live.web_ph")):
            # A direct live-page session has no ``live.web_ph`` before the
            # first userLogin response.  Its first request therefore uses
            # the explicit bootstrap contract; the regular QR/CP-backed
            # session keeps the historical room bootstrap sequence.
            profile = ("live_room_current_login_bootstrap"
                       if _live_only_session(auth)
                       else "live_room_login_bootstrap")
        # A mobile-code session has no live.web_ph until this first userLogin
        # response. Select the explicit bootstrap contract instead of sending
        # a fabricated placeholder value.
        if (context == "home" and not getattr(auth, "_cookie", {}).get(
                "kuaishou.live.web_ph")):
            profile = (_home_cookie_profile(auth, "login_bootstrap")
                       if _live_only_session(auth)
                       else "live_home_login_bootstrap")
        return KuaishouLiveAPI._post(auth, "/live_api/baseuser/userLogin", body, eid=eid,
                                     referer=referer, cookie_profile=profile)

    @staticmethod
    def user_login_session(auth, auth_token: str, sid: str = "kuaishou.live.web",
                           eid: str = "", **kwargs) -> tuple:
        """同 :meth:`user_login`，但把服务端 Set-Cookie 的会话票据也取回来。

        响应体只有 ``{"data":{"result":1}}``，**真正有用的是 Set-Cookie**：
        ``kuaishou.live.web_st`` / ``kuaishou.live.web_ph``。

        :return: ``(是否成功, 下发的 cookie dict)``。
        """
        referer = kwargs.get("referer") or (
            KuaishouLiveAPI.room_referer(eid) if eid else f'{KuaishouLiveAPI.live_url}/')
        headers = KuaishouLiveAPI._headers(auth, referer,
                                           HeaderType.POST, sentry=True)
        body = {"userLoginInfo": {"authToken": auth_token, "sid": sid}}
        context = _live_context(referer)
        profile = (_room_cookie_profile(auth, "login") if context == "room"
                   else _home_cookie_profile(auth, "login") if context == "home"
                   else f"live_{context}_login")
        if (context == "room" and
                not getattr(auth, "_cookie", {}).get("kuaishou.live.web_ph")):
            profile = ("live_room_current_login_bootstrap"
                       if _live_only_session(auth)
                       else "live_room_login_bootstrap")
        if (context == "home" and not getattr(auth, "_cookie", {}).get(
                "kuaishou.live.web_ph")):
            profile = (_home_cookie_profile(auth, "login_bootstrap")
                       if _live_only_session(auth)
                       else "live_home_login_bootstrap")
        _assert_live_contract(
            auth, "POST", "/live_api/baseuser/userLogin", {}, body,
            profile, True, referer)
        KuaishouLiveAPI._wire_headers(auth, headers, profile)
        url = KuaishouLiveAPI._url("/live_api/baseuser/userLogin", {}, method="POST",
                                   body=body)
        data = json.dumps(body, ensure_ascii=False, separators=(',', ':')).encode("utf-8")
        wire_headers = headers.get()
        _assert_live_url_contract("/live_api/baseuser/userLogin", url)
        _assert_live_headers("POST", True, wire_headers, profile)
        resp = requests.post(url, headers=wire_headers, data=data,
                             verify=False, timeout=TIMEOUT)
        payload = _safe_json(resp)
        ok = (payload.get("data") or {}).get("result") == 1
        issued = response_cookies(resp)
        if not ok:
            logger.warning(f"[live] userLogin 失败：{payload}")
        elif hasattr(auth, "advance_live_cookie_phase"):
            # Chrome home sends the first post-login pay request with its own
            # authenticated_1 order; the room keeps the login order through
            # that pay request and advances only afterwards.
            if context == "room" and _live_only_session(auth):
                # Direct room navigation has no intermediate CP/pay requests;
                # the next observed request (websocketinfo) uses the
                # authenticated live-only Cookie order.
                auth.advance_live_cookie_phase(context, "authenticated")
            else:
                auth.advance_live_cookie_phase(
                    context, "authenticated_1" if context == "home" else "login")
        return ok, issued

    @staticmethod
    def logout_session(auth, eid: str = _CURRENT_LIVE_LOGOUT_EID,
                       **kwargs) -> dict:
        """Replay the two-request live logout action from the current bundle.

        Current ``app.1241f9804c38413b871f.js`` executes
        ``userStore.logout -> ks-login.logout() -> logoutMutation()``: first
        ``POST id.kuaishou.com/pass/kuaishou/login/logout``, then
        ``POST /live_api/baseuser/userLogout``.  The first response deletes
        root/passport cookies, while the second request still carries the
        live-path cookies visible to that URL.  Both wire headers are therefore
        frozen before the first request; applying the first deletion to a flat
        mapping before serializing the second request would be observably wrong.

        This method is intentionally not used by any automatic verification:
        it changes login state when called against the network.
        """
        referer = kwargs.get("referer") or KuaishouLiveAPI.room_referer(eid)
        if referer != _LIVE_LOGOUT_REFERER or eid != _CURRENT_LIVE_LOGOUT_EID:
            raise RuntimeError(
                "logout 只放行当前 Chrome 成功保留的精确房间 Referer，拒绝外推")
        values = dict(getattr(auth, "_cookie", {}) or {})
        session_present = tuple(bool(values.get(key)) for key in (
            "userId", "kuaishou.live.web_st", "kuaishou.live.web_ph"))
        if all(session_present):
            state = "authenticated"
        elif not any(session_present):
            state = "clean"
        else:
            raise RuntimeError(
                "live logout 遇到部分清理 Cookie 状态；当前 Chrome 无该分支合同")

        serializer = getattr(auth, "cookie_header", None)
        next_sentry = getattr(auth, "next_live_sentry_ids", None)
        apply_logout = getattr(auth, "apply_live_logout", None)
        if not all(callable(item) for item in (
                serializer, next_sentry, apply_logout)):
            raise RuntimeError("live logout 需要精确 Cookie/Sentry/状态清理能力")

        passport_profile = f"live_logout_passport_{state}"
        live_profile = f"live_room_logout_{state}"
        # The page header and both scoped Cookie lines are one pre-action
        # snapshot.  This also preserves the JS-generated security quartet.
        kww = str(getattr(auth, "kww", "") or "")
        passport_cookie = serializer(site=passport_profile)
        live_cookie = serializer(site=live_profile)
        _assert_passport_logout_cookie(passport_cookie, passport_profile)

        passport_header = HeaderBuilder().build(
            HeaderType.POST, style="login_pass_token")
        passport_header.set_referer(referer)
        passport_header.set_origin(KuaishouLiveAPI.live_url)
        passport_header.set_header("sec-fetch-site", "same-site")
        passport_header.set_header("cookie", passport_cookie)
        passport_headers = passport_header.get()
        _assert_passport_logout_headers(passport_headers, passport_profile)

        trace_id, span_id = next_sentry(referer)
        live_header = HeaderBuilder().build(HeaderType.GET, style="live")
        live_header.set_referer(referer)
        live_header.set_origin(KuaishouLiveAPI.live_url)
        live_header.with_sentry(trace_id=trace_id, span_id=span_id)
        live_header.set_header("kww", kww)
        live_header.set_header("cookie", live_cookie)
        live_headers = live_header.get()
        _assert_live_contract(
            auth, "POST", _LIVE_USER_LOGOUT_PATH, {}, None,
            live_profile, True, referer)
        _assert_live_logout_headers(live_headers, live_profile)
        if len(_LIVE_PASSPORT_LOGOUT_BODY) != 57:
            raise AssertionError("passport logout body byte contract drift")

        passport_resp = requests.post(
            _LIVE_PASSPORT_LOGOUT_URL, headers=passport_headers,
            data=_LIVE_PASSPORT_LOGOUT_BODY, verify=False, timeout=TIMEOUT)
        passport_payload = _safe_json(passport_resp)
        _assert_logout_response(
            passport_resp, passport_payload, "passport",
            require_body=state == "clean")
        apply_logout(passport=True)

        live_resp = requests.post(
            f"{KuaishouLiveAPI.live_url}{_LIVE_USER_LOGOUT_PATH}",
            headers=live_headers, data=b"", verify=False, timeout=TIMEOUT)
        live_payload = _safe_json(live_resp)
        _assert_logout_response(
            live_resp, live_payload, "live", require_body=state == "clean")
        apply_logout(live=True)
        return {
            "result": 1,
            "state": state,
            "passport": passport_payload,
            "live": live_payload,
        }

    # ------------------------------------------------------------------ #
    # 房间 / 评论 / 礼物（cookie 直连即可）                                   #
    # ------------------------------------------------------------------ #
    @staticmethod
    def comment_list(auth, live_stream_id: str, eid: str = "", **kwargs) -> dict:
        """直播间评论列表（REST，非 WebSocket）。

        :param auth: KuaishouAuth。
        :param live_stream_id: liveStreamId。
        :param eid: 仅用于 Referer。
        :return: JSON。
        """
        return KuaishouLiveAPI._get(auth, "/live_api/comment/list",
                                    {"liveStreamId": live_stream_id}, eid=eid)

    @staticmethod
    def comment_add(auth, photo_id: str, principal_id: str, content: str,
                    reply_to: int = 0, reply_to_comment_id: int = 0,
                    eid: str = "", referer: str = "", **kwargs) -> dict:
        """发评论（作品评论区）。不带签名，靠 cookie 鉴权。

        实抓 body（2026-08-16，在自己作品下真发一条）::

            {"photoId":"…","principalId":"…","content":"…","replyTo":0,"replyToCommentId":0}

        **``replyTo`` / ``replyToCommentId`` 是数字 0，不是空串。** 传空串的话服务端
        既不返回也不报错，直接把连接挂住到超时——这是实测踩出来的，别改成 ""。

        Referer 必须是作品页 ``/u/<作者eid>/<photoId>``，不是房间页。

        :param auth: KuaishouAuth。
        :param photo_id: 作品 id。
        :param principal_id: 作者 eid。
        :param content: 评论内容。
        :param reply_to: 回复对象的 userId，不回复就是 0。
        :param reply_to_comment_id: 被回复评论的 id，不回复就是 0。
        :param eid: 作者 eid，用于拼 Referer。
        :param referer: 显式指定 Referer，留空则用 ``/u/<eid>/<photo_id>``。
        :return: JSON ``data:{result: 1}``。
        """
        body = {
            "photoId": photo_id,
            "principalId": principal_id,
            "content": content,
            "replyTo": reply_to,
            "replyToCommentId": reply_to_comment_id,
        }
        return KuaishouLiveAPI._post(
            auth, "/live_api/comment/add", body, eid=eid,
            referer=referer or KuaishouLiveAPI.work_referer(eid or principal_id, photo_id))

    @staticmethod
    def comment_like(auth, photo_id: str, comment_id: str, cancel: bool = False,
                     eid: str = "", **kwargs) -> dict:
        """给评论点赞 / 取消点赞（``cancel=True`` 走 unlike）。"""
        api = "/live_api/comment/unlike" if cancel else "/live_api/comment/like"
        return KuaishouLiveAPI._post(auth, api,
                                     {"photoId": photo_id, "commentId": comment_id}, eid=eid)

    @staticmethod
    def photo_comment_list(auth, photo_id: str, page: int = 1, pcursor: str = "",
                           count: int = 20, eid: str = "", **kwargs) -> dict:
        """作品评论列表（网关转发到 ``/rest/k/photo/comment/list``，需 sig4）。

        参数取自调用点原文（live-common.js @142918）::

            He({photoId: e, page: t.comment.page, pcursor: t.comment.pcursor, count: 20})

        没有 ``principalId``；``page`` 从 1 起每次 +1，``pcursor`` 首页空串、之后填响应里的游标。

        :return: JSON ``data:{commentCount, commentList[], pcursor, realCommentCount}``。
        """
        return KuaishouLiveAPI._get(auth, "/live_api/comment/list",
                                    {"photoId": photo_id, "page": page,
                                     "pcursor": pcursor, "count": count}, eid=eid)

    @staticmethod
    def profile_feed(auth, principal_id: str, privacy: str = "public", pcursor: str = "",
                     count: int = 12, has_more: bool = True, eid: str = "", **kwargs) -> dict:
        """主播作品列表。

        源码里三个路径共用一套参数，只是 ``privacy`` 不同::

            /live_api/profile/public   privacy=public
            /live_api/profile/private  privacy=private
            /live_api/profile/liked    privacy=liked

        实抓 query（一个都不能少，2026-08-16 profile 页）::

            count=12&hasMore=true&pcursor=&principalId=<eid>&privacy=public

        ``pcursor`` 首页就是空串（要发，不是省略），翻页时填上一页返回的游标。

        :param privacy: ``public`` / ``private`` / ``liked``。
        :param count: 每页条数，页面默认 12。
        :param has_more: 页面固定传 true。
        """
        if privacy not in ("public", "private", "liked"):
            raise ValueError("privacy 只能是 public / private / liked")
        query = {
            "count": count,
            "hasMore": "true" if has_more else "false",
            "pcursor": pcursor,
            "principalId": principal_id,
            "privacy": privacy,
        }
        page_eid = eid or principal_id
        return KuaishouLiveAPI._get(
            auth, f"/live_api/profile/{privacy}", query, eid=page_eid,
            referer=KuaishouLiveAPI.profile_referer(page_eid))

    @staticmethod
    def profile_feed_by_id(auth, photo_id: str, principal_id: str = "", eid: str = "",
                           **kwargs) -> dict:
        """按 id 取单个作品。"""
        query = {"photoId": photo_id}
        if principal_id:
            query["principalId"] = principal_id
        return KuaishouLiveAPI._get(auth, "/live_api/profile/feedbyid", query, eid=eid)

    @staticmethod
    def user_info_by_id(auth, principal_id: str, eid: str = "", **kwargs) -> dict:
        """按 eid 取用户信息（需 sig4）。实抓 query 只有 ``principalId``。"""
        page_eid = eid or principal_id
        return KuaishouLiveAPI._get(
            auth, "/live_api/baseuser/userinfo/byid", {"principalId": principal_id},
            eid=page_eid, referer=KuaishouLiveAPI.profile_referer(page_eid))

    @staticmethod
    def user_info_sensitive(auth, principal_id: str, eid: str = "", **kwargs) -> dict:
        """用户敏感信息（需 sig4）。"""
        page_eid = eid or principal_id
        return KuaishouLiveAPI._get(
            auth, "/live_api/baseuser/userinfo/sensitive", {"principalId": principal_id},
            eid=page_eid, referer=KuaishouLiveAPI.profile_referer(page_eid))

    @staticmethod
    def profile_interest_list(auth, principal_id: str, limit: int = 4, eid: str = "",
                              **kwargs) -> dict:
        """主播推荐位（需 sig4）。实抓 query：``limit=4&principalId=<eid>``。"""
        page_eid = eid or principal_id
        referer = KuaishouLiveAPI.profile_referer(page_eid)
        explicit = kwargs.get("cookie_profile")
        phase = (getattr(auth, "_live_cookie_phase", {}) or {}).get("profile")
        profile = explicit or ("live_profile_authenticated_1" if phase == "login"
                               else _current_live_profile(auth, referer))
        result = KuaishouLiveAPI._get(
            auth, "/live_api/profile/interestlist",
            {"limit": limit, "principalId": principal_id}, eid=page_eid,
            referer=referer, cookie_profile=profile)
        if (not explicit and phase == "login" and
                hasattr(auth, "advance_live_cookie_phase")):
            auth.advance_live_cookie_phase("profile", "authenticated_1")
        return result

    @staticmethod
    def profile_interest_mask(auth, principal_id: str, source: int = 2, eid: str = "",
                              **kwargs) -> dict:
        """主播分类标签（需 sig4）。实抓 query：``principalId=<eid>&source=2``。"""
        page_eid = eid or principal_id
        return KuaishouLiveAPI._get(
            auth, "/live_api/profileInterestMask/list",
            {"principalId": principal_id, "source": source}, eid=page_eid,
            referer=KuaishouLiveAPI.profile_referer(page_eid))

    @staticmethod
    def profile_like(auth, photo_id: str, principal_id: str, cancel: bool = False,
                     eid: str = "", **kwargs) -> dict:
        """给作品点赞（``/live_api/profile/like``，GET）。"""
        return KuaishouLiveAPI._get(auth, "/live_api/profile/like",
                                    {"photoId": photo_id, "principalId": principal_id,
                                     "cancel": "true" if cancel else "false"}, eid=eid)

    @staticmethod
    def liveroom_status(auth, live_stream_id: str, eid: str = "", **kwargs) -> dict:
        """直播间状态（是否在播等）。"""
        return KuaishouLiveAPI._get(auth, "/live_api/liveroom/status",
                                    {"liveStreamId": live_stream_id}, eid=eid)

    @staticmethod
    def gift_list(auth, live_stream_id: str, sort_type=None, eid: str = "",
                  **kwargs) -> dict:
        """礼物列表。

        当前 Network 有两种真实调用：

        - 首屏：``liveStreamId=<id>``，带 sentry/baggage，使用 initial Cookie；
        - 点击“更多礼物”：``liveStreamId=<id>&sortType=0``，不带 sentry/baggage，
          使用 authenticated Cookie。
        """
        query = {"liveStreamId": live_stream_id}
        if sort_type is not None:
            query["sortType"] = sort_type
        interactive = sort_type is not None
        return KuaishouLiveAPI._get(
            auth, "/live_api/emoji/gift-list", query, eid=eid,
            sentry=kwargs.get("sentry", not interactive),
            cookie_profile=kwargs.get("cookie_profile") or
            (_room_cookie_profile(auth, "authenticated") if interactive else
             _current_live_profile(auth, KuaishouLiveAPI.room_referer(eid))))

    @staticmethod
    def category_classify(auth, category_type: int = 4, source: int = 2,
                          page: int = 1, page_size: int = 20, eid: str = "",
                          **kwargs) -> dict:
        """当前直播页分类列表（Network: type/source/page/pageSize）。"""
        referer = kwargs.get("referer") or (
            KuaishouLiveAPI.room_referer(eid) if eid else f'{KuaishouLiveAPI.live_url}/')
        profile = kwargs.get("cookie_profile") or _current_live_profile(auth, referer)
        return KuaishouLiveAPI._get(
            auth, "/live_api/category/classify",
            {"type": category_type, "source": source, "page": page,
             "pageSize": page_size}, eid=eid, referer=referer,
            cookie_profile=profile)

    @staticmethod
    def emoji_panel(auth, eid: str = "", **kwargs) -> dict:
        """当前表情面板接口（点击聊天框左侧表情图标触发）。"""
        return KuaishouLiveAPI._get(
            auth, "/live_api/emoji/panel", eid=eid,
            sentry=kwargs.get("sentry", False),
            cookie_profile=kwargs.get("cookie_profile") or
            _room_cookie_profile(auth, "authenticated"))

    @staticmethod
    def emoji_icon(auth, eid: str = "", **kwargs) -> dict:
        """房间首屏表情图标字典（当前 Network: ``/emoji/icon``）。"""
        referer = kwargs.get("referer") or KuaishouLiveAPI.room_referer(eid)
        return KuaishouLiveAPI._get(
            auth, "/live_api/emoji/icon", eid=eid, referer=referer,
            sentry=kwargs.get("sentry", True),
            cookie_profile=kwargs.get("cookie_profile") or
            "live_room_assets_initial")

    @staticmethod
    def emoji_all_gifts(auth, eid: str = "", **kwargs) -> dict:
        """房间首屏完整礼物字典（当前 Network: ``/emoji/allgifts``）。"""
        referer = kwargs.get("referer") or KuaishouLiveAPI.room_referer(eid)
        return KuaishouLiveAPI._get(
            auth, "/live_api/emoji/allgifts", eid=eid, referer=referer,
            sentry=kwargs.get("sentry", True),
            cookie_profile=kwargs.get("cookie_profile") or
            "live_room_assets_initial")

    @staticmethod
    def pay_get(auth, eid: str = "", **kwargs) -> dict:
        referer = kwargs.get("referer") or (
            KuaishouLiveAPI.room_referer(eid) if eid else f'{KuaishouLiveAPI.live_url}/')
        context = _live_context(referer)
        direct_home = context == "home" and _live_only_session(auth)
        if (not kwargs.get("cookie_profile") and direct_home
                and getattr(auth, "_live_cookie_phase", {}).get("home") == "authenticated_1"
                and getattr(auth, "_live_home_login_pay_count", 0) >= 1
                and hasattr(auth, "advance_live_cookie_phase")):
            # Direct live-home's first pay and following userinfo both keep
            # authenticated_1.  The next pay rotates the page-scoped quartet.
            auth.advance_live_cookie_phase("home", "authenticated_2")
        profile = kwargs.get("cookie_profile") or _current_live_profile(auth, referer)
        result = KuaishouLiveAPI._get(
            auth, "/live_api/web/pay/get-pay", eid=eid, referer=referer,
            sentry=kwargs.get("sentry", True),
            cookie_profile=profile)
        if not kwargs.get("cookie_profile") and hasattr(auth, "advance_live_cookie_phase"):
            phases = getattr(auth, "_live_cookie_phase", {}) or {}
            phase = phases.get(context, "initial")
            if context == "home" and direct_home:
                if phase == "authenticated_1":
                    auth._live_home_login_pay_count = (
                        getattr(auth, "_live_home_login_pay_count", 0) + 1)
                elif phase == "authenticated_2":
                    auth._live_home_login_pay_count = (
                        getattr(auth, "_live_home_login_pay_count", 0) + 1)
                    auth.advance_live_cookie_phase("home", "authenticated_3")
            elif context == "home" and phase == "authenticated_1":
                auth.advance_live_cookie_phase("home", "authenticated_2")
            elif context == "room" and phase == "login":
                # Current active-room Network keeps the login Cookie order
                # across two consecutive pay/get requests. Promotion occurs
                # immediately before the following authenticated userinfo.
                auth._live_room_login_pay_count = (
                    getattr(auth, "_live_room_login_pay_count", 0) + 1)
            elif context == "profile" and phase == "login":
                # Older captures had pay before the post-login userinfo.
                auth.advance_live_cookie_phase("profile", "authenticated")
            elif context == "profile" and phase == "authenticated_1":
                # Current capture has one final pay after interestlist before
                # userinfo rotates the live ticket pair to the final order.
                auth.advance_live_cookie_phase("profile", "authenticated")
        return result

    @staticmethod
    def user_follow_count(auth, eid: str = "", **kwargs) -> dict:
        referer = kwargs.get("referer") or (
            KuaishouLiveAPI.room_referer(eid) if eid else f'{KuaishouLiveAPI.live_url}/')
        delayed = bool(kwargs.get("delayed", False))
        context = _live_context(referer)
        if delayed:
            profile = ("live_home_delayed" if context == "home"
                       else _room_cookie_profile(auth, "authenticated"))
        else:
            profile = kwargs.get("cookie_profile") or _current_live_profile(auth, referer)
        return KuaishouLiveAPI._get(
            auth, "/live_api/baseuser/userFollowCount", eid=eid, referer=referer,
            sentry=kwargs.get("sentry", not delayed), cookie_profile=profile)

    @staticmethod
    def interest_mask_list(auth, eid: str = "", **kwargs) -> dict:
        referer = kwargs.get("referer") or (
            KuaishouLiveAPI.room_referer(eid) if eid else f'{KuaishouLiveAPI.live_url}/')
        return KuaishouLiveAPI._get(
            auth, "/live_api/interestMask/list", eid=eid, referer=referer,
            cookie_profile=kwargs.get("cookie_profile") or
            _current_live_profile(auth, referer))

    @staticmethod
    def liveroom_reco(auth, body: dict = None, eid: str = "", **kwargs) -> dict:
        """推荐直播流请求；body 字段保持调用方给出的顺序。"""
        return KuaishouLiveAPI._post(auth, "/live_api/liveroom/reco", body or {
            "followingParam": {"queryFollowing": True, "followingWeight": 50},
            "gameFavour": [
                {"gameId": 1, "totalStayLength": 100},
                {"gameId": 25, "totalStayLength": 100},
                {"gameId": 1001, "totalStayLength": 100},
                {"gameId": 22008, "totalStayLength": 100},
                {"gameId": 22146, "totalStayLength": 100},
                {"gameId": 22181, "totalStayLength": 100},
            ]}, eid=eid)

    @staticmethod
    def liveroom_recall(auth, live_stream_id: str, feed_type_cursor_map: dict = None,
                        eid: str = "", **kwargs) -> dict:
        body = {"liveStreamId": live_stream_id,
                "feedTypeCursorMap": feed_type_cursor_map or {"1": 0, "2": 0}}
        return KuaishouLiveAPI._post(
            auth, "/live_api/liveroom/recall", body, eid=eid,
            cookie_profile=kwargs.get("cookie_profile") or
            _room_cookie_profile(auth, "authenticated"))

    @staticmethod
    def user_info(auth, eid: str = "", **kwargs) -> dict:
        """当前登录用户信息（POST，无 body）。"""
        referer = kwargs.get("referer") or (
            KuaishouLiveAPI.room_referer(eid) if eid else f'{KuaishouLiveAPI.live_url}/')
        if (not kwargs.get("cookie_profile") and
                _live_context(referer) == "room" and
                getattr(auth, "_live_cookie_phase", {}).get("room") == "login" and
                getattr(auth, "_live_room_login_pay_count", 0) >= 2 and
                hasattr(auth, "advance_live_cookie_phase")):
            auth.advance_live_cookie_phase("room", "authenticated")
        direct_home = (_live_context(referer) == "home"
                       and _live_only_session(auth)
                       and not kwargs.get("cookie_profile"))
        result = KuaishouLiveAPI._post(
            auth, "/live_api/baseuser/userinfo", {}, eid=eid, referer=referer,
            cookie_profile=kwargs.get("cookie_profile") or
            _current_live_profile(auth, referer))
        if (direct_home
                and getattr(auth, "_live_cookie_phase", {}).get("home") == "authenticated_1"
                and getattr(auth, "_live_home_login_pay_count", 0) >= 1
                and hasattr(auth, "advance_live_cookie_phase")):
            # The first post-login pay and userinfo share the same direct-home
            # Cookie line; rotate only after userinfo for the next pay.
            auth.advance_live_cookie_phase("home", "authenticated_2")
        return result

    @staticmethod
    def home_list(auth, **kwargs) -> dict:
        """直播首页列表。"""
        return KuaishouLiveAPI._get(auth, "/live_api/home/list",
                                    referer=f'{KuaishouLiveAPI.live_url}/',
                                    cookie_profile=_home_cookie_profile(auth, "initial"))

    @staticmethod
    def category_simple(auth, **kwargs) -> dict:
        """分类简表。"""
        eid = kwargs.get("eid", "")
        return KuaishouLiveAPI._get(
            auth, "/live_api/category/simple", eid=eid,
            referer=kwargs.get("referer") or
            (KuaishouLiveAPI.room_referer(eid) if eid else f'{KuaishouLiveAPI.live_url}/'),
            cookie_profile=kwargs.get("cookie_profile") or
            _current_live_profile(
                auth, kwargs.get("referer") or
                (KuaishouLiveAPI.room_referer(eid) if eid
                 else f'{KuaishouLiveAPI.live_url}/')))

    @staticmethod
    def home_category(auth, **kwargs) -> dict:
        """直播首页点击分类后的当前分类数据。"""
        return KuaishouLiveAPI._get(
            auth, "/live_api/home/category",
            referer=f'{KuaishouLiveAPI.live_url}/',
            cookie_profile=kwargs.get("cookie_profile") or
            _home_cookie_profile(auth, "authenticated_3" if
                                 _live_only_session(auth) else "authenticated_2"))


def _safe_json(resp) -> dict:
    """容错解析响应 JSON。"""
    try:
        return resp.json()
    except Exception:
        logger.warning(f"[live] 响应非 JSON: {resp.status_code} {(resp.text or '')[:180]}")
        return {}
