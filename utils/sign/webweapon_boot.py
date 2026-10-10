#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""webweapon 引导换票（``POST https://gdfp.gifshow.com/s/w/c``）。

这一步以前是缺的：``kwfv1`` / ``kwscode`` / ``kwssectoken`` 三个 cookie **不是**
纯本地算出来的，SDK 启动时必须先跟 gdfp 换一次票，拿到两个脚本地址和 secToken。

对应 captcha-vendors.js 里的 ``fetchConfig``（@435294）::

    r = {productName, ts: Date.now(), did};
    o = at(JSON.stringify(r));
    xhr.open("POST", host + "/s/w/c"); xhr.send(JSON.stringify({data: o}));
    // 响应：AES-128-CBC(key=IV="webweaponconfigs") + PKCS7 + base64
    cfg = JSON.parse(decrypt(resp.dataRsp));

然后 ``handleSignature(cfg.signUrl, cfg.secToken)``::

    window.kwscb = t => { setCookie("kwssectoken", secToken, {expires: 6/1440});
                          setCookie("kwscode",     t,        {expires: 6/1440}); };
    loadScript(cfg.signUrl);        // 脚本跑完回调 kwscb 交出 kwscode

``6/1440`` 天正好 6 分钟，和实测的 cookie 有效期吻合。
"""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.parse
from dataclasses import dataclass, field

from Crypto.Cipher import AES

# captcha-vendors.js 里 `d = "webweaponconfigs"`，既当密钥又当 IV
CONFIG_KEY = b"webweaponconfigs"

GDFP_HOSTS = {
    "production": "https://gdfp.gifshow.com",
    "test": "https://infra-gdfp.test.gifshow.com",
    "kwai": "https://g-gdfp.kwai-pro.com",
}
CONFIG_PATH = "/s/w/c"
FINGERPRINT_REPORT_PATH = "/s/w/p"

# 各站的 productName（cookie kwpsecproductname 里也是这个值）
PRODUCT_WWW = "kuaishou-vision"
PRODUCT_CP = "onvideo-cp"
# 验证码 iframe 使用独立的 webweapon 产品名。它与业务页的
# ``kuaishou-vision`` 票据并存，不能把两者合并后再发到 captcha 域。
PRODUCT_CAPTCHA = "verification-captcha"

COOKIE_TTL_SECONDS = 6 * 60          # SDK 写的是 expires: 6/1440 天
RESPONSE_CONTENT_TYPE = "application/json;charset=UTF-8"
PREFLIGHT_MAX_AGE_SECONDS = 1800
PREFLIGHT_CACHE_ATTR = "_ks_gdfp_swc_preflight_cache"
# The captured Chrome route negotiated HTTP/2, but the service can currently
# answer the same endpoint over HTTP/1.1 from some networks.  Keep the strict
# contract available for forensic/replay runs while allowing the normal QR
# flow to continue when the only drift is the negotiated protocol.
ENV_STRICT_HTTP2 = "KS_STRICT_GDFP_HTTP2"


def _browser_user_agent() -> str:
    from utils.fingerprint import get_profile
    return get_profile()["ua"]


def _strict_http2() -> bool:
    """Whether a gdfp HTTP/1.1 downgrade should fail closed.

    The default is permissive for functionality (HTTP/2 remains preferred by
    the curl_cffi transport).  Set ``KS_STRICT_GDFP_HTTP2=1`` when exact
    Chrome wire parity is required and a downgrade must abort before minting
    tickets.
    """
    return str(os.environ.get(ENV_STRICT_HTTP2, "")).strip().lower() in {
        "1", "true", "yes", "on",
    }


def _pkcs7(data: bytes) -> bytes:
    pad = 16 - len(data) % 16
    return data + bytes([pad]) * pad


def _unpad(data: bytes) -> bytes:
    pad = data[-1]
    if not 1 <= pad <= 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("PKCS7 padding 不合法，密钥或密文不对")
    return data[:-pad]


def encrypt_payload(plain: str) -> str:
    """``at()``：AES-128-CBC(key=IV=webweaponconfigs) + PKCS7，输出 base64。"""
    cipher = AES.new(CONFIG_KEY, AES.MODE_CBC, CONFIG_KEY)
    return base64.b64encode(cipher.encrypt(_pkcs7(plain.encode("utf-8")))).decode()


def decrypt_payload(blob: str) -> str:
    """响应侧的逆运算。"""
    cipher = AES.new(CONFIG_KEY, AES.MODE_CBC, CONFIG_KEY)
    return _unpad(cipher.decrypt(base64.b64decode(blob))).decode("utf-8")


@dataclass
class WeaponConfig:
    """``/s/w/c`` 换回来的配置。"""

    fp_url: str = ""                 # kwf 脚本：生成 kwfv1
    sign_url: str = ""               # kws 脚本：生成 kwscode
    sec_token: str = ""              # 直接作为 kwssectoken cookie
    script_switch: bool = True
    is_visible_report: bool = True
    log_uris: list = field(default_factory=list)
    related_uris: list = field(default_factory=list)
    fetched_at: float = 0.0
    raw: dict = field(default_factory=dict)
    http_version: str = ""

    @property
    def expired(self) -> bool:
        return time.time() - self.fetched_at > COOKIE_TTL_SECONDS

    @classmethod
    def from_dict(cls, data: dict) -> "WeaponConfig":
        return cls(
            fp_url=data.get("fpUrl", ""),
            sign_url=data.get("signUrl", ""),
            sec_token=data.get("secToken", ""),
            script_switch=bool(data.get("scriptSwitch", True)),
            is_visible_report=bool(data.get("isVisibleReport", True)),
            log_uris=list(data.get("logUris") or []),
            related_uris=list(data.get("releatedUris") or []),
            fetched_at=time.time(),
            raw=data,
        )


def build_request_body(did: str, product_name: str = PRODUCT_WWW,
                       now_ms: int | None = None) -> str:
    """拼 ``{"data": "<密文>"}``。

    明文键顺序照抄源码 ``{productName, ts, did}``，不要排序 —— JSON 是
    按插入顺序序列化的，顺序变了密文就和浏览器不一样。
    """
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    plain = json.dumps({"productName": product_name, "ts": now_ms, "did": did},
                       ensure_ascii=False, separators=(",", ":"))
    return json.dumps({"data": encrypt_payload(plain)},
                      ensure_ascii=False, separators=(",", ":"))


def parse_response(text: str) -> WeaponConfig:
    """解 ``{"dataRsp": "...", "result": 1, "error_msg": ""}``。"""
    envelope = json.loads(text)
    if envelope.get("result") != 1:
        raise RuntimeError(f"gdfp 换票失败: result={envelope.get('result')} "
                           f"{envelope.get('error_msg')!r}")
    return WeaponConfig.from_dict(json.loads(decrypt_payload(envelope["dataRsp"])))


def _response_header(response, name: str) -> str:
    """Read a response header case-insensitively from either HTTP client."""
    headers = getattr(response, "headers", None)
    if headers is None:
        return ""
    wanted = str(name).lower()
    try:
        for key, value in headers.items():
            if str(key).lower() == wanted:
                return str(value or "")
    except AttributeError:
        pass
    try:
        return str(headers.get(name, "") or headers.get(wanted, ""))
    except AttributeError:
        return ""


def _response_body_bytes(response) -> bytes:
    value = getattr(response, "content", None)
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    return str(getattr(response, "text", "") or "").encode("utf-8")


def _preflight_cache(http) -> dict:
    """Return the session-local preflight cache without leaking global state."""
    cache = getattr(http, PREFLIGHT_CACHE_ATTR, None)
    if not isinstance(cache, dict):
        cache = {}
        try:
            setattr(http, PREFLIGHT_CACHE_ATTR, cache)
        except Exception:  # pragma: no cover - exotic immutable diagnostic fakes
            return {}
    return cache


def _is_real_curl_session(http) -> bool:
    """Recognize curl_cffi sessions without treating arbitrary fakes as live."""
    module = type(http).__module__.lower()
    return (module.startswith("curl_cffi.")
            and callable(getattr(http, "options", None))
            and bool(getattr(http, "_ks_shared_transport", False)))


def _ensure_cors_preflight(http, *, url: str, origin: str, referer: str,
                           timeout: float) -> None:
    """Run the browser's one-shot CORS preflight for ``POST /s/w/c``.

    Chrome caches this result for the server-provided 1800 seconds.  The key
    intentionally includes the exact URL, origin and page Referer because the
    same shared transport can serve www, CP and captcha iframe sessions.  A
    preflight is only called for the real shared session; injected fixture
    sessions are kept deterministic and are validated by their own contracts.
    """
    import time as _time
    from utils.transport import http_version_label, is_http11, is_http2

    cache = _preflight_cache(http)
    key = (str(origin), str(referer), str(url))
    now = _time.monotonic()
    expires = cache.get(key)
    if isinstance(expires, (int, float)) and expires > now:
        return
    cache.pop(key, None)

    options = getattr(http, "options", None)
    if not callable(options):
        raise RuntimeError(
            "gdfp /s/w/c CORS preflight unavailable; refusing HTTP/2 POST")
    # Keep this application-header order aligned with the captured Chrome
    # preflight.  The captured H2 OPTIONS carries the same ``priority``
    # pseudo/application hint as the following cross-site POST.  We only run
    # this path after selecting the real shared browser transport.
    headers = {
        "accept": "*/*",
        "access-control-request-headers": "content-type",
        "access-control-request-method": "POST",
        "origin": origin,
        "sec-fetch-mode": "cors",
        "user-agent": _browser_user_agent(),
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,ja;q=0.6",
        "priority": "u=1, i",
        "referer": referer,
        "sec-fetch-dest": "empty",
        "sec-fetch-site": "cross-site",
    }
    response = options(url, headers=headers, timeout=timeout)
    response.raise_for_status()
    status = getattr(response, "status_code", None)
    if status != 200:
        raise RuntimeError(
            f"gdfp /s/w/c CORS preflight HTTP status drift: {status!r}")
    if _response_body_bytes(response) != b"":
        raise RuntimeError("gdfp /s/w/c CORS preflight body drift: expected empty")
    expected_headers = {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "POST",
        "access-control-allow-headers": "content-type",
        "access-control-max-age": "1800",
    }
    for name, expected in expected_headers.items():
        actual = _response_header(response, name)
        if actual != expected:
            raise RuntimeError(
                f"gdfp /s/w/c CORS preflight {name} drift: {actual!r}")
    content_length = _response_header(response, "content-length")
    if content_length not in {"", "0"}:
        raise RuntimeError(
            f"gdfp /s/w/c CORS preflight content-length drift: {content_length!r}")
    version = getattr(response, "http_version", "")
    if not is_http2(version):
        # HTTP/1.1 is a supported functional fallback for this endpoint.  It
        # is still recorded in the returned config and can be rejected by
        # callers that enable the forensic strict switch.
        if not is_http11(version) or _strict_http2():
            raise RuntimeError(
                "gdfp /s/w/c CORS preflight did not negotiate captured HTTP/2; "
                f"actual http_version={http_version_label(version) or 'unknown'}")
    cache[key] = now + PREFLIGHT_MAX_AGE_SECONDS


def fetch_config(did: str, product_name: str = PRODUCT_WWW,
                 referer: str = "https://www.kuaishou.com/",
                 env: str = "production", session=None,
                 timeout: float = 15.0) -> WeaponConfig:
    """真去换一次票。头顺序照抄实抓（referer 在 accept 之前）。"""
    # The current browser contract for the cross-site bootstrap is HTTP/2.
    # curl_cffi still prefers that negotiation, while the normal functional
    # path permits an HTTP/1.1 response when the service/network selects it.
    # Set KS_STRICT_GDFP_HTTP2=1 to restore the old fail-closed behavior.
    if session is None:
        # Normal program traffic must use the shared curl_cffi Chrome
        # impersonation session; requests is retained only when a caller
        # explicitly injects a diagnostic fake/session.
        from utils.transport import shared_session
        http = shared_session()
    else:
        http = session
    url = GDFP_HOSTS.get(env, GDFP_HOSTS["production"]) + CONFIG_PATH
    parsed_referer = urllib.parse.urlsplit(referer)
    if parsed_referer.scheme not in {"http", "https"} or not parsed_referer.netloc:
        raise ValueError(f"无效 webweapon Referer: {referer!r}")
    # Origin never contains the page path/query.  KwwSigner passes full page
    # hrefs (CP publish route and captcha iframe included), so ``rstrip('/')``
    # would emit an impossible Origin such as ``https://host/path``.
    origin = f"{parsed_referer.scheme}://{parsed_referer.netloc}"
    if _is_real_curl_session(http):
        _ensure_cors_preflight(
            http, url=url, origin=origin, referer=referer, timeout=timeout)
    body = build_request_body(did, product_name).encode("utf-8")
    # gdfp /s/w/c is the one current browser sample on this path that
    # negotiated HTTP/2 and exposed Chrome's request priority. Keep its
    # application header insertion order separate from same-origin www
    # traffic (which is HTTP/1.1 and has no priority).
    headers = {
        "user-agent": _browser_user_agent(),
        "content-type": "application/json",
        "referer": referer,
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,ja;q=0.6",
        "origin": origin,
        "priority": "u=1, i",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "cross-site",
    }
    resp = http.post(url, data=body, headers=headers, timeout=timeout)
    resp.raise_for_status()
    if getattr(resp, "status_code", None) != 200:
        raise RuntimeError(
            f"gdfp /s/w/c HTTP 状态偏离当前成功样本 200: "
            f"{getattr(resp, 'status_code', None)!r}")
    response_headers = getattr(resp, "headers", None)
    content_type = ""
    if response_headers is not None:
        try:
            content_type = str(response_headers.get("content-type", "") or
                               response_headers.get("Content-Type", ""))
        except AttributeError:
            content_type = ""
    if content_type != RESPONSE_CONTENT_TYPE:
        raise RuntimeError(
            f"gdfp /s/w/c Content-Type 偏离当前 Chrome: {content_type!r}")
    cfg = parse_response(resp.text)
    # curl_cffi exposes the negotiated protocol as a CurlHttpVersion/integer
    # (3 for HTTP/2; 2 is HTTP/1.1). Normalize it only after validating the
    # raw enum so callers never invert those two values.
    version = getattr(resp, "http_version", "")
    from utils.transport import http_version_label, is_http11, is_http2
    cfg.http_version = http_version_label(version)
    if not is_http2(version) and (not is_http11(version) or _strict_http2()):
        raise RuntimeError(
            "gdfp /s/w/c 未协商浏览器要求的 HTTP/2，拒绝继续生成 webweapon 票据"
            f"（实际 http_version={cfg.http_version or 'unknown'}）"
        )
    return cfg


def report_fingerprint(did: str, product_name: str = PRODUCT_CP,
                       referer: str = "https://cp.kuaishou.com/",
                       href: str | None = None, cookie: str = "",
                       kwfcv1: str = "", current_kwfv1: str = "",
                       session=None, timeout: float = 15.0) -> str:
    """Replay Chrome's official ``getData(1) -> POST /s/w/p -> wid`` chain.

    The server response is ``{"c": 200, "r": "<17-digit wid>"}``.  The
    returned value is accepted only in that observed shape; callers persist
    it as the root-domain ``wid`` cookie.  No local/random wid is generated.
    """
    from utils.sign import weapon_oracle

    page_href = href or referer
    report = weapon_oracle.gen_fingerprint_report(
        did=did, href=page_href, cookie=cookie,
        kwfcv1=kwfcv1, current_kwfv1=current_kwfv1)
    if not report:
        raise RuntimeError("official kwf getData(1) did not produce fingerprint report")
    payload = {
        "1": did,
        "2": product_name,
        "9": int(time.time() * 1000),
        "data": report,
        "p": "w",
    }
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if session is None:
        from utils.transport import shared_session
        http = shared_session()
    else:
        http = session
    headers = {
        "user-agent": _browser_user_agent(),
        "content-type": "application/json",
        "referer": referer,
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "zh-CN,zh;q=0.9",
        "origin": referer.rstrip("/"),
        "priority": "u=1, i",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "cross-site",
    }
    response = http.post(GDFP_HOSTS["production"] + FINGERPRINT_REPORT_PATH,
                         data=body, headers=headers, timeout=timeout)
    response.raise_for_status()
    data = response.json()
    wid = str(data.get("r") or "") if data.get("c") == 200 else ""
    if len(wid) != 17 or not wid.isdigit():
        raise RuntimeError(f"gdfp fingerprint report rejected: {data!r}")
    return wid
