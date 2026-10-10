#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""统一的浏览器传输层：由 ALPN 协商协议并冒充 Chrome TLS 指纹。

为什么必须换掉 ``requests``（2026-08-16 用 https://tls.peet.ws/api/all 实测）::

    真实 Chrome 151          h2   ja4=t13d1517h2_8daaf6152771_a87ad97598a9
                                  akamai=1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
    requests                 h1   ja4=t13d1812h1_85036bcba153_375ca2c5e164   0/5 项相同
    httpx(h2)                h2   ja4=t13d1812h1_85036bcba153_1f22a2ca17c4   1/5 项相同
    curl_cffi chrome150      h2   当前 Chrome 151 完整握手/恢复握手两种 JA4、
                                  peetprint 与 Akamai H2 均一致

    ``requests`` 在 TLS 测试站既没有 Chrome TLS，也没有 Chrome 的 h2 行为。当前
快手业务域名则由 Chrome 与 curl_cffi 都协商为 HTTP/1.1；不能把测试站的 h2 结论
错误推广成“全站强制 h2”。``curl_cffi`` 的价值是复现 Chrome TLS/ALPN/HTTP 指纹。
当前 Chrome 会随机排列 TLS extensions，所以单次 JA3 hash 天生不固定。按正确的
对齐口径比较 JA3 非扩展组件、扩展集合、首次/恢复握手、JA4、peetprint 和 Akamai H2；
运行时只依赖 ``curl_cffi`` 的 Chrome impersonation，不读取本地浏览器配置或抓包文件。

用法::

    from utils.transport import new_session
    http = new_session()            # 之后当 requests.Session 用即可
"""

from __future__ import annotations

import numbers
import os

# curl_cffi 当前支持列表中与真实 Chrome 151 最接近的最新目标。
# 当前 Chrome 151 的 TLS 模板与 curl_cffi chrome150 在首次/恢复握手两种模式下
# 对齐；名字是 curl_cffi 的模板标签，不等于浏览器 UA 主版本。
DEFAULT_IMPERSONATE = "chrome150"

# 仅显式诊断时允许退回 requests；正常业务请求缺少 curl_cffi 必须立即失败，
# 否则程序会静默从 Chrome TLS/ALPN 退化为 Python requests 指纹。
ENV_FORCE_REQUESTS = "KS_FORCE_REQUESTS"


def impersonate_target() -> str:
    return os.environ.get("KS_IMPERSONATE", DEFAULT_IMPERSONATE)


def browser_transport_available() -> bool:
    if os.environ.get(ENV_FORCE_REQUESTS):
        return False
    try:
        import curl_cffi.requests  # noqa: F401
    except Exception:                                  # noqa: BLE001
        return False
    return True


# 兼容旧调用名；它现在表示 curl_cffi 浏览器传输可用，不承诺目标域名协商 h2。
h2_available = browser_transport_available


def new_session(impersonate: str | None = None):
    """产出一个会话对象。

    正常模式强制使用 ``curl_cffi``（Chrome TLS/ALPN 指纹，HTTP 版本由目标站与
    浏览器模板协商）。只有调用者
    显式设置 ``KS_FORCE_REQUESTS=1`` 做传输层诊断时才允许退回 ``requests``；
    依赖缺失时绝不静默降级。

    :param impersonate: 覆盖默认的冒充目标。
    """
    if browser_transport_available():
        from curl_cffi import requests as creq
        # default_headers=False 很关键：impersonate 默认会自己塞一套头
        # （sec-ch-ua* / upgrade-insecure-requests / sec-fetch-user）并排在最前，
        # 把调用方精心排好的顺序打乱。而 Chrome 对快手并不发这些 —— 客户端提示
        # 要服务端用 Accept-CH 主动 opt-in，快手没开（CDP 实抓里也没有这些头）。
        # 关掉之后线序完全由我们控制，TLS/h2 指纹不受影响。
        return creq.Session(impersonate=impersonate or impersonate_target(),
                            default_headers=False)
    if not os.environ.get(ENV_FORCE_REQUESTS):
        raise RuntimeError(
            "缺少必需依赖 curl_cffi>=0.16.1；严格浏览器对齐禁止静默回退 "
            "requests/Python TLS。仅诊断时可显式设置 KS_FORCE_REQUESTS=1")
    import requests
    session = requests.Session()
    # requests 默认头不一定匹配当前 Chrome；诊断模式至少不预置这些字段。
    session.headers.pop("Connection", None)
    session.headers.pop("Accept-Encoding", None)
    session.headers.pop("Accept", None)
    session.headers.pop("User-Agent", None)
    return session


_SHARED = None


def shared_session():
    """进程内共享的会话，各站 API 都用这一个，省掉重复握手。"""
    global _SHARED
    if _SHARED is None:
        _SHARED = new_session()
        # Mark the process-wide browser transport so protocol-specific helpers
        # can distinguish it from explicitly injected diagnostic sessions.
        try:
            setattr(_SHARED, "_ks_shared_transport", True)
        except Exception:  # pragma: no cover - defensive for custom sessions
            pass
    return _SHARED


class _HttpProxy:
    """把 ``requests.get/post`` 接管到 h2 共享会话，其余属性透传给真 ``requests``。

    这样有三个好处：

    1. 调用点写法不变，各站 API 里仍然是 ``requests.post(...)``；
    2. ``requests.exceptions`` / ``requests.packages`` / ``requests.Session``
       这些还能正常用；
    3. 离线拦包的工具照旧 ``mod.requests.post = fake`` 就能打桩
       —— 赋值会在实例上盖住方法。
    """

    def __init__(self, real):
        object.__setattr__(self, "_real", real)

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_real"), name)

    def get(self, *args, **kwargs):
        return shared_session().get(*args, **kwargs)

    def post(self, *args, **kwargs):
        return shared_session().post(*args, **kwargs)

    def request(self, *args, **kwargs):
        return shared_session().request(*args, **kwargs)


def http_proxy(real_requests):
    """各站 API 模块里 ``requests = http_proxy(requests)`` 即可接管传输层。"""
    return _HttpProxy(real_requests)


def request_errors() -> tuple:
    """可用于 ``except`` 的网络异常基类元组，覆盖当前可能的两种传输层。

    ``except requests.RequestException`` 在 curl_cffi 下抓不到任何东西
    （它抛的是 ``curl_cffi.requests.RequestsError``），重试/换 endpoint 会失效。
    """
    import requests as _requests
    errors = [_requests.RequestException]
    try:
        from curl_cffi.requests import RequestsError
    except Exception:                                  # noqa: BLE001
        pass
    else:
        errors.append(RequestsError)
    return tuple(errors)


def response_cookies(resp) -> dict:
    """取一个响应 Set-Cookie 下发的 ``{名: 值}``，两种传输层都能用。

    两边的迭代协议不同，直接 ``{c.name: c.value for c in resp.cookies}`` 会在
    curl_cffi 下抛 ``AttributeError: 'str' object has no attribute 'name'``：

    - ``requests``：``RequestsCookieJar`` 迭代出 Cookie 对象；
    - ``curl_cffi``：``Cookies`` 是 ``MutableMapping[str, str]``，迭代出键名，
      真正的 ``CookieJar`` 在 ``.jar`` 上。
    """
    jar = getattr(resp, "cookies", None)
    if not jar:
        return {}
    raw = getattr(jar, "jar", jar)
    try:
        return {c.name: c.value for c in raw}
    except AttributeError:
        return dict(jar)


def _curl_http_version_value(version):
    """Return a curl/libcurl protocol enum value when one is unambiguous.

    ``curl_cffi.Response.http_version`` is a ``CurlHttpVersion``/integer, where
    2 means HTTP/1.1 and 3 means HTTP/2.  Treating ``str(version) == "2"`` as
    HTTP/2 silently inverts the contract. Named textual values (``"h2"`` /
    ``"HTTP/1.1"``) remain supported for fixtures.
    """
    if isinstance(version, bool):
        return None
    if isinstance(version, numbers.Integral):
        return int(version)
    # curl_cffi exposes an int, but small test/fallback adapters often
    # serialize it before handing the response to us.  Only accept the
    # protocol enum values here; textual protocol names are handled below.
    if isinstance(version, str):
        value = version.strip()
        if value in {"0", "1", "2", "3", "4", "5", "30", "31"}:
            return int(value)
    return None


def is_http2(version) -> bool:
    """Whether a response protocol value denotes HTTP/2 (not HTTP/3)."""
    numeric = _curl_http_version_value(version)
    if numeric is not None:
        try:
            from curl_cffi.const import CurlHttpVersion
        except Exception:  # noqa: BLE001
            return numeric == 3
        return numeric == int(CurlHttpVersion.V2_0)
    return str(version or "").strip().lower() in {
        "2.0", "h2", "http/2", "http/2.0",
    }


def is_http11(version) -> bool:
    """Whether a response protocol value denotes HTTP/1.1."""
    numeric = _curl_http_version_value(version)
    if numeric is not None:
        try:
            from curl_cffi.const import CurlHttpVersion
        except Exception:  # noqa: BLE001
            return numeric == 2
        return numeric == int(CurlHttpVersion.V1_1)
    return str(version or "").strip().lower() in {"1.1", "http/1.1"}


def http_version_label(version) -> str:
    """Normalize a response protocol for logs/results without losing meaning."""
    if is_http2(version):
        return "h2"
    if is_http11(version):
        return "http/1.1"
    return str(version or "")


def describe() -> str:
    """给日志/回归用的一行说明。"""
    if browser_transport_available():
        return f"curl_cffi Chrome TLS/ALPN impersonate={impersonate_target()}"
    if os.environ.get(ENV_FORCE_REQUESTS):
        return "requests HTTP/1.1（仅显式 KS_FORCE_REQUESTS 诊断模式）"
    return "curl_cffi 不可用（正常请求会立即失败，禁止静默 HTTP/1.1 回退）"
