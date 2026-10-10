#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""gdfp manMachine 预检（滑块验证码提交前必须先上报的行为遥测）。

浏览器在提交 ``kSecretApiVerify`` **之前**会先打一串 gdfp（2026-08-16 CDP 实抓）::

    POST gdfp.gifshow.com/s/u/v?…&bussType=manMachine&…&type=SDK_INIT
    POST gdfp.gifshow.com/n/a/b?…&bussType=manMachine&…      ← 6028 字节行为遥测
    POST gdfp.gifshow.com/p/z/s?…

不做这一步直接提交 verify，服务端回 ``350014 anti check err``
（推断：它拿这次遥测里的 ``identity`` UUID 跟后续 verify 做关联）。

--------------------------------------------------------------------------
签名（``weblogger.2e328f42.js`` 明文，非混淆）
--------------------------------------------------------------------------
::

    AppKeyAndSecretKey.production = {appKey: "10001001",
                                     secretKey: "f2fff381c551a8dcdb765e316f3d44ac"}
    Hosts.production = "https://gdfp.gifshow.com"
    Urls = {report: "/p/z/s", strategy: "/s/u/v"}
    CoreDataLoggerId = "10001002"
    RM_VERSION = "1.6.0"

    function getReportUrl(o) {
        var ts = ((new Date).valueOf() / 1e3).toFixed();
        var sign = md5(appKey + secretKey + ts);
        var path = o.reportUrls ? o.reportUrls[rand] : Urls.report;
        return host + path + "?appkey=" + appKey + "&seckey=" + secretKey
             + "&bussType=" + o.bussType + "&timestamp=" + ts + "&sign=" + sign;
    }

用两条实抓的 timestamp 反算 sign，**逐字符一致**（已在 selftest 里固化成回归）。

``/n/a/b`` 这个路径不在 ``Urls`` 里，来自 ``options.reportUrls``
——captcha iframe 初始化 gdfp SDK 时传进去的数组，三个 bundle 里都搜不到
（运行时拼的），所以这里直接写死。

--------------------------------------------------------------------------
body（``RiskMgt.generateCoreModuleSection`` 逐字段还原）
--------------------------------------------------------------------------
外层 ``{"flag": 2, "data": "<base64(JSON)>"}``，内层字段号含义::

    1  referUrl（父页 url）        2  location.href（iframe url）
    3  network_package.ip          5  sessionId
    7  cookie 解析成的 dict         8  分辨率 "2560x1440"
    11 device_package.ua           16 identity_package.user_id
    17 identity_package.device_id（= did）
    28 sha1(did + referUrl + 分辨率 + ua + href)
    33 appCodeName  34 appName  35 appVersion  36 platform
    55 webdriver?1:0              56 userAgent
    69 canvas 指纹 hash            75 webdriver?"0":"1"   76 webdriver 字符串
    77 detectjsFiles()（页面加载过的 js 列表）
    79 printCallStack()
    82 {cf,ch,ff,fh,el,eh,ci,ih}  各原生函数 toString 的长度与 md5
    89 ts 计时块                   102 history.length     108 location

顶层再包一层::

    {"1": did, "3": "10001002", "6": "manMachine", "7": 10,
     "9": 毫秒时间戳, "10": "", "12": "10001001", "13": "", "14": "1.6.0",
     "module_section": [ <上面那个 moduleSection> ]}
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import string
import time
import uuid
from urllib.parse import urlsplit

# weblogger.2e328f42.js 明文常量
APP_KEY = "10001001"
SECRET_KEY = "f2fff381c551a8dcdb765e316f3d44ac"
CORE_DATA_LOGGER_ID = "10001002"
RM_VERSION = "1.6.0"
HOST = "https://gdfp.gifshow.com"
URL_REPORT = "/p/z/s"
URL_STRATEGY = "/s/u/v"
# captcha iframe 初始化时通过 options.reportUrls 传进来的（bundle 里搜不到，实抓得知）
URL_CORE_REPORT = "/n/a/b"
BUSS_TYPE_MAN_MACHINE = "manMachine"
BUSS_TYPE_GAME_LIVE = "gameLive"
BUSS_TYPE_VISION = "com.vision.gifshow"
RM_VERSION_GAME_LIVE = "1.4.0"
FLAG = 2
RESPONSE_CONTENT_TYPE = "application/json;charset=UTF-8"
MAN_MACHINE_INIT_RESPONSE = (
    b'{"result":1,"error_msg":"","antispamPluginRsp":'
    b'"eyJzd2l0Y2giOjEsIm1heEJhdGNoTGVuZ3RoIjo1MCwid2FpdCI6MTAwMCwiZW5hYmxlTmF0aXZlIjoxLCJqc3ZlciI6IjEuMC4xIiwicmVwb3J0Q29uZmlnIjp7InJlcG9ydFVybHMiOlsiL24vYS9iIl19LCJwb2xpY3lJZCI6MjU0LCJwdmVyIjoiMS4wLjIiLCJzdGF0dXMiOjF9"}'
)
REPORT_RESPONSE = b'{"result":1,"error_msg":""}'
ENV_STRICT_HTTP2 = "KS_STRICT_GDFP_HTTP2"

GAME_LIVE_INIT_CONFIG = {
    "switch": 1,
    "maxBatchLength": 50,
    "wait": 1000,
    "enableNative": 0,
    "jsver": "1.0.1",
    "reportConfig": {"reportUrls": ["/n/a/b"]},
    "policyId": 277,
    "pver": "1.0.2",
    "status": 1,
}

MAN_MACHINE_INIT_CONFIG = {
    "switch": 1,
    "maxBatchLength": 50,
    "wait": 1000,
    "enableNative": 1,
    "jsver": "1.0.1",
    "reportConfig": {"reportUrls": ["/n/a/b"]},
    "policyId": 254,
    "pver": "1.0.2",
    "status": 1,
}

CAPTCHA_SCRIPT_URLS = [
    "https://p23-plat.wskwai.com/kos/nlav111449/technology-platform/static/captcha/js/weblogger.2e328f42.js",
    "https://p23-plat.wskwai.com/kos/nlav111449/technology-platform/static/captcha/js/chunk-vendors.39300a01.js",
    "https://p23-plat.wskwai.com/kos/nlav111449/technology-platform/static/captcha/js/encrypt.ee7d2a41.js",
    "https://p23-plat.wskwai.com/kos/nlav111449/technology-platform/static/captcha/js/iframe/index.c9ae8c81.js",
]
PLUGIN_LIST = json.dumps([
    {"name": "PDF Viewer", "filename": "internal-pdf-viewer",
     "description": "Portable Document Format"},
    {"name": "Chrome PDF Viewer", "filename": "internal-pdf-viewer",
     "description": "Portable Document Format"},
    {"name": "Chromium PDF Viewer", "filename": "internal-pdf-viewer",
     "description": "Portable Document Format"},
    {"name": "Microsoft Edge PDF Viewer", "filename": "internal-pdf-viewer",
     "description": "Portable Document Format"},
    {"name": "WebKit built-in PDF", "filename": "internal-pdf-viewer",
     "description": "Portable Document Format"},
], separators=(",", ":"))
MIME_LIST = json.dumps([
    {"type": "application/pdf", "description": "Portable Document Format"},
    {"type": "text/pdf", "description": "Portable Document Format"},
], separators=(",", ":"))
PERMISSION_STATES = [
    {"permissionName": name, "state": state} for name, state in (
        ("speaker", "error"), ("device-info", "error"),
        ("bluetooth", "error"), ("ambient-light-sensor", "error"),
        ("clipboard", "error"), ("nfc", "error"),
        ("geolocation", "denied"), ("notifications", "denied"),
        ("push", "denied"), ("midi", "denied"),
        ("camera", "denied"), ("microphone", "denied"),
        ("background-fetch", "prompt"), ("background-sync", "granted"),
        ("persistent-storage", "prompt"), ("accelerometer", "granted"),
        ("gyroscope", "granted"), ("magnetometer", "granted"),
        ("display-capture", "denied"),
    )
]
CORE_NATIVE_FINGERPRINT = {
    "cf": 585, "ch": "3b4de2be29905d2bcc3812d4fa039bc3",
    "ff": 166, "fh": "7daf378bafe0d3babac2696177d5de0d",
    "el": 33, "eh": "dc4d3e06840e103f3e77747a82029aa9",
}
WHOLE_NATIVE_FINGERPRINT = {
    "pc": 134, "ph": "594d639a69bb0bdf419c1c14ccbb560a",
    "wf": 1159, "wh": "6a9ba63fd2cbda1ce03b5204db881cac",
    "cf": 585, "ch": "3b4de2be29905d2bcc3812d4fa039bc3",
    "mf": 1052, "mh": "3bbcec74126d8f15aa514a6c7b4179f8",
    "ff": 166, "fh": "7daf378bafe0d3babac2696177d5de0d",
    "af": 1031, "ah": "744f127aa70ee2cd33f97f47cf641a77",
    "gr": 598, "gh": "54a77c38470096d9684100f3909f3109",
    "el": 33, "eh": "dc4d3e06840e103f3e77747a82029aa9",
    "ow": 19748, "oh": "4f323cba12d2aba1b62665eb7b260b40",
    "ky": 33, "kh": "61792d30f54bedfe1007347e9fdc4223",
}


def sign_for(ts_seconds: str | int) -> str:
    """``md5(appKey + secretKey + 秒级时间戳)``。

    :param ts_seconds: 秒级时间戳（字符串或整数）。
    """
    return hashlib.md5(f"{APP_KEY}{SECRET_KEY}{ts_seconds}".encode()).hexdigest()


def build_url(path: str, buss_type: str = BUSS_TYPE_MAN_MACHINE,
              ts_seconds: int = None, extra: str = "") -> str:
    """拼 gdfp 请求 url（含 appkey / seckey / sign）。

    :param path: ``/n/a/b`` / ``/p/z/s`` / ``/s/u/v``。
    :param buss_type: 业务类型，验证码链路是 ``manMachine``。
    :param ts_seconds: 秒级时间戳，默认取当前。
    :param extra: 额外拼在末尾的 query（如 ``&type=SDK_INIT``）。
    """
    ts = int(time.time()) if ts_seconds is None else int(ts_seconds)
    return (f"{HOST}{path}?appkey={APP_KEY}&seckey={SECRET_KEY}"
            f"&bussType={buss_type}&timestamp={ts}&sign={sign_for(ts)}{extra}")


def _sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def _md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def _script_list(script_urls=None) -> list:
    out = list(CAPTCHA_SCRIPT_URLS)
    for url in script_urls or []:
        value = str(url or "")
        if value and value not in out:
            out.append(value)
    return out


def _browser_profile() -> dict:
    """Return the single browser profile shared by all anti-abuse payloads."""
    from utils.fingerprint import get_profile
    return get_profile()


def _profile_resolution(profile: dict) -> str:
    geo = profile.get("geo") or ()
    width = profile.get("screen_width") or (geo[6] if len(geo) > 6 else 2560)
    height = profile.get("screen_height") or (geo[7] if len(geo) > 7 else 1440)
    return f"{int(width)}x{int(height)}"


def _cookie_fingerprint(cookies: dict) -> dict:
    line = "; ".join(f"{key}={value}" for key, value in cookies.items())
    return {"ci": len(line), "ih": _md5(line)}


def _call_stack(kind: str = "core") -> str:
    base = CAPTCHA_SCRIPT_URLS[0]
    if kind == "whole":
        frames = (
            ("printCallStack", 34236), ("RiskMgt._this.generateModuleSection", 77458),
            ("RiskMgt.<anonymous>", 84095), ("", 4825), ("Object.next", 4930),
            ("", 3857), ("newPromise(<anonymous>)", None),
            ("__awaiter", 3602), ("RiskMgt.sendWholeData", 83975),
            ("RiskMgt.<anonymous>", 83076),
        )
    else:
        frames = (
            ("printCallStack", 34236),
            ("RiskMgt._this.generateCoreModuleSection", 79648),
            ("RiskMgt.<anonymous>", 83773), ("", 4825),
            ("Object.next", 4930), ("", 3857),
            ("newPromise(<anonymous>)", None), ("__awaiter", 3602),
            ("RiskMgt.sendCoreData", 83346), ("n", 82235),
        )
    result = []
    for name, offset in frames:
        if offset is None:
            result.append(f"at{name}")
        else:
            result.append(f"at{name}({base}:1:{offset})" if name
                          else f"at{base}:1:{offset}")
    return "".join(result)


def _timings(begin_ms: int, now_ms: int, whole: bool = False) -> dict:
    values = {
        "cs": begin_ms + 246, "ce": begin_ms + 250,
        "as": begin_ms + 255, "ae": begin_ms + 259,
        "cae": begin_ms + 338, "ls": now_ms,
    }
    if whole:
        values.update({"le": begin_ms + 472, "cre": begin_ms + 688,
                       "gs": begin_ms + 492, "ge": begin_ms + 515})
    return values


def build_core_payload(did: str, user_id: str, cookies: dict,
                       parent_url: str, iframe_url: str,
                       ua: str, resolution: str = None,
                       identity: str = None, now_ms: int = None,
                       begin_ms: int = None, session_id: str = None,
                       script_urls=None) -> dict:
    """造 ``/n/a/b`` 的内层 payload（``generateCoreModuleSection`` 的产物）。

    :param did: 设备标识（cookie 里的 did）。
    :param user_id: 账号 ID（cookie 里的 userId）。
    :param cookies: 完整 cookie dict（字段 7 原样带上）。
    :param parent_url: 父页 url（触发验证码的那个业务页）。
    :param iframe_url: 验证码 iframe 的完整 url。
    :param ua: User-Agent。
    :param resolution: 屏幕分辨率。
    :param identity: 本次会话的 UUID，不给就现生成。
    :param now_ms: 毫秒时间戳。
    :param begin_ms: SDK 初始化时刻（用于 initTime 与 ts 计时块）。
    """
    profile = _browser_profile()
    resolution = resolution or _profile_resolution(profile)
    now_ms = int(time.time() * 1000) if now_ms is None else int(now_ms)
    begin_ms = now_ms - random.randint(600, 1400) if begin_ms is None else int(begin_ms)
    identity = identity or str(uuid.uuid4())
    session_id = session_id or str(uuid.uuid4())
    field82 = dict(CORE_NATIVE_FINGERPRINT)
    field82.update(_cookie_fingerprint(cookies))

    module_section = {
        "1": {"page": parent_url, "identity": identity, "page_type": 2},
        "2": iframe_url,
        "5": session_id,
        "7": dict(cookies),
        "8": resolution,
        "11": ua,
        "17": did,
        "21": {"type": "PAGE_ENTER", "timestamp": now_ms - 20,
               "initTime": begin_ms},
        "28": _sha1(f"{did}{parent_url}{resolution}{ua}{iframe_url}"),
        "33": "Mozilla",
        "34": "Netscape",
        "35": ua.split("Mozilla/", 1)[-1] if "Mozilla/" in ua else ua,
        "36": profile.get("platform", "Win32"),
        "55": 0,
        "56": ua,
        "69": "0043c0b8a0b002e8133a140d14068859",
        "75": "1",
        "76": "",
        "77": _script_list(script_urls),
        "79": _call_stack("core"),
        "82": field82,
        "89": _timings(begin_ms, now_ms),
        "102": 50,
        "108": {},
    }
    return {
        "1": did,
        "3": CORE_DATA_LOGGER_ID,
        "6": BUSS_TYPE_MAN_MACHINE,
        "7": 10,
        "9": now_ms,
        "10": "",
        "12": APP_KEY,
        "13": "",
        "14": RM_VERSION,
        "module_section": [module_section],
    }


def _webrtc_fields() -> tuple[str, str]:
    """Generate the session-specific WebRTC candidate/SDP shape.

    Chrome uses fresh mDNS hostnames, ICE credentials, certificate
    fingerprint and ports for every iframe.  Replaying the captured values is
    itself a fingerprint mismatch, so retain the exact syntax but regenerate
    the ephemeral components on each report.
    """
    mdns1, mdns2 = f"{uuid.uuid4()}.local", f"{uuid.uuid4()}.local"
    port1, port2 = random.randint(50000, 59998), random.randint(50000, 59998)
    ufrag = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(4))
    pwd = "".join(random.choice(string.ascii_letters + string.digits + "+/") for _ in range(24))
    fingerprint = ":".join(f"{random.randrange(256):02X}" for _ in range(32))
    session = random.randint(10**18, 10**19 - 1)
    candidates = (
        f";candidate:1801140675 1 udp 2113937151 {mdns1} {port1} typ host "
        f"generation 0 ufrag {ufrag} network-cost 999"
        f";candidate:1070259456 1 udp 2113939711 {mdns2} {port2} typ host "
        f"generation 0 ufrag {ufrag} network-cost 999"
    )
    candidate1 = (
        f"a=candidate:1801140675 1 udp 2113937151 {mdns1} {port1} "
        "typ host generation 0 network-cost 999\r\n")
    candidate2 = (
        f"a=candidate:1070259456 1 udp 2113939711 {mdns2} {port2} "
        "typ host generation 0 network-cost 999\r\n")
    prefix = (
        f"v=0\r\no=- {session} 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"
        "a=group:BUNDLE 0\r\na=extmap-allow-mixed\r\na=msid-semantic: WMS\r\n"
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
        "c=IN IP4 0.0.0.0\r\n")
    suffix = (
        f"a=ice-ufrag:{ufrag}\r\na=ice-pwd:{pwd}\r\n"
        f"a=ice-options:trickle\r\na=fingerprint:sha-256 {fingerprint}\r\n"
        "a=setup:actpass\r\na=mid:0\r\na=sctp-port:5000\r\na=max-message-size:262144\r\n"
    )
    # Chrome's promise resolves once with the first host candidate and again
    # after the second one is gathered; the collector concatenates both SDP
    # snapshots.  Reqid 1256 therefore contains two ``;v=0`` blocks.
    sdp = f";{prefix}{candidate1}{suffix};{prefix}{candidate1}{candidate2}{suffix}"
    return candidates, sdp


def build_whole_payload(did: str, user_id: str, cookies: dict,
                        parent_url: str, iframe_url: str, ua: str,
                        resolution: str = None, identity: str = None,
                        now_ms: int = None, begin_ms: int = None,
                        session_id: str = None, script_urls=None,
                        report_path: str = URL_CORE_REPORT) -> dict:
    """Build the second, full ``sendWholeData`` `/n/a/b` report.

    Current Chrome emits this roughly one second after the smaller core
    report.  Field presence and insertion order follow reqid 1256; ephemeral
    UUID/WebRTC/timing values are regenerated rather than replayed.
    """
    profile = _browser_profile()
    resolution = resolution or _profile_resolution(profile)
    now_ms = int(time.time() * 1000) if now_ms is None else int(now_ms)
    begin_ms = now_ms - 1520 if begin_ms is None else int(begin_ms)
    identity = identity or str(uuid.uuid4())
    session_id = session_id or str(uuid.uuid4())
    candidates, sdp = _webrtc_fields()
    native = dict(WHOLE_NATIVE_FINGERPRINT)
    native.update(_cookie_fingerprint(cookies))
    scripts = _script_list(script_urls)
    module_section = {
        "1": {"page": parent_url, "identity": identity, "page_type": 2},
        "2": iframe_url,
        "4": "https://captcha.zt.kuaishou.com",
        "5": session_id,
        "6": "captcha",
        "7": dict(cookies),
        "8": resolution,
        "9": 360, "10": 360,
        "11": ua, "12": "NT 10.0", "13": "zh-CN", "14": "Windows",
        "17": did,
        "21": {"type": "PAGE_ENTER", "timestamp": begin_ms + 491,
               "initTime": begin_ms},
        "24": "10", "25": "10-1", "26": "0",
        "28": _sha1(f"{did}{parent_url}{resolution}{ua}{iframe_url}"),
        "29": report_path, "30": "production", "31": 1, "32": "0.00",
        "33": "Mozilla", "34": "Netscape",
        "35": ua.split("Mozilla/", 1)[-1] if "Mozilla/" in ua else ua,
        "36": profile.get("platform", "Win32"),
        "37": json.dumps(["zh-CN", "zh", "en", "zh-TW", "ja"],
                         separators=(",", ":")),
        "41": "20030107", "42": "Google Inc.",
        "43": "", "44": int(profile.get("cpu_core_num") or 20),
        "50": 10, "51": "", "52": 1, "53": "Gecko", "54": True,
        "55": 0, "56": ua, "57": "zh-CN",
        "58": PLUGIN_LIST, "59": MIME_LIST,
        "61": profile.get("webgl_vendor", "Google Inc. (NVIDIA)"),
        "62": profile.get("webgl_renderer", ""),
        "63": "1", "64": "WebKit",
        "65": "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
        "66": "WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)",
        "67": 0, "68": "f3bd24f5b153d57f5817372fd5f22573",
        "69": "0043c0b8a0b002e8133a140d14068859",
        "70": "ba6689f9a1550fb5eef25d1fc682c8c1",
        "75": "1", "76": "", "77": scripts,
        "78": {"w": {"pc": 1256, "kc": 255, "lc": 261},
               "n": {"pc": 0, "kc": 0, "lc": 82}},
        "79": _call_stack("whole"), "80": "2200", "81": "1032",
        "82": native, "85": candidates, "86": sdp,
        "87": {
            "w": int(profile.get("screen_width") or 2560),
            "h": int(profile.get("screen_height") or 1440),
            "c": 24, "p": 24,
        },
        "88": _md5(sdp), "89": _timings(begin_ms, now_ms, whole=True),
        "90": "", "100": 11, "101": {"lsc": 10, "ssc": 2},
        "102": 50, "103": {"en": False, "isF": False},
        "104": {"ts": begin_ms + 520, "cts": begin_ms + 520},
        "105": "0", "106": list(PERMISSION_STATES), "107": -8, "108": {},
    }
    return {
        "1": did, "3": APP_KEY, "6": BUSS_TYPE_MAN_MACHINE, "7": 10,
        "9": now_ms, "10": "", "12": APP_KEY, "13": "",
        "14": RM_VERSION, "module_section": [module_section],
    }

def encode_body(payload: dict) -> str:
    """外层封装：``{"flag":2,"data":"<base64(JSON)>"}``。"""
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    data = base64.b64encode(raw.encode("utf-8")).decode("ascii")
    return json.dumps({"flag": FLAG, "data": data}, separators=(",", ":"))


def build_init_body(did: str, sdk_ver: str = RM_VERSION,
                    pver: str = "0.0.0", platform: int = 3,
                    buss_type: str = BUSS_TYPE_MAN_MACHINE) -> str:
    """``/s/u/v?type=SDK_INIT`` 的 body（实抓逐字段）::

        {"data": "<base64>", "flag": 2}
        base64 解开 = {"device_id": did, "sdkver": "1.6.0",
                       "pver": "0.0.0", "hp": "manMachine", "platform": 3}

    发空 body 会被回 ``{"result":-7,"error_msg":"PARAM_INVALID"}``。

    :param did: 设备标识。
    :param platform: 3 = web。
    """
    if buss_type not in {
            BUSS_TYPE_MAN_MACHINE, BUSS_TYPE_GAME_LIVE, BUSS_TYPE_VISION}:
        raise ValueError(f"unsupported gdfp SDK_INIT bussType: {buss_type!r}")
    inner = {"device_id": did, "sdkver": sdk_ver, "pver": pver,
             "hp": buss_type, "platform": platform}
    raw = json.dumps(inner, separators=(",", ":"), ensure_ascii=False)
    return json.dumps({"data": base64.b64encode(raw.encode()).decode("ascii"),
                       "flag": FLAG}, separators=(",", ":"))


def build_game_live_init_body(did: str) -> str:
    """Build the exact current live-room ``gameLive`` SDK_INIT body."""
    value = str(did or "")
    if not re.fullmatch(r"web_[0-9a-f]{32}", value):
        raise ValueError(
            "gameLive SDK_INIT did must match current Chrome web_<32 lowercase hex>")
    return build_init_body(
        value, sdk_ver=RM_VERSION_GAME_LIVE,
        buss_type=BUSS_TYPE_GAME_LIVE)


def game_live_init(did: str, referer: str, session=None,
                   ts_seconds: int = None, timeout: float = 15.0,
                   user_agent: str = None) -> dict:
    """Send the current live-room gdfp ``gameLive`` SDK_INIT request.

    Chrome reqids 918/1062 only prove the strategy request.  They do not show
    a subsequent gameLive ``/n/a/b`` report, so this helper deliberately stops
    after SDK_INIT instead of borrowing the captcha ``manMachine`` payload.
    """
    parsed = urlsplit(str(referer or ""))
    if (parsed.scheme != "https" or parsed.netloc != "live.kuaishou.com"
            or not re.fullmatch(r"/u/[0-9a-z]+", parsed.path)
            or parsed.query or parsed.fragment):
        raise ValueError(
            f"gameLive SDK_INIT requires exact current room Referer: {referer!r}")
    body = build_game_live_init_body(did).encode("utf-8")
    if session is None:
        from utils.transport import shared_session
        http = shared_session()
    else:
        http = session
    if user_agent is None:
        from utils.fingerprint import get_profile
        user_agent = get_profile()["ua"]
    headers = {
        "user-agent": user_agent,
        "content-type": "text/plain;charset=UTF-8",
        "referer": referer,
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,ja;q=0.6",
        "origin": "https://live.kuaishou.com",
        "priority": "u=1, i",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "cross-site",
    }
    url = build_url(
        URL_STRATEGY, buss_type=BUSS_TYPE_GAME_LIVE,
        ts_seconds=ts_seconds, extra="&type=SDK_INIT")
    response = http.post(url, data=body, headers=headers, timeout=timeout)
    response.raise_for_status()
    if getattr(response, "status_code", None) != 200:
        raise RuntimeError(
            "gameLive SDK_INIT HTTP status drift: "
            f"{getattr(response, 'status_code', None)!r}")
    if _response_content_type(response) != RESPONSE_CONTENT_TYPE:
        raise RuntimeError(
            "gameLive SDK_INIT response content-type drift: "
            f"{_response_content_type(response)!r}")
    try:
        envelope = response.json()
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("gameLive SDK_INIT response is not JSON") from exc
    if (list(envelope) != ["result", "error_msg", "antispamPluginRsp"]
            or envelope.get("result") != 1 or envelope.get("error_msg") != ""):
        raise RuntimeError(f"unexpected gameLive SDK_INIT envelope: {envelope!r}")
    config = parse_init_response(envelope)
    if config != GAME_LIVE_INIT_CONFIG:
        raise RuntimeError(
            f"unknown gameLive SDK_INIT policy/config; refusing drift: {config!r}")
    version = getattr(response, "http_version", "")
    from utils.transport import http_version_label, is_http11, is_http2
    if not is_http2(version) and (not is_http11(version) or _strict_http2()):
        raise RuntimeError(
            "gdfp gameLive SDK_INIT negotiated an unsupported HTTP version; "
            f"actual http_version={http_version_label(version) or 'unknown'}")
    return {"response": envelope, "config": config,
            "http_version": http_version_label(version)}


def parse_init_response(resp_json: dict) -> dict:
    """解 SDK_INIT 响应里的 ``antispamPluginRsp``（base64 的 JSON）。

    **``/n/a/b`` 这个上报路径就是从这里下发的**，不是写死在 bundle 里的
    —— 所以三个 bundle 全文搜 ``/n/a/b`` 都搜不到。实抓解出来是::

        {"switch": 1, "maxBatchLength": 50, "wait": 1000, "enableNative": 1,
         "jsver": "1.0.1", "reportConfig": {"reportUrls": ["/n/a/b"]},
         "policyId": 254, "pver": "1.0.2", "status": 1}

    对应 ``getReportUrl(options)`` 里的 ``options.reportUrls``。

    :return: 解开的配置 dict；解不出返回 {}。
    """
    blob = (resp_json or {}).get("antispamPluginRsp") or ""
    if not blob:
        return {}
    try:
        pad = "=" * (-len(blob) % 4)
        return json.loads(base64.b64decode(blob + pad).decode("utf-8"))
    except Exception:                                          # noqa: BLE001
        return {}


def _response_content_type(response) -> str:
    headers = getattr(response, "headers", None)
    if headers is None:
        return ""
    try:
        return str(headers.get("content-type", "") or
                   headers.get("Content-Type", ""))
    except AttributeError:
        return ""


def _strict_http2() -> bool:
    """Whether to restore the old fail-closed HTTP/2-only behavior.

    The captured gdfp request used HTTP/2, but the same endpoint currently
    negotiates HTTP/1.1 for some networks. Treating that normal fallback as a
    protocol error prevents the captcha request from ever reaching verify.
    Set ``KS_STRICT_GDFP_HTTP2=1`` only for forensic wire-contract checks.
    """
    return str(os.environ.get(ENV_STRICT_HTTP2, "")).strip().lower() in {
        "1", "true", "yes", "on",
    }


def _validate_http_version(response, *, role: str) -> str:
    """Accept the endpoint's normal HTTP/1.1 fallback and return its label."""
    from utils.transport import http_version_label, is_http11, is_http2

    version = getattr(response, "http_version", "")
    if is_http2(version):
        return http_version_label(version)
    if is_http11(version) and not _strict_http2():
        return http_version_label(version)
    raise RuntimeError(
        f"gdfp manMachine {role} negotiated an unsupported HTTP version; "
        f"actual http_version={http_version_label(version) or 'unknown'}")


def _raw_response(response) -> bytes:
    content = getattr(response, "content", None)
    if isinstance(content, bytes):
        return content
    if isinstance(content, bytearray):
        return bytes(content)
    return str(getattr(response, "text", "") or "").encode("utf-8")


def _validate_man_machine_init(response) -> dict:
    response.raise_for_status()
    if getattr(response, "status_code", None) != 200:
        raise RuntimeError(
            "gdfp manMachine SDK_INIT HTTP status drift: "
            f"{getattr(response, 'status_code', None)!r}")
    content_type = _response_content_type(response)
    if content_type != RESPONSE_CONTENT_TYPE:
        raise RuntimeError(
            "gdfp manMachine SDK_INIT content-type drift: "
            f"{content_type!r}")
    _validate_http_version(response, role="SDK_INIT")
    raw = _raw_response(response)
    if raw != MAN_MACHINE_INIT_RESPONSE:
        raise RuntimeError(
            f"gdfp manMachine SDK_INIT response body drift: {raw!r}")
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("gdfp manMachine SDK_INIT is not UTF-8 JSON") from exc
    if (list(envelope) != ["result", "error_msg", "antispamPluginRsp"]
            or envelope.get("result") != 1 or envelope.get("error_msg") != ""):
        raise RuntimeError(
            f"unexpected gdfp manMachine SDK_INIT response: {envelope!r}")
    config = parse_init_response(envelope)
    if config != MAN_MACHINE_INIT_CONFIG or list(config) != list(MAN_MACHINE_INIT_CONFIG):
        raise RuntimeError(
            f"unknown gdfp manMachine policy/config; refusing drift: {config!r}")
    return envelope


def _validate_man_machine_response(response, *, role: str) -> dict:
    """Validate the successful JSON envelope and negotiated protocol."""
    response.raise_for_status()
    if getattr(response, "status_code", None) != 200:
        raise RuntimeError(
            f"gdfp manMachine {role} HTTP status drift: "
            f"{getattr(response, 'status_code', None)!r}")
    content_type = _response_content_type(response)
    if content_type != RESPONSE_CONTENT_TYPE:
        raise RuntimeError(
            f"gdfp manMachine {role} content-type drift: {content_type!r}")
    _validate_http_version(response, role=role)
    raw = _raw_response(response)
    if raw != REPORT_RESPONSE:
        raise RuntimeError(
            f"gdfp manMachine {role} response body drift: {raw!r}")
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"gdfp manMachine {role} is not UTF-8 JSON") from exc
    if (list(envelope or {}) != ["result", "error_msg"]
            or envelope != {"result": 1, "error_msg": ""}):
        raise RuntimeError(
            f"unexpected gdfp manMachine {role} response: {envelope!r}")
    return envelope


def report(http, did: str, user_id: str, cookies: dict,
           parent_url: str, iframe_url: str, ua: str,
           resolution: str = None, identity: str = None,
           timeout=(10, 30), script_urls=None) -> dict:
    """打完整 manMachine 预检（SDK_INIT -> core /n/a/b -> whole /n/a/b）。

    :param http: 复用调用方的会话（curl_cffi 或 requests）。
    :return: ``{"init":…, "config":…, "core":…, "identity":…}``。
    """
    identity = identity or str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    begin_ms = int(time.time() * 1000)
    headers = {
        "user-agent": ua,
        "content-type": "text/plain;charset=UTF-8",
        "referer": iframe_url,
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,ja;q=0.6",
        "origin": "https://captcha.zt.kuaishou.com",
        "priority": "u=1, i",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "cross-site",
    }
    out = {"identity": identity}

    # 1) SDK_INIT：换策略，**上报路径由它下发**
    init_response = http.post(
        build_url(URL_STRATEGY, extra="&type=SDK_INIT"),
        data=build_init_body(did).encode("utf-8"),
        headers=headers, timeout=timeout)
    out["init"] = _validate_man_machine_init(init_response)
    cfg = parse_init_response(out["init"])
    out["config"] = cfg
    report_urls = (cfg.get("reportConfig") or {}).get("reportUrls")
    if report_urls != [URL_CORE_REPORT]:
        raise RuntimeError(
            f"unknown gdfp manMachine reportUrls: {report_urls!r}")
    path = report_urls[0]

    # 2) 行为遥测（关键的一步）
    core_now = int(time.time() * 1000)
    payload = build_core_payload(
        did, user_id, cookies, parent_url, iframe_url, ua, resolution,
        identity, now_ms=core_now, begin_ms=begin_ms,
        session_id=session_id, script_urls=script_urls)
    core_response = http.post(
        build_url(path), data=encode_body(payload).encode("utf-8"),
        headers=headers, timeout=timeout)
    out["core"] = _validate_man_machine_response(
        core_response, role="core report")

    # 3) The SDK's configured wait separates sendCoreData from sendWholeData.
    # Current strategy says 1000 ms; cap an unexpected server value so a
    # malformed response cannot stall the caller indefinitely.
    wait_ms = int(cfg["wait"])
    time.sleep(wait_ms / 1000.0)
    whole_now = int(time.time() * 1000)
    whole_payload = build_whole_payload(
        did, user_id, cookies, parent_url, iframe_url, ua, resolution,
        identity, now_ms=whole_now, begin_ms=begin_ms,
        session_id=session_id, script_urls=script_urls, report_path=path)
    whole_response = http.post(
        build_url(path), data=encode_body(whole_payload).encode("utf-8"),
        headers=headers, timeout=timeout)
    out["whole"] = _validate_man_machine_response(
        whole_response, role="whole report")
    return out


def _safe_json(resp):
    try:
        return resp.json()
    except Exception:                                          # noqa: BLE001
        return {"_status": getattr(resp, "status_code", 0),
                "_text": (getattr(resp, "text", "") or "")[:200]}


def selftest() -> bool:
    """回归：用实抓的两条 timestamp 反算 sign，必须逐字符一致。"""
    cases = [
        ("1786887567", "8b549916157e6d6cb0509169a3f9927c"),
        ("1786887566", "fba217b12cfa4272dd7721ba895540ed"),
    ]
    ok = True
    for ts, want in cases:
        got = sign_for(ts)
        good = got == want
        ok = ok and good
        print(f"  {'PASS' if good else 'FAIL'}  sign({ts}) = {got}")
    return ok


if __name__ == "__main__":
    import sys
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print("gdfp sign 自检（对实抓）：")
    sys.exit(0 if selftest() else 1)
