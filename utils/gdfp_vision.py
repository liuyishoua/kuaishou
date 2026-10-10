#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Current www ``com.vision.gifshow`` gdfp fingerprint chain.

Chrome reqids 354/360/361 prove the request bytes.  A later ordinary page
reload, captured at document start, recovered all three response bodies at
reqids 3752/3773/3775.  The SDK_INIT response also survived in the old page's
heap and was tied to the exact XHR ``finalUrl``.  This module can therefore
send the observed SDK_INIT -> concurrent core/whole chain, but rejects any
request, policy, response, content-type, or HTTP/2 drift.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import json
import re
import uuid
from urllib.parse import urlsplit

from utils import gdfp_manmachine as common
from utils.fingerprint import get_profile
from utils.transport import http_version_label, is_http11, is_http2

BUSS_TYPE = common.BUSS_TYPE_VISION
SDK_VERSION = "1.6.0"
INIT_RESPONSE = (
    b'{"result":1,"error_msg":"","antispamPluginRsp":'
    b'"eyJzd2l0Y2giOjEsIm1heEJhdGNoTGVuZ3RoIjo1MCwid2FpdCI6MCwiZW5hYmxlTmF0aXZlIjowLCJwb2xpY3lJZCI6MTE2LCJwdmVyIjoiMS4wLjEiLCJzdGF0dXMiOjF9"}'
)
REPORT_RESPONSE = b'{"result":1,"error_msg":""}'
INIT_CONFIG = {
    "switch": 1,
    "maxBatchLength": 50,
    "wait": 0,
    "enableNative": 0,
    "policyId": 116,
    "pver": "1.0.1",
    "status": 1,
}
RESPONSE_CONTENT_TYPE = "application/json;charset=UTF-8"
APP_BUNDLE = (
    "https://p2-plat.wskwai.com/kos/nlav111422/pc-vision/js/"
    "app.e3175f3a.js"
)
SCRIPT_URLS = [
    "https://p2-plat.wskwai.com/kos/nlav111422/pc-vision/js/chunk-2d20e806.51d40e4c.js",
    "https://p2-plat.wskwai.com/kos/nlav111422/pc-vision/js/NewReco-briliant-error-hash-home-movie-movie-video-myFollow-profile-reco-search-short-video-tesla-ho-a483385b.3ed6fd3c.js",
    "https://p2-plat.wskwai.com/kos/nlav111422/pc-vision/js/NewReco-briliant-error-hash-home-movie-movie-video-myFollow-profile-reco-search-short-video-theater-video.30433293.js",
    "https://p2-plat.wskwai.com/kos/nlav111422/pc-vision/js/NewReco-csr-movie-video-short-video-tesla-home-tesla-video-video.ff41941e.js",
    "https://p2-plat.wskwai.com/kos/nlav111422/pc-vision/js/csr-short-video.13a6bfad.js",
    "https://p2-plat.wskwai.com/kos/nlav111422/pc-vision/js/chunk-vendors.e14b482a.js",
    "https://p2-plat.wskwai.com/kos/nlav111422/pc-vision/js/short-video.4caa6fda.js",
    APP_BUNDLE,
    "https://h4.static.yximgs.com/kcdn/cdn-kcdn112369/kwf/kwf-0.0.2.2cee19b4b7dec496.js?x-kcdn-pid=112369",
    "https://h4.static.yximgs.com/kcdn/cdn-kcdn112369/kws/kws-5-0.0.1-obfuscated.4e553d17691b3c5a.js?x-kcdn-pid=112369",
]
COOKIE_KEYS = (
    "did", "wid", "didv", "kwpsecproductname", "bUserId",
    "ktrace-context", "kwssectoken", "kwscode", "kwfv1",
)
COOKIE_VALUE_LENGTHS = {
    "did": 36, "wid": 17, "didv": 13, "kwpsecproductname": 15,
    "bUserId": 13, "ktrace-context": 192, "kwssectoken": 88,
    "kwscode": 64, "kwfv1": 174,
}
CORE_NATIVE = {
    "cf": 585, "ch": "c0519fd2bed463968d3dda8a51549f00",
    "ff": 166, "fh": "a7fab3d87506078e99b7a518bd1a9414",
    "el": 33, "eh": "dc4d3e06840e103f3e77747a82029aa9",
}
WHOLE_NATIVE = {
    "pc": 134, "ph": "4520c028e388f43639cef55233412eed",
    "wf": 1159, "wh": "22978b27827759da99e60cd96a2fa53a",
    "cf": 585, "ch": "c0519fd2bed463968d3dda8a51549f00",
    "mf": 1052, "mh": "11126de7acecbb3c904e5010a10910f5",
    "ff": 166, "fh": "a7fab3d87506078e99b7a518bd1a9414",
    "af": 1031, "ah": "721d7130925f7e1cc7d0378a28c25033",
    "gr": 408, "gh": "f1cca09f57e3b665b8cd99b2cb53ecbe",
    "el": 33, "eh": "dc4d3e06840e103f3e77747a82029aa9",
    "ow": 20016, "oh": "7b206694c1ff311160afd3f33e81c883",
    "ky": 33, "kh": "61792d30f54bedfe1007347e9fdc4223",
}
PERMISSION_STATES = [
    {"permissionName": name, "state": state} for name, state in (
        ("speaker", "error"), ("device-info", "error"),
        ("bluetooth", "error"), ("ambient-light-sensor", "error"),
        ("clipboard", "error"), ("nfc", "error"),
        ("geolocation", "prompt"), ("notifications", "prompt"),
        ("push", "prompt"), ("midi", "prompt"),
        ("camera", "prompt"), ("microphone", "prompt"),
        ("background-fetch", "granted"), ("background-sync", "granted"),
        ("persistent-storage", "prompt"), ("accelerometer", "granted"),
        ("gyroscope", "granted"), ("magnetometer", "granted"),
        ("display-capture", "prompt"),
    )
]


def _call_stack(kind: str) -> str:
    frames = (
        (("printCallStack", 153530),
         ("RiskMgt.generateCoreModuleSection", 198767),
         ("RiskMgt.<anonymous>", 202817), ("", 124303),
         ("Object.next", 124408), ("", 123335),
         ("newPromise(<anonymous>)", None), ("__awaiter", 123080),
         ("RiskMgt.sendCoreData", 202390), ("n", 201279),
         ("RiskMgt.decryptSuccessFunc", 206531),
         ("Worker.<anonymous>", 207891))
        if kind == "core" else
        (("printCallStack", 153530),
         ("RiskMgt.generateModuleSection", 196577),
         ("RiskMgt.<anonymous>", 203139), ("", 124303),
         ("Object.next", 124408), ("", 123335),
         ("newPromise(<anonymous>)", None), ("__awaiter", 123080),
         ("RiskMgt.sendWholeData", 203019),
         ("RiskMgt.<anonymous>", 202120), ("", 124303),
         ("Object.next", 124408), ("a", 123137))
    )
    out = []
    for name, offset in frames:
        if offset is None:
            out.append(f"at{name}")
        elif name:
            out.append(f"at{name}({APP_BUNDLE}:1:{offset})")
        else:
            out.append(f"at{APP_BUNDLE}:1:{offset}")
    return "".join(out)


def _md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def _validate(did: str, page_url: str, cookies: dict,
              document_cookie: str, session_id: str) -> tuple[str, dict]:
    did = str(did or "")
    if not re.fullmatch(r"web_[0-9a-f]{32}", did):
        raise ValueError("vision gdfp did must match web_<32 lowercase hex>")
    parsed = urlsplit(str(page_url or ""))
    if (parsed.scheme != "https" or parsed.netloc != "www.kuaishou.com"
            or not re.fullmatch(r"/short-video/[0-9a-z]+", parsed.path)
            or parsed.query or parsed.fragment):
        raise ValueError("vision gdfp currently supports exact short-video pages only")
    ordered = dict(cookies or {})
    if tuple(ordered) != COOKIE_KEYS:
        raise ValueError(
            f"vision gdfp Cookie key/order drift: {tuple(ordered)!r}")
    for key, expected in COOKIE_VALUE_LENGTHS.items():
        if len(str(ordered[key])) != expected:
            raise ValueError(
                f"vision gdfp Cookie {key} length drift: "
                f"{len(str(ordered[key]))} != {expected}")
    if ordered["did"] != did or ordered["kwpsecproductname"] != "kuaishou-vision":
        raise ValueError("vision gdfp did/product Cookie values do not match current contract")
    if len(str(document_cookie or "")) != 919:
        raise ValueError(
            "vision gdfp document.cookie fingerprint requires current 919-char line")
    try:
        parsed_uuid = uuid.UUID(str(session_id))
    except (ValueError, AttributeError) as exc:
        raise ValueError("vision gdfp session_id must be a UUID") from exc
    if not parsed_uuid.int:
        raise ValueError("vision gdfp session_id must be non-zero")
    return did, ordered


def build_init_body(did: str) -> str:
    """Exact reqid 354 SDK_INIT envelope."""
    if not re.fullmatch(r"web_[0-9a-f]{32}", str(did or "")):
        raise ValueError("vision gdfp did must match web_<32 lowercase hex>")
    return common.build_init_body(
        did, sdk_ver=SDK_VERSION, buss_type=BUSS_TYPE)


def _native(base: dict, document_cookie: str) -> dict:
    value = dict(base)
    value.update({"ci": len(document_cookie), "ih": _md5(document_cookie)})
    return value


def build_core_payload(*, did: str, page_url: str, cookies: dict,
                       document_cookie: str, session_id: str,
                       init_ms: int, core_ms: int, user_agent: str = None) -> dict:
    did, cookies = _validate(
        did, page_url, cookies, document_cookie, session_id)
    ua = user_agent or get_profile()["ua"]
    resolution = "2560x1440"
    module = {
        "1": "", "2": page_url, "5": session_id, "7": cookies,
        "8": resolution, "11": ua, "17": did,
        "21": {"type": "PAGE_ENTER", "timestamp": int(core_ms) - 9,
               "initTime": int(init_ms)},
        "28": hashlib.sha1(
            f"{did}{resolution}{ua}{page_url}".encode("utf-8")).hexdigest(),
        "33": "Mozilla", "34": "Netscape",
        "35": ua.split("Mozilla/", 1)[-1], "36": "Win32",
        "55": 0, "56": ua,
        "69": "0043c0b8a0b002e8133a140d14068859",
        "75": "1", "76": "", "77": list(SCRIPT_URLS),
        "79": _call_stack("core"),
        "82": _native(CORE_NATIVE, document_cookie),
        "89": {"cs": int(init_ms) + 286, "ce": int(init_ms) + 290,
               "as": int(init_ms) + 292, "ae": int(init_ms) + 294,
               "cae": int(init_ms) + 333, "ls": int(core_ms) - 1},
        "102": 50, "108": {},
    }
    return {
        "1": did, "3": common.CORE_DATA_LOGGER_ID, "6": BUSS_TYPE,
        "7": 10, "9": int(core_ms), "10": "", "12": common.APP_KEY,
        "13": "", "14": SDK_VERSION, "module_section": [module],
    }


def build_whole_payload(*, did: str, page_url: str, page_title: str,
                        cookies: dict, document_cookie: str, session_id: str,
                        init_ms: int, core_ms: int, whole_ms: int,
                        user_agent: str = None) -> dict:
    did, cookies = _validate(
        did, page_url, cookies, document_cookie, session_id)
    if not str(page_title or ""):
        raise ValueError("vision gdfp whole report requires the current document title")
    ua = user_agent or get_profile()["ua"]
    resolution = "2560x1440"
    module = {
        "1": "", "2": page_url, "4": "https://www.kuaishou.com",
        "5": session_id, "6": page_title, "7": cookies,
        "8": resolution, "9": 1215, "10": 2560,
        "11": ua, "12": "NT 10.0", "13": "zh-CN", "14": "Windows",
        "17": did,
        "21": {"type": "PAGE_ENTER", "timestamp": int(whole_ms) - 25,
               "initTime": int(init_ms)},
        "24": "6", "25": "6-1", "26": "0",
        "28": hashlib.sha1(
            f"{did}{resolution}{ua}{page_url}".encode("utf-8")).hexdigest(),
        "29": common.URL_REPORT, "30": "ks", "31": 1, "32": "0.00",
        "33": "Mozilla", "34": "Netscape",
        "35": ua.split("Mozilla/", 1)[-1], "36": "Win32",
        "37": '["zh-CN","zh","en","zh-TW","ja"]',
        "41": "20030107", "42": "Google Inc.", "43": "", "44": 20,
        "50": 10, "51": "", "52": 1, "53": "Gecko", "54": True,
        "55": 0, "56": ua, "57": "zh-CN",
        "58": common.PLUGIN_LIST, "59": common.MIME_LIST,
        "61": "Google Inc. (NVIDIA)",
        "62": ("ANGLE (NVIDIA, NVIDIA GeForce RTX 5060 Ti (0x00002D04) "
               "Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        "63": "1", "64": "WebKit",
        "65": "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
        "66": "WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)",
        "67": 0, "68": "f3bd24f5b153d57f5817372fd5f22573",
        "69": "0043c0b8a0b002e8133a140d14068859",
        "70": "ba6689f9a1550fb5eef25d1fc682c8c1",
        "75": "1", "76": "", "77": list(SCRIPT_URLS),
        "78": {"w": {"pc": 1272, "kc": 272, "lc": 278},
               "n": {"pc": 0, "kc": 0, "lc": 82}},
        "79": _call_stack("whole"), "80": "0", "81": "177",
        "82": _native(WHOLE_NATIVE, document_cookie),
        "85": "", "86": "",
        "87": {"w": 2560, "h": 1440, "c": 24, "p": 24},
        "88": "57ba58a858b13208d8b79670f7fa8f94",
        "89": {"cs": int(init_ms) + 286, "ce": int(init_ms) + 290,
               "as": int(init_ms) + 292, "ae": int(init_ms) + 294,
               "cae": int(init_ms) + 333, "ls": int(whole_ms),
               "le": int(core_ms), "gs": int(whole_ms) - 25,
               "ge": int(whole_ms) - 7, "cre": int(whole_ms) - 1},
        "90": "", "100": 12, "101": {"lsc": 25, "ssc": 3},
        "102": 50, "103": {"en": True, "isF": False},
        "104": {"ts": int(whole_ms) - 2, "cts": int(whole_ms) - 2},
        "105": "0", "106": list(PERMISSION_STATES), "107": -8, "108": {},
    }
    return {
        "1": did, "3": common.APP_KEY, "6": BUSS_TYPE, "7": 10,
        "9": int(whole_ms), "10": "", "12": common.APP_KEY, "13": "",
        "14": SDK_VERSION, "module_section": [module],
    }


def build_chain(*, did: str, page_url: str, page_title: str,
                cookies: dict, document_cookie: str, session_id: str,
                init_ms: int, core_ms: int, whole_ms: int,
                ts_seconds: int, report_ts_seconds: int = None) -> dict:
    """Return the exact observed request materials without sending them."""
    core = build_core_payload(
        did=did, page_url=page_url, cookies=cookies,
        document_cookie=document_cookie, session_id=session_id,
        init_ms=init_ms, core_ms=core_ms)
    whole = build_whole_payload(
        did=did, page_url=page_url, page_title=page_title, cookies=cookies,
        document_cookie=document_cookie, session_id=session_id,
        init_ms=init_ms, core_ms=core_ms, whole_ms=whole_ms)
    headers = {
        "user-agent": get_profile()["ua"],
        "content-type": "text/plain;charset=UTF-8",
        "referer": page_url,
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,ja;q=0.6",
        "origin": "https://www.kuaishou.com",
        "priority": "u=1, i",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "cross-site",
    }
    return {
        "init_url": common.build_url(
            common.URL_STRATEGY, buss_type=BUSS_TYPE,
            ts_seconds=ts_seconds, extra="&type=SDK_INIT"),
        "report_url": common.build_url(
            common.URL_REPORT, buss_type=BUSS_TYPE,
            ts_seconds=(ts_seconds if report_ts_seconds is None
                        else report_ts_seconds)),
        "headers": headers,
        "init_body": build_init_body(did).encode("utf-8"),
        "core_body": common.encode_body(core).encode("utf-8"),
        "whole_body": common.encode_body(whole).encode("utf-8"),
    }


def parse_init_response(envelope: dict) -> dict:
    """Decode and strictly validate the captured vision strategy response."""
    if (list(envelope or {}) != ["result", "error_msg", "antispamPluginRsp"]
            or envelope.get("result") != 1 or envelope.get("error_msg") != ""):
        raise RuntimeError(
            f"unexpected vision SDK_INIT response envelope: {envelope!r}")
    blob = envelope.get("antispamPluginRsp")
    try:
        decoded = json.loads(base64.b64decode(blob, validate=True).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("vision SDK_INIT policy is not strict base64 JSON") from exc
    if decoded != INIT_CONFIG or list(decoded) != list(INIT_CONFIG):
        raise RuntimeError(
            f"unknown vision SDK_INIT policy/config; refusing drift: {decoded!r}")
    return decoded


def _raw_response(response) -> bytes:
    value = getattr(response, "content", None)
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    return str(getattr(response, "text", "") or "").encode("utf-8")


def _header(response, name: str) -> str:
    headers = getattr(response, "headers", None)
    if headers is None:
        return ""
    try:
        return str(headers.get(name, "") or headers.get(name.lower(), ""))
    except AttributeError:
        return ""


def _validate_response(response, *, role: str, expected: bytes) -> dict:
    response.raise_for_status()
    if getattr(response, "status_code", None) != 200:
        raise RuntimeError(
            f"vision {role} HTTP status drift: "
            f"{getattr(response, 'status_code', None)!r}")
    raw = _raw_response(response)
    if raw != expected:
        raise RuntimeError(
            f"vision {role} response body drift: {raw!r}")
    content_type = _header(response, "content-type")
    if content_type != RESPONSE_CONTENT_TYPE:
        raise RuntimeError(
            f"vision {role} response content-type drift: {content_type!r}")
    version = getattr(response, "http_version", "")
    if not is_http2(version) and (not is_http11(version) or common._strict_http2()):
        raise RuntimeError(
            f"vision {role} negotiated an unsupported HTTP version; "
            f"actual http_version={http_version_label(version) or 'unknown'}")
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"vision {role} response is not UTF-8 JSON") from exc
    if role == "SDK_INIT":
        parse_init_response(envelope)
    elif list(envelope) != ["result", "error_msg"] or envelope != {
            "result": 1, "error_msg": ""}:
        raise RuntimeError(
            f"unexpected vision {role} response envelope: {envelope!r}")
    return envelope


async def _maybe_await(value):
    return await value if inspect.isawaitable(value) else value


async def send_chain_async(*, did: str, page_url: str, page_title: str,
                           cookies: dict, document_cookie: str,
                           session_id: str, init_ms: int, core_ms: int,
                           whole_ms: int, ts_seconds: int, session=None,
                           report_ts_seconds: int = None,
                           timeout: float = 15.0) -> dict:
    """Send the exact observed vision chain with browser dispatch semantics.

    SDK_INIT is awaited because it supplies the policy.  The SDK builds/queues
    core first, but its first-send encryption worker delays that XHR; whole
    reaches Network first, then core, and both remain in flight.  Chrome reqids
    3773 (whole) and 3775 (core) overlap in exactly that order.  An injected
    session may expose either async or sync ``post`` for deterministic tests.
    """
    chain = build_chain(
        did=did, page_url=page_url, page_title=page_title, cookies=cookies,
        document_cookie=document_cookie, session_id=session_id,
        init_ms=init_ms, core_ms=core_ms, whole_ms=whole_ms,
        ts_seconds=ts_seconds, report_ts_seconds=report_ts_seconds)
    owns_session = session is None
    if session is None:
        from curl_cffi import requests as crequests
        from utils.transport import impersonate_target
        session = crequests.AsyncSession(
            max_clients=2, impersonate=impersonate_target(),
            default_headers=False)

    async def post(body: bytes, url: str):
        return await _maybe_await(session.post(
            url, data=body, headers=dict(chain["headers"]), timeout=timeout))

    try:
        init_response = await post(chain["init_body"], chain["init_url"])
        init_envelope = _validate_response(
            init_response, role="SDK_INIT", expected=INIT_RESPONSE)
        config = parse_init_response(init_envelope)

        whole_task = asyncio.create_task(post(
            chain["whole_body"], chain["report_url"]))
        await asyncio.sleep(0)
        core_task = asyncio.create_task(post(
            chain["core_body"], chain["report_url"]))
        whole_response, core_response = await asyncio.gather(
            whole_task, core_task)
        core_envelope = _validate_response(
            core_response, role="core report", expected=REPORT_RESPONSE)
        whole_envelope = _validate_response(
            whole_response, role="whole report", expected=REPORT_RESPONSE)
        return {
            "init": init_envelope,
            "config": config,
            "core": core_envelope,
            "whole": whole_envelope,
            "http_versions": [
                http_version_label(getattr(item, "http_version", ""))
                for item in (init_response, core_response, whole_response)
            ],
        }
    finally:
        if owns_session:
            close = getattr(session, "close", None)
            if close is not None:
                await _maybe_await(close())


def send_chain(**kwargs) -> dict:
    """Synchronous wrapper for :func:`send_chain_async`."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(send_chain_async(**kwargs))
    raise RuntimeError(
        "send_chain cannot run inside an active event loop; "
        "await send_chain_async(...) instead")
