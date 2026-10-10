#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Observed ``gameLive`` gdfp full-report request builder.

The live page emits a report after ``SDK_INIT``.  Chrome marks this request
``no-cors`` and DevTools does not expose a usable response body or response
headers, so this module deliberately implements *request construction only*.
Callers can use :func:`build_chain` to inspect/replay the exact wire bytes;
there is no optimistic sender which would treat an unknown response as a
successful telemetry submission.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import uuid
from collections import OrderedDict
from urllib.parse import urlsplit

from utils import gdfp_manmachine as common
from utils.fingerprint import get_profile


BUSS_TYPE = common.BUSS_TYPE_GAME_LIVE
SDK_VERSION = common.RM_VERSION_GAME_LIVE
REPORT_PATH = common.URL_REPORT
PAGE_ORIGIN = "https://live.kuaishou.com"
RESOLUTION = "2560x1440"
UA_DEFAULT = get_profile()["ua"]

SCRIPT_PREFIX = [
    "https://static.yximgs.com/udata/pkg/ks-track-platform-new/weblogger/3.9.49/async/gzipper.min.js",
    "https://p2-game.kskwai.com/udata/pkg/KS-GAME-WEB/pc-live-next/js/115.1241f9804c38413b871f.js",
    "https://p2-game.kskwai.com/udata/pkg/KS-GAME-WEB/pc-live-next/js/959.1241f9804c38413b871f.js",
    "https://p2-game.kskwai.com/udata/pkg/KS-GAME-WEB/pc-live-next/js/56.1241f9804c38413b871f.js",
    "https://p2-game.kskwai.com/udata/pkg/KS-GAME-WEB/pc-live-next/js/liveRoom.1241f9804c38413b871f.js",
    "https://p2-game.kskwai.com/udata/pkg/KS-GAME-WEB/pc-live-next/js/vendors.1241f9804c38413b871f.js",
    "https://p2-game.kskwai.com/udata/pkg/KS-GAME-WEB/pc-live-next/js/purecommon.1241f9804c38413b871f.js",
    "https://p2-game.kskwai.com/udata/pkg/KS-GAME-WEB/pc-live-next/js/common.1241f9804c38413b871f.js",
    "https://p2-game.kskwai.com/udata/pkg/KS-GAME-WEB/pc-live-next/js/app.1241f9804c38413b871f.js",
]
SCRIPT_COUNT = len(SCRIPT_PREFIX) + 2
STACK_LENGTH = 708
KWF_RE = re.compile(
    r"https://h(?:4|5|23)\.static\.yximgs\.com/kcdn/cdn-kcdn112369/"
    r"kwf/kwf-0\.0\.2\.2cee19b4b7dec496\.js\?x-kcdn-pid=112369$")
KWS_RE = re.compile(
    r"https://h(?:4|5|23)\.static\.yximgs\.com/kcdn/cdn-kcdn112369/"
    r"kws/kws-(?:0|1|2|3|4|5|6|7|8|9|10|11|12|13|15|16|17|18|19)-"
    r"0\.0\.1-obfuscated\.[0-9a-f]{16}\.js\?x-kcdn-pid=112369$")

COOKIE_ORDERS = (
    ("did", "wid", "didv", "bUserId", "kwpsecproductname", "kwfv1",
     "kwssectoken", "kwscode"),
    ("did", "wid", "didv", "bUserId", "kwpsecproductname", "kwssectoken",
     "kwscode", "kwfv1"),
)
COOKIE_LENGTHS = {
    "did": 36, "wid": 17, "didv": 13, "bUserId": 13,
    # Both currently retained gameLive full-report samples (reqid 322/447)
    # carry the high-count 0.1.1 webweapon output.  This is deliberately not
    # inherited from the low-count www/captcha profiles, which may be 174.
    "kwpsecproductname": 6, "kwfv1": 218, "kwssectoken": 88,
    "kwscode": 64,
}
NATIVE = {
    "pc": 122, "ph": "9ca2d73849ec1f87e04da872d8f365c7",
    "wf": 1231, "wh": "e001e8f8001e4cc41f87ac2834c88cc1",
    "cf": 569, "ch": "c84d109dd869085095215f162438a2bd",
    "mf": 695, "mh": "b65fd614f988bf26059cc26bb60c8cce",
    "ff": 155, "fh": "3b88502da11f9891fbcfb1728c3ef4dd",
    "af": 973, "ah": "0c0f37af54a48e821c3ce168ea7f92c7",
    "gr": 596, "gh": "f464e5064ed202b7fbdc3e50e4438a13",
    "el": 33, "eh": "dc4d3e06840e103f3e77747a82029aa9",
    "ow": 48, "oh": "b1f70a306127c28f23145b72a4281de2",
    "ky": 33, "kh": "61792d30f54bedfe1007347e9fdc4223",
}
PERMISSION_STATES = [
    {"permissionName": name, "state": state} for name, state in (
        ("speaker", "error"), ("device-info", "error"),
        ("bluetooth", "error"), ("ambient-light-sensor", "error"),
        ("clipboard", "error"), ("nfc", "error"),
        ("geolocation", "prompt"), ("notifications", "prompt"),
        ("push", "prompt"), ("midi", "prompt"), ("camera", "prompt"),
        ("microphone", "prompt"), ("background-fetch", "granted"),
        ("background-sync", "granted"), ("persistent-storage", "prompt"),
        ("accelerometer", "granted"), ("gyroscope", "granted"),
        ("magnetometer", "granted"), ("display-capture", "prompt"),
    )
]


def _md5(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def _sha1(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()


def _validate_context(did: str, page_url: str, page_title: str,
                      cookies: dict, script_urls: list, session_id: str,
                      user_agent: str) -> tuple[str, OrderedDict, list, str]:
    did = str(did or "")
    if not re.fullmatch(r"web_[0-9a-f]{32}", did):
        raise ValueError("gameLive report did must match web_<32 lowercase hex>")
    parsed = urlsplit(str(page_url or ""))
    if (parsed.scheme != "https" or parsed.netloc != "live.kuaishou.com"
            or not re.fullmatch(r"/u/[0-9a-z]+", parsed.path)
            or parsed.query or parsed.fragment):
        raise ValueError("gameLive report supports exact /u/<eid> pages only")
    try:
        sid = uuid.UUID(str(session_id))
    except (ValueError, AttributeError) as exc:
        raise ValueError("gameLive report session_id must be a UUID") from exc
    if not sid.int:
        raise ValueError("gameLive report session_id must be non-zero")
    if not str(page_title or ""):
        raise ValueError("gameLive report requires the current document title")
    ordered = OrderedDict(cookies or {})
    if tuple(ordered) not in COOKIE_ORDERS:
        raise ValueError(f"gameLive report Cookie order drift: {tuple(ordered)!r}")
    for key, expected in COOKIE_LENGTHS.items():
        value = str(ordered.get(key, ""))
        if len(value) != expected:
            raise ValueError(f"gameLive report Cookie {key} length drift")
    if ordered["did"] != did or ordered["kwpsecproductname"] != "PCLive":
        raise ValueError("gameLive report did/product Cookie mismatch")
    scripts = list(script_urls or [])
    if len(scripts) != SCRIPT_COUNT or scripts[:len(SCRIPT_PREFIX)] != SCRIPT_PREFIX:
        raise ValueError("gameLive report script list drift")
    if not KWF_RE.fullmatch(str(scripts[len(SCRIPT_PREFIX)])):
        raise ValueError("gameLive report kwf script drift")
    if not KWS_RE.fullmatch(str(scripts[len(SCRIPT_PREFIX) + 1])):
        raise ValueError("gameLive report kws script drift")
    ua = str(user_agent or UA_DEFAULT)
    if "Chrome/151." not in ua or "Windows NT 10.0" not in ua:
        raise ValueError("gameLive report requires the captured Chrome 151 UA")
    return did, ordered, scripts, ua


def build_payload(*, did: str, page_url: str, page_title: str,
                   cookies: dict, session_id: str, init_ms: int,
                   report_ms: int, timings: dict | None = None,
                   script_urls: list | None = None,
                   user_agent: str | None = None,
                   stack: str | None = None) -> dict:
    """Build the decoded inner ``gameLive`` full-report payload.

    ``timings`` is accepted explicitly because Chrome's performance values
    vary per load.  It must contain the observed eight keys and ``ls`` must
    equal ``report_ms``.  Exact browser timings and the captured JS stack are
    required; this constructor never invents either value.
    """
    did, cookies, scripts, ua = _validate_context(
        did, page_url, page_title, cookies, script_urls, session_id,
        user_agent)
    report_ms, init_ms = int(report_ms), int(init_ms)
    if report_ms <= init_ms:
        raise ValueError("gameLive report_ms must be after init_ms")
    if timings is None:
        raise ValueError("gameLive report requires captured browser timings")
    timings = dict(timings)
    if list(timings) != ["cs", "ce", "as", "ae", "cae", "gs", "ge", "ls"]:
        raise ValueError("gameLive report timing key order drift")
    if int(timings["ls"]) != report_ms:
        raise ValueError("gameLive report timing ls must equal report_ms")
    if any(int(timings[a]) > int(timings[b]) for a, b in zip(list(timings), list(timings)[1:])):
        raise ValueError("gameLive report timings must be monotonic")
    if stack is None or len(str(stack)) != STACK_LENGTH or "generateModuleSection" not in str(stack):
        raise ValueError("gameLive report requires the captured JS call stack")
    stack = str(stack)
    module = OrderedDict([
        ("1", ""), ("2", page_url), ("4", PAGE_ORIGIN), ("5", str(session_id)),
        ("6", str(page_title)), ("7", cookies), ("8", RESOLUTION),
        ("9", 1215), ("10", 2560), ("11", ua), ("12", "NT 10.0"),
        ("13", "zh-CN"), ("14", "Windows"), ("17", did),
        # In both retained Chrome reports the PAGE_ENTER timestamp is the
        # same browser performance mark as ``gs``.  Deriving it from the
        # supplied timing map keeps replay deterministic and avoids inventing
        # a fixed offset from the report timestamp.
        ("21", {"type": "PAGE_ENTER", "timestamp": int(timings["gs"]),
                "initTime": init_ms}),
        ("24", "99"), ("25", "99"), ("26", "0"),
        ("28", _sha1(f"{did}{RESOLUTION}{ua}{page_url}")),
        ("29", REPORT_PATH), ("30", "ks"), ("31", 1), ("32", "0.00"),
        ("33", "Mozilla"), ("34", "Netscape"),
        ("35", ua.split("Mozilla/", 1)[-1]), ("36", "Win32"),
        ("37", '["zh-CN","zh","en","zh-TW","ja"]'),
        ("41", "20030107"), ("42", "Google Inc."), ("43", ""),
        ("44", 20), ("50", 10), ("51", ""), ("52", 1), ("53", "Gecko"),
        ("54", True), ("55", 0), ("56", ua), ("57", "zh-CN"),
        ("58", common.PLUGIN_LIST), ("59", common.MIME_LIST),
        ("61", "Google Inc. (NVIDIA)"),
        ("62", "ANGLE (NVIDIA, NVIDIA GeForce RTX 5060 Ti (0x00002D04) Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ("63", "1"), ("64", "WebKit"),
        ("65", "WebGL 1.0 (OpenGL ES 2.0 Chromium)"),
        ("66", "WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)"),
        ("67", 0), ("68", "f3bd24f5b153d57f5817372fd5f22573"),
        ("69", "0043c0b8a0b002e8133a140d14068859"),
        ("70", "ba6689f9a1550fb5eef25d1fc682c8c1"),
        ("75", "1"), ("76", "false"), ("77", scripts),
        ("78", {"w": {"pc": 1256, "kc": 256, "lc": 262},
                "n": {"pc": 0, "kc": 0, "lc": 82}}),
        ("79", stack), ("80", "0"), ("81", "177"),
        ("82", {**NATIVE, "ci": len("; ".join(f"{k}={v}" for k, v in cookies.items())),
                "ih": _md5("; ".join(f"{k}={v}" for k, v in cookies.items()))}),
        ("85", ""), ("86", ""), ("87", {"w": 2560, "h": 1440, "c": 24, "p": 24}),
        ("88", "57ba58a858b13208d8b79670f7fa8f94"), ("89", timings), ("90", ""),
    ])
    return OrderedDict([
        ("1", did), ("3", common.APP_KEY), ("6", BUSS_TYPE), ("7", 10),
        ("9", report_ms), ("10", ""), ("12", common.APP_KEY), ("13", ""),
        ("14", SDK_VERSION), ("module_section", [module]),
    ])


def encode_body(payload: dict) -> bytes:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return json.dumps({"flag": common.FLAG, "data": base64.b64encode(raw).decode("ascii")},
                      separators=(",", ":")).encode("utf-8")


def build_chain(*, did: str, page_url: str, page_title: str,
                cookies: dict, session_id: str, init_ms: int,
                report_ms: int, ts_seconds: int,
                script_urls: list | None = None, timings: dict | None = None,
                user_agent: str | None = None, stack: str | None = None) -> dict:
    """Return SDK_INIT + observed report URLs, headers and exact body bytes."""
    report = build_payload(
        did=did, page_url=page_url, page_title=page_title, cookies=cookies,
        session_id=session_id, init_ms=init_ms, report_ms=report_ms,
        timings=timings, script_urls=script_urls, user_agent=user_agent, stack=stack)
    ua = str(user_agent or UA_DEFAULT)
    headers = OrderedDict([
        ("user-agent", ua), ("content-type", "text/plain;charset=UTF-8"),
        ("referer", page_url), ("accept", "*/*"),
        ("accept-encoding", "gzip, deflate, br, zstd"),
        ("accept-language", "zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,ja;q=0.6"),
        ("origin", PAGE_ORIGIN), ("priority", "u=1, i"),
        ("sec-fetch-dest", "empty"), ("sec-fetch-mode", "no-cors"),
        ("sec-fetch-site", "cross-site"),
        ("sec-fetch-storage-access", "active"),
    ])
    return {
        "init_url": common.build_url(common.URL_STRATEGY, buss_type=BUSS_TYPE,
                                      ts_seconds=ts_seconds, extra="&type=SDK_INIT"),
        "report_url": common.build_url(REPORT_PATH, buss_type=BUSS_TYPE,
                                        ts_seconds=ts_seconds),
        "init_body": common.build_game_live_init_body(did).encode("utf-8"),
        "report_body": encode_body(report), "report_payload": report,
        "headers": headers,
    }
