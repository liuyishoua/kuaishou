#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""webweapon 预言机桥接：在 Node 里跑真实的 kwf / kws 脚本，产出 ``kwfv1`` / ``kwscode``。

为什么必须这么做（notes_webweapon.md 的结论）::

    /s/w/c 换票 -> {fpUrl, signUrl, secToken}
    loadScript(fpUrl)   # kwf 脚本，算出 kwfv1，写 localStorage + cookie
    loadScript(signUrl) # kws 脚本，算完回调 window.kwscb(code) 交出 kwscode

也就是说 ``kwfv1`` / ``kwscode`` **都是本地脚本算的**，不是服务端下发的。
纯 Python 复刻要先把两套 Brook 字节码虚拟机移植过来（kwf 53KB 字节码、
kws 48KB×N 个变体），成本极高；而直接在 Node 里跑官方脚本，产出的就是
**与浏览器同源同算法**的值 —— 这正是「和浏览器完全一致」的最短路径。

两个已定位并修好的反注入检测点（见 reverse/tools/kws_oracle.js）：

1. **navigator canary**：脚本往 ``navigator.platform`` / ``userAgent`` /
   ``appCodeName`` 写标记串 ``"ctrip.com"`` 再读回来。真实浏览器里这些是
   ``Navigator.prototype`` 上的 getter-only 访问器，非严格模式下赋值静默失败；
   普通对象字面量却会被真写进去 —— VM 一看值变了就判定环境被 hook，
   走异常分支，产出的 kwscode 里会出现 nibble > 15 的非 hex 字符。
2. **div 布局 canary**：``createElement("div")`` -> ``style.height="20px"``
   -> ``body.appendChild`` -> 读 ``offsetHeight``。真实浏览器挂载后是 20，
   未挂载是 0（CDP 在 www.kuaishou.com 上实测过）。

``did`` 一致性：``kwfv1`` 的明文里带 did，所以传进来的 did 必须与 cookie 里的一致。

用法::

    from utils.sign.weapon_oracle import gen_kwfv1, gen_kwscode, oracle_available
    if oracle_available():
        kwfv1 = gen_kwfv1(did="web_xxx", href="https://www.kuaishou.com/new-reco")
        kwscode = gen_kwscode(sec_token=cfg.sec_token)
"""

from __future__ import annotations

import json
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlparse

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = REPO_ROOT / "reverse" / "tools"
WEAPON_DIR = REPO_ROOT / "reverse" / "bundles" / "weapon"

KWF_ORACLE = TOOLS_DIR / "kwf_oracle.js"
KWS_ORACLE = TOOLS_DIR / "kws_oracle.js"

# Chrome has emitted two kwf generations in the captured sessions.  The
# original www bootstrap (kwf-0.0.2) produces the 174-character value, while
# the newer CP bootstrap (kwf-0.1.1, kept as ``reverse/js/cp-kwf.js``) produces
# the 218-character value.  ``kwfcv1`` is the only persisted discriminator we
# have across the page switch, so keep the selection explicit and deterministic
# instead of padding/truncating an oracle result.
KWF_CURRENT_SCRIPT = REPO_ROOT / "reverse" / "js" / "cp-kwf.js"
KWF_LEGACY_SCRIPT = WEAPON_DIR / "kwf-0.0.2.2cee19b4b7dec496.js"
KWF_CURRENT_CAPTURE_NAME = "kwf-0.1.1.a6d1e5d478c2cafa.js"
KWF_NEW_GENERATION_COUNTER = 999

# 仅供显式离线自检。生产链必须执行 /s/w/c 的 exact signUrl，不能用这个
# 已抓变体替代服务端本次指派的脚本。
KWS_PREFERRED = "kws-13-0.0.1-obfuscated.6b74e9640ff18648.js"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_KWS_FILENAME = re.compile(
    r"^kws-(\d+)-0\.0\.1-obfuscated\.([0-9a-f]{16})\.js$")
_KWS_MIN_BYTES = 32_000
_KWS_MAX_BYTES = 128_000

# 子进程超时：Brook VM 解释 5 万条字节码，冷启动约 1~3 秒
_TIMEOUT = 60


class UnsupportedKwfScriptError(RuntimeError):
    """gdfp returned an fpUrl whose exact official script was not captured."""


class UnsupportedKwsScriptError(RuntimeError):
    """gdfp returned an invalid/unavailable exact KWS script contract."""


def node_available() -> bool:
    """本机有没有 node。"""
    return shutil.which("node") is not None


def oracle_available() -> bool:
    """预言机是否可用（node + 两个脚本 + 至少一个 kws 变体都在）。"""
    return (node_available() and KWF_ORACLE.exists() and KWS_ORACLE.exists()
            and WEAPON_DIR.exists() and any(WEAPON_DIR.glob("kws-*.js")))


def _run_node(args: list, env_extra: dict = None) -> str:
    """跑 node 子进程，返回 stdout。

    显式指定 ``encoding="utf-8"``：Windows 上默认按 GBK 解，
    脚本里的中文注释会直接抛 UnicodeDecodeError。
    """
    env = dict(os.environ)
    env.update({k: str(v) for k, v in (env_extra or {}).items() if v is not None})
    proc = subprocess.run(
        ["node"] + [str(a) for a in args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=_TIMEOUT, env=env, cwd=str(REPO_ROOT),
    )
    if proc.returncode != 0:
        raise RuntimeError(f"node 退出码 {proc.returncode}: {(proc.stderr or '')[:300]}")
    return (proc.stdout or "").strip()


def _kwf_script_for_counter(kwfcv1: str = "", script_path: str = "") -> str:
    """Choose the captured kwf generation for a persisted browser counter.

    A captured explicit script always wins.  The content hash in ``fpUrl`` is
    part of the browser contract: an unknown URL must fail closed rather than
    silently reusing another bundle with the same semantic version.  Fresh www
    state (empty/low counter) stays on the 0.0.2 fixture; the current Chrome
    sessions switch to the 0.1.1 bundle once the persisted counter reaches the
    observed high range when no fpUrl is available.
    """
    if script_path:
        candidate = Path(str(script_path))
        if candidate.exists():
            return str(candidate)
        # ``fpUrl`` is normally an HTTPS URL.  Resolve only exact captured
        # content-addressed filenames to local immutable copies; never pass a
        # URL to Node as a filesystem path or guess from the version prefix.
        raw_path = str(script_path)
        parsed = urlparse(raw_path)
        capture_name = Path(unquote(parsed.path if parsed.scheme else raw_path)).name.lower()
        if capture_name == KWF_CURRENT_CAPTURE_NAME and KWF_CURRENT_SCRIPT.exists():
            return str(KWF_CURRENT_SCRIPT)
        if capture_name == KWF_LEGACY_SCRIPT.name.lower() and KWF_LEGACY_SCRIPT.exists():
            return str(KWF_LEGACY_SCRIPT)
        raise UnsupportedKwfScriptError(
            f"uncaptured gdfp fpUrl/script_path: {raw_path}"
        )
    try:
        if int(str(kwfcv1)) >= KWF_NEW_GENERATION_COUNTER and KWF_CURRENT_SCRIPT.exists():
            return str(KWF_CURRENT_SCRIPT)
    except (TypeError, ValueError):
        pass
    return ""


def _validate_kws_url(sign_url: str) -> tuple[str, str]:
    """Validate an official content-addressed KWS URL and return host/name."""
    raw = str(sign_url or "")
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    name = Path(unquote(parsed.path)).name
    if (parsed.scheme.lower() != "https" or not host):
        raise UnsupportedKwsScriptError(f"KWS signUrl 必须是 HTTPS: {raw}")
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        raise UnsupportedKwsScriptError(f"KWS signUrl authority 不合法: {raw}")
    if not (host == "static.yximgs.com" or host.endswith(".static.yximgs.com")):
        raise UnsupportedKwsScriptError(f"KWS signUrl 域名不在抓包可信范围: {raw}")
    query = parse_qsl(parsed.query, keep_blank_values=True)
    if (parsed.fragment or "/kws/" not in parsed.path.lower()
            or (query and not (len(query) == 1
                               and query[0][0] == "x-kcdn-pid"
                               and query[0][1].isdigit()))):
        raise UnsupportedKwsScriptError(f"KWS signUrl 路径/查询不符合合同: {raw}")
    if not _KWS_FILENAME.fullmatch(name):
        raise UnsupportedKwsScriptError(f"KWS signUrl 文件名不符合合同: {raw}")
    return host, name


def _looks_like_official_kws(content: bytes) -> bool:
    """Reject HTML/error bodies and non-Brook payloads before caching."""
    if not (_KWS_MIN_BYTES <= len(content) <= _KWS_MAX_BYTES):
        return False
    prefix = content[:256].lstrip()
    if not prefix.startswith(b"(function(){"):
        return False
    return (b"function" in content[:16_000] and b"window" in content
            and re.search(rb'[A-Za-z0-9+/=]{20000,}', content) is not None)


def _kws_content_hash_matches(name: str, content: bytes) -> bool:
    """The filename hash is the middle 16 hex characters of the script MD5."""
    match = _KWS_FILENAME.fullmatch(name)
    return bool(match and hashlib.md5(content).hexdigest()[8:24] == match.group(2))


def _download_exact_kws(sign_url: str, target: Path, href: str,
                        session=None, timeout: float = 30.0) -> Path:
    """Download one exact official signUrl through the Chrome transport."""
    if session is None:
        from utils.transport import shared_session
        http = shared_session()
    else:
        http = session
    referer = href or "https://www.kuaishou.com/new-reco"
    headers = {
        "user-agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/151.0.0.0 Safari/537.36"),
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,ja;q=0.6",
        "referer": referer,
        "sec-fetch-dest": "script",
        "sec-fetch-mode": "no-cors",
        "sec-fetch-site": "cross-site",
    }
    response = http.get(sign_url, headers=headers, timeout=timeout,
                        allow_redirects=False)
    if int(getattr(response, "status_code", 0) or 0) != 200:
        raise UnsupportedKwsScriptError(
            f"exact KWS 下载失败: HTTP {getattr(response, 'status_code', '?')}")
    content = bytes(getattr(response, "content", b"") or b"")
    if not _looks_like_official_kws(content):
        raise UnsupportedKwsScriptError("exact KWS 响应不是受支持的官方 Brook 脚本")
    if not _kws_content_hash_matches(target.name, content):
        raise UnsupportedKwsScriptError("exact KWS 内容与文件名 MD5 hash 不一致")
    target.parent.mkdir(parents=True, exist_ok=True)
    temp_name = ""
    try:
        with tempfile.NamedTemporaryFile(
                mode="wb", prefix=target.name + ".", suffix=".tmp",
                dir=str(target.parent), delete=False) as tmp:
            tmp.write(content)
            tmp.flush()
            os.fsync(tmp.fileno())
            temp_name = tmp.name
        os.replace(temp_name, target)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)
    return target


def _resolve_kws_script(script_path: str = "", sign_url: str = "",
                        href: str = "", session=None) -> tuple[Path, str]:
    """Resolve only the exact requested KWS bundle; never choose a substitute."""
    requested = str(sign_url or script_path or "")
    if not requested:
        raise UnsupportedKwsScriptError("缺少 /s/w/c 返回的 exact signUrl")
    candidate = Path(requested)
    if candidate.exists():
        resolved = candidate.resolve()
        if not _KWS_FILENAME.fullmatch(resolved.name):
            raise UnsupportedKwsScriptError(f"本地 KWS 文件名不符合合同: {resolved}")
        content = resolved.read_bytes()
        if (not _looks_like_official_kws(content)
                or not _kws_content_hash_matches(resolved.name, content)):
            raise UnsupportedKwsScriptError(f"本地 KWS 内容/hash 不符合合同: {resolved}")
        return resolved, resolved.as_uri()
    if not urlparse(requested).scheme and candidate.name == requested:
        local = WEAPON_DIR / candidate.name
        if local.exists() and _KWS_FILENAME.fullmatch(local.name):
            content = local.read_bytes()
            if (not _looks_like_official_kws(content)
                    or not _kws_content_hash_matches(local.name, content)):
                raise UnsupportedKwsScriptError(f"本地 KWS 内容/hash 不符合合同: {local}")
            return local.resolve(), local.resolve().as_uri()
        raise UnsupportedKwsScriptError(f"未捕获的本地 KWS 文件: {requested}")
    _, name = _validate_kws_url(requested)
    local = WEAPON_DIR / name
    if not local.exists():
        _download_exact_kws(requested, local, href, session=session)
    content = local.read_bytes()
    if (not _looks_like_official_kws(content)
            or not _kws_content_hash_matches(local.name, content)):
        raise UnsupportedKwsScriptError(f"本地 exact KWS 缓存损坏: {local}")
    return local.resolve(), requested


def gen_kwfv1(did: str = "", href: str = "https://www.kuaishou.com/new-reco",
              cookie: str = "", hostname: str = "", kwfcv1: str = "",
              current_kwfv1: str = "", return_state: bool = False,
              hardware_concurrency: int = 20, script_path: str = ""):
    """跑官方 kwf 脚本产出当前 ``kwfv1``。

    新页面初始化时会把当时的值冻结为 ``kww``；同一页面后续 Cookie
    ``kwfv1`` 轮换时，二者可以不同，调用方不得用该结果覆盖已有页面快照。

    :param did: 设备标识，必须与 cookie 里的 did 一致。
    :param href: 页面地址（进指纹明文）。
    :param cookie: 完整 cookie 串；不给则用 ``did=<did>`` 兜底。
    :param hostname: 站点域名，默认从 href 推。
    :param script_path: 可选的 fpUrl/本地官方脚本；URL 会解析到仓库内对应的抓包副本。
    :return: 指纹串（当前脚本实测 174 或 218 字符），失败返回空串。
    """
    if not hostname:
        m = re.match(r"https?://([^/]+)", href or "")
        hostname = m.group(1) if m else "www.kuaishou.com"
    selected_script = _kwf_script_for_counter(kwfcv1, script_path)
    out = _run_node([KWF_ORACLE, "--json"], {
        "KS_DID": did,
        "KS_HREF": href,
        "KS_HOSTNAME": hostname,
        "KS_COOKIE": cookie or (f"did={did}" if did else ""),
        "KS_KWFCV1": kwfcv1,
        "KS_KWFV1": current_kwfv1,
        "KS_HARDWARE_CONCURRENCY": hardware_concurrency,
        "KS_KWF_SCRIPT": selected_script or None,
    })
    try:
        state = json.loads(out.splitlines()[-1]) if out else {}
    except Exception:  # noqa: BLE001
        state = {"value": "", "kwfv1": "", "kwfcv1": str(kwfcv1 or "")}
    value = str(state.get("value") or "")
    if return_state:
        return {
            "value": value,
            "kwfv1": str(state.get("kwfv1") or value),
            "kwfcv1": str(state.get("kwfcv1") or kwfcv1 or ""),
        }
    return value


def gen_fingerprint_report(did: str = "", href: str = "https://cp.kuaishou.com/",
                           cookie: str = "", hostname: str = "",
                           kwfcv1: str = "", current_kwfv1: str = "",
                           hardware_concurrency: int = 20,
                           script_path: str = "") -> str:
    """Run the official kwf VM's browser ``getData(1)`` report path.

    This is the encrypted fingerprint body sent as ``data`` to ``/s/w/p``;
    it is not the short ``kwfv1``/``kww`` output from ``getData()``.
    """
    if not hostname:
        m = re.match(r"https?://([^/]+)", href or "")
        hostname = m.group(1) if m else "cp.kuaishou.com"
    out = _run_node([KWF_ORACLE, "--json"], {
        "KS_DID": did,
        "KS_HREF": href,
        "KS_HOSTNAME": hostname,
        "KS_COOKIE": cookie or (f"did={did}" if did else ""),
        "KS_KWFCV1": kwfcv1,
        "KS_KWFV1": current_kwfv1,
        "KS_HARDWARE_CONCURRENCY": hardware_concurrency,
        "KS_KWF_REPORT_MODE": "1",
        "KS_KWF_SCRIPT": _kwf_script_for_counter(kwfcv1, script_path) or None,
    })
    try:
        data = json.loads(out.splitlines()[-1]) if out else {}
    except Exception:  # noqa: BLE001
        return ""
    return str(data.get("value") or "")


def gen_kwscode(sec_token: str = "", script: str = "", did: str = "",
                href: str = "https://www.kuaishou.com/new-reco",
                cookie: str = "", strict: bool = True,
                script_path: str = "", sign_url: str = "", session=None) -> str:
    """Execute the exact official KWS assigned by ``/s/w/c``.

    ``sign_url`` is authoritative.  A captured local path/name is accepted only
    for fixture-backed offline verification.  Unknown URL, invalid host/path,
    download failure, VM failure, or a non-64-hex result all fail closed; this
    function never substitutes another KWS variant.
    """
    requested = sign_url or script_path or script
    selected, source_url = _resolve_kws_script(
        requested, sign_url=sign_url, href=href, session=session)
    raw = _run_node([KWS_ORACLE, selected, "--json"], {
        "KS_SECTOKEN": sec_token,
        "KS_DID": did,
        "KS_HREF": href,
        "KS_COOKIE": cookie or (f"did={did}" if did else ""),
        "KS_KWS_SCRIPT_URL": source_url,
    })
    try:
        data = json.loads(raw.splitlines()[-1])
    except Exception as exc:                               # noqa: BLE001
        raise UnsupportedKwsScriptError("exact KWS oracle 输出无法解析") from exc
    code = str(data.get("kwscode") or "")
    if not _HEX64.match(code):
        raise UnsupportedKwsScriptError(
            f"exact KWS 触发环境检测或输出漂移: {code!r}")
    return code


def gen_kwscode_any(sec_token: str = "", **kwargs) -> str:
    """Disabled compatibility entry point: variant substitution is forbidden."""
    raise UnsupportedKwsScriptError(
        "gen_kwscode_any 已禁用；必须传 /s/w/c 本次返回的 exact signUrl")


def selftest() -> dict:
    """自检：两个预言机是否都能产出合法值。"""
    result = {"node": node_available(), "oracle": oracle_available()}
    if not result["oracle"]:
        return result
    did = "web_" + "0" * 32
    try:
        kwfv1 = gen_kwfv1(did=did)
        result["kwfv1_len"] = len(kwfv1)
        result["kwfv1_ok"] = len(kwfv1) > 100
    except Exception as exc:                               # noqa: BLE001
        result["kwfv1_err"] = str(exc)[:200]
    try:
        code = gen_kwscode(sec_token="x" * 88, did=did,
                           script=KWS_PREFERRED)
        result["kwscode"] = code
        result["kwscode_ok"] = bool(_HEX64.match(code or ""))
    except Exception as exc:                               # noqa: BLE001
        result["kwscode_err"] = str(exc)[:200]
    return result


if __name__ == "__main__":
    import sys
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    for key, value in selftest().items():
        print(f"  {key:14} = {value}")
