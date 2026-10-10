#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""ksuploader 分片上传客户端（纯 HTTP 客户端，无浏览器依赖）。

协议以 2026-08-16 实抓为准（浏览器里真发一条视频抓下来的）：

    探测已传分片   GET  {endpoint}/api/upload/resume?upload_token=<token>
                  -> {data: {existed, fragmentIndex, fragmentList: [{id}, ...]}}
                     existed 为真表示服务端已有整份文件，直接结束

    上传单个分片   POST {endpoint}/api/upload/fragment?upload_token=<token>&fragment_id=<i>
                  Content-Type: application/octet-stream
                  Content-Range: bytes <start>-<end-1>/<total>
                  body = 文件切片
                  -> {result:1, checksum, size}

    收尾          POST {endpoint}/api/upload/complete?fragment_count=<n>&upload_token=<token>

当前重新登录后的 Chrome 视频与图文小文件都实际走
``resume -> fragment -> complete``。旧代码中的 ``POST /api/upload`` 在当前会话没有
成功 Network 证据，因此仍然 fail-closed，不能因为文件小就擅自切换协议。

**参数名是下划线不是驼峰。** 之前按 bundle 里的变量名写成了 ``uploadToken`` /
``fragmentId`` / ``fragmentCount``，服务端照收不误（HTTP 200），但认不出 token，
分片等于没传上去，最后 ``upload/finish`` 才报「视频文件不完整」。

分片大小 4MB（bundle 里 ``1024*1024*4``），并发批次 32（``z = 32``）。
``endpoints`` 是候选列表，逐个试直到成功（源码里 ``for (o = 0; o < x.length; o += 1)``）。
"""

from __future__ import annotations

import os

import requests
from utils.transport import request_errors, shared_session

REQUEST_ERRORS = request_errors()

CHUNK_SIZE = 1024 * 1024 * 4          # bundle: 1024*1024*4
BATCH = 32                            # bundle: z = 32
BIZ_NAME = "KUAISHOU_CREATOR_PLATFORM"
TIMEOUT = 120

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36")
ACCEPT = "application/json, text/plain, */*"
ACCEPT_ENCODING = "gzip, deflate, br, zstd"
ACCEPT_LANGUAGE = "zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,ja;q=0.6"
CP_ROOT = "https://cp.kuaishou.com/"
CP_ORIGIN = "https://cp.kuaishou.com"

_REQUEST_CONTRACTS = {
    ("GET", "/api/upload/resume"): {
        "query": ("upload_token",),
        "headers": (
            "user-agent", "accept", "referer", "accept-encoding",
            "accept-language", "origin", "sec-fetch-dest", "sec-fetch-mode",
            "sec-fetch-site",
        ),
    },
    ("POST", "/api/upload/fragment"): {
        "query": ("upload_token", "fragment_id"),
        "headers": (
            "referer", "user-agent", "accept", "content-type", "content-range",
            "accept-encoding", "accept-language", "origin", "sec-fetch-dest",
            "sec-fetch-mode", "sec-fetch-site",
        ),
    },
    ("POST", "/api/upload/complete"): {
        "query": ("fragment_count", "upload_token"),
        "headers": (
            "user-agent", "accept", "referer", "accept-encoding",
            "accept-language", "origin", "sec-fetch-dest", "sec-fetch-mode",
            "sec-fetch-site",
        ),
    },
}


def _headers(path: str, content_range: str = "") -> dict:
    """Build the exact current Chrome header field order for one upload path."""
    if path == "/api/upload/fragment":
        return {
            "referer": CP_ROOT,
            "user-agent": USER_AGENT,
            "accept": ACCEPT,
            "content-type": "application/octet-stream",
            "content-range": content_range,
            "accept-encoding": ACCEPT_ENCODING,
            "accept-language": ACCEPT_LANGUAGE,
            "origin": CP_ORIGIN,
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "cross-site",
        }
    return {
        "user-agent": USER_AGENT,
        "accept": ACCEPT,
        "referer": CP_ROOT,
        "accept-encoding": ACCEPT_ENCODING,
        "accept-language": ACCEPT_LANGUAGE,
        "origin": CP_ORIGIN,
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "cross-site",
    }


def _base(endpoint: str) -> str:
    """endpoints 里可能是裸域名，也可能带 scheme，统一成 https 前缀且无尾斜杠。"""
    endpoint = (endpoint or "").strip().rstrip("/")
    if not endpoint:
        return ""
    if not endpoint.startswith(("http://", "https://")):
        endpoint = "https://" + endpoint
    return endpoint


class KsUploader:
    """一次文件上传的会话：固定 token，在若干候选 endpoint 间自动切换。"""

    def __init__(self, upload_token: str, endpoints, chunk_size: int = CHUNK_SIZE,
                 session: requests.Session = None):
        """:param upload_token: upload/pre 下发的 token。
        :param endpoints: upload/pre 下发的 endPoints 列表。
        :param chunk_size: 分片大小，默认与浏览器一致的 4MB。
        """
        self.token = upload_token
        self.endpoints = [_base(e) for e in (endpoints or []) if _base(e)]
        if not self.endpoints:
            raise ValueError("没有可用的上传 endpoint（upload/pre 的 endPoints 为空）")
        # Current successful Network used the first endpoint exactly.  There is
        # no retained current request proving retry/failover wire behavior.
        if self.endpoints[0] != "https://upload.kuaishouzt.com":
            raise RuntimeError(
                f"首个上传 endpoint {self.endpoints[0]} 没有当前成功 Chrome 合同，拒绝出网")
        if int(chunk_size) != CHUNK_SIZE:
            raise RuntimeError(
                f"当前成功 Chrome 合同固定分片大小为 {CHUNK_SIZE} 字节；"
                f"拒绝自定义 chunk_size={chunk_size}")
        self.chunk_size = CHUNK_SIZE
        # 共享会话是全站公用的，不能往它的默认头里塞 cp 的 referer/origin：
        # 那会跟着漏进之后每一个 www/live 请求（GET 本来不该发 origin），
        # 所以上传头只逐请求合并。
        self.session = session or shared_session()
        self._idx = 0

    # ------------------------------------------------------------------ #
    # 底层请求：失败时轮换 endpoint                                         #
    # ------------------------------------------------------------------ #
    def _request(self, method: str, path: str, params: dict = None,
                 data: bytes = None, headers: dict = None) -> dict:
        method = str(method).upper()
        contract = _REQUEST_CONTRACTS.get((method, path))
        if contract is None:
            raise RuntimeError(
                f"{method} {path} 没有当前成功 Chrome Network 合同，拒绝出网")
        params = dict(params or {})
        if tuple(params) != contract["query"]:
            raise ValueError(
                f"{method} {path} query 字段/顺序错误: {tuple(params)} "
                f"!= {contract['query']}")
        merged = dict(headers or _headers(path))
        if tuple(merged) != contract["headers"]:
            raise RuntimeError(
                f"{method} {path} header 字段/顺序错误: {tuple(merged)} "
                f"!= {contract['headers']}")
        if "cookie" in merged:
            raise RuntimeError(f"{method} {path} 当前 Chrome 不发送 Cookie")
        if path == "/api/upload/resume":
            if data is not None or "content-type" in merged:
                raise RuntimeError("upload/resume 必须无 body、无 content-type")
        elif path == "/api/upload/complete":
            if data not in (None, b"") or "content-type" in merged:
                raise RuntimeError("upload/complete 必须是 0 字节 body 且无 content-type")
            data = b""  # force the browser-observed Content-Length: 0
        else:
            if not isinstance(data, bytes) or not data:
                raise RuntimeError("upload/fragment body 必须是非空原始 bytes")
            expected = headers.get("content-range", "") if headers else ""
            if not expected.startswith("bytes "):
                raise RuntimeError("upload/fragment 缺少合法 Content-Range")

        url = f"{self.endpoints[0]}{path}"
        try:
            resp = self.session.request(method, url, params=params, data=data,
                                        headers=merged, timeout=TIMEOUT, verify=False)
        except REQUEST_ERRORS as exc:
            raise RuntimeError(f"当前 Chrome 已验证 endpoint 请求失败: {exc}") from exc
        if resp.status_code >= 400:
            raise RuntimeError(f"{resp.status_code} {resp.text[:180]}")
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

    # ------------------------------------------------------------------ #
    # 协议步骤                                                            #
    # ------------------------------------------------------------------ #
    def resume(self) -> dict:
        """探测服务端已有哪些分片。"""
        return self._request("GET", "/api/upload/resume",
                             params={"upload_token": self.token},
                             headers=_headers("/api/upload/resume"))

    def upload_fragment(self, index: int, chunk: bytes, start: int, total: int) -> dict:
        """上传一片。``Content-Range`` 必带，实抓形如 ``bytes 0-8394/8395``。"""
        if not isinstance(chunk, bytes) or not chunk:
            raise ValueError("fragment body 必须是非空原始 bytes")
        if index != 0 or start != 0 or total != len(chunk):
            raise RuntimeError(
                "当前成功 Chrome 只验证单片完整文件："
                "index=0、start=0、total=len(chunk)；其他分片形状拒绝出网")
        content_range = f"bytes {start}-{start + len(chunk) - 1}/{total}"
        headers = _headers("/api/upload/fragment", content_range)
        return self._request("POST", "/api/upload/fragment",
                             params={"upload_token": self.token, "fragment_id": str(index)},
                             data=chunk, headers=headers)

    def complete(self, fragment_count: int) -> dict:
        """收尾。实抓的参数顺序是 fragment_count 在前、upload_token 在后。"""
        if int(fragment_count) != 1:
            raise RuntimeError("当前成功 Chrome 合同只验证 fragment_count=1")
        return self._request("POST", "/api/upload/complete",
                             params={"fragment_count": int(fragment_count),
                                     "upload_token": self.token},
                             data=b"", headers=_headers("/api/upload/complete"))

    def upload_whole(self, blob: bytes) -> dict:
        """当前重新登录会话没有 ``/api/upload`` 成功抓包，严格拒绝。"""
        raise RuntimeError(
            "POST /api/upload 没有当前成功 Chrome Network 合同；禁止按旧图集代码发包")

    # ------------------------------------------------------------------ #
    # 对外入口                                                            #
    # ------------------------------------------------------------------ #
    def upload_file(self, path: str, on_progress=None) -> dict:
        """按浏览器口径上传一个文件：resume 探测 -> 补传缺失分片 -> complete。

        :param path: 本地文件路径。
        :param on_progress: 可选回调 ``fn(已传字节, 总字节)``。
        :return: complete 的响应（或 resume 命中秒传时的响应）。
        """
        total = os.path.getsize(path)
        if total <= 0:
            raise ValueError("上传文件不能为空")
        if total > self.chunk_size:
            raise RuntimeError(
                "当前重新登录后的 Chrome 只保留了一片上传成功证据；"
                "多分片并发/收尾顺序尚未重抓，严格模式拒绝猜测")
        with open(path, "rb") as fp:
            blob = fp.read()
        return self._upload_single_fragment(blob, on_progress=on_progress)

    def _upload_single_fragment(self, blob: bytes, on_progress=None,
                                after_resume=None) -> dict:
        """执行当前唯一有成功证据的一片上传分支。"""
        if not isinstance(blob, bytes) or not blob:
            raise ValueError("上传 body 必须是非空原始 bytes")
        total = len(blob)
        if total > self.chunk_size:
            raise RuntimeError(
                "当前重新登录后的 Chrome 只保留了一片上传成功证据；"
                "多分片并发/收尾顺序尚未重抓，严格模式拒绝猜测")

        info = self.resume()
        # 响应是平铺的、下划线命名的（实抓：
        # {"result":1,"existed":false,"fragment_index":-1,"fragment_list":[],"endpoint":[…]}）
        data = info.get("data") or info
        if data.get("existed"):
            raise RuntimeError("当前 Chrome 没有 existed=true 秒传分支成功证据，拒绝猜测")

        done = {item.get("id") for item in (data.get("fragment_list")
                                            or data.get("fragmentList") or [])
                if isinstance(item, dict)}
        # fragment_list 缺省时按 fragment_index 推：0..index 都已传（-1 表示一片都没有）
        index_hint = data.get("fragment_index", data.get("fragmentIndex"))
        if not done and index_hint is not None and int(index_hint) >= 0:
            done = set(range(int(index_hint) + 1))
        if done or int(index_hint if index_hint is not None else -1) != -1:
            raise RuntimeError("当前 Chrome 没有断点续传分支成功证据，拒绝猜测")

        if after_resume:
            after_resume(info)
        self.upload_fragment(0, blob, 0, total)
        if on_progress:
            on_progress(total, total)
        return self.complete(1)

    def upload_bytes(self, blob: bytes, name: str = "blob", on_progress=None,
                     after_resume=None) -> dict:
        """按当前图文 Network 上传原始图片字节。

        ``name`` 只用于调用侧日志兼容；浏览器这三条 upload-host 请求没有文件名字段，
        因而它绝不能进入 query/header/body。当前仅允许一片、非秒传、非断点分支。
        """
        del name
        return self._upload_single_fragment(
            blob, on_progress=on_progress, after_resume=after_resume)
