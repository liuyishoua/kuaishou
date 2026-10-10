#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""快手创作者中心发布接口（cp.kuaishou.com），风格对齐 douyin 框架。

站点：``https://cp.kuaishou.com/article/publish/video?origin=www.kuaishou.com``
（图文 atlas + 视频 video 两条链路）。
约定：
    - 全部 ``@staticmethod``，第一参数 ``auth``（KuaishouAuth），中文 docstring。
    - 统一域名 ``https://cp.kuaishou.com`` + api；``Referer: .../article/publish/video``；``Origin`` 同域。
    - 请求头注入当前 CP webweapon 会话独立生成的 ``kww``；不得把 Cookie ``kwfv1``
      强行复制成 header 值；query 追加 cp 侧签名（sig3 或 sig4）。
    - 请求体统一 JSON；只有当前 auth 确实持有非空 ``kuaishou.web.cp.api_ph`` 时才把它
      追加为最后一个字段，首轮无票据请求不得伪造空字段。
    - 响应形如 ``{result:1, currentTime, data:{...}, message:"成功"}``。

签名说明（详见 utils/sign/sig3_pure）：
    cp 侧大量接口走 ``__NS_sig3``；但 nearby / ip2poi / video/pc/edit/info / poi/search 与
    **发布提交 /rest/cp/works/v2/video/pc/submit** 走 ``__NS_hxfalcon``（sig4）。路由由
    ``Params.with_cp_sign`` 自动判定。即使个别请求偶尔省略签名仍返回 result:1，也不能据此
    删除字段；当前 Network 中出现的签名必须始终发送。两个签名均为纯算实现，webweapon
    状态按 ``KuaishouAuth`` 会话隔离，禁止跨站点或跨账号共享。
"""

import json
import mimetypes
import os
import re
import time
from contextlib import ExitStack
from tempfile import TemporaryDirectory
from urllib.parse import parse_qsl, urlsplit

import requests

requests.packages.urllib3.disable_warnings()
from loguru import logger

from builder.header import HeaderBuilder, HeaderType
from builder.params import Params
from utils.ksuploader import CHUNK_SIZE, KsUploader
from utils.transport import http_proxy, response_cookies

requests = http_proxy(requests)   # get/post 走 Chrome TLS/ALPN 共享会话

# uploadType 取值（bundle 实测）：视频 Mp.pc = 1，图文固定 10。
UPLOAD_TYPE_VIDEO = 1
UPLOAD_TYPE_ATLAS = 10
# 单张图片上限（bundle: V.size < 15*1024*1024）
ATLAS_IMAGE_MAX_BYTES = 15 * 1024 * 1024
# 图文编辑器返回的 atlasImageCountLimit（实抓为 31）。
ATLAS_IMAGE_MAX_COUNT = 31
# upload/tips/show 的 tips 数组（实抓默认值）
DEFAULT_TIPS = ("collectionRedDot", "collectionBubble", "publishPanoramicVideo", "mmuIsNew")

_IMAGE_SUFFIXES = frozenset({
    ".jpg", ".jpeg", ".jfif", ".png", ".webp", ".bmp", ".gif", ".tif",
    ".tiff", ".ico", ".heic", ".heif", ".avif",
})
_VIDEO_SUFFIXES = frozenset({
    ".mp4", ".mov", ".m4v", ".avi", ".mkv", ".webm", ".flv", ".ts",
    ".mts", ".m2ts", ".3gp", ".3g2", ".mpeg", ".mpg", ".mpe", ".wmv",
    ".asf", ".ogv", ".vob", ".mxf", ".rm", ".rmvb", ".divx",
})
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


# Current successful private-video submit (Chrome reqid 1316, 2026-08-25).
# Keep this tuple separate from the historical 43-field request: JSON key order
# is part of sig4 input and the two browser builds are not wire-compatible.
_CURRENT_VIDEO_SUBMIT_KEYS = (
    "fileId", "coverKey", "coverTimeStamp", "caption", "photoStatus",
    "coverType", "coverTitle", "photoType", "collectionId", "publishTime",
    "longitude", "latitude", "poiId", "notifyResult", "domain",
    "secondDomain", "coverCropped", "pkCoverKey", "profileCoverKey",
    "downloadType", "disableNearbyShow", "allowSameFrame", "movieId",
    "openPrePreview", "declareInfo", "activityIds", "riseQuality", "chapters",
    "videoComposite", "useAiCaptionCover", "useAiCaption", "isUseIdealTime",
    "useAiCover", "kceInfo", "coverSize", "pkCoverTimeStamp", "pkCoverType",
    "pkCoverSize", "innerChannel", "mediaId", "videoInfoMeta", "triggerH265",
    "recTagIdList", "onvideoDuration", "disallowRecreation",
    "previewUrlErrorMessage", "coPublishUser", "coPublishRole", "extraInfo",
    "videoDuration", "kuaishou.web.cp.api_ph",
)

_HISTORICAL_VIDEO_SUBMIT_KEYS = (
    "fileId", "coverKey", "coverTimeStamp", "caption", "photoStatus",
    "coverType", "coverTitle", "photoType", "collectionId", "publishTime",
    "longitude", "latitude", "poiId", "notifyResult", "domain",
    "secondDomain", "coverCropped", "pkCoverKey", "profileCoverKey",
    "downloadType", "disableNearbyShow", "allowSameFrame", "movieId",
    "openPrePreview", "declareInfo", "activityIds", "riseQuality", "chapters",
    "useAiCaptionCover", "useAiCaption", "isUseIdealTime", "useAiCover",
    "kceInfo", "projectId", "recTagIdList", "videoInfoMeta",
    "previewUrlErrorMessage", "coPublishUser", "triggerH265", "mediaId",
    "photoIdStr", "videoDuration", "kuaishou.web.cp.api_ph",
)

_CURRENT_VIDEO_DECLARE_INFO = {
    "source": 0,
    "platform": 0,
    "time": 0,
    "location": "",
    "sourceId": 0,
    "sourceName": "",
    "statementId": 0,
}


# Browser-captured CP contracts. These are ordered key tuples because
# JSON.stringify preserves insertion order and sig3/sig4 consume those bytes.
# A path absent from this table has no successful retained Network request and
# must not be sent by the generic request helper.
_CP_POST_BODY_KEY_CONTRACTS = {
    "/rest/v2/creator/pc/authority/account/current": {
        (), ("kuaishou.web.cp.api_ph",),
    },
    "/rest/v2/creator/pc/frontend/kswitch/config": {
        ("keys",), ("keys", "kuaishou.web.cp.api_ph"),
    },
    "/rest/bamboo/pc/hotspot/show": {
        (), ("kuaishou.web.cp.api_ph",),
    },
    "/rest/wd/pc/emotion/package/list": {
        ("kuaishou.web.cp.api_ph",),
    },
    "/rest/wd/kconf/get": {
        ("key", "type", "kuaishou.web.cp.api_ph"),
    },
    "/rest/cp/creator/comment/report/menu": {
        ("kuaishou.web.cp.api_ph",),
    },
    "/rest/cp/works/v2/common/pc/fe/kconf": {
        ("kuaishou.web.cp.api_ph",),
    },
    "/rest/cp/works/v2/video/pc/upload/tips/show": {
        ("tips", "kuaishou.web.cp.api_ph"),
    },
    "/rest/v2/creator/pc/school/category/tree": {
        ("kuaishou.web.cp.api_ph",),
    },
    "/rest/cp/works/v2/common/pc/current/user": {
        ("kuaishou.web.cp.api_ph",),
    },
    "/rest/cp/works/v2/collection/tab": {
        ("kuaishou.web.cp.api_ph",),
    },
    "/rest/v2/creator/pc/notification/unReadCountV3": {
        ("kuaishou.web.cp.api_ph",),
    },
    "/rest/cp/creator/pc/home/userInfo": {
        ("kuaishou.web.cp.api_ph",),
    },
    "/rest/cp/creator/analysis/export/task/list": {
        ("page", "count", "kuaishou.web.cp.api_ph"),
    },
    "/rest/cp/creator/pc/home/infoV2": {
        ("kuaishou.web.cp.api_ph",),
    },
    "/rest/v2/creator/pc/satisfy/list": {
        ("page", "forceShow", "kuaishou.web.cp.api_ph"),
    },
    # Creator manage page work list.  The cursor/time values are opaque
    # request inputs; only this exact key order is accepted.
    "/rest/cp/works/v2/video/pc/photo/list": {
        ("queryType", "cursor", "startTime", "endTime", "limit",
         "timeRangeType", "keyword", "kuaishou.web.cp.api_ph"),
    },
    "/rest/cp/works/v2/common/pc/report": {
        ("bizKey", "bizType", "data", "kuaishou.web.cp.api_ph"),
    },
    "/rest/cp/works/v2/video/pc/publish/refresh": {
        ("ids", "kuaishou.web.cp.api_ph"),
    },
    "/rest/cp/works/atlas/pc/upload/config": {
        ("kuaishou.web.cp.api_ph",),
    },
    "/rest/cp/works/v2/common/pc/w/info": {
        ("biz", "kuaishou.web.cp.api_ph"),
    },
    "/rest/cp/works/v2/collection/visible": {
        ("kuaishou.web.cp.api_ph",),
    },
    "/rest/cp/works/atlas/pc/publishInfo/snapshot/info": {
        ("kuaishou.web.cp.api_ph",),
    },
    "/rest/cp/creator/pc/magnetic/guide": {
        ("type", "kuaishou.web.cp.api_ph"),
    },
    "/rest/cp/works/v2/video/pc/upload/config": {
        ("kuaishou.web.cp.api_ph",),
    },
    "/rest/cp/works/v2/video/pc/upload/domain/list": {
        ("kuaishou.web.cp.api_ph",),
    },
    "/rest/cp/works/v2/video/pc/snapshot/info": {
        ("photoType", "kuaishou.web.cp.api_ph"),
    },
    "/rest/cp/works/v2/video/pc/upload/cover/profile": {
        ("kuaishou.web.cp.api_ph",),
    },
    # Current 2026-08-25 upload/edit Network after selecting sample.mp4.
    "/rest/wd/relation/isFollow": {
        ("userId", "kuaishou.web.cp.api_ph"),
    },
    "/rest/cp/works/v2/video/pc/realize/entrance": {
        ("movieId", "kuaishou.web.cp.api_ph"),
    },
    "/rest/cp/works/v2/video/pc/realize/banner/entrance": {
        ("moviedId", "kuaishou.web.cp.api_ph"),
    },
    "/rest/cp/works/v2/video/pc/publish/time": {
        ("kuaishou.web.cp.api_ph",),
    },
    "/rest/v2/creator/activity/pc/list": {
        ("page", "count", "category", "rewardType", "sortType", "pageSource",
         "kuaishou.web.cp.api_ph"),
        ("page", "count", "category", "sortType", "rewardType", "pageSource",
         "kuaishou.web.cp.api_ph"),
    },
    "/rest/cp/works/v2/collection/canAdd": {
        ("kuaishou.web.cp.api_ph",),
    },
    "/rest/cp/works/v2/collection/canAddAtlas": {
        ("kuaishou.web.cp.api_ph",),
    },
    "/rest/v2/creator/activity/pc/tab": {
        ("kuaishou.web.cp.api_ph",),
    },
    "/rest/v2/creator/activity/pc/filter": {
        ("kuaishou.web.cp.api_ph",),
    },
    "/rest/cp/works/v4/video/pc/upload/material/specified": {
        ("fileId", "kuaishou.web.cp.api_ph"),
    },
    "/rest/cp/works/v4/video/pc/cover/edit/recommend/submit": {
        ("fileId", "kuaishou.web.cp.api_ph"),
    },
    "/rest/cp/works/v4/video/pc/cover/edit/recommend/query": {
        ("fileId", "jobId", "kuaishou.web.cp.api_ph"),
    },
    "/rest/cp/works/v2/video/pc/publishInfo/snapshot/save": {
        (
            "fileId", "coverKey", "coverTimeStamp", "caption", "photoStatus",
            "coverType", "coverTitle", "photoType", "collectionId", "publishTime",
            "longitude", "latitude", "poiId", "notifyResult", "domain",
            "secondDomain", "coverCropped", "pkCoverKey", "profileCoverKey",
            "fileName", "fileType", "onvideoFileName", "onvideoFileSize", "fileSize",
            "downloadType", "disableNearbyShow", "allowSameFrame", "movieId",
            "openPrePreview", "declareInfo", "activityIds", "riseQuality", "chapters",
            "videoFirstFrameURL", "videoSizeWidth", "videoSizeHeight",
            "useAiCaptionCover", "useAiCaption", "isUseIdealTime", "useAiCover",
            "kceInfo", "projectId", "recTagIdList", "videoInfoMeta",
            "previewUrlErrorMessage", "needDeleteKey", "coPublishUser", "triggerH265",
            "duration", "width", "height", "mediaId", "coverMediaId", "photoIdStr",
            "videoDuration", "fileToken", "kuaishou.web.cp.api_ph",
        ),
    },
    "/rest/cp/works/v4/video/pc/upload/cover/extract": {
        ("fileId", "durations", "kuaishou.web.cp.api_ph"),
    },
    "/rest/cp/works/v4/video/pc/upload/cover/extract/query": {
        ("fileId", "kuaishou.web.cp.api_ph"),
    },
    # Successful private video publish capture (publish_flow.json).
    "/rest/cp/works/v2/video/pc/upload/pre": {
        ("uploadType", "kuaishou.web.cp.api_ph"),
    },
    "/rest/cp/works/v2/video/pc/upload/finish": {
        ("token", "fileName", "fileType", "fileLength",
         "kuaishou.web.cp.api_ph"),
    },
    "/rest/cp/works/v2/video/pc/submit": {
        _CURRENT_VIDEO_SUBMIT_KEYS,
        _HISTORICAL_VIDEO_SUBMIT_KEYS,
    },
    # Successful private atlas publish contract captured from Chrome Network.
    "/rest/cp/works/atlas/pc/upload/pre": {
        ("uploadType", "pictureCount", "fileExtendNames",
         "kuaishou.web.cp.api_ph"),
        ("atlasId", "fileId", "uploadType", "pictureCount", "fileExtendNames",
         "kuaishou.web.cp.api_ph"),
    },
    "/rest/cp/works/atlas/pc/upload/single/finish": {
        ("fileId", "atlasId", "blobKey", "kuaishou.web.cp.api_ph"),
    },
    "/rest/cp/works/atlas/pc/publishInfo/snapshot/save": {
        (
            "fileId", "atlasId", "caption", "photoStatus", "longitude",
            "latitude", "declareInfo", "activityIds", "publishTime",
            "coPublishUser", "kuaishou.web.cp.api_ph",
        ),
    },
    "/rest/cp/works/atlas/pc/upload/finish": {
        ("fileId", "atlasId", "blobKey", "kuaishou.web.cp.api_ph"),
    },
    "/rest/cp/works/atlas/pc/publish/submit": {
        ("fileId", "atlasId", "caption", "photoStatus", "longitude", "latitude",
         "declareInfo", "activityIds", "publishTime", "coPublishUser",
         "useAiCaption", "coverType", "kuaishou.web.cp.api_ph"),
    },
}

_CP_COOKIE_KEY_CONTRACTS = {
    "cp_creator_initial": (
        "did", "wid", "didv", "userId", "bUserId", "kuaishou.web.cp.api_st",
        "kuaishou.web.cp.api_ph", "kwpsecproductname", "kwssectoken",
        "kwscode", "kwfv1",
    ),
    "cp_creator_restricted_probe": (
        "did", "wid", "didv", "userId", "bUserId", "kuaishou.web.cp.api_st",
        "kuaishou.web.cp.api_ph", "kwssectoken", "kwscode", "kwfv1",
        "kwpsecproductname",
    ),
    "cp_creator_manage_initial": (
        "did", "wid", "didv", "userId", "bUserId", "kuaishou.web.cp.api_st",
        "kuaishou.web.cp.api_ph", "kwssectoken", "kwscode", "kwfv1",
        "kwpsecproductname"),
    "cp_creator_manage_warmed": (
        "did", "wid", "didv", "userId", "bUserId", "kuaishou.web.cp.api_st",
        "kuaishou.web.cp.api_ph", "kwssectoken", "kwscode", "kwfv1",
        "kwpsecproductname"),
    "cp_creator_manage_refreshed": (
        "did", "wid", "didv", "userId", "bUserId", "kuaishou.web.cp.api_st",
        "kuaishou.web.cp.api_ph", "kwpsecproductname", "kwssectoken",
        "kwscode", "kwfv1"),
    "cp_creator_warmed": (
        "did", "wid", "didv", "userId", "bUserId", "kuaishou.web.cp.api_st",
        "kuaishou.web.cp.api_ph", "kwpsecproductname", "kwscode",
        "kwssectoken", "kwfv1",
    ),
    "cp_creator_refreshed": (
        "did", "wid", "didv", "userId", "bUserId", "kuaishou.web.cp.api_st",
        "kuaishou.web.cp.api_ph", "kwpsecproductname", "kwscode",
        "kwssectoken", "kwfv1",
    ),
    "cp": (
        "did", "wid", "didv", "userId", "bUserId", "kuaishou.web.cp.api_st",
        "kuaishou.web.cp.api_ph", "kwpsecproductname", "kwscode",
        "kwssectoken", "kwfv1",
    ),
    "cp_upload": (
        "did", "wid", "didv", "userId", "bUserId", "kuaishou.web.cp.api_st",
        "kuaishou.web.cp.api_ph", "kwpsecproductname", "kwfv1", "kwssectoken",
        "kwscode",
    ),
    "cp_video_submit": (
        "did", "wid", "didv", "userId", "bUserId", "kuaishou.web.cp.api_st",
        "kuaishou.web.cp.api_ph", "kwpsecproductname", "kwfv1", "kwssectoken",
        "kwscode",
    ),
    "cp_post_publish_manage": (
        "did", "wid", "didv", "userId", "bUserId", "kuaishou.web.cp.api_st",
        "kuaishou.web.cp.api_ph", "kwpsecproductname", "kwssectoken",
        "kwscode", "kwfv1",
    ),
    "cp_atlas": (
        "did", "wid", "didv", "userId", "bUserId", "kuaishou.web.cp.api_st",
        "kuaishou.web.cp.api_ph", "kwpsecproductname", "kwfv1", "kwssectoken",
        "kwscode",
    ),
    "onvideo_bootstrap": (
        "did", "wid", "didv", "userId", "bUserId", "kuaishou.web.cp.api_st",
        "kuaishou.web.cp.api_ph", "kwpsecproductname", "kwfv1", "kwssectoken",
        "kwscode",
    ),
    "onvideo_post_bootstrap": (
        "did", "wid", "didv", "userId", "bUserId", "kuaishou.web.cp.api_st",
        "kuaishou.web.cp.api_ph", "kwpsecproductname", "ks_onvideo_token",
        "kwssectoken", "kwscode", "kwfv1",
    ),
    "onvideo_warm": (
        "did", "wid", "didv", "userId", "bUserId", "kuaishou.web.cp.api_st",
        "kuaishou.web.cp.api_ph", "ks_onvideo_token", "kwpsecproductname",
        "kwscode", "kwssectoken", "kwfv1",
    ),
}

_CP_HEADER_KEY_CONTRACTS = {
    "cp_creator_json": (
        "referer", "user-agent", "accept", "content-type",
        "returnsetrootdomainloginurl", "accept-encoding", "accept-language", "cookie",
        "origin", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
    ),
    "cp_creator_axios": (
        "referer", "x-requested-with", "user-agent", "accept", "content-type",
        "returnsetrootdomainloginurl", "accept-encoding", "accept-language", "cookie",
        "origin", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
    ),
    "cp_creator_manage_json": (
        "referer", "user-agent", "accept", "content-type",
        "returnsetrootdomainloginurl", "accept-encoding", "accept-language",
        "cookie", "origin", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
    ),
    "cp_creator_manage_axios": (
        "referer", "x-requested-with", "user-agent", "accept", "content-type",
        "returnsetrootdomainloginurl", "accept-encoding", "accept-language",
        "cookie", "origin", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
    ),
    "cp": (
        "referer", "user-agent", "content-type", "kww", "accept",
        "accept-encoding", "accept-language", "cookie", "origin", "sec-fetch-dest",
        "sec-fetch-mode", "sec-fetch-site",
    ),
    "cp_submit": (
        "referer", "user-agent", "content-type", "kww", "accept",
        "accept-encoding", "accept-language", "connection", "content-length",
        "cookie", "host", "origin", "sec-fetch-dest", "sec-fetch-mode",
        "sec-fetch-site",
    ),
    "onvideo": (
        "user-agent", "kww", "referer", "accept", "accept-encoding",
        "accept-language", "cookie", "origin", "priority", "sec-fetch-dest",
        "sec-fetch-mode", "sec-fetch-site",
    ),
    "cp_upload_get": (
        "user-agent", "kww", "referer", "accept", "accept-encoding",
        "accept-language", "cookie", "sec-fetch-dest", "sec-fetch-mode",
        "sec-fetch-site",
    ),
}

_CP_UNSIGNED_PATHS = {
    "/rest/bamboo/pc/hotspot/show",
    "/rest/wd/pc/emotion/package/list",
    "/rest/wd/kconf/get",
    "/rest/wd/relation/isFollow",
}
_CP_SIG4_PATHS = {"/rest/cp/works/v2/video/pc/submit"}

_CP_VIDEO_UPLOAD_POST_PATHS = {
    "/rest/wd/relation/isFollow",
    "/rest/cp/works/v2/video/pc/realize/entrance",
    "/rest/cp/works/v2/video/pc/upload/pre",
    "/rest/cp/works/v2/video/pc/realize/banner/entrance",
    "/rest/cp/works/v2/video/pc/publish/time",
    "/rest/v2/creator/activity/pc/list",
    "/rest/cp/works/v2/collection/canAdd",
    "/rest/v2/creator/activity/pc/tab",
    "/rest/v2/creator/activity/pc/filter",
    "/rest/cp/works/v2/video/pc/upload/finish",
    "/rest/cp/works/v4/video/pc/upload/material/specified",
    "/rest/cp/works/v4/video/pc/cover/edit/recommend/submit",
    "/rest/cp/works/v4/video/pc/cover/edit/recommend/query",
    "/rest/cp/works/v2/video/pc/publishInfo/snapshot/save",
    "/rest/cp/works/v4/video/pc/upload/cover/extract",
    "/rest/cp/works/v4/video/pc/upload/cover/extract/query",
    "/rest/cp/works/v2/video/pc/submit",
    "/rest/cp/works/v2/common/pc/report",
}

_CP_EXPLICIT_HTTP11_POST_PATHS = {
    "/rest/cp/works/v2/common/pc/report",
    "/rest/cp/works/v2/video/pc/submit",
}

# Paths that are unambiguously in the atlas editor/upload phase.  The final
# ``upload/finish`` and ``publish/submit`` endpoints are included here too:
# their request shapes were recovered from the retained atlas capture, while
# all runtime values (IDs, blob keys, api_ph, Cookie and sig3) are generated by
# the current Python session.  A browser is never consulted at runtime.
_CP_ATLAS_UPLOAD_POST_PATHS = {
    "/rest/cp/works/atlas/pc/publishInfo/snapshot/info",
    "/rest/cp/works/v2/collection/canAddAtlas",
    "/rest/cp/works/atlas/pc/upload/pre",
    "/rest/cp/works/atlas/pc/upload/single/finish",
    "/rest/cp/works/atlas/pc/publishInfo/snapshot/save",
    "/rest/cp/works/atlas/pc/upload/finish",
    "/rest/cp/works/atlas/pc/publish/submit",
}

# The atlas final endpoints are valid Python runtime operations.  Their
# retained capture is used only as a wire-shape contract; it is not an auth
# cookie or response replay.  Keep this set for compatibility with callers
# that introspect it, but do not use it as a runtime/browser gate.
_CP_HISTORICAL_ONLY_POST_PATHS = set()

_CP_POST_FIXED_VALUES = {
    "/rest/cp/works/v2/video/pc/realize/entrance": {"movieId": ""},
    # The browser really sends this misspelled key; correcting it changes the wire.
    "/rest/cp/works/v2/video/pc/realize/banner/entrance": {"moviedId": ""},
    "/rest/cp/works/v2/video/pc/upload/pre": {"uploadType": UPLOAD_TYPE_VIDEO},
    "/rest/v2/creator/activity/pc/list": {
        "page": 1, "count": 20, "category": 0, "rewardType": 0,
        "sortType": 0, "pageSource": 2,
    },
    "/rest/cp/works/v4/video/pc/upload/cover/extract": {
        "durations": [0] * 16,
    },
    "/rest/cp/works/v2/video/pc/submit": {
        "coverTimeStamp": 0, "caption": "", "photoStatus": 2,
        "coverType": 1, "coverTitle": "", "photoType": 0,
        "collectionId": 0, "publishTime": 0, "longitude": "", "latitude": "",
        "poiId": 0, "notifyResult": 0, "domain": "", "secondDomain": "",
        "coverCropped": False, "pkCoverKey": "", "profileCoverKey": "",
        "downloadType": 1, "disableNearbyShow": False, "allowSameFrame": True,
        "movieId": "", "openPrePreview": False,
        "declareInfo": _CURRENT_VIDEO_DECLARE_INFO, "activityIds": [],
        "riseQuality": False, "chapters": None, "videoComposite": None,
        "useAiCaptionCover": False, "useAiCaption": False,
        "isUseIdealTime": False, "useAiCover": False, "kceInfo": "",
        "coverSize": "", "pkCoverTimeStamp": -1, "pkCoverType": 1,
        "pkCoverSize": "", "innerChannel": 0, "videoInfoMeta": "",
        "triggerH265": False, "recTagIdList": [], "onvideoDuration": 0,
        "disallowRecreation": False, "previewUrlErrorMessage": "",
        "coPublishUser": [], "coPublishRole": 0, "extraInfo": "",
    },
    "/rest/cp/works/v2/common/pc/report": {
        "bizType": 1,
        "data": "{}",
    },
    "/rest/cp/works/atlas/pc/upload/pre": {
        "uploadType": UPLOAD_TYPE_ATLAS,
        "pictureCount": 1,
        "fileExtendNames": '[{"fileExtendName":"image/png"}]',
    },
    "/rest/cp/works/atlas/pc/publishInfo/snapshot/save": {
        "caption": "",
        "photoStatus": 1,
        "longitude": "",
        "latitude": "",
        "declareInfo": {},
        "activityIds": [],
        "publishTime": 0,
        "coPublishUser": [],
    },
}


def _cookie_names(raw: str) -> tuple:
    return tuple(part.split("=", 1)[0] for part in (raw or "").split("; ") if part)


def _cp_cookie_profile(auth, site: str) -> str:
    if site == "cp_creator":
        phase = getattr(auth, "_cp_cookie_phase", "initial")
        return ("cp_creator_refreshed" if phase == "refreshed"
                else "cp_creator_warmed" if phase == "warmed"
                else "cp_creator_initial")
    if site == "cp_creator_manage":
        phase = getattr(auth, "_cp_cookie_phase", "initial")
        return ("cp_creator_manage_refreshed" if phase == "refreshed"
                else "cp_creator_manage_warmed" if phase == "warmed"
                else "cp_creator_manage_initial")
    if site == "onvideo":
        return ("onvideo_post_bootstrap"
                if getattr(auth, "_onvideo_cookie_phase", "warm") == "post_bootstrap"
                else "onvideo_warm")
    return site


def _assert_cp_body_contract(api: str, body: dict, auth) -> None:
    if (api in _CP_HISTORICAL_ONLY_POST_PATHS
            and getattr(auth, "_cp_cookie_phase", None) != "historical"):
        raise RuntimeError(
            f"{api} 只有旧会话成功 fixture，当前重新登录 Chrome 未抓到成功请求，拒绝出网")
    allowed = _CP_POST_BODY_KEY_CONTRACTS.get(api)
    if allowed is None:
        raise RuntimeError(
            f"{api} 尚无成功 Chrome Network 请求合同，拒绝按代码形状发包")
    actual = tuple((body or {}).keys())
    historical = getattr(auth, "_cp_cookie_phase", None) == "historical"
    if api == "/rest/cp/works/v2/video/pc/submit":
        expected = (_HISTORICAL_VIDEO_SUBMIT_KEYS if historical
                    else _CURRENT_VIDEO_SUBMIT_KEYS)
        if actual != expected:
            raise ValueError(
                f"{api} body 字段/顺序不符合当前会话 Chrome Network: "
                f"{actual} != {expected}")
    if actual not in allowed:
        raise ValueError(
            f"{api} body 字段/顺序不符合 Chrome Network: {actual}，允许 {sorted(allowed)}")
    # No-api_ph variants are retained only for the explicitly historical
    # creator-shell fixture. Current direct navigation always carries api_ph.
    if (getattr(auth, "_cp_cookie_phase", None) != "historical"
            and "kuaishou.web.cp.api_ph" not in actual):
        raise RuntimeError(f"{api} 缺少当前 Chrome 必带的 kuaishou.web.cp.api_ph，拒绝出网")
    fixed_values = _CP_POST_FIXED_VALUES.get(api, {})
    if (historical and (api.startswith("/rest/cp/works/atlas/pc/")
                        or api == "/rest/cp/works/v2/video/pc/submit")):
        fixed_values = {}
    for key, value in fixed_values.items():
        if body.get(key) != value:
            raise ValueError(
                f"{api} 固定字段 {key} 不符合当前 Chrome Network: "
                f"{body.get(key)!r} != {value!r}")
    if api == "/rest/cp/works/v2/video/pc/submit" and not historical:
        dynamic_types = {
            "fileId": int, "coverKey": str, "mediaId": str,
            "videoDuration": int, "kuaishou.web.cp.api_ph": str,
        }
        for key, expected_type in dynamic_types.items():
            if type(body.get(key)) is not expected_type:
                raise ValueError(
                    f"{api} 当前 Chrome 字段 {key} 类型必须为 "
                    f"{expected_type.__name__}")
        if body["fileId"] <= 0:
            raise ValueError(f"{api} fileId 必须来自当前 upload/finish 的正整数")
        if (len(body["coverKey"]) != 42
                or not body["coverKey"].startswith("cp_video_upload_cover_")
                or not body["coverKey"].endswith(".jpg")):
            raise ValueError(f"{api} coverKey 不符合当前 upload/finish 的 42 字符形状")
        if len(body["mediaId"]) != 26 or not body["mediaId"].isdigit():
            raise ValueError(f"{api} mediaId 不符合当前 upload/finish 的 26 位数字形状")
        if body["videoDuration"] <= 0:
            raise ValueError(f"{api} videoDuration 必须来自当前 upload/finish 且大于 0")
        if len(body["kuaishou.web.cp.api_ph"]) != 36:
            raise ValueError(f"{api} api_ph 必须为当前 Network 的 36 字符票据")


def _assert_cp_headers(style: str, headers: dict) -> None:
    expected = _CP_HEADER_KEY_CONTRACTS[style]
    if style.startswith("cp_creator_manage_") and {
            "cache-control", "pragma"}.issubset(headers):
        expected = tuple(
            key for key in expected
            if key not in {"cookie", "origin"}
        )[:expected.index("accept-language") + 1] + (
            "cache-control", "cookie", "origin", "pragma",
        ) + tuple(
            key for key in expected
            if key not in {"cookie", "origin"}
            and expected.index(key) > expected.index("accept-language")
        )
    actual = tuple(headers)
    if actual != expected:
        raise RuntimeError(
            f"CP header 字段/顺序不符合 Chrome Network ({style}): {actual} != {expected}")


def _assert_cp_url_contract(api: str, url: str) -> None:
    query_pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    query = dict(query_pairs)
    sig3 = query.get("__NS_sig3")
    sig4 = query.get("__NS_hxfalcon")
    if api in _CP_UNSIGNED_PATHS:
        if sig3 or sig4:
            raise RuntimeError(f"{api} Chrome Network 不带签名，当前请求却带了签名")
    elif api in _CP_SIG4_PATHS:
        if ([key for key, _ in query_pairs] != ["__NS_hxfalcon", "caver"]
                or len(sig4 or "") != 267 or query.get("caver") != "2" or sig3):
            raise RuntimeError(f"{api} 必须严格使用 267 字符 sig4 + caver=2")
    elif len(sig3 or "") != 56 or sig4:
        raise RuntimeError(f"{api} 必须严格使用 56 字符 sig3")


def _url(base: str, api: str, params: Params) -> str:
    """拼最终 url；query 自己序列化，理由见 ks_apis/kuaishou_api.py 的同名函数。"""
    query = params.to_query_string()
    if not query:
        return f'{base}{api}'
    sep = '&' if '?' in api else '?'
    return f'{base}{api}{sep}{query}'


class KuaishouPublishAPI:
    PUBLIC_METHOD_REGISTRY = (
        "atlas_activity_filter", "atlas_activity_list", "atlas_activity_tab",
        "atlas_cover_upload", "atlas_publish_info_snapshot_info",
        "atlas_publish_info_snapshot_save", "atlas_realize_entrance",
        "atlas_upload_config", "atlas_upload_finish", "atlas_upload_pre",
        "atlas_upload_single_finish", "authority_account_current",
        "bamboo_hotspot_show", "collection_can_add", "collection_can_add_atlas",
        "collection_tab", "collection_visible", "creator_activity_filter",
        "creator_activity_list", "creator_activity_tab",
        "creator_comment_report_menu", "creator_export_task_list",
        "creator_home_info_v2", "creator_home_user_info",
        "creator_satisfy_list", "current_user", "emotion_package_list",
        "fe_kconf", "kswitch_config", "magnetic_guide", "material_fonts",
        "notification_unread_count", "publish_atlas", "publish_atlas_images",
        "publish_media_file",
        "publish_video", "publish_video_file", "relation_is_follow",
        "require_publish_authority",
        "school_category_tree", "upload_atlas_images", "upload_video_file",
        "video_cover_extract", "video_cover_extract_query",
        "video_cover_profile", "video_cover_recommend_query",
        "video_cover_recommend_submit", "video_cover_report", "video_cover_upload",
        "video_detect_result", "video_detect_start", "video_material_specified",
        "video_photo_list",
        "video_publish_info_save", "video_publish_refresh", "video_publish_time",
        "video_realize_banner_entrance", "video_realize_entrance",
        "video_snapshot_info", "video_upload_config", "video_upload_cover_view",
        "video_upload_domain_list", "video_upload_finish", "video_upload_pre",
        "video_upload_tips_show", "w_info", "wd_kconf_get",
    )
    cp_url = 'https://cp.kuaishou.com'
    onvideo_url = 'https://onvideoapi.kuaishou.com'
    # Current Chrome Network (2026-08-25 re-login, direct creator-page
    # navigation) uses the URL actually shown in the address bar.  The old
    # ``source=NewReco`` suffix belonged to an earlier entry flow and is not
    # present on the current page, so it must not be added speculatively.
    publish_referer = 'https://cp.kuaishou.com/article/publish/video?origin=www.kuaishou.com'
    post_publish_manage_referer = (
        'https://cp.kuaishou.com/article/manage/video?status=2&from=publish')

    # ------------------------------------------------------------------ #
    # 内部通用请求器                                                        #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _wire_headers(auth, headers, site: str = "cp"):
        """Attach the complete browser Cookie header, including scoped names."""
        serializer = getattr(auth, "cookie_header", None)
        if callable(serializer):
            raw = serializer(site=site)
            headers.set_header("cookie", raw)
            if (getattr(auth, "_cp_ignore_cache", False)
                    and site == "cp_creator_manage"
                    and getattr(auth, "_cp_cookie_phase", "initial") in {"initial", "warmed"}):
                headers.set_header("cache-control", "no-cache")
                headers.set_header("pragma", "no-cache")
            if getattr(auth, "_cp_cookie_phase", None) != "historical":
                profile = _cp_cookie_profile(auth, site)
                expected = _CP_COOKIE_KEY_CONTRACTS.get(profile)
                actual = _cookie_names(raw)
                if expected and actual != expected:
                    raise RuntimeError(
                        f"Cookie profile {profile} 不完整或顺序错误，拒绝出网: "
                        f"{actual} != {expected}")
                products = [value for key, value in
                            (part.split("=", 1) for part in raw.split("; ") if "=" in part)
                            if key == "kwpsecproductname"]
                expected_product = ("kuaishou-vision"
                                    if profile in {"cp_upload", "cp_video_submit",
                                                   "cp_post_publish_manage"}
                                    else "onvideo-cp")
                if products != [expected_product]:
                    raise RuntimeError(
                        f"Cookie profile {profile} 的 kwpsecproductname 必须为 "
                        f"{expected_product}，"
                        f"实际 {products}")
            # 页面 kww 已在组头阶段冻结；Cookie 刷新不能反向覆盖它。
        return headers

    @staticmethod
    def _post(auth, api: str, body: dict = None, referer: str = None,
              header_style: str = "cp", with_kww: bool = True,
              creator_headers: bool = False,
              upload_context: str = None, wire_site: str = None) -> dict:
        """通用 POST（JSON body），按会话状态注入 kww/header profile 与 cp api_ph。

        Chrome 创作者中心首轮可能尚未拿到 ``kuaishou.web.cp.api_ph``，此时
        只发送业务 body；拿到真实 cookie 后才把 api_ph 追加为最后一个字段。

        :param auth: KuaishouAuth。
        :param api: pathname，如 /rest/cp/works/v2/common/pc/current/user。
        :param body: 业务 body（会与 api_ph 基座合并）。
        :param referer: Referer，默认发布页。
        :return: 响应 JSON。
        """
        if upload_context not in {None, "video", "atlas"}:
            raise ValueError(f"unknown CP upload_context: {upload_context}")
        historical = getattr(auth, "_cp_cookie_phase", None) == "historical"
        if not historical:
            if upload_context is None:
                if api in _CP_ATLAS_UPLOAD_POST_PATHS:
                    upload_context = "atlas"
                elif api in _CP_VIDEO_UPLOAD_POST_PATHS:
                    upload_context = "video"
            switch_name = ("use_cp_atlas" if upload_context == "atlas"
                           else "use_cp_upload" if upload_context == "video"
                           else None)
            switch = getattr(auth, switch_name, None) if switch_name else None
            if callable(switch):
                switch()
        # cp 侧 body 基座：已拿到 cp api_ph 的会话几乎所有接口都带它。
        # **顺序要紧**：实抓是 {"biz":"addPoi","kuaishou.web.cp.api_ph":"..."} ——
        # 业务字段在前、api_ph 在最后。body 进 sig3 的 JSON.stringify，顺序不同签名就不同。
        # 创作者中心首轮请求发生在 api_ph cookie 下发之前，Chrome 实抓发送的是
        # ``{}`` / 业务字段本身，而不是把空字符串伪装成 api_ph；空字段会改变
        # body 字节、Content-Length 和 sig3 输入，连续请求时会触发风控差异。
        merged = dict(body or {})
        api_ph = getattr(auth, "cp_api_ph", "") or ""
        if api_ph:
            merged["kuaishou.web.cp.api_ph"] = api_ph
        _assert_cp_body_contract(api, merged, auth)
        # A historical fixture may explicitly pin its old entry URL through
        # ``auth.cp_referer``; normal sessions use the current Network URL
        # above.  Never silently append query parameters that were not seen.
        default_referer = getattr(auth, "cp_referer", None) or KuaishouPublishAPI.publish_referer
        effective_referer = referer or default_referer
        manage_page = "/article/manage/" in (effective_referer or "")
        if manage_page and not with_kww and creator_headers:
            header_style = ("cp_creator_manage_axios" if header_style == "cp_creator_axios"
                            else "cp_creator_manage_json" if header_style == "cp_creator_json"
                            else header_style)
        if api in _CP_EXPLICIT_HTTP11_POST_PATHS and not historical:
            header_style = "cp_submit"
        headers = HeaderBuilder().build(HeaderType.POST, style=header_style)
        headers.set_referer(effective_referer)
        headers.set_origin(KuaishouPublishAPI.cp_url)
        if with_kww:
            headers.with_kww(auth)
        if creator_headers:
            # 2026-08-24 Chrome Network：创作者中心外壳请求统一带这个布尔头。
            # axios 会把它序列化为字符串 true（不是 JSON body 字段）。
            headers.set_header("returnsetrootdomainloginurl", "true")
            if header_style in {"cp_creator_axios", "cp_creator_manage_axios"}:
                headers.set_header("x-requested-with", "XMLHttpRequest")
        params = Params()
        params.with_cp_sign(api, body=merged)
        # 必须编成 bytes：传 str 时 requests 按字符数算 Content-Length，中文标题是多字节，
        # 长度会报小，服务端等不到剩余字节，请求直接挂死（实测 live 侧踩过，这里同理）。
        data = json.dumps(merged, ensure_ascii=False, separators=(',', ':')).encode("utf-8")
        if api in _CP_EXPLICIT_HTTP11_POST_PATHS and not historical:
            headers.set_header("connection", "keep-alive")
            headers.set_header("content-length", str(len(data)))
            headers.set_header("host", "cp.kuaishou.com")
        cookie_site = wire_site or ("cp_video_submit"
                       if api in _CP_EXPLICIT_HTTP11_POST_PATHS and not historical
                       else "cp_atlas" if upload_context == "atlas" and not historical
                       else "cp_upload" if upload_context == "video" and not historical
                       else "cp" if with_kww else "cp_creator_manage" if manage_page else "cp_creator")
        KuaishouPublishAPI._wire_headers(auth, headers, site=cookie_site)
        url = _url(KuaishouPublishAPI.cp_url, api, params)
        wire_headers = headers.get()
        _assert_cp_url_contract(api, url)
        _assert_cp_headers(header_style, wire_headers)
        if api in _CP_EXPLICIT_HTTP11_POST_PATHS and not historical:
            pairs = [part.split("=", 1) for part in wire_headers.get("cookie", "").split("; ")
                     if "=" in part]
            values = {key: value for key, value in pairs}
            if len(wire_headers.get("kww", "")) != 174:
                raise RuntimeError("当前视频 submit 的 Chrome kww 必须为 174 字符")
            if len(values.get("kwfv1", "")) != 218:
                raise RuntimeError("当前视频 submit 的 Cookie kwfv1 必须为 218 字符")
            if len(values.get("kwssectoken", "")) != 88:
                raise RuntimeError("当前视频 submit 的 kwssectoken 必须为 88 字符")
            if len(values.get("kwscode", "")) != 64:
                raise RuntimeError("当前视频 submit 的 kwscode 必须为 64 字符")
            if wire_headers.get("kww") == values.get("kwfv1"):
                raise RuntimeError("当前视频 submit 的 kww 与 Cookie kwfv1 必须独立且值不相等")
        resp = requests.post(url, headers=wire_headers, data=data, verify=False)
        # 最新普通刷新有两个明确的 webweapon 改写边界：
        #   233--235 -> 239--246：bamboo/hotspot 完成后进入 warmed；
        #   246 -> 248：第一次 collection/tab 完成后进入 refreshed。
        # 历史 source=NewReco fixture 单独固定，不能被当前状态机覆盖。
        if creator_headers and not with_kww and getattr(auth, "_cp_cookie_phase", None) != "historical":
            advance = getattr(auth, "advance_cp_cookie_phase", None)
            if callable(advance):
                if api == "/rest/bamboo/pc/hotspot/show":
                    advance("warmed")
                elif api == "/rest/cp/works/v2/collection/tab":
                    advance("refreshed")
        return _safe_json(resp)

    @staticmethod
    def _get(auth, api: str, query_items, referer: str = None,
             upload_context: bool = True) -> dict:
        """Current CP GET helper; only the captured cover/view contract is allowed."""
        if api != "/rest/cp/works/v2/video/pc/upload/cover/view":
            raise RuntimeError(f"{api} 尚无成功 Chrome Network GET 合同，拒绝出网")
        items = list(query_items or [])
        if [key for key, _ in items] != ["coverKey", "_t"]:
            raise ValueError(f"{api} query 字段/顺序必须为 coverKey,_t")
        cover_key, timestamp = items[0][1], items[1][1]
        if not cover_key or not str(timestamp).isdigit():
            raise ValueError(f"{api} coverKey/_t 值不符合当前 Chrome Network")

        switch = getattr(auth, "use_cp_upload" if upload_context else "use_site", None)
        if callable(switch):
            switch() if upload_context else switch(KuaishouPublishAPI.cp_url)

        headers = HeaderBuilder().build(HeaderType.GET, style="cp_upload_get")
        headers.with_kww(auth)
        headers.set_referer(referer or KuaishouPublishAPI.publish_referer)
        KuaishouPublishAPI._wire_headers(
            auth, headers, site="cp_upload" if upload_context else "cp")
        params = Params()
        for key, value in items:
            params.add_param(key, value)
        url = _url(KuaishouPublishAPI.cp_url, api, params)
        wire_headers = headers.get()
        _assert_cp_headers("cp_upload_get", wire_headers)
        resp = requests.get(url, headers=wire_headers, verify=False)
        return _safe_json(resp)

    @staticmethod
    def _post_form(auth, api: str, file_path: str, fields: dict = None,
                   referer: str = None) -> dict:
        """通用 multipart POST（对应源码里的 ``postForm``，封面/图片编辑类接口用）。

        注意签名口径：``build_sign_input`` 只在 content-type 为
        ``application/x-www-form-urlencoded`` 时把 body 归到 form 段，multipart 两段都为空，
        所以这里的签名输入只有 query —— 与浏览器一致（文件内容不进签名）。

        :param auth: KuaishouAuth。
        :param api: pathname。
        :param file_path: 本地文件路径，字段名固定为 ``file``。
        :param fields: 额外的表单字段。
        :param referer: Referer，默认发布页。
        :return: 响应 JSON。
        """
        raise RuntimeError(
            f"{api} 当前没有成功 Chrome Network multipart 请求合同，拒绝按代码推测发包")

    # ------------------------------------------------------------------ #
    # 账户 / 通用信息                                                       #
    # ------------------------------------------------------------------ #
    @staticmethod
    def current_user(auth, **kwargs) -> dict:
        """获取当前创作者账户信息。

        :param auth: KuaishouAuth。
        :return: JSON ``{result, data:{prGr}, ...}``。
        """
        # 创作者中心外壳首发请求不带 kww；嵌入发布 iframe 的同一路径
        # 另有一条带 kww 的请求，调用方可传 ``publish_context=True`` 复现后者。
        if kwargs.get("publish_context"):
            return KuaishouPublishAPI._post(auth, "/rest/cp/works/v2/common/pc/current/user")
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/works/v2/common/pc/current/user",
            header_style="cp_creator_axios", with_kww=False, creator_headers=True)

    @staticmethod
    def w_info(auth, biz: str = "addPoi", **kwargs) -> dict:
        """获取通用信息（按 biz 区分）。

        :param auth: KuaishouAuth。
        :param biz: 业务标识（如 addPoi）。
        :return: JSON。
        """
        return KuaishouPublishAPI._post(auth, "/rest/cp/works/v2/common/pc/w/info", {"biz": biz})

    @staticmethod
    def fe_kconf(auth, **kwargs) -> dict:
        """获取发布页前端配置。

        :param auth: KuaishouAuth。
        :return: JSON。
        """
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/works/v2/common/pc/fe/kconf",
            header_style="cp_creator_axios", with_kww=False, creator_headers=True)

    @staticmethod
    def creator_home_user_info(auth, **kwargs) -> dict:
        """获取创作者首页用户信息。

        :param auth: KuaishouAuth。
        :return: JSON。
        """
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/creator/pc/home/userInfo",
            header_style="cp_creator_axios", with_kww=False, creator_headers=True)

    @staticmethod
    def creator_home_info_v2(auth, **kwargs) -> dict:
        """获取创作者首页信息 v2。

        :param auth: KuaishouAuth。
        :return: JSON。
        """
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/creator/pc/home/infoV2",
            header_style="cp_creator_axios", with_kww=False, creator_headers=True)

    @staticmethod
    def authority_account_current(auth, **kwargs) -> dict:
        """创作者中心账户权限（外壳首发请求）。

        Chrome Network 实抓：外壳请求不带 ``kww``，但带
        ``returnsetrootdomainloginurl: true``，accept 为 ``application/json``；
        发布 iframe 的同一路径可传 ``publish_context=True`` 切换为 cp 发布头。
        """
        if kwargs.get("publish_context"):
            # 发布 iframe 也会请求同一路径，但使用 cp 发布 axios 头（含 kww、accept */*）。
            result = KuaishouPublishAPI._post(
                auth, "/rest/v2/creator/pc/authority/account/current")
        else:
            result = KuaishouPublishAPI._post(
                auth, "/rest/v2/creator/pc/authority/account/current",
                header_style="cp_creator_json", with_kww=False,
                creator_headers=True)
        KuaishouPublishAPI._observe_authority_response(auth, result)
        return result

    @staticmethod
    def _observe_authority_response(auth, result: dict) -> dict:
        """把真实权限响应写回程序会话；不根据页面文案或代码推断。"""
        result = dict(result or {})
        if result.get("result") == 119120:
            marker = getattr(auth, "mark_account_restricted", None)
            if callable(marker):
                marker(True)
            auth._cp_publish_authority_response = None
        elif (result.get("result") == 1 and
              (((result.get("data") or {}).get("ab") or {}).get("enablePublish")) is True):
            auth._cp_account_restricted = False
            auth._cp_publish_authority_response = result
        return result

    @staticmethod
    def require_publish_authority(auth) -> dict:
        """在任何上传副作用前复现 CP 发布页的账号权限门禁。

        当前成功 Network 响应必须同时是 ``result=1`` 且
        ``data.ab.enablePublish=true``。当前受限账号 reqid 2170 明确返回
        ``result=119120``；这种状态必须停在 ``upload/pre`` 之前。
        """
        if getattr(auth, "_cp_cookie_phase", None) == "historical":
            return {"result": 1, "historical": True}
        if getattr(auth, "_cp_account_restricted", False):
            raise RuntimeError(
                "创作者权限预检失败：当前程序会话已收到账号限制响应；"
                "已在 upload/pre 前停止")
        cached = getattr(auth, "_cp_publish_authority_response", None)
        if cached is not None:
            return cached
        # An unknown/fresh program-owned session starts from the successful
        # creator-shell contract (current reqids 97/1203).  The later restricted
        # reqid 2170 has a different Cookie creation order and is retained only
        # as evidence for an already-restricted page; it must not be generalized
        # to a future healthy account.
        result = KuaishouPublishAPI.authority_account_current(auth)
        if result.get("result") == 119120:
            raise RuntimeError(
                "创作者权限预检失败：账号异常，系统暂时无法使用（result=119120）；"
                "已在 upload/pre 前停止")
        if result.get("result") != 1:
            raise RuntimeError(
                f"创作者权限预检失败 result={result.get('result')!r}: "
                f"{result.get('message') or result}")
        enabled = (((result.get("data") or {}).get("ab") or {}).get("enablePublish"))
        if enabled is not True:
            raise RuntimeError(
                "创作者权限预检响应缺少浏览器成功合同字段 "
                "data.ab.enablePublish=true，拒绝进入 upload/pre")
        return result

    @staticmethod
    def kswitch_config(auth, keys: list = None, **kwargs) -> dict:
        """创作者中心灰度开关配置。``keys`` 缺省必须是空数组。"""
        body = {"keys": list(keys or [])}
        return KuaishouPublishAPI._post(
            auth, "/rest/v2/creator/pc/frontend/kswitch/config", body,
            header_style="cp_creator_json", with_kww=False, creator_headers=True)

    @staticmethod
    def bamboo_hotspot_show(auth, **kwargs) -> dict:
        """创作者中心热点展示配置（不带 sig3、无 kww）。"""
        return KuaishouPublishAPI._post(
            auth, "/rest/bamboo/pc/hotspot/show",
            header_style="cp_creator_axios", with_kww=False, creator_headers=True)

    @staticmethod
    def emotion_package_list(auth, **kwargs) -> dict:
        """创作者中心表情包列表（不带 sig3、无 kww）。"""
        return KuaishouPublishAPI._post(
            auth, "/rest/wd/pc/emotion/package/list",
            header_style="cp_creator_axios", with_kww=False, creator_headers=True)

    @staticmethod
    def wd_kconf_get(auth, key: str = "frontend.cp.cp-custom-text",
                     value_type: str = "json", **kwargs) -> dict:
        """``/rest/wd/kconf/get`` 前端文案配置。"""
        body = {"key": key, "type": value_type}
        return KuaishouPublishAPI._post(
            auth, "/rest/wd/kconf/get", body,
            header_style="cp_creator_axios", with_kww=False, creator_headers=True)

    @staticmethod
    def creator_comment_report_menu(auth, **kwargs) -> dict:
        """评论举报菜单。"""
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/creator/comment/report/menu",
            header_style="cp_creator_axios", with_kww=False, creator_headers=True)

    @staticmethod
    def school_category_tree(auth, **kwargs) -> dict:
        """创作者学院分类树。"""
        return KuaishouPublishAPI._post(
            auth, "/rest/v2/creator/pc/school/category/tree",
            header_style="cp_creator_axios", with_kww=False, creator_headers=True)

    @staticmethod
    def notification_unread_count(auth, **kwargs) -> dict:
        """创作者中心未读通知数。"""
        return KuaishouPublishAPI._post(
            auth, "/rest/v2/creator/pc/notification/unReadCountV3",
            header_style="cp_creator_axios", with_kww=False, creator_headers=True)

    @staticmethod
    def creator_export_task_list(auth, page: int = 1, count: int = 1000,
                                 **kwargs) -> dict:
        """数据导出任务列表；浏览器固定发送 page=1、count=1000。"""
        body = {"page": int(page), "count": int(count)}
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/creator/analysis/export/task/list", body,
            header_style="cp_creator_axios", with_kww=False, creator_headers=True)

    @staticmethod
    def creator_satisfy_list(auth, page: str = "CREATOR_CENTER_PC_HOME",
                             force_show: bool = False, **kwargs) -> dict:
        """成长/满意度任务列表。"""
        body = {"page": page, "forceShow": bool(force_show)}
        return KuaishouPublishAPI._post(
            auth, "/rest/v2/creator/pc/satisfy/list", body,
            header_style="cp_creator_axios", with_kww=False, creator_headers=True)

    @staticmethod
    def video_photo_list(auth, query_type: str = "0", cursor: int = None,
                         start_time: int = None, end_time: int = None,
                         limit: int = 30, time_range_type: int = 5,
                         keyword: str = "", **kwargs) -> dict:
        """创作者管理页作品列表（当前 Network reqid=144）。

        时间和 cursor 必须由调用方传入当前页面实际值；不自动猜测或补
        ``now``，避免改变签名/body 字节。字段顺序固定为浏览器顺序。
        """
        values = {
            "queryType": str(query_type),
            "cursor": cursor,
            "startTime": start_time,
            "endTime": end_time,
            "limit": int(limit),
            "timeRangeType": int(time_range_type),
            "keyword": str(keyword),
        }
        if any(values[key] is None for key in ("cursor", "startTime", "endTime")):
            raise ValueError("video_photo_list 必须显式传入当前 Network 的 cursor/startTime/endTime")
        result = KuaishouPublishAPI._post(
            auth, "/rest/cp/works/v2/video/pc/photo/list", values,
            referer=kwargs.get("referer"), header_style="cp_creator_axios",
            with_kww=False, creator_headers=True,
            wire_site=("cp_post_publish_manage" if kwargs.get("post_publish")
                       else None))
        actual_referer = kwargs.get("referer") or getattr(auth, "cp_referer", None) \
            or KuaishouPublishAPI.publish_referer
        if result.get("result") == 1:
            rows = ((result.get("data") or {}).get("list") or [])
            finish = getattr(auth, "_cp_last_video_finish", None) or {}
            post_publish = (
                actual_referer == KuaishouPublishAPI.post_publish_manage_referer
                and str(query_type) == "2" and len(rows) == 1
                and isinstance(rows[0], dict)
                and rows[0].get("publishStatus") == 2
                and rows[0].get("workId") is None
                and rows[0].get("unPublishCoverKey") == finish.get("coverKey")
                and type(rows[0].get("publishId")) is int
                and rows[0]["publishId"] > 0)
            auth._cp_publish_refresh_ids = (
                (rows[0]["publishId"],) if post_publish else None)
        return result

    @staticmethod
    def video_publish_refresh(auth, publish_ids=None, **kwargs) -> dict:
        """Poll publish state using IDs returned by this session's photo/list.

        Chrome reqid 1331 proves the body is exactly ``ids,api_ph`` and the
        first ID is reqid 1328 ``data.list[0].publishId``.  The submit response
        has an empty data object, so deriving an ID from submit would be a guess.
        """
        observed = tuple(getattr(auth, "_cp_publish_refresh_ids", None) or ())
        requested = tuple(observed if publish_ids is None else publish_ids)
        if not observed or requested != observed:
            raise RuntimeError(
                "publish/refresh ids 必须原样来自当前程序会话成功 photo/list 响应，拒绝出网")
        if any(type(value) is not int or value <= 0 for value in requested):
            raise ValueError("publish/refresh ids 必须是 photo/list 返回的正整数 publishId")
        referer = kwargs.get("referer") or KuaishouPublishAPI.post_publish_manage_referer
        if referer != KuaishouPublishAPI.post_publish_manage_referer:
            raise RuntimeError("publish/refresh Referer 必须为当前发布后管理页，拒绝出网")
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/works/v2/video/pc/publish/refresh",
            {"ids": list(requested)}, referer=referer,
            header_style="cp_creator_axios", with_kww=False,
            creator_headers=True, wire_site="cp_post_publish_manage")

    @staticmethod
    def magnetic_guide(auth, guide_type: int = 1, **kwargs) -> dict:
        """磁力引导配置（发布 iframe 请求，带 kww、accept */*）。"""
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/creator/pc/magnetic/guide", {"type": int(guide_type)})

    @staticmethod
    def material_fonts(auth, timestamp_ms: int = None, **kwargs) -> dict:
        """获取 onvideo 字体素材列表。

        Chrome Network 的唯一 query 顺序为 ``source=cp&_t=<ms>``，无
        sig3/sig4，Referer 固定为 CP 根页。``ks_onvideo_token`` 是两阶段合同：

        - reqid 749：token 不存在时，浏览器首次请求确实不发送它；响应 200 并
          ``Set-Cookie: ks_onvideo_token=...; Max-Age=86400; Path=/``；
        - reqid 870：后续请求必须在当前 Cookie 顺序中发送该 token。

        因此只允许这个有 Network 证据的首次缺省；若响应没有下发 token，立即
        失败，禁止让后续请求继续处于缺字段状态。
        """
        raw_cookie = getattr(auth, "_cookie", {}) or {}
        had_token = bool(raw_cookie.get("ks_onvideo_token"))

        headers = HeaderBuilder().build(HeaderType.GET, style="onvideo")
        headers.with_kww(auth)
        headers.set_referer(f"{KuaishouPublishAPI.cp_url}/")
        headers.set_origin(KuaishouPublishAPI.cp_url)
        headers.set_header("sec-fetch-site", "same-site")
        KuaishouPublishAPI._wire_headers(
            auth, headers, site="onvideo" if had_token else "onvideo_bootstrap")

        params = Params()
        params.add_param("source", "cp")
        params.add_param("_t", int(timestamp_ms if timestamp_ms is not None
                                   else time.time() * 1000))
        url = _url(KuaishouPublishAPI.onvideo_url, "/api/material/fonts", params)
        wire_headers = headers.get()
        _assert_cp_headers("onvideo", wire_headers)
        resp = requests.get(url, headers=wire_headers, verify=False)
        issued = response_cookies(resp)
        if issued:
            update = getattr(auth, "update_cookies", None)
            if callable(update):
                update(issued)
        if not had_token and not (getattr(auth, "_cookie", {}) or {}).get("ks_onvideo_token"):
            raise RuntimeError(
                "material/fonts 首次无 token 请求后未收到 Chrome 实抓要求的 "
                "Set-Cookie: ks_onvideo_token，禁止继续发送后续 onvideo 请求")
        return _safe_json(resp)

    # ------------------------------------------------------------------ #
    # 视频发布链路                                                          #
    # ------------------------------------------------------------------ #
    @staticmethod
    def relation_is_follow(auth, user_id: str, **kwargs) -> dict:
        """上传页当前实抓的作者关注关系查询（reqid 1519，无签名）。"""
        return KuaishouPublishAPI._post(
            auth, "/rest/wd/relation/isFollow", {"userId": str(user_id)})

    @staticmethod
    def video_realize_entrance(auth, **kwargs) -> dict:
        """视频变现入口（reqid 1523）。"""
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/works/v2/video/pc/realize/entrance", {"movieId": ""})

    @staticmethod
    def video_realize_banner_entrance(auth, **kwargs) -> dict:
        """变现横幅入口；字段名按 Network 保留为 ``moviedId``。"""
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/works/v2/video/pc/realize/banner/entrance",
            {"moviedId": ""})

    @staticmethod
    def video_publish_time(auth, **kwargs) -> dict:
        """当前发布页允许的定时发布范围（reqid 1534）。"""
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/works/v2/video/pc/publish/time")

    @staticmethod
    def creator_activity_list(auth, phase: str = "initial",
                              upload_context: str = "video", **kwargs) -> dict:
        """活动列表的两套浏览器字段顺序（reqid 1535/1548）。"""
        if phase == "initial":
            body = {"page": 1, "count": 20, "category": 0, "rewardType": 0,
                    "sortType": 0, "pageSource": 2}
        elif phase == "post_resume":
            body = {"page": 1, "count": 20, "category": 0, "sortType": 0,
                    "rewardType": 0, "pageSource": 2}
        else:
            raise ValueError("activity phase 只能是 initial 或 post_resume")
        return KuaishouPublishAPI._post(
            auth, "/rest/v2/creator/activity/pc/list", body,
            upload_context=upload_context)

    @staticmethod
    def collection_can_add(auth, **kwargs) -> dict:
        """当前账号是否可把作品加入合集（reqid 1536）。"""
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/works/v2/collection/canAdd")

    @staticmethod
    def creator_activity_tab(auth, upload_context: str = "video", **kwargs) -> dict:
        return KuaishouPublishAPI._post(
            auth, "/rest/v2/creator/activity/pc/tab",
            upload_context=upload_context)

    @staticmethod
    def creator_activity_filter(auth, upload_context: str = "video", **kwargs) -> dict:
        return KuaishouPublishAPI._post(
            auth, "/rest/v2/creator/activity/pc/filter",
            upload_context=upload_context)

    @staticmethod
    def video_upload_config(auth, **kwargs) -> dict:
        """视频上传配置（大小/时长/格式/分片策略等）。

        :param auth: KuaishouAuth。
        :return: JSON ``data:{maxSize, maxDuration, supportFormats, uploadConfigs, ...}``。
        """
        return KuaishouPublishAPI._post(auth, "/rest/cp/works/v2/video/pc/upload/config")

    @staticmethod
    def video_upload_domain_list(auth, **kwargs) -> dict:
        """专属领域列表（``fetchDomainList``，发布时选领域用，与上传域名无关）。

        :param auth: KuaishouAuth。
        :return: JSON ``data:[{domain, secondDomain:[...]}]``。
        """
        return KuaishouPublishAPI._post(auth, "/rest/cp/works/v2/video/pc/upload/domain/list")

    @staticmethod
    def video_upload_pre(auth, upload_type: int = UPLOAD_TYPE_VIDEO, **kwargs) -> dict:
        """视频上传预处理：拿 ksuploader 的 token / endPoints 与 fileId。

        对应源码 ``getPreInfo({}, {uploadType: Mp.pc})``，``Mp.pc`` 实测为 1。
        这是上传链的第一步，没有它拿不到 uploadToken。

        :param auth: KuaishouAuth。
        :param upload_type: 上传类型，PC 端为 1。
        :return: JSON ``data:{token, fileId, endPoints:[...]}``。
        """
        return KuaishouPublishAPI._post(auth, "/rest/cp/works/v2/video/pc/upload/pre",
                                        {"uploadType": upload_type})

    @staticmethod
    def video_upload_finish(auth, token: str, file_name: str, file_type: str,
                            file_length: int, **kwargs) -> dict:
        """分片传完后通知服务端收尾（``notifyUploadFinish``）。

        对应源码 ``notifyUploadFinish({}, {token, fileName, fileType, fileLength})``。
        响应里必须有 ``videoDuration`` 且 > 0，否则前端会判为「获取视频时长失败」。

        :param auth: KuaishouAuth。
        :param token: upload/pre 下发的 token。
        :param file_name: 文件名。
        :param file_type: MIME，如 ``video/mp4``。
        :param file_length: 文件字节数。
        :return: JSON ``data:{videoDuration, width, height, ...}``。
        """
        body = {"token": token, "fileName": file_name,
                "fileType": file_type, "fileLength": int(file_length)}
        result = KuaishouPublishAPI._post(
            auth, "/rest/cp/works/v2/video/pc/upload/finish", body)
        if result.get("result") == 1:
            data = result.get("data") or {}
            auth._cp_last_video_finish = dict(data)
        return result

    @staticmethod
    def video_cover_report(auth, cover_key: str = None, **kwargs) -> dict:
        """Report the raw cover immediately before video submit (reqid 1315).

        ``bizKey`` is not caller-chosen: it must equal the ``coverKey`` returned
        by this program session's successful upload/finish response.
        """
        finish = getattr(auth, "_cp_last_video_finish", None) or {}
        observed = finish.get("coverKey")
        requested = observed if cover_key is None else cover_key
        if not observed or requested != observed:
            raise RuntimeError(
                "common/pc/report bizKey 必须原样来自当前程序会话 upload/finish.data.coverKey，"
                "拒绝出网")
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/works/v2/common/pc/report",
            {"bizKey": requested, "bizType": 1, "data": "{}"})

    @staticmethod
    def video_cover_upload(auth, file_path: str, **kwargs) -> dict:
        """上传视频封面（``uploadCover``，multipart 表单）。

        :param auth: KuaishouAuth。
        :param file_path: 本地封面图路径。
        :return: JSON ``data:{coverKey}``——submit 时要带这个 coverKey。
        """
        return KuaishouPublishAPI._post_form(
            auth, "/rest/cp/works/v2/video/pc/upload/cover/upload", file_path)

    @staticmethod
    def video_detect_start(auth, file_id: str, **kwargs) -> dict:
        """发起视频质量检测（``postDetectVideo``，可选步骤）。

        :param auth: KuaishouAuth。
        :param file_id: upload/pre 下发的 fileId。
        :return: JSON。
        """
        return KuaishouPublishAPI._post(auth, "/rest/cp/works/v2/video/pc/upload/check/start",
                                        {"fileId": str(file_id)})

    @staticmethod
    def video_detect_result(auth, file_id: str, **kwargs) -> dict:
        """查询视频质量检测结果（``getDetectResult``）。

        :param auth: KuaishouAuth。
        :param file_id: fileId。
        :return: JSON ``data:{hasResult, level, checkStatus}``。
        """
        return KuaishouPublishAPI._post(auth, "/rest/cp/works/v2/video/pc/upload/check/getResult",
                                        {"fileId": str(file_id)})

    @staticmethod
    def video_publish_info_save(auth, snapshot: dict, **kwargs) -> dict:
        """保存发布草稿（``savePublishInfo``，可选）。

        :param auth: KuaishouAuth。
        :param snapshot: 发布信息快照（源码会先剔除 ``url`` 字段）。
        :return: JSON。
        """
        body = {k: v for k, v in (snapshot or {}).items() if k != "url"}
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/works/v2/video/pc/publishInfo/snapshot/save", body)

    @staticmethod
    def video_upload_cover_view(auth, cover_key: str, timestamp_ms: int = None,
                                **kwargs) -> dict:
        """读取 upload/finish 生成的封面（reqid 1563/1564）。"""
        stamp = int(timestamp_ms if timestamp_ms is not None else time.time() * 1000)
        return KuaishouPublishAPI._get(
            auth, "/rest/cp/works/v2/video/pc/upload/cover/view",
            [("coverKey", cover_key), ("_t", stamp)],
            upload_context=kwargs.get("upload_context", True))

    @staticmethod
    def video_material_specified(auth, file_id, **kwargs) -> dict:
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/works/v4/video/pc/upload/material/specified",
            {"fileId": int(file_id)})

    @staticmethod
    def video_cover_recommend_submit(auth, file_id, **kwargs) -> dict:
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/works/v4/video/pc/cover/edit/recommend/submit",
            {"fileId": int(file_id)})

    @staticmethod
    def video_cover_recommend_query(auth, file_id, job_id: str, **kwargs) -> dict:
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/works/v4/video/pc/cover/edit/recommend/query",
            {"fileId": int(file_id), "jobId": str(job_id)})

    @staticmethod
    def video_cover_extract(auth, file_id, durations=None, **kwargs) -> dict:
        values = [0] * 16 if durations is None else list(durations)
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/works/v4/video/pc/upload/cover/extract",
            {"fileId": int(file_id), "durations": values})

    @staticmethod
    def video_cover_extract_query(auth, file_id, **kwargs) -> dict:
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/works/v4/video/pc/upload/cover/extract/query",
            {"fileId": int(file_id)})

    @staticmethod
    def video_snapshot_info(auth, **kwargs) -> dict:
        """视频快照信息。

        :param auth: KuaishouAuth。
        :return: JSON。
        """
        # Chrome 发布 iframe 实抓固定带 photoType=0；之前漏掉该字段，
        # 服务端可能首次放行但后续请求画像会不同。
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/works/v2/video/pc/snapshot/info", {"photoType": 0})

    @staticmethod
    def video_cover_profile(auth, **kwargs) -> dict:
        """视频封面上传配置。

        :param auth: KuaishouAuth。
        :return: JSON。
        """
        return KuaishouPublishAPI._post(auth, "/rest/cp/works/v2/video/pc/upload/cover/profile")

    @staticmethod
    def video_upload_tips_show(auth, tips: list = None, **kwargs) -> dict:
        """发布页各处红点/气泡是否展示（``getTipVisible``）。

        实抓 body 带 ``tips`` 数组，默认值就是浏览器发的那四项。

        :param auth: KuaishouAuth。
        :param tips: 要查询的提示项；缺省用实抓默认值。
        :return: JSON ``data:{collectionRedDot, collectionBubble, publishPanoramicVideo, mmuIsNew}``。
        """
        body = {"tips": list(tips) if tips else list(DEFAULT_TIPS)}
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/works/v2/video/pc/upload/tips/show", body,
            header_style="cp_creator_axios", with_kww=False, creator_headers=True)

    # ------------------------------------------------------------------ #
    # 图文（atlas）发布链路                                                  #
    # ------------------------------------------------------------------ #
    @staticmethod
    def atlas_upload_config(auth, **kwargs) -> dict:
        """图文上传配置（图片数量/大小上限等）。

        :param auth: KuaishouAuth。
        :return: JSON ``data:{atlasImageCountLimit(31), atlasImageSizeLimit(15MB), ...}``。
        """
        return KuaishouPublishAPI._post(auth, "/rest/cp/works/atlas/pc/upload/config")

    @staticmethod
    def atlas_publish_info_snapshot_info(auth, **kwargs) -> dict:
        """读取当前图文草稿快照（page 12 reqid 124）。"""
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/works/atlas/pc/publishInfo/snapshot/info")

    @staticmethod
    def atlas_realize_entrance(auth, **kwargs) -> dict:
        """图文编辑器的变现入口；路径与视频相同但 product/profile 不同。"""
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/works/v2/video/pc/realize/entrance",
            {"movieId": ""}, upload_context="atlas")

    @staticmethod
    def atlas_activity_list(auth, phase: str = "initial", **kwargs) -> dict:
        """图文编辑器活动列表的两套当前字段顺序。"""
        return KuaishouPublishAPI.creator_activity_list(
            auth, phase=phase, upload_context="atlas")

    @staticmethod
    def atlas_activity_tab(auth, **kwargs) -> dict:
        return KuaishouPublishAPI.creator_activity_tab(
            auth, upload_context="atlas")

    @staticmethod
    def atlas_activity_filter(auth, **kwargs) -> dict:
        return KuaishouPublishAPI.creator_activity_filter(
            auth, upload_context="atlas")

    @staticmethod
    def collection_can_add_atlas(auth, **kwargs) -> dict:
        """当前账号是否可把图文加入合集（page 12 reqid 138）。"""
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/works/v2/collection/canAddAtlas")

    @staticmethod
    def atlas_upload_pre(auth, images: list, atlas_id=None, file_id=None, **kwargs) -> dict:
        """图文上传预处理：申请 token / endPoints / blobKey。

        实抓（2026-08-16）里浏览器是**每张图各调一次**、``pictureCount`` 恒为 1：

        - 第一张不带 ``atlasId`` / ``fileId``，服务端创建后在响应里回传；
        - 之后每张都要带上，且这两个键**排在 body 最前面**。

        首次调用时浏览器传的是 undefined，``JSON.stringify`` 会整个丢掉这两个键
        （不是 null）。body 进签名，所以这里必须同样省略。

        :param auth: KuaishouAuth。
        :param images: 本次申请的图片路径列表；浏览器每次只申请一张。
        :param atlas_id: 第二张起必须传。
        :param file_id: 第二张起必须传。
        :return: JSON ``data:{atlasId, fileId, uploadInfo:[{token, endPoints, blobKey}, ...]}``。
        """
        if len(images or []) != 1:
            raise ValueError("atlas_upload_pre 每次必须只传一张图片")
        if (atlas_id is None) != (file_id is None):
            raise ValueError("atlas_upload_pre 的 atlasId/fileId 必须同时为空或同时提供")
        extend_names = [{"fileExtendName": mimetypes.guess_type(p)[0] or "image/jpeg"}
                        for p in images]
        body = {}
        # 首次调用时浏览器传的是 undefined，JSON.stringify 会**整个丢掉这两个键**（不是 null）。
        # body 进签名，所以这里必须同样省略，否则签名和浏览器不一致。
        if atlas_id is not None:
            body["atlasId"] = atlas_id
        if file_id is not None:
            body["fileId"] = file_id
        body["uploadType"] = UPLOAD_TYPE_ATLAS
        body["pictureCount"] = len(images)
        # 注意这里是「JSON 字符串」而不是数组，源码就是 JSON.stringify 后再放进 body
        body["fileExtendNames"] = json.dumps(extend_names, ensure_ascii=False,
                                            separators=(',', ':'))
        return KuaishouPublishAPI._post(auth, "/rest/cp/works/atlas/pc/upload/pre", body)

    @staticmethod
    def atlas_upload_single_finish(auth, file_id, atlas_id, blob_key: str, **kwargs) -> dict:
        """单张图片传完后的收尾（``uploadImagesFinish``），每张都要调一次。

        :param auth: KuaishouAuth。
        :param file_id: atlas_upload_pre 返回的 fileId。
        :param atlas_id: atlas_upload_pre 返回的 atlasId。
        :param blob_key: 该图对应 uploadInfo[i].blobKey。
        :return: JSON ``data:{url:[{url}]}``。
        """
        return KuaishouPublishAPI._post(auth, "/rest/cp/works/atlas/pc/upload/single/finish",
                                        {"fileId": file_id, "atlasId": atlas_id,
                                         "blobKey": blob_key})

    @staticmethod
    def atlas_publish_info_snapshot_save(
            auth, file_id, atlas_id, caption: str = "",
            photo_status: int = 1, publish_time: int = 0, **kwargs) -> dict:
        """保存图文编辑器自动草稿，字段/顺序来自 page 12 reqid 165。"""
        body = {
            "fileId": file_id,
            "atlasId": atlas_id,
            "caption": re.sub(r'(\S)#', r'\1 #', caption or ""),
            "photoStatus": photo_status,
            "longitude": "",
            "latitude": "",
            "declareInfo": {},
            "activityIds": [],
            "publishTime": publish_time,
            "coPublishUser": [],
        }
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/works/atlas/pc/publishInfo/snapshot/save", body)

    @staticmethod
    def atlas_cover_upload(auth, file_path: str, **kwargs) -> dict:
        """上传图文封面（``uploadImagesCover``，multipart）。

        :param auth: KuaishouAuth。
        :param file_path: 本地封面图路径。
        :return: JSON ``data:{coverKey}``。
        """
        return KuaishouPublishAPI._post_form(
            auth, "/rest/cp/works/atlas/pc/upload/cover/upload", file_path)

    # ------------------------------------------------------------------ #
    # 合集                                                                 #
    # ------------------------------------------------------------------ #
    @staticmethod
    def collection_tab(auth, **kwargs) -> dict:
        """获取合集 tab。

        :param auth: KuaishouAuth。
        :return: JSON。
        """
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/works/v2/collection/tab",
            header_style="cp_creator_axios", with_kww=False, creator_headers=True)

    @staticmethod
    def collection_visible(auth, **kwargs) -> dict:
        """获取合集可见性。

        :param auth: KuaishouAuth。
        :return: JSON。
        """
        return KuaishouPublishAPI._post(auth, "/rest/cp/works/v2/collection/visible")

    @staticmethod
    def atlas_upload_finish(auth, file_id, atlas_id, blob_keys: list, **kwargs) -> dict:
        """图文上传完成校验（发布提交前必须先调，服务端做内容审核）。

        :param auth: KuaishouAuth。
        :param file_id: 上传返回的 fileId。
        :param atlas_id: 图集 id。
        :param blob_keys: 各图上传返回的 blobKey 列表。
        :return: JSON；``result != 1`` 时 message 为不通过原因。
        """
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/works/atlas/pc/upload/finish",
            {"fileId": file_id, "atlasId": atlas_id,
             "blobKey": list(blob_keys or [])}, upload_context="atlas")

    # ------------------------------------------------------------------ #
    # 发布提交                                                             #
    # ------------------------------------------------------------------ #
    # 查看权限（实抓字段名是 photoStatus，不是 visibility）
    PHOTO_STATUS_PUBLIC = 1        # 所有人可见
    PHOTO_STATUS_PRIVATE = 2       # 仅自己可见
    PHOTO_STATUS_FRIENDS = 4       # 好友可见

    @staticmethod
    def publish_video(auth, caption: str, file_id, cover_key: str = "",
                      media_id: str = "", photo_id_str: str = "", video_duration: int = 0,
                      photo_status: int = PHOTO_STATUS_PRIVATE, publish_time: int = 0,
                      extra: dict = None, **kwargs) -> dict:
        """提交视频发布。**走 sig4 而非 sig3**（命中 CP_SIG4_INTERFACES）。

        正常运行字段与顺序严格来自当前重新登录 Chrome reqid 1316：50 个业务
        字段加末尾 ``api_ph``（共 51 键），只放行已成功的空 caption、立即发布、仅自己可见
        分支。旧 43 字段请求只供显式 historical fixture 回归。

        ``fileId`` / ``mediaId`` / ``photoIdStr`` / ``videoDuration`` / ``coverKey``
        全都来自 :meth:`upload_video_file` 的 ``upload/finish`` 响应，必须原样透传；
        其中 **fileId 是整数**，封面由服务端在 upload/finish 时自动抽帧生成。

        :param auth: KuaishouAuth。
        :param caption: 作品描述（正文里的 ``#`` 前会补空格，同前端行为）。
        :param file_id: upload/finish 给的 fileId（整数）。
        :param cover_key: upload/finish 给的 coverKey。
        :param media_id: upload/finish 给的 mediaId。
        :param photo_id_str: upload/finish 给的 photoIdStr。
        :param video_duration: upload/finish 给的 videoDuration（毫秒）。
        :param photo_status: 查看权限，见 ``PHOTO_STATUS_*``，默认所有人可见。
        :param publish_time: 定时发布时间戳；0 表示立即发布。
        :param extra: 覆盖/追加字段。
        :return: JSON ``{"result":1,"message":"成功"}``。
        """
        historical = getattr(auth, "_cp_cookie_phase", None) == "historical"
        if historical:
            body = {
                "fileId": int(file_id) if str(file_id).lstrip("-").isdigit() else file_id,
                "coverKey": cover_key, "coverTimeStamp": 0,
                "caption": re.sub(r'(\S)#', r'\1 #', caption or ""),
                "photoStatus": photo_status, "coverType": 1, "coverTitle": "",
                "photoType": 0, "collectionId": "", "publishTime": publish_time,
                "longitude": "", "latitude": "", "poiId": 0, "notifyResult": 0,
                "domain": "", "secondDomain": "", "coverCropped": False,
                "pkCoverKey": "", "profileCoverKey": "", "downloadType": 1,
                "disableNearbyShow": False, "allowSameFrame": True, "movieId": "",
                "openPrePreview": False, "declareInfo": {}, "activityIds": [],
                "riseQuality": False, "chapters": [], "useAiCaptionCover": False,
                "useAiCaption": False, "isUseIdealTime": False, "useAiCover": False,
                "kceInfo": "", "projectId": "", "recTagIdList": [],
                "videoInfoMeta": "", "previewUrlErrorMessage": "",
                "coPublishUser": [], "triggerH265": False, "mediaId": media_id,
                "photoIdStr": photo_id_str, "videoDuration": video_duration,
            }
            if extra:
                body.update(extra)
            return KuaishouPublishAPI._post(
                auth, "/rest/cp/works/v2/video/pc/submit", body)

        if caption not in {None, ""}:
            raise RuntimeError("当前视频 submit 只成功抓到 caption 为空的分支，拒绝出网")
        if photo_status != KuaishouPublishAPI.PHOTO_STATUS_PRIVATE:
            raise RuntimeError("当前视频 submit 只成功抓到 photoStatus=2（仅自己可见）")
        if publish_time != 0:
            raise RuntimeError("当前视频 submit 未抓到定时发布分支")
        if extra:
            raise RuntimeError("当前视频 submit 未抓到 extra 覆盖/追加字段分支")
        if photo_id_str:
            raise RuntimeError("当前视频 submit Network 不含 photoIdStr，拒绝携带或映射该字段")

        finish = getattr(auth, "_cp_last_video_finish", None) or {}
        expected_dynamic = {
            "fileId": finish.get("fileId"),
            "coverKey": finish.get("coverKey"),
            "mediaId": finish.get("mediaId"),
            "videoDuration": finish.get("videoDuration"),
        }
        actual_dynamic = {
            "fileId": int(file_id) if str(file_id).lstrip("-").isdigit() else file_id,
            "coverKey": cover_key,
            "mediaId": media_id,
            "videoDuration": video_duration,
        }
        if not finish or actual_dynamic != expected_dynamic:
            raise RuntimeError(
                "当前视频 submit 的 fileId/coverKey/mediaId/videoDuration 必须全部原样来自"
                "当前程序会话成功 upload/finish 响应，拒绝出网")

        # Chrome Network order is report(reqid 1315) immediately followed by
        # submit(reqid 1316); report result=1 is a mandatory gate.
        report = KuaishouPublishAPI.video_cover_report(auth, cover_key)
        if report.get("result") != 1:
            raise RuntimeError(f"common/pc/report 未通过，拒绝 submit: {report}")

        body = {
            "fileId": int(file_id) if str(file_id).lstrip("-").isdigit() else file_id,
            "coverKey": cover_key,
            "coverTimeStamp": 0,
            "caption": re.sub(r'(\S)#', r'\1 #', caption or ""),
            "photoStatus": photo_status,
            "coverType": 1,
            "coverTitle": "",
            "photoType": 0,
            "collectionId": 0,
            "publishTime": publish_time,
            "longitude": "",
            "latitude": "",
            "poiId": 0,
            "notifyResult": 0,
            "domain": "",
            "secondDomain": "",
            "coverCropped": False,
            "pkCoverKey": "",
            "profileCoverKey": "",
            "downloadType": 1,
            "disableNearbyShow": False,
            "allowSameFrame": True,
            "movieId": "",
            "openPrePreview": False,
            "declareInfo": dict(_CURRENT_VIDEO_DECLARE_INFO),
            "activityIds": [],
            "riseQuality": False,
            "chapters": None,
            "videoComposite": None,
            "useAiCaptionCover": False,
            "useAiCaption": False,
            "isUseIdealTime": False,
            "useAiCover": False,
            "kceInfo": "",
            "coverSize": "",
            "pkCoverTimeStamp": -1,
            "pkCoverType": 1,
            "pkCoverSize": "",
            "innerChannel": 0,
            "mediaId": media_id,
            "videoInfoMeta": "",
            "triggerH265": False,
            "recTagIdList": [],
            "onvideoDuration": 0,
            "disallowRecreation": False,
            "previewUrlErrorMessage": "",
            "coPublishUser": [],
            "coPublishRole": 0,
            "extraInfo": "",
            "videoDuration": video_duration,
        }
        return KuaishouPublishAPI._post(auth, "/rest/cp/works/v2/video/pc/submit", body)

    @staticmethod
    def publish_video_file(auth, file_path: str, caption: str,
                           photo_status: int = PHOTO_STATUS_PRIVATE, publish_time: int = 0,
                           extra: dict = None, on_progress=None, **kwargs) -> dict:
        """一步发布：上传文件 → 直接提交，中间字段自动透传。

        :param auth: KuaishouAuth。
        :param file_path: 本地视频路径。
        :param caption: 作品描述。
        :param photo_status: 查看权限，见 ``PHOTO_STATUS_*``。
        :param publish_time: 定时发布时间戳；0 立即发布。
        :param extra: 覆盖 submit 的字段。
        :param on_progress: 上传进度回调 ``fn(已传, 总数)``。
        :return: submit 的响应 JSON。
        """
        historical = getattr(auth, "_cp_cookie_phase", None) == "historical"
        if not historical:
            if caption not in {None, ""} or photo_status != 2 or publish_time != 0 or extra:
                raise RuntimeError(
                    "publish_video_file 当前只放行 Chrome 成功抓到的空 caption、"
                    "photoStatus=2、publishTime=0、无 extra 分支")
            # Check account permission while still in the creator-page
            # context, then enter the distinct video-upload webweapon context.
            # The latter performs the exact CP 0.1.1 rotation that yields a
            # 218-character Cookie kwfv1 while preserving the page kww snapshot
            # at 174 characters.
            KuaishouPublishAPI.require_publish_authority(auth)
            switch = getattr(auth, "use_cp_upload", None)
            if callable(switch):
                switch()
            # Fail before upload/pre when the program-owned page state cannot
            # reproduce the current submit branch.
            current_kww = getattr(auth, "kww", "") or ""
            current_kwfv1 = getattr(auth, "kwfv1", "") or (
                getattr(auth, "_cookie", {}) or {}).get("kwfv1", "")
            if len(current_kww) != 174:
                raise RuntimeError("publish_video_file 当前 submit 需要 174 字符页面 kww")
            if len(current_kwfv1) != 218:
                raise RuntimeError("publish_video_file 当前 submit 需要 218 字符 Cookie kwfv1")
            if current_kww == current_kwfv1:
                raise RuntimeError("publish_video_file 当前 submit 要求 kww/kwfv1 独立且不相等")
        uploaded = KuaishouPublishAPI.upload_video_file(auth, file_path,
                                                        on_progress=on_progress)
        info = (uploaded.get("finish") or {}).get("data") or {}
        missing = [key for key in ("fileId", "coverKey", "mediaId", "videoDuration")
                   if info.get(key) in (None, "")]
        if not historical and missing:
            raise RuntimeError(
                f"当前 upload/finish 缺少构造 reqid 1316 submit 的字段: {missing}")
        return KuaishouPublishAPI.publish_video(
            auth, caption,
            file_id=(info.get("fileId") if not historical
                     else info.get("fileId") or uploaded.get("fileId")),
            cover_key=info.get("coverKey", ""),
            media_id=info.get("mediaId", ""),
            photo_id_str=(info.get("photoIdStr", "") if historical else ""),
            video_duration=info.get("videoDuration", 0),
            photo_status=photo_status, publish_time=publish_time, extra=extra)

    @staticmethod
    def publish_atlas(auth, caption: str, file_id, atlas_id,
                      photo_status: int = PHOTO_STATUS_PUBLIC, publish_time: int = 0,
                      cover_type: int = 1, extra: dict = None, **kwargs) -> dict:
        """提交图文发布。

        字段与顺序照 2026-08-16 实抓（真发了一条两图图集，``result:1``），
        原始请求导出含会话信息，不随仓库提交；这里保留经过代码审查的字段合同。

        与视频 submit 的两个关键差别，别套用：

        - **图集 submit 走 sig3**，视频 submit 走 sig4。
        - 只有 12 个业务字段（视频 42 个），而且**不带 blobKey**——
          图片是靠之前的 ``upload/finish`` 关联到 atlasId 上的。

        提交前必须先调 :meth:`atlas_upload_finish`（服务端内容审核）。

        :param auth: KuaishouAuth。
        :param caption: 作品描述。
        :param file_id: 上传返回的 fileId。
        :param atlas_id: 图集 id。
        :param photo_status: 查看权限，见 ``PHOTO_STATUS_*``。
        :param publish_time: 定时发布时间戳；0 表示立即发布。
        :param cover_type: 封面类型，默认 1（用第一张图）。
        :param extra: 覆盖/追加字段。
        :return: JSON ``{"result":1,"message":"成功"}``。
        """
        body = {
            "fileId": file_id,
            "atlasId": atlas_id,
            "caption": re.sub(r'(\S)#', r'\1 #', caption or ""),
            "photoStatus": photo_status,
            "longitude": "",
            "latitude": "",
            "declareInfo": {},
            "activityIds": [],
            "publishTime": publish_time,
            "coPublishUser": [],
            "useAiCaption": False,
            "coverType": cover_type,
        }
        if extra:
            body.update(extra)
        return KuaishouPublishAPI._post(
            auth, "/rest/cp/works/atlas/pc/publish/submit", body,
            upload_context="atlas")

    @staticmethod
    def publish_atlas_images(auth, images: list, caption: str,
                             photo_status: int = PHOTO_STATUS_PUBLIC,
                             publish_time: int = 0, extra: dict = None,
                             on_progress=None, **kwargs) -> dict:
        """一步发布图集：逐图上传 → 校验 → 提交。

        :param auth: KuaishouAuth。
        :param images: 本地图片路径列表，顺序即图集顺序。
        :param caption: 作品描述。
        :param photo_status: 查看权限，见 ``PHOTO_STATUS_*``。
        :param publish_time: 定时发布时间戳；0 立即发布。
        :param extra: 覆盖 submit 的字段。
        :param on_progress: 进度回调 ``fn(已完成张数, 总张数)``。
        :return: submit 的响应 JSON。
        """
        up = KuaishouPublishAPI.upload_atlas_images(auth, images, on_progress=on_progress)
        checked = KuaishouPublishAPI.atlas_upload_finish(
            auth, up["fileId"], up["atlasId"], up["blobKeys"])
        if checked.get("result") != 1:
            raise RuntimeError(f"atlas upload/finish 未通过: {checked.get('message')} / {checked}")
        return KuaishouPublishAPI.publish_atlas(
            auth, caption, up["fileId"], up["atlasId"],
            photo_status=photo_status, publish_time=publish_time, extra=extra)

    @staticmethod
    def publish_media_file(auth, file_path: str, caption: str = "",
                           media_type: str = "auto",
                           photo_status: int = PHOTO_STATUS_PUBLIC,
                           publish_time: int = 0, extra: dict = None,
                           on_progress=None, **kwargs) -> dict:
        """按文件类型自动选择图文或视频发布链路。

        媒体类型识别和图文格式归一化都在发布 API 层完成，调用方只需给出
        一个本地路径。图文仍由 :meth:`publish_atlas_images` 执行已验证的
        PNG wire contract；视频仍由 :meth:`publish_video_file` 执行原文件
        上传链路。

        ``media_type`` 可显式指定 ``image``/``video``，默认 ``auto`` 会按
        常见扩展名、MIME 和文件头判断。未知类型不会猜测。
        """
        if media_type not in {"auto", "image", "video"}:
            raise ValueError("media_type 必须是 auto、image 或 video")
        path = os.path.abspath(os.fspath(file_path))
        if not os.path.isfile(path):
            raise ValueError(f"媒体文件不存在或不可读: {path}")
        if os.path.getsize(path) <= 0:
            raise ValueError(f"媒体文件为空: {path}")
        resolved = _resolve_media_type(path, media_type)
        auth.use_site("https://cp.kuaishou.com")
        if resolved == "image":
            return KuaishouPublishAPI.publish_atlas_images(
                auth, [path], caption=caption, photo_status=photo_status,
                publish_time=publish_time, extra=extra, on_progress=on_progress)
        return KuaishouPublishAPI.publish_video_file(
            auth, path, caption=caption, photo_status=photo_status,
            publish_time=publish_time, extra=extra, on_progress=on_progress)

    # ------------------------------------------------------------------ #
    # 编排：把上传链串起来（浏览器发布页的实际调用顺序）                        #
    # ------------------------------------------------------------------ #
    @staticmethod
    def upload_video_file(auth, file_path: str, on_progress=None, **kwargs) -> dict:
        """走完视频上传链，返回 submit 需要的 fileId 与探测到的视频信息。

        顺序与发布页一致：``upload/pre`` → ksuploader 分片 → ``upload/finish``。
        拿到结果后再自行调 :meth:`video_cover_upload` 与 :meth:`publish_video`。

        :param auth: KuaishouAuth。
        :param file_path: 本地视频路径。
        :param on_progress: 可选回调 ``fn(已传字节, 总字节)``。
        :return: ``{"fileId":…, "token":…, "finish": <upload/finish 的响应>}``。
        """
        if not os.path.isfile(file_path):
            raise ValueError(f"视频素材不存在或不可读: {file_path}")
        if os.path.getsize(file_path) <= 0:
            raise ValueError(f"视频素材为空: {file_path}")
        # This helper is public and can be called without publish_video_file;
        # keep the same fail-closed permission boundary here as well.  A
        # successful page precheck is cached, so the one-step flow emits only
        # the single browser-observed authority call.
        KuaishouPublishAPI.require_publish_authority(auth)
        pre = KuaishouPublishAPI.video_upload_pre(auth)
        if pre.get("result") != 1:
            raise RuntimeError(f"upload/pre 失败: {pre.get('message')} / {pre}")
        data = pre.get("data") or {}
        token = data.get("token")
        file_id = data.get("fileId")
        endpoints = data.get("endPoints") or data.get("endpoints") or []
        if not token or not endpoints:
            raise RuntimeError(f"upload/pre 未下发 token/endPoints: {data}")

        size = os.path.getsize(file_path)
        logger.info(f"[publish] 视频分片上传开始 fileId={file_id} size={size}")
        KsUploader(token, endpoints).upload_file(file_path, on_progress=on_progress)

        finish = KuaishouPublishAPI.video_upload_finish(
            auth, token, os.path.basename(file_path),
            mimetypes.guess_type(file_path)[0] or "video/mp4", size)
        if finish.get("result") != 1:
            raise RuntimeError(f"upload/finish 失败: {finish.get('message')} / {finish}")
        duration = (finish.get("data") or {}).get("videoDuration")
        if not duration or float(duration) <= 0:
            # 前端在这里也会直接判失败（"获取视频时长失败，请选择其他视频上传"）
            raise RuntimeError(f"upload/finish 未返回有效 videoDuration: {finish}")
        return {"fileId": file_id, "token": token, "finish": finish}

    @staticmethod
    def upload_atlas_images(auth, images: list, on_progress=None, **kwargs) -> dict:
        """走完图文上传链，返回 submit 需要的 fileId / atlasId / blobKey 列表。

        顺序与发布页实抓一致：**每张图各走一遍** ``atlas/upload/pre``（``pictureCount:1``）
        → ksuploader 分片 → ``upload/single/finish``。第一张的 pre 不带
        ``atlasId``/``fileId``，服务端创建后回传，之后每张都带上。

        之后再调 :meth:`atlas_upload_finish` 校验、:meth:`publish_atlas` 提交，
        或者直接用 :meth:`publish_atlas_images` 一步到位。

        :param auth: KuaishouAuth。
        :param images: 本地图片路径列表，顺序即图集顺序。
        :param on_progress: 可选回调 ``fn(已完成张数, 总张数)``。
        :return: ``{"fileId":…, "atlasId":…, "blobKeys":[…], "urls":[…]}``。

        图文上传的底层 wire contract 是 ``image/png``。调用方可以传入常见的
        JPG、JPEG、WEBP、BMP、GIF、TIFF 等 Pillow 可读图片；非 PNG 图片会在
        这里转换到一个临时目录，随后整个上传链都使用转换后的 PNG，流程结束
        后自动清理。这样 demo、业务代码和直接调用者共享同一套 MIME/内容规则。
        """
        if isinstance(images, (str, bytes, os.PathLike)):
            images = [images]
        if not images:
            raise ValueError("images 不能为空")
        with ExitStack() as cleanup:
            images = _prepare_atlas_images(images, cleanup)
            if not 1 <= len(images) <= ATLAS_IMAGE_MAX_COUNT:
                raise ValueError(
                    f"图文图片数量必须在 1～{ATLAS_IMAGE_MAX_COUNT} 张之间")
            for path in images:
                if os.path.getsize(path) >= ATLAS_IMAGE_MAX_BYTES:
                    raise ValueError(f"{path} 超过 15MB，前端会直接拒绝")
                if os.path.getsize(path) > CHUNK_SIZE:
                    raise RuntimeError(
                        "当前上传合同只验证单片文件（不超过 4MB）；"
                        f"请压缩图片后重试: {path}")

            historical = getattr(auth, "_cp_cookie_phase", None) == "historical"
            snapshot = None
            after_resume_done = False
            if not historical:
                # QR/phone login finishes on the www product (kuaishou-vision).
                # The creator-shell authority request is the CP page contract
                # and must be sent after entering the ordinary CP context
                # (onvideo-cp). The first atlas-specific request below then
                # rotates to the atlas upload context as Chrome does.
                use_site = getattr(auth, "use_site", None)
                current_product = ((getattr(auth, "_cookie", {}) or {})
                                   .get("kwpsecproductname") or "")
                if callable(use_site) and current_product != "onvideo-cp":
                    use_site("https://cp.kuaishou.com")
                KuaishouPublishAPI.require_publish_authority(auth)

                # These page-12 requests happen once after selecting the atlas,
                # before the first upload/pre. They must not be repeated per image.
                preflight = (
                    ("atlas realize/entrance", KuaishouPublishAPI.atlas_realize_entrance(auth)),
                    ("atlas activity/list initial",
                     KuaishouPublishAPI.atlas_activity_list(auth, phase="initial")),
                    ("atlas collection/canAddAtlas",
                     KuaishouPublishAPI.collection_can_add_atlas(auth)),
                )
                for label, response in preflight:
                    if response.get("result") != 1:
                        raise RuntimeError(f"{label} 未通过: {response}")

            file_id, atlas_id = None, None
            blob_keys, urls = [], []
            for idx, path in enumerate(images):
                # Browser contract: one upload/pre per picture. The first call
                # creates the atlas; subsequent calls carry the returned IDs.
                pre = KuaishouPublishAPI.atlas_upload_pre(
                    auth, [path], atlas_id=atlas_id, file_id=file_id)
                if pre.get("result") != 1:
                    raise RuntimeError(
                        f"第 {idx + 1} 张 atlas upload/pre 失败: "
                        f"{pre.get('message')} / {pre}")
                data = pre.get("data") or {}
                file_id = data.get("fileId") or file_id
                atlas_id = data.get("atlasId") or atlas_id
                one = data.get("uploadInfo") or []
                if not file_id or not atlas_id or len(one) != 1:
                    raise RuntimeError(
                        f"第 {idx + 1} 张 atlas upload/pre 响应形状不完整: {data}")
                info = one[0]
                token = info.get("token")
                endpoints = info.get("endPoints") or info.get("endpoints") or []
                blob_key = info.get("blobKey")
                if not token or not endpoints or not blob_key:
                    raise RuntimeError(
                        f"第 {idx + 1} 张 atlas upload/pre 未下发 "
                        f"token/endPoints/blobKey: {info}")

                def after_resume(_resume_response):
                    nonlocal after_resume_done
                    if historical or after_resume_done:
                        return
                    followups = (
                        ("atlas activity/list post_resume",
                         KuaishouPublishAPI.atlas_activity_list(auth, phase="post_resume")),
                        ("atlas activity/tab", KuaishouPublishAPI.atlas_activity_tab(auth)),
                        ("atlas activity/filter", KuaishouPublishAPI.atlas_activity_filter(auth)),
                    )
                    for label, response in followups:
                        if response.get("result") != 1:
                            raise RuntimeError(f"{label} 未通过: {response}")
                    after_resume_done = True

                with open(path, "rb") as fp:
                    KsUploader(token, endpoints).upload_bytes(
                        fp.read(), os.path.basename(path), after_resume=after_resume)
                done = KuaishouPublishAPI.atlas_upload_single_finish(
                    auth, file_id, atlas_id, blob_key)
                if done.get("result") != 1:
                    raise RuntimeError(
                        f"第 {idx + 1} 张 atlas upload/single/finish 失败: {done}")
                blob_keys.append(blob_key)
                url_list = (done.get("data") or {}).get("url") or []
                urls.append(url_list[0].get("url") if url_list else None)
                if on_progress:
                    on_progress(idx + 1, len(images))

            # The current one-picture editor saves an automatic draft snapshot.
            # The retained multi-picture contract goes straight from the
            # per-picture finishes to atlas upload/finish, so do not invent a
            # snapshot request for multi-picture publishes.
            if not historical and len(images) == 1:
                snapshot = KuaishouPublishAPI.atlas_publish_info_snapshot_save(
                    auth, file_id, atlas_id)
                if snapshot.get("result") != 1:
                    raise RuntimeError(
                        f"atlas publishInfo/snapshot/save 失败: {snapshot}")
            result = {
                "fileId": file_id,
                "atlasId": atlas_id,
                "blobKeys": blob_keys,
                "urls": urls,
            }
            if snapshot is not None:
                result["snapshot"] = snapshot
            return result


# --------------------------------------------------------------------------- #
# 模块级辅助                                                                    #
# --------------------------------------------------------------------------- #
def _resolve_media_type(path: str, media_type: str = "auto") -> str:
    """Resolve a local media path without changing its upload bytes."""
    if media_type != "auto":
        return media_type
    suffix = os.path.splitext(path)[1].lower()
    if suffix in _VIDEO_SUFFIXES:
        return "video"
    if suffix in _IMAGE_SUFFIXES:
        return "image"
    mime = mimetypes.guess_type(path)[0] or ""
    if mime.startswith("video/"):
        return "video"
    if mime.startswith("image/"):
        return "image"
    try:
        with open(path, "rb") as fp:
            head = fp.read(4096)
    except OSError:
        head = b""
    if head.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"BM")):
        return "image"
    if head.startswith((b"II*\x00", b"MM\x00*")):
        return "image"
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "image"
    if len(head) >= 12 and head[4:8] == b"ftyp":
        brand = head[8:12].lower()
        if brand in {b"heic", b"heix", b"hevc", b"hevx", b"avif", b"avis"}:
            return "image"
        return "video"
    if head.startswith((b"\x1a\x45\xdf\xa3", b"FLV", b"OggS", b"\x30\x26\xb2\x75")):
        return "video"
    if head.startswith(b"\x00\x00\x01\xba"):
        return "video"
    raise ValueError(
        f"无法自动识别媒体类型：{os.path.basename(path)}；请指定 media_type=image 或 video")


def _prepare_atlas_images(images: list, cleanup: ExitStack) -> list:
    """Validate and normalize atlas inputs to the PNG wire contract.

    ``cleanup`` owns every temporary directory so callers cannot accidentally
    leave converted credentials-adjacent media in the workspace.  The helper
    is deliberately used by the lower-level upload chain rather than the demo.
    """
    prepared = []
    for source in images:
        path = os.fspath(source)
        if not os.path.isfile(path):
            raise ValueError(f"图文素材不存在或不可读: {path}")
        if os.path.getsize(path) >= ATLAS_IMAGE_MAX_BYTES:
            raise ValueError(f"{path} 超过 15MB，前端会直接拒绝")
        if os.path.splitext(path)[1].lower() == ".png":
            try:
                with open(path, "rb") as fp:
                    is_png = fp.read(len(_PNG_SIGNATURE)) == _PNG_SIGNATURE
            except OSError:
                is_png = False
            if is_png:
                prepared.append(path)
                continue

        try:
            from PIL import Image
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise RuntimeError(
                "非 PNG 图文需要 Pillow，请先执行：pip install -r requirements.txt") from exc

        temp_dir = cleanup.enter_context(TemporaryDirectory(prefix="kuaishou_atlas_"))
        stem = os.path.splitext(os.path.basename(path))[0] or "image"
        converted = os.path.join(temp_dir, f"{stem}.png")
        try:
            with Image.open(path) as image:
                image.load()
                if image.mode not in {"RGB", "RGBA"}:
                    image = image.convert("RGBA" if "A" in image.getbands() else "RGB")
                image.save(converted, format="PNG", optimize=False)
        except Exception as exc:
            raise ValueError(f"无法读取或转换图文素材：{path}") from exc
        logger.info(f"[publish] 图文素材已临时转换为 PNG: {os.path.basename(path)}")
        prepared.append(converted)
    return prepared


def _safe_json(resp) -> dict:
    try:
        return json.loads(resp.text)
    except Exception:
        logger.error(f'响应非 JSON：{resp.status_code} {resp.text[:200]}')
        return {"result": -1, "error": resp.text[:500]}


if __name__ == '__main__':
    from builder.auth import KuaishouAuth

    cookies_str = ''
    auth_ = KuaishouAuth()
    auth_.prepare_auth(cookies_str)

    # 只读接口，实测 cookie 直连多返回 result:1（sig3 就绪后更稳）：
    # print(KuaishouPublishAPI.current_user(auth_))
    # print(KuaishouPublishAPI.video_upload_config(auth_))
    # print(KuaishouPublishAPI.atlas_upload_config(auth_))
    # print(KuaishouPublishAPI.w_info(auth_, biz='addPoi'))
    # print(KuaishouPublishAPI.collection_tab(auth_))
