#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""快手 Web 数据接口（www.kuaishou.com），风格对齐 DouYin_Spider/dy_apis/douyin_api.py。

约定：
    - 全部 ``@staticmethod``，第一参数 ``auth``（KuaishouAuth），中文 docstring 标注参数含义。
    - 统一域名 ``https://www.kuaishou.com`` + api；Referer 必须来自对应真实页面。
    - 请求头注入页面快照 ``kww``（它不等于 Cookie ``kwfv1``）；命中签名白名单的接口追加 query ``__NS_hxfalcon`` + ``caver=2``。
    - REST 接口体多为 JSON（POST），响应形如 ``{result:1, pcursor, feeds:[...]}``。

签名说明（详见 utils/sign）：
    白名单接口需 ``__NS_hxfalcon``（sig4），已纯算实现并对真实抓包逐字节校验。
    ``feed/hot`` 等服务端实测宽松，``profile/*`` / ``search/*`` / ``collect`` 严格校验签名；
    不在白名单的接口（comment/relation）不需签名。
"""

import json
import time
import urllib.parse

import requests

requests.packages.urllib3.disable_warnings()
from loguru import logger

from builder.header import HeaderBuilder, HeaderType, ACCEPT_ANY
from builder.params import Params
from utils.transport import http_proxy

requests = http_proxy(requests)   # get/post 走 Chrome TLS/ALPN 共享会话


class UnverifiedBrowserContractError(RuntimeError):
    """阻止没有当前 Chrome Network 成功证据的旧接口继续发包。"""


# 当前 Chrome 已成功发出的 REST body 键及顺序。这里是运行时护栏，不只是测试：
# 后续有人删字段、补“方便字段”或改变顺序时，请求会在出网前直接失败。
_REST_BODY_KEY_CONTRACTS = {
    "/rest/v/feed/hot": {()},
    "/rest/v/photo/comment/list": {("photoId", "pcursor")},
    "/rest/v/profile/feed": {("user_id", "pcursor", "page")},
    "/rest/v/search/feed": {
        ("keyword", "page", "webPageArea", "pcursor"),
        ("keyword", "pcursor", "searchSessionId"),
    },
    "/rest/v/search/user": {("keyword", "pcursor", "searchSessionId")},
    "/rest/v/feed/liked": {("pcursor", "page")},
    "/rest/v/collect/list": {("userId", "pcursor", "page")},
    "/rest/v/profile/private/list": {("pcursor", "page")},
    "/rest/v/live/playBack/list": {("userId", "pcursor")},
    "/rest/v/relation/fol": {("pcursor", "ftype")},
    "/rest/v/system/configs": {()},
    "/rest/v/kconf/get": {()},
}

# Current QR/re-login session successful REST paths.  system/configs remains
# in the historical body table above for offline comparison, but the latest
# re-login profile/new-reco/search Network did not send it, so runtime relogin
# calls must not use that older evidence.
_CURRENT_RELOGIN_REST_POST_PATHS = {
    "/rest/v/feed/hot", "/rest/v/photo/comment/list",
    "/rest/v/profile/feed", "/rest/v/search/feed", "/rest/v/search/user",
    "/rest/v/feed/liked", "/rest/v/collect/list",
    "/rest/v/profile/private/list", "/rest/v/live/playBack/list",
    "/rest/v/relation/fol", "/rest/v/kconf/get",
}

# Current successful other-user profile browser flow.  The cursor values are
# response-issued opaque strings and must be replayed byte-for-byte; accepting
# arbitrary targets/cursors would invent an uncaptured Cookie phase.
_CURRENT_OTHER_PROFILE_EID = "3xjgwdr9sfzyx89"
_CURRENT_OTHER_PROFILE_CURSOR_PROFILES = {
    "": "www_relogin_profile_other_initial",
    "1.785297653203E12": "www_relogin_profile_other_page_first",
    "1.784772031506E12": "www_relogin_profile_other_page_following",
    "1.781776036886E12": "www_relogin_profile_other_page_following",
}

# Fresh current new-reco comment requests. Cookie order changes independently
# of pcursor, so the exact browser-observed photo/cursor pair selects the phase;
# arbitrary pairs must not guess between phase A and B.
_CURRENT_RECO_COMMENT_PROFILES = {
    ("3xnjb6xrxbiffb9", ""): "www_relogin_reco_comment_phase_a",
    ("3xnjb6xrxbiffb9", "1170575910810"): "www_relogin_reco_comment_phase_a",
    ("3x2dgrbddyqs2fi", ""): "www_relogin_reco_comment_phase_a",
    ("3x2dgrbddyqs2fi", "1161895002302"): "www_relogin_reco_comment_phase_a",
    ("3xjx8922wuz3ify", ""): "www_relogin_reco_comment_phase_b",
    ("3xjx8922wuz3ify", "1169141423181"): "www_relogin_reco_comment_phase_b",
}

_GRAPHQL_VARIABLE_KEY_CONTRACTS = {
    "visionShortVideoReco": {("page", "photoId")},
    "visionVideoDetail": {("photoId", "page")},
    "commentListQuery": {("photoId", "pcursor")},
    "visionSubCommentList": {("photoId", "rootCommentId", "pcursor")},
    "visionBaseEmoticons": {()},
    "visionLoginConfig": {("key",)},
    "checkLoginQuery": {()},
    "visionOttConfig": {("key",)},
    "likeDataQuery": {("token", "st", "page")},
    "visionProfileReduced": {(), ("userId",)},
    "visionProfilePhotoList": {("pcursor", "page", "profile_referer")},
    "visionConfigQuery": {()},
    "userInfoQuery": {()},
}

_RELOGIN_COOKIE_KEY_CONTRACTS = {
    "www_relogin_initial": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kwscode", "kwssectoken", "kwscode", "ktrace-context", "kpn",
        "kwpsecproductname", "kwssectoken", "kwfv1",
    ),
    "www_relogin_profile_self_initial": (
      "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
      "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
      "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
      "kwpsecproductname", "kwssectoken", "kwscode", "kwssectoken",
      "kwscode", "kwfv1", "ktrace-context", "kpn",
    ),
    "www_relogin_profile_self_restricted": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kwpsecproductname", "kwssectoken", "kwscode", "kwfv1",
        "ktrace-context", "kpn", "kwssectoken", "kwscode",
    ),
    "www_relogin_liked": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
      "kwpsecproductname", "kwssectoken", "kwscode", "ktrace-context",
      "kpn", "kwfv1", "kwssectoken", "kwscode",
    ),
    "www_relogin_collection": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kwssectoken", "kwscode", "ktrace-context", "kpn",
        "kwpsecproductname", "kwssectoken", "kwscode", "kwfv1",
    ),
    "www_relogin_collect": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
      "kwpsecproductname", "kwssectoken", "kwscode", "ktrace-context",
      "kpn", "kwssectoken", "kwscode", "kwfv1",
    ),
    "www_relogin_private": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
      "kwpsecproductname", "ktrace-context", "kpn", "kwssectoken",
      "kwscode", "kwssectoken", "kwscode", "kwfv1",
    ),
    "www_relogin_profile_self_ignore_cache": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kwpsecproductname", "kwfv1", "kwssectoken", "kwscode",
        "kwssectoken", "kwscode", "ktrace-context", "kpn",
    ),
    "www_relogin_profile_tabs_ignore_cache": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kwpsecproductname", "ktrace-context", "kpn", "kwssectoken",
        "kwscode", "kwssectoken", "kwscode", "kwfv1",
    ),
    "www_relogin_relation_following": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "ktrace-context", "kpn", "kwpsecproductname", "kwssectoken",
        "kwscode", "kwfv1", "kwssectoken", "kwscode",
    ),
    "www_relogin_relation_fans": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "ktrace-context", "kpn", "kwpsecproductname", "kwssectoken",
        "kwscode", "kwssectoken", "kwscode", "kwfv1",
    ),
    "www_relogin_reco_initial": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kwpsecproductname", "kwssectoken", "kwscode", "kwssectoken",
        "kwscode", "kwfv1", "ktrace-context", "kpn",
    ),
    "www_relogin_reco_comment_phase_a": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kwpsecproductname", "kwssectoken", "kwscode", "ktrace-context",
        "kpn", "kwssectoken", "kwscode", "kwfv1",
    ),
    "www_relogin_reco_comment_phase_b": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kwpsecproductname", "ktrace-context", "kpn", "kwssectoken",
        "kwscode", "kwfv1", "kwssectoken", "kwscode",
    ),
    "www_relogin_reco_page": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kwpsecproductname", "ktrace-context", "kpn", "kwssectoken",
        "kwscode", "kwssectoken", "kwscode", "kwfv1",
    ),
    "www_relogin_search_initial": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kwpsecproductname", "kwssectoken", "kwscode", "ktrace-context",
        "kpn", "kwssectoken", "kwscode", "kwfv1",
    ),
    "www_relogin_search_feed_page": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kwpsecproductname", "ktrace-context", "kpn", "kwssectoken",
        "kwscode", "kwssectoken", "kwscode", "kwfv1",
    ),
    "www_relogin_search_user_page_first": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kwpsecproductname", "ktrace-context", "kpn", "kwssectoken",
        "kwscode", "kwssectoken", "kwscode", "kwfv1",
    ),
    "www_relogin_search_user_page_following": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kwpsecproductname", "ktrace-context", "kpn", "kwssectoken",
        "kwscode", "kwfv1", "kwssectoken", "kwscode",
    ),
    "www_relogin_profile_other_initial": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kwssectoken", "kwscode", "ktrace-context", "kpn",
        "kwpsecproductname", "kwfv1", "kwssectoken", "kwscode",
    ),
    "www_relogin_profile_other_page_first": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "ktrace-context", "kpn", "kwpsecproductname", "kwssectoken",
        "kwscode", "kwfv1", "kwssectoken", "kwscode",
    ),
    "www_relogin_profile_other_page_following": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "ktrace-context", "kpn", "kwpsecproductname", "kwssectoken",
        "kwscode", "kwssectoken", "kwscode", "kwfv1",
    ),
    "www_graphql_relogin_initial": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kwpsecproductname", "kwssectoken", "kwscode", "ktrace-context",
        "kwssectoken", "kwscode", "kwfv1", "kpn",
    ),
    "www_graphql_relogin_refreshed": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kwpsecproductname", "ktrace-context", "kwssectoken", "kwscode",
        "kpn", "kwssectoken", "kwscode", "kwfv1",
    ),
    "www_graphql_detail_initial": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kwpsecproductname", "ktrace-context", "kwssectoken", "kwscode",
        "kpn", "kwfv1", "kwssectoken", "kwscode",
    ),
    "www_graphql_detail_bootstrap": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "bUserId", "ktrace-context", "kwpsecproductname", "kwssectoken",
        "kwscode", "kwfv1", "kwssectoken", "kwscode", "kpn",
    ),
    "www_graphql_detail_video_success": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "bUserId", "ktrace-context", "kwpsecproductname", "kpn",
        "kwssectoken", "kwscode", "kwssectoken", "kwscode", "kwfv1",
    ),
    "www_graphql_detail_refreshed": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kwpsecproductname", "ktrace-context", "kwssectoken", "kwscode",
        "kpn", "kwfv1", "kwssectoken", "kwscode",
    ),
    # Chrome reqids 14832/14841/14849/14858 and 15500. Comment pagination
    # uses a page-local security phase distinct from the initial detail calls.
    "www_graphql_comment_initial": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "ktrace-context", "kpn", "kwpsecproductname", "kwssectoken",
        "kwscode", "kwssectoken", "kwscode", "kwfv1",
    ),
    # Current logged-in Chrome reqid 26926 after clicking “查看更多回复”.
    # This UI phase is distinct from root-comment pagination.
    "www_graphql_subcomment_initial": (
        "kpf", "clientid", "did", "wid", "didv", "kwpsecproductname",
        "userId", "kuaishou.server.webday7_st", "kuaishou.server.webday7_ph",
        "bUserId", "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
        "kwpsecproductname", "ktrace-context", "kwssectoken", "kwscode",
        "kpn", "kwfv1", "kwssectoken", "kwscode",
    ),
}


def _assert_exact_keys(kind: str, name: str, value: dict | None, contracts: dict):
    allowed = contracts.get(name)
    if allowed is None:
        raise UnverifiedBrowserContractError(
            f"{kind} {name} 没有当前 Chrome Network 成功合同，拒绝出网")
    actual = tuple(value.keys()) if isinstance(value, dict) else ()
    if actual not in allowed:
        expected = " or ".join(str(item) for item in sorted(allowed, key=len))
        raise ValueError(f"{kind} {name} 字段/顺序不符合当前 Chrome Network: "
                         f"actual={actual}, expected={expected}")

# --------------------------------------------------------------------------- #
# GraphQL query 文本                                                           #
# --------------------------------------------------------------------------- #
# **逐字取自 Chrome DevTools 实抓**（2026-08-16，作品详情页）。
# 服务端按 query 文本本身做持久化查询校验，**一个字符都不能改**
# （包括换行和缩进），改了会直接被拒。
GQL_SHORT_VIDEO_RECO = (
    "fragment photoContent on PhotoEntity {\n"
    "  __typename\n  id\n  duration\n  caption\n  originCaption\n  likeCount\n"
    "  viewCount\n  commentCount\n  realLikeCount\n  coverUrl\n  photoUrl\n"
    "  photoH265Url\n  manifest\n  manifestH265\n  videoResource\n  coverUrls {\n"
    "    url\n    __typename\n  }\n  timestamp\n  expTag\n  animatedCoverUrl\n"
    "  distance\n  disableSensitivePhoto\n  videoRatio\n  liked\n  stereoType\n"
    "  profileUserTopPhoto\n  musicBlocked\n  riskTagContent\n  riskTagUrl\n}\n\n"
    "query visionShortVideoReco($semKeyword: String, $semCrowd: String, "
    "$utmSource: String, $utmMedium: String, $page: String, $photoId: String, "
    "$utmCampaign: String) {\n"
    "  visionShortVideoReco(semKeyword: $semKeyword, semCrowd: $semCrowd, "
    "utmSource: $utmSource, utmMedium: $utmMedium, page: $page, photoId: $photoId, "
    "utmCampaign: $utmCampaign) {\n"
    "    llsid\n    feeds {\n      type\n      author {\n        id\n        name\n"
    "        following\n        headerUrl\n        __typename\n      }\n"
    "      photo {\n        ...photoContent\n        __typename\n      }\n"
    "      tags {\n        type\n        name\n        __typename\n      }\n"
    "      authorStatement {\n        content\n        type\n        riskStyleType\n"
    "        __typename\n      }\n      canAddComment\n      __typename\n    }\n"
    "    __typename\n  }\n}\n"
)

GQL_COMMENT_LIST = (
    "query commentListQuery($photoId: String, $pcursor: String) {\n"
    "  visionCommentList(photoId: $photoId, pcursor: $pcursor) {\n"
    "    commentCount\n    commentCountV2\n    pcursor\n    rootCommentsV2 {\n"
    "      commentId\n      authorId\n      authorName\n      content\n      headurl\n"
    "      timestamp\n      hasSubComments\n      likedCount\n      liked\n      status\n"
    "      __typename\n    }\n    pcursorV2\n    rootComments {\n      commentId\n"
    "      authorId\n      authorName\n      content\n      headurl\n      timestamp\n"
    "      likedCount\n      realLikedCount\n      liked\n      status\n      authorLiked\n"
    "      subCommentCount\n      subCommentsPcursor\n      subComments {\n"
    "        commentId\n        authorId\n        authorName\n        content\n"
    "        headurl\n        timestamp\n        likedCount\n        realLikedCount\n"
    "        liked\n        status\n        authorLiked\n        replyToUserName\n"
    "        replyTo\n        __typename\n      }\n      __typename\n    }\n"
    "    __typename\n  }\n}\n"
)

GQL_SUB_COMMENT_LIST = (
    "mutation visionSubCommentList($photoId: String, $rootCommentId: String, $pcursor: String) {\n"
    "  visionSubCommentList(photoId: $photoId, rootCommentId: $rootCommentId, pcursor: $pcursor) {\n"
    "    pcursor\n    subComments {\n      commentId\n      authorId\n      authorName\n"
    "      content\n      headurl\n      timestamp\n      likedCount\n      realLikedCount\n"
    "      liked\n      status\n      authorLiked\n      replyToUserName\n      replyTo\n"
    "      __typename\n    }\n    pcursorV2\n    subCommentsV2 {\n      commentId\n"
    "      authorId\n      authorName\n      content\n      headurl\n      timestamp\n"
    "      hasSubComments\n      likedCount\n      liked\n      status\n      replyToUserName\n"
    "      replyTo\n      __typename\n    }\n    __typename\n  }\n}\n"
)

# 这是目标作品详情请求的 query 模板，保留用于出网前严格校验。当前
# Chrome/JSReverser 已抓到成功的 ``visionVideoDetail`` 请求（目标页
# ``<photo_id>``，body 1841 字节）；不能把
# visionShortVideoReco 推荐流第一条冒充目标详情。
GQL_VIDEO_DETAIL = (
    "query visionVideoDetail($photoId: String, $type: String, $page: String, $webPageArea: String) {\n"
    "  visionVideoDetail(photoId: $photoId, type: $type, page: $page, webPageArea: $webPageArea) {\n"
    "    status\n"
    "    type\n"
    "    author {\n"
    "      id\n      name\n      following\n      headerUrl\n      livingInfo\n"
    "      verifiedDetail\n      __typename\n"
    "    }\n"
    "    photo {\n"
    "      id\n      duration\n      caption\n      likeCount\n      realLikeCount\n"
    "      coverUrl\n      photoUrl\n      liked\n      timestamp\n      expTag\n      llsid\n"
    "      viewCount\n      videoRatio\n      stereoType\n      musicBlocked\n      riskTagContent\n"
    "      riskTagUrl\n"
    "      manifest {\n"
    "        mediaType\n        businessType\n        version\n"
    "        adaptationSet {\n"
    "          id\n          duration\n"
    "          representation {\n"
    "            id\n            defaultSelect\n            backupUrl\n            codecs\n"
    "            url\n            height\n            width\n            avgBitrate\n            maxBitrate\n"
    "            m3u8Slice\n            qualityType\n            qualityLabel\n            frameRate\n"
    "            featureP2sp\n            hidden\n            disableAdaptive\n            __typename\n"
    "          }\n"
    "          __typename\n"
    "        }\n"
    "        __typename\n"
    "      }\n"
    "      manifestH265\n      photoH265Url\n      coronaCropManifest\n"
    "      coronaCropManifestH265\n      croppedPhotoH265Url\n      croppedPhotoUrl\n"
    "      videoResource\n      __typename\n"
    "    }\n"
    "    authorStatement {\n      content\n      type\n      riskStyleType\n      __typename\n    }\n"
    "    tags {\n      type\n      name\n      __typename\n    }\n"
    "    commentLimit {\n      canAddComment\n      __typename\n    }\n"
    "    llsid\n    danmakuSwitch\n    __typename\n"
    "  }\n}\n"
)

GQL_BASE_EMOTICONS = (
    "query visionBaseEmoticons {\n"
    "  visionBaseEmoticons {\n"
    "    iconUrls\n"
    "    __typename\n"
    "  }\n"
    "}\n"
)

# 取当前登录用户信息。比打 profile/get 轻，而且**直接给 eid**
# （`/rest/v/*` 的 body 里要的就是 eid，不是 cookie 里那个数字 userId）。
GQL_USER_INFO = (
    "query userInfoQuery {\n  userInfo {\n    id\n    name\n    avatar\n    eid\n"
    "    userId\n    __typename\n  }\n}\n"
)

# --------------------------------------------------------------------------- #
# 当前 myFollow / profile GraphQL（2026-08-25 Chrome Network req 783/786/785）#
# --------------------------------------------------------------------------- #
# 这些 query 文本逐字来自当前版本的 Chrome Network 证据（原始导出不入库）。
# 不要按业务字段自行删减：GraphQL 持久化校验和风控链路都把 query 文本纳入
# 请求画像。likeData / profilePhotoList 共用的四个 fragment 也保持浏览器顺序。
GQL_FOLLOW_FEED_FRAGMENTS = (
    "fragment photoContent on PhotoEntity {\n"
    "  __typename\n"
    "  id\n"
    "  duration\n"
    "  caption\n"
    "  originCaption\n"
    "  likeCount\n"
    "  viewCount\n"
    "  commentCount\n"
    "  realLikeCount\n"
    "  coverUrl\n"
    "  photoUrl\n"
    "  photoH265Url\n"
    "  manifest\n"
    "  manifestH265\n"
    "  videoResource\n"
    "  coverUrls {\n"
    "    url\n"
    "    __typename\n"
    "  }\n"
    "  timestamp\n"
    "  expTag\n"
    "  animatedCoverUrl\n"
    "  distance\n"
    "  disableSensitivePhoto\n"
    "  videoRatio\n"
    "  liked\n"
    "  stereoType\n"
    "  profileUserTopPhoto\n"
    "  musicBlocked\n"
    "  riskTagContent\n"
    "  riskTagUrl\n"
    "}\n\n"
    "fragment recoPhotoFragment on recoPhotoEntity {\n"
    "  __typename\n"
    "  id\n"
    "  duration\n"
    "  caption\n"
    "  originCaption\n"
    "  likeCount\n"
    "  viewCount\n"
    "  commentCount\n"
    "  realLikeCount\n"
    "  coverUrl\n"
    "  photoUrl\n"
    "  photoH265Url\n"
    "  manifest\n"
    "  manifestH265\n"
    "  videoResource\n"
    "  coverUrls {\n"
    "    url\n"
    "    __typename\n"
    "  }\n"
    "  timestamp\n"
    "  expTag\n"
    "  animatedCoverUrl\n"
    "  distance\n"
    "  videoRatio\n"
    "  liked\n"
    "  stereoType\n"
    "  profileUserTopPhoto\n"
    "  musicBlocked\n"
    "  riskTagContent\n"
    "  riskTagUrl\n"
    "}\n\n"
    "fragment feedContentWithLiveInfo on Feed {\n"
    "  type\n"
    "  author {\n"
    "    id\n"
    "    name\n"
    "    headerUrl\n"
    "    following\n"
    "    livingInfo\n"
    "    headerUrls {\n"
    "      url\n"
    "      __typename\n"
    "    }\n"
    "    verifiedDetail {\n"
    "      description\n"
    "      iconType\n"
    "      newVerified\n"
    "      musicCompany\n"
    "      type\n"
    "      __typename\n"
    "    }\n"
    "    __typename\n"
    "  }\n"
    "  photo {\n"
    "    ...photoContent\n"
    "    ...recoPhotoFragment\n"
    "    __typename\n"
    "  }\n"
    "  canAddComment\n"
    "  llsid\n"
    "  status\n"
    "  authorStatement {\n"
    "    content\n"
    "    type\n"
    "    riskStyleType\n"
    "    __typename\n"
    "  }\n"
    "  currentPcursor\n"
    "  tags {\n"
    "    type\n"
    "    name\n"
    "    __typename\n"
    "  }\n"
    "  __typename\n"
    "}\n\n"
    "fragment photoResult on PhotoResult {\n"
    "  result\n"
    "  llsid\n"
    "  expTag\n"
    "  serverExpTag\n"
    "  pcursor\n"
    "  feeds {\n"
    "    ...feedContentWithLiveInfo\n"
    "    __typename\n"
    "  }\n"
    "  webPageArea\n"
    "  __typename\n"
    "}\n\n"
)

GQL_LIKE_DATA = GQL_FOLLOW_FEED_FRAGMENTS + (
    "query likeDataQuery($pcursor: String, $page: String, $token: String, $st: Long) {\n"
    "  likeData(pcursor: $pcursor, page: $page, token: $token, st: $st) {\n"
    "    ...photoResult\n"
    "    __typename\n"
    "  }\n"
    "}\n"
)

GQL_VISION_PROFILE_REDUCED = (
    "query visionProfileReduced($userId: String) {\n"
    "  visionProfileReduced(userId: $userId) {\n"
    "    result\n"
    "    hostName\n"
    "    userProfile {\n"
    "      profile {\n"
    "        gender\n"
    "        user_name\n"
    "        user_id\n"
    "        headurl\n"
    "        user_text\n"
    "        user_profile_bg_url\n"
    "        __typename\n"
    "      }\n"
    "      isFollowing\n"
    "      isUserIsolated\n"
    "      livingInfo\n"
    "      __typename\n"
    "    }\n"
    "    __typename\n"
    "  }\n"
    "}\n"
)

# visionProfilePhotoList 的浏览器 query 没有 photoResult fragment；它直接在
# visionProfilePhotoList 节点下展开 feeds。用同一份源码片段切掉最后一个
# fragment，避免两份长文本后续漂移。
GQL_PROFILE_PHOTO_LIST = GQL_FOLLOW_FEED_FRAGMENTS.split(
    "fragment photoResult on PhotoResult {", 1)[0] + (
    "query visionProfilePhotoList($pcursor: String, $userId: String, $page: String, $webPageArea: String, $profile_referer: String) {\n"
    "  visionProfilePhotoList(pcursor: $pcursor, userId: $userId, page: $page, webPageArea: $webPageArea, profile_referer: $profile_referer) {\n"
    "    result\n"
    "    llsid\n"
    "    webPageArea\n"
    "    feeds {\n"
    "      ...feedContentWithLiveInfo\n"
    "      __typename\n"
    "    }\n"
    "    hostName\n"
    "    pcursor\n"
    "    __typename\n"
    "  }\n"
    "}\n"
)

GQL_VISION_CONFIG = (
    "query visionConfigQuery {\n"
    "  visionConfig {\n"
    "    coronaTabs {\n"
    "      tabId\n"
    "      name\n"
    "      folded\n"
    "      selected\n"
    "      __typename\n"
    "    }\n"
    "    tubeTabs {\n"
    "      tabId\n"
    "      name\n"
    "      folded\n"
    "      selected\n"
    "      subTabs {\n"
    "        subTabId\n"
    "        subTabName\n"
    "        __typename\n"
    "      }\n"
    "      __typename\n"
    "    }\n"
    "    banners {\n"
    "      id\n"
    "      landingUrl\n"
    "      imageUrl\n"
    "      checkLogin\n"
    "      openInNewTab\n"
    "      __typename\n"
    "    }\n"
    "    movieTagTypes {\n"
    "      movieTagType\n"
    "      movieTagValues\n"
    "      __typename\n"
    "    }\n"
    "    disabledModules\n"
    "    homeModuleOrder\n"
    "    __typename\n"
    "  }\n"
    "}\n"
)

GQL_KCONF = "query {\n  kconf(key: $key)\n}\n"
GQL_VISION_LOGIN_CONFIG = (
    "query visionLoginConfig($key: String) {\n"
    "  kconf(key: $key)\n"
    "}\n"
)
GQL_CHECK_LOGIN = "query checkLoginQuery {\n  checkLogin\n}\n"
GQL_VISION_OTT_CONFIG = (
    "query visionOttConfig($key: String) {\n"
    "  kconf(key: $key)\n"
    "}\n"
)

_GRAPHQL_QUERY_CONTRACTS = {
    "visionShortVideoReco": GQL_SHORT_VIDEO_RECO,
    "visionVideoDetail": GQL_VIDEO_DETAIL,
    "commentListQuery": GQL_COMMENT_LIST,
    "visionSubCommentList": GQL_SUB_COMMENT_LIST,
    "visionBaseEmoticons": GQL_BASE_EMOTICONS,
    "visionLoginConfig": GQL_VISION_LOGIN_CONFIG,
    "checkLoginQuery": GQL_CHECK_LOGIN,
    "visionOttConfig": GQL_VISION_OTT_CONFIG,
    "likeDataQuery": GQL_LIKE_DATA,
    "visionProfileReduced": GQL_VISION_PROFILE_REDUCED,
    "visionProfilePhotoList": GQL_PROFILE_PHOTO_LIST,
    "visionConfigQuery": GQL_VISION_CONFIG,
    "userInfoQuery": GQL_USER_INFO,
}


def _url(base: str, api: str, params: Params) -> str:
    """拼最终 url。

    query 自己按 axios 口径序列化后拼进 url，不走 requests 的 ``params=`` ——
    requests 会把 ``$`` 编成 ``%24``，而 ``__NS_hxfalcon`` 的值里带 ``$``，
    那样发出去的 url 和浏览器就不一样了。
    """
    query = params.to_query_string()
    if not query:
        return f'{base}{api}'
    sep = '&' if '?' in api else '?'
    return f'{base}{api}{sep}{query}'


class KuaishouAPI:
    # Static review gate: every public callable must be listed here.  Tests
    # compare this tuple with inspect.getmembers(), so a newly added endpoint
    # cannot bypass browser-contract review silently.
    PUBLIC_METHOD_REGISTRY = (
        "check_login", "get_all_comment", "get_all_comment_gql",
        "get_base_emoticons", "get_collect_list", "get_comment_list",
        "get_comment_list_gql", "get_feed_hot", "get_history_list",
        "get_liked_list", "get_playback_list", "get_private_list",
        "get_profile", "get_profile_feed", "get_profile_user_v2",
        "get_relation", "get_short_video_reco", "get_some_feed_hot",
        "get_some_relation", "get_sub_comment_list", "get_user_all_work",
        "get_user_info", "get_video_detail", "get_work_info", "graphql",
        "kconf_get", "like_data", "search_feed", "search_some_feed",
        "search_user", "system_configs", "system_startup", "vision_config",
        "vision_login_config", "vision_ott_config", "vision_profile_photo_list",
        "vision_profile_reduced",
    )
    kuaishou_url = 'https://www.kuaishou.com'
    reco_referer = 'https://www.kuaishou.com/new-reco'

    # ------------------------------------------------------------------ #
    # 内部通用请求器                                                        #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _cookie_profile(auth, api: str, referer: str = None) -> str:
        """Select the browser-observed Cookie line for the current www page.

        The latest re-login Network capture has three path-scoped sequences;
        choosing one global ``www`` order would silently omit/reorder fields.
        Legacy sessions retain the existing ``www`` phase behavior.
        """
        if getattr(auth, "_www_cookie_phase", "") != "relogin":
            return "www"
        effective_referer = referer or KuaishouAPI.reco_referer
        path = urllib.parse.urlsplit(effective_referer).path
        if path.startswith("/profile/"):
            target_eid = path.rsplit("/", 1)[-1]
            self_eid = str(getattr(auth, "_self_eid_cache", "") or "")
            if not self_eid:
                raise UnverifiedBrowserContractError(
                    "当前 profile Cookie 线序区分本人页和他人页；必须先在 /new-reco "
                    "调用 profile/get 缓存本人 eid，禁止猜测出网")
            if target_eid != self_eid:
                if target_eid != _CURRENT_OTHER_PROFILE_EID:
                    raise UnverifiedBrowserContractError(
                        f"当前重新登录 Chrome 只成功抓到他人个人页 "
                        f"{_CURRENT_OTHER_PROFILE_EID}；target={target_eid!r} 未验证，拒绝出网")
                other_paths = {
                    "/rest/v/kconf/get", "/rest/v/profile/get",
                    "/rest/v/profile/feed", "/rest/v/live/playBack/list",
                }
                if api not in other_paths:
                    raise UnverifiedBrowserContractError(
                        f"他人个人页未抓到 {api} 的当前成功 Network 合同，拒绝出网")
                return "www_relogin_profile_other_initial"
            if api == "/rest/v/feed/liked":
                if getattr(auth, "_www_ignore_cache", False):
                    return "www_relogin_profile_tabs_ignore_cache"
                return "www_relogin_liked"
            if api == "/rest/v/collect/list":
                if getattr(auth, "_www_ignore_cache", False):
                    return "www_relogin_profile_tabs_ignore_cache"
                return "www_relogin_collect"
            if api == "/rest/v/profile/private/list":
                if getattr(auth, "_www_ignore_cache", False):
                    return "www_relogin_profile_tabs_ignore_cache"
                return "www_relogin_private"
            if api == "/rest/v/relation/fol":
                raise UnverifiedBrowserContractError(
                    "当前本人页 relation/fol 的 Cookie 线序由 ftype 精确选择；"
                    "禁止只按 URL 猜测阶段")
            profile_paths = {
                "/rest/v/kconf/get",
                "/rest/v/profile/get", "/rest/v/profile/feed",
                "/rest/v/live/playBack/list",
            }
            if api not in profile_paths:
                raise UnverifiedBrowserContractError(
                    f"个人页未抓到 {api} 的当前成功 Network 合同，拒绝出网")
            if getattr(auth, "_www_account_restricted", False):
                if getattr(auth, "_www_ignore_cache", False):
                    raise UnverifiedBrowserContractError(
                        "账号限制后只抓到普通 profile reload，未抓 ignore-cache 分支")
                return "www_relogin_profile_self_restricted"
            return ("www_relogin_profile_self_ignore_cache"
                    if getattr(auth, "_www_ignore_cache", False)
                    else "www_relogin_profile_self_initial")
        if path == "/new-reco":
            reco_paths = {
                "/rest/v/kconf/get", "/rest/v/profile/get",
                "/rest/v/feed/hot", "/rest/v/photo/comment/list",
            }
            if api not in reco_paths:
                raise UnverifiedBrowserContractError(
                    f"new-reco 未抓到 {api} 的当前成功 Network 合同，拒绝出网")
            if api == "/rest/v/photo/comment/list":
                raise UnverifiedBrowserContractError(
                    "当前 new-reco 评论 Cookie 阶段不能只按 URL 判断；"
                    "必须由已抓到的 photoId/pcursor 精确选择")
            return "www_relogin_reco_initial"
        if path == "/search/video":
            search_paths = {
                "/rest/v/kconf/get", "/rest/v/profile/get",
                "/rest/v/search/feed", "/rest/v/search/user",
            }
            if api not in search_paths:
                raise UnverifiedBrowserContractError(
                    f"search/video 未抓到 {api} 的当前成功 Network 合同，拒绝出网")
            return "www_relogin_search_initial"
        raise UnverifiedBrowserContractError(
            f"当前重新登录会话没有 Referer={effective_referer!r} 对应的 "
            f"REST Cookie/请求合同，拒绝出网")

    @staticmethod
    def _wire_headers(auth, headers, site: str = "www"):
        """Attach the complete browser Cookie header, including duplicates."""
        serializer = getattr(auth, "cookie_header", None)
        if callable(serializer):
            cookie_line = serializer(site=site)
            headers.set_header("cookie", cookie_line)
            # Cache directives are emitted only when the caller explicitly
            # marks a DevTools ignore-cache navigation. The current fresh
            # login capture is an ordinary navigation and carries neither.
            if (getattr(auth, "_www_cookie_phase", "") == "relogin"
                    and getattr(auth, "_www_ignore_cache", False)
                    and site == "www_relogin_profile_self_ignore_cache"):
                headers.set_header("cache-control", "no-cache")
                headers.set_header("pragma", "no-cache")
            # 当前重新登录合同要求 Cookie 字段完整且顺序一致。不要让 serializer
            # 静默跳过缺值字段后继续出网；这种“首次能用”会逐渐进入风控画像。
            if getattr(auth, "_www_cookie_phase", "") == "relogin":
                contract_site = ("www_graphql_relogin_initial"
                                 if site == "www_graphql" else site)
                expected = _RELOGIN_COOKIE_KEY_CONTRACTS.get(contract_site)
                if expected:
                    pairs = [tuple(part.split("=", 1)) for part in
                             cookie_line.split("; ") if part and "=" in part]
                    actual = tuple(key for key, _ in pairs)
                    # Direct short-video navigation can be anonymous even
                    # when the caller later reuses a logged-in auth object:
                    # reqids 365--369/416 omit account-scoped user/STS/CP
                    # fields while retaining the same path-scoped webweapon
                    # cookies. Those five fields are optional only for the
                    # detail-page profiles; every other profile remains an
                    # exact fixed-key contract.
                    optional_detail = {
                        "userId", "kuaishou.server.webday7_st",
                        "kuaishou.server.webday7_ph",
                        "kuaishou.web.cp.api_st", "kuaishou.web.cp.api_ph",
                    }
                    if contract_site in {
                            "www_graphql_detail_bootstrap",
                            "www_graphql_detail_video_success"}:
                        expected = tuple(key for key in expected
                                        if key in actual or key not in optional_detail)
                    if actual != expected:
                        missing = [key for key in expected if key not in actual]
                        raise RuntimeError(
                            f"Cookie profile {contract_site} 不完整或顺序错误，拒绝出网: "
                            f"missing={missing}, actual={actual}, expected={expected}")
                    values = {}
                    for key, value in pairs:
                        values.setdefault(key, []).append(value)
                    fixed = {"kpf": "PC_WEB", "clientid": "3",
                             "kpn": "KUAISHOU_VISION"}
                    bad = {key: values.get(key) for key, value in fixed.items()
                           if values.get(key) != [value]}
                    products = values.get("kwpsecproductname", [])
                    allowed_products = (["kuaishou-vision"] if len(products) == 1
                                        else ["kuaishou-vision", "kuaishou-vision"])
                    # Current background live polling can leave the second
                    # path-scoped product at PCLive while the base www cookie
                    # is already kuaishou-vision (historical search/user reqid
                    # 1252 and reco reqids 632/736/739). This exact alternative is
                    # browser-observed; any other value/order still fails.
                    if (contract_site not in {"www_relogin_profile_self_initial",
                                              "www_relogin_profile_self_restricted"}
                            and len(products) == 2 and products[0] == "kuaishou-vision" \
                            and products[1] == "PCLive"):
                        allowed_products = products
                    if products != allowed_products:
                        bad["kwpsecproductname"] = products
                    if bad:
                        raise RuntimeError(
                            f"Cookie profile {contract_site} 固定值不符合当前 Chrome Network，"
                            f"拒绝出网: {bad}")
                if not headers.headers.get("kww"):
                    raise RuntimeError("当前 Chrome 请求必须带独立 kww；缺失时拒绝出网")
                if (contract_site in {"www_relogin_profile_self_initial",
                                      "www_relogin_profile_self_restricted",
                                      "www_relogin_profile_self_ignore_cache",
                                      "www_relogin_profile_tabs_ignore_cache",
                                      "www_relogin_liked",
                                      "www_relogin_collect",
                                      "www_relogin_private",
                                      "www_graphql_detail_video_success",
                                      "www_graphql_comment_initial",
                                      "www_graphql_subcomment_initial"}
                        and len(headers.headers.get("kww", "")) != 218):
                    raise RuntimeError(
                        f"当前本人 profile 合同 {contract_site} 的 kww 必须为 218 字符，"
                        "拒绝出网")
                expected_kwfv1_lengths = {
                    # The reqid=416 fixture stores the request body and
                    # response, but not a complete request-header capture.
                    # Do not guess a branch length for this profile: the
                    # browser's kwfv1 output is dynamic (174/218 branches)
                    # and is validated by the signer/oracle instead.
                    "www_relogin_profile_self_initial": {218},
                    # Fresh restricted reload reqids 468/470/471/472 use the
                    # 174 branch while the independent page kww stays 218.
                    "www_relogin_profile_self_restricted": {174},
                    "www_relogin_profile_self_ignore_cache": {174},
                    "www_relogin_profile_tabs_ignore_cache": {174},
                    # Current fresh-login Chrome reqids 90/91, 94/95 and 98.
                    "www_relogin_liked": {174},
                    "www_relogin_collect": {174},
                    "www_relogin_private": {218},
                    "www_graphql_comment_initial": {218},
                    "www_graphql_subcomment_initial": {174},
                }
                if contract_site in expected_kwfv1_lengths:
                    kwfv1_values = values.get("kwfv1", []) if expected else []
                    actual_lengths = [len(value) for value in kwfv1_values]
                    expected_lengths = expected_kwfv1_lengths[contract_site]
                    if (len(kwfv1_values) != 1
                            or actual_lengths[0] not in expected_lengths):
                        raise RuntimeError(
                            f"当前本人 profile 合同 {contract_site} 的 Cookie kwfv1 必须"
                            f"唯一且长度属于 {sorted(expected_lengths)}，拒绝出网；"
                            f"actual={actual_lengths}")
                # Current self-profile Network contains two scoped kws pairs
                # with different values. Repeating one current value twice
                # merely matches the field names and is still a browser
                # mismatch, so fail before transport. The reqid=416 detail
                # header capture did not preserve a measured kwfv1 length,
                # but it did preserve the two 88/64 security-ticket pairs;
                # enforce those independently of the dynamic kwfv1 branch.
                security_profiles = {
                    "www_graphql_detail_video_success",
                    "www_relogin_profile_self_initial",
                    "www_relogin_profile_self_restricted",
                    "www_relogin_profile_self_ignore_cache",
                    "www_relogin_profile_tabs_ignore_cache",
                    "www_relogin_liked",
                    "www_relogin_collect",
                    "www_relogin_private",
                    "www_graphql_comment_initial",
                    "www_graphql_subcomment_initial",
                }
                if contract_site in security_profiles:
                    kwfv1_values = values.get("kwfv1", []) if expected else []
                    if (len(kwfv1_values) != 1 or not kwfv1_values[0]):
                        raise RuntimeError(
                            f"当前本人 profile 合同 {contract_site} 的 Cookie kwfv1 必须"
                            "唯一且非空，拒绝出网；"
                            f"actual={len(kwfv1_values)}")
                    sec_values = values.get("kwssectoken", [])
                    code_values = values.get("kwscode", [])
                    sec_lengths = [len(value) for value in sec_values]
                    code_lengths = [len(value) for value in code_values]
                    if (len(sec_values) != 2 or len(set(sec_values)) != 2
                            or sec_lengths != [88, 88]
                            or len(code_values) != 2 or len(set(code_values)) != 2
                            or code_lengths != [64, 64]):
                        raise RuntimeError(
                            f"当前本人 profile 合同 {contract_site} 必须携带两组真实且"
                            "值不同的 88 字符 kwssectoken/64 字符 kwscode；"
                            f"拒绝出网；sec_lengths={sec_lengths}, "
                            f"code_lengths={code_lengths}")
                    # reqid=416 lacks a complete header value capture, so do
                    # not infer a kww/kwfv1 equality relation for this profile.
                    # Other relogin profiles retain measured relationship
                    # checks.
                    if contract_site != "www_graphql_detail_video_success":
                        expect_kww_equal = (
                            contract_site == "www_relogin_profile_self_initial")
                        actual_kww_equal = (
                            headers.headers.get("kww", "") == kwfv1_values[0])
                        if actual_kww_equal != expect_kww_equal:
                            raise RuntimeError(
                                f"当前本人 profile 合同 {contract_site} 的 kww/kwfv1 "
                                f"相等关系必须为 {expect_kww_equal}；"
                                f"actual={actual_kww_equal}，拒绝出网")
            # 不得在 Cookie 轮换后重读并覆盖 kww。Chrome 当前 profile 页会
            # 继续发送页面初始化时冻结的 kww，同时 Cookie kwfv1 已更新。
        return headers

    @staticmethod
    def _post(auth, api: str, body: dict = None, referer: str = None,
              force_sign: bool = False, extra_headers: dict = None,
              cookie_profile: str = None) -> dict:
        """通用 POST（JSON body），自动注入 kww 头 + 命中白名单时注入 __NS_hxfalcon。

        :param auth: KuaishouAuth。
        :param api: pathname，如 /rest/v/feed/hot。
        :param body: JSON 请求体（None 表示空 body）。
        :param referer: Referer，默认 new-reco。
        :param force_sign: 强制签名（忽略白名单）。
        :return: 响应 JSON。
        """
        if (getattr(auth, "_www_cookie_phase", "") == "relogin"
                and api not in _CURRENT_RELOGIN_REST_POST_PATHS):
            raise UnverifiedBrowserContractError(
                f"POST {api} 没有当前重新登录 Chrome Network 成功合同，拒绝出网")
        _assert_exact_keys("REST body", api, body, _REST_BODY_KEY_CONTRACTS)
        effective_referer = referer or KuaishouAPI.reco_referer
        headers = HeaderBuilder().build(HeaderType.POST)
        headers.set_referer(effective_referer)
        headers.set_origin(KuaishouAPI.kuaishou_url)
        headers.with_kww(auth)
        for key, value in (extra_headers or {}).items():
            headers.set_header(str(key).lower(), str(value))
        if body is None:
            # 空 body 的 POST 浏览器不发 content-type（实抓 feed/hot：
            # content-length: 0 且无 content-type）。
            headers.remove_header("content-type")
        params = Params()
        params.with_hxfalcon(api, method="POST", body=body, force=force_sign)
        # 编成 bytes 再发：传 str 时 requests 用字符数当 Content-Length，
        # 含中文的 body 会因长度报小而被服务端挂住（live 侧实测踩过）。
        data = (json.dumps(body, ensure_ascii=False, separators=(',', ':')).encode("utf-8")
                if body is not None else None)
        profile = cookie_profile or KuaishouAPI._cookie_profile(
            auth, api, effective_referer)
        KuaishouAPI._wire_headers(auth, headers, site=profile)
        resp = requests.post(_url(KuaishouAPI.kuaishou_url, api, params), headers=headers.get(),
                            data=data, verify=False)
        result = _safe_json(resp)
        # 撞上滑块风控（400002）就过一次验证码再重发。_solved 标记防止无限递归。
        if not force_sign and _is_risk(result):
            if KuaishouAPI._pass_captcha(auth, result, effective_referer):
                # Captcha verification may rotate the short-lived quartet;
                # reserialize the exact selected profile before retrying.
                KuaishouAPI._wire_headers(auth, headers, site=profile)
                resp = requests.post(_url(KuaishouAPI.kuaishou_url, api, params),
                                     headers=headers.get(), data=data, verify=False)
                result = _safe_json(resp)
        # 当前个人页首屏以 profile/feed 收尾；随后点击点赞/收藏/私密时，
        # Network 的 www quartet 已进入 refreshed Cookie 线序。
        if api == "/rest/v/profile/feed" and getattr(auth, "_www_cookie_phase", "") != "relogin":
            advance = getattr(auth, "advance_www_cookie_phase", None)
            if callable(advance):
                advance("refreshed")
        return result

    @staticmethod
    def _pass_captcha(auth, risk_response: dict, referer: str = None) -> bool:
        """撞上 400002 时过一次滑块验证码。

        整条链见 :mod:`utils.captcha`：config → 下图 → 找缺口 → 造轨迹
        → gdfp manMachine 预检 → ``$encrypt`` → ``kSecretApiVerify``。

        :param auth: KuaishouAuth（要 did 与 cookie）。
        :param risk_response: 带 ``data.url`` 的那个 400002 响应。
        :param referer: 触发风控的业务页，作 iframe 的父页 url。
        :return: 过了返回 True；没过/异常返回 False（调用方按原样返回风控响应）。
        """
        try:
            from utils.captcha import (SlidingCaptcha, extract_captcha_url,
                                       extract_session)
        except Exception as exc:                               # noqa: BLE001
            logger.warning(f"[captcha] 模块不可用，跳过自动过验证码：{exc}")
            return False
        session = extract_session(risk_response)
        if not session:
            return False
        logger.info("[captcha] 命中滑块风控，开始自动验证…")
        try:
            # The iframe's complete URL is the real Referer.  Its query
            # carries type/configUrl/bizName/displayType and is part of the
            # anti-abuse correlation; rebuilding a shortened URL changes the
            # browser wire contract.  Config/verify XHRs also carry the page
            # kww, while image subresources deliberately do not.
            iframe_url = extract_captcha_url(risk_response)
            captcha_context = auth.prepare_captcha_context(iframe_url)
            solver = SlidingCaptcha(
                session,
                cookies=captcha_context["cookies"],
                did=auth.did,
                referer=iframe_url,
                kww=captcha_context["kww"],
                cookie_header=captcha_context["cookie_header"],
                parent_url=referer or KuaishouAPI.reco_referer,
                script_urls=captcha_context.get("script_urls"),
                fingerprint=(getattr(auth, "captcha_fingerprint", None)
                             or captcha_context.get("fingerprint")),
            )
            result = solver.solve()
        except Exception as exc:                               # noqa: BLE001
            logger.warning(f"[captcha] 验证异常：{exc}")
            return False
        ok = (result or {}).get("result") == 1
        logger.info(f"[captcha] 验证{'通过' if ok else '失败'}：{str(result)[:120]}")
        return ok

    @staticmethod
    def _get(auth, api: str, query: dict = None, referer: str = None, force_sign: bool = False,
             cookie_profile: str = None) -> dict:
        """通用 GET，自动注入 kww 头 + 命中白名单时注入 __NS_hxfalcon。"""
        if api != "/rest/v/profile/get":
            raise UnverifiedBrowserContractError(
                f"GET {api} 没有当前 Chrome Network 成功合同，拒绝出网")
        if api == "/rest/v/profile/get" and query:
            raise ValueError("profile/get 当前 Chrome query 只有签名器生成的 __NS_hxfalcon,caver")
        effective_referer = referer or KuaishouAPI.reco_referer
        headers = HeaderBuilder().build(HeaderType.GET)
        headers.set_referer(effective_referer)
        headers.with_kww(auth)
        params = Params()
        if query:
            params.update_params(query)
        params.with_hxfalcon(api, method="GET", body=None, force=force_sign)
        profile = cookie_profile or KuaishouAPI._cookie_profile(
            auth, api, effective_referer)
        KuaishouAPI._wire_headers(auth, headers, site=profile)
        resp = requests.get(_url(KuaishouAPI.kuaishou_url, api, params), headers=headers.get(),
                           verify=False)
        result = _safe_json(resp)
        # 与 _post 同：撞上滑块风控就过一次验证码再重发
        if not force_sign and _is_risk(result):
            if KuaishouAPI._pass_captcha(auth, result, effective_referer):
                KuaishouAPI._wire_headers(auth, headers, site=profile)
                resp = requests.get(_url(KuaishouAPI.kuaishou_url, api, params),
                                    headers=headers.get(), verify=False)
                result = _safe_json(resp)
        return result

    # ------------------------------------------------------------------ #
    # 推荐流 / 作品                                                         #
    # ------------------------------------------------------------------ #
    @staticmethod
    def get_feed_hot(auth, pcursor: str = "", **kwargs) -> dict:
        """获取推荐流（精彩推荐）。

        :param auth: KuaishouAuth。
        :param pcursor: 翻页游标（首页传空串）。
        :return: JSON ``{result, pcursor, feeds:[{photo, author}]}``。
        签名：白名单内（sig4），服务端实测宽松，多数情况 cookie 直连即可。
        """
        api = "/rest/v/feed/hot"
        # Current Chrome new-reco has two byte-distinct branches:
        # first page is a true 0-byte POST; every observed continuation sends
        # the literal two bytes ``{}`` and still receives ``pcursor="1"``.
        # It never sends a ``pcursor`` field in the body.
        cursor = str(pcursor or "")
        if cursor not in {"", "1"}:
            raise UnverifiedBrowserContractError(
                f"feed/hot 只抓到首屏空 body 与翻页 pcursor='1' 的 {{}} body，"
                f"拒绝未验证 pcursor={cursor!r}")
        body = None if not cursor else {}
        profile = ("www_relogin_reco_page" if cursor and
                   getattr(auth, "_www_cookie_phase", "") == "relogin" else None)
        return KuaishouAPI._post(auth, api, body, cookie_profile=profile)

    @staticmethod
    def get_some_feed_hot(auth, num: int = 20, **kwargs) -> list:
        """翻页拉取指定数量推荐流作品。

        :param auth: KuaishouAuth。
        :param num: 期望数量。
        :return: feed 列表（含 photo/author）。
        """
        pcursor = ""
        feed_list = []
        while True:
            res_json = KuaishouAPI.get_feed_hot(auth, pcursor)
            feeds = res_json.get("feeds", []) or []
            feed_list.extend(feeds)
            pcursor = str(res_json.get("pcursor", "no_more"))
            if not feeds or pcursor in ("no_more", "-1", "") or len(feed_list) >= num:
                break
        return feed_list[:num]

    @staticmethod
    def get_work_info(auth, work_url_or_id: str, **kwargs) -> dict:
        """兼容入口；委托到已按当前 Network 对齐的目标详情请求。"""
        return KuaishouAPI.get_video_detail(auth, work_url_or_id, **kwargs)

    @staticmethod
    def get_video_detail(auth, work_url_or_id: str, **kwargs) -> dict:
        """获取目标作品详情并严格校验浏览器响应合同。

        ``visionShortVideoReco`` 是详情页旁路推荐流，不能作为目标作品
        详情的替代。真实浏览器成功响应必须同时包含目标 ``photoId``、
        ``status=1`` 及 query 请求的完整顶层/照片字段；任何 GraphQL
        错误、空节点或错作品响应都会在返回业务层前 fail-closed。
        """
        photo_id = _extract_photo_id(work_url_or_id)
        referer = kwargs.pop("referer", None)
        if kwargs:
            unknown = ", ".join(sorted(kwargs))
            raise TypeError(f"get_video_detail 不接受未验证参数: {unknown}")
        data = KuaishouAPI.graphql(
            auth, "visionVideoDetail", {"photoId": photo_id, "page": "detail"},
            GQL_VIDEO_DETAIL,
            referer=referer or f"{KuaishouAPI.kuaishou_url}/short-video/{photo_id}",
            cookie_site="www_graphql_detail")
        detail = ((data.get("data") or {}).get("visionVideoDetail")
                  if isinstance(data, dict) else None)
        if not isinstance(detail, dict):
            errors = data.get("errors") if isinstance(data, dict) else None
            raise UnverifiedBrowserContractError(
                "visionVideoDetail 响应缺少 data.visionVideoDetail"
                + (f": {errors!r}" if errors else ""))
        if detail.get("status") != 1:
            raise UnverifiedBrowserContractError(
                f"visionVideoDetail 返回未成功 status={detail.get('status')!r}")
        photo = detail.get("photo")
        if not isinstance(photo, dict) or str(photo.get("id")) != str(photo_id):
            got = photo.get("id") if isinstance(photo, dict) else None
            raise UnverifiedBrowserContractError(
                f"visionVideoDetail photo.id 与目标不一致: {got!r} != {photo_id!r}")
        required_detail = {
            "type", "author", "photo", "authorStatement", "tags",
            "commentLimit", "llsid", "danmakuSwitch",
        }
        missing_detail = sorted(required_detail.difference(detail))
        if missing_detail:
            raise UnverifiedBrowserContractError(
                f"visionVideoDetail 顶层字段缺失: {missing_detail!r}")
        required_photo = {
            "id", "duration", "caption", "likeCount", "realLikeCount",
            "coverUrl", "photoUrl", "liked", "timestamp", "expTag", "llsid",
            "viewCount", "videoRatio", "stereoType", "musicBlocked",
            "riskTagContent", "riskTagUrl", "manifest", "manifestH265",
            "photoH265Url", "coronaCropManifest", "coronaCropManifestH265",
            "croppedPhotoH265Url", "croppedPhotoUrl", "videoResource",
        }
        missing_photo = sorted(required_photo.difference(photo))
        if missing_photo:
            raise UnverifiedBrowserContractError(
                f"visionVideoDetail photo 字段缺失: {missing_photo!r}")
        return detail

    @staticmethod
    def get_short_video_reco(auth, work_url_or_id: str, **kwargs) -> dict:
        """获取详情页同时加载的推荐流（不是目标作品详情）。"""
        photo_id = _extract_photo_id(work_url_or_id)
        data = KuaishouAPI.graphql(
            auth, "visionShortVideoReco",
            {"page": "detail", "photoId": photo_id}, GQL_SHORT_VIDEO_RECO,
            referer=f'{KuaishouAPI.kuaishou_url}/short-video/{photo_id}',
            cookie_site="www_graphql_detail")
        return ((data.get("data") or {}).get("visionShortVideoReco") or {})

    @staticmethod
    def graphql(auth, operation_name: str, variables: dict, query: str,
                referer: str = None, cookie_site: str = "www_graphql") -> dict:
        """通用 GraphQL 请求（``POST /graphql``）。

        与浏览器实抓一致（2026-08-16 CDP）：``accept: */*``、
        ``content-type: application/json``、body 是
        ``{"operationName":…, "variables":{…}, "query":"…"}``，**不带签名**。

        :param auth: KuaishouAuth。
        :param operation_name: 如 ``visionShortVideoReco``。
        :param variables: 查询变量。
        :param query: 完整 query 文本（必须与浏览器逐字一致）。
        :param referer: Referer。
        :param cookie_site: Cookie 线序 profile；短视频详情页使用
            ``www_graphql_detail``，myFollow 使用 ``www_graphql``。
        :return: 响应 JSON（``{"data": {...}}``）。
        """
        headers = HeaderBuilder().build(HeaderType.POST, accept=ACCEPT_ANY)
        effective_referer = referer or KuaishouAPI.reco_referer
        headers.set_referer(effective_referer)
        headers.set_origin(KuaishouAPI.kuaishou_url)
        headers.with_kww(auth)
        body = {"operationName": operation_name, "variables": variables, "query": query}
        _assert_exact_keys("GraphQL variables", operation_name, variables,
                           _GRAPHQL_VARIABLE_KEY_CONTRACTS)
        expected_query = _GRAPHQL_QUERY_CONTRACTS.get(operation_name)
        if expected_query is None:
            raise UnverifiedBrowserContractError(
                f"GraphQL {operation_name} 没有当前 Chrome Network 成功合同，拒绝出网")
        if query != expected_query:
            raise ValueError(
                f"GraphQL {operation_name} query 文本与当前 Chrome Network 不一致，拒绝出网")
        data = json.dumps(body, ensure_ascii=False, separators=(',', ':')).encode("utf-8")
        # GraphQL 的 Cookie path/domain 组合与 REST www 请求不同；当前
        # myFollow Network 明确存在重复 kwpsecproductname，且 kpn 在末尾。
        # 当前短视频页 GraphQL（包括 loginConfig/checkLogin/userInfo）使用
        # 专用 Cookie 线序。按真实 Referer 选择，不能按 operationName 猜。
        effective_cookie_site = cookie_site
        page_path = urllib.parse.urlsplit(effective_referer).path
        if not (page_path == "/myFollow" or page_path.startswith("/short-video/")):
            raise UnverifiedBrowserContractError(
                "当前 GraphQL 成功合同只覆盖 /myFollow 与 "
                f"/short-video/<photoId>，拒绝 Referer={effective_referer!r} 出网")
        if (cookie_site in {"www_graphql", "www_graphql_detail"}
                and page_path.startswith("/short-video/")):
            detail_initial_ops = {
                ("visionLoginConfig", ("key",)),
                ("checkLoginQuery", ()),
                ("visionShortVideoReco", ("page", "photoId")),
                ("commentListQuery", ("photoId", "pcursor")),
                ("visionBaseEmoticons", ()),
                ("userInfoQuery", ()),
            }
            detail_bootstrap_ops = {
                ("visionLoginConfig", ("key",)),
                ("checkLoginQuery", ()),
                ("visionShortVideoReco", ("page", "photoId")),
                ("commentListQuery", ("photoId", "pcursor")),
                ("visionBaseEmoticons", ()),
            }
            detail_refreshed_ops = {
                ("visionConfigQuery", ()),
            }
            request_shape = (operation_name, tuple(variables.keys()))
            if request_shape == ("visionVideoDetail", ("photoId", "page")):
                # The target detail request is emitted after the page-local
                # webweapon rotation. Its Cookie line differs from the
                # bootstrap/recommendation calls (kpn before both scoped
                # ticket pairs, kwfv1 last).
                effective_cookie_site = "www_graphql_detail_video_success"
            elif (operation_name == "commentListQuery"
                    and getattr(auth, "_wire_cookie_history", None)):
                # Real comment pagination (reqids 14832--14858) uses a
                # separate Cookie order from the detail bootstrap calls.
                effective_cookie_site = "www_graphql_comment_initial"
            elif request_shape in detail_bootstrap_ops:
                # Fresh direct-navigation bootstrap phase (reqids 365--369)
                # has no account-scoped Cookie fields and places kpn last.
                effective_cookie_site = "www_graphql_detail_bootstrap"
            elif operation_name == "visionSubCommentList":
                effective_cookie_site = "www_graphql_subcomment_initial"
            elif request_shape in detail_initial_ops:
                effective_cookie_site = "www_graphql_detail_initial"
            elif request_shape in detail_refreshed_ops:
                effective_cookie_site = "www_graphql_detail_refreshed"
            else:
                raise UnverifiedBrowserContractError(
                    "当前短视频详情页没有该 GraphQL operation/variables 的成功 "
                    f"Network 证据，拒绝出网: {request_shape!r}")
        elif (cookie_site == "www_graphql"
              and getattr(auth, "_www_cookie_phase", "") == "relogin"):
            if page_path != "/myFollow":
                raise UnverifiedBrowserContractError(
                    "当前重新登录 GraphQL 成功合同只覆盖 /myFollow 与 "
                    f"/short-video/<photoId>，拒绝 Referer={effective_referer!r} 出网")
            # Current post-CP/live myFollow Network has two concrete Cookie
            # phases. Route only the exact operation/variables combinations
            # that succeeded in Chrome; do not infer a generic phase.
            initial_ops = {
                ("visionLoginConfig", ("key",)),
                ("checkLoginQuery", ()),
                ("likeDataQuery", ("token", "st", "page")),
                ("visionOttConfig", ("key",)),
                ("visionProfileReduced", ()),
                ("visionProfilePhotoList", ("pcursor", "page", "profile_referer")),
            }
            refreshed_ops = {
                ("userInfoQuery", ()),
                ("visionProfileReduced", ("userId",)),
                ("visionConfigQuery", ()),
            }
            request_shape = (operation_name, tuple(variables.keys()))
            if request_shape in initial_ops:
                effective_cookie_site = "www_graphql_relogin_initial"
            elif request_shape in refreshed_ops:
                effective_cookie_site = "www_graphql_relogin_refreshed"
            else:
                raise UnverifiedBrowserContractError(
                    "当前重新登录 myFollow 没有该 GraphQL operation/variables 的成功 "
                    f"Network 证据，拒绝出网: {request_shape!r}")
        elif page_path == "/myFollow" and cookie_site != "www_graphql":
            raise UnverifiedBrowserContractError(
                f"/myFollow 未抓到 Cookie profile={cookie_site!r} 的成功合同，拒绝出网")
        KuaishouAPI._wire_headers(auth, headers, site=effective_cookie_site)
        resp = requests.post(f'{KuaishouAPI.kuaishou_url}/graphql', headers=headers.get(),
                             data=data, verify=False)
        result = _safe_json(resp)
        # GraphQL 侧同样会撞风控（评论走的就是它），一并接上自动过验证码
        if _is_risk(result):
            risk = _graphql_risk_as_rest(result)
            if risk and KuaishouAPI._pass_captcha(auth, risk, effective_referer):
                # 滑块通过后浏览器会下发/轮换短期 cookie；重发前必须重新
                # 序列化同一个详情页 Cookie profile，不能沿用挑战前的 header。
                KuaishouAPI._wire_headers(auth, headers, site=effective_cookie_site)
                resp = requests.post(f'{KuaishouAPI.kuaishou_url}/graphql',
                                     headers=headers.get(), data=data, verify=False)
                result = _safe_json(resp)
        return result

    @staticmethod
    def get_base_emoticons(auth, referer: str = None) -> dict:
        """获取短视频评论面板使用的表情映射。

        当前详情页 reqid=2413 的完整请求为 ``visionBaseEmoticons``，变量为空
        对象，响应成功时节点为 ``iconUrls``。该请求同样使用详情页 GraphQL
        Cookie 线序；不把返回 URL 映射自行删减。
        """
        if not referer:
            raise ValueError(
                "visionBaseEmoticons 必须传当前短视频详情页 Referer；"
                "不能用 new-reco 等页面地址揣测替代")
        data = KuaishouAPI.graphql(
            auth, "visionBaseEmoticons", {}, GQL_BASE_EMOTICONS,
            referer=referer,
            cookie_site="www_graphql_detail")
        return ((data.get("data") or {}).get("visionBaseEmoticons") or {})

    @staticmethod
    def vision_login_config(auth, referer: str = None) -> dict:
        """当前 myFollow 首屏的 ``visionLoginConfig`` GraphQL 请求。"""
        data = KuaishouAPI.graphql(
            auth, "visionLoginConfig",
            {"key": "frontendExplore.vision.loginConfig"},
            GQL_VISION_LOGIN_CONFIG,
            referer=referer or "https://www.kuaishou.com/myFollow",
        )
        return (data.get("data") or {}).get("kconf") or {}

    @staticmethod
    def check_login(auth, referer: str = None) -> bool:
        """当前 myFollow 首屏的 ``checkLoginQuery``。"""
        data = KuaishouAPI.graphql(
            auth, "checkLoginQuery", {}, GQL_CHECK_LOGIN,
            referer=referer or "https://www.kuaishou.com/myFollow",
        )
        return bool((data.get("data") or {}).get("checkLogin"))

    @staticmethod
    def vision_ott_config(auth, referer: str = None) -> dict:
        """当前 myFollow 首屏的 ``visionOttConfig`` GraphQL 请求。"""
        data = KuaishouAPI.graphql(
            auth, "visionOttConfig",
            {"key": "frontendExplore.vision.ottConfig"},
            GQL_VISION_OTT_CONFIG,
            referer=referer or "https://www.kuaishou.com/myFollow",
        )
        return (data.get("data") or {}).get("kconf") or {}

    @staticmethod
    def like_data(auth, page: str = "follow", st: int = None,
                  token: str = None, pcursor: str = None,
                  web_page_area: str = None, referer: str = None) -> dict:
        """获取关注页 ``likeDataQuery``，按当前 bundle 生成 token。

        当前 Network 首次请求的 variables 顺序是 ``token, st, page``，并且
        ``pcursor`` / ``webPageArea`` 在值为 ``undefined`` 时被 JSON.stringify
        省略；因此默认不主动补这两个键。不要把空串当成“等价字段”。
        """
        if pcursor is not None or web_page_area is not None:
            raise UnverifiedBrowserContractError(
                "当前 Chrome 只抓到 likeDataQuery 首屏 variables=token,st,page；"
                "翻页 pcursor/webPageArea 尚无本轮 Network 证据，禁止猜测发包")
        if st is None:
            st = int(time.time() * 1000)
        if token is None:
            from utils.sign.like_token import generate_like_token
            token = generate_like_token(
                getattr(auth, "did", ""), st, "/rest/v/feed/myfollow")
        variables = {"token": str(token), "st": int(st), "page": str(page)}
        data = KuaishouAPI.graphql(
            auth, "likeDataQuery", variables, GQL_LIKE_DATA,
            referer=referer or "https://www.kuaishou.com/myFollow",
        )
        return ((data.get("data") or {}).get("likeData") or {})

    @staticmethod
    def vision_profile_reduced(auth, user_id: str = None,
                               referer: str = None) -> dict:
        """当前关注页的 ``visionProfileReduced``，保留空 variables 请求。"""
        variables = {} if user_id is None else {"userId": str(user_id)}
        data = KuaishouAPI.graphql(
            auth, "visionProfileReduced", variables, GQL_VISION_PROFILE_REDUCED,
            referer=referer or "https://www.kuaishou.com/myFollow",
        )
        return ((data.get("data") or {}).get("visionProfileReduced") or {})

    @staticmethod
    def vision_profile_photo_list(auth, pcursor: str = "", page: str = "follow",
                                  profile_referer: str = "", user_id: str = None,
                                  web_page_area: str = None,
                                  referer: str = None) -> dict:
        """当前关注页的 ``visionProfilePhotoList``。

        reqid=786 的真实 variables 顺序为 ``pcursor,page,profile_referer``；
        未提供的可选变量保持省略，不能为方便统一补 ``null``/空串。
        """
        if user_id is not None or web_page_area is not None:
            raise UnverifiedBrowserContractError(
                "当前 Chrome 只抓到 visionProfilePhotoList 首屏 "
                "pcursor,page,profile_referer；userId/webPageArea 组合尚未验证")
        variables = {"pcursor": str(pcursor), "page": str(page),
                     "profile_referer": str(profile_referer)}
        data = KuaishouAPI.graphql(
            auth, "visionProfilePhotoList", variables, GQL_PROFILE_PHOTO_LIST,
            referer=referer or "https://www.kuaishou.com/myFollow",
        )
        return ((data.get("data") or {}).get("visionProfilePhotoList") or {})

    @staticmethod
    def vision_config(auth, referer: str = None) -> dict:
        """当前关注页的完整 ``visionConfigQuery``。"""
        data = KuaishouAPI.graphql(
            auth, "visionConfigQuery", {}, GQL_VISION_CONFIG,
            referer=referer or "https://www.kuaishou.com/myFollow",
        )
        return (data.get("data") or {}).get("visionConfig") or {}

    @staticmethod
    def get_user_info(auth, referer: str = None) -> dict:
        """当前关注页的 ``userInfoQuery``（登录用户轻量信息）。"""
        data = KuaishouAPI.graphql(
            auth, "userInfoQuery", {}, GQL_USER_INFO,
            referer=referer or "https://www.kuaishou.com/myFollow",
        )
        return (data.get("data") or {}).get("userInfo") or {}

    # ------------------------------------------------------------------ #
    # 评论                                                                 #
    # ------------------------------------------------------------------ #
    @staticmethod
    def get_comment_list(auth, photo_id: str, pcursor: str = "", **kwargs) -> dict:
        """获取作品一级评论。

        :param auth: KuaishouAuth。
        :param photo_id: 作品 photoId。
        :param pcursor: 翻页游标（首页空串）。
        :return: JSON ``{result, pcursorV2, commentCountV2, rootCommentsV2:[...]}``。
        签名：不在白名单，cookie 直连即可。
        """
        api = "/rest/v/photo/comment/list"
        photo = str(photo_id)
        cursor = str(pcursor or "")
        body = {"photoId": photo, "pcursor": cursor}
        profile = None
        if getattr(auth, "_www_cookie_phase", "") == "relogin":
            profile = _CURRENT_RECO_COMMENT_PROFILES.get((photo, cursor))
            if profile is None:
                raise UnverifiedBrowserContractError(
                    f"当前 new-reco 未抓到 photoId={photo!r}, pcursor={cursor!r} "
                    "对应的精确 Cookie 阶段，拒绝出网")
        return KuaishouAPI._post(auth, api, body, cookie_profile=profile)

    @staticmethod
    def get_all_comment(auth, photo_id: str, num: int = 100, **kwargs) -> list:
        """翻页拉取作品一级评论。

        :param auth: KuaishouAuth。
        :param photo_id: 作品 photoId。
        :param num: 期望数量。
        :return: 一级评论列表。
        """
        pcursor = ""
        comment_list = []
        while True:
            res_json = KuaishouAPI.get_comment_list(auth, photo_id, pcursor)
            comments = res_json.get("rootCommentsV2", []) or res_json.get("rootComments", []) or []
            comment_list.extend(comments)
            pcursor = str(res_json.get("pcursorV2", res_json.get("pcursor", "no_more")))
            if not comments or pcursor in ("no_more", "-1", "") or len(comment_list) >= num:
                break
        return comment_list[:num]

    @staticmethod
    def get_comment_list_gql(auth, photo_id: str, pcursor: str = "", **kwargs) -> dict:
        """获取作品评论（**GraphQL 版，与浏览器一致**）。

        作品详情页用的是这个，不是 REST 的 ``/rest/v/photo/comment/list``
        （2026-08-16 CDP 实抓确认）。两个好处：

        1. 二级评论**直接内嵌**在 ``rootComments[].subComments`` 里，
           不用再单独打 ``comment/sublist``（浏览器压根不发那个请求）；
        2. 字段更全（``subCommentCount`` / ``replyToUserName`` / ``authorLiked``）。

        :param auth: KuaishouAuth。
        :param photo_id: 作品 photoId。
        :param pcursor: 翻页游标。
        :return: ``visionCommentList`` 节点。**实际数据在 V2 字段里**：
            ``{commentCountV2, pcursorV2, rootCommentsV2:[…]}``；
            老字段 ``commentCount`` / ``pcursor`` / ``rootComments`` 实测恒为
            null/空数组，服务端已经切到 V2 了，取值要认 V2。
        """
        data = KuaishouAPI.graphql(
            auth, "commentListQuery",
            {"photoId": str(photo_id), "pcursor": pcursor}, GQL_COMMENT_LIST,
            referer=f'{KuaishouAPI.kuaishou_url}/short-video/{photo_id}',
            cookie_site="www_graphql_detail")
        return ((data.get("data") or {}).get("visionCommentList") or {})

    @staticmethod
    def get_all_comment_gql(auth, photo_id: str, num: int = 100, **kwargs) -> list:
        """翻页拉取 GraphQL 版评论（认 V2 字段）。

        :param auth: KuaishouAuth。
        :param photo_id: 作品 photoId。
        :param num: 期望数量。
        :return: 一级评论列表（``hasSubComments`` 为 True 的那些，
            二级评论在 REST 版里要单独拉，GraphQL 版的 rootComments 才内嵌）。
        """
        pcursor, out = "", []
        while True:
            node = KuaishouAPI.get_comment_list_gql(auth, photo_id, pcursor)
            batch = node.get("rootCommentsV2") or node.get("rootComments") or []
            out.extend(batch)
            pcursor = str(node.get("pcursorV2") or node.get("pcursor") or "no_more")
            if not batch or pcursor in ("no_more", "-1", "", "None") or len(out) >= num:
                break
        return out[:num]

    @staticmethod
    def get_sub_comment_list(auth, photo_id: str, root_comment_id: str, pcursor: str = "", **kwargs) -> dict:
        """获取点击“查看更多回复”触发的 GraphQL 二级评论。

        当前成功 Network 只有 reqid 26926 这一组 photo/root/cursor。旧 REST
        ``/rest/v/photo/comment/sublist`` 仍没有当前证据，绝不恢复。
        """
        current = ("3xgv6ute4cr9szw", "1139746042562", "")
        actual = (str(photo_id), str(root_comment_id), str(pcursor or ""))
        if actual != current:
            raise UnverifiedBrowserContractError(
                "当前 Chrome 只成功抓到 visionSubCommentList "
                f"photo/root/cursor={current!r}；actual={actual!r} 未验证，拒绝出网")
        data = KuaishouAPI.graphql(
            auth, "visionSubCommentList",
            {"photoId": actual[0], "rootCommentId": actual[1], "pcursor": actual[2]},
            GQL_SUB_COMMENT_LIST,
            referer=f'{KuaishouAPI.kuaishou_url}/short-video/{actual[0]}',
            cookie_site="www_graphql_detail")
        return ((data.get("data") or {}).get("visionSubCommentList") or {})

    # ------------------------------------------------------------------ #
    # 我的资料 / 用户作品                                                    #
    # ------------------------------------------------------------------ #
    @staticmethod
    def get_profile(auth, referer: str = None, profile_id: str = "", **kwargs) -> dict:
        """获取当前登录用户资料（🔒 需 __NS_hxfalcon）。

        :param auth: KuaishouAuth。
        :param referer: 发起请求的真实页面地址；不传时按浏览器首页 ``/new-reco``。
        :param profile_id: 个人页场景的 eid。仅在未显式传 ``referer`` 时使用，
            生成 ``https://www.kuaishou.com/profile/<eid>``。
        :return: JSON ``{result, userId, userName, userDefineId, userHead, sex, fans, follows, ...}``。
        """
        api = "/rest/v/profile/get"
        page_referer = referer
        if not page_referer and profile_id:
            page_referer = f"{KuaishouAPI.kuaishou_url}/profile/{profile_id}"
        result = KuaishouAPI._get(auth, api, referer=page_referer)
        eid = str((result or {}).get("eid") or (result or {}).get("userDefineId") or "")
        if eid:
            auth._self_eid_cache = eid
        return result

    @staticmethod
    def get_profile_feed(auth, user_id: str, pcursor: str = "", **kwargs) -> dict:
        """获取指定用户作品列表（🔒 需 __NS_hxfalcon）。

        body 字段与浏览器实抓完全一致（2026-08-16 CDP）::

            {"user_id":"<eid>","pcursor":"","page":"profile"}

        两处之前是错的：键名是 **user_id（下划线）不是 userId**，
        而且浏览器**不发 count**。键名错了服务端当没传，等于拿不到指定用户。

        另外这个接口的请求头会多一个空的 ``profile_referer``（实抓可见）。

        :param auth: KuaishouAuth。
        :param user_id: 目标用户 ID（eid）。
        :param pcursor: 翻页游标。
        :return: JSON ``{result, pcursor, feeds:[...]}``。
        """
        api = "/rest/v/profile/feed"
        body = {"user_id": str(user_id), "pcursor": pcursor, "page": "profile"}
        referer = f'https://www.kuaishou.com/profile/{user_id}'
        profile = None
        if getattr(auth, "_www_cookie_phase", "") == "relogin":
            self_eid = str(getattr(auth, "_self_eid_cache", "") or "")
            if not self_eid:
                raise UnverifiedBrowserContractError(
                    "profile/feed 必须先通过当前 /new-reco profile/get 缓存本人 eid，"
                    "否则无法判断本人页/他人页 Cookie 合同")
            if str(user_id) != self_eid:
                if str(user_id) != _CURRENT_OTHER_PROFILE_EID:
                    raise UnverifiedBrowserContractError(
                        f"当前重新登录 Chrome 只成功抓到他人 profile/feed "
                        f"{_CURRENT_OTHER_PROFILE_EID}；target={user_id!r} 未验证")
                profile = _CURRENT_OTHER_PROFILE_CURSOR_PROFILES.get(str(pcursor))
                if profile is None:
                    raise UnverifiedBrowserContractError(
                        f"他人 profile/feed cursor={pcursor!r} 没有当前成功 "
                        "Chrome Network/Cookie 阶段，拒绝出网")
            elif pcursor:
                raise UnverifiedBrowserContractError(
                    "当前本人 profile/feed 响应 pcursor=no_more，未抓到非空 pcursor 分支")
        result = KuaishouAPI._post(
            auth, api, body, referer=referer,
            extra_headers={"profile_referer": ""}, cookie_profile=profile)
        # Chrome reqid 472 returned this exact result after the account was
        # restricted.  Preserve the server-observed state so later requests
        # select the independent post-restriction Cookie contract.
        if str(user_id) == str(getattr(auth, "_self_eid_cache", "") or "") \
                and (result or {}).get("result") == 208007:
            marker = getattr(auth, "mark_account_restricted", None)
            if callable(marker):
                marker(True)
        return result

    @staticmethod
    def get_user_all_work(auth, user_id: str, num: int = 100, **kwargs) -> list:
        """翻页拉取指定用户的全部/前 num 个作品（🔒）。

        :param auth: KuaishouAuth。
        :param user_id: 目标用户 ID。
        :param num: 期望数量。
        :return: feed 列表。
        """
        pcursor = ""
        feed_list = []
        while True:
            res_json = KuaishouAPI.get_profile_feed(auth, user_id, pcursor)
            feeds = res_json.get("feeds", []) or []
            feed_list.extend(feeds)
            pcursor = str(res_json.get("pcursor", "no_more"))
            if not feeds or pcursor in ("no_more", "-1", "") or len(feed_list) >= num:
                break
        return feed_list[:num]

    @staticmethod
    def get_profile_user_v2(auth, user_id: str, **kwargs) -> dict:
        """获取指定用户资料 v2（🔒 需 __NS_hxfalcon）。

        .. warning::
           **该端点已下线**：2026-08-16 实测服务端返回 HTTP 404
           ``{"error":"Not Found","path":"/rest/v/profile/user/v2"}``。
           端点名来自主包白名单常量，但线上已不存在。要拿他人资料改用
           :meth:`get_profile_feed`（作品列表里带作者信息）。

        :param auth: KuaishouAuth。
        :param user_id: 目标用户 ID。
        :return: JSON。
        """
        raise UnverifiedBrowserContractError(
            "当前 Chrome 没有 /rest/v/profile/user/v2 成功请求；旧证据只有 HTTP 404，已禁止发包")

    # ------------------------------------------------------------------ #
    # 搜索                                                                 #
    # ------------------------------------------------------------------ #
    @staticmethod
    def search_feed(auth, keyword: str, pcursor: str = "", web_page_area: str = "",
                    search_session_id: str = "", **kwargs) -> dict:
        """搜索作品（🔒 需 __NS_hxfalcon）。

        body 字段与浏览器实抓完全一致（2026-08-16 CDP）::

            {"keyword":"美食","page":"search","webPageArea":"","pcursor":""}

        ``page`` / ``webPageArea`` 之前漏了 —— 少字段服务端首次会放行，
        多打几次就会进风控画像，必须补齐。

        :param auth: KuaishouAuth。
        :param keyword: 搜索关键字。
        :param pcursor: 翻页游标。
        :param web_page_area: 翻页时回传上一页响应里的 ``webPageArea``；首页传空串。
        :return: JSON。
        """
        api = "/rest/v/search/feed"
        cursor = str(pcursor or "")
        if (getattr(auth, "_www_cookie_phase", "") == "relogin"
                and cursor not in {"", "1", "2", "3", "4", "5", "6", "7"}):
            raise UnverifiedBrowserContractError(
                f"当前 search/feed 只重抓到 pcursor 1..7；拒绝未验证 {cursor!r}")
        if cursor:
            if web_page_area:
                raise UnverifiedBrowserContractError(
                    "当前 search/feed 翻页 body 不发送 page/webPageArea，禁止混入首屏字段")
            if not search_session_id:
                raise UnverifiedBrowserContractError(
                    "当前 search/feed 翻页必须原样回传首屏 searchSessionId")
            body = {"keyword": keyword, "pcursor": cursor,
                    "searchSessionId": str(search_session_id)}
        else:
            if search_session_id:
                raise UnverifiedBrowserContractError(
                    "当前 search/feed 首屏不发送 searchSessionId")
            if web_page_area:
                raise UnverifiedBrowserContractError(
                    "当前 search/feed 首屏只抓到 webPageArea 空串；拒绝未验证非空值")
            body = {"keyword": keyword, "page": "search",
                    "webPageArea": "", "pcursor": ""}
        # referer 要 url 编码：HTTP 头只能是 latin-1，关键字里有中文会直接抛
        # UnicodeEncodeError（浏览器也是编码后再发的）。与 search_user 同理。
        referer = ('https://www.kuaishou.com/search/video?searchKey='
                   + urllib.parse.quote(keyword, safe=''))
        profile = None
        if cursor and getattr(auth, "_www_cookie_phase", "") == "relogin":
            profile = "www_relogin_search_feed_page"
        return KuaishouAPI._post(
            auth, api, body, referer=referer, cookie_profile=profile)

    @staticmethod
    def search_some_feed(auth, keyword: str, num: int = 20, **kwargs) -> list:
        """翻页搜索指定数量作品（🔒）。

        :param auth: KuaishouAuth。
        :param keyword: 搜索关键字。
        :param num: 期望数量。
        :return: 搜索结果列表。
        """
        pcursor = ""
        search_session_id = ""
        feed_list = []
        while True:
            res_json = KuaishouAPI.search_feed(
                auth, keyword, pcursor, search_session_id=search_session_id)
            feeds = res_json.get("feeds", []) or res_json.get("list", []) or []
            feed_list.extend(feeds)
            pcursor = str(res_json.get("pcursor", "no_more"))
            search_session_id = str(
                res_json.get("searchSessionId") or search_session_id or "")
            if not feeds or pcursor in ("no_more", "-1", "") or len(feed_list) >= num:
                break
        return feed_list[:num]

    @staticmethod
    def search_user(auth, keyword: str, pcursor: str = "", search_session_id: str = "",
                    **kwargs) -> dict:
        """搜索用户（🔒 需 __NS_hxfalcon）。

        body 字段与浏览器实抓完全一致（2026-08-16 CDP）::

            {"keyword":"美食","pcursor":"","searchSessionId":""}

        ``searchSessionId`` 之前漏了。服务端在响应里回一个
        ``searchSessionId``，翻页时要原样带回去（同一次搜索会话）。

        :param auth: KuaishouAuth。
        :param keyword: 搜索关键字。
        :param pcursor: 翻页游标。
        :param search_session_id: 上一页响应里的 ``searchSessionId``；首页传空串。
        :return: JSON。
        """
        api = "/rest/v/search/user"
        cursor = str(pcursor or "")
        session_id = str(search_session_id or "")
        body = {"keyword": keyword, "pcursor": cursor,
                "searchSessionId": session_id}
        # 本轮 Chrome search/video 首屏同时发 search/feed 与 search/user；
        # search/user 的 Referer 也是 search/video，不是 search/author。
        referer = ('https://www.kuaishou.com/search/video?searchKey='
                   + urllib.parse.quote(keyword, safe=''))
        if cursor and not session_id:
            raise UnverifiedBrowserContractError(
                "当前 search/user 翻页必须原样回传首屏 searchSessionId")
        if not cursor and session_id:
            raise UnverifiedBrowserContractError(
                "当前 search/user 首屏的 searchSessionId 必须为空串")
        if (getattr(auth, "_www_cookie_phase", "") == "relogin"
                and cursor not in {"", "1", "2", "3", "4", "5", "6", "7", "8"}):
            raise UnverifiedBrowserContractError(
                f"当前 search/user 只重抓到首屏与 pcursor 1..8；拒绝 {pcursor!r}")
        profile = None
        if cursor and getattr(auth, "_www_cookie_phase", "") == "relogin":
            profile = ("www_relogin_search_user_page_first"
                       if cursor in {"1", "2", "3"}
                       else "www_relogin_search_user_page_following")
        return KuaishouAPI._post(
            auth, api, body, referer=referer, cookie_profile=profile)

    # ------------------------------------------------------------------ #
    # 关注 / 粉丝                                                          #
    # ------------------------------------------------------------------ #
    @staticmethod
    def get_relation(auth, ftype: int = 1, pcursor: str = "", **kwargs) -> dict:
        """获取关注(1)/粉丝(2)列表。

        :param auth: KuaishouAuth。
        :param ftype: 1 关注, 2 粉丝。
        :param pcursor: 翻页游标。
        :return: JSON ``{result, pcursor, authors:[...]}``。
        签名：不在白名单，cookie 直连即可。
        """
        relation_type = int(ftype)
        cursor = str(pcursor or "")
        if relation_type not in {1, 2}:
            raise UnverifiedBrowserContractError(
                f"当前本人页只成功抓到 relation/fol ftype=1/2；拒绝 {ftype!r}")
        if cursor:
            raise UnverifiedBrowserContractError(
                "当前关注/粉丝响应 pcursor=no_more，Chrome 未发送翻页请求；"
                f"拒绝未验证 pcursor={cursor!r}")
        self_eid = str(getattr(auth, "_self_eid_cache", "") or "")
        if not self_eid:
            raise UnverifiedBrowserContractError(
                "relation/fol 必须先由当前 profile/get 缓存本人 eid，禁止猜 Referer")
        referer = f"{KuaishouAPI.kuaishou_url}/profile/{self_eid}"
        profile = ("www_relogin_relation_following" if relation_type == 1
                   else "www_relogin_relation_fans")
        return KuaishouAPI._post(
            auth, "/rest/v/relation/fol",
            {"pcursor": cursor, "ftype": relation_type},
            referer=referer, cookie_profile=profile)

    @staticmethod
    def get_some_relation(auth, ftype: int = 1, num: int = 100, **kwargs) -> list:
        """翻页拉取关注/粉丝列表。

        :param auth: KuaishouAuth。
        :param ftype: 1 关注, 2 粉丝。
        :param num: 期望数量。
        :return: author 列表。
        """
        pcursor = ""
        author_list = []
        while True:
            res_json = KuaishouAPI.get_relation(auth, ftype, pcursor)
            authors = res_json.get("authors", []) or res_json.get("fols", []) or []
            author_list.extend(authors)
            pcursor = str(res_json.get("pcursor", "no_more"))
            if not authors or pcursor in ("no_more", "-1", "") or len(author_list) >= num:
                break
        return author_list[:num]

    # ------------------------------------------------------------------ #
    # 喜欢 / 收藏 / 私密 / 历史（🔒 多为白名单）                              #
    # ------------------------------------------------------------------ #
    @staticmethod
    def get_liked_list(auth, pcursor: str = "", referer: str = None,
                       profile_id: str = "", **kwargs) -> dict:
        """获取我的喜欢列表（🔒 需 __NS_hxfalcon）。

        :param auth: KuaishouAuth。
        :param pcursor: 翻页游标。
        :return: JSON ``{result, pcursor, feeds:[...]}``。
        """
        api = "/rest/v/feed/liked"
        if pcursor and getattr(auth, "_www_cookie_phase", "") == "relogin":
            raise UnverifiedBrowserContractError(
                "当前本人 liked 响应 pcursor=no_more，未抓到非空 pcursor 分支")
        body = {"pcursor": pcursor, "page": "profile"}
        page_referer = referer
        if not page_referer and profile_id:
            page_referer = f"{KuaishouAPI.kuaishou_url}/profile/{profile_id}"
        return KuaishouAPI._post(auth, api, body, referer=page_referer)

    @staticmethod
    def get_collect_list(auth, user_id: str = "", pcursor: str = "", **kwargs) -> dict:
        """获取收藏列表（🔒 需 __NS_hxfalcon）。

        body 字段与浏览器实抓完全一致（2026-08-16 CDP，个人页点「收藏」标签）::

            {"userId":"<eid>","pcursor":"","page":"collect"}

        之前只发了 ``pcursor``，**漏了 userId 和 page**。注意这里键名是
        **userId（驼峰）**，与 profile/feed 的 ``user_id``（下划线）不一样，
        是服务端两个接口各自的历史包袱，别统一。

        :param auth: KuaishouAuth。
        :param user_id: 目标用户 eid；不传则用当前登录用户。
        :param pcursor: 翻页游标。
        :return: JSON。
        """
        api = "/rest/v/collect/list"
        if pcursor and getattr(auth, "_www_cookie_phase", "") == "relogin":
            raise UnverifiedBrowserContractError(
                "当前本人 collect 响应 pcursor=no_more，未抓到非空 pcursor 分支")
        # 注意：这里要的是 **eid**（形如 3x...），不是 cookie 里的数字
        # userId——浏览器实抓发的就是 eid。
        # 不传就现取一次 profile/get 拿自己的 eid（结果缓存在 auth 上）。
        uid = str(user_id or KuaishouAPI._self_eid(auth) or "")
        body = {"userId": uid, "pcursor": pcursor, "page": "collect"}
        referer = f'https://www.kuaishou.com/profile/{uid}' if uid else None
        return KuaishouAPI._post(auth, api, body, referer=referer)

    @staticmethod
    def _self_eid(auth) -> str:
        """取当前登录用户的 **eid**（`3x...` 格式），带缓存。

        使用当前 new-reco 成功抓到的 ``/rest/v/profile/get``。不能为了少几 KB
        在没有对应页面 Network 证据时自行改走 ``userInfoQuery``。

        cookie 里的 ``userId`` 是数字 ID，而 ``/rest/v/*`` 的 body 里要的是 eid，
        两者不能混用（混用等于查了个不存在的用户）。
        """
        cached = getattr(auth, "_self_eid_cache", None)
        if cached:
            return cached
        eid = ""
        try:
            r = KuaishouAPI.get_profile(auth, referer=KuaishouAPI.reco_referer)
            # 当前 Chrome profile/get 响应同时有 eid 与数字 userId；
            # collect/list/profile/feed 要的是 eid，绝不能降级成数字 ID。
            eid = str((r or {}).get("eid") or (r or {}).get("userDefineId") or "")
        except Exception:                                  # noqa: BLE001
            pass
        if eid:
            auth._self_eid_cache = eid
        return eid

    @staticmethod
    def get_private_list(auth, pcursor: str = "", referer: str = None,
                         profile_id: str = "", **kwargs) -> dict:
        """获取我的私密作品列表（🔒 需 __NS_hxfalcon）。

        :param auth: KuaishouAuth。
        :param pcursor: 翻页游标。
        :return: JSON。
        """
        api = "/rest/v/profile/private/list"
        if pcursor and getattr(auth, "_www_cookie_phase", "") == "relogin":
            raise UnverifiedBrowserContractError(
                "当前本人 private 响应 pcursor=no_more，未抓到非空 pcursor 分支")
        body = {"pcursor": pcursor, "page": "private"}
        page_referer = referer
        if not page_referer and profile_id:
            page_referer = f"{KuaishouAPI.kuaishou_url}/profile/{profile_id}"
        return KuaishouAPI._post(auth, api, body, referer=page_referer)

    @staticmethod
    def get_history_list(auth, pcursor: str = "", **kwargs) -> dict:
        """获取浏览历史列表。

        .. warning::
           **该端点已下线**：2026-08-16 实测服务端返回 HTTP 404
           ``{"error":"Not Found","path":"/rest/v/profile/history/list","status":404}``。
           端点名来自早期抓包，线上已不存在。

        :param auth: KuaishouAuth。
        :param pcursor: 翻页游标。
        :return: JSON。
        签名：不在白名单，cookie 直连即可。
        """
        raise UnverifiedBrowserContractError(
            "当前 Chrome 没有 /rest/v/profile/history/list 成功请求；旧证据只有 HTTP 404，已禁止发包")

    @staticmethod
    def get_playback_list(auth, user_id: str, pcursor: str = "", **kwargs) -> dict:
        """获取用户的直播回放列表。

        个人主页加载时会自动打一次（2026-08-16 CDP 实抓）::

            POST /rest/v/live/playBack/list
            {"userId":"<eid>","pcursor":""}

        不在 sig4 白名单，cookie 直连即可。

        :param auth: KuaishouAuth。
        :param user_id: 目标用户 eid。
        :param pcursor: 翻页游标。
        :return: JSON。
        """
        api = "/rest/v/live/playBack/list"
        if pcursor and getattr(auth, "_www_cookie_phase", "") == "relogin":
            raise UnverifiedBrowserContractError(
                "当前 playback 响应 pcursor=no_more，未抓到非空 pcursor 分支")
        body = {"userId": str(user_id), "pcursor": pcursor}
        referer = f'https://www.kuaishou.com/profile/{user_id}'
        return KuaishouAPI._post(auth, api, body, referer=referer)

    # ------------------------------------------------------------------ #
    # 系统 / 配置                                                          #
    # ------------------------------------------------------------------ #
    @staticmethod
    def system_configs(auth, referer: str = None, **kwargs) -> dict:
        """读取浏览器实际使用的系统配置（无需签名）。

        个人页 Network 的真实路径是 ``/rest/v/system/configs``；旧代码
        错用了 ``/rest/v/system/startup``。请求体为空，且浏览器不发
        ``content-type``，所以必须复用 ``_post(..., body=None)``。

        :param auth: KuaishouAuth。
        :return: JSON。
        """
        api = "/rest/v/system/configs"
        return KuaishouAPI._post(auth, api, None, referer=referer)

    @staticmethod
    def system_startup(auth, referer: str = None, **kwargs) -> dict:
        """兼容旧调用名；实际请求必须使用浏览器的 ``system/configs``。"""
        return KuaishouAPI.system_configs(auth, referer=referer, **kwargs)

    @staticmethod
    def kconf_get(auth, referer: str = None, profile_id: str = "", **kwargs) -> dict:
        """前端 kconf 配置（无需签名）。

        浏览器实抓是**不发 body** 的（XHR 钩子记到 ``b="null"``），
        之前发了个 ``{}`` —— 有 body 就会带上 ``content-type``，
        而浏览器那一发既没 content-type 也没 content-length。

        :param auth: KuaishouAuth。
        :return: JSON。
        """
        api = "/rest/v/kconf/get"
        page_referer = referer
        if not page_referer and profile_id:
            page_referer = f"{KuaishouAPI.kuaishou_url}/profile/{profile_id}"
        return KuaishouAPI._post(auth, api, None, referer=page_referer)


# --------------------------------------------------------------------------- #
# 模块级辅助                                                                    #
# --------------------------------------------------------------------------- #
def _is_risk(resp: dict) -> bool:
    """是不是滑块风控挑战。

    REST 端点返回 ``data.result == 400002``；GraphQL 端点返回
    ``errors`` + ``data.captcha.url``。两种形状都必须保留，不能把 GraphQL
    的 ``Need captcha`` 当成普通空数据。

    与 :func:`utils.captcha.is_captcha_challenge` 同义，这里单独放一份，
    是为了让 ks_apis 不必在模块顶层强依赖 captcha（它要 cv2/numpy/PIL，
    只做数据抓取的场景没必要装）。
    """
    data = (resp or {}).get("data") or {}
    if data.get("result") == 400002 and bool(data.get("url")):
        return True
    captcha = data.get("captcha") or {}
    return bool(captcha.get("url")) and bool((resp or {}).get("errors"))


def _graphql_risk_as_rest(resp: dict) -> dict:
    """把 GraphQL captcha 响应适配给现有滑块求解器的输入合同。"""
    data = (resp or {}).get("data") or {}
    captcha = data.get("captcha") or {}
    if captcha.get("url"):
        return {"data": {"result": 400002, "url": captcha["url"]}}
    return resp or {}


def _safe_json(resp) -> dict:
    try:
        return json.loads(resp.text)
    except Exception:
        logger.error(f'响应非 JSON：{resp.status_code} {resp.text[:200]}')
        return {"result": -1, "error": resp.text[:500]}


def _extract_photo_id(work_url_or_id: str) -> str:
    """从作品链接或直接的 photoId 提取 photoId。"""
    s = str(work_url_or_id)
    if '/' in s:
        return s.rstrip('/').split('/')[-1].split('?')[0]
    return s


if __name__ == '__main__':
    from builder.auth import KuaishouAuth

    cookies_str = ''
    auth_ = KuaishouAuth()
    auth_.prepare_auth(cookies_str)

    # 不需签名，直连即可跑通：
    # print(KuaishouAPI.get_feed_hot(auth_))
    # feeds = KuaishouAPI.get_some_feed_hot(auth_, 20)
    # print(len(feeds))
    # print(KuaishouAPI.get_comment_list(auth_, '<photo_id>'))
    # print(KuaishouAPI.get_relation(auth_, ftype=1))

    # 需签名（签名器就绪后可通）：
    # print(KuaishouAPI.get_profile(auth_))
    # print(KuaishouAPI.search_some_feed(auth_, '美食', 20))
    # print(KuaishouAPI.get_collect_list(auth_))
