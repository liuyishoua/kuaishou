#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""快手滑块验证码（captcha.zt.kuaishou.com）客户端。

触发场景：风控接口返回 ``{"data":{"result":400002,"url":"…/iframe/index.html?captchaSession=…"}}``，
从那个 url 里取出 ``captchaSession``，走完本模块的流程拿到放行，再重发原请求。

链路（2026-08-16 实抓）::

    POST /rest/zt/captcha/sliding/config      form: captchaSession=…
         -> {captchaSn, bgPicUrl, cutPicUrl, bgPicWidth/Height, cutPicWidth/Height,
             disX, disY, verifyUrl, verifyUrl2, refSes, ...}
    GET  /rest/zt/captcha/sliding/bgPic?captchaSn=…      背景图（带缺口）
    GET  /rest/zt/captcha/sliding/cutPic?captchaSn=…     滑块图
    POST <verifyUrl>                          明文 JSON
    POST <verifyUrl2>  (kSecretApiVerify)     {"verifyParam": "<加密 blob>"}

verifyParam 那条是把整个载荷塞进 kSecret 加密层（实抓 9KB base64），本模块走**明文
verifyUrl**，载荷字段取自页面源码 (captcha-iframe.js)::

    {captchaSn, bgDisWidth, bgDisHeight, cutDisWidth, cutDisHeight,
     relativeX, relativeY, trajectory, gpuInfo, captchaExtraParam}

其中 ``trajectory`` 是 ``x|y|dt`` 三元组用逗号连接（dt 相对第一个点）：
``trackList.reduce((acc,n)=> acc + "," + n[0] + "|" + n[1] + "|" + (n[2]-t0), "").slice(1)``
"""

from __future__ import annotations

import io
import json
import random
import urllib.parse

import numpy as np
import requests
from loguru import logger
from PIL import Image

from utils.sign import captcha_crypto
from utils import captcha_fp
from utils.fingerprint import get_profile
from utils.transport import shared_session

requests.packages.urllib3.disable_warnings()

HOST = "https://captcha.zt.kuaishou.com"
CONFIG_URL = f"{HOST}/rest/zt/captcha/sliding/config"
TIMEOUT = (10, 30)

UA = get_profile()["ua"]


def extract_captcha_url(risk_response: dict) -> str:
    """从风控响应里取出验证码 iframe 的完整 URL。

    ``url`` 不能只截成 host 或只保留 ``captchaSession``：验证码页会把
    ``type``/``configUrl``/``bizName``/``displayType`` 等查询参数带进
    Referer，并参与风控关联。
    """
    data = risk_response.get("data") or risk_response
    url = data.get("url") or (data.get("captcha") or {}).get("url") or ""
    return str(url or "")


def extract_session(risk_response: dict) -> str:
    """从风控响应里取出 ``captchaSession``。

    :param risk_response: 形如 ``{"data":{"result":400002,"url":"…captchaSession=…"}}``。
    :return: captchaSession，取不到返回空串。
    """
    url = extract_captcha_url(risk_response)
    if not url:
        return ""
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    return (qs.get("captchaSession") or [""])[0]


def is_captcha_challenge(resp: dict) -> bool:
    """判断响应是不是风控验证码挑战。"""
    data = resp.get("data") or {}
    if data.get("result") == 400002 and bool(data.get("url")):
        return True
    # GraphQL 业务错误形状：errors + data.captcha.url。
    return bool((data.get("captcha") or {}).get("url")) and bool(
        resp.get("errors"))


def find_gap_x(bg_png: bytes, cut_png: bytes) -> int:
    """在背景图里找缺口的横坐标（原图像素，返回**滑块左边缘**该落到的 x）。

    做法：用滑块图 alpha 通道裁出实际形状 -> 在背景的边缘图上做带掩码的模板匹配。
    三个关键约束（缺一个就会给出越界或明显错误的结果）：

    1. **搜索范围要裁掉右边界**：滑块宽 w，背景宽 W，左边缘最大只能到 W-w。
       之前没裁，匹配到 642（W=686、w=122，实际上限是 564），发出去必然失败。
    2. **要跳过滑块自身所在的那一列**：滑块渲染在背景图左侧（disX 附近），
       它自己的边缘是最强的匹配，不排除掉就会匹配到自己身上。
    3. 匹配分数太低时**宁可用亮度突变兜底也要夹到合法区间**，不能直接返回。

    :return: 缺口左边缘的 x（原图坐标系），保证落在 ``[0, W-w]``。
    """
    import cv2

    bg = cv2.cvtColor(np.array(Image.open(io.BytesIO(bg_png)).convert("RGB")),
                      cv2.COLOR_RGB2BGR)
    cut_rgba = np.array(Image.open(io.BytesIO(cut_png)).convert("RGBA"))

    alpha = cut_rgba[:, :, 3]
    ys, xs = np.where(alpha > 32)
    if len(xs) == 0:
        raise ValueError("滑块图 alpha 全空，无法定位")
    x0, x1, y0, y1 = xs.min(), xs.max(), ys.min(), ys.max()
    piece = cv2.cvtColor(cut_rgba[y0:y1 + 1, x0:x1 + 1, :3], cv2.COLOR_RGB2BGR)
    mask = (alpha[y0:y1 + 1, x0:x1 + 1] > 32).astype(np.uint8) * 255

    bg_h, bg_w = bg.shape[:2]
    piece_w = piece.shape[1]
    max_x = max(0, bg_w - piece_w)          # 左边缘的合法上限

    # 缺口和滑块的边缘形状一致，用边缘图匹配比灰度稳
    bg_edge = cv2.Canny(cv2.GaussianBlur(bg, (3, 3), 0), 60, 180)
    piece_edge = cv2.Canny(cv2.GaussianBlur(piece, (3, 3), 0), 60, 180)
    res = cv2.matchTemplate(bg_edge, piece_edge, cv2.TM_CCOEFF_NORMED,
                            mask=cv2.erode(mask, np.ones((3, 3), np.uint8)))
    res = np.nan_to_num(res, nan=-1.0, posinf=-1.0, neginf=-1.0)

    # 把每个候选左边缘的得分压成一维（同一列取纵向最大），再按上面三条约束筛
    score_by_x = res.max(axis=0) if res.ndim == 2 else res
    valid = np.full(score_by_x.shape, -1.0, dtype=np.float32)
    upper = min(max_x, len(score_by_x) - 1)
    valid[:upper + 1] = score_by_x[:upper + 1]
    # 屏蔽滑块自身所在区域：它渲染在背景左侧，自身边缘是最强匹配
    valid[:piece_w] = -1.0

    best_x = int(np.argmax(valid))
    if valid[best_x] > 0.25:
        return int(min(max(best_x, 0), max_x))

    # 退路：缺口通常比周围暗，逐列找亮度突变（同样只在合法区间里找）
    gray = cv2.cvtColor(bg, cv2.COLOR_BGR2GRAY).astype(np.float32)
    col = gray.mean(axis=0)
    diff = np.abs(np.diff(col))
    lo, hi = piece_w, min(max_x, len(diff) - 1)
    if hi <= lo:
        return int(min(max(best_x, 0), max_x))
    return int(min(max(int(np.argmax(diff[lo:hi + 1])) + lo, 0), max_x))


def build_trajectory(distance: float, start_y: int = 0) -> list:
    """造一条像人手的拖动轨迹，返回 ``[[x, y, t], ...]``（t 是毫秒时间戳偏移）。

    先加速后减速，末段带小幅回调与抖动 —— 匀速直线最容易被判机器。
    """
    points, t = [], 0
    x, v = 0.0, 0.0
    # 前 70% 加速，之后减速
    mid = distance * (0.7 + random.random() * 0.1)
    while x < distance:
        a = 2.0 + random.random() * 2.0 if x < mid else -(2.5 + random.random() * 2.0)
        dt = 8 + random.random() * 14
        v = max(0.4, v + a * dt / 100.0)
        x = min(distance, x + v)
        t += int(dt)
        points.append([round(x, 2), start_y + round(random.gauss(0, 0.8), 2), t])
    # 冲过头一点再拉回来
    for back in (2.2, 1.1, 0.4, 0.0):
        t += int(20 + random.random() * 40)
        points.append([round(distance - back, 2),
                       start_y + round(random.gauss(0, 0.6), 2), t])
    return points


def format_trajectory(points: list) -> str:
    """按源码格式拼轨迹串：``x|y|dt`` 逗号连接，dt 相对第一个点。"""
    if not points:
        return ""
    t0 = points[0][2]
    return ",".join(f"{p[0]}|{p[1]}|{p[2] - t0}" for p in points)


class SlidingCaptcha:
    """一次滑块验证会话。"""

    def __init__(self, session: str, cookies=None, referer: str = "",
                 http: requests.Session = None, did: str = "",
                 kww: str = "", cookie_header: str = "",
                 parent_url: str = "", script_urls=None,
                 fingerprint: dict = None):
        """:param session: 风控响应里的 captchaSession。
        :param cookies: 业务侧 cookie（同域才有意义，可不传）。
        :param referer: iframe 的完整 url，作 Referer 用。
        :param did: 设备标识；进 captchaExtraParam 的 key1，
            要与 cookie 里的 did 一致（不一致是明显的异常信号）。
            不传则从 cookies 里取。
        :param kww: 验证码 iframe 页面初始化时冻结的 webweapon 值。它只
            注入 config/verify 的 XHR，不能放进共享 session，否则图片请求
            会错误地携带这个自定义头。
        :param cookie_header: 已按浏览器 path/domain 作用域展开的 Cookie
            header。验证码请求存在重复 ``kwpsecproductname``，不能依赖
            ``cookies=`` mapping（mapping 会丢掉重复名和创建顺序）。
        :param parent_url: 触发验证码的 www 业务页。gdfp module_section.1.page
            使用它，不能误写成 captcha iframe 所在域。
        :param script_urls: 本次 verification-captcha `/s/w/c` 下发并执行的
            exact fpUrl/signUrl，进入 gdfp detectjsFiles 字段。
        :param fingerprint: 可选的真实浏览器采集结果，形如
            ``{"gpuInfo": {...}, "captchaExtraParam": {...}}``。传入后
            优先使用它，避免把随包的旧机器指纹带入 verify。
        """
        self.session = session
        self.cookies = dict(cookies or {}) if isinstance(cookies, dict) else {}
        self.http = http or shared_session()
        self.kww = str(kww or "")
        self.parent_url = str(parent_url or "https://www.kuaishou.com")
        self.script_urls = [str(url) for url in (script_urls or []) if url]
        self._cookie_header = str(cookie_header or "")
        if not self._cookie_header and self.cookies:
            self._cookie_header = "; ".join(
                f"{key}={value}" for key, value in self.cookies.items()
                if key and value not in (None, ""))
        self.referer = referer or (
            f"{HOST}/iframe/index.html?captchaSession={urllib.parse.quote(session)}"
            "&type=1&bizName=ANTICRAWL_COMMON")
        # did：进 captchaExtraParam 的 key1，要与 cookie 里的 did 一致。
        # 有外部传入就用外部的，否则从 cookies 里取。
        if did:
            self.did = did
        elif isinstance(cookies, dict):
            self.did = cookies.get("did", "")
        else:
            self.did = ""
        # 指纹覆盖：在同一台机器上长期运行不需要改；换机器时传入真实值。
        fp = fingerprint if isinstance(fingerprint, dict) else {}
        self.gpu_info: dict = fp.get("gpuInfo") or fp.get("gpu_info")
        self.captcha_extra_param: dict = (
            fp.get("captchaExtraParam") or fp.get("captcha_extra_param"))
        # Do not mutate shared-session defaults here.  The browser sends
        # different headers for config/verify XHR versus image subresources;
        # each request gets an explicit profile from ``_headers`` below.
        self.config = {}

    def _headers(self, kind: str) -> dict:
        """Return a per-request Chrome header profile.

        ``kind`` is ``config``, ``image`` or ``verify``.  In particular,
        ``kww`` is intentionally absent from image requests, matching the
        iframe's axios interceptor (XHR only) and Chrome's ``<img>`` fetch.
        """
        if kind == "image":
            headers = {
                "user-agent": UA,
                "accept": ("image/avif,image/webp,image/apng,image/svg+xml,"
                           "image/*,*/*;q=0.8"),
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,ja;q=0.6",
                "referer": self.referer,
                "sec-fetch-dest": "image",
                "sec-fetch-mode": "no-cors",
                "sec-fetch-site": "same-origin",
            }
        else:
            headers = {
                "user-agent": UA,
                "accept": "application/json, text/plain, */*",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,ja;q=0.6",
                "origin": HOST,
                "referer": self.referer,
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
            }
            if kind == "config":
                headers["content-type"] = "application/x-www-form-urlencoded"
            elif kind == "verify":
                headers["content-type"] = "application/json"
            if self.kww:
                headers["kww"] = self.kww
        if self._cookie_header:
            headers["cookie"] = self._cookie_header
        return headers

    # ------------------------------------------------------------------ #
    def load_config(self) -> dict:
        """第 1 步：拿 captchaSn 与图片尺寸。"""
        if not self.kww:
            raise RuntimeError("验证码 config 请求缺少浏览器页面 kww，拒绝降级出网")
        if not self._cookie_header:
            raise RuntimeError("验证码 config 请求缺少显式重复 Cookie header，拒绝出网")
        body = "captchaSession=" + urllib.parse.quote(self.session, safe="")
        resp = self.http.post(
            CONFIG_URL, data=body.encode("utf-8"), verify=False,
            timeout=TIMEOUT,
            headers=self._headers("config"))
        self.config = resp.json()
        if self.config.get("result") != 1:
            logger.warning(f"[captcha] config 失败：{self.config}")
        return self.config

    def load_images(self) -> tuple:
        """第 2 步：下背景图与滑块图。"""
        sn = self.config["captchaSn"]
        def get(url):
            r = self.http.get(url, params={"captchaSn": sn}, verify=False,
                              timeout=TIMEOUT, headers=self._headers("image"))
            return r.content
        return get(self.config["bgPicUrl"]), get(self.config["cutPicUrl"])

    def solve(self) -> dict:
        """走完整条：config -> 下图 -> 找缺口 -> 造轨迹 -> 提交明文 verify。

        :return: verify 的响应 JSON。
        """
        if not self.config:
            self.load_config()
        if self.config.get("result") != 1:
            return self.config

        bg_png, cut_png = self.load_images()
        gap_x = find_gap_x(bg_png, cut_png)
        dis_x = int(self.config.get("disX", 0))
        distance = max(1.0, gap_x - dis_x)
        logger.info(f"[captcha] 缺口 x={gap_x} 起点 disX={dis_x} 需移动 {distance:.1f}px")

        points = build_trajectory(distance, start_y=int(self.config.get("disY", 0)))

        # 提交前先打 gdfp manMachine 预检（/s/u/v SDK_INIT -> /n/a/b 行为遥测）。
        # 不打这一步直接提交，服务端回 350014 anti check err —— 推断它拿这次遥测里的
        # identity UUID 跟后续 verify 做关联。见 utils/gdfp_manmachine。
        self.precheck()

        payload = {
            "captchaSn": self.config["captchaSn"],
            "bgDisWidth": int(self.config["bgPicWidth"]),
            "bgDisHeight": int(self.config["bgPicHeight"]),
            "cutDisWidth": int(self.config["cutPicWidth"]),
            "cutDisHeight": int(self.config["cutPicHeight"]),
            "relativeX": int(round(dis_x + distance)),
            "relativeY": int(self.config.get("disY", 0)),
            "trajectory": format_trajectory(points),
            # gpuInfo 4 键、captchaExtraParam 65 键，都是 CDP 在真实浏览器的
            # 验证码 iframe 页里直接调 Gt["b"]() / Ga() 取回来的真值，
            # 见 utils/captcha_fp（含换机器时的重抓办法）。
            # key1 用当前会话的 did，避免与 cookie 里的 did 对不上。
            "gpuInfo": captcha_fp.gpu_info_json(self.gpu_info),
            "captchaExtraParam": captcha_fp.captcha_extra_param_json(
                self.captcha_extra_param, did=self.did),
        }
        return self.submit(payload)

    def precheck(self) -> dict:
        """提交 verify 前先打 gdfp manMachine 预检（SDK_INIT → /n/a/b 行为遥测）。

        不打这一步直接提交，服务端回 ``350014 anti check err``。
        见 :mod:`utils.gdfp_manmachine` 的完整说明。
        """
        from utils import gdfp_manmachine as gdfp
        # 取真实 UA
        session_headers = getattr(self.http, "headers", {}) or {}
        ua = (session_headers.get("user-agent") or UA)
        result = gdfp.report(
            self.http, did=self.did,
            user_id=str(self.cookies.get("userId", "") if isinstance(self.cookies, dict) else ""),
            cookies=dict(self.cookies) if isinstance(self.cookies, dict) else {},
            parent_url=self.parent_url,
            iframe_url=self.referer,
            ua=ua,
            script_urls=self.script_urls,
        )
        cfg = result.get("config") or {}
        report_urls = ((cfg.get("reportConfig") or {}).get("reportUrls") or [])
        if ((result.get("init") or {}).get("result") != 1
                or cfg.get("switch") != 1 or cfg.get("status") != 1
                or not report_urls
                or (result.get("core") or {}).get("result") != 1
                or (result.get("whole") or {}).get("result") != 1):
            raise RuntimeError(
                "验证码 gdfp 双阶段预检未完整通过，拒绝提交 verify: "
                f"init={(result.get('init') or {}).get('result')}, "
                f"switch={cfg.get('switch')}, status={cfg.get('status')}, "
                f"reportUrls={report_urls}, "
                f"core={(result.get('core') or {}).get('result')}, "
                f"whole={(result.get('whole') or {}).get('result')}"
            )
        logger.debug(f"[captcha] precheck SDK_INIT={result.get('init',{}).get('result')} "
                     f"core={result.get('core',{}).get('result')} "
                     f"whole={result.get('whole',{}).get('result')} "
                     f"identity={result.get('identity','')[:8]}")
        return result
    APP_ID = captcha_crypto.APP_ID

    def submit(self, payload: dict) -> dict:
        """把载荷加密成 ``verifyParam`` 提交。

        明文 ``verifyUrl`` 走不通（JSON 和 form 都是 ``350013 form data err``），
        服务端只认 ``verifyUrl2``（kSecretApiVerify）的 ``{"verifyParam": "<base64>"}``。
        """
        if not self.kww or not self._cookie_header:
            raise RuntimeError("验证码 verify 缺少 kww/显式 Cookie，拒绝出网")
        param = self.encrypt(payload)
        resp = self.http.post(
            self.config.get("verifyUrl2") or (HOST + "/rest/zt/captcha/sliding/"
                                              "kSecretApiVerify"),
            data=json.dumps({"verifyParam": param},
                            separators=(",", ":")).encode("utf-8"),
            verify=False, timeout=TIMEOUT, headers=self._headers("verify"))
        try:
            return resp.json()
        except Exception:
            return {"_status": resp.status_code, "_text": resp.text[:200]}

    def encrypt(self, payload: dict) -> str:
        """把 verify 载荷加密成 base64 的 ``verifyParam``（纯 Python）。

        序列化用 ``qs.stringify`` 而不是 ``JSON.stringify`` —— 页面 d702 里是
        ``qs`` 包。加密见 :mod:`utils.sign.captcha_crypto`，已和 Node 预言机
        逐字节对拍通过（``reverse/tools/verify_captcha_crypto.py``）。
        """
        return captcha_crypto.verify_param(payload, self.APP_ID)
