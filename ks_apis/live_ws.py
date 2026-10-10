#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""直播弹幕 WebSocket 客户端（纯 Python，protobuf 自解）。

链路（与浏览器一致）::

    1. get_room_state(eid)                -> liveStreamId
    2. websocketinfo(liveStreamId)        -> token + websocketUrls（需 __NS_hxfalcon）
    3. wss 连上后立刻发 CS_ENTER_ROOM(token, liveStreamId)
    4. 收到 SC_ENTER_ROOM_ACK，按里面的 heartbeatIntervalMs 定时发 CS_HEARTBEAT
    5. 持续收 SC_FEED_PUSH（弹幕/点赞/礼物/系统通知）等
    6. 退出前发 CS_USER_EXIT

编解码全在 :mod:`utils.live_proto`，schema 从 bundle 内嵌的 protobufjs descriptor 抽出，
字段不缺。
"""

import threading
import time

import websocket
from loguru import logger

from ks_apis.live_api import KuaishouLiveAPI
from utils.live_proto import (decode_frame, enter_room_frame, heartbeat_frame,
                             user_exit_frame)

# 浏览器建 wss 时带的头（Origin 必带，否则被拒）
WS_ORIGIN = "https://live.kuaishou.com"
WS_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
         "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36")


class LiveDanmakuClient:
    """一个直播间的弹幕连接。

    :param auth: KuaishouAuth。
    :param eid: 房间 url 里的 eid（``live.kuaishou.com/u/<eid>``）。
    """

    def __init__(self, auth, eid: str, room: dict | None = None):
        self.auth = auth
        self.eid = eid
        # ``find_live_room`` already resolved the eid/liveStreamId from one
        # concrete home/list response. Reusing that snapshot avoids a second
        # home/list race where the rotating recommendation page no longer
        # contains the selected room.
        self.room = dict(room or {})
        self.live_stream_id = ""
        self.token = ""
        self.ws_urls = []
        self.ws = None
        self.heartbeat_interval = 20.0
        self._stop = threading.Event()
        self._hb_thread = None
        self.handlers = {}
        self.risk_controlled = False        # True 表示被滑块验证码挡住，不是代码问题
        self.stats = {"frames": 0, "comments": 0, "likes": 0, "gifts": 0}

    # ------------------------------------------------------------------ #
    def on(self, payload_type: str, func):
        """注册回调，如 ``on("SC_FEED_PUSH", fn)``；``"*"`` 收全部。"""
        self.handlers.setdefault(payload_type, []).append(func)
        return self

    def _emit(self, message: dict):
        for key in (message["type"], "*"):
            for func in self.handlers.get(key, ()):
                try:
                    func(message)
                except Exception as exc:
                    logger.warning(f"[danmaku] 回调异常 {key}: {exc}")

    # ------------------------------------------------------------------ #
    def prepare(self) -> bool:
        """走 REST 拿 liveStreamId + token + wss 地址。"""
        # A QR/mobile/WWW session may have a valid passToken but no
        # live.kuaishou.com path-scoped tickets yet. Bootstrap those tickets
        # before any live REST request so direct live-only sessions can also
        # use home/list room discovery (its initial request needs the live
        # page tickets as well).
        live_cookies = getattr(self.auth, "_cookie", {}) or {}
        if (not live_cookies.get("kuaishou.live.web_st")
                or not live_cookies.get("kuaishou.live.web_ph")):
            from ks_apis.login_api import KuaishouLoginAPI, SID_LIVE
            refreshed = KuaishouLoginAPI.refresh_site_session(
                self.auth, SID_LIVE, KuaishouLiveAPI.live_url,
                referer=KuaishouLiveAPI.room_referer(self.eid))
            if not refreshed:
                logger.error("[danmaku] 缺少直播会话票据，且 passToken 换票失败")
                return False
        state = self.room or KuaishouLiveAPI.get_room_state(self.auth, self.eid)
        self.live_stream_id = state.get("liveStreamId", "")
        if not self.live_stream_id:
            logger.error(f"[danmaku] 拿不到 liveStreamId：{self.eid}")
            return False
        if not state.get("isLiving"):
            logger.warning(f"[danmaku] 主播当前不在播：{self.eid}")
        info = (KuaishouLiveAPI.websocket_info(
            self.auth, self.live_stream_id, eid=self.eid) or {}).get("data") or {}
        if not info.get("token"):
            # 先当会话过期处理：拿 passToken 换票 + userLogin 重建，浏览器每次加载
            # 直播页也是先走这两步。
            logger.info(f"[danmaku] websocketinfo 没给 token（{info}），尝试重建直播会话")
            from ks_apis.login_api import KuaishouLoginAPI, SID_LIVE
            if KuaishouLoginAPI.refresh_site_session(
                    self.auth, SID_LIVE, KuaishouLiveAPI.live_url):
                info = (KuaishouLiveAPI.websocket_info(
                    self.auth, self.live_stream_id, eid=self.eid) or {}).get("data") or {}
            if KuaishouLiveAPI.is_risk_controlled({"data": info}):
                # 重建后仍是 result:2 —— 这是账号/IP 级风控，不是会话问题。
                # 实测此时浏览器打开同一直播间也会弹滑块，得先过验证码。
                self.risk_controlled = True
                logger.error("[danmaku] 被风控挡住（websocketinfo result:2），"
                             "需先过滑块验证码；浏览器此时同样拿不到弹幕")
                return False
        self.token = info.get("token", "")
        self.ws_urls = info.get("websocketUrls") or []
        if not (self.token and self.ws_urls):
            logger.error(f"[danmaku] websocketinfo 没给 token/地址：{info}")
            return False
        logger.info(f"[danmaku] {self.eid} -> {self.live_stream_id}，"
                    f"{len(self.ws_urls)} 个接入点")
        return True

    def _heartbeat_loop(self):
        while not self._stop.wait(self.heartbeat_interval):
            try:
                self.ws.send(heartbeat_frame(), opcode=websocket.ABNF.OPCODE_BINARY)
            except Exception as exc:
                logger.warning(f"[danmaku] 心跳发送失败：{exc}")
                return

    def _handle(self, raw: bytes):
        message = decode_frame(raw)
        self.stats["frames"] += 1
        kind, payload = message["type"], message["payload"]
        if kind == "SC_ENTER_ROOM_ACK":
            interval = int(payload.get("heartbeatIntervalMs") or 20000)
            self.heartbeat_interval = max(1.0, interval / 1000.0)
            logger.info(f"[danmaku] 进房成功，心跳间隔 {self.heartbeat_interval}s")
            if self._hb_thread is None:
                self._hb_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
                self._hb_thread.start()
        elif kind == "SC_FEED_PUSH":
            self.stats["comments"] += len(payload.get("commentFeeds") or [])
            self.stats["likes"] += len(payload.get("likeFeeds") or [])
            self.stats["gifts"] += len(payload.get("giftFeeds") or [])
        elif kind == "SC_ERROR":
            logger.warning(f"[danmaku] 服务端报错：{payload}")
        self._emit(message)

    def _connect_once(self, url: str, deadline, reconnect_count: int) -> str:
        """连一个接入点并收到断开为止。

        :return: ``"done"`` 到时间/主动停；``"closed"`` 需要重连；``"failed"`` 连不上。
        """
        try:
            logger.info(f"[danmaku] 连接 {url}"
                        + (f"（第 {reconnect_count} 次重连）" if reconnect_count else ""))
            self.ws = websocket.create_connection(
                url, origin=WS_ORIGIN, header=[f"User-Agent: {WS_UA}"], timeout=10)
        except Exception as exc:
            logger.warning(f"[danmaku] 连接失败：{exc}")
            return "failed"
        try:
            self.ws.send(enter_room_frame(self.token, self.live_stream_id,
                                          reconnect_count=reconnect_count),
                         opcode=websocket.ABNF.OPCODE_BINARY)
            while not self._stop.is_set():
                if deadline and time.time() > deadline:
                    return "done"
                self.ws.settimeout(5)
                try:
                    opcode, data = self.ws.recv_data()
                except websocket.WebSocketTimeoutException:
                    continue
                except Exception as exc:
                    # 服务端会主动掐连接（实测跑一会儿就来一次），当断线处理去重连
                    logger.warning(f"[danmaku] 收流中断：{type(exc).__name__}: {exc}")
                    return "closed"
                if opcode == websocket.ABNF.OPCODE_CLOSE:
                    logger.info("[danmaku] 服务端关闭连接")
                    return "closed"
                if opcode == websocket.ABNF.OPCODE_BINARY and data:
                    try:
                        self._handle(data)
                    except Exception as exc:
                        # 单帧解不开不该拖垮整条连接
                        logger.warning(f"[danmaku] 帧解析失败（已跳过）：{exc}")
        finally:
            self._close_socket()
        return "done"

    def run(self, duration: float = None, max_reconnect: int = 5):
        """连上并阻塞收流，断线自动重连。

        :param duration: 收多少秒后自动退出；None 表示一直收。
        :param max_reconnect: 最多重连几次（浏览器也是断了就重连并递增 reconnectCount）。
        :return: 计数统计 dict。
        """
        if not (self.token or self.prepare()):
            return self.stats
        deadline = time.time() + duration if duration else None
        reconnect, url_index = 0, 0
        while not self._stop.is_set():
            if deadline and time.time() > deadline:
                break
            if url_index >= len(self.ws_urls):        # 所有接入点轮完一圈
                logger.error("[danmaku] 所有接入点都连不上")
                break
            state = self._connect_once(self.ws_urls[url_index], deadline, reconnect)
            if state == "done":
                break
            if state == "failed":
                url_index += 1
                continue
            reconnect += 1
            if reconnect > max_reconnect:
                logger.warning(f"[danmaku] 重连超过 {max_reconnect} 次，停止")
                break
            self._hb_thread = None                     # 重连后按新的 ack 重开心跳
            time.sleep(min(2.0 * reconnect, 10.0))
        self.close()
        return self.stats

    def _close_socket(self):
        """发退房帧并断开当前连接（重连时也走这里）。"""
        if self.ws:
            try:
                self.ws.send(user_exit_frame(), opcode=websocket.ABNF.OPCODE_BINARY)
            except Exception:
                pass
            try:
                self.ws.close()
            except Exception:
                pass
            self.ws = None

    def close(self):
        """彻底停止（心跳线程也会退出）。"""
        self._stop.set()
        self._close_socket()
