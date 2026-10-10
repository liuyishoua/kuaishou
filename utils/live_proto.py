#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""直播弹幕 WebSocket 的 protobuf 编解码（纯 Python，描述符驱动）。

schema 不是手抄的：``live-app.js`` 里内嵌了 protobufjs 的 JSON descriptor
（``Root.fromJSON(i)`` 的入参），已整份抽到 ``reverse/fixtures/live_ws_proto.json``
（65 个消息 / 12 个枚举），本模块直接按它做编解码，所以字段一个都不会漏。
抽取脚本：``reverse/tools/extract_proto.py``。

外层信封与收发逻辑（``live-app.js`` 明文）::

    SocketMessage { payloadType=1, compressionType=2, payload=3 }
    CompressionType { UNKNOWN:0, NONE:1, GZIP:2, AES:3 }

    编码：SocketMessage.encode({payloadType: <CS_* 编号>, payload: <子消息序列化>})
    解码：先解信封，再按 compressionType 处理 payload：
          3 -> AES-128-CBC 解密（key "PPbzKKL7NB15leYy"，iv "JRODKJiolJ9xqso0"）
          2 -> gzip 解压
          其余原样
          最后用 payloadType 对应的消息类型解出对象

上行只有三种（``E`` 表）：CS_ENTER_ROOM=200、CS_HEARTBEAT=1、CS_USER_EXIT=202。
"""

from __future__ import annotations

import gzip
import json
import os
import struct
import time
import zlib

from Crypto.Cipher import AES

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROTO_JSON = os.path.join(_HERE, "reverse", "fixtures", "live_ws_proto.json")
MAPS_JSON = os.path.join(_HERE, "reverse", "fixtures", "live_ws_maps.json")

# live-app.js 里的 sjcl AES 常量
WS_AES_KEY = b"PPbzKKL7NB15leYy"
WS_AES_IV = b"JRODKJiolJ9xqso0"

COMPRESSION_NONE, COMPRESSION_GZIP, COMPRESSION_AES = 1, 2, 3

# 上行消息：名字 -> (payloadType 编号, 消息类型名)
UPSTREAM = {
    "CS_ENTER_ROOM": (200, "CSWebEnterRoom"),
    "CS_HEARTBEAT": (1, "CSWebHeartbeat"),
    "CS_USER_EXIT": (202, "CSWebUserExit"),
}

_VARINT_TYPES = {"int32", "int64", "uint32", "uint64", "bool", "enum",
                 "sint32", "sint64"}
_FIXED64 = {"fixed64", "sfixed64", "double"}
_FIXED32 = {"fixed32", "sfixed32", "float"}


# --------------------------------------------------------------------------- #
# 描述符                                                                        #
# --------------------------------------------------------------------------- #
class Schema:
    """把 protobufjs descriptor 摊平成 {消息名: {字段号: 规格}} 与 {枚举名: {值: 名}}。"""

    def __init__(self, descriptor: dict):
        self.messages = {}
        self.enums = {}
        self._flatten(descriptor)
        self.payload_names = self.enums.get("PayloadType", {})

    def _flatten(self, node: dict):
        for name, body in node.items():
            if not isinstance(body, dict):
                continue
            if "fields" in body:
                by_id = {}
                for field, spec in body["fields"].items():
                    by_id[int(spec["id"])] = {
                        "name": field,
                        "type": spec["type"],
                        "repeated": spec.get("rule") == "repeated",
                    }
                self.messages[name] = by_id
            if "values" in body:
                self.enums[name] = {int(v): k for k, v in body["values"].items()}
            if "nested" in body:
                self._flatten(body["nested"])

    def kind(self, type_name: str) -> str:
        if type_name in self.messages:
            return "message"
        if type_name in self.enums:
            return "enum"
        return type_name


_SCHEMA = None
_MAPS = None


def schema() -> Schema:
    global _SCHEMA
    if _SCHEMA is None:
        with open(PROTO_JSON, encoding="utf-8") as fp:
            _SCHEMA = Schema(json.load(fp))
    return _SCHEMA


def maps() -> dict:
    """bundle 里的运行时映射（``reverse/tools/extract_proto_maps.py`` 抽的）。

    - ``number_to_name``：即源码里的 ``h`` 表。**它比 descriptor 的 PayloadType 枚举更权威**：
      浏览器就是 ``i = h[payloadType]; if (i) …``，不在 h 表里的帧浏览器直接丢
      （实抓见过 510，就属于这种）。
    - ``name_to_type``：即 ``y`` 表，SC_* 名字到 protobuf 消息类型名。
    """
    global _MAPS
    if _MAPS is None:
        with open(MAPS_JSON, encoding="utf-8") as fp:
            raw = json.load(fp)
        _MAPS = {
            "number_to_name": {int(k): v for k, v in raw["number_to_name"].items()},
            "name_to_type": raw["name_to_type"],
            "upstream": {k: tuple(v) for k, v in raw["upstream"].items()},
        }
    return _MAPS


# --------------------------------------------------------------------------- #
# wire 格式                                                                    #
# --------------------------------------------------------------------------- #
def _read_varint(buf: bytes, pos: int):
    result, shift = 0, 0
    while True:
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


def _write_varint(value: int) -> bytes:
    out = bytearray()
    value &= (1 << 64) - 1
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _zigzag_decode(value: int) -> int:
    return (value >> 1) ^ -(value & 1)


def decode_message(buf: bytes, type_name: str) -> dict:
    """按 schema 解一条消息；未知字段会以 ``_unknown_<号>`` 保留，不丢数据。"""
    sch = schema()
    fields = sch.messages.get(type_name)
    if fields is None:
        return {"_raw": buf.hex()}
    out, pos, size = {}, 0, len(buf)
    while pos < size:
        tag, pos = _read_varint(buf, pos)
        field_no, wire = tag >> 3, tag & 7
        spec = fields.get(field_no)
        if wire == 0:
            value, pos = _read_varint(buf, pos)
            if spec and spec["type"] in ("sint32", "sint64"):
                value = _zigzag_decode(value)
            elif spec and spec["type"] == "bool":
                value = bool(value)
            elif spec and sch.kind(spec["type"]) == "enum":
                value = sch.enums[spec["type"]].get(value, value)
        elif wire == 2:
            length, pos = _read_varint(buf, pos)
            chunk, pos = buf[pos:pos + length], pos + length
            if spec is None:
                value = chunk.hex()
            elif sch.kind(spec["type"]) == "message":
                value = decode_message(chunk, spec["type"])
            elif spec["type"] == "string":
                value = chunk.decode("utf-8", "replace")
            elif spec["type"] == "bytes":
                value = chunk
            else:                                   # packed 标量
                value, inner = [], 0
                while inner < len(chunk):
                    item, inner = _read_varint(chunk, inner)
                    value.append(item)
        elif wire == 1:
            value, pos = struct.unpack_from("<Q", buf, pos)[0], pos + 8
        elif wire == 5:
            value, pos = struct.unpack_from("<I", buf, pos)[0], pos + 4
        else:
            break                                   # group 已废弃，遇到就停
        key = spec["name"] if spec else f"_unknown_{field_no}"
        if spec and spec["repeated"]:
            out.setdefault(key, []).append(value)
        elif key in out:
            out[key] = (out[key] if isinstance(out[key], list) else [out[key]]) + [value]
        else:
            out[key] = value
    return out


def encode_message(obj: dict, type_name: str) -> bytes:
    """按 schema 编一条消息（只用得到上行那几个，故只支持常见标量 + 嵌套）。"""
    sch = schema()
    fields = sch.messages[type_name]
    by_name = {spec["name"]: (no, spec) for no, spec in fields.items()}
    out = bytearray()
    for name, value in obj.items():
        if value is None or name not in by_name:
            continue
        field_no, spec = by_name[name]
        items = value if spec["repeated"] else [value]
        for item in items:
            kind = sch.kind(spec["type"])
            if kind == "message":
                payload = encode_message(item, spec["type"])
                out += _write_varint(field_no << 3 | 2) + _write_varint(len(payload)) + payload
            elif spec["type"] == "string":
                payload = str(item).encode("utf-8")
                out += _write_varint(field_no << 3 | 2) + _write_varint(len(payload)) + payload
            elif spec["type"] == "bytes":
                out += _write_varint(field_no << 3 | 2) + _write_varint(len(item)) + item
            elif spec["type"] in _VARINT_TYPES or kind == "enum":
                out += _write_varint(field_no << 3 | 0) + _write_varint(int(item))
            elif spec["type"] in _FIXED64:
                out += _write_varint(field_no << 3 | 1) + struct.pack("<Q", int(item))
            elif spec["type"] in _FIXED32:
                out += _write_varint(field_no << 3 | 5) + struct.pack("<I", int(item))
            else:
                raise ValueError(f"不支持的字段类型 {spec['type']}（{type_name}.{name}）")
    return bytes(out)


# --------------------------------------------------------------------------- #
# 信封                                                                         #
# --------------------------------------------------------------------------- #
def _decompress(payload: bytes, compression) -> bytes:
    """按 compressionType 还原 payload。compression 可能已被枚举名替换。"""
    if compression in (COMPRESSION_AES, "AES"):
        plain = AES.new(WS_AES_KEY, AES.MODE_CBC, WS_AES_IV).decrypt(payload)
        pad = plain[-1] if plain else 0
        if 1 <= pad <= 16 and plain[-pad:] == bytes([pad]) * pad:
            plain = plain[:-pad]
        return plain
    if compression in (COMPRESSION_GZIP, "GZIP"):
        try:
            return gzip.decompress(payload)
        except OSError:
            return zlib.decompress(payload, -zlib.MAX_WBITS)
    return payload


def decode_frame(frame: bytes) -> dict:
    """解一帧下行。

    :return: ``{"type": <PayloadType 名>, "payloadType": <号>, "payload": {...}}``。
        类型名不在 bundle 的 h 表里时（浏览器会直接丢弃这种帧），payload 保留
        ``{"_raw": hex}`` 而不是丢掉，便于后续发现新类型。
    """
    envelope = decode_message(frame, "SocketMessage")
    raw_type = envelope.get("payloadType", 0)
    sch, table = schema(), maps()
    if isinstance(raw_type, str):                     # 枚举已被 decode 转成名字
        name = raw_type
        number = next((k for k, v in sch.payload_names.items() if v == name), 0)
    else:
        number = raw_type
        name = table["number_to_name"].get(raw_type) \
            or sch.payload_names.get(raw_type) or str(raw_type)
    payload = envelope.get("payload") or b""
    if payload:
        payload = _decompress(payload, envelope.get("compressionType"))
    body = {}
    if payload:
        type_name = table["name_to_type"].get(name)
        body = (decode_message(payload, type_name) if type_name in sch.messages
                else {"_raw": payload.hex()})
    return {"type": name, "payloadType": number, "payload": body}


def encode_frame(kind: str, payload: dict = None) -> bytes:
    """编一帧上行。

    :param kind: ``CS_ENTER_ROOM`` / ``CS_HEARTBEAT`` / ``CS_USER_EXIT``。
    :param payload: 子消息字段。
    """
    number, type_name = UPSTREAM[kind]
    body = encode_message(payload or {}, type_name)
    return encode_message({"payloadType": number, "payload": body}, "SocketMessage")


def enter_room_frame(token: str, live_stream_id: str, page_id: str = "",
                     reconnect_count: int = 0, exp_tag: str = "", attach: str = "") -> bytes:
    """进房帧（连上 WS 后第一件事）。token 来自 ``liveroom/websocketinfo``。"""
    payload = {"token": token, "liveStreamId": live_stream_id}
    if reconnect_count:
        payload["reconnectCount"] = reconnect_count
    for key, value in (("expTag", exp_tag), ("attach", attach), ("pageId", page_id)):
        if value:
            payload[key] = value
    return encode_frame("CS_ENTER_ROOM", payload)


def heartbeat_frame(timestamp_ms: int = None) -> bytes:
    """心跳帧；间隔用 ``SC_ENTER_ROOM_ACK`` 回的 ``heartbeatIntervalMs``。"""
    return encode_frame("CS_HEARTBEAT",
                        {"timestamp": int(time.time() * 1000) if timestamp_ms is None
                         else timestamp_ms})


def user_exit_frame(timestamp_ms: int = None) -> bytes:
    """退房帧。"""
    return encode_frame("CS_USER_EXIT",
                        {"time": int(time.time() * 1000) if timestamp_ms is None
                         else timestamp_ms})
