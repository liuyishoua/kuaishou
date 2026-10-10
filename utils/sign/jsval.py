#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""JS 值语义的忠实移植，供两个签名器共用。

签名输入最终都要拼成字符串再哈希，所以任何一处字符串化和浏览器不一致，签名就会错。
Python 与 JS 分叉最多的就是数字：``str(1.0)`` 在 Python 是 ``"1.0"``，在 JS 是 ``"1"``；
``1e-7`` 在 Python 的 repr 里是 ``"1e-07"``，JS 是 ``"1e-7"``。所以这里按
ECMAScript ``Number::toString`` 规范重写，而不是依赖 ``str`` / ``json.dumps``。
"""

from __future__ import annotations

import math
import re
import urllib.parse

# encodeURI 不转义的保留字符：字母数字 + ;,/?:@&=+$ + -_.!~*'() + #
ENCODE_URI_SAFE = ";,/?:@&=+$-_.!~*'()#"
# encodeURIComponent 只保留 -_.!~*'()
ENCODE_URI_COMPONENT_SAFE = "-_.!~*'()"

_REPR_RE = re.compile(r"^(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$")

_JSON_ESCAPE = {
    '"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f",
    "\n": "\\n", "\r": "\\r", "\t": "\\t",
}


def js_number_to_string(value) -> str:
    """ECMAScript ``Number::toString``（十进制）。

    JS 的数字都是 double，所以整数也先落到 double 再格式化，超过 2^53 时与浏览器同样丢精度。
    """
    if isinstance(value, bool):                       # bool 是 int 的子类，先挡掉
        return "true" if value else "false"
    try:
        x = float(value)
    except (OverflowError, ValueError, TypeError):
        return "Infinity" if value > 0 else "-Infinity"

    if math.isnan(x):
        return "NaN"
    if x == 0:
        return "0"                                    # JS 里 String(-0) 也是 "0"
    if x < 0:
        return "-" + js_number_to_string(-x)
    if math.isinf(x):
        return "Infinity"

    m = _REPR_RE.match(repr(x))
    if not m:                                         # 理论上到不了
        return repr(x)
    int_part, frac_part, exp_part = m.group(1), m.group(2) or "", m.group(3)
    exp = int(exp_part) if exp_part else 0

    digits = (int_part + frac_part).lstrip("0")
    stripped = digits.rstrip("0")
    trailing = len(digits) - len(stripped)
    s = stripped or "0"
    k = len(s)
    n = k + trailing + exp - len(frac_part)

    if k <= n <= 21:
        return s + "0" * (n - k)
    if 0 < n <= 21:
        return s[:n] + "." + s[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + s
    exponent = n - 1
    sign = "+" if exponent >= 0 else "-"
    mantissa = s if k == 1 else s[0] + "." + s[1:]
    return f"{mantissa}e{sign}{abs(exponent)}"


def js_to_string(value) -> str:
    """ECMAScript ``ToString``：隐式字符串化（``"" + value`` 的结果）。"""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        return js_number_to_string(value)
    if isinstance(value, (list, tuple)):
        # Array.prototype.join：null / undefined 变空串，而不是 "null"
        return ",".join("" if v is None else js_to_string(v) for v in value)
    return "[object Object]"


def js_quote_string(text: str) -> str:
    """``JSON.stringify`` 的字符串转义：只转义引号、反斜杠和控制字符，非 ASCII 原样保留。"""
    out = ['"']
    for ch in text:
        esc = _JSON_ESCAPE.get(ch)
        if esc is not None:
            out.append(esc)
        elif ch < " ":
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def js_sort_key(text: str) -> bytes:
    """JS ``Array.prototype.sort`` 的默认序：按 **UTF-16 码元**比较，不是码点。

    差别只在星平面字符上：``"😀"`` 的首个码元是 0xD83D，在 JS 里排在 ``"\\uf000"`` 之前，
    但按 Python 的码点比较（0x1F600）会排在之后。
    """
    return text.encode("utf-16-be", "surrogatepass")


def js_sorted(items):
    """按 JS 默认序排序字符串序列。"""
    return sorted(items, key=js_sort_key)


def _is_array_index(key: str) -> bool:
    """JS 的「数组下标」键：0 ~ 2^32-2 的规范十进制串（"0" 算，"00"/"01"/"-1" 不算）。"""
    return key.isdigit() and (key == "0" or key[0] != "0") and int(key) < 4294967295


def js_own_keys(obj: dict) -> list:
    """ECMAScript 自有属性枚举顺序：整数下标键按数值升序在前，其余按插入顺序在后。

    这一条直接影响 ``JSON.stringify`` 的输出顺序，进而影响签名。
    """
    keys = [str(k) for k in obj.keys()]
    idx = sorted((k for k in keys if _is_array_index(k)), key=int)
    return idx + [k for k in keys if not _is_array_index(k)]


def js_json_stringify(value) -> str:
    """``JSON.stringify``（无缩进）。数字走 Number::toString，非有限数出 ``null``。"""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return js_quote_string(value)
    if isinstance(value, (int, float)):
        x = float(value) if not isinstance(value, int) else value
        if isinstance(x, float) and (math.isnan(x) or math.isinf(x)):
            return "null"
        return js_number_to_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(js_json_stringify(v) for v in value) + "]"
    if isinstance(value, dict):
        by_str = {str(k): v for k, v in value.items()}
        parts = [f"{js_quote_string(k)}:{js_json_stringify(by_str[k])}" for k in js_own_keys(by_str)]
        return "{" + ",".join(parts) + "}"
    return js_quote_string(str(value))


def encode_uri(value) -> str:
    """JS ``encodeURI``（比 encodeURIComponent 少转义保留字符）。"""
    return urllib.parse.quote(js_to_string(value), safe=ENCODE_URI_SAFE, encoding="utf-8")


def encode_uri_component(value) -> str:
    """JS ``encodeURIComponent``。"""
    return urllib.parse.quote(js_to_string(value), safe=ENCODE_URI_COMPONENT_SAFE, encoding="utf-8")


if __name__ == "__main__":
    # 期望值全部由 Node 实测产出（reverse/tools/js_truth.js），改动本文件后跑一遍。
    number_cases = [
        (0, "0"), (-0.0, "0"), (1, "1"), (-1, "-1"), (1.0, "1"), (2.5, "2.5"),
        (-0.5, "-0.5"), (0.1, "0.1"), (1e21, "1e+21"), (1e-6, "0.000001"),
        (1e-7, "1e-7"), (1e-8, "1e-8"), (2147483647, "2147483647"),
        (4294967295, "4294967295"), (9007199254740991, "9007199254740991"),
        (9007199254740993, "9007199254740992"),      # 超过 2^53，与 JS 同样丢精度
        (1.2345678901234568e+29, "1.2345678901234568e+29"),
        (123456.789, "123456.789"), (1e300, "1e+300"), (5e-324, "5e-324"),
        (100, "100"), (20, "20"),
    ]
    string_cases = [
        (None, "null"), (True, "true"), (False, "false"), ("", ""), ("a", "a"),
        ([1, 2], "1,2"), ([1, None, 2], "1,,2"), ([[1, 2], 3], "1,2,3"),
        ([], ""), ({}, "[object Object]"), ([{}], "[object Object]"),
    ]
    json_cases = [
        ({"b": 1, "2": 2, "a": 3, "10": 4, "1": 5, "01": 6, "-1": 7},
         '{"1":5,"2":2,"10":4,"b":1,"a":3,"01":6,"-1":7}'),
        ({"pcursor": 2.5, "k-1": 20, "0": "#hash"},
         '{"0":"#hash","pcursor":2.5,"k-1":20}'),
        ({"x": 1.0, "y": 1e-7, "z": [1.0, None]}, '{"x":1,"y":1e-7,"z":[1,null]}'),
        ({"s": "中文😀", "t": 'a"b\\c\nd'}, '{"s":"中文😀","t":"a\\"b\\\\c\\nd"}'),
    ]
    uri_cases = [
        ("[object Object]", "%5Bobject%20Object%5D"), ("a b", "a%20b"),
        ("中文", "%E4%B8%AD%E6%96%87"), ("a/b?c=d&e=f", "a/b?c=d&e=f"),
        ("#hash", "#hash"), ("'\"\\", "'%22%5C"), ("😀", "%F0%9F%98%80"),
    ]
    sort_case = (["😀key", "\uf000key", "𝄞clef", "\ue000tail", "a", "z"],
                 ["a", "z", "𝄞clef", "😀key", "\ue000tail", "\uf000key"])

    failed = 0
    for value, want in number_cases:
        got = js_number_to_string(value)
        failed += got != want
        if got != want:
            print(f"  数字 {value!r}: 期望 {want!r} 得到 {got!r}")
    for value, want in string_cases:
        got = js_to_string(value)
        failed += got != want
        if got != want:
            print(f"  ToString {value!r}: 期望 {want!r} 得到 {got!r}")
    for value, want in json_cases:
        got = js_json_stringify(value)
        failed += got != want
        if got != want:
            print(f"  stringify: 期望 {want!r} 得到 {got!r}")
    for value, want in uri_cases:
        got = encode_uri(value)
        failed += got != want
        if got != want:
            print(f"  encodeURI {value!r}: 期望 {want!r} 得到 {got!r}")
    got_sort = js_sorted(sort_case[0])
    failed += got_sort != sort_case[1]
    if got_sort != sort_case[1]:
        print(f"  sort: 期望 {sort_case[1]!r} 得到 {got_sort!r}")

    total = len(number_cases) + len(string_cases) + len(json_cases) + len(uri_cases) + 1
    print(f"jsval 自检：{total - failed}/{total} 与 JS 一致")
