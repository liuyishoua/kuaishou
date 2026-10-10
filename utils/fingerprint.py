# -*- coding: utf-8 -*-
"""Current Chrome fingerprint shared by headers and gdfp payload builders.

The values are pinned to the active Chrome 151 profile observed on 2026-08-27
instead of randomly mixing geometry/GPU presets that never coexisted in one
browser.  A future browser profile must add new evidence before changing them.
"""

# Current Chrome 151 iframe geometry (screen/inner/outer/available sizes).
# Keep this in one profile so headers, gdfp, and captchaExtraParam cannot drift.
CURRENT_GEO = (2560, 1440, 2560, 1460, 2560, 1440, 2560, 1440)
CURRENT_OUTER_WIDTH = 2576
CURRENT_GPU = (
    "Google Inc. (NVIDIA)",
    "ANGLE (NVIDIA, NVIDIA GeForce RTX 5060 Ti (0x00002D04) "
    "Direct3D11 vs_5_0 ps_5_0, D3D11)",
)

_profile = None


def get_profile():
    """进程级指纹档案（UA/几何/硬件统一，进程内稳定）。"""
    global _profile
    if _profile is None:
        geo = CURRENT_GEO
        gpu = CURRENT_GPU
        _profile = {
            "ua": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"),
            "sec_ch_ua": '"Not)A;Brand";v="8", "Chromium";v="151", "Google Chrome";v="151"',
            "sec_ch_ua_platform": '"Windows"',
            "browser_name": "Chrome",
            "browser_version": "151.0.0.0",
            "engine_name": "Blink",
            "engine_version": "151.0.0.0",
            "os_name": "Windows",
            "os_version": "10",
            "platform": "Win32",
            "language": "zh-CN",
            "time_zone": "UTC+8",
            "product_sub": "20030107",
            "product": "Gecko",
            "cpu_core_num": "20",
            "device_memory": "32",
            "geo": geo,
            "webgl_vendor": gpu[0],
            "webgl_renderer": gpu[1],
            "screen_width": str(geo[6]),
            "screen_height": str(geo[7]),
            "avail_width": str(geo[4]),
            "avail_height": str(geo[5]),
            "inner_height": str(geo[1]),
            "outer_width": str(CURRENT_OUTER_WIDTH),
            "outer_height": str(geo[3]),
            "device_pixel_ratio": "1",
        }
    return _profile
