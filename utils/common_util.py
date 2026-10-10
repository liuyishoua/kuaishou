#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""通用工具：init() / load_env()（对齐 DouYin_Spider/utils/common_util.py）。"""

import os

from dotenv import load_dotenv

ks_auth = None


def load_env():
    """读取 .env，构造 KuaishouAuth。"""
    global ks_auth
    load_dotenv()
    cookies_ks = os.getenv('KS_COOKIES')
    from builder.auth import KuaishouAuth
    ks_auth = KuaishouAuth()
    # Keep session construction in KuaishouAuth: a supplied CK is materialized
    # there, while an empty value starts the complete QR/STS/device flow.
    ks_auth.initialize(cookies_ks or "")
    return ks_auth


def init():
    """初始化保存目录 + 读取 auth。返回 (auth, base_path)。"""
    media_base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../datas/media_datas'))
    excel_base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../datas/excel_datas'))
    for base_path in [media_base_path, excel_base_path]:
        if not os.path.exists(base_path):
            os.makedirs(base_path)
    auth = load_env()
    base_path = {
        'media': media_base_path,
        'excel': excel_base_path,
    }
    return auth, base_path
