#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Browser-faithful ``likeDataQuery`` token generation.

The page source proves that the input is the values of ``{did, ts, uri}``
sorted by key and joined with ``:`` before the bundle's ``$encode`` engine.
The small Node bridge executes the captured engine locally; it never reads or
copies a browser Cookie/header.  Keeping this separate from sig4 is
intentional: it is a different engine and a different input contract.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ORACLE = ROOT / "reverse" / "tools" / "like_token_oracle.js"


def oracle_available() -> bool:
    return bool(shutil.which("node") and ORACLE.exists()
                and (ROOT / "reverse" / "fixtures"
                     / "current_follow_script_813.network-response").exists())


def generate_like_token(did: str, ts: int, uri: str = "/rest/v/feed/myfollow") -> str:
    """Generate the exact 56-hex token used by the current myFollow bundle.

    Raises ``RuntimeError`` when the captured bundle/Node runtime is missing;
    silently falling back to an invented hash would violate the Network-first
    contract and is therefore deliberately forbidden.
    """
    if not oracle_available():
        raise RuntimeError("likeData token oracle unavailable: captured bundle or node missing")
    payload = json.dumps({"did": str(did or ""), "ts": int(ts), "uri": str(uri)},
                         ensure_ascii=False, separators=(",", ":"))
    proc = subprocess.run(
        ["node", str(ORACLE)], input=payload, text=True, encoding="utf-8",
        errors="replace", capture_output=True, cwd=str(ROOT), timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "like token oracle failed").strip())
    token = (proc.stdout or "").strip()
    if len(token) != 56 or any(c not in "0123456789abcdef" for c in token):
        raise RuntimeError(f"like token oracle returned invalid token: {token!r}")
    return token
