"""请求匹配规则 — profile match 与生成插件共用."""

from __future__ import annotations

import fnmatch
import json
import urllib.parse
from typing import Any

STATIC_RESOURCE_EXTS = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".tif", ".tiff",
    ".css", ".map",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".wav", ".ogg", ".mp4", ".webm", ".avi", ".mov", ".m4v",
    ".pdf", ".zip", ".rar", ".7z", ".gz", ".br",
)


def is_static_resource(path: str, content_type: str = "", accept: str = "") -> bool:
    """过滤图片/样式/字体/音视频等静态资源。

    注意：GDMP 需要 patch vendor-gdmp-common*.js 以注入 X-Burp-GDMP-Key，
    所以 JS 不能在引擎层直接跳过；插件内部只 patch 命中特征的目标 JS。
    """
    clean_path = urllib.parse.urlparse(path or "").path.lower()
    if clean_path.endswith(STATIC_RESOURCE_EXTS):
        return True
    ct = (content_type or "").lower()
    if ct.startswith(("image/", "font/", "audio/", "video/")):
        return True
    if "text/css" in ct:
        return True
    acc = (accept or "").lower().strip()
    if acc.startswith("image/") or "text/css" in acc:
        return True
    return False


def matches_request(
    match: dict[str, Any],
    *,
    host: str,
    path: str,
    method: str,
    content_type: str = "",
    accept: str = "",
    body_text: str = "",
) -> bool:
    """判断请求是否命中 profile 的 match 规则."""
    if (match or {}).get("skip_static", True) and is_static_resource(path, content_type, accept):
        return False

    if not match:
        return True

    hosts = match.get("host", [])
    if hosts:
        host_matched = False
        for h in hosts:
            if h == host or h == "*":
                host_matched = True
                break
            if "*" in h and h.replace("*", "") in host:
                host_matched = True
                break
        if not host_matched:
            return False

    paths = match.get("path", [])
    if paths and not any(fnmatch.fnmatch(path, p) for p in paths):
        return False

    methods = match.get("methods", [])
    if methods and method not in methods:
        return False

    ctypes = match.get("content_type", [])
    ct = (content_type or "").lower()
    if ctypes and not any(c in ct for c in ctypes):
        return False

    require_fields = match.get("require_fields", [])
    if require_fields:
        try:
            if "json" in ct:
                body = json.loads(body_text or "{}")
            elif "urlencoded" in ct:
                body = dict(urllib.parse.parse_qsl(body_text or ""))
            else:
                body = {}
            if not all(f in body for f in require_fields):
                return False
        except Exception:
            return False

    return True


def generate_match_guard_code(match: dict[str, Any]) -> str:
    """为 plugin.py 生成 _should_process 匹配函数."""
    if not match:
        return ""
    return f'''MATCH_RULES = {match!r}
_MATCH_MISS_LOGGED = 0

def _should_process(flow: http.HTTPFlow) -> bool:
    from core.match_rules import matches_request
    ok = matches_request(
        MATCH_RULES,
                host=flow.request.host,
                path=flow.request.path,
                method=flow.request.method,
                content_type=flow.request.headers.get("Content-Type", ""),
                accept=flow.request.headers.get("Accept", ""),
                body_text=flow.request.text or "",
            )
    if not ok:
        global _MATCH_MISS_LOGGED
        if _MATCH_MISS_LOGGED < 5:
            _MATCH_MISS_LOGGED += 1
            print(
                f"跳过(未匹配规则): {{flow.request.method}} "
                f"{{flow.request.host}}{{flow.request.path}}"
            )
            if _MATCH_MISS_LOGGED == 5:
                print("跳过(未匹配规则): 后续同类提示已省略，请检查 profiles 的 match 或左侧「规则」")
    return ok

'''
