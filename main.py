"""mitmdump 入口。

GUI 启动两条本地代理：
- decrypt: 浏览器 -> decrypt -> Burp(明文)
- encrypt: Burp(明文) -> encrypt -> 服务器

两端都通过 PROFILE=current、BASEURL、PROXY_ROLE 环境变量控制。
"""

import logging
import os
import sys

ROOT = os.path.dirname(__file__)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

logging.basicConfig(level=logging.INFO, format="%(message)s")

from core.mitm_engine import MitmEngine

addons = [MitmEngine()]
