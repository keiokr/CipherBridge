"""CipherBridge 极简版 GUI.

保留功能：
1. 当前 baseurl 输入与保存；
2. decrypt / encrypt 双端启动停止，链路固定为：
   浏览器 -> decrypt -> Burp(明文) -> encrypt -> 服务器
   服务器 -> encrypt -> Burp(明文) -> decrypt -> 浏览器
3. 加密/解密明文报文表格与详情查看；
4. plugins/current/plugin.py 输入、修改、保存。

其它历史功能已从主界面移除。
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import traceback
import urllib.parse
from datetime import datetime
from pathlib import Path

import yaml
from PyQt6.QtCore import QProcess, QProcessEnvironment, QTimer, Qt
from PyQt6.QtGui import QFont, QTextCursor
from PyQt6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

try:
    from core.paths import get_app_root
except Exception:
    def get_app_root() -> str:
        return os.path.dirname(__file__)

from core.net_utils import (
    can_bind_ipv4,
    detect_local_ipv4,
    is_port_in_use,
    normalise_local_ipv4,
)

from core.http_message import HTTP_LOG_BEGIN, HTTP_LOG_BLANK, HTTP_LOG_END


PROJECT_ROOT = Path(get_app_root())
PROFILES_DIR = PROJECT_ROOT / "profiles"
PLUGINS_DIR = PROJECT_ROOT / "plugins"
WORKSPACE_DIR = PROJECT_ROOT / "workspace"
MAIN_SCRIPT = PROJECT_ROOT / "main.py"
STATE_PATH = WORKSPACE_DIR / "cipherbridge_minimal.json"
PLUGIN_SKILL_PATH = WORKSPACE_DIR / "cipherbridge_plugin_generation_skill.md"
AI_REQUEST_SAMPLE_PATH = WORKSPACE_DIR / "cipherbridge_ai_request.txt"
AI_RESPONSE_SAMPLE_PATH = WORKSPACE_DIR / "cipherbridge_ai_response.txt"
PROFILE_NAME = "current"
PLUGIN_NAME = "current"
PLUGIN_DIR = PLUGINS_DIR / PLUGIN_NAME
PLUGIN_PATH = PLUGIN_DIR / "plugin.py"
PROFILE_PATH = PROFILES_DIR / f"{PROFILE_NAME}.yaml"

APP_TITLE = "CipherBridge 明文桥接器"


DEFAULT_PLUGIN_CODE = r'''"""CipherBridge 当前项目插件。

此插件由 decrypt / encrypt 两端共用，通过 ctx._role 区分角色：

- role == "decrypt":
  - request(ctx): 浏览器发来的密文请求 -> 解密成明文给 Burp
  - response(ctx): Burp 回给浏览器的明文响应 -> 如浏览器需要密文，可在这里重新加密

- role == "encrypt":
  - request(ctx): Burp 修改后的明文请求 -> 加密成服务器真实密文协议
  - response(ctx): 服务器返回的密文响应 -> 解密成明文给 Burp

按你的实际算法修改下面四个分支即可。
"""

import json


def request(ctx) -> None:
    role = getattr(ctx, "_role", "")

    if role == "decrypt":
        # TODO: 浏览器密文请求 -> Burp 明文请求
        # 示例：
        # data = ctx.request_json
        # data["payload"] = your_decrypt(data["payload"])
        # ctx.request_json = data
        return

    if role == "encrypt":
        # TODO: Burp 明文请求 -> 服务器密文请求
        # 示例：
        # data = ctx.request_json
        # data["payload"] = your_encrypt(data["payload"])
        # ctx.request_json = data
        return


def response(ctx) -> None:
    role = getattr(ctx, "_role", "")

    if role == "encrypt":
        # TODO: 服务器密文响应 -> Burp 明文响应
        # 示例：
        # data = ctx.response_json
        # data["payload"] = your_decrypt(data["payload"])
        # ctx.response_json = data
        return

    if role == "decrypt":
        # TODO: Burp 明文响应 -> 浏览器响应
        # 如果浏览器端仍需要密文协议，在这里重新加密；否则保持明文返回。
        return
'''


def _resolve_mitmdump() -> str:
    import shutil

    for name in ("mitmdump.exe", "mitmdump"):
        cand = PROJECT_ROOT / name
        if cand.is_file():
            return str(cand)
    if sys.platform == "win32":
        cand = Path(sys.executable).parent / "Scripts" / "mitmdump.exe"
        if cand.is_file():
            return str(cand)
    return shutil.which("mitmdump") or "mitmdump"


def _mitmdump_available() -> bool:
    import shutil

    path = _resolve_mitmdump()
    return (path != "mitmdump" and Path(path).is_file()) or bool(shutil.which("mitmdump"))


def _normalise_baseurl(text: str) -> str:
    text = (text or "").strip()
    if not text:
        return ""
    parsed = urllib.parse.urlparse(text)
    if not parsed.scheme:
        text = "https://" + text
        parsed = urllib.parse.urlparse(text)
    if not parsed.netloc:
        raise ValueError("baseurl 必须包含域名，例如：https://example.com 或 https://example.com/api")
    return text.rstrip("/")


def _baseurl_to_match(baseurl: str) -> dict:
    parsed = urllib.parse.urlparse(baseurl)
    host = parsed.hostname or "*"
    path = parsed.path or "/"
    if not path or path == "/":
        path_rule = "*"
    else:
        path_rule = path.rstrip("/") + "*"
    return {
        "host": [host],
        "path": [path_rule],
        "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        "skip_static": True,
    }


def _load_json(path: Path, default: dict) -> dict:
    try:
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return dict(default)


def ensure_project_files(baseurl: str = "") -> None:
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    PLUGIN_DIR.mkdir(parents=True, exist_ok=True)
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
    if not PLUGIN_PATH.exists():
        PLUGIN_PATH.write_text(DEFAULT_PLUGIN_CODE, encoding="utf-8")
    if not PLUGIN_SKILL_PATH.exists():
        PLUGIN_SKILL_PATH.write_text(CIPHERBRIDGE_PLUGIN_SKILL_TEXT, encoding="utf-8")
    if baseurl:
        save_profile(baseurl)


def load_state() -> dict:
    ensure_project_files()
    default_listen_host = detect_local_ipv4()
    state = _load_json(
        STATE_PATH,
        {
            "baseurl": "",
            "listen_host": default_listen_host,
            "burp_host": default_listen_host,
            "decrypt_port": 8083,
            "burp_port": 8080,
            "encrypt_port": 8081,
        },
    )
    state["listen_host"] = (
        state.get("listen_host")
        or state.get("local_ip")
        or default_listen_host
    )
    state["burp_host"] = (
        state.get("burp_host")
        or state.get("burp_ip")
        or state.get("listen_host")
        or default_listen_host
    )
    if not state.get("baseurl") and PROFILE_PATH.exists():
        try:
            cfg = yaml.safe_load(PROFILE_PATH.read_text(encoding="utf-8")) or {}
            state["baseurl"] = cfg.get("baseurl", "")
        except Exception:
            pass
    return state


def save_state(state: dict) -> None:
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def save_profile(baseurl: str) -> None:
    cfg = {
        "name": PROFILE_NAME,
        "plugin": PLUGIN_NAME,
        "roles": ["decrypt", "encrypt"],
        "baseurl": baseurl,
        "match": _baseurl_to_match(baseurl),
    }
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    PROFILE_PATH.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False), encoding="utf-8")


class DetailDialog(QDialog):
    def __init__(self, title: str, text: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(980, 720)
        layout = QVBoxLayout(self)
        viewer = QPlainTextEdit()
        viewer.setReadOnly(True)
        viewer.setFont(QFont("Consolas", 10))
        viewer.setPlainText(text)
        layout.addWidget(viewer)
        close = QPushButton("关闭")
        close.clicked.connect(self.accept)
        layout.addWidget(close, alignment=Qt.AlignmentFlag.AlignRight)


class TrafficTable(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.records: list[dict] = []
        self._pending_records: list[dict] = []
        self._max_records = 400
        self._max_pending_records = 120
        self._flush_timer = QTimer(self)
        self._flush_timer.setInterval(60)
        self._flush_timer.timeout.connect(self._flush_pending_records)
        self._flush_timer.start()
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        title = QLabel("加密 / 解密明文详情（Burp 原始报文样式，双击表格行查看完整内容）")
        layout.addWidget(title)

        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(["时间", "角色", "方向", "方法", "URL/摘要", "状态码", "长度", "说明"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)
        self.table.doubleClicked.connect(self.show_selected_detail)
        layout.addWidget(self.table, 3)

        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setFont(QFont("Consolas", 10))
        self.detail.setPlaceholderText("点击表格行预览 Burp 原始报文，双击行打开详情窗口。")
        self.table.itemSelectionChanged.connect(self._preview_selected)
        layout.addWidget(self.detail, 2)

        buttons = QHBoxLayout()
        clear = QPushButton("清空表格")
        clear.clicked.connect(self.clear)
        open_detail = QPushButton("查看选中详情")
        open_detail.clicked.connect(self.show_selected_detail)
        buttons.addStretch(1)
        buttons.addWidget(clear)
        buttons.addWidget(open_detail)
        layout.addLayout(buttons)

    def clear(self):
        self.records.clear()
        self._pending_records.clear()
        self.table.setRowCount(0)
        self.detail.clear()

    def add_http_record(self, tag: str, message: str, source: str):
        record = self._parse_record(tag, message, source)
        self._pending_records.append(record)
        if len(self._pending_records) > self._max_pending_records:
            self._pending_records = self._pending_records[-self._max_pending_records:]
        if len(self._pending_records) >= 20:
            self._flush_pending_records()

    def _flush_pending_records(self):
        if not self._pending_records:
            return
        pending = self._pending_records
        self._pending_records = []
        self.table.setUpdatesEnabled(False)
        try:
            for record in pending:
                self.records.append(record)
                row = self.table.rowCount()
                self.table.insertRow(row)
                values = [
                    record["time"],
                    record["role_cn"],
                    record["phase_cn"],
                    record["method"],
                    record["summary"],
                    record["status"],
                    str(record["length"]),
                    record["note"],
                ]
                for col, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    if col in (0, 1, 2, 3, 5, 6, 7):
                        item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                    self.table.setItem(row, col, item)
            while self.table.rowCount() > self._max_records:
                self.table.removeRow(0)
                if self.records:
                    self.records.pop(0)
            if pending:
                self.table.scrollToBottom()
        finally:
            self.table.setUpdatesEnabled(True)

    def _parse_record(self, tag: str, message: str, source: str) -> dict:
        role = ""
        phase = ""
        summary = tag
        m = re.search(r"\[(decrypt|encrypt)\]\[[^\]]*\]\[(request|response)\]\s*(.*)$", tag)
        if m:
            role, phase, summary = m.group(1), m.group(2), m.group(3)
        lines = message.splitlines()
        first = lines[0] if lines else ""
        method = ""
        status = ""
        if phase == "request" and first:
            parts = first.split()
            method = parts[0] if parts else ""
            summary = parts[1] if len(parts) > 1 else summary
        elif phase == "response" and first:
            parts = first.split()
            status = parts[1] if len(parts) > 1 else ""
            method = "HTTP"
        length = len(message.encode("utf-8", errors="replace"))
        role_cn = "解密" if role == "decrypt" else ("加密" if role == "encrypt" else source)
        phase_cn = "请求" if phase == "request" else ("响应" if phase == "response" else "")
        note = ""
        if role == "decrypt" and phase == "request":
            note = "浏览器密文解密后送 Burp"
        elif role == "encrypt" and phase == "request":
            note = "Burp 明文加密后送服务器"
        elif role == "encrypt" and phase == "response":
            note = "服务器密文解密后回 Burp"
        elif role == "decrypt" and phase == "response":
            note = "Burp 响应回浏览器"
        return {
            "time": datetime.now().strftime("%H:%M:%S"),
            "role": role,
            "role_cn": role_cn,
            "phase": phase,
            "phase_cn": phase_cn,
            "method": method,
            "summary": summary,
            "status": status,
            "length": length,
            "note": note,
            "tag": tag,
            "message": message,
        }

    def _selected_record(self) -> dict | None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self.records):
            return None
        return self.records[row]

    def _preview_selected(self):
        rec = self._selected_record()
        if not rec:
            return
        self.detail.setPlainText(
            f"【{rec['role_cn']} / {rec['phase_cn']}】Burp 原始报文\n\n{rec['message']}"
        )

    def show_selected_detail(self):
        rec = self._selected_record()
        if not rec:
            return
        DetailDialog(
            f"{rec['role_cn']} / {rec['phase_cn']} - Burp 原始报文",
            f"【{rec['role_cn']} / {rec['phase_cn']}】Burp 原始报文\n\n{rec['message']}",
            self,
        ).exec()


class PluginEditor(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()
        self.load()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        header = QHBoxLayout()
        self.path_label = QLabel(str(PLUGIN_PATH))
        self.path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        header.addWidget(QLabel("当前 plugin.py："))
        header.addWidget(self.path_label, 1)
        self.reload_btn = QPushButton("重新读取")
        self.reload_btn.clicked.connect(self.load)
        self.save_btn = QPushButton("保存 plugin.py")
        self.save_btn.clicked.connect(self.save)
        header.addWidget(self.reload_btn)
        header.addWidget(self.save_btn)
        layout.addLayout(header)

        self.editor = QPlainTextEdit()
        self.editor.setFont(QFont("Consolas", 10))
        self.editor.setPlaceholderText("在这里编辑 plugins/current/plugin.py，保存后重启 decrypt/encrypt 端生效。")
        layout.addWidget(self.editor, 1)

    def load(self):
        ensure_project_files()
        self.editor.setPlainText(PLUGIN_PATH.read_text(encoding="utf-8"))

    def save(self):
        ensure_project_files()
        PLUGIN_PATH.write_text(self.editor.toPlainText(), encoding="utf-8")
        QMessageBox.information(self, "已保存", f"已保存：\n{PLUGIN_PATH}\n\n修改后请重启 decrypt / encrypt 端。")


CIPHERBRIDGE_PLUGIN_SKILL_TEXT = """# ai适配CipherBridge生成完整且正确plugin.py文件提示词skills。

你是 CipherBridge 加密解密插件生成专家。用户通常只会提供加密请求、密文响应；你的任务是根据这些样本自动分析、推断加密解密流程，并生成当前 CipherBridge 软件可直接保存使用的完整 plugin.py 文件。

不能输出 Burp/Jython 扩展，不能输出伪代码，不能输出步骤说明。最终只输出完整 Python3 源码。

如果样本不足以完全确定算法、密钥、IV、签名规则或动态参数，不能凭空编造固定密钥、固定 IV、固定算法；应在 plugin.py 中生成稳健的多策略自动识别、异常保护、print 日志和清晰的可配置参数位置，保证插件可运行、不中断真实流量。

## 软件链路

浏览器 -> decrypt -> Burp(明文) -> encrypt -> 服务器
服务器 -> encrypt -> Burp(明文) -> decrypt -> 浏览器

## 端口/用法

1、Burp 监听在 Burp IP 的 <b>8080</b>，尽可能都明文显示。
2、Burp 的上游代理设置为 CipherBridge IP 的 <b>8081</b>，也就是 encrypt 加密端，用于加密后提交给目标服务器。
3、浏览器代理设置为 CipherBridge IP 的 <b>8083</b>，也就是 decrypt 解密端；登录或访问页面后，decrypt 自动解密并交给 Burp 明文。
4、操作 burpsuite，修改明文后经 encrypt 加密提交给目标服务器，方便调用插件自动化检测和手动明文测试。

请求链路：
浏览器 -> 本机IP:8083 decrypt -> 本机IP:8080 Burp 明文 -> 本机IP:8081 encrypt -> 目标服务器

响应链路：
目标服务器 -> 本机IP:8081 encrypt -> 本机IP:8080 Burp 明文 -> 本机IP:8083 decrypt -> 浏览器

## 处理范围

1. 插件只处理当前 CipherBridge baseurl 范围内的请求/响应；如果插件内部自行判断 URL、Host、Path，也必须以当前 flow 为准，不要误处理其它站点。
2. 遇到图片、CSS、字体、视频、音频、favicon、静态资源下载等非加密业务接口，request(ctx) / response(ctx) 应直接 return，不要尝试加解密。
3. 如果请求或响应明显不是目标加密协议，应直接 return 或保留原文转发，并 print 日志说明跳过原因。
4. 插件不能影响非目标业务请求，不能污染浏览器、服务器真实协议。

## 输出要求

1. 只输出完整 Python3 源码，不要 Markdown 代码块，不要解释，不要步骤说明。
2. 生成的文件必须是当前 CipherBridge 可直接保存使用的 plugin.py，不是 Burp/Jython 扩展。
3. 禁止导入 burp、java、javax、jarray，禁止生成 IBurpExtender。
4. 必须包含：
   def request(ctx) -> None:
   def response(ctx) -> None:
5. 必须用 role = getattr(ctx, "_role", "") 区分 decrypt/encrypt。
6. decrypt 角色：
   - request(ctx)：浏览器密文请求 -> Burp 明文请求。
   - response(ctx)：Burp 明文响应 -> 浏览器；必须保证浏览器最终收到的响应符合原客户端协议。如果浏览器端 JS/客户端原本期待密文响应，则在返回浏览器前重新加密/编码/压缩。
7. encrypt 角色：
   - request(ctx)：Burp 明文请求 -> 服务器密文请求。
   - response(ctx)：服务器密文响应 -> Burp 明文响应。
8. Burp 中应尽量全程看到明文请求和明文响应，服务器侧仍保持真实密文协议。
9. 代码必须可运行，不能写伪代码；未知处也要用稳健的异常保护、自动识别和 print 日志。
10. 尽量自动处理 JSON、form-urlencoded、query 参数、raw body、headers、cookies、base64、hex、URL 编码、gzip/zlib、AES/DES/3DES/RSA/SM2/SM4、签名、时间戳、nonce、动态 key、响应提取 key。
11. 第三方加密库必须 try/except 导入；缺失时不能导致插件整体崩溃，应 print 明确日志并保留原文继续转发。
12. 如果需要使用 mitmproxy flow，请通过 ctx._raw_flow 获取。
13. 可以使用 ctx.request_json、ctx.response_json、ctx.request_text、ctx.response_text、ctx.request_bytes、ctx.response_headers 等 Context 能力。
14. 修改 body 后要同步 Content-Length；如果改成 JSON 明文，Content-Type 可设置为 application/json; charset=utf-8。
15. 发往服务器前、发往浏览器前，都要删除只给 Burp 明文链路使用的调试头、说明字段和临时字段，避免污染真实请求/响应。

## 不可逆字段要求

1. 能解密明文到 Burp 的尽量输出明文。
2. 如果是不可逆字段，例如登录密码 MD5、SHA、HMAC、签名、摘要，decrypt 阶段不要伪造明文，保留密文/摘要值，并通过字段名、辅助字段或 print 日志标记“不可逆，已保留原值”。
3. 不可逆字段的 encrypt 不能丢：Burp 后续直接使用明文测试时，encrypt 阶段必须把 Burp 明文按原规则重新 MD5/SHA/HMAC/签名/加密后提交给服务器。
4. 如果请求里存在签名字段，Burp 修改明文字段后，encrypt 阶段必须重新计算签名、时间戳、nonce、Content-Length 等依赖字段。
5. 生成代码要尽量通过 print 日志、Burp-facing 临时说明头、Burp-facing 临时说明字段记录转换结果，让 CipherBridge 运行日志和明文详情表都能看出处理状态。
6. 为了让明文详情表记录不可逆字段，decrypt/encrypt 返回 Burp 的明文报文中可以临时添加 X-CipherBridge-Notes 头，或在 JSON/form 明文中添加 __cipherbridge_notes 字段，标明“字段 password 为 MD5 不可逆，Burp 可填写明文，encrypt 会重新 MD5 后提交”。
7. 所有 X-CipherBridge-*、__cipherbridge_*、只给 Burp 看的人类说明字段，在 encrypt request 发往服务器前、decrypt response 发往浏览器前，都必须删除，不能污染目标业务协议。

## 多层嵌套加密/签名要求

1. 如果存在多种加密、编码、压缩、签名、摘要嵌套，encrypt 阶段必须完整复现原始提交服务器的所有步骤，顺序绝对不能丢。
2. 即使最外层是不可逆摘要、签名、哈希，Burp 里仍然让用户输入明文；提交服务器前必须先执行内层可逆步骤，例如 JSON 序列化、字段 AES/SM4/RSA 加密、gzip、base64、URL 编码等，再执行外层不可逆步骤，例如 MD5/SHA/HMAC/签名，最终提交服务器的一定是完整密文协议。
3. 多层嵌套必须按原链路逆序/正序处理：
   - decrypt 展示 Burp 明文时，能逆的层尽量逆向解开，不可逆层保留原值并说明。
   - encrypt 提交服务器时，从 Burp 明文开始，按原始协议顺序依次重新生成每一层，包括内层可逆加密和最外层不可逆摘要/签名。
   - 不能因为某一层不可逆就跳过其它可逆加密步骤。
4. 如果响应中提取到动态 key、token、nonce、session seed、RSA 公钥、SM2 公钥、AES key 包装字段等，插件应使用模块级缓存记录，并在后续 encrypt request 中复用或更新。
5. 如果动态字段有过期、一次性 nonce、时间戳依赖，应在每次 encrypt request 时重新生成或从最新响应缓存中提取，不能长期写死。

## 代码稳健性要求

1. 所有加解密、解析、编码、压缩、签名逻辑必须有 try/except 保护。
2. 解析失败时不能抛异常中断代理，应保留原始请求/响应继续转发，并 print 明确错误。
3. 对 JSON、form-urlencoded、query、raw body 要分别尝试识别。
4. 对 base64、hex、URL 编码、gzip、zlib 等包装层要自动探测，失败则回退原值。
5. 修改请求或响应 body 后必须同步 Content-Length。
6. 如果删除或修改 Content-Encoding、Transfer-Encoding、Content-Type 等头，会影响 body 解释，必须同步处理。
7. 发往服务器的请求必须尽量还原真实客户端协议。
8. 发往浏览器的响应必须尽量还原真实客户端协议。
9. 返回 Burp 的请求和响应必须尽量明文化，方便手工测试和插件自动化检测。

## 用户会在下面继续提供样本

用户后续通常只提供“加密请求、密文响应”。请自行分析编码、结构、字段关系和可能的算法，必要时在代码中加入多策略自动尝试、异常保护、日志记录和可配置参数位置，直接输出完整且正确的 CipherBridge plugin.py 文件。"""


class AIGeneratorTab(QWidget):
    """无加解密方法文件时：提供 skills/提示词，粘贴外部 AI 生成的 plugin.py 并保存。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()
        self._load_saved_samples()

    def _section_title(self, text: str) -> QLabel:
        label = QLabel(text)
        font = QFont("Microsoft YaHei", 11)
        font.setBold(True)
        label.setFont(font)
        label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        label.setStyleSheet("padding: 0px 0px 2px 0px;")
        return label

    def _build_ui(self):
        body_font = QFont("Microsoft YaHei", 10)
        mono_font = QFont("Consolas", 10)
        self.setFont(body_font)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 8)
        layout.setSpacing(8)

        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.setChildrenCollapsible(False)

        usage_panel = QWidget()
        usage_panel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        usage_panel.setMinimumHeight(154)
        usage_panel.setMaximumHeight(172)
        usage_layout = QVBoxLayout(usage_panel)
        usage_layout.setContentsMargins(0, 0, 0, 0)
        usage_layout.setSpacing(4)
        usage_layout.addWidget(self._section_title("一、用法（CipherBridge IP + Burp IP 端口链路）"))
        self.usage_text = QLabel()
        self.usage_text.setFont(body_font)
        self.usage_text.setTextFormat(Qt.TextFormat.RichText)
        self.usage_text.setWordWrap(True)
        self.usage_text.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.usage_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.usage_text.setStyleSheet(
            "QLabel {border:1px solid #d8dde6; "
            "border-radius:4px; padding:8px 10px; }"
        )
        self.usage_text.setText(
            "<div style='font-family:Microsoft YaHei; font-size:10pt; line-height:1.45;'>"
            "<p style='margin:0 0 6px 0;'>"
            "1、burpsuite 监听本机IP: <b>8080</b>，尽可能都明文显示。<br>"
            "2、burpsuite 上游代理设置为本机IP: <b>8081</b>，也就是 <b>encrypt 加密端</b>，加密提交给目标服务器。<br>"
            "3、操作浏览器，代理设置为本机IP: <b>8083</b>，也就是 <b>decrypt 解密端</b>；登录或页面后自动交给 burpsuite 明文。<br>"
            "4、操作 burpsuite ，明文修改后加密提交给目标服务器，方便调用插件自动化检测和手动明文测试。"
            "</p>"
            "<p style='margin:8px 0 0 0;'>"
            "<b>请求链路：</b> 浏览器 → CipherBridge IP:8083 decrypt → Burp IP:8080 Burp 明文 → CipherBridge IP:8081 encrypt → 目标服务器<br>"
            "<b>响应链路：</b> 目标服务器 → CipherBridge IP:8081 encrypt → Burp IP:8080 Burp 明文 → CipherBridge IP:8083 decrypt → 浏览器"
            "</p>"
            "</div>"
        )
        usage_layout.addWidget(self.usage_text, 1)
        layout.addWidget(usage_panel, 0)

        skill_panel = QWidget()
        skill_panel.setMinimumHeight(210)
        skill_layout = QVBoxLayout(skill_panel)
        skill_layout.setContentsMargins(0, 0, 0, 0)
        skill_layout.setSpacing(4)
        skill_header = QHBoxLayout()
        skill_header.setContentsMargins(0, 0, 0, 0)
        skill_header.setSpacing(6)
        skill_header.addStretch(1)
        self.copy_skills_btn = QPushButton("复制skills")
        self.copy_skills_btn.clicked.connect(self.copy_skills)
        self.copy_skills_btn.setFixedWidth(92)
        skill_header.addWidget(self.copy_skills_btn)
        skill_layout.addLayout(skill_header)
        self.skill_text = QPlainTextEdit()
        self.skill_text.setReadOnly(True)
        self.skill_text.setFont(mono_font)
        self.skill_text.setPlainText(CIPHERBRIDGE_PLUGIN_SKILL_TEXT)
        self.skill_text.moveCursor(QTextCursor.MoveOperation.Start)
        skill_layout.addWidget(self.skill_text, 1)
        main_splitter.addWidget(skill_panel)

        samples_panel = QWidget()
        samples_panel.setMinimumHeight(150)
        samples_layout = QVBoxLayout(samples_panel)
        samples_layout.setContentsMargins(0, 0, 0, 0)
        samples_layout.setSpacing(4)

        packet_splitter = QSplitter(Qt.Orientation.Horizontal)
        packet_splitter.setChildrenCollapsible(False)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 4, 0)
        left_layout.setSpacing(4)
        left_layout.addWidget(self._section_title("请求包内容"))
        self.request_input = QPlainTextEdit()
        self.request_input.setFont(mono_font)
        self.request_input.setPlaceholderText("粘贴浏览器发出的加密请求包，完整 HTTP request。")
        left_layout.addWidget(self.request_input, 1)
        left_btns = QHBoxLayout()
        left_btns.setContentsMargins(0, 0, 0, 0)
        left_btns.setSpacing(6)
        self.load_request_btn = QPushButton("读取请求包")
        self.load_request_btn.clicked.connect(self.load_request_sample)
        self.save_request_btn = QPushButton("保存请求包")
        self.save_request_btn.clicked.connect(self.save_request_sample)
        left_btns.addWidget(self.load_request_btn)
        left_btns.addWidget(self.save_request_btn)
        left_btns.addStretch(1)
        left_layout.addLayout(left_btns)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(4, 0, 0, 0)
        right_layout.setSpacing(4)
        right_layout.addWidget(self._section_title("响应包内容"))
        self.response_input = QPlainTextEdit()
        self.response_input.setFont(mono_font)
        self.response_input.setPlaceholderText("粘贴服务器返回的密文响应包，完整 HTTP response。")
        right_layout.addWidget(self.response_input, 1)
        right_btns = QHBoxLayout()
        right_btns.setContentsMargins(0, 0, 0, 0)
        right_btns.setSpacing(6)
        self.load_response_btn = QPushButton("读取响应包")
        self.load_response_btn.clicked.connect(self.load_response_sample)
        self.save_response_btn = QPushButton("保存响应包")
        self.save_response_btn.clicked.connect(self.save_response_sample)
        right_btns.addWidget(self.load_response_btn)
        right_btns.addWidget(self.save_response_btn)
        right_btns.addStretch(1)
        right_layout.addLayout(right_btns)

        packet_splitter.addWidget(left)
        packet_splitter.addWidget(right)
        packet_splitter.setSizes([1, 1])
        samples_layout.addWidget(packet_splitter, 1)
        main_splitter.addWidget(samples_panel)

        main_splitter.setStretchFactor(0, 3)
        main_splitter.setStretchFactor(1, 2)
        main_splitter.setSizes([360, 230])
        layout.addWidget(main_splitter, 1)

    def _load_saved_samples(self):
        if AI_REQUEST_SAMPLE_PATH.exists():
            self.request_input.setPlainText(AI_REQUEST_SAMPLE_PATH.read_text(encoding="utf-8", errors="replace"))
        if AI_RESPONSE_SAMPLE_PATH.exists():
            self.response_input.setPlainText(AI_RESPONSE_SAMPLE_PATH.read_text(encoding="utf-8", errors="replace"))

    def copy_skills(self):
        text = (
            self.skill_text.toPlainText().strip()
            + "\n\n## 请求包内容（加密请求 / 完整 HTTP request）\n\n"
            + self.request_input.toPlainText().strip()
            + "\n\n## 响应包内容（密文响应 / 完整 HTTP response）\n\n"
            + self.response_input.toPlainText().strip()
            + "\n\n请根据上面的 skills、请求包内容、响应包内容，直接输出完整且正确的 CipherBridge plugin.py 源码。"
        )
        QApplication.clipboard().setText(text)
        QMessageBox.information(self, "已复制", "已复制：skills内容 + 请求包内容 + 响应包内容。")

    def save_request_sample(self):
        WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
        AI_REQUEST_SAMPLE_PATH.write_text(self.request_input.toPlainText(), encoding="utf-8")
        QMessageBox.information(self, "已保存", f"请求包已保存：\n{AI_REQUEST_SAMPLE_PATH}")

    def load_request_sample(self):
        if AI_REQUEST_SAMPLE_PATH.exists():
            self.request_input.setPlainText(AI_REQUEST_SAMPLE_PATH.read_text(encoding="utf-8", errors="replace"))
        else:
            QMessageBox.information(self, "未找到", f"请求包文件不存在：\n{AI_REQUEST_SAMPLE_PATH}")

    def save_response_sample(self):
        WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
        AI_RESPONSE_SAMPLE_PATH.write_text(self.response_input.toPlainText(), encoding="utf-8")
        QMessageBox.information(self, "已保存", f"响应包已保存：\n{AI_RESPONSE_SAMPLE_PATH}")

    def load_response_sample(self):
        if AI_RESPONSE_SAMPLE_PATH.exists():
            self.response_input.setPlainText(AI_RESPONSE_SAMPLE_PATH.read_text(encoding="utf-8", errors="replace"))
        else:
            QMessageBox.information(self, "未找到", f"响应包文件不存在：\n{AI_RESPONSE_SAMPLE_PATH}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(1280, 820)
        self.setMinimumSize(1100, 700)
        self.decrypt_process: QProcess | None = None
        self.encrypt_process: QProcess | None = None
        self._decrypt_user_stop = False
        self._encrypt_user_stop = False
        self._buffers: dict[str, str] = {"DECRYPT": "", "ENCRYPT": ""}
        self._http_buffers: dict[str, list[str] | None] = {"DECRYPT": None, "ENCRYPT": None}
        self._http_tags: dict[str, str] = {"DECRYPT": "", "ENCRYPT": ""}
        self._pending_log_lines: list[str] = []
        self._max_log_lines = 300
        self._mitm_line_prefix = re.compile(r"^\[\d{2}:\d{2}:\d{2}\.\d+\]\s*")
        self.state = load_state()
        ensure_project_files(self.state.get("baseurl", ""))
        self._build_ui()
        self._load_state_to_ui()
        self._log_flush_timer = QTimer(self)
        self._log_flush_timer.setInterval(100)
        self._log_flush_timer.timeout.connect(self._flush_pending_logs)
        self._log_flush_timer.start()

    def _build_ui(self):
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(8)
        self.setCentralWidget(central)

        self.top_tabs = QTabWidget()
        root.addWidget(self.top_tabs, 1)

        bridge_page = QWidget()
        bridge_layout = QVBoxLayout(bridge_page)
        bridge_layout.setContentsMargins(6, 6, 6, 6)
        bridge_layout.setSpacing(8)

        base_group = QGroupBox("当前 baseurl（decrypt / encrypt 两端只处理这个范围，静态图片/脚本/样式/字体会自动跳过）")
        grid = QGridLayout(base_group)
        self.baseurl_edit = QLineEdit()
        self.baseurl_edit.setPlaceholderText("https://example.com 或 https://example.com/api")
        self.save_baseurl_btn = QPushButton("保存 baseurl")
        self.save_baseurl_btn.clicked.connect(self.save_baseurl)
        self.listen_host_edit = QLineEdit()
        self.listen_host_edit.setPlaceholderText("例如 192.168.2.101，不要使用回环地址")
        self.listen_host_edit.setToolTip("本机网卡 IPv4：decrypt/encrypt 监听、Burp 中间明文层、encrypt 上游代理都使用这里的地址。")
        self.burp_host_edit = QLineEdit()
        self.burp_host_edit.setPlaceholderText("例如 192.168.2.108，Burp 所在 IP")
        self.burp_host_edit.setToolTip("Burp 所在主机的 IPv4；如果 Burp 就在本机，也填写本机网卡 IP，不要填 127.0.0.1。")
        self.detect_host_btn = QPushButton("自动检测本机IP")
        self.detect_host_btn.clicked.connect(self.detect_local_ip)
        grid.addWidget(QLabel("baseurl:"), 0, 0)
        grid.addWidget(self.baseurl_edit, 0, 1)
        grid.addWidget(self.save_baseurl_btn, 0, 2)
        grid.addWidget(QLabel("CipherBridge IP:"), 1, 0)
        grid.addWidget(self.listen_host_edit, 1, 1)
        grid.addWidget(self.detect_host_btn, 1, 2)
        grid.addWidget(QLabel("Burp IP:"), 2, 0)
        grid.addWidget(self.burp_host_edit, 2, 1)

        self.chain_label = QLabel(
            "链路：浏览器 → CipherBridgeIP:decrypt → Burp(明文) → CipherBridgeIP:encrypt → 服务器；"
            "服务器 → CipherBridgeIP:encrypt → Burp(明文) → CipherBridgeIP:decrypt → 浏览器"
        )
        self.chain_label.setWordWrap(True)
        grid.addWidget(self.chain_label, 3, 1, 1, 2)
        bridge_layout.addWidget(base_group)

        controls = QHBoxLayout()
        controls.addWidget(self._build_decrypt_group(), 1)
        controls.addWidget(self._build_burp_group(), 1)
        controls.addWidget(self._build_encrypt_group(), 1)
        bridge_layout.addLayout(controls)

        self.tabs = QTabWidget()
        self.traffic_tab = TrafficTable()
        self.plugin_tab = PluginEditor()
        self.tabs.addTab(self.traffic_tab, "明文详情表")
        self.tabs.addTab(self.plugin_tab, "plugin.py 编辑")
        bridge_layout.addWidget(self.tabs, 1)

        log_group = QGroupBox("运行日志")
        log_layout = QVBoxLayout(log_group)
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumHeight(150)
        self.log_view.setFont(QFont("Consolas", 9))
        try:
            self.log_view.document().setMaximumBlockCount(self._max_log_lines)
        except Exception:
            pass
        log_layout.addWidget(self.log_view)
        bridge_layout.addWidget(log_group)

        self.ai_generator_tab = AIGeneratorTab()
        self.top_tabs.addTab(bridge_page, "明文桥接")
        self.top_tabs.addTab(self.ai_generator_tab, "AI及用法")

    def _build_decrypt_group(self) -> QGroupBox:
        group = QGroupBox("decrypt 解密端")
        layout = QHBoxLayout(group)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        self.decrypt_status = QLabel("已停止")
        self.decrypt_port = QSpinBox()
        self.decrypt_port.setRange(1024, 65535)
        self.decrypt_port.setFixedWidth(92)
        self.decrypt_start_btn = QPushButton("启动 decrypt")
        self.decrypt_stop_btn = QPushButton("停止 decrypt")
        self.decrypt_stop_btn.setEnabled(False)
        self.decrypt_start_btn.clicked.connect(self.start_decrypt)
        self.decrypt_stop_btn.clicked.connect(self.stop_decrypt)
        group.setToolTip("浏览器代理指向 decrypt 端口；decrypt 解密后把明文送到中间 Burp。")
        layout.addWidget(QLabel("状态:"))
        layout.addWidget(self.decrypt_status)
        layout.addWidget(QLabel("监听端口:"))
        layout.addWidget(self.decrypt_port)
        layout.addWidget(self.decrypt_start_btn)
        layout.addWidget(self.decrypt_stop_btn)
        group.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        return group

    def _build_burp_group(self) -> QGroupBox:
        group = QGroupBox("Burp 中间明文层")
        layout = QHBoxLayout(group)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        self.burp_port = QSpinBox()
        self.burp_port.setRange(1024, 65535)
        self.burp_port.setFixedWidth(92)
        group.setToolTip(
            "Burp 放在中间：\n"
            "1. Proxy Listener 监听 Burp IP 上的此端口，接收 decrypt 发来的明文。\n"
            "2. Burp 的 Upstream Proxy 必须指向 CipherBridge IP 的 encrypt 端口 8081，而不是 decrypt 端口 8083。"
        )
        layout.addWidget(QLabel("监听端口:"))
        layout.addWidget(self.burp_port)
        layout.addWidget(QLabel("看到:"))
        layout.addWidget(QLabel("明文请求 / 明文响应"))
        group.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        return group

    def _build_encrypt_group(self) -> QGroupBox:
        group = QGroupBox("encrypt 加密端")
        layout = QHBoxLayout(group)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        self.encrypt_status = QLabel("已停止")
        self.encrypt_port = QSpinBox()
        self.encrypt_port.setRange(1024, 65535)
        self.encrypt_port.setFixedWidth(92)
        self.encrypt_start_btn = QPushButton("启动 encrypt")
        self.encrypt_stop_btn = QPushButton("停止 encrypt")
        self.encrypt_stop_btn.setEnabled(False)
        self.encrypt_start_btn.clicked.connect(self.start_encrypt)
        self.encrypt_stop_btn.clicked.connect(self.stop_encrypt)
        group.setToolTip("Burp 修改明文后，经 Upstream Proxy 发到 encrypt 端口；encrypt 重新加密后访问服务器。")
        layout.addWidget(QLabel("状态:"))
        layout.addWidget(self.encrypt_status)
        layout.addWidget(QLabel("监听端口:"))
        layout.addWidget(self.encrypt_port)
        layout.addWidget(self.encrypt_start_btn)
        layout.addWidget(self.encrypt_stop_btn)
        group.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        return group

    def _load_state_to_ui(self):
        self.baseurl_edit.setText(self.state.get("baseurl", ""))
        self.listen_host_edit.setText(self.state.get("listen_host") or detect_local_ipv4())
        self.burp_host_edit.setText(self.state.get("burp_host") or self.state.get("listen_host") or detect_local_ipv4())
        self.decrypt_port.setValue(int(self.state.get("decrypt_port", 8083)))
        self.burp_port.setValue(int(self.state.get("burp_port", 8080)))
        self.encrypt_port.setValue(int(self.state.get("encrypt_port", 8081)))

    def _state_from_ui(self) -> dict:
        return {
            "baseurl": self.baseurl_edit.text().strip(),
            "listen_host": self.listen_host_edit.text().strip(),
            "burp_host": self.burp_host_edit.text().strip(),
            "decrypt_port": self.decrypt_port.value(),
            "burp_port": self.burp_port.value(),
            "encrypt_port": self.encrypt_port.value(),
        }

    def detect_local_ip(self):
        detected = detect_local_ipv4()
        if detected:
            self.listen_host_edit.setText(detected)
            self.append_log("INFO", f"已自动检测本机IP={detected}")
        else:
            QMessageBox.warning(self, "未检测到本机IP", "未检测到可用的非回环 IPv4，请手工填写当前网卡 IP。")

    def _current_listen_host(self) -> str:
        host = normalise_local_ipv4(self.listen_host_edit.text(), auto_detect=True)
        if host:
            self.listen_host_edit.setText(host)
        return host

    def _current_burp_host(self) -> str:
        default_host = self.listen_host_edit.text().strip() or detect_local_ipv4()
        host = normalise_local_ipv4(self.burp_host_edit.text().strip() or default_host, auto_detect=True)
        if host:
            self.burp_host_edit.setText(host)
        return host

    def save_baseurl(self) -> bool:
        try:
            baseurl = _normalise_baseurl(self.baseurl_edit.text())
            if not baseurl:
                QMessageBox.warning(self, "baseurl 为空", "请填写当前目标站点 baseurl。")
                return False
        except Exception as e:
            QMessageBox.warning(self, "baseurl 无效", str(e))
            return False

        try:
            listen_host = self._current_listen_host()
            if not listen_host:
                QMessageBox.warning(self, "本机IP为空", "请填写本机网卡 IPv4，Burp 中间明文层不能走回环地址。")
                return False
            burp_host = self._current_burp_host()
            if not burp_host:
                QMessageBox.warning(self, "Burp IP为空", "请填写 Burp 所在主机 IPv4；Burp 在本机时也填写本机网卡 IP。")
                return False
        except Exception as e:
            QMessageBox.warning(self, "本机IP无效", str(e))
            return False

        try:
            self.baseurl_edit.setText(baseurl)
            ensure_project_files(baseurl)
            state = self._state_from_ui()
            state["baseurl"] = baseurl
            state["listen_host"] = listen_host
            state["burp_host"] = burp_host
            save_state(state)
            self.state = state
            self.append_log(
                "INFO",
                f"已保存 baseurl={baseurl}，CipherBridge IP={listen_host}，Burp IP={burp_host}；encrypt/decrypt 只处理该范围，静态资源自动跳过。",
            )
            return True
        except Exception as e:
            QMessageBox.warning(self, "保存失败", str(e))
            return False

    def _validate_before_start(self, role: str) -> bool:
        if not self.save_baseurl():
            return False
        ensure_project_files(self.baseurl_edit.text().strip())
        if not PLUGIN_PATH.is_file():
            QMessageBox.warning(self, "plugin.py 不存在", f"未找到：\n{PLUGIN_PATH}")
            return False
        if not _mitmdump_available():
            QMessageBox.warning(self, "未找到 mitmdump", "请安装 mitmproxy，或将 mitmdump.exe 放到程序目录。")
            return False
        host = self._current_listen_host()
        if not host:
            QMessageBox.warning(self, "本机IP无效", "请填写可连接的本机网卡 IPv4。")
            return False
        burp_host = self._current_burp_host()
        if not burp_host:
            QMessageBox.warning(self, "Burp IP无效", "请填写可连接的 Burp 主机 IPv4。")
            return False
        if not can_bind_ipv4(host):
            QMessageBox.warning(self, "本机IP不可绑定", f"{host} 不是当前机器可绑定的 IPv4，请点“自动检测本机IP”重新填写。")
            return False
        if role == "decrypt" and self.decrypt_port.value() == self.burp_port.value():
            QMessageBox.warning(self, "端口冲突", "decrypt 监听端口不能与 Burp 端口相同。")
            return False
        port = self.decrypt_port.value() if role == "decrypt" else self.encrypt_port.value()
        if is_port_in_use(host, port):
            QMessageBox.warning(self, "端口被占用", f"{role} 端口 {host}:{port} 已被占用。")
            return False
        if role == "decrypt" and not is_port_in_use(burp_host, self.burp_port.value()):
            self.append_log(
                "WARNING",
                f"Burp 端口 {burp_host}:{self.burp_port.value()} 当前无监听；如未启动 Burp，decrypt 转发会失败。",
            )
        return True

    def _launch(self, role: str, port: int) -> QProcess | None:
        host = self._current_listen_host()
        burp_host = self._current_burp_host()
        env_map = {
            "PYTHONPATH": str(PROJECT_ROOT),
            "PROFILE": PROFILE_NAME,
            "PROXY_ROLE": role,
            "BASEURL": self.baseurl_edit.text().strip(),
            "LOG_HTTP": "1",
            "LISTEN_HOST": host,
            "BURP_HOST": burp_host,
            "ENCRYPT_PORT": str(self.encrypt_port.value()),
            "BURP_CONNECT_TIMEOUT": "5",
            "BURP_READ_TIMEOUT": "60",
            "PYTHONUTF8": "1",
            "PYTHONIOENCODING": "utf-8",
        }
        if role == "decrypt":
            env_map["BURP_PORT"] = str(self.burp_port.value())
        args = [
            "-s",
            str(MAIN_SCRIPT),
            "--listen-host",
            host,
            "-p",
            str(port),
            "--set",
            "flow_detail=0",
            "--ssl-insecure",
        ]
        if role == "decrypt":
            args.extend(["--mode", f"upstream:http://{burp_host}:{self.burp_port.value()}"])
        process = QProcess(self)
        env = QProcessEnvironment.systemEnvironment()
        for key, value in env_map.items():
            env.insert(key, value)
        process.setProcessEnvironment(env)
        process.setWorkingDirectory(str(PROJECT_ROOT))
        process.setProgram(_resolve_mitmdump())
        process.setArguments(args)
        process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        tag = role.upper()
        process.readyReadStandardOutput.connect(lambda p=process, t=tag: self._on_output(p, t))
        return process

    def start_decrypt(self):
        if not self._validate_before_start("decrypt"):
            return
        encrypt_running = (
            self.encrypt_process is not None
            and self.encrypt_process.state() != QProcess.ProcessState.NotRunning
        )
        if not encrypt_running:
            self.append_log(
                "WARNING",
                f"encrypt 端当前未运行，将先启动 encrypt {self._current_listen_host()}:{self.encrypt_port.value()}，再启动 decrypt。",
            )
            self.start_encrypt()
            encrypt_running = (
                self.encrypt_process is not None
                and self.encrypt_process.state() != QProcess.ProcessState.NotRunning
            )
            if not encrypt_running:
                QMessageBox.warning(
                    self,
                    "encrypt 启动失败",
                    "decrypt 启动前必须先确保 encrypt 端已在监听。\n"
                    f"请检查 {self._current_listen_host()}:{self.encrypt_port.value()} 是否可用。",
                )
                return
        self.decrypt_process = self._launch("decrypt", self.decrypt_port.value())
        self.decrypt_process.finished.connect(lambda c, s: self._on_finished("decrypt", c))
        self.decrypt_process.start()
        if not self.decrypt_process.waitForStarted(5000):
            QMessageBox.warning(self, "decrypt 启动失败", self.decrypt_process.errorString())
            self.decrypt_process = None
            return
        self._set_running("decrypt", True)
        host = self._current_listen_host()
        burp_host = self._current_burp_host()
        self.append_log(
            "INFO",
            f"decrypt 已启动：浏览器代理 -> {host}:{self.decrypt_port.value()}，转发 Burp -> {burp_host}:{self.burp_port.value()}",
        )

    def start_encrypt(self):
        if not self._validate_before_start("encrypt"):
            return
        self.encrypt_process = self._launch("encrypt", self.encrypt_port.value())
        self.encrypt_process.finished.connect(lambda c, s: self._on_finished("encrypt", c))
        self.encrypt_process.start()
        if not self.encrypt_process.waitForStarted(5000):
            QMessageBox.warning(self, "encrypt 启动失败", self.encrypt_process.errorString())
            self.encrypt_process = None
            return
        self._set_running("encrypt", True)
        host = self._current_listen_host()
        self.append_log(
            "INFO",
            f"encrypt 已启动：Burp Upstream Proxy -> {host}:{self.encrypt_port.value()}；仅处理 baseurl={self.baseurl_edit.text().strip()}",
        )

    def stop_decrypt(self):
        self._decrypt_user_stop = True
        self._stop_process("decrypt")

    def stop_encrypt(self):
        self._encrypt_user_stop = True
        self._stop_process("encrypt")

    def _stop_process(self, role: str):
        proc = self.decrypt_process if role == "decrypt" else self.encrypt_process
        if proc and proc.state() != QProcess.ProcessState.NotRunning:
            proc.terminate()
            QTimer.singleShot(3000, proc.kill)

    def _stop_all_listeners_for_exit(self) -> None:
        """窗口关闭时快速停止 encrypt/decrypt，避免 GUI 卡死。"""
        try:
            save_state(self._state_from_ui())
        except Exception:
            pass
        for role, proc in (("decrypt", self.decrypt_process), ("encrypt", self.encrypt_process)):
            if not proc or proc.state() == QProcess.ProcessState.NotRunning:
                continue
            try:
                if role == "decrypt":
                    self._decrypt_user_stop = True
                else:
                    self._encrypt_user_stop = True
                try:
                    self.append_log("INFO", f"正在关闭 {role} 端进程...")
                except Exception:
                    pass
                proc.terminate()
                proc.kill()
            except Exception:
                pass

    def _set_running(self, role: str, running: bool):
        if role == "decrypt":
            self.decrypt_status.setText("运行中" if running else "已停止")
            self.decrypt_start_btn.setEnabled(not running)
            self.decrypt_stop_btn.setEnabled(running)
            self.decrypt_port.setEnabled(not running)
            self.burp_port.setEnabled(not running)
        else:
            self.encrypt_status.setText("运行中" if running else "已停止")
            self.encrypt_start_btn.setEnabled(not running)
            self.encrypt_stop_btn.setEnabled(running)
            self.encrypt_port.setEnabled(not running)

    def _on_finished(self, role: str, code: int):
        user_stop = self._decrypt_user_stop if role == "decrypt" else self._encrypt_user_stop
        if role == "decrypt":
            self._decrypt_user_stop = False
            self.decrypt_process = None
        else:
            self._encrypt_user_stop = False
            self.encrypt_process = None
        self._set_running(role, False)
        level = "INFO" if user_stop or code == 0 else "ERROR"
        self.append_log(level, f"{role} 已停止，exit_code={code}")

    def _on_output(self, process: QProcess, tag: str):
        chunk = process.readAllStandardOutput().data().decode("utf-8", errors="replace")
        self._buffers[tag] += chunk
        while "\n" in self._buffers[tag]:
            line, rest = self._buffers[tag].split("\n", 1)
            self._buffers[tag] = rest
            self._process_line(tag, line.rstrip("\r"))

    def _process_line(self, tag: str, line: str):
        line = self._mitm_line_prefix.sub("", line)
        if HTTP_LOG_BEGIN in line:
            idx = line.index(HTTP_LOG_BEGIN)
            self._http_tags[tag] = line[idx + len(HTTP_LOG_BEGIN):].strip()
            self._http_buffers[tag] = []
            return
        if line.strip() == HTTP_LOG_END:
            buf = self._http_buffers.get(tag)
            if buf is not None:
                message = "\n".join(buf)
                self.traffic_tab.add_http_record(self._http_tags.get(tag, ""), message, tag)
            self._http_buffers[tag] = None
            self._http_tags[tag] = ""
            return
        if self._http_buffers.get(tag) is not None:
            self._http_buffers[tag].append("" if line.strip() == HTTP_LOG_BLANK else line)
            return
        if line.strip():
            self.append_log("INFO", f"[{tag}] {line.strip()}")

    def append_log(self, level: str, message: str):
        now = datetime.now().strftime("%H:%M:%S")
        self._pending_log_lines.append(f"{now} [{level}] {message}")
        if len(self._pending_log_lines) > self._max_log_lines:
            self._pending_log_lines = self._pending_log_lines[-self._max_log_lines:]
        if len(self._pending_log_lines) >= 40:
            self._flush_pending_logs()

    def _flush_pending_logs(self):
        if not self._pending_log_lines:
            return
        lines = self._pending_log_lines
        self._pending_log_lines = []
        text = "\n".join(lines) + "\n"
        self.log_view.setUpdatesEnabled(False)
        try:
            cursor = self.log_view.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            cursor.insertText(text)
            self.log_view.setTextCursor(cursor)
            self.log_view.ensureCursorVisible()
        finally:
            self.log_view.setUpdatesEnabled(True)

    def _kill_process_tree(self, proc: QProcess | None, role: str) -> None:
        """强制结束 QProcess 及其子进程树，防止窗口关闭后残留 mitmdump/python。"""
        if not proc or proc.state() == QProcess.ProcessState.NotRunning:
            return
        try:
            pid = int(proc.processId())
        except Exception:
            pid = 0
        try:
            proc.terminate()
        except Exception:
            pass
        if pid > 0:
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    timeout=5,
                )
            except Exception:
                pass
        try:
            proc.kill()
        except Exception:
            pass

    def _cleanup_on_exit(self) -> None:
        """统一的退出清理入口，供 closeEvent / aboutToQuit 调用。"""
        self._decrypt_user_stop = True
        self._encrypt_user_stop = True
        try:
            save_state(self._state_from_ui())
        except Exception:
            pass
        try:
            if hasattr(self, "_log_flush_timer"):
                self._log_flush_timer.stop()
        except Exception:
            pass
        try:
            self._flush_pending_logs()
        except Exception:
            pass
        self._kill_process_tree(self.decrypt_process, "decrypt")
        self._kill_process_tree(self.encrypt_process, "encrypt")
        self.decrypt_process = None
        self.encrypt_process = None

    def closeEvent(self, event):
        self._cleanup_on_exit()
        event.accept()


def main():
    try:
        ensure_project_files()
        app = QApplication(sys.argv)
        win = MainWindow()
        win.show()
        sys.exit(app.exec())
    except Exception as e:
        traceback.print_exc()
        try:
            QMessageBox.critical(None, "启动失败", f"{e}\n\n请查看终端完整错误。")
        except Exception:
            pass
        sys.exit(1)


if __name__ == "__main__":
    main()
