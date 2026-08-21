"""Mitm引擎 — mitmproxy addon，核心入口.

端口职责:
  8082 解密端 (PROXY_ROLE=decrypt): request() 解密请求体 → 转发Burp
  8081 加密端 (PROXY_ROLE=encrypt): request() 加密请求体+签名 → 转发服务器
  Burp 默认 8080

插件标准: def request(ctx) / def response(ctx)
环境变量:
  PROFILE  — GUI 指定项目名时跳过自动匹配
  PROXY_ROLE — decrypt | encrypt
  LISTEN_HOST — decrypt / encrypt 监听的本机网卡 IP
  BURP_HOST — 解密端转发到 Burp 中间明文层的本机网卡 IP
  BURP_PORT — 解密端 Burp 端口
  ENCRYPT_PORT — Burp Upstream Proxy 指向的 encrypt 端端口
  BURP_CONNECT_TIMEOUT / BURP_READ_TIMEOUT — decrypt 等待 Burp 的连接/读取超时
"""

import inspect
import os
import sys
import logging
import requests
import urllib.parse
from mitmproxy import http

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.context import Context
from core.http_message import log_http_message
from core.plugin_loader import PluginLoader
from core.match_rules import is_static_resource
from core.net_utils import detect_local_ipv4

APP_NAME = "CipherBridge"

logger = logging.getLogger(__name__)


def _cp_log(msg: str) -> None:
    """输出到 mitmdump stdout，确保 GUI 日志 Tab 可见."""
    print(f"[{APP_NAME}] {msg}", flush=True)
    logger.info(msg)


class MitmEngine:
    def __init__(self):
        self.loader = PluginLoader()
        self.loader.load_all_profiles()
        self.role = os.environ.get("PROXY_ROLE", "decrypt")
        self.listen_host = (
            os.environ.get("LISTEN_HOST")
            or os.environ.get("LOCAL_IP")
            or detect_local_ipv4()
        ).strip()
        self.burp_host = (
            os.environ.get("BURP_HOST")
            or self.listen_host
            or detect_local_ipv4()
        ).strip()
        self.burp_port = os.environ.get("BURP_PORT", "8080")
        self.encrypt_port = os.environ.get("ENCRYPT_PORT", "8081")
        try:
            self.burp_connect_timeout = float(os.environ.get("BURP_CONNECT_TIMEOUT", "5"))
        except Exception:
            self.burp_connect_timeout = 5.0
        try:
            self.burp_read_timeout = float(os.environ.get("BURP_READ_TIMEOUT", "60"))
        except Exception:
            self.burp_read_timeout = 60.0
        if self.burp_read_timeout < 10:
            self.burp_read_timeout = 10.0
        self.forced_profile = os.environ.get("PROFILE", "").strip()
        self.baseurl = (os.environ.get("BASEURL") or os.environ.get("BASE_URL") or "").strip().rstrip("/")
        self._baseurl_skip_logged = 0
        self._static_skip_logged = 0
        if self.role == "decrypt":
            route_desc = f"浏览器 → decrypt → Burp({self.burp_host or '(未指定)'}:{self.burp_port})"
        else:
            route_desc = "Burp → encrypt → 目标服务器"
        _cp_log(
            f"MitmEngine 已初始化 | role={self.role} | profile={self.forced_profile or '(auto)'} "
            f"| listen={self.listen_host or '(未指定)'} | baseurl={self.baseurl or '(未限定)'} "
            f"| route={route_desc}"
        )

    def _baseurl_allowed(self, flow: http.HTTPFlow) -> bool:
        """加密/解密两端都只处理当前 baseurl 范围内的请求."""
        if not self.baseurl:
            return True
        try:
            base = urllib.parse.urlparse(self.baseurl)
            if not base.netloc:
                base = urllib.parse.urlparse("https://" + self.baseurl)
            req_host = (flow.request.host or "").lower()
            base_host = (base.hostname or "").lower()
            if not base_host or req_host != base_host:
                return False
            if base.scheme and flow.request.scheme and base.scheme.lower() != flow.request.scheme.lower():
                return False
            base_port = base.port
            if base_port and flow.request.port and base_port != flow.request.port:
                return False
            base_path = base.path or "/"
            if base_path != "/":
                base_path = base_path.rstrip("/")
                req_path = urllib.parse.urlparse(flow.request.path or "/").path
                if req_path != base_path and not req_path.startswith(base_path + "/"):
                    return False
            return True
        except Exception:
            return True

    def _is_static(self, flow: http.HTTPFlow) -> bool:
        return is_static_resource(
            flow.request.path,
            flow.request.headers.get("Content-Type", ""),
            flow.request.headers.get("Accept", ""),
        )

    def _resolve_profile(self, flow: http.HTTPFlow) -> str:
        if not self._baseurl_allowed(flow):
            if self._baseurl_skip_logged < 5:
                self._baseurl_skip_logged += 1
                _cp_log(
                    f"跳过(非当前baseurl): {flow.request.method} {flow.request.pretty_url} "
                    f"| 当前 baseurl={self.baseurl}"
                )
            return ""
        if self._is_static(flow):
            if self._static_skip_logged < 5:
                self._static_skip_logged += 1
                _cp_log(f"跳过(静态资源): {flow.request.method} {flow.request.host}{flow.request.path}")
            return ""
        if self.forced_profile:
            cfg = self.loader.get_profile_config(self.forced_profile)
            if not self.baseurl:
                self.baseurl = (cfg.get("baseurl") or "").strip().rstrip("/")
            if self.loader.profile_matches(self.forced_profile, flow):
                return self.forced_profile
            return ""
        return self.loader.match_profile(flow)

    def _invoke_plugin_handler(self, handler, flow: http.HTTPFlow):
        """兼容 request(ctx) 与 request(flow) 两种插件风格."""
        params = list(inspect.signature(handler).parameters.values())
        if params and params[0].name == "flow":
            handler(flow)
        else:
            ctx = Context(flow)
            ctx._role = self.role
            handler(ctx)

    def _call_plugin(self, profile_name: str, flow: http.HTTPFlow, phase: str):
        plugin = self.loader.load_plugin(profile_name)
        if not plugin:
            logger.error("无法加载插件: %s", profile_name)
            return
        cfg = self.loader.get_profile_config(profile_name)
        roles = cfg.get("roles") or ["decrypt", "encrypt"]
        if self.role not in roles:
            logger.warning(
                "[%s] 当前为 %s 端，但项目 roles=%s，插件可能不会修改请求体",
                profile_name, self.role, roles,
            )
        handler = getattr(plugin, phase, None)
        if not handler:
            return
        if phase == "response":
            before_content = flow.response.content or b"" if flow.response is not None else b""
            body_name = "响应体"
        else:
            before_content = flow.request.content or b""
            body_name = "请求体"
        try:
            logger.info("[%s][%s] 调用 plugin.%s()", profile_name, self.role, phase)
            self._invoke_plugin_handler(handler, flow)
            if phase == "response":
                after_content = flow.response.content or b"" if flow.response is not None else b""
            else:
                after_content = flow.request.content or b""
            if before_content != after_content:
                _cp_log(
                    f"[{profile_name}][{self.role}] {body_name}已修改 "
                    f"({len(before_content)} → {len(after_content)} bytes)"
                )
                try:
                    preview = after_content.decode("utf-8")[:240]
                    _cp_log(f"{body_name}预览: {preview}")
                except Exception:
                    pass
            else:
                _cp_log(
                    f"[{profile_name}][{self.role}] {body_name}未修改"
                    "（普通明文/无需加解密时这是正常现象，按当前链路继续转发）"
                )
            logger.info(
                "[%s][%s] %s 完成: %s %s",
                profile_name, self.role, phase, flow.request.method, flow.request.path,
            )
        except Exception as e:
            import traceback
            _cp_log(f"[{profile_name}] {phase} 处理异常: {e}")
            _cp_log(traceback.format_exc())
            logger.error("[%s] %s 处理异常: %s", profile_name, phase, e)

    def _handle_response(self, profile_name: str, flow: http.HTTPFlow) -> None:
        if getattr(flow, "_cryptoproxy_response_logged", False):
            return
        self._call_plugin(profile_name, flow, "response")
        log_http_message(flow, "response", self.role, profile_name)
        flow._cryptoproxy_response_logged = True

    def request(self, flow: http.HTTPFlow) -> None:
        profile_name = self._resolve_profile(flow)
        if not profile_name:
            _cp_log(
                f"未匹配项目，跳过: {flow.request.method} {flow.request.host}{flow.request.path}"
                f" （请检查 profiles 匹配规则 / 左侧「规则」）"
            )
            return
        _cp_log(f"处理请求: {profile_name} | {flow.request.method} {flow.request.host}{flow.request.path}")
        self._call_plugin(profile_name, flow, "request")
        log_http_message(flow, "request", self.role, profile_name)

        if flow.response is not None:
            self._handle_response(profile_name, flow)

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        profile_name = self._resolve_profile(flow)
        if not profile_name:
            return
        self._handle_response(profile_name, flow)

    def _prepare_forward_headers(self, flow: http.HTTPFlow) -> dict:
        """修正转发头 — 同步修改后的 Content-Length / Host."""
        headers = dict(flow.request.headers)
        for h in ("Connection", "Transfer-Encoding", "Proxy-Connection", "Keep-Alive", "Content-Length"):
            headers.pop(h, None)
        headers["Connection"] = "close"
        host = flow.request.host
        port = flow.request.port
        if (flow.request.scheme == "https" and port != 443) or (
            flow.request.scheme == "http" and port != 80
        ):
            headers["Host"] = f"{host}:{port}"
        else:
            headers["Host"] = host
        content = flow.request.content or b""
        if content:
            headers["Content-Length"] = str(len(content))
        return headers

    def _forward_to_burp(self, flow: http.HTTPFlow):
        """解密端: 用 requests 将修改后的请求经 Burp 代理转发（与用户脚本一致）."""
        body = flow.request.content or b""
        headers = self._prepare_forward_headers(flow)
        if not self.burp_host:
            msg = "BURP_HOST 未设置，无法确定 Burp 中间明文层地址"
            _cp_log(msg)
            flow.response = http.Response.make(
                502,
                msg.encode("utf-8"),
                {"Content-Type": "text/plain; charset=utf-8"},
            )
            return
        burp_url = f"http://{self.burp_host}:{self.burp_port}"
        proxies = {"http": burp_url, "https": burp_url}
        target_url = flow.request.url

        _cp_log(f"requests → Burp {burp_url} | {flow.request.method} {target_url} | body {len(body)} bytes")
        try:
            _cp_log(f"转发 body: {body.decode('utf-8')[:300]}")
        except Exception:
            pass

        try:
            session = requests.Session()
            session.trust_env = False
            burp_resp = session.request(
                method=flow.request.method,
                url=target_url,
                headers=headers,
                data=body,
                allow_redirects=False,
                proxies=proxies,
                timeout=(self.burp_connect_timeout, self.burp_read_timeout),
                verify=False,
            )
            flow.response = http.Response.make(
                burp_resp.status_code,
                burp_resp.content,
                {k: v for k, v in burp_resp.headers.items()},
            )
            _cp_log(f"Burp 响应: {burp_resp.status_code} ({len(burp_resp.content)} bytes)")
        except requests.exceptions.ConnectTimeout as e:
            import traceback
            _cp_log(f"转发到 Burp 连接超时: {e}")
            _cp_log(f"请检查 Burp Proxy Listener 是否真正监听 {self.burp_host}:{self.burp_port}")
            _cp_log(traceback.format_exc())
            logger.error("转发到Burp连接超时: %s", e)
            body_text = (
                "CipherBridge 转发到 Burp 中间明文层失败。\n"
                f"Burp 地址: {self.burp_host}:{self.burp_port}\n"
                f"错误: {e}\n"
                "说明：CipherBridge 还没有连上 Burp Listener。请先确认 Burp 监听地址/端口、防火墙，以及 Burp 的 Listener 绑定的是 Burp 主机本机网卡 IP，而不是 127.0.0.1。"
            )
            flow.response = http.Response.make(
                502,
                body_text.encode("utf-8"),
                {"Content-Type": "text/plain; charset=utf-8"},
            )
        except requests.exceptions.ReadTimeout as e:
            import traceback
            _cp_log(f"转发到 Burp 等待响应超时: {e}")
            _cp_log(
                "常见原因：Burp 的 Intercept 仍然开启、Burp Upstream Proxy 未指向 encrypt 端 "
                f"{self.listen_host}:{self.encrypt_port}、"
                "或 encrypt/目标服务器响应较慢。"
            )
            _cp_log(traceback.format_exc())
            logger.error("转发到Burp读取超时: %s", e)
            body_text = (
                "CipherBridge 已把请求送到 Burp，但 Burp 没有在预设时间内返回响应。\n"
                f"Burp 地址: {self.burp_host}:{self.burp_port}\n"
                f"等待超时: {self.burp_read_timeout:.1f}s\n"
                f"错误: {e}\n"
                "优先检查：1) Burp Intercept 是否关闭；2) Burp Upstream Proxy 是否指向 CipherBridge encrypt 端；"
                "3) encrypt 端是否在监听并可达。"
            )
            flow.response = http.Response.make(
                504,
                body_text.encode("utf-8"),
                {"Content-Type": "text/plain; charset=utf-8"},
            )
        except Exception as e:
            import traceback
            _cp_log(f"转发到 Burp 失败: {e}")
            _cp_log(f"请检查 Burp Proxy Listener 是否监听 {self.burp_host}:{self.burp_port}")
            _cp_log(traceback.format_exc())
            logger.error("转发到Burp失败: %s", e)
            body_text = (
                "CipherBridge 转发到 Burp 中间明文层失败。\n"
                f"Burp 地址: {self.burp_host}:{self.burp_port}\n"
                f"错误: {e}\n"
                "已阻断默认直连服务器，避免 Burp HTTP history 为空时误以为已过 Burp。"
            )
            flow.response = http.Response.make(
                502,
                body_text.encode("utf-8"),
                {"Content-Type": "text/plain; charset=utf-8"},
            )

    def _forward_to_server(self, flow: http.HTTPFlow):
        """加密端: 将修改后的请求转发到真实服务器."""
        try:
            session = requests.Session()
            session.trust_env = False
            server_resp = session.request(
                method=flow.request.method,
                url=flow.request.url,
                headers=self._prepare_forward_headers(flow),
                data=flow.request.content,
                allow_redirects=False,
                timeout=30,
                verify=False,
            )
            flow.response = http.Response.make(
                server_resp.status_code,
                server_resp.content,
                {k: v for k, v in server_resp.headers.items()},
            )
            logger.debug("转发到服务器成功: %s -> %s", flow.request.url, server_resp.status_code)
        except Exception as e:
            logger.error("转发到服务器失败: %s", e)
