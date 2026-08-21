"""CipherBridge 本机网络地址辅助函数。

所有本地链路地址都应使用网卡 IPv4，而不是回环地址：

浏览器 -> 本机IP:decrypt_port -> 本机IP:burp_port -> 本机IP:encrypt_port -> 目标服务器
"""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess


_RFC1918_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def _append_unique(values: list[str], value: str | None) -> None:
    value = (value or "").strip()
    if value and value not in values:
        values.append(value)


def _ipv4(value: str) -> ipaddress.IPv4Address | None:
    try:
        ip = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None
    return ip if isinstance(ip, ipaddress.IPv4Address) else None


def is_usable_local_ipv4(value: str) -> bool:
    """判断是否适合作为 CipherBridge 本地链路地址。"""
    ip = _ipv4(value)
    if ip is None:
        return False
    return not (
        ip.is_loopback
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_link_local
    )


def is_rfc1918_ipv4(value: str) -> bool:
    ip = _ipv4(value)
    return bool(ip and any(ip in network for network in _RFC1918_NETS))


def collect_local_ipv4_candidates() -> list[str]:
    """收集当前机器上的 IPv4 候选地址，尽量覆盖 Windows 多网卡场景。"""
    candidates: list[str] = []

    # psutil 如果存在，能最准确列出网卡地址；没有也不影响运行。
    try:
        import psutil  # type: ignore

        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                if getattr(addr, "family", None) == socket.AF_INET:
                    _append_unique(candidates, getattr(addr, "address", ""))
    except Exception:
        pass

    # hostname / fqdn 解析能覆盖多数普通桌面环境。
    for host in {socket.gethostname(), socket.getfqdn()}:
        if not host:
            continue
        try:
            for item in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM):
                _append_unique(candidates, item[4][0])
        except Exception:
            pass
        try:
            for value in socket.gethostbyname_ex(host)[2]:
                _append_unique(candidates, value)
        except Exception:
            pass

    # Windows 下解析 ipconfig 输出，兼容英文/中文系统。
    try:
        output = subprocess.check_output(
            ["ipconfig"],
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=3,
        )
        for line in output.splitlines():
            if "IPv4" not in line:
                continue
            match = re.search(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})", line)
            if match:
                _append_unique(candidates, match.group(1))
    except Exception:
        pass

    return candidates


def detect_local_ipv4() -> str:
    """优先返回 RFC1918 网卡 IPv4；否则返回第一个非回环 IPv4。"""
    candidates = collect_local_ipv4_candidates()
    for value in candidates:
        if is_usable_local_ipv4(value) and is_rfc1918_ipv4(value):
            return str(_ipv4(value))
    for value in candidates:
        if is_usable_local_ipv4(value):
            return str(_ipv4(value))
    return ""


def normalise_local_ipv4(text: str, *, auto_detect: bool = True) -> str:
    """规范化 GUI 输入的本机 IPv4。

    支持用户误粘贴 ``http://192.168.1.10:8080`` 或 ``192.168.1.10:8080``，
    最终只返回 IP 部分。
    """
    raw = (text or "").strip()
    if not raw and auto_detect:
        raw = detect_local_ipv4()
    if not raw:
        return ""

    match = re.search(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})", raw)
    host = match.group(1) if match else raw
    ip = _ipv4(host)
    if ip is None:
        raise ValueError("本机IP必须是 IPv4 地址，例如：192.168.2.101。")
    if ip.is_loopback:
        raise ValueError("本机IP不能使用回环地址，请填写当前网卡 IPv4。")
    if ip.is_unspecified:
        raise ValueError("本机IP不能使用 0.0.0.0；Burp 明文层需要可连接的网卡 IPv4。")
    if ip.is_multicast or ip.is_link_local:
        raise ValueError("本机IP必须是当前机器可连接的网卡 IPv4。")
    return str(ip)


def can_bind_ipv4(host: str) -> bool:
    """检查该 IPv4 是否是本机可绑定地址。"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, 0))
        return True
    except OSError:
        return False


def is_port_in_use(host: str, port: int) -> bool:
    """按指定本机 IP 检查端口是否已有监听。"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.25)
            return sock.connect_ex((host, int(port))) == 0
    except OSError:
        return False
