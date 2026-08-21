""" mitmproxy plugin for CipherBridge.

当前文件是 CipherBridge 可直接保存/加载的 plugin.py 格式：
    def request(ctx) -> None
    def response(ctx) -> None

链路目标：
    浏览器 -> decrypt -> Burp(明文) -> encrypt -> 服务器
    服务器 -> encrypt -> Burp(明文) -> decrypt -> 浏览器

来源逻辑：
    从 gdmp_crypto_helper.py 的 GDMP DataObfuscator / gzip / base64 / query/body
    加解密、vendor-gdmp-common*.js patch、X-Ca-Grt 刷新逻辑转换而来。
"""
