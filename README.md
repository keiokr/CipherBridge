# CipherBridgeV22
CipherBridgeV22
# CipherBridge明文桥接
CipherBridge明文桥接

一、软件设置<br>
1、你先用ai写好 plugin.py<br>
2、然后 baseurl设置为加密解密目标站点<br>
3、CipherBridge 设置本机ip（192.168.2.101），不要设置127.0.0.1<br>
4)	Burpsuite可以是本机 也可以是你局域网其他机器ip(192.168.2.108），<br>
不要设置127.0.0.1<br>
 <img width="1389" height="685" alt="image" src="https://github.com/user-attachments/assets/ea4040a8-2da8-4273-ac9f-18611413e154" />

<img width="1585" height="1010" alt="image" src="https://github.com/user-attachments/assets/4b4dc20f-2247-4fe1-a86f-f7e83e248b3b" />


⦁	burpsuite设置<br>
1)	burp监听 8080<br>
 <img width="1370" height="600" alt="image" src="https://github.com/user-attachments/assets/f25b6b54-c94d-4a64-867f-1ba780158fa4" />
<br>
1)	burp设置上有代理设置 CipherBridge的8081端口 （加密端口）<br>
 <img width="1379" height="610" alt="image" src="https://github.com/user-attachments/assets/dd2fa954-4cb8-4633-91ae-0e002ebc76ea" />
<br>
⦁	浏览器设置<br>
 CipherBridge的8083端口 （解密端口）<br>


 <img width="1336" height="424" alt="image" src="https://github.com/user-attachments/assets/42db4f79-b31f-4f27-94bd-4384109bc6b8" /><br>
浏览器操作全部burp里面明文显示，因为经过（解密端）所以burp里面全部都是明文。
<br>
<img width="1060" height="759" alt="image" src="https://github.com/user-attachments/assets/3fdd162c-6dde-47c4-867e-71623a399e14" />
<br>
直接操作burpsuite 里面明文，因为经过（加密端），所以明文提交都是经过加密能正常被目标识别。然后返回会经过解密，所以burp响应包全部也是明文显示。
 <br>
 
# ai适配CipherBridge生成完整且正确plugin.py文件提示词skills。

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

用户后续通常只提供“加密请求、密文响应”。请自行分析编码、结构、字段关系和可能的算法，必要时在代码中加入多策略自动尝试、异常保护、日志记录和可配置参数位置，直接输出完整且正确的 CipherBridge plugin.py 文件。

## 请求包内容（加密请求 / 完整 HTTP request）

111

## 响应包内容（密文响应 / 完整 HTTP response）

2222

请根据上面的 skills、请求包内容、响应包内容，直接输出完整且正确的 CipherBridge plugin.py 源码。
