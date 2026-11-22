# 低内存 NAT VPS 的 sing-box 和 Xray 安装器

## NAT 直连 HTTPS 与端口预检

在实际使用的 Windows 客户端运行 `Test-NatRelayTcp.ps1 -HostName 域名`，可自动读取旁边的本机面板清单 `NatRelayTcp.local.json`。配置示例为 `{"host":"nat.example.com","mappings":[{"public":10880,"internal":443,"role":"proxy"}]}`。修改面板后需同步更新本机清单。也可以通过 `-PublicPorts 10880,10881` 指定面板已分配的 TCP 端口。脚本列出当前能完成握手的端口，并单独标出已有的内部 `443` 映射。共享入口的 TCP 握手可能来自其他服务，未建立映射或未启动服务的端口也可能超时。下一阶段通过本 VPS 的 HTTPS 验证码确认实际转发。

准备解析到服务商公网入口的域名。安装器默认读取 `/etc/letsencrypt/live/域名/fullchain.pem` 和 `privkey.pem`，也可用 `--cert` 和 `--key` 指定文件。如果本机没有证书，脚本自动生成 30 天的临时证书。探测核对公钥指纹，节点链接携带 `pcs` 证书指纹，需使用支持该字段的 Xray 客户端。普通浏览器仍会提示临时证书未受信任。只有高位公网端口时，可以通过 DNS-01 签发公开受信任证书。

```bash
sudo bash nat-relay.sh --nat-web nat.example.com --public-ports 10880,10881 --listen-port 443
```

候选端口取自面板已分配的 TCP 端口。按 VPS 终端提示，先把候选公网端口临时映射到同一个空闲的 VPS 内部端口，面板只允许一条规则时可逐个测试。从实际使用的客户端网络运行 VPS 输出的 Windows PowerShell 探测命令，确认输出中列为 `Verified` 的端口并保留对应映射。临时 HTTPS 探测服务验证本次验证码，收到选择后停止，随后才部署 Caddy 和 Xray。

部署结果包含网页地址和 `vless://…#NAT-HTTPS` 链接。公网映射使用所选端口，服务监听 `--listen-port` 指定的内部端口。Caddy 提供 HTTPS 网页和 WebSocket 反代，Xray 只监听回环，拒绝 UDP 转发。此模式不经过 CDN，不申请隧道域名，也不启用 HTTP/3。需要具有面板映射权限的用户建立或保留转发规则。证书更新后应同步更新 Caddy 服务配置。

### 更换公网端口

已部署 NAT HTTPS 时，把面板分配的新候选公网 TCP 端口转发到原来的 VPS 内部端口。旧映射可先保留。

```bash
sudo bash nat-relay.sh --switch-web-port --public-ports 10881,10882
```

运行 VPS 输出的 PowerShell 命令。它会验证各端口的 TLS 和现有 WebSocket 握手。把一个 `Verified` 端口填回 VPS，脚本将重新输出节点链接。换端口保留域名、证书、UUID 和内部端口，服务继续运行。导入并验证新链接后，可从面板移除旧映射。

## HTTPS 443 接入

在 VPS 上运行 `bash nat-relay.sh --check-egress` 可探测 ngrok 的 TCP 443 和 Cloudflare 的 TCP 7844。这个命令只发起 DNS 查询和 TCP 握手。面板的常规入站端口映射与出站访问权限独立。若服务商还限制出站，需要在上游开通所选连接器的目标端口。

使用 ngrok 控制台分配的开发域名，在 VPS 的交互终端运行以下命令。使用 `--origin-port 0` 时，脚本会复用已安装服务的本地端口，或选一个空闲的回环端口。安装器会隐藏输入 authtoken，验证公网 HTTPS 和 WebSocket 后输出 VLESS 链接。

```bash
sudo bash nat-relay.sh --https-edge your-domain.ngrok-free.dev --origin-port 0
```

客户端连接公网域名的 HTTPS/TCP 443。VPS 上的 ngrok 代理通过出站 TCP 443 建立隧道，并转发至仅监听回环地址的 Xray。VLESS Encryption 保护网关到客户端之间的代理负载，导入链接时使用支持该功能的 Xray 内核。此模式拒绝 UDP 转发，DNS 查询和 ngrok 域名解析仍取决于各设备的解析器设置。VPS 面板无需配置入站端口转发。部署后可通过 `systemctl status nat-relay-ngrok nat-relay-wss` 检查两项服务。

VPS 需要能访问 ngrok 的出站 TCP 443，客户端也需要能访问所分配的 HTTPS 域名。免费套餐有流量额度。[ngrok 出站连接说明](https://ngrok.com/docs/gateway/site-to-site-connectivity/end-customers) · [套餐额度](https://ngrok.com/docs/pricing-limits)

也可以使用已有的 Cloudflare 命名隧道。先在 Cloudflare 控制台添加公开主机名，将 HTTP 回源地址设为 `http://127.0.0.1:8001`，再执行：

```bash
sudo bash nat-relay.sh --https-edge relay.example.com --edge-provider cloudflare --origin-port 8001
```

按提示隐藏输入该隧道的 token。客户端使用 HTTPS/TCP 443，VPS 连接器固定使用 HTTP/2 over TCP 7844。同时运行两个连接器时，请让它们使用相同的本地回环端口。大陆线路对各入口域名的解析和连通性可能不同，可以在实际使用的宽带或移动网络上分别测试，再选择可用入口。连接器与客户端都需要能访问各自的服务端点。[Cloudflare Tunnel 防火墙端口](https://developers.cloudflare.com/tunnel/configuration/#firewall-rules) · [Cloudflare 连接器协议](https://developers.cloudflare.com/tunnel/reference/run-parameters/#protocol)

## 单文件安装

若面板已提供公网 TCP 端口转发，可以部署 XHTTP/HTTP2 直连。将下面的示例域名和端口换成面板的实际参数。入口域名需要解析到面板的公网 IPv4。`--host` 也接受公网 IPv4，旧版参数 `--ip` 仍可使用：

```bash
sudo bash nat-relay.sh --host nat.example.com --xhttp-tcp 23456:8001
```

该模式监听 VPS 的内部端口，客户端连接公网端口。两端端口相同可以只填一个数字，分隔符支持 `:` 和 `：`。安装器默认生成本地 TLS 证书，并将 SHA-256 证书指纹写入 VLESS 链接的 `pcs` 和 Mihomo 节点的 `fingerprint`。导入时使用支持相应字段的客户端。使用 NRP 合并链接需要本目录的新版 `relay_v1.py`。若使用自己的证书，可以传入 `--name`、`--cert` 和 `--key`。同时使用 Snell 时，为它分配单独的 TCP 映射。

在使用 systemd 的 Debian 12+ 或 Ubuntu 22.04+ VPS 网页终端中以 root 运行安装器。默认部署单进程 XHTTP/HTTP2，只问 TCP 端口映射。例如转发为 `10880 → 10880` 时填 `10880`，两端不同时填 `公网端口:内部端口`。共享 NAT 的入口与出口地址可能不同，使用面板域名可直接指定入口。

```bash
bash nat-relay.sh --host nat.example.com --xhttp-tcp 10882:443
```

安装器先验证内部监听的 TLS 证书和 HTTP/2 协商，再输出 v2rayN 节点链接。启动或本机自检失败会回滚该 Xray 服务配置。公网回环检测从 VPS 发起，可能受服务商回环策略限制。导入后请从实际使用的客户端网络验证真实代理请求。需要聚合时可以显式加 `--multipath`。

GitHub 下载器核对 SHA-256 后保存为 `$HOME/nat-relay.sh`。下载版本及摘要由 `get.sh` 固定。

```bash
(set -o pipefail; curl -fsSL --retry 2 https://raw.githubusercontent.com/TianWen6654/Xray-go-XHTTP/36c15131aea9719c6eb439bef53ca78138302d34/nat-relay/get.sh | bash)
```

对于尚未确认 systemd 环境的 Podman VPS，可先下载并自检。自检需要 Python 3.9+。将 `--check` 换为 `--download-only` 可仅保存脚本。

```bash
(set -o pipefail; wget -O- -nv https://raw.githubusercontent.com/TianWen6654/Xray-go-XHTTP/36c15131aea9719c6eb439bef53ca78138302d34/nat-relay/get.sh | bash -s -- --check)
```

使用 `--auto` 可部署 Snell 6 和临时 XHTTP。脚本优先读取 SSH 会话的公网服务端 IPv4，否则通过 HTTPS 查询出口 IPv4。若提供商使用不同的 NAT 入口，请执行 `bash /root/nat-relay.sh --auto --host 面板公网入口`。临时 XHTTP 自动选择可用的回环端口。

安装器先用一个短时 systemd 服务测试挂载命名空间和凭据。在返回 `226/NAMESPACE` 或 `243/CREDENTIALS` 的容器中，每种服务使用独立的非登录系统账号。其配置及所需证书位于 `/etc/nat-relay-unit-data/` 下各自的目录，文件由 root 所有，仅授予对应服务组读取权限。临时 XHTTP 服务退出时会清理其运行配置。

隧道分配域名后，VPS 会将 XHTTP 和 Snell 合入同一份配置，并在当前终端打印一条 `nrp://v2/…`。请保持临时隧道会话打开。该链接含访问凭据，只交给自己的客户端。原生节点同时提供 `vless://`、`snell://` 和 Surge 策略行。

客户端将本目录的 `relay_v1.py` 和 `multipath.py` 放在一起，安装 Python 3.9+ 和支持相关传输的 Mihomo。在客户端运行 `python relay_v1.py client -`，按提示粘贴合并链接。其他应用连接适配器的 SOCKS5 地址 `127.0.0.1:2081`。临时域名更换后，使用当前终端输出的新链接重新启动适配器。

已经上传单文件时，在文件所在目录运行：

```bash
sudo bash nat-relay.sh
```

运行 `bash nat-relay.sh --menu` 可选择其他模式。临时 XHTTP 需要 VPS 能出站连接隧道网关的 TCP 22。Snell 6 + Hysteria 2 使用 TCP 和 UDP 两个映射，需要域名和证书。

可用 `bash nat-relay.sh --check` 离线验证内嵌模块，或用 `bash nat-relay.sh --options` 查看非交互参数。单文件内包含四个 Python 源文件。首次部署所需的核心和依赖仍需由 VPS 下载。维护者修改源文件后，用 `python3 build_oneclick.py` 重新生成单文件。

普通节点使用 `install.py`。启用适配器时，将 `install.py`、`relay_v1.py`、`multipath.py` 放在同一目录。目标系统为 Debian 12+ 或 Ubuntu 22.04+，使用 systemd、Python 3 和系统 CA。直连 TLS 模式还需 OpenSSL 和有效域名证书。临时域名模式可单独运行。

## NRP/2 多路径：客户端一个节点

应用只连接本地 SOCKS5 `127.0.0.1:2081`。客户端适配器在后台启动自己的 Mihomo 实例，为每种载体建立独立的本地监听。每个应用 TCP 连接对应一个认证会话；VPS 只为它打开一个目标连接。上传和下载都能把数据分到不同路径上。

**部署**。在原安装命令中添加 `--multipath`，并一次列出要用的 sing-box 入站。例如，服务商将公网 TCP、UDP 的 31415 都映射到 VPS 的 8443 时：

```bash
sudo python3 install.py --multipath --ip 203.0.113.10 \
  --snell 31415:8443 --udp 31415:8443 --name relay.example.com \
  --cert /etc/letsencrypt/live/relay.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/relay.example.com/privkey.pem
```

替换示例地址、映射和证书。VLESS/WS 用 `--tcp`，XHTTP/H3 用 `--xhttp-h3`，同传输的不同监听器各需一个可用映射。临时公网 XHTTP 可以另开终端执行 `sudo python3 install.py --multipath --xhttp-temp --origin-port 8001`。不同时间部署的 sing-box 组、H3 和临时入口会合并进同一份客户端文件。临时域名分配或过期时，服务端更新该文件，客户端需取回新版并重启适配器。

**客户端**。私下取回 `/etc/nat-relay/relay-node.json`。其中包含凭据、信任证书和候选路径。将同版本的 `relay_v1.py` 和 `multipath.py` 放在一起，使用 Python 3.9+ 及支持所选传输的 Mihomo。示例：

```bash
python relay_v1.py client relay-node.json --mihomo /path/to/mihomo --max-paths 2
```

Windows 的 `--mihomo` 可填带引号的绝对 exe 路径。在 v2rayN 或支持 SOCKS5 的应用中仅添加一个本地 SOCKS5 节点，地址为 `127.0.0.1`，端口为 `2081`。适配器会在回环地址上为底层核心分配其余端口。NRP/2 的目标名随会话发往 VPS。命令行验证可用 `curl --proxy socks5h://127.0.0.1:2081 https://example.com/`。手机上的 Surge 等客户端只有在能运行或接入适配器时才能使用聚合；下文仍提供原生 Snell 导入方式。

**资源和恢复**。默认同时使用两个载体，`--max-paths 3` 可启用三个，上限为六个，实际数量受可用协议和映射限制。发送方在可写路径间按未确认块数分配数据，接收方按序交付并去重。每个方向最多保留 32 个未确认的 8 KiB 块，合计 256 KiB；重排缓冲、TLS、核心和系统套接字另占内存。缺少确认约 1.5 秒后可以经其他路径补发。全部路径短时中断时，会话最多保留约 20 秒等待重新加入。进程重启、目标连接关闭或超过保留时间会结束会话。聚合仅承载应用 TCP，无法保证在共享瓶颈上叠加带宽。

**观察与复测**。客户端命令添加 `--trace`，每条路径结束时会显示发送、接收、补发的载荷字节数。离线集成测试使用本地 HTTP 源站和真实客户端/服务端核心，可运行：

```bash
python test_multipath.py --sing-box /path/to/sing-box --mihomo /path/to/mihomo \
  --xray /path/to/xray --openssl /path/to/openssl
```

测试需要回环 TCP 18930–18934 可用。它会主动切断测试链路，核对应用请求次数和双向 SHA-256，并注入丢失与重复的数据帧验证补发、去重和半关闭。临时域名的外部网关及真实运营商线路需在实际部署地验证。

**线协议**。NRP/2 在每条载体内建立并验证到同一服务端的 TLS 1.3 连接。握手由 `NRP\x02`、32 字节令牌、32 字节随机会话 ID 和操作码组成；OPEN 指定目标，JOIN 绑定已有会话。数据帧头为网络字节序的类型、64 位块序号及 16 位长度。ACK 是下一期待的块号，空 DATA 表示有序的单向 FIN。内层分帧和重组由两端适配器处理。

## 使用新协议 NRP/1

NRP/1 是本项目的实验性 TCP 流协议。配套客户端在选中的底层代理上建立内层 TLS 1.3 连接，再发送 NRP/1 的认证、目标地址和数据帧。服务端把请求交给 VPS 上已有的 sing-box 或 Xray 出口。底层可用 Snell 6、Hysteria 2、VLESS/WS、XHTTP/H3 或临时 XHTTP。每次连接只走一条路径；新连接可随 Mihomo 的探测结果切换，已经建立的连接需要在断线后重连。v1 支持 SOCKS5 CONNECT 的 TCP 流量。

**服务端**：在所需部署命令中追加 `--relay-v1`。例如只用一个已分配的 TCP 映射时：

```bash
sudo python3 install.py --relay-v1 --ip 203.0.113.10 --snell 31415:8443
```

把示例 IP 和映射换为面板中的实际值。要加临时域名，可在另一终端运行 `sudo python3 install.py --relay-v1 --xhttp-temp --origin-port 8001`。只有明确启用 NRP/1 的入口才会写入 `/etc/nat-relay/relay-carriers.yaml`。服务端使用回环 TCP 18930–18933；无需在公网映射这些端口。新增的适配器服务为 `nat-relay-v1`，可用 `systemctl show nat-relay-v1 -p MemoryCurrent` 查看内存。仅结束临时隧道时，适配器服务仍可供其他入口使用；全部停用时可执行 `sudo systemctl disable --now nat-relay-v1`。

**客户端**：私下取回 `/etc/nat-relay/relay-v1.json` 和 `/etc/nat-relay/relay-carriers.yaml`。前者包括认证令牌和服务器信任证书，后者包括底层节点凭据。客户端使用相同版本的 `relay_v1.py` 和 Python 3.9+。

1. 在支持这些传输的 Mihomo 内核客户端导入 `relay-carriers.yaml`，启用其中的 Auto 组。也可在一个终端运行 `mihomo -f relay-carriers.yaml`。该配置监听本机 2080。临时域名发生变化时，重新取回并导入该文件。
2. 在另一个终端运行 `python relay_v1.py client relay-v1.json --via-port 2080 --listen-port 2081`。应用使用 SOCKS5 `127.0.0.1:2081` 即可走 NRP/1。可用 `curl --proxy socks5h://127.0.0.1:2081 https://example.com/` 验证。2080 与 2081 要使用不同端口。

服务端内层 TLS 证书由安装器通过 OpenSSL 生成，有效期两年，重跑安装复用同一对密钥。客户端依照私下分发的证书验证服务器。更换服务器身份时需要重新分发客户端信任配置。隧道网关仍能观察外层传输，内层认证、目标地址与数据受端到端 TLS 保护。

### NRP/1 线格式

每条 TLS 连接承载一个 TCP 流。所有整数均按网络字节序编码。v1 没有 UDP 数据报或跨链路迁移功能。

| 消息 | 字段 |
|---|---|
| 客户端 CONNECT | 四字节魔数 `4e 52 50 01`、一字节命令 `01`、32 字节令牌、两字节目标端口、一字节地址长度、1–253 字节 ASCII 域名或 IP 文本。国际域名使用 IDNA。 |
| 服务端结果 | 同一魔数和一字节状态。0 成功，1 认证失败，2 请求无效，3 出口连接失败。失败后关闭连接。 |
| 双向 DATA | 两字节长度，随后为相应长度的原始字节。接收器支持 1–65535 字节，实现发送上限为 32768 字节。 |
| 单向 FIN | 两字节零长度帧，结束该方向发送，另一方向可继续返回数据。 |

## Snell 6 在其他客户端中的用法

| 客户端 | 导入方式 |
|---|---|
| v2rayN | 在“添加自定义配置服务器”中导入 `snell-v2rayn.json`，核心选支持 Snell 6 的 **sing-box**，自定义配置内的 SOCKS 端口填 **2080**。如果 v2rayN 自身已经占用 2080，先修改文件中 `inbounds[0].listen_port`，并在界面填写相同端口。 |
| Clash/Mihomo | 在使用支持 Snell 6 的 **Mihomo 内核**的客户端导入 `mihomo.yaml`。 |
| Surge | 把 `snell-surge.conf` 中的策略行加入现有配置的 `[Proxy]`，选用 Snell6。 |
| Potatso | 从 `links.txt` 复制 `snell://…?version=6#Snell6`。该 URI 同时写入 Base64 列表，接收软件需要支持这一 URI 方言。 |

以上方式也可单独使用 Snell，无需启动 NRP/1 适配器。[v2rayN 自定义配置说明](https://github.com/2dust/v2rayN/wiki/Description-of-some-ui) · [Surge Snell 参数](https://manual.nssurge.com/policies/snell.html) · [Potatso URI 格式](https://potatso.com/docs/protocols/snell/)

## 临时公网域名 → VPS 本地 XHTTP

在 VPS 上执行：

```bash
sudo python3 install.py --xhttp-temp --origin-port 8001
```

数据路径为 **客户端 → 临时域名的 HTTPS 443 → localhost.run → VPS 发起的加密隧道 → 127.0.0.1:8001 → Xray**。8001 仅在 VPS 回环上监听，无需新增公网端口映射。脚本用 OpenSSH 客户端主动连接网关的 TCP 22；VPS 的 SSH 服务端口与这条数据路径无关。

- 安装器启动临时 Xray 实例，核对网关公布的 ED25519 主机密钥，再申请临时域名。成功后打印一条包含实际域名、UUID 和路径的 `vless://` 链接，同时写入 `/etc/nat-relay/xhttp-temp.txt`。在支持 XHTTP 的 Xray 客户端中导入，例如使用 Xray 内核的 v2rayN。
- 保持命令运行。脚本通过 SSH 请求 JSON 注册事件，从 `data.address` 读取完整域名（包括 `*.app.lhr.life`），随即更新合并节点。首次分配等待 60 秒，同一 SSH 会话收到新域名时会再次输出链接。Ctrl+C 会关闭隧道、停止临时 Xray 并移除临时链接。
- HTTPS 在第三方网关终止，因此网关可以读取外层 XHTTP 流量和临时节点凭据。应用自身的端到端 HTTPS 仍由应用验证。临时节点使用独立凭据。免费域名可能在数小时后更换或失效，届时重新运行命令并导入新链接。
- 临时回源不会替换既有的 H3 或 sing-box 服务。若进程被系统强杀，可以执行 `sudo systemctl stop nat-relay-xhttp-temp.service` 清理残留的临时服务。正常退出后释放这部分内存。

有关免费域名、TLS 终止方式与主机密钥，请参阅 [localhost.run 使用说明](https://localhost.run/docs)、[HTTP 隧道](https://localhost.run/docs/http-tunnels)、[安全文档](https://localhost.run/docs/security)和[免费域名说明](https://localhost.run/docs/faq)。

## 直连协议和端口

下文的地址和端口是示例。用服务商面板中的真实公网 IPv4 和映射替换。每个映射写成 `公网端口:VPS内部端口`。UDP 与 TCP 可以共用同一个端口号；同一协议的两个监听器需要不同端口。

| 参数 | VPS 内核 | 客户端与用途 |
|---|---|---|
| `--snell 31415:8443` | sing-box，TCP，Snell 6 | 支持 v6 的 Surge、sing-box 或 Mihomo。使用 PSK，无需证书 |
| `--udp 31415:8443` | sing-box，Hysteria 2 | UDP 映射能通时，可在其中承载应用 TCP 流量 |
| `--tcp 31415:8443` | sing-box，VLESS + WS + TLS | 固定 TCP 映射；可选 `--cdn` 接入自己已配置且允许此用途的同域名 CDN |
| `--xhttp-h3 31415:8443` | Xray，VLESS + XHTTP + HTTP/3 | 固定 UDP 映射，客户端需支持 XHTTP/H3 |
| `--xhttp-temp --origin-port 8001` | 临时 Xray，VLESS + XHTTP | 在没有新增公网映射的情况下接入临时域名 |

**仅部署 Snell 6**，使用一个 TCP 映射和一个常驻进程：

```bash
sudo python3 install.py --ip 203.0.113.10 --snell 31415:8443
```

**Snell 6 + Hysteria 2**，让一个 sing-box 进程同时提供 TCP 和 UDP 两条路径。仅在服务商确实分别映射了两个协议时使用该组合：

```bash
sudo python3 install.py --ip 203.0.113.10 --snell 31415:8443 --udp 31415:8443 \
  --name relay.example.com --cert /etc/letsencrypt/live/relay.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/relay.example.com/privkey.pem
```

**仅部署 XHTTP/H3**，与上游示例的 H3 功能对应。脚本使用指定映射，客户端按你自己的证书域名校验 TLS。需要同时启动临时公网入口时，可追加 `--xhttp-temp --origin-port 8001`。

```bash
sudo python3 install.py --ip 203.0.113.10 --xhttp-h3 31415:8443 \
  --name relay.example.com --cert /etc/letsencrypt/live/relay.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/relay.example.com/privkey.pem
```

Snell v6 需要支持该版本的客户端和 sing-box 核心。sing-box 的 Snell 入站从 1.14.0 引入，能否运行 v6 以实际核心的配置检查为准。脚本使用独立随机 PSK。端口只分到一个 TCP 映射时，可在 Snell 和 WS 之间选一种；只有一个 UDP 映射时，可在 Hysteria 2 和 XHTTP/H3 之间选一种。[sing-box Snell 入站](https://sing-box.sagernet.org/configuration/inbound/snell/) · [Snell 出站](https://sing-box.sagernet.org/configuration/outbound/snell/)

## 客户端导入与 DNS

安装结果在 `/etc/nat-relay/`，其中链接、PSK 和订阅文件都是私密凭据。

| 文件 | 内容 |
|---|---|
| `xhttp-temp.txt` | 仅在临时隧道会话中有效的 XHTTP 链接 |
| `xhttp-h3.txt` | XHTTP/H3 直连链接 |
| `snell-surge.conf` | Surge 的 Snell 6 `[Proxy]` 配置段，可复制进现有配置并选用 |
| `client.json`、`mihomo.yaml` | sing-box 模式的完整客户端配置，支持 Snell 6；多节点时自动按探测延迟选路 |
| `links.txt`、`subscription.b64` | sing-box 模式下的 VLESS/WS、Hysteria 2 和 Potatso 格式的 Snell 6 链接 |

完整 sing-box/Mihomo 配置提供本地 HTTP/SOCKS 代理 `127.0.0.1:2080`。使用 `socks5h://` 或代理内 DNS 将目标域名传给服务端。直连节点拨公网 IP，VPS 默认使用 DoH 解析目标。可用 `--exit-doh` 指定在 443 提供 `/dns-query` 且证书覆盖其 IP 的 IPv4 解析器。sing-box 模式下，`--bootstrap-doh` 控制客户端解析 CDN 域名的 DoH。临时公网域名的入口 DNS 遵循导入链接的客户端设置。

## 两份上游脚本的取舍

- **sing-box-yg** 的 `sb.sh` 包含系统和架构识别、组合配置以及多客户端输出。同时，其防火墙相关分支包含 `ufw disable` 和 `iptables -F`，端口选择逻辑也允许随机生成端口。这些动作会影响同机服务或使 NAT 映射失配。本安装器从上游借鉴组合配置与多客户端输出，公网映射由参数指定，防火墙由管理员按映射放行。[上游 sb.sh](https://github.com/yonggekkk/sing-box-yg/blob/main/sb.sh)
- **Xray-go** 中，`reality"n"` 关闭 REALITY，`h3"y"` 随机选择 H3 端口。原脚本要求域名和 Token 均非空才启用 Argo，所以题中命令实际只启用随机端口的 H3。脚本还会停止同名 Xray、按进程名杀掉 cloudflared，并以文件头或大小判断下载成功。这版独立生成 XHTTP 配置，保留 REALITY 关闭的选型，使用本地回源的临时域名和明确分配的 H3 端口。[上游 xray-go.sh](https://github.com/eishare/Xray-go/blob/main/xray-go.sh)
- 首次使用 Xray 时优先复用现有核心；否则从 XTLS 官方稳定版发行资产下载 amd64/arm64 压缩包，流式校验官方 API 返回的 SHA-256，仅提取 `xray`。sing-box 使用现有核心或上游签名 APT 仓库。两个服务都先用对应核心检查配置，再用独立的 systemd 服务名和动态用户启动。[Xray 官方发行版](https://github.com/XTLS/Xray-core/releases) · [sing-box 安装源](https://sing-box.sagernet.org/installation/package-manager/)
- 原有 sing-box 安装重跑时，身份密钥继续使用，客户端配置按本次选定的 sing-box 入站重新生成。之前用旧版生成过 CDN 节点的用户，按所需的直连参数重跑，再重新导入客户端配置。只运行临时模式不会重写已有 sing-box 配置。证书续期后用原参数重新部署对应直连服务。

## 运行和验收

同时启用直连 XHTTP 和临时 XHTTP 时，各有一个 Xray 进程，临时实例关闭后释放；仅选 Snell + Hysteria 2 时只有一个 sing-box 服务。Go 内存软目标按可见内存和 cgroup 限额设置，每个核心使用一个 Go 调度处理器。实际总内存随并发和协议变化。

```bash
# 在 VPS，检查回源监听、服务状态和内存
ss -lntup
systemctl status nat-relay-xhttp-temp --no-pager
systemctl show nat-relay nat-relay-xray nat-relay-xhttp-temp -p MemoryCurrent -p NRestarts

# 在客户端，导入并选中待测节点后执行，端口替换为客户端的本地 SOCKS 端口
curl --proxy socks5h://127.0.0.1:2080 --max-time 15 https://example.com/
```

收到临时域名只说明网关已分配入口。在客户端选中该节点并成功代理请求，才能确认该条公网线路可用。关闭临时模式用 Ctrl+C；常驻 sing-box 和 H3 服务分别用 `sudo systemctl disable --now nat-relay` 和 `sudo systemctl disable --now nat-relay-xray` 停用。
