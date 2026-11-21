# 低内存 NAT VPS 的 sing-box 和 Xray 安装器

## NAT 直连 HTTPS 与端口预检

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

若使用面板的 TCP 端口转发，可以用 XHTTP/HTTP2 直连。请将示例域名、外部和内部 TCP 端口换成面板的实际值。入口域名应解析到面板的公网 IPv4。`--host` 也支持公网 IPv4，原参数 `--ip` 仍可用。两端端口相同可以只填一个数字，分隔符支持 `:` 和 `：`。

```bash
sudo bash nat-relay.sh --host nat.example.com --xhttp-tcp 23456:8001
```

脚本默认生成本机 TLS 证书，并把 SHA-256 指纹写入 VLESS 链接的 `pcs` 和 Mihomo 节点的 `fingerprint`。导入时使用支持相应字段的客户端。使用 NRP 合并链接时需更新本目录的 `relay_v1.py`。如需使用自己的证书，可以传入 `--name`、`--cert` 和 `--key`。同时使用 Snell 时，为它分配单独的 TCP 映射。

在使用 systemd 的 Debian 12+ 或 Ubuntu 22.04+ VPS 网页终端中以 root 运行以下命令。下载器核对 SHA-256 后保存为 `$HOME/nat-relay.sh`。默认只问一个 TCP 端口。例如转发为 `10880 → 10880` 时填 `10880`，两端不同时填 `公网端口:内部端口`。

```bash
(set -o pipefail; curl -fsSL --retry 2 https://raw.githubusercontent.com/TianWen6654/Xray-go-XHTTP/main/nat-relay/get.sh | bash)
```

对于尚未确认 systemd 环境的 Podman VPS，可先下载并自检。自检需要 Python 3.9+。将 `--check` 换为 `--download-only` 可仅保存脚本。

```bash
(set -o pipefail; wget -O- -nv https://raw.githubusercontent.com/TianWen6654/Xray-go-XHTTP/main/nat-relay/get.sh | bash -s -- --check)
```

默认部署 Snell 6 和临时 XHTTP。脚本优先读取 SSH 会话的公网服务端 IPv4，否则通过 HTTPS 查询出口 IPv4。若提供商使用不同的 NAT 入口，请执行 `bash /root/nat-relay.sh --auto --ip 面板入口IPv4`。XHTTP 自动选择可用的回环端口。

安装器先用一个短时 systemd 服务测试挂载命名空间和凭据。在返回 `226/NAMESPACE` 或 `243/CREDENTIALS` 的容器中，每种服务使用独立的非登录系统账号。其配置及所需证书位于 `/etc/nat-relay-unit-data/` 下各自的目录，文件由 root 所有，仅授予对应服务组读取权限。临时 XHTTP 服务退出时会清理其运行配置。

隧道分配域名后，VPS 会将 XHTTP 和 Snell 合入同一份配置，并在当前终端打印一条 `nrp://v2/…`。请保持临时隧道会话打开。该链接含访问凭据，只交给自己的客户端。原生节点同时提供 `vless://`、`snell://` 和 Surge 策略行。

客户端将本目录的 `relay_v1.py` 和 `multipath.py` 放在一起，安装 Python 3.9+ 和支持相关传输的 Mihomo。在客户端运行 `python relay_v1.py client -`，按提示粘贴合并链接。其他应用连接适配器的 SOCKS5 地址 `127.0.0.1:2081`。临时域名更换后，使用当前终端输出的新链接重新启动适配器。
