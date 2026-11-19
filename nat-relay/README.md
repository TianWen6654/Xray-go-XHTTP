# 低内存 NAT VPS 的 sing-box 和 Xray 安装器

## 单文件安装

在使用 systemd 的 Debian 12+ 或 Ubuntu 22.04+ VPS 网页终端中以 root 运行以下命令。下载器核对 SHA-256 后保存为 `$HOME/nat-relay.sh`。默认只问一个 TCP 端口。例如转发为 `10880 → 10880` 时填 `10880`，两端不同时填 `公网端口:内部端口`。

```bash
(set -o pipefail; curl -fsSL --retry 2 https://raw.githubusercontent.com/TianWen6654/Xray-go-XHTTP/main/nat-relay/get.sh | bash)
```

对于尚未确认 systemd 环境的 Podman VPS，可先下载并自检。自检需要 Python 3.9+。将 `--check` 换为 `--download-only` 可仅保存脚本。

```bash
(set -o pipefail; wget -O- -nv https://raw.githubusercontent.com/TianWen6654/Xray-go-XHTTP/main/nat-relay/get.sh | bash -s -- --check)
```

默认部署 Snell 6 和临时 XHTTP。脚本优先读取 SSH 会话的公网服务端 IPv4，否则通过 HTTPS 查询出口 IPv4。若提供商使用不同的 NAT 入口，请执行 `bash /root/nat-relay.sh --auto --ip 面板入口IPv4`。XHTTP 自动选择可用的回环端口。

隧道分配域名后，VPS 会将 XHTTP 和 Snell 合入同一份配置，并在当前终端打印一条 `nrp://v2/…`。请保持临时隧道会话打开。该链接含访问凭据，只交给自己的客户端。原生节点同时提供 `vless://`、`snell://` 和 Surge 策略行。

客户端将本目录的 `relay_v1.py` 和 `multipath.py` 放在一起，安装 Python 3.9+ 和支持相关传输的 Mihomo。在客户端运行 `python relay_v1.py client -`，按提示粘贴合并链接。其他应用连接适配器的 SOCKS5 地址 `127.0.0.1:2081`。临时域名更换后，使用当前终端输出的新链接重新启动适配器。
