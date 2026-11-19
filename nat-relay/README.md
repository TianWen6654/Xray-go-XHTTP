# 低内存 NAT VPS 的 sing-box 和 Xray 安装器

## 单文件安装

在 VPS 的 Bash 网页终端中以 root 运行以下命令即可从 GitHub 安装。下载器将已固定版本的安装包写入临时文件，核对 SHA-256 后保存为 `$HOME/nat-relay.sh`，再打开交互菜单。安装支持使用 systemd 的 Debian 12+ 或 Ubuntu 22.04+。

```bash
(set -o pipefail; curl -fsSL --retry 2 https://raw.githubusercontent.com/TianWen6654/Xray-go-XHTTP/main/nat-relay/get.sh | bash)
```

对于尚未确认 systemd 环境的 Podman VPS，可先下载并自检。自检需要 Python 3.9+。将 `--check` 换为 `--download-only` 可仅保存脚本。

```bash
(set -o pipefail; wget -O- -nv https://raw.githubusercontent.com/TianWen6654/Xray-go-XHTTP/main/nat-relay/get.sh | bash -s -- --check)
```
