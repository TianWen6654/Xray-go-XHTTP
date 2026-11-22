"""Build the Bash installer and its verified terminal-paste copy."""
import base64
import gzip
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MODULES = ("install.py", "relay_v1.py", "multipath.py", "nat_web.py")
HEADER = r'''#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'HELP'
NRP/2 单文件安装器（Debian 12+ 或 Ubuntu 22.04+，使用 systemd）
  sudo bash nat-relay.sh                 单进程 XHTTP/HTTP2，只问 TCP 端口映射
  sudo bash nat-relay.sh --host 公网入口 --auto-tcp  用面板入口，交互填写端口
  sudo bash nat-relay.sh --menu          选择其他部署模式
  bash nat-relay.sh --check              离线验证内嵌文件，无需 root
  bash nat-relay.sh --check-egress       测试 HTTPS 隧道的出站 TCP 端口，无需 root
  sudo bash nat-relay.sh --host 公网域名或IPv4 --snell 公网端口:内部端口
  sudo bash nat-relay.sh --host 公网域名或IPv4 --xhttp-tcp 公网端口:内部端口
  sudo bash nat-relay.sh --nat-web 公网域名 --public-ports 端口1,端口2 --listen-port 443
  sudo bash nat-relay.sh --switch-web-port --public-ports 端口1,端口2
  sudo bash nat-relay.sh --https-edge 公网域名 --edge-provider ngrok或cloudflare --origin-port 8001
  sudo bash nat-relay.sh --quick-edge     临时 HTTPS 入口，无需公网映射、域名或令牌
  sudo bash nat-relay.sh --show-quick-edge  验证当前临时域名并输出节点
  sudo bash nat-relay.sh --xhttp-temp --origin-port 8001
  bash nat-relay.sh --options            显示全部协议参数
直接 XHTTP/HTTP2 可用 --multipath 显式开启聚合。
HELP
}

fail() { printf '%s\n' "$*" >&2; exit 1; }

case "${1:-}" in
    --help|-h) usage; exit 0 ;;
esac

action=install
case "${1:-}" in
    --check) action=check; shift ;;
    --options) action=options; shift ;;
    --check-egress) action=egress; shift ;;
esac
if [[ $action != install && $# -ne 0 ]]; then fail '该模式不接受其他参数'; fi

if [[ $action == install ]]; then
    [[ $EUID == 0 ]] || fail '请使用 sudo bash nat-relay.sh，或在 root 终端运行。'
    [[ -d /run/systemd/system ]] || fail '当前系统没有运行 systemd。'
    command -v apt-get >/dev/null || fail '此安装器需要 Debian/Ubuntu 的 apt-get。'
    if [[ $# == 0 ]]; then
        [[ -t 0 ]] || fail '请在终端启动，或用 --host 公网入口 --xhttp-tcp 公网端口:内部端口。'
        set -- --auto-tcp
    elif [[ $# == 1 && $1 == --menu ]]; then
        [[ -t 0 ]] || fail '非交互运行需要提供协议参数。可执行 bash nat-relay.sh --help。'
        printf '%s\n' \
            '1) Snell 6 + 临时 XHTTP（一个 TCP 映射，无需自备证书）' \
            '2) Snell 6 + Hysteria 2（TCP 和 UDP 映射，需域名证书）' \
            '3) 仅 Snell 6（一个 TCP 映射）' \
            '4) 仅临时 XHTTP（无需新增公网映射）' \
            '5) 直连 XHTTP/HTTP2（一个 TCP 映射，无需第三方隧道）' \
            '6) 临时 HTTPS 入口（仅 TCP，无需公网映射、域名或令牌）'
        read -r -p '选择 [1]: ' mode
        mode=${mode:-1}
        case "$mode" in 1|2|3|4|5|6) ;; *) fail '请选择 1 至 6';; esac
        params=()
        if [[ $mode != 4 && $mode != 6 ]]; then
            while :; do
                read -r -p 'TCP 映射（同端口填一个数字，不同则填公网端口:内部端口）: ' tcp || fail '终端输入已关闭。'
                [[ -n $tcp ]] && break
                printf '%s\n' '请输入端口号。'
            done
            if [[ $mode == 5 ]]; then
                params+=(--auto-tcp --xhttp-tcp "$tcp")
            else
                params+=(--snell "$tcp")
            fi
        fi
        if [[ $mode == 2 ]]; then
            read -r -p 'UDP 映射（公网端口:内部端口）: ' udp
            read -r -p '证书域名: ' name
            read -r -p 'fullchain.pem 绝对路径: ' cert
            read -r -p '私钥 PEM 绝对路径: ' key
            params+=(--udp "$udp" --name "$name" --cert "$cert" --key "$key")
        fi
        if [[ $mode == 1 || $mode == 4 ]]; then
            read -r -p '临时 XHTTP 的 VPS 本地端口 [8001]: ' origin
            params+=(--xhttp-temp --origin-port "${origin:-8001}")
        fi
        if [[ $mode == 6 ]]; then params+=(--quick-edge); fi
        set -- "${params[@]}"
    fi
    packages=()
    command -v python3 >/dev/null || packages+=(python3)
    command -v openssl >/dev/null || packages+=(openssl)
    [[ -s /etc/ssl/certs/ca-certificates.crt ]] || packages+=(ca-certificates)
    if (( ${#packages[@]} )); then
        apt-get -o Acquire::Languages=none update
        DEBIAN_FRONTEND=noninteractive DPKG_DEB_THREADS_MAX=1 apt-get install -y --no-install-recommends "${packages[@]}"
    fi
fi
command -v python3 >/dev/null || fail '需要 Python 3.9 或更新版本。'
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
'''
FOOTER = r'''
if [[ $action == check ]]; then
    python3 -I -B -c 'import pathlib,sys; sys.version_info >= (3, 9) or sys.exit("需要 Python 3.9 或更新版本。"); p=pathlib.Path(sys.argv[1]).resolve(); sys.path.insert(0,str(p)); import install,relay_v1,multipath,nat_web; assert all(pathlib.Path(m.__file__).parent == p for m in (install,relay_v1,multipath,nat_web))' "$stage"
    printf '%s\n' '通过：内嵌模块的 SHA-256 和 Python 导入检查均成功。'
    exit 0
fi
if [[ $action == options ]]; then
    python3 -B "$stage/install.py" --help
    exit 0
fi
if [[ $action == egress ]]; then
    python3 -B "$stage/install.py" --check-egress
    exit 0
fi
read_oom_kills() {
    oom_kills=
    local field count
    if [[ -r /sys/fs/cgroup/memory.events ]]; then
        while read -r field count; do
            if [[ $field == oom_kill && $count =~ ^[0-9]+$ ]]; then
                oom_kills=$count
                break
            fi
        done < /sys/fs/cgroup/memory.events
    fi
}

read_oom_kills
oom_before=$oom_kills
relay=(--multipath)
for option in "$@"; do
    case "$option" in
        --auto-tcp|--xhttp-tcp|--xhttp-tcp=*|--quick-edge|--show-quick-edge)
            relay=()
            break
            ;;
    esac
done
if python3 -B "$stage/install.py" "${relay[@]}" "$@"; then
    exit 0
else
    status=$?
fi
if [[ $status == 137 ]]; then
    read_oom_kills
    if [[ -n $oom_before && -n $oom_kills ]] && (( oom_kills > oom_before )); then
        printf '安装期间检测到容器 OOM 杀进程（oom_kill %s → %s）。释放内存后再重试。\n' "$oom_before" "$oom_kills" >&2
    else
        printf '%s\n' '安装进程收到 SIGKILL。请查看容器内存和 memory.events 后再重试。' >&2
    fi
fi
exit "$status"
'''
PASTE_TEMPLATE = r'''(
set -euo pipefail
cd ~root
stage=$(mktemp .nat-relay.XXXXXXXX)
trap 'rm -f -- "$stage"' EXIT
base64 -d <<'NAT_RELAY_GZIP' | gzip -dc > "$stage"
{payload}NAT_RELAY_GZIP
printf '%s  %s\n' '{digest}' "$stage" | sha256sum -c - >/dev/null
if [ -e nat-relay.sh ]; then
    if ! cmp -s "$stage" nat-relay.sh; then
        mv -- "$stage" "$stage.sh"
        printf 'Verified script: %s/%s.sh\n' "$PWD" "$stage"
        exit 0
    fi
else
    mv -- "$stage" nat-relay.sh
fi
printf 'Verified script: %s/nat-relay.sh\n' "$PWD"
)
'''


def build():
    sections = [HEADER]
    checks = []
    for name in MODULES:
        source = (ROOT / name).read_text(encoding="utf-8").rstrip("\n") + "\n"
        marker = "NRP_FILE_" + name.replace(".", "_").upper()
        assert marker not in source.splitlines()
        sections.append(f'cat > "$stage/{name}" <<\'{marker}\'\n{source}{marker}\n')
        checks.append(f"{hashlib.sha256(source.encode()).hexdigest()}  {name}")
    sections.append('(cd -- "$stage" && sha256sum --check --status <<\'NRP_SHA256\'\n'
                    + "\n".join(checks) + '\nNRP_SHA256\n) || fail "内嵌文件校验失败。"\n')
    sections.append(FOOTER)
    target = ROOT / "nat-relay.sh"
    script = "".join(sections).encode()
    target.write_bytes(script)
    target.chmod(0o755)
    packed = base64.encodebytes(gzip.compress(script, mtime=0)).decode("ascii")
    paste = PASTE_TEMPLATE.format(payload=packed, digest=hashlib.sha256(script).hexdigest())
    (ROOT / "paste-to-vps.txt").write_bytes(paste.encode("ascii"))
    return target


if __name__ == "__main__":
    print(build())
