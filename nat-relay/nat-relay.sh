#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'HELP'
NRP/2 单文件安装器（Debian 12+ 或 Ubuntu 22.04+，使用 systemd）
  sudo bash nat-relay.sh                 自动配置 Snell 6 和临时 XHTTP，只问 TCP 端口
  sudo bash nat-relay.sh --menu          选择其他部署模式
  bash nat-relay.sh --check              离线验证内嵌文件，无需 root
  sudo bash nat-relay.sh --ip IP --snell 公网端口:内部端口
  sudo bash nat-relay.sh --xhttp-temp --origin-port 8001
  bash nat-relay.sh --options            显示全部协议参数
安装时默认启用 --multipath。只有一个载体时也能测试连通性。
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
esac
if [[ $action != install && $# -ne 0 ]]; then fail '该模式不接受其他参数'; fi

if [[ $action == install ]]; then
    [[ $EUID == 0 ]] || fail '请使用 sudo bash nat-relay.sh，或在 root 终端运行。'
    [[ -d /run/systemd/system ]] || fail '当前系统没有运行 systemd。'
    command -v apt-get >/dev/null || fail '此安装器需要 Debian/Ubuntu 的 apt-get。'
    if [[ $# == 0 ]]; then
        [[ -t 0 ]] || fail '请在终端启动，或用 --auto --snell 公网端口:内部端口。'
        set -- --auto
    elif [[ $# == 1 && $1 == --menu ]]; then
        [[ -t 0 ]] || fail '非交互运行需要提供协议参数。可执行 bash nat-relay.sh --help。'
        printf '%s\n' \
            '1) Snell 6 + 临时 XHTTP（一个 TCP 映射，无需自备证书）' \
            '2) Snell 6 + Hysteria 2（TCP 和 UDP 映射，需域名证书）' \
            '3) 仅 Snell 6（一个 TCP 映射）' \
            '4) 仅临时 XHTTP（无需新增公网映射）'
        read -r -p '选择 [1]: ' mode
        mode=${mode:-1}
        case "$mode" in 1|2|3|4) ;; *) fail '请选择 1 至 4';; esac
        params=()
        if [[ $mode != 4 ]]; then
            while :; do
                read -r -p 'TCP 映射（同端口填一个数字，不同则填公网端口:内部端口）: ' tcp || fail '终端输入已关闭。'
                [[ -n $tcp ]] && break
                printf '%s\n' '请输入端口号。'
            done
            [[ $tcp == *:* ]] || tcp="$tcp:$tcp"
            params+=(--snell "$tcp")
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
        set -- "${params[@]}"
    fi
    packages=()
    command -v python3 >/dev/null || packages+=(python3)
    command -v openssl >/dev/null || packages+=(openssl)
    [[ -s /etc/ssl/certs/ca-certificates.crt ]] || packages+=(ca-certificates)
    if (( ${#packages[@]} )); then
        apt-get update
        apt-get install -y --no-install-recommends "${packages[@]}"
    fi
fi
command -v python3 >/dev/null || fail '需要 Python 3.9 或更新版本。'
python3 -I -c 'import sys; sys.exit(sys.version_info < (3, 9))' || fail '需要 Python 3.9 或更新版本。'
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
cat > "$stage/install.py" <<'NRP_FILE_INSTALL_PY'
#!/usr/bin/env python3
"""Fixed-port sing-box and Xray installer for Debian/Ubuntu with systemd 247+."""
import argparse
import base64
from contextlib import contextmanager, ExitStack
from functools import lru_cache
import hashlib
import ipaddress
import json
import os
import platform
from pathlib import Path
import re
import secrets
import selectors
import signal
import shutil
import socket
import ssl
import subprocess
import sys
from types import SimpleNamespace
import tempfile
import time
from urllib.parse import quote, urlencode
from urllib.request import urlopen
from urllib.request import ProxyHandler, build_opener
import uuid
import zipfile

ROOT = Path("/etc/nat-relay")
UNIT = Path("/etc/systemd/system/nat-relay.service")
UNIT_MARK = "# Managed by nat-relay/install.py\n"
UNIT_DATA = Path("/etc/nat-relay-unit-data")


def run(*cmd, **kwargs):
    return subprocess.run(cmd, check=True, **kwargs)


def dump(data):
    return json.dumps(data, indent=2) + "\n"


def mapping(value):
    try:
        public, local = map(int, value.split(":"))
        if 1 <= min(public, local) and max(public, local) <= 65535:
            return public, local
    except ValueError:
        pass
    raise argparse.ArgumentTypeError("映射应为 公网端口:内部端口，范围 1–65535")


def discover_ipv4():
    def public(text):
        try:
            ip = ipaddress.IPv4Address(text.strip())
        except ValueError:
            return None
        return ip if ip.is_global and not ip.is_multicast else None

    ssh = os.environ.get("SSH_CONNECTION", "").split()
    address = public(ssh[2]) if len(ssh) == 4 else None
    if address:
        print(f"SSH 服务端公网地址 {address}", flush=True)
        return address
    opener = build_opener(ProxyHandler({}))
    for endpoint in ("https://api.ipify.org", "https://ipv4.icanhazip.com"):
        try:
            with opener.open(endpoint, timeout=5) as response:
                address = public(response.read(64).decode("ascii"))
        except (OSError, UnicodeError):
            continue
        if address:
            print(f"检测到出口 IPv4 {address}。若与面板的 NAT 入口不同，请用 --ip 指定入口。", flush=True)
            return address
    raise ValueError("无法探测公网 IPv4。请用 --auto --ip 面板入口IPv4 重试。")


def quick_setup(a):
    from relay_v1 import EGRESS, SERVICE_PORT
    reserved = (SERVICE_PORT, *EGRESS)
    while not a.snell:
        try:
            value = input("TCP 端口（如 10880；端口不同时填 公网端口:内部端口）：").strip()
        except EOFError:
            raise ValueError("终端输入已关闭。可以用 --auto --snell 公网端口:内部端口。") from None
        try:
            ports = mapping(value if ":" in value else f"{value}:{value}")
            if ports[1] in reserved:
                raise ValueError("内部端口 18930–18933 已保留。")
            a.snell = ports
        except (argparse.ArgumentTypeError, ValueError) as error:
            print(error, file=sys.stderr)
    a.xhttp_temp = True
    # Probe the loopback listener without changing the public NAT mapping.
    for port in range(8001, 8102):
        if port == a.snell[1]:
            continue
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
        a.origin_port = port
        return
    raise ValueError("没有可用的本地回源端口，请使用 --xhttp-temp --origin-port 指定。")


def domain(value):
    labels = value.lower().split(".")
    if len(labels) < 2 or len(value) > 253 or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels
    ):
        raise argparse.ArgumentTypeError("请输入 ASCII 域名或 Punycode")
    return ".".join(labels)


def credentials():
    return dict(uuid=str(uuid.uuid4()), password=secrets.token_urlsafe(32),
                path="/ws-" + secrets.token_hex(12))


def dns(address):
    return {"servers": [{"type": "https", "tag": "doh", "server": str(address),
                         "path": "/dns-query", "tls": {"enabled": True}}], "final": "doh"}


def generate(a, keys, cert, key):
    client_tls = {"enabled": True, "server_name": a.name}
    server_tls = {"enabled": True, "certificate": cert, "key": key}
    listeners, nodes, links = [], [], []
    ip = str(a.ip)
    if a.snell:
        public, local = a.snell
        proto = dict(type="snell", version=6, psk=keys["snell_psk"])
        listeners.append(dict(**proto, listen="0.0.0.0", listen_port=local))
        nodes.append(dict(**proto, tag="Snell6", server=ip, server_port=public))
        links.append(f"snell://{quote(keys['snell_psk'], safe='')}@{ip}:{public}?version=6#Snell6")
    if a.udp:
        public, local = a.udp
        auth = keys["password"]
        listeners.append(dict(type="hysteria2", listen="0.0.0.0", listen_port=local,
                              users=[{"password": auth}], tls=server_tls))
        nodes.append(dict(type="hysteria2", tag="UDP", server=ip, server_port=public,
                          password=auth, tls=client_tls))
        links.append(f"hysteria2://{auth}@{ip}:{public}/?sni={a.name}#NAT-UDP")
    if a.tcp:
        public, local = a.tcp
        uid, path = keys["uuid"], keys["path"]
        transport = {"type": "ws", "path": path}
        listeners.append(dict(type="vless", listen="0.0.0.0", listen_port=local,
                              users=[{"uuid": uid}], transport=transport, tls=server_tls))
        targets = [("TCP", ip, public, a.name)]
        if a.cdn:
            targets.append(("CDN", a.name, a.edge_port, a.name))
        for tag, host, port, tls_name in targets:
            tls = {"enabled": True, "server_name": tls_name}
            nodes.append(dict(type="vless", tag=tag, server=host, server_port=port,
                              uuid=uid, tls=tls,
                              transport={**transport, "headers": {"Host": tls_name}}))
            query = urlencode(dict(encryption="none", security="tls", type="ws",
                                   host=tls_name, sni=tls_name, path=path))
            links.append(f"vless://{uid}@{host}:{port}?{query}#NAT-{tag}")
    server = dict(log={"level": "warn"}, inbounds=listeners, dns=dns(a.exit_doh),
                  outbounds=[{"type": "direct", "tag": "exit"}],
                  route={"default_domain_resolver": "doh", "final": "exit",
                         "rules": [{"action": "resolve", "strategy": "ipv4_only"},
                                   {"ip_is_private": True, "action": "reject"}]})
    tags = [n["tag"] for n in nodes]
    final = tags[0]
    if len(tags) > 1:
        final = "Auto"
        nodes.append(dict(type="urltest", tag=final, outbounds=tags,
                          url="https://www.gstatic.com/generate_204", interval="1m",
                          tolerance=80, interrupt_exist_connections=False))
    client = dict(log={"level": "warn"}, dns=dns(a.bootstrap_doh),
                  inbounds=[dict(type="mixed", listen="127.0.0.1", listen_port=2080)],
                  outbounds=nodes, route={"default_domain_resolver": "doh", "final": final})
    return server, client, links


def atomic(path, data, mode=0o600, gid=None):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
        tmp = Path(f.name)
        try:
            f.write(data)
            f.flush()
            if gid is not None:
                os.fchown(f.fileno(), 0, gid)
            os.fchmod(f.fileno(), mode)
        except BaseException:
            tmp.unlink()
            raise
    os.replace(tmp, path)


def mihomo_profile(a, client):
    proxies = []
    for node in client["outbounds"]:
        if node["type"] == "urltest":
            continue
        proxy = {"name": node["tag"], "type": node["type"], "server": node["server"],
                 "port": node["server_port"], "udp": True}
        if node["type"] == "snell":
            proxy.update(version=node["version"], psk=node["psk"])
        elif node["type"] == "hysteria2":
            proxy.update(password=node["password"], sni=a.name)
        else:
            proxy.update(uuid=node["uuid"], tls=True, servername=node["tls"]["server_name"], network="ws",
                         **{"ws-opts": {"path": node["transport"]["path"],
                                        "headers": node["transport"]["headers"]}})
            if "alpn" in node["tls"]:
                proxy["alpn"] = node["tls"]["alpn"]
        proxies.append(proxy)
    tags = [p["name"] for p in proxies]
    return {"mixed-port": 2080, "allow-lan": False, "mode": "rule",
            "log-level": "warning", "proxies": proxies,
            "proxy-groups": [{"name": "Auto", "type": "url-test", "proxies": tags,
                              "url": "https://www.gstatic.com/generate_204",
                              "interval": 60, "tolerance": 80}],
            "dns": {"enable": True, "ipv6": False,
                    "proxy-server-nameserver": [f"https://{a.bootstrap_doh}/dns-query"],
                    "nameserver": [f"https://{a.exit_doh}/dns-query#Auto"]},
            "rules": ["MATCH,Auto"]}


def core():
    binary = shutil.which("sing-box")
    if binary:
        return binary
    # Use a signed private APT source. Extract the binary without enabling a
    # second distribution service or changing the system's repository list.
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        d.chmod(0o755)
        ring = d / "sagernet.asc"
        with urlopen("https://sing-box.app/gpg.key", timeout=30) as response:
            atomic(ring, response.read(), 0o644)
        src = d / "sagernet.sources"
        atomic(src, (f"Types: deb\nURIs: https://deb.sagernet.org/\nSuites: *\n"
                     f"Components: *\nSigned-By: {ring}\n").encode(), 0o644)
        lists = d / "lists"
        lists.mkdir(mode=0o755)
        opts = ["-o", f"Dir::Etc::sourcelist={src}", "-o", "Dir::Etc::sourceparts=-",
                "-o", f"Dir::State::lists={lists}", "-o", "Acquire::Languages=none"]
        run("apt-get", *opts, "update", "--error-on=any")
        run("apt-get", *opts, "download", "sing-box", cwd=d)
        pkg, = d.glob("*.deb")
        run("dpkg-deb", "-x", pkg, d / "unpacked")
        target = Path("/usr/local/lib/nat-relay/sing-box")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        # Copy as a stream on small systems.
        with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as dest:
            with (d / "unpacked/usr/bin/sing-box").open("rb") as source:
                shutil.copyfileobj(source, dest)
            os.fchmod(dest.fileno(), 0o755)
        os.replace(dest.name, target)
        return str(target)


def memory_budget():
    total = int(re.search(r"MemTotal:\s+(\d+)", Path("/proc/meminfo").read_text())[1]) // 1024
    for file in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        p = Path(file)
        if p.is_file() and (v := p.read_text().strip()).isdigit():
            total = min(total, int(v) // 1048576)
    return max(16, min(128, total // 3))


@lru_cache(maxsize=1)
def has_service_namespace():
    name = f"natr-probe-{uuid.uuid4().hex[:16]}.service"
    result = subprocess.run(["systemd-run", "--quiet", "--wait", "--service-type=simple",
                             "--unit", name, "-p", "DynamicUser=yes", "-p", "ProtectSystem=strict",
                             "-p", "ProtectHome=yes", "-p", "LoadCredential=probe:/etc/os-release",
                             "/bin/true"], capture_output=True, text=True)
    if result.returncode == 0:
        return True
    status = subprocess.run(["systemctl", "show", name, "-p", "ExecMainStatus", "--value"],
                            capture_output=True, text=True).stdout.strip()
    subprocess.run(["systemctl", "reset-failed", name], capture_output=True)
    if status not in {"226", "243"} and result.returncode not in (226, 243):
        raise ValueError(f"systemd 服务探测失败（ExecMainStatus={status}）：{result.stderr.strip()}")
    print("容器无法创建服务挂载命名空间，使用独立非登录账号读取各服务的私有配置。", flush=True)
    return False


def service_gid(name):
    import grp
    import pwd
    marker = "NAT relay service " + name
    try:
        account = pwd.getpwnam(name)
    except KeyError:
        run("useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent",
            "--shell", "/usr/sbin/nologin", "--comment", marker, name)
        account = pwd.getpwnam(name)
    group = grp.getgrgid(account.pw_gid)
    if (account.pw_uid == 0 or account.pw_gid == 0 or account.pw_gecos != marker
            or account.pw_shell != "/usr/sbin/nologin" or group.gr_name != name or group.gr_mem):
        raise ValueError(f"服务账号或组已被占用：{name}")
    return account.pw_gid


@contextmanager
def service_access(unit, config_path, encoded, extra, temporary=False):
    sources = {"config.json": config_path, **extra}
    if has_service_namespace():
        properties = ["DynamicUser=yes", "ProtectSystem=strict", "ProtectHome=yes"]
        properties.extend(f"LoadCredential={key}:{value}" for key, value in sources.items())
        yield properties, f"/run/credentials/{unit}" if temporary else "%d"
        return
    name = {"nat-relay.service": "natr-singbox", "nat-relay-v1.service": "natr-adapter",
            "nat-relay-xray.service": "natr-xray", "nat-relay-xhttp-temp.service": "natr-temp"}[unit]
    gid = service_gid(name)
    directory = UNIT_DATA / name
    for folder in (UNIT_DATA, directory):
        folder.mkdir(mode=0o700, exist_ok=True)
        st = folder.lstat()
        if folder.is_symlink() or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError(f"服务配置目录权限异常：{folder}")
    UNIT_DATA.chmod(0o711)
    os.chown(directory, 0, gid)
    directory.chmod(0o710)
    with ExitStack() as restore:
        for key, source in sources.items():
            data = encoded if key == "config.json" else source.read_bytes()
            target = directory / key
            if target.exists() and not temporary:
                old = target.read_bytes()
                if old == data and target.stat().st_gid == gid and target.stat().st_mode & 0o777 == 0o640:
                    continue
                restore.callback(atomic, target, old, 0o640, gid)
            else:
                restore.callback(target.unlink, missing_ok=True)
            atomic(target, data, 0o640, gid)
        yield [f"User={name}", f"Group={name}", "UMask=0077"], str(directory)
        if not temporary:
            restore.pop_all()


def activate(binary, server, path, unit_path, arguments="run -c %d/config.json", credentials=None,
             reuse_active=False):
    if unit_path.exists() and not unit_path.read_text().startswith(UNIT_MARK):
        raise ValueError(f"已有其他服务使用 {unit_path}")
    old = path.read_bytes() if path.exists() else None
    old_unit = unit_path.read_bytes() if unit_path.exists() else None
    ports = (inbound.get("listen_port", inbound.get("port", 0)) for inbound in server.get("inbounds", []))
    capabilities = "CAP_NET_BIND_SERVICE" if any(0 < port < 1024 for port in ports) else ""
    encoded = dump(server).encode()
    installing = False
    try:
        with service_access(unit_path.name, path, encoded, credentials or {}) as (props, directory):
            unit = service_unit(binary, arguments.replace("%d", directory), props, capabilities).encode()
            if (reuse_active and old == encoded and old_unit == unit
                    and subprocess.run(["systemctl", "is-active", "--quiet", unit_path.name]).returncode == 0):
                run("systemctl", "enable", unit_path.name)
                return
            installing = True
            atomic(path, encoded)
            atomic(unit_path, unit, 0o644)
            run("systemctl", "daemon-reload")
            run("systemctl", "restart", unit_path.name)
            time.sleep(2)
            run("systemctl", "is-active", "--quiet", unit_path.name)
            run("systemctl", "enable", unit_path.name)
    except BaseException:
        if installing:
            subprocess.run(["systemctl", "stop", unit_path.name])
            for dest, data, mode in ((unit_path, old_unit, 0o644), (path, old, 0o600)):
                if data is None:
                    dest.unlink(missing_ok=True)
                else:
                    atomic(dest, data, mode)
            run("systemctl", "daemon-reload")
            if old_unit and old:
                run("systemctl", "start", unit_path.name)
        raise


def service_unit(binary, arguments, properties, capabilities):
    protection = "\n".join(properties)
    return UNIT_MARK + f"""[Unit]
Description=NAT relay
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
{protection}
ExecStart="{binary}" {arguments}
Environment=GOMEMLIMIT={memory_budget()}MiB
Environment=GOMAXPROCS=1
CapabilityBoundingSet={capabilities}
AmbientCapabilities={capabilities}
NoNewPrivileges=yes
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
"""


def xray_binary():
    target = Path("/usr/local/lib/nat-relay/xray")
    binary = shutil.which("xray")
    if binary or target.is_file():
        return binary or str(target)
    arch = {"x86_64": "64", "aarch64": "arm64-v8a"}.get(platform.machine())
    if not arch:
        raise ValueError("此架构请先安装官方 Xray-core")
    with urlopen("https://api.github.com/repos/XTLS/Xray-core/releases/latest", timeout=30) as r:
        release = json.load(r)
    name = f"Xray-linux-{arch}.zip"
    asset = next((v for v in release["assets"] if v["name"] == name), {})
    digest = asset.get("digest") or ""
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise ValueError("官方发行清单缺少有效 SHA-256，请先安装经验证的 Xray-core")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=target.parent) as tmp:
        archive = Path(tmp) / name
        sha = hashlib.sha256()
        with urlopen(asset["browser_download_url"], timeout=60) as res, archive.open("wb") as f:
            while chunk := res.read(262144):
                sha.update(chunk)
                f.write(chunk)
        if "sha256:" + sha.hexdigest() != digest:
            raise ValueError("Xray 压缩包摘要不匹配")
        staged = Path(tmp) / "xray"
        with zipfile.ZipFile(archive) as z, z.open("xray") as source, staged.open("wb") as f:
            shutil.copyfileobj(source, f)
        staged.chmod(0o755)
        run(staged, "version")
        os.replace(staged, target)
    return str(target)


def xhttp_inbound(tag, port, uid, path, cert=None, key=None):
    stream = {"network": "xhttp", "security": "none",
              "xhttpSettings": {"mode": "packet-up", "path": path}}
    if cert:
        stream.update(security="tls", tlsSettings={"alpn": ["h3"], "certificates": [
            {"certificate": cert.splitlines(), "key": key.splitlines()}]})
    return {"tag": tag, "port": port, "listen": "0.0.0.0" if cert else "127.0.0.1",
            "protocol": "vless", "settings": {"clients": [{"id": uid}], "decryption": "none"},
            "streamSettings": stream}


def xhttp_link(host, port, sni, alpn, uid, path, tag):
    params = dict(type="xhttp", encryption="none", mode="packet-up", security="tls",
                  sni=sni, alpn=alpn, path=path)
    return f"vless://{uid}@{host}:{port}?{urlencode(params)}#{tag}"


def xhttp_carrier(host, port, sni, alpn, uid, path, tag):
    return dict(name=tag, type="vless", server=str(host), port=port, uuid=uid,
                network="xhttp", tls=True, servername=sni, alpn=[alpn],
                **{"xhttp-opts": {"mode": "packet-up", "path": path}})


def publish_carriers(group, proxies, bootstrap=None, exit_doh=None, announce=True):
    """Persist each independently installed group's state and rebuild under one lock."""
    import fcntl
    with (ROOT / "carriers.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = ROOT / "carriers-state.json"
        if not proxies and not state.exists():
            return
        data = json.loads(state.read_text()) if state.exists() else {}
        data[group] = proxies
        if bootstrap:
            data["bootstrap"] = str(bootstrap)
            data["exit_doh"] = str(exit_doh)
        atomic(state, dump(data).encode())
        nodes = [p for kind in ("singbox", "h3", "temp") for p in data.get(kind, [])]
        target = ROOT / "relay-carriers.yaml"
        bundle = ROOT / "relay-node.json"
        if not nodes:
            target.unlink(missing_ok=True)
            bundle.unlink(missing_ok=True)
            return
        opts = SimpleNamespace(bootstrap_doh=data.get("bootstrap","1.1.1.1"),
                               exit_doh=data.get("exit_doh","1.1.1.1"))
        profile = mihomo_profile(opts, {"outbounds": []})
        profile["proxies"] = nodes
        profile["proxy-groups"][0]["proxies"] = [p["name"] for p in nodes]
        atomic(target, dump(profile).encode())
        client = json.loads((ROOT / "relay-v1.json").read_text())
        config = dict(client, version=2, carriers=profile)
        atomic(bundle, dump(config).encode())
        if proxies and announce:
            from relay_v1 import share_link
            print("NRP/2 合并节点（" + " + ".join(p["name"] for p in nodes) + "）",
                  share_link(config), sep="\n", flush=True)


def setup_v1(keys):
    from relay_v1 import SERVICE_PORT
    directory = ROOT / "nrp-tls"
    if not directory.exists():
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            pair = Path(tmp) / "tls"
            pair.mkdir(mode=0o700)
            run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-days", "730", "-subj", "/CN=nrp.invalid", "-addext",
                "subjectAltName=DNS:nrp.invalid", "-keyout", pair / "key.pem", "-out", pair / "cert.pem")
            os.replace(pair, directory)
    source = Path(__file__).with_name("relay_v1.py")
    program = Path("/usr/local/lib/nat-relay/relay_v1.py")
    program.parent.mkdir(parents=True, exist_ok=True)
    code = source.read_bytes()
    module = source.with_name("multipath.py").read_bytes()
    atomic(program.with_name("multipath.py"), module, 0o644)
    if not program.exists() or program.read_bytes() != code:
        atomic(program, code, 0o644)
    certificate = (directory / "cert.pem").read_text()
    config = dict(version=1, token=keys["nrp_token"], egress_password=keys["nrp_egress"],
                  runtime_sha256=hashlib.sha256(code + module).hexdigest(),
                  certificate_sha256=hashlib.sha256(certificate.encode()).hexdigest())
    cred = {n: directory / n for n in ("cert.pem","key.pem")}
    activate(sys.executable, config, ROOT / "nrp-server.json", UNIT.with_name("nat-relay-v1.service"),
             f'-B "{program}" server %d/config.json', cred, reuse_active=True)
    atomic(ROOT / "relay-v1.json", dump(dict(version=1, token=config["token"],
           certificate=certificate)).encode())
    print(f"NRP/1 已启用，VPS 回环入口 {SERVICE_PORT}。")


def enable_carrier(server, kind, password):
    from relay_v1 import SERVICE_PORT, EGRESS
    socks_port = dict(singbox=EGRESS[0], h3=EGRESS[1], temp=EGRESS[2])[kind]
    if kind == "singbox":
        tags = []
        for i, inbound in enumerate(server["inbounds"]):
            tags.append(inbound.setdefault("tag", f"carrier-{i}"))
        server["route"]["rules"].insert(0, {"inbound": tags, "ip_cidr": ["127.0.0.1/32"],
            "port": SERVICE_PORT, "network": "tcp", "action": "route", "outbound": "exit"})
        server["inbounds"].append(dict(type="socks", tag="nrp-egress", listen="127.0.0.1",
            listen_port=socks_port, users=[dict(username="nrp", password=password)]))
    else:
        tags = [i["tag"] for i in server["inbounds"]]
        server["routing"]["rules"].insert(0, dict(type="field", inboundTag=tags,
            ip=["127.0.0.1/32"], port=str(SERVICE_PORT), network="tcp", outboundTag="nrp"))
        server["outbounds"].append(dict(tag="nrp", protocol="freedom", settings={"finalRules": [
            dict(action="allow", ip=["127.0.0.1/32"], network="tcp", port=str(SERVICE_PORT))]}))
        server["inbounds"].append(dict(tag="nrp-egress", protocol="socks", listen="127.0.0.1",
            port=socks_port, settings={"auth": "password", "accounts": [{"user":"nrp","pass":password}]}))


def tunnel(port, uid, path, relay=False):
    # The edge host key is published at https://localhost.run/docs/security.
    scan = run("ssh-keyscan", "-T", "10", "-t", "ed25519", "localhost.run",
               stdout=subprocess.PIPE, text=True)
    keyfile = ROOT / "tunnel-known-hosts"
    for line in scan.stdout.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[:2] == ["localhost.run", "ssh-ed25519"]:
            fp = base64.b64encode(hashlib.sha256(base64.b64decode(fields[2])).digest())
            if fp.rstrip(b"=") == b"pG6qrBxubYfWa1Zadu/V0NUgjEDiBds/7e2xzte/QNM":
                atomic(keyfile, (line + "\n").encode())
                break
    else:
        raise ValueError("隧道网关主机密钥不匹配，请对照官方公布的指纹")
    command = ["ssh", "-T", "-F", "/dev/null", "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={keyfile}",
               "-o", "GlobalKnownHostsFile=/dev/null", "-o", "HostKeyAlgorithms=ssh-ed25519",
               "-o", "IdentityAgent=none", "-o", "PubkeyAuthentication=no",
               "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=20",
               "-o", "ServerAliveCountMax=3", "-o", "ConnectTimeout=15",
               "-R", f"80:127.0.0.1:{port}", "nokey@localhost.run"]
    output = ROOT / "xhttp-temp.txt"
    output.unlink(missing_ok=True)
    print(f"正在申请临时域名，回源 127.0.0.1:{port}；Ctrl+C 关闭。", flush=True)
    # Capture only the assigned hostname; exclude banners and request logs.
    assigned = re.compile(r"(?<![\w.-])([a-z0-9-]+\.(?:lhr\.life|lhr\.rocks|localhost\.run))\s+tunneled\s+with\s+tls", re.I)
    proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE)
    try:
        with selectors.DefaultSelector() as poll:
            poll.register(proc.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 45
            banner = ""
            while not output.exists():
                if not poll.select(max(0, deadline - time.monotonic())) or time.monotonic() >= deadline:
                    raise ValueError("等待临时域名超时，请检查网关可达性和域名分配情况")
                chunk = os.read(proc.stdout.fileno(), 4096)
                if not chunk:
                    raise ValueError("网关未返回临时域名，请检查出站 TCP 22 和服务商状态")
                banner = (banner + chunk.decode(errors="replace"))[-16384:]
                clean = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", banner)
                match = assigned.search(clean) or re.search(
                    r"https://([a-z0-9-]+\.lhr\.life)(?=[/\s])", clean, re.I)
                if match:
                    host = match[1].lower()
                    link = xhttp_link(host, 443, host, "http/1.1", uid, path, "XHTTP-Temp")
                    atomic(output, (link + "\n").encode())
                    if relay:
                        publish_carriers("temp", [xhttp_carrier(host, 443, host, "http/1.1",
                                                               uid, path, "XHTTP-Temp")])
                    print(link, flush=True)
        while proc.stdout.read(4096):
            pass
        if proc.wait():
            raise ValueError("临时隧道已中断，重新运行可申请新域名")
    finally:
        proc.terminate()
        proc.wait()
        output.unlink(missing_ok=True)
        if relay:
            publish_carriers("temp", [])


def xray_config(inbounds, doh):
    private = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
               "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4",
               "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"]
    return {"log": {"loglevel": "warning"}, "inbounds": inbounds,
            "dns": {"servers": [f"https+local://{doh}/dns-query"], "queryStrategy": "UseIPv4"},
            "outbounds": [{"protocol": "freedom", "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4"}}},
                          {"protocol": "blackhole", "tag": "deny"}],
            "routing": {"domainStrategy": "IPOnDemand", "rules": [
                {"type": "field", "ip": private, "outboundTag": "deny"}]}}


def temporary_xhttp(binary, port, doh, password=None):
    if not all(shutil.which(cmd) for cmd in ("ssh", "ssh-keyscan")):
        run("apt-get", "update")
        run("apt-get", "install", "-y", "--no-install-recommends", "openssh-client")
    uid, path = str(uuid.uuid4()), "/x-" + secrets.token_hex(12)
    server = xray_config([xhttp_inbound("temp", port, uid, path)], doh)
    if password:
        enable_carrier(server, "temp", password)
    unit = "nat-relay-xhttp-temp.service"
    with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
        config = Path(tmp) / "temp.json"
        encoded = dump(server).encode()
        atomic(config, encoded)
        run(binary, "run", "-test", "-c", config)
        with service_access(unit, config, encoded, {}, temporary=True) as (props, directory):
            args = [arg for prop in props for arg in ("-p", prop)]
            capability = "CAP_NET_BIND_SERVICE" if port < 1024 else ""
            run("systemd-run", "--collect", "--service-type=exec", "--unit", unit, *args,
                "-p", "NoNewPrivileges=yes", "-p", f"AmbientCapabilities={capability}",
                "-p", f"CapabilityBoundingSet={capability}", "-E", "GOMAXPROCS=1",
                "-E", f"GOMEMLIMIT={memory_budget()}MiB", binary, "run", "-c", f"{directory}/config.json")
            try:
                time.sleep(1)
                run("systemctl", "is-active", "--quiet", unit)
                tunnel(port, uid, path, bool(password))
            finally:
                subprocess.run(["systemctl", "stop", unit])


def deploy(a):
    import fcntl
    if os.geteuid() or not Path("/run/systemd/system").is_dir():
        raise ValueError("请在使用 systemd 的 Debian/Ubuntu VPS 上以 root 运行")
    ROOT.mkdir(mode=0o700, exist_ok=True)
    lock = (ROOT / "install.lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX)
    session = None
    if a.xhttp_temp or a.xhttp_h3:
        session = (ROOT / "xhttp.lock").open("a")
        fcntl.flock(session, fcntl.LOCK_EX | fcntl.LOCK_NB)
        (ROOT / "xhttp-temp.txt").unlink(missing_ok=True)
    cert = key = None
    if a.udp or a.tcp or a.xhttp_h3:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(a.cert, a.key)
        run("openssl", "verify", "-verify_hostname", a.name, "-purpose", "sslserver",
            "-untrusted", a.cert, a.cert)
        cert, key = a.cert.read_text(), a.key.read_text()
    identity = ROOT / "identity.json"
    keys = json.loads(identity.read_text()) if identity.exists() else credentials()
    if a.snell and "snell_psk" not in keys:
        keys["snell_psk"] = secrets.token_urlsafe(32)
    if a.relay_v1 and "nrp_token" not in keys:
        keys.update(nrp_token=secrets.token_hex(32), nrp_egress=secrets.token_urlsafe(32))
    atomic(identity, dump(keys).encode())
    if a.relay_v1:
        setup_v1(keys)
    if a.udp or a.tcp or a.snell:
        server, client, links = generate(a, keys, cert, key)
        if a.relay_v1:
            enable_carrier(server, "singbox", keys["nrp_egress"])
        private_core = Path("/usr/local/lib/nat-relay/sing-box")
        binary = str(private_core) if private_core.exists() else core()
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            draft = Path(tmp) / "check.json"
            for config in (client, server):
                draft.write_text(dump(config))
                run(binary, "check", "-c", draft)
        activate(binary, server, ROOT / "server.json", UNIT)
        raw = "".join(link + "\n" for link in links).encode()
        atomic(ROOT / "links.txt", raw)
        atomic(ROOT / "subscription.b64", base64.b64encode(raw) + b"\n")
        atomic(ROOT / "client.json", dump(client).encode())
        profile = mihomo_profile(a, client)
        atomic(ROOT / "mihomo.yaml", dump(profile).encode())
        publish_carriers("singbox", profile["proxies"] if a.relay_v1 else [], a.bootstrap_doh, a.exit_doh,
                         announce=not a.xhttp_temp)
        surge = ROOT / "snell-surge.conf"
        if a.snell:
            snell_client = dict(client, outbounds=[n for n in client["outbounds"] if n["type"] == "snell"],
                                route=dict(client["route"], final="Snell6"))
            atomic(ROOT / "snell-v2rayn.json", dump(snell_client).encode())
            line = f"Snell6 = snell, {a.ip}, {a.snell[0]}, psk={keys['snell_psk']}, version=6"
            atomic(surge, ("[Proxy]\n" + line + "\n").encode())
            print("Surge 策略行", line, sep="\n")
            print(f"Snell 6 已写入 {surge}、client.json 和 mihomo.yaml")
        else:
            surge.unlink(missing_ok=True)
            (ROOT / "snell-v2rayn.json").unlink(missing_ok=True)
        print(*links, sep="\n", flush=True)
        if a.xhttp_temp:
            print("等待临时 XHTTP 域名。分配成功后将在这里输出含 XHTTP 的合并节点，请保持终端打开。", flush=True)
    if a.xhttp_temp or a.xhttp_h3:
        binary = xray_binary()
    if a.xhttp_h3:
        path = keys["path"] + "-h3"
        inbound = xhttp_inbound("h3", a.xhttp_h3[1], keys["uuid"], path, cert, key)
        server = xray_config([inbound], a.exit_doh)
        if a.relay_v1:
            enable_carrier(server, "h3", keys["nrp_egress"])
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            draft = Path(tmp) / "check.json"
            draft.write_text(dump(server))
            run(binary, "run", "-test", "-c", draft)
        activate(binary, server, ROOT / "xray.json", UNIT.with_name("nat-relay-xray.service"))
        h3 = ROOT / "xhttp-h3.txt"
        link = xhttp_link(a.ip, a.xhttp_h3[0], a.name, "h3", keys["uuid"], path, "XHTTP-H3")
        atomic(h3, (link + "\n").encode())
        carriers = [xhttp_carrier(a.ip, a.xhttp_h3[0], a.name, "h3", keys["uuid"], path, "XHTTP-H3")]
        publish_carriers("h3", carriers if a.relay_v1 else [], a.bootstrap_doh, a.exit_doh)
        print(link, flush=True)
    lock.close()
    if a.xhttp_temp:
        def end_session(signum, frame):
            raise KeyboardInterrupt

        for sig in (signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, end_session)
        publish_carriers("temp", [], a.bootstrap_doh, a.exit_doh)
        temporary_xhttp(binary, a.origin_port, a.exit_doh, keys["nrp_egress"] if a.relay_v1 else None)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--auto", action="store_true", help="仅输入 TCP 映射，自动选择临时 XHTTP 回源端口")
    p.add_argument("--ip", type=ipaddress.IPv4Address, help="NAT 公网 IPv4")
    p.add_argument("--name", type=domain, help="直连 TLS 证书域名")
    p.add_argument("--cert", type=Path, help="受信任的完整证书链")
    p.add_argument("--key", type=Path, help="对应的 PEM 私钥")
    for flag in ("--tcp", "--udp", "--snell", "--xhttp-h3"):
        p.add_argument(flag, type=mapping, metavar="PUBLIC:LOCAL")
    p.add_argument("--xhttp-temp", action="store_true", help="为 VPS 本地 XHTTP 申请临时 HTTPS 域名")
    p.add_argument("--origin-port", default=8001, type=int, help="临时隧道的 VPS 回环 TCP 端口")
    p.add_argument("--cdn", action="store_true", help="使用已有同域名 WebSocket CDN")
    p.add_argument("--relay-v1", "--multipath", action="store_true", help="启用兼容 NRP/1 的多路径适配器")
    p.add_argument("--edge-port", type=int, default=443)
    p.add_argument("--bootstrap-doh", type=ipaddress.IPv4Address, default="1.1.1.1")
    p.add_argument("--exit-doh", type=ipaddress.IPv4Address, default="1.1.1.1")
    a = p.parse_args()
    if a.auto:
        quick_setup(a)
    if a.relay_v1:
        if not all(Path(__file__).with_name(n).is_file() for n in ("relay_v1.py", "multipath.py")):
            p.error("请把 relay_v1.py、multipath.py 与 install.py 放在同一目录")
        from relay_v1 import SERVICE_PORT, EGRESS
        local = [m[1] for m in (a.tcp, a.snell) if m]
        if a.xhttp_temp:
            local.append(a.origin_port)
        if set(local).intersection((SERVICE_PORT, *EGRESS)):
            p.error("NRP/1 保留 18930–18933 作为本地 TCP 端口")
    direct = a.tcp or a.udp or a.xhttp_h3
    if not (direct or a.snell or a.xhttp_temp):
        p.error("请指定一种入站或 --xhttp-temp")
    if (direct or a.snell) and not a.ip:
        a.ip = discover_ipv4()
    if direct and not (a.name and a.cert and a.key):
        p.error("直连 TLS 入站需要 --name、--cert 和 --key")
    if (a.cdn and not a.tcp) or not all(1 <= i <= 65535 for i in [a.edge_port, a.origin_port]):
        p.error("CDN 需要 --tcp；端口范围为 1–65535")
    for group in ((a.tcp, a.snell), (a.udp, a.xhttp_h3)):
        if all(group) and any(x == y for x, y in zip(*group)):
            p.error("同一传输协议的两个服务不能共用公网端口或内部端口")
    if a.xhttp_temp and any(m and m[1] == a.origin_port for m in (a.tcp, a.snell)):
        p.error("回源端口与其他 TCP 服务冲突")
    deploy(a)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
NRP_FILE_INSTALL_PY
cat > "$stage/relay_v1.py" <<'NRP_FILE_RELAY_V1_PY'
"""NRP/1 TCP stream adapter. Python 3.9+, no third-party dependencies."""
import argparse
import asyncio
import base64
import contextlib
import getpass
import hmac
import ipaddress
import json
import socket
import signal
import ssl
import struct
from pathlib import Path
import multipath

MAGIC = b"NRP\x01"
SERVICE_PORT = 18930
EGRESS = (18931, 18932, 18933)
LIMIT = 32
TIMEOUT = 12


def share_link(cfg):
    profile = cfg["carriers"]
    dns = profile["dns"]
    payload = [cfg["token"], cfg["certificate"], profile["proxies"],
               dns["proxy-server-nameserver"][0], dns["nameserver"][0]]
    data = json.dumps(payload, separators=(",", ":")).encode()
    return "nrp://v2/" + base64.urlsafe_b64encode(data).decode().rstrip("=")


def import_link(link):
    import re
    prefix = "nrp://v2/"
    if not link.startswith(prefix) or len(link) > 65536:
        raise ValueError("需要完整的 nrp://v2/ 节点连接。")
    try:
        body = link[len(prefix):]
        data = base64.b64decode(body + "=" * (-len(body) % 4), altchars=b"-_", validate=True)
        token, cert, nodes, bootstrap, resolver = json.loads(data)
        if not re.fullmatch(r"[0-9a-fA-F]{64}", token) or not 1 <= len(nodes) <= 6:
            raise ValueError
        if not isinstance(cert, str) or not cert.startswith("-----BEGIN CERTIFICATE-----"):
            raise ValueError
        for url, suffix in ((bootstrap, "/dns-query"), (resolver, "/dns-query#Auto")):
            if not url.startswith("https://") or not url.endswith(suffix):
                raise ValueError
            ipaddress.IPv4Address(url[8:-len(suffix)])
        allowed = {"name","type","server","port","udp","version","psk","password","sni",
                   "uuid","network","tls","servername","alpn","ws-opts","xhttp-opts"}
        for node in nodes:
            if node["type"] not in ("vless","snell","hysteria2") or set(node) - allowed:
                raise ValueError
            if not isinstance(node["port"], int) or not 1 <= node["port"] <= 65535:
                raise ValueError
            if set(node.get("ws-opts", {})) - {"path","headers"} or set(node.get("xhttp-opts", {})) - {"mode","path"}:
                raise ValueError
        profile = {"mode":"rule", "allow-lan":False, "log-level":"warning", "proxies":nodes,
                   "rules":["MATCH,Auto"], "dns":{"enable":True,"ipv6":False,
                   "proxy-server-nameserver":[bootstrap],"nameserver":[resolver]}}
        return dict(version=2, token=token, certificate=cert, carriers=profile)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise ValueError("NRP/2 节点连接不完整或格式错误。") from exc


async def address(reader, kind):
    if kind == 3:
        length = (await reader.readexactly(1))[0]
        return (await reader.readexactly(length)).decode("ascii")
    size = {1: 4, 4: 16}.get(kind)
    if size is None:
        raise ValueError("unsupported address")
    return str(ipaddress.ip_address(await reader.readexactly(size)))


def connect_socks(port, host, target_port, password=None):
    """Return a connected socket with no buffered bytes beyond the SOCKS reply."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT)
    try:
        with sock.makefile("rb", buffering=0) as src:
            def take(n):
                data = bytearray()
                while len(data) < n:
                    chunk = src.read(n - len(data))
                    if not chunk:
                        raise OSError("SOCKS connection closed")
                    data.extend(chunk)
                return bytes(data)
            method = 2 if password else 0
            sock.sendall(bytes([5, 1, method]))
            if take(2) != bytes([5, method]):
                raise OSError("SOCKS method rejected")
            if password:
                pw = password.encode("ascii")
                sock.sendall(b"\x01\x03nrp" + bytes([len(pw)]) + pw)
                if take(2) != b"\x01\x00":
                    raise OSError("SOCKS authentication rejected")
            try:
                ip = ipaddress.ip_address(host)
                dest = bytes([1 if ip.version == 4 else 4]) + ip.packed
            except ValueError:
                encoded = host.encode("idna")
                dest = bytes([3, len(encoded)]) + encoded
            sock.sendall(b"\x05\x01\x00" + dest + struct.pack("!H", target_port))
            ver, status, reserved, kind = take(4)
            if (ver, status, reserved) != (5, 0, 0):
                raise OSError("SOCKS CONNECT rejected")
            length = take(1)[0] if kind == 3 else {1: 4, 4: 16}[kind]
            take(length + 2)
        sock.setblocking(False)
        return sock
    except BaseException:
        sock.close()
        raise


async def open_egress(host, port, secret):
    for proxy_port in EGRESS:
        try:
            sock = await asyncio.to_thread(connect_socks, proxy_port, host, port, secret)
        except (OSError, ValueError):
            continue
        return await asyncio.open_connection(sock=sock)
    raise OSError("no reachable egress")


async def streams(plain, wire):
    async def encode():
        while True:
            block = await plain[0].read(32768)
            wire[1].write(struct.pack("!H", len(block)) + block)
            await wire[1].drain()
            if not block:
                return

    async def decode():
        while True:
            size = int.from_bytes(await wire[0].readexactly(2), "big")
            if size == 0:
                plain[1].write_eof()
                return
            plain[1].write(await wire[0].readexactly(size))
            await plain[1].drain()

    tasks = [asyncio.create_task(encode()), asyncio.create_task(decode())]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def serve_connection(reader, writer, cfg, hub):
    prefix = await asyncio.wait_for(reader.readexactly(4), TIMEOUT)
    if prefix == multipath.MAGIC:
        return await hub.accept(reader, writer, cfg)
    async def handshake():
        if prefix != MAGIC or await reader.readexactly(1) != b"\x01":
            raise ValueError("unsupported protocol or operation")
        if not hmac.compare_digest(await reader.readexactly(32), bytes.fromhex(cfg["token"])):
            raise PermissionError("authentication failed")
        port, length = struct.unpack("!HB", await reader.readexactly(3))
        host = (await reader.readexactly(length)).decode("ascii")
        if not port or not host or length > 253 or "\x00" in host:
            raise ValueError("invalid destination")
        return await open_egress(host, port, cfg["egress_password"])

    try:
        plain = await asyncio.wait_for(handshake(), TIMEOUT)
    except (OSError, ValueError, asyncio.TimeoutError) as err:
        status = 1 if isinstance(err, PermissionError) else 2 if isinstance(err, ValueError) else 3
        writer.write(MAGIC + bytes([status]))
        await writer.drain()
        return
    try:
        writer.write(MAGIC + b"\x00")
        await writer.drain()
        await streams(plain, (reader, writer))
    finally:
        plain[1].close()


async def client_connection(reader, writer, cfg, ctx, via):
    wire = None
    async def handshake():
        nonlocal wire
        ver, count = await reader.readexactly(2)
        if ver != 5 or 0 not in await reader.readexactly(count):
            writer.write(b"\x05\xff")
            await writer.drain()
            return False
        writer.write(b"\x05\x00")
        await writer.drain()
        ver, cmd, reserved, kind = await reader.readexactly(4)
        if (ver, cmd, reserved) != (5, 1, 0):
            writer.write(b"\x05\x07\x00\x01" + bytes(6))
            await writer.drain()
            return False
        host = (await address(reader, kind)).encode("ascii")
        port = await reader.readexactly(2)
        sock = await asyncio.to_thread(connect_socks, via, "127.0.0.1", SERVICE_PORT)
        wire = await asyncio.open_connection(sock=sock, ssl=ctx, server_hostname="nrp.invalid")
        wire[1].write(MAGIC + b"\x01" + bytes.fromhex(cfg["token"]) + port + bytes([len(host)]) + host)
        await wire[1].drain()
        if await wire[0].readexactly(5) != MAGIC + b"\x00":
            raise OSError("NRP CONNECT rejected")
        return True
    try:
        try:
            ready = await asyncio.wait_for(handshake(), TIMEOUT + 5)
        except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            writer.write(b"\x05\x01\x00\x01" + bytes(6))
            await writer.drain()
            return
        if ready:
            writer.write(b"\x05\x00\x00\x01" + bytes(6))
            await writer.drain()
            await streams((reader, writer), wire)
    finally:
        if wire:
            wire[1].close()


async def main_loop(a):
    if a.mode == "client" and str(a.config) == "-":
        cfg = import_link(getpass.getpass("粘贴 nrp://v2/ 节点连接后按回车：").strip())
    else:
        cfg = json.loads(a.config.read_text(encoding="utf-8"))
    if cfg.get("version") not in (1, 2) or len(bytes.fromhex(cfg["token"])) != 32:
        raise ValueError("unsupported or invalid NRP profile")
    server = a.mode == "server"
    if not server and cfg["version"] == 1 and a.listen_port == a.via_port:
        raise ValueError("NRP/1 本地入口和底层代理需要不同的端口")
    if server:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(a.config.with_name("cert.pem"), a.config.with_name("key.pem"))
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cadata=cfg["certificate"])
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    handlers = set()
    hub = multipath.Hub(open_egress)
    async def handle(reader, writer):
        if len(handlers) >= (LIMIT * 6 if server else LIMIT):
            writer.close()
            return
        task = asyncio.current_task()
        handlers.add(task)
        try:
            if server:
                await serve_connection(reader, writer, cfg, hub)
            elif cfg["version"] == 2:
                await multipath.client(reader, writer, cfg, ctx, routes,
                                       (address, connect_socks, SERVICE_PORT), a.trace, a.max_paths)
            else:
                await client_connection(reader, writer, cfg, ctx, a.via_port)
        except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            pass
        finally:
            handlers.discard(task)
            writer.close()
            with contextlib.suppress(OSError, asyncio.TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), 2)
    port = SERVICE_PORT if server else a.listen_port
    opts = {"ssl": ctx, "ssl_handshake_timeout": TIMEOUT} if server else {}
    manager = (multipath.carrier_process(cfg, a.mihomo, port) if not server and cfg["version"] == 2
               else contextlib.nullcontext([]))
    with manager as routes:
        async with await asyncio.start_server(handle, "127.0.0.1", port, **opts) as listener:
            versions = "1+2" if server else str(cfg["version"])
            print(f"NRP/{versions} {a.mode} 127.0.0.1:{port}", flush=True)
            try:
                await listener.serve_forever()
            finally:
                for task in handlers.copy():
                    task.cancel()
                await asyncio.gather(*handlers, return_exceptions=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=["server", "client"])
    p.add_argument("config", type=Path, help="配置文件路径；客户端填 - 可直接粘贴合并节点")
    p.add_argument("--via-port", type=int, default=2080)
    p.add_argument("--listen-port", type=int, default=2081)
    p.add_argument("--mihomo", default="mihomo", help="NRP/2 底层核心的可执行文件")
    p.add_argument("--trace", action="store_true", help="断开路径时输出每条路径的数据字节数")
    p.add_argument("--max-paths", type=int, default=2, choices=range(1, 7),
                   help="每个 NRP/2 会话的并行路径上限（默认 2）")
    args = p.parse_args()
    if args.mode == "client" and not all(1 <= v <= 65535 for v in (args.via_port, args.listen_port)):
        p.error("端口范围为 1–65535")
    try:
        def stop(signum, frame):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, stop)
        asyncio.run(main_loop(args))
    except KeyboardInterrupt:
        pass
NRP_FILE_RELAY_V1_PY
cat > "$stage/multipath.py" <<'NRP_FILE_MULTIPATH_PY'
"""NRP/2. One ordered TCP stream over authenticated TLS carrier connections."""
import asyncio
import contextlib
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import struct
import subprocess
import tempfile
import time

MAGIC = b"NRP\x02"
HEADER = struct.Struct("!BQH")   # type, chunk number, payload length
DATA, ACK, PING, PONG = range(4)
BLOCK, WINDOW = 8192, 32
GRACE = 20


class Link:
    def __init__(self, reader, writer, name):
        self.reader, self.writer, self.name = reader, writer, name
        self.seen = self.last_ping = time.monotonic()
        self.sent = self.received = self.replayed = 0
        self.used = 0

    def frame(self, kind, number, data=b""):
        self.writer.write(HEADER.pack(kind, number, len(data)) + data)


class Bond:
    def __init__(self, plain, trace=False):
        self.plain = plain
        self.trace = trace
        self.links = []
        self.pending = {}        # number -> (bytes, last link, send time)
        self.reorder = {}
        self.tx = self.rx = 0
        self.local_fin = self.peer_fin = False
        self.changed = asyncio.Event()
        self.delivery = asyncio.Lock()
        self.finished = False

    async def source(self):
        while not self.local_fin:
            while len(self.pending) >= WINDOW:
                self.changed.clear()
                await self.changed.wait()
            data = await self.plain[0].read(BLOCK)
            self.pending[self.tx] = (data, None, 0)
            self.tx += 1
            self.local_fin = not data
            self.changed.set()

    async def receive(self, link):
        self.links.append(link)
        self.changed.set()
        try:
            while True:
                kind, num, size = HEADER.unpack(await link.reader.readexactly(HEADER.size))
                if size > BLOCK or (kind != DATA and size):
                    raise ValueError("bad frame size")
                payload = await link.reader.readexactly(size)
                link.seen = time.monotonic()
                if kind == DATA:
                    link.received += size
                    async with self.delivery:
                        if num >= self.rx + WINDOW or (self.peer_fin and num >= self.rx):
                            raise ValueError("bad data sequence")
                        if num >= self.rx:
                            self.reorder.setdefault(num, payload)
                        while self.rx in self.reorder:
                            data = self.reorder.pop(self.rx)
                            if self.peer_fin:
                                raise ValueError("data after FIN")
                            if data:
                                self.plain[1].write(data)
                            else:
                                self.plain[1].write_eof()
                                self.peer_fin = True
                            await self.plain[1].drain()
                            self.rx += 1
                        link.frame(ACK, self.rx)
                elif kind == ACK and num <= self.tx:
                    for seq in list(self.pending):
                        if seq < num:
                            del self.pending[seq]
                elif kind == PING:
                    link.frame(PONG, num)
                elif kind != PONG:
                    raise ValueError("bad control frame")
                self.changed.set()
                await link.writer.drain()
        except (OSError, ValueError, asyncio.IncompleteReadError):
            pass
        finally:
            self.links.remove(link)
            link.writer.close()
            self.changed.set()
            if self.trace:
                print(f"path={link.name} sent={link.sent} received={link.received} replay={link.replayed}", flush=True)

    async def schedule(self):
        empty_since = ended = None
        while True:
            self.changed.clear()
            now = time.monotonic()
            if not self.links:
                empty_since = empty_since or now
                if now - empty_since >= GRACE:
                    raise ConnectionError("all carriers unavailable")
            else:
                empty_since = None
            if self.peer_fin and self.local_fin and not self.pending:
                ended = ended or now
                if now - ended >= 2:
                    return
            usable = []
            for link in self.links:
                if now - link.seen > 10:
                    link.writer.transport.abort()
                elif not link.writer.is_closing():
                    if now - link.last_ping >= 2:
                        link.frame(PING, 0)
                        link.last_ping = now
                    if link.writer.transport.get_write_buffer_size() < BLOCK * 8:
                        usable.append(link)
            load = {link: 0 for link in usable}
            for _, last, _ in self.pending.values():
                if last in load:
                    load[last] += 1
            for seq, (data, last, stamp) in self.pending.items():
                if not usable:
                    break
                if last in self.links and now - stamp < 1.5:
                    continue
                # Prefer a different carrier on timeout. Bound out-of-order data
                # by keeping every unacknowledged chunk in the same send window.
                choices = [link for link in usable if link is not last] or usable
                link = min(choices, key=lambda item: (load[item], item.used))
                link.frame(DATA, seq, data)
                link.sent += len(data)
                if last is not None:
                    link.replayed += len(data)
                link.used = time.monotonic_ns()
                if last in load:
                    load[last] -= 1
                load[link] += 1
                self.pending[seq] = (data, link, now)
            try:
                await asyncio.wait_for(self.changed.wait(), .2)
            except asyncio.TimeoutError:
                pass

    async def run(self):
        tasks = [asyncio.create_task(self.source()), asyncio.create_task(self.schedule())]
        try:
            await asyncio.gather(*tasks)
        finally:
            self.finished = True
            for task in tasks:
                task.cancel()
            for link in self.links:
                link.writer.close()
            self.plain[1].close()
            await asyncio.gather(*tasks, return_exceptions=True)


class Hub:
    def __init__(self, dial):
        self.sessions = {}
        self.dial = dial

    async def accept(self, reader, writer, cfg):
        async def handshake():
            token = await reader.readexactly(32)
            if not hmac.compare_digest(token, bytes.fromhex(cfg["token"])):
                raise ValueError("bad token")
            sid = await reader.readexactly(32)
            operation = await reader.readexactly(1)
            if operation == b"J":
                bond = self.sessions.get(sid)
                if not bond or bond.finished or len(bond.links) >= 6:
                    raise ValueError("unknown or full session")
            elif operation == b"O":
                port, length = struct.unpack("!HB", await reader.readexactly(3))
                host = (await reader.readexactly(length)).decode("ascii")
                if not host or not port or length > 253:
                    raise ValueError("invalid session")
                if sid in self.sessions:
                    bond = self.sessions[sid]
                    if (not bond or bond.finished or bond.destination != (host, port)
                            or len(bond.links) >= 6):
                        raise ValueError("conflicting session")
                    return bond
                if len(self.sessions) >= 32:
                    raise ValueError("session limit")
                self.sessions[sid] = None
                try:
                    bond = Bond(await self.dial(host, port, cfg["egress_password"]))
                    bond.destination = (host, port)
                    self.sessions[sid] = bond
                    asyncio.create_task(self.run(sid, bond))
                except BaseException:
                    self.sessions.pop(sid, None)
                    raise
            else:
                raise ValueError("bad operation")
            return bond
        bond = await asyncio.wait_for(handshake(), 12)
        writer.write(MAGIC + b"\x00")
        await bond.receive(Link(reader, writer, "inbound"))

    async def run(self, sid, bond):
        try:
            await bond.run()
        except (OSError, ValueError):
            pass
        finally:
            self.sessions.pop(sid, None)


async def client(reader, writer, cfg, ctx, routes, helpers, trace=False, max_paths=2):
    address, connect_socks, service_port = helpers
    sid = secrets.token_bytes(32)
    token = bytes.fromhex(cfg["token"])
    bond = Bond((reader, writer), trace)
    async def socks_request():
        ver, count = await reader.readexactly(2)
        if ver != 5 or 0 not in await reader.readexactly(count):
            writer.write(b"\x05\xff")
            return None
        writer.write(b"\x05\x00")
        ver, cmd, reserved, kind = await reader.readexactly(4)
        if (ver, cmd, reserved) != (5, 1, 0):
            writer.write(b"\x05\x07\x00\x01" + bytes(6))
            return None
        host = (await address(reader, kind)).encode("ascii")
        port = await reader.readexactly(2)
        return port + bytes([len(host)]) + host
    dest = await asyncio.wait_for(socks_request(), 12)
    if dest is None:
        return
    async def attach(route, operation):
        sock = await asyncio.to_thread(connect_socks, route[1], "127.0.0.1", service_port)
        link_reader, w = await asyncio.open_connection(sock=sock, ssl=ctx, server_hostname="nrp.invalid")
        try:
            w.write(MAGIC + token + sid + operation)
            await w.drain()
            if await link_reader.readexactly(5) != MAGIC + b"\x00":
                raise ConnectionError("NRP/2 handshake rejected")
        except BaseException:
            w.close()
            raise
        return Link(link_reader, w, route[0])

    workers = {}
    backoff = {}
    async def replenish():
        while not bond.finished:
            now = time.monotonic()
            for route, task in list(workers.items()):
                if task.done():
                    await asyncio.gather(task, return_exceptions=True)
                    del workers[route]
                    backoff[route] = now + 4
            for route in routes:
                if len(workers) >= max_paths:
                    break
                if route not in workers and backoff.get(route, 0) <= now:
                    async def join(candidate):
                        link = await asyncio.wait_for(attach(candidate, b"J"), 6)
                        await bond.receive(link)
                    workers[route] = asyncio.create_task(join(route))
            await asyncio.sleep(.15)
    manager = None
    try:
        for route in routes:
            try:
                link = await asyncio.wait_for(attach(route, b"O" + dest), 6)
                workers[route] = asyncio.create_task(bond.receive(link))
                break
            except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                backoff[route] = time.monotonic() + 4
        else:
            writer.write(b"\x05\x01\x00\x01" + bytes(6))
            return
        manager = asyncio.create_task(replenish())
        writer.write(b"\x05\x00\x00\x01" + bytes(6))
        await bond.run()
    finally:
        if manager:
            manager.cancel()
            await asyncio.gather(manager, return_exceptions=True)
        for task in workers.values():
            task.cancel()
        await asyncio.gather(*workers.values(), return_exceptions=True)


@contextlib.contextmanager
def carrier_process(cfg, executable, local_port):
    binary = shutil.which(executable)
    if not binary:
        raise ValueError("请安装 Mihomo，或使用 --mihomo 指定其可执行文件路径")
    profile = dict(cfg["carriers"])
    profile.pop("mixed-port", None)
    # Keep the DNS proxy group, but avoid unrelated URL probes.
    nodes = profile["proxies"]
    profile["proxy-groups"] = [{"type":"select", "name":"Auto", "proxies":[n["name"] for n in nodes]}]
    routes = []
    profile["listeners"] = []
    with contextlib.ExitStack() as stack:
        for node in nodes:
            sock = stack.enter_context(socket.socket())
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
            if port == local_port:
                sock = stack.enter_context(socket.socket())
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            routes.append((node["name"], port))
            profile["listeners"].append(dict(name="via-"+node["name"], type="socks", listen="127.0.0.1",
                                             port=port, proxy=node["name"], udp=False))
    with tempfile.TemporaryDirectory(prefix="nrp-") as tmp:
        path = Path(tmp) / "mihomo.yaml"
        path.write_text(json.dumps(profile), encoding="utf-8")
        os.chmod(path, 0o600)
        subprocess.run([binary, "-t", "-d", tmp, "-f", str(path)], check=True,
                       stdout=subprocess.DEVNULL)
        proc = subprocess.Popen([binary, "-d", tmp, "-f", str(path)], stdout=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 5
            for _, port in routes:
                while True:
                    if proc.poll() is not None or time.monotonic() >= deadline:
                        raise OSError("Mihomo 路径监听器启动失败")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.2):
                            break
                    except OSError:
                        time.sleep(.05)
            yield routes
        finally:
            proc.terminate()
            try:
                proc.wait(3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
NRP_FILE_MULTIPATH_PY
(cd -- "$stage" && sha256sum --check --status <<'NRP_SHA256'
30e67738b3be16d649f673df0edf2ba1aa963a55c44d78419c4be65802d016e9  install.py
3dbd1008e62b2a9b24defda01e1605c6be327625082bccf2ec5b99829031d5f2  relay_v1.py
291eeb242df5a7f625441c1c1aad76bf8e0fd5e5a86805a0ed1cde59582f4f9a  multipath.py
NRP_SHA256
) || fail "内嵌文件校验失败。"

if [[ $action == check ]]; then
    python3 -I -B -c 'import pathlib,sys; p=pathlib.Path(sys.argv[1]).resolve(); sys.path.insert(0,str(p)); import install,relay_v1,multipath; assert all(pathlib.Path(m.__file__).parent == p for m in (install,relay_v1,multipath))' "$stage"
    printf '%s\n' '通过：三个内嵌模块的 SHA-256 和 Python 导入检查均成功。'
    exit 0
fi
if [[ $action == options ]]; then
    python3 -B "$stage/install.py" --help
    exit 0
fi
python3 -B "$stage/install.py" --multipath "$@"
