#!/usr/bin/env python3
"""Fixed-port sing-box and Xray installer for Debian/Ubuntu with systemd 247+."""
import argparse
import base64
from contextlib import contextmanager, ExitStack
from functools import lru_cache
from itertools import combinations
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import shutil
import socket
import subprocess
import sys
from types import SimpleNamespace
import tempfile
import time
from urllib.parse import parse_qs, quote, urlencode, urlsplit, urlunsplit
import uuid
import warnings

ROOT = Path("/etc/nat-relay")
UNIT = Path("/etc/systemd/system/nat-relay.service")
UNIT_MARK = "# Managed by nat-relay/install.py\n"
UNIT_DATA = Path("/etc/nat-relay-unit-data")
RUNTIME_UNITS = Path("/run/systemd/system")
# Verified against the SHA-256 fingerprint at https://localhost.run/docs/security.
TUNNEL_HOST_KEY = (
    "localhost.run ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILVqOuSMnyeGDVO1lG6EaG5In/dXABCchhmHKkuRU2s9\n"
)


def run(*cmd, **kwargs):
    return subprocess.run(cmd, check=True, **kwargs)


def dump(data):
    return json.dumps(data, indent=2) + "\n"


def mapping(value):
    parts = value.replace("：", ":").split(":")
    if len(parts) == 1:
        parts *= 2
    try:
        public, local = map(int, parts)
        if 1 <= min(public, local) and max(public, local) <= 65535:
            return public, local
    except ValueError:
        pass
    raise argparse.ArgumentTypeError("请输入端口号或 公网端口:内部端口，范围 1–65535")


def public_ports(value):
    parts = re.split(r"[,，\s]+", value.strip())
    if not 1 <= len(parts) <= 20 or any(
        not re.fullmatch(r"[0-9]{1,5}", part) or not 1 <= int(part) <= 65535 for part in parts
    ):
        raise argparse.ArgumentTypeError("填写面板分配的 1–20 个 TCP 端口，以逗号分隔")
    return list(dict.fromkeys(map(int, parts)))


def discover_ipv4():
    from urllib.request import ProxyHandler, build_opener

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
            print(f"检测到出口 IPv4 {address}。若与面板的 NAT 入口不同，请用 --host 指定入口。", flush=True)
            return address
    raise ValueError("无法探测公网 IPv4。请用 --host 指定面板的公网入口域名或 IPv4。")


def quick_setup(a):
    from relay_v1 import EGRESS, SERVICE_PORT
    reserved = (SERVICE_PORT, *EGRESS)
    while not a.snell:
        try:
            value = input("TCP 端口（如 10880；端口不同时填 公网端口:内部端口）：").strip()
        except EOFError:
            raise ValueError("终端输入已关闭。可以用 --auto --snell 公网端口:内部端口。") from None
        try:
            ports = mapping(value)
            if ports[1] in reserved:
                raise ValueError("内部端口 18930–18934 已保留。")
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


def entry_host(value):
    value = value.strip()
    try:
        return ipaddress.IPv4Address(value)
    except ValueError:
        if value.endswith("."):
            value = value[:-1]
        if not re.fullmatch(r"[0-9.]+", value):
            try:
                return domain(value)
            except argparse.ArgumentTypeError:
                pass
        raise argparse.ArgumentTypeError("请填写入口域名或 IPv4，不含协议、端口或路径") from None


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
    from urllib.request import urlopen
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


@contextmanager
def runtime_unit(name, contents):
    path = RUNTIME_UNITS / name
    if path.is_symlink() or (path.exists() and not path.read_text().startswith(UNIT_MARK)):
        raise ValueError(f"已有其他运行时服务使用 {path}")
    atomic(path, contents.encode(), 0o644)
    loaded = False
    try:
        run("systemctl", "daemon-reload")
        fragment = run("systemctl", "show", "-p", "FragmentPath", "--value", name,
                       stdout=subprocess.PIPE, text=True).stdout.strip()
        if fragment != str(path):
            raise ValueError(f"systemd 未加载 {path}（FragmentPath={fragment}）")
        loaded = True
        yield
    finally:
        if loaded:
            subprocess.run(["systemctl", "stop", name])
            subprocess.run(["systemctl", "reset-failed", name], capture_output=True)
        path.unlink(missing_ok=True)
        subprocess.run(["systemctl", "daemon-reload"])


@lru_cache(maxsize=1)
def has_service_namespace():
    name = f"natr-probe-{uuid.uuid4().hex[:16]}.service"
    probe = UNIT_MARK + """[Service]
Type=oneshot
DynamicUser=yes
ProtectSystem=strict
ProtectHome=yes
LoadCredential=probe:/etc/os-release
ExecStart=/bin/true
"""
    with runtime_unit(name, probe):
        result = subprocess.run(["systemctl", "start", name], capture_output=True, text=True)
        if result.returncode == 0:
            return True
        status = run("systemctl", "show", "-p", "ExecMainStatus", "--value", name,
                     stdout=subprocess.PIPE, text=True).stdout.strip()
        if status not in {"226", "243"}:
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
        # System services use this credential directory even on systemd 247,
        # which supports LoadCredential but does not expand the %d specifier.
        yield properties, f"/run/credentials/{unit}"
        return
    name = {"nat-relay.service": "natr-singbox", "nat-relay-v1.service": "natr-adapter",
            "nat-relay-xray.service": "natr-xray", "nat-relay-xhttp-tcp.service": "natr-xhttp",
            "nat-relay-xhttp-temp.service": "natr-temp", "nat-relay-wss.service": "natr-wss",
            "nat-relay-ngrok.service": "natr-ngrok", "nat-relay-cloudflared.service": "natr-cf",
            "nat-relay-web.service": "natr-web", "nat-relay-web-xray.service": "natr-web-xray",
            "nat-relay-quick-origin.service": "natr-quick-origin",
            "nat-relay-quick-edge.service": "natr-quick-edge",
            "nat-relay-quick-ssh.service": "natr-quick-ssh"}[unit]
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
             reuse_active=False, bind_port=None, verify=None):
    if unit_path.exists() and not unit_path.read_text().startswith(UNIT_MARK):
        raise ValueError(f"已有其他服务使用 {unit_path}")
    old = path.read_bytes() if path.exists() else None
    old_unit = unit_path.read_bytes() if unit_path.exists() else None
    inbounds = server.get("inbounds", []) if isinstance(server, dict) else []
    ports = (inbound.get("listen_port", inbound.get("port", 0)) for inbound in inbounds)
    needs_bind_capability = (bind_port is not None and bind_port < 1024) or any(0 < port < 1024 for port in ports)
    capabilities = "CAP_NET_BIND_SERVICE" if needs_bind_capability else ""
    encoded = server if isinstance(server, bytes) else dump(server).encode()
    installing = False
    try:
        with service_access(unit_path.name, path, encoded, credentials or {}) as (props, directory):
            unit = service_unit(binary, arguments.replace("%d", directory), props, capabilities).encode()
            if (reuse_active and old == encoded and old_unit == unit
                    and subprocess.run(["systemctl", "is-active", "--quiet", unit_path.name]).returncode == 0):
                if verify:
                    verify()
                run("systemctl", "enable", unit_path.name)
                return
            installing = True
            atomic(path, encoded)
            atomic(unit_path, unit, 0o644)
            run("systemctl", "daemon-reload")
            run("systemctl", "restart", unit_path.name)
            time.sleep(2)
            run("systemctl", "is-active", "--quiet", unit_path.name)
            if verify:
                verify()
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


def service_unit(binary, arguments, properties, capabilities, restart="on-failure"):
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
Restart={restart}
RestartSec=3

[Install]
WantedBy=multi-user.target
"""


def xray_binary():
    binary = shutil.which("xray")
    if binary:
        return binary
    target = Path("/usr/local/lib/nat-relay/xray")
    directory = target.parent
    directory.mkdir(parents=True, exist_ok=True, mode=0o711)
    info = directory.lstat()
    if directory.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError(f"Xray 安装目录权限异常：{directory}")
    mode = info.st_mode & 0o7777
    # A restrictive umask can remove directory traversal for the service account.
    if mode & 0o111 != 0o111:
        directory.chmod(mode | 0o111)
    if target.is_file():
        return str(target)
    import platform
    from urllib.request import urlopen
    import zipfile

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


def xhttp_inbound(tag, port, uid, path, cert=None, key=None, alpn="h3"):
    stream = {"network": "xhttp", "security": "none",
              "xhttpSettings": {"mode": "packet-up", "path": path}}
    if cert:
        stream.update(security="tls", tlsSettings={"alpn": [alpn], "certificates": [
            {"certificate": cert.splitlines(), "key": key.splitlines()}]})
    return {"tag": tag, "port": port, "listen": "0.0.0.0" if cert else "127.0.0.1",
            "protocol": "vless", "settings": {"clients": [{"id": uid}], "decryption": "none"},
            "streamSettings": stream}


def xhttp_link(host, port, sni, alpn, uid, path, tag, fingerprint=None):
    params = dict(type="xhttp", encryption="none", mode="packet-up", security="tls",
                  sni=sni, alpn=alpn, path=path)
    if fingerprint:
        params["pcs"] = fingerprint
    return f"vless://{uid}@{host}:{port}?{urlencode(params)}#{tag}"


def xhttp_carrier(host, port, sni, alpn, uid, path, tag, fingerprint=None):
    carrier = dict(name=tag, type="vless", server=str(host), port=port, uuid=uid,
                   network="xhttp", tls=True, servername=sni, alpn=[alpn],
                   **{"xhttp-opts": {"mode": "packet-up", "path": path}})
    if fingerprint:
        carrier["fingerprint"] = fingerprint
    return carrier


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
        nodes = [p for kind in ("singbox", "h3", "xhttp-tcp", "temp") for p in data.get(kind, [])]
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


def local_tls_pair(directory, name):
    if not directory.exists():
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            pair = Path(tmp) / "tls"
            pair.mkdir(mode=0o700)
            run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-days", "730", "-subj", f"/CN={name}", "-addext",
                f"subjectAltName=DNS:{name}", "-keyout", pair / "key.pem", "-out", pair / "cert.pem")
            os.replace(pair, directory)


def setup_v1(keys):
    from relay_v1 import SERVICE_PORT
    directory = ROOT / "nrp-tls"
    local_tls_pair(directory, "nrp.invalid")
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
    socks_port = dict(zip(("singbox", "h3", "temp", "xhttp-tcp"), EGRESS))[kind]
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


def assigned_host(line):
    """Read only allocation records; banners and forwarded request URLs are not nodes."""
    try:
        event = json.loads(line)
    except ValueError:
        match = re.match(r"^([a-z0-9.-]+)\s+tunneled with tls\b", line.strip(), re.I)
        if not match:
            return None
        address = match[1]
    else:
        if not isinstance(event, dict):
            return None
        if event.get("type") == "run.localhost.tunnel.registered":
            data = event.get("data")
            address = data.get("address") if isinstance(data, dict) else None
        elif event.get("event") == "tcpip-forward":
            if event.get("status") in ("error", "failed", "failure", "denied"):
                reason = str(event.get("message") or event["status"]).splitlines()[0]
                raise ValueError("网关拒绝分配临时域名：" + "".join(c for c in reason if c.isprintable())[:240])
            address = event.get("address") if event.get("status", "success") == "success" else None
        else:
            return None
    if not isinstance(address, str):
        return None
    try:
        host = domain(address)
    except argparse.ArgumentTypeError:
        return None
    if host.endswith((".lhr.life", ".lhr.rocks", ".localhost.run")) and host != "admin.localhost.run":
        return host
    return None


def tunnel_hosts(stream, timeout=60):
    deadline = time.monotonic() + timeout
    current = None
    pending = b""
    skipping = False
    with selectors.DefaultSelector() as poll:
        poll.register(stream, selectors.EVENT_READ)
        while True:
            remaining = max(0, deadline - time.monotonic()) if current is None else None
            if remaining == 0 or not poll.select(remaining):
                raise ValueError("临时域名分配超时：未收到有效的网关注册事件。")
            chunk = stream.read1(16384)
            lines = (pending + chunk).split(b"\n")
            pending = lines.pop() if chunk else b""
            for raw in lines:
                if skipping:
                    skipping = False
                    continue
                line = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", raw.decode(errors="replace")).strip()
                host = assigned_host(line)
                if host and current != host:
                    current = host
                    yield host
                elif current is None and line == "Host key verification failed.":
                    raise ValueError("localhost.run 主机密钥校验失败，请核对官方公布的 ED25519 指纹。")
                elif current is None and (line.startswith(("ssh:", "Error: remote port forwarding failed"))
                                          or "Permission denied (" in line):
                    raise ValueError(f"SSH 转发失败：{line[:300]}")
            if len(pending) > 262144:
                pending = b""
                skipping = True
            if not chunk:
                if current is None:
                    raise ValueError("SSH 会话已关闭，网关未返回有效的临时域名。")
                return


def ssh_tunnel_args(port, keyfile):
    return ["-T", "-F", "/dev/null", "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={keyfile}",
               "-o", "GlobalKnownHostsFile=/dev/null", "-o", "HostKeyAlgorithms=ssh-ed25519",
               "-o", "IdentityAgent=none", "-o", "PubkeyAuthentication=no",
               "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=20",
               "-o", "ServerAliveCountMax=3", "-o", "ConnectTimeout=15",
               "-R", f"80:127.0.0.1:{port}", "nokey@localhost.run", "--", "--output", "json"]


def tunnel(port, uid, path, relay=False):
    keyfile = ROOT / "tunnel-known-hosts"
    atomic(keyfile, TUNNEL_HOST_KEY.encode("ascii"))
    command = ["ssh", *ssh_tunnel_args(port, keyfile)]
    output = ROOT / "xhttp-temp.txt"
    output.unlink(missing_ok=True)
    print(f"正在申请临时域名，回源 127.0.0.1:{port}；Ctrl+C 关闭。", flush=True)
    proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        for host in tunnel_hosts(proc.stdout):
            link = xhttp_link(host, 443, host, "http/1.1", uid, path, "XHTTP-Temp")
            atomic(output, (link + "\n").encode())
            if relay:
                publish_carriers("temp", [xhttp_carrier(host, 443, host, "http/1.1",
                                                       uid, path, "XHTTP-Temp")])
            print(link, flush=True)
        if proc.wait():
            raise ValueError("临时隧道已中断，重新运行可申请新域名")
    finally:
        proc.terminate()
        proc.wait()
        proc.stdout.close()
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
    if not shutil.which("ssh"):
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
            capability = "CAP_NET_BIND_SERVICE" if port < 1024 else ""
            definition = service_unit(binary, f'run -c "{directory}/config.json"', props, capability, restart="no")
            with runtime_unit(unit, definition):
                run("systemctl", "restart", unit)
                time.sleep(1)
                run("systemctl", "is-active", "--quiet", unit)
                tunnel(port, uid, path, bool(password))


def direct_xhttp(binary, a, keys, kind, ports, cert, key):
    from nat_web import verify_tcp_tls

    alpn, name, fingerprint = ("h2" if kind == "xhttp-tcp" else "h3"), a.name, None
    if not cert:
        name = "xhttp.nrp.invalid"
        directory = ROOT / "xhttp-tcp-tls"
        local_tls_pair(directory, name)
        cert = (directory / "cert.pem").read_text()
        key = (directory / "key.pem").read_text()
        fingerprint = hashlib.sha256(base64.b64decode("".join(cert.splitlines()[1:-1]), validate=True)).hexdigest()
    public, local = ports
    uid, path = keys["uuid"], keys["path"] + ("-h2" if alpn == "h2" else "-h3")
    server = xray_config([xhttp_inbound(kind, local, uid, path, cert, key, alpn)], a.exit_doh)
    if a.relay_v1:
        enable_carrier(server, kind, keys["nrp_egress"])
    elif alpn == "h2":
        server["routing"]["rules"].insert(0, {"type": "field", "network": "udp", "outboundTag": "deny"})
    with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
        draft = Path(tmp) / "check.json"
        atomic(draft, dump(server).encode())
        run(binary, "run", "-test", "-c", draft)
    unit = "nat-relay-xhttp-tcp.service" if alpn == "h2" else "nat-relay-xray.service"
    config = "xhttp-tcp.json" if alpn == "h2" else "xray.json"
    verify = None
    if alpn == "h2":
        def verify():
            try:
                verify_tcp_tls("127.0.0.1", local, name, alpn, fingerprint)
            except (OSError, ValueError) as error:
                raise ValueError(f"VPS 本机 TCP {local} 的 TLS/HTTP2 自检失败：{error}") from error
    activate(binary, server, ROOT / config, UNIT.with_name(unit), reuse_active=True, verify=verify)
    if alpn == "h2":
        print(f"VPS 本机 TCP {local} 已通过 TLS/HTTP2 自检。面板映射应为 TCP {public} → {local}。", flush=True)
        try:
            verify_tcp_tls(str(a.ip), public, name, alpn, fingerprint)
        except (OSError, ValueError) as error:
            print(f"从 VPS 到公网入口 {a.ip}:{public} 的回环测试未通过：{error}。"
                  "请核对面板映射并从客户端运行真实代理测试。", file=sys.stderr, flush=True)
        else:
            print("从 VPS 到公网入口的回环测试通过。请从实际使用的客户端验证代理请求。", flush=True)
    tag = "XHTTP-TCP" if alpn == "h2" else "XHTTP-H3"
    args = (a.ip, public, name, alpn, uid, path, tag, fingerprint)
    link = xhttp_link(*args)
    atomic(ROOT / f"{tag.lower()}.txt", (link + "\n").encode())
    publish_carriers(kind, [xhttp_carrier(*args)] if a.relay_v1 else [], a.bootstrap_doh, a.exit_doh)
    print(link, flush=True)


def ngrok_binary():
    import platform
    import tarfile
    from urllib.request import urlopen

    def recent(path):
        if not path:
            return False
        result = subprocess.run([path, "version"], capture_output=True, text=True)
        match = re.search(r"\b3\.(\d+)\.(\d+)\b", result.stdout)
        return result.returncode == 0 and match is not None and tuple(map(int, match.groups())) >= (39, 7)

    managed = Path("/usr/local/lib/nat-relay/ngrok")
    for path in (shutil.which("ngrok"), managed if managed.is_file() else None):
        if recent(path):
            return path
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if not arch:
        raise ValueError("此架构请先安装官方 ngrok 3.39.7 或更新的 3.x 版本")
    url = f"https://bin.ngrok.com/c/bNyj1mQVY4c/ngrok-v3-stable-linux-{arch}.tgz"
    managed.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=managed.parent) as tmp:
        staged = Path(tmp) / "ngrok"
        with urlopen(url, timeout=45) as response:
            if not response.geturl().startswith("https://"):
                raise ValueError("ngrok 官方下载降级为非 HTTPS 连接")
            with tarfile.open(fileobj=response, mode="r|gz") as archive:
                for member in archive:
                    if member.isfile() and member.name in ("ngrok", "./ngrok"):
                        with archive.extractfile(member) as src, staged.open("wb") as dst:
                            shutil.copyfileobj(src, dst, length=128 * 1024)
                        break
        if not staged.is_file():
            raise ValueError("ngrok 发行包中没有找到代理程序")
        staged.chmod(0o755)
        if not recent(staged):
            raise ValueError("ngrok 代理版本不足，无法通过 HTTPS 查询证书吊销列表")
        os.replace(staged, managed)
    return managed


def edge_config(host, port, token):
    return {
        "version": 3,
        "agent": {
            "authtoken": token,
            "web_addr": "false",
            "console_ui": False,
            "remote_management": False,
            "update_check": False,
            "crl_url": "https://crl.ngrok-agent.com/ngrok.crl",
            "log": "stdout",
            "log_level": "warn",
        },
        "endpoints": [{
            "name": "nat-relay",
            "url": f"https://{host}",
            "upstream": {"url": f"http://127.0.0.1:{port}", "protocol": "http1"},
        }],
    }


def check_edge_egress():
    checks = (
        ("localhost.run", "localhost.run", 22),
        ("ngrok", "connect.ngrok-agent.com", 443),
        ("ngrok HTTPS CRL", "crl.ngrok-agent.com", 443),
        ("Cloudflare 区域 1", "region1.v2.argotunnel.com", 7844),
        ("Cloudflare 区域 2", "region2.v2.argotunnel.com", 7844),
    )
    for label, host, port in checks:
        try:
            addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as error:
            print(f"{label} {host}:{port} DNS 查询失败（{error}）", flush=True)
            continue
        # Try one address per family so a failed port does not stall the whole check.
        tested = set()
        failures = []
        for family, kind, protocol, _, address in sorted(addresses, key=lambda r: r[0] != socket.AF_INET):
            if family in tested:
                continue
            tested.add(family)
            try:
                with socket.socket(family, kind, protocol) as probe:
                    probe.settimeout(3)
                    probe.connect(address)
            except OSError as error:
                failures.append(f"{address[0]} {error.strerror or str(error)}")
                continue
            print(f"{label} {host}:{port} TCP 可达（{address[0]}）", flush=True)
            break
        else:
            print(f"{label} {host}:{port} TCP 未连通（{'；'.join(failures)}）", flush=True)


def cloudflared_binary(quick=False):
    import platform
    from urllib.request import urlopen

    managed = Path("/usr/local/lib/nat-relay/cloudflared")
    def supports(path):
        args = ["tunnel"] if quick else ["tunnel", "run"]
        flag = "--no-prechecks" if quick else "--token-file"
        result = subprocess.run([path, *args, "--help"], capture_output=True, text=True)
        return result.returncode == 0 and flag in result.stdout

    for path in (shutil.which("cloudflared"), managed if managed.is_file() else None):
        if path:
            if supports(path):
                return path
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if not arch:
        raise ValueError("此架构请先安装最新官方 cloudflared")
    with urlopen("https://api.github.com/repos/cloudflare/cloudflared/releases/latest", timeout=20) as response:
        release = json.load(response)
    asset = next((a for a in release["assets"] if a["name"] == f"cloudflared-linux-{arch}"), {})
    digest = asset.get("digest") or ""
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise ValueError("cloudflared 官方发行清单缺少 SHA-256，请先安装官方代理程序")
    managed.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=managed.parent) as tmp:
        staged = Path(tmp) / "cloudflared"
        sha = hashlib.sha256()
        with urlopen(asset["browser_download_url"], timeout=45) as response, staged.open("wb") as f:
            while chunk := response.read(128 * 1024):
                sha.update(chunk)
                f.write(chunk)
        if "sha256:" + sha.hexdigest() != digest:
            raise ValueError("cloudflared 下载文件的 SHA-256 校验失败")
        staged.chmod(0o755)
        if not supports(staged):
            raise ValueError("官方 cloudflared 缺少所需启动参数")
        os.replace(staged, managed)
    return managed


def verify_websocket(host, path, unit):
    import http.client
    import ssl

    nonce = base64.b64encode(secrets.token_bytes(16)).decode()
    expected = base64.b64encode(hashlib.sha1((nonce + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
    for _ in range(8):
        conn = http.client.HTTPSConnection(host, 443, timeout=3)
        try:
            conn.request("GET", path, headers={"Connection": "Upgrade", "Upgrade": "websocket",
                         "Sec-WebSocket-Key": nonce, "Sec-WebSocket-Version": "13"})
            response = conn.getresponse()
            accepted = response.getheader("Sec-WebSocket-Accept", "").encode()
            if response.status == 101 and secrets.compare_digest(expected, accepted):
                return
            reason = f"HTTP {response.status}"
            code = response.getheader("ngrok-error-code", "")
            if re.fullmatch(r"ERR_NGROK_\d+", code):
                reason += " " + code
        except ssl.SSLCertVerificationError:
            raise ValueError(f"{host} 的公网 TLS 证书校验失败") from None
        except (OSError, http.client.HTTPException) as exc:
            reason = type(exc).__name__
        finally:
            conn.close()
        time.sleep(2)
    raise ValueError(f"{host}:443 的 WebSocket 握手未就绪（{reason}）。请查看 journalctl -u {unit} -n 25。")


def edge_origin(xray, identity, port, doh):
    if identity.is_file():
        keys = json.loads(identity.read_text())
    else:
        generated = run(xray, "vlessenc", stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout
        match = re.search(r'"decryption"\s*:\s*"([^"]+)"\s*,?\s*"encryption"\s*:\s*"([^"]+)"', generated)
        if match is None:
            raise ValueError("当前 Xray 缺少 VLESS Encryption，请升级 Xray-core")
        keys = {**credentials(), "decrypt": match[1], "encrypt": match[2]}
        atomic(identity, dump(keys).encode())
    inbound = {"tag": "wss-edge", "listen": "127.0.0.1", "port": port, "protocol": "vless",
               "settings": {"clients": [{"id": keys["uuid"]}], "decryption": keys["decrypt"]},
               "streamSettings": {"network": "ws", "security": "none",
                                  "wsSettings": {"path": keys["path"]}}}
    server = xray_config([inbound], doh)
    server["routing"]["rules"].insert(0, {"type": "field", "network": "udp", "outboundTag": "deny"})
    with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
        draft = Path(tmp) / "check.json"
        atomic(draft, dump(server).encode())
        run(xray, "run", "-test", "-c", draft)
    return server, keys


def export_edge_link(host, keys, path, label):
    params = urlencode(dict(type="ws", security="tls", encryption=keys["encrypt"],
                            host=host, sni=host, alpn="http/1.1", path=keys["path"]))
    link = f"vless://{keys['uuid']}@{host}:443?{params}#{label}"
    atomic(path, (link + "\n").encode())
    print(link, flush=True)


QUICK_UNIT = "nat-relay-quick-edge.service"
QUICK_SSH_UNIT = "nat-relay-quick-ssh.service"
QUICK_HOST = re.compile(r"https://([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.trycloudflare\.com)(?![a-z0-9.-])")


def quick_tunnel_host(unit=QUICK_UNIT, timeout=60):
    deadline = time.monotonic() + timeout
    while True:
        current = run("systemctl", "show", "-p", "InvocationID", "--value", unit,
                      stdout=subprocess.PIPE, text=True).stdout.strip()
        if re.fullmatch(r"[0-9a-f]{32}", current) and int(current, 16):
            logs = run("journalctl", "--no-pager", "-o", "cat", "-u", unit,
                       "_SYSTEMD_INVOCATION_ID=" + current, stdout=subprocess.PIPE, text=True).stdout
            if unit == QUICK_SSH_UNIT:
                for line in reversed(logs.splitlines()):
                    host = assigned_host(line)
                    if host:
                        return host
                    if line.startswith("ssh:") or line == "Host key verification failed.":
                        raise ValueError(f"SSH 转发失败：{line[:240]}")
            else:
                match = QUICK_HOST.search(logs)
                if match and "protocol=http2" in logs and "Registered tunnel connection" in logs:
                    return match[1]
        if time.monotonic() >= deadline:
            port = 22 if unit == QUICK_SSH_UNIT else 7844
            raise ValueError(f"临时域名未就绪。请检查出站 TCP {port} 和 journalctl -u {unit} -n 25。")
        time.sleep(1)


def deploy_quick_edge(a):
    import fcntl
    import shlex

    if os.geteuid() or not RUNTIME_UNITS.is_dir():
        raise ValueError("请在使用 systemd 的 Debian/Ubuntu VPS 上以 root 运行")
    ROOT.mkdir(mode=0o700, exist_ok=True)
    with (ROOT / "install.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        identity = ROOT / "quick-identity.json"
        origin = ROOT / "quick-origin.json"
        unit_path = UNIT.with_name("nat-relay-quick-origin.service")
        uses_ssh = a.edge_provider == "localhost-run"
        unit = QUICK_SSH_UNIT if uses_ssh else QUICK_UNIT
        connector = UNIT.with_name(unit)

        def verified_host(keys):
            host = quick_tunnel_host(unit)
            print(f"正在验证 {host}:443 的 HTTPS 和 WebSocket 握手。", flush=True)
            verify_websocket(host, keys["path"], unit)
            return host

        if a.show_quick_edge:
            if not identity.is_file() or not connector.is_file():
                raise ValueError("请先运行 --quick-edge 安装临时入口")
            keys = json.loads(identity.read_text())
            host = verified_host(keys)
        else:
            existing_port = json.loads(origin.read_text())["inbounds"][0]["port"] if origin.is_file() else 0
            port = a.origin_port or existing_port
            other = QUICK_UNIT if uses_ssh else QUICK_SSH_UNIT
            if existing_port and port != existing_port and UNIT.with_name(other).is_file():
                raise ValueError(f"另一个连接器已使用回源端口 {existing_port}；请复用此端口")
            if port == 0:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                    probe.bind(("127.0.0.1", 0))
                    port = probe.getsockname()[1]
            print(f"临时 HTTPS 入口的本地回源是 127.0.0.1:{port}。", flush=True)
            if uses_ssh:
                agent = shutil.which("ssh")
                if not agent:
                    run("apt-get", "update")
                    run("apt-get", "install", "-y", "--no-install-recommends", "openssh-client")
                    agent = shutil.which("ssh")
                edge = TUNNEL_HOST_KEY.encode("ascii")
                config = ROOT / "quick-ssh-host-key"
                args = shlex.join(ssh_tunnel_args(port, "%d/config.json"))
            else:
                agent = cloudflared_binary(quick=True)
                edge = b"{}\n"
                config = ROOT / "quick-edge.yaml"
                args = ('tunnel --config "%d/config.json" --no-autoupdate --no-prechecks '
                        f'--protocol http2 --metrics 127.0.0.1:0 --url http://127.0.0.1:{port}')
            xray = xray_binary()
            server, keys = edge_origin(xray, identity, port, a.exit_doh)
            was_installed = unit_path.exists()
            activate(xray, server, origin, unit_path, reuse_active=True)
            host = None

            def verify():
                nonlocal host
                host = verified_host(keys)

            try:
                activate(agent, edge, config, connector, arguments=args,
                         reuse_active=True, verify=verify)
            except BaseException:
                if not was_installed:
                    subprocess.run(["systemctl", "disable", "--now", unit_path.name])
                    unit_path.unlink(missing_ok=True)
                    origin.unlink(missing_ok=True)
                    subprocess.run(["systemctl", "daemon-reload"])
                raise
        filename = "quick-ssh.txt" if uses_ssh else "quick-edge.txt"
        export_edge_link(host, keys, ROOT / filename, "NAT-TCP-Quick")


def deploy_https_edge(a):
    import fcntl
    import getpass

    if os.geteuid() or not RUNTIME_UNITS.is_dir():
        raise ValueError("请在使用 systemd 的 Debian/Ubuntu VPS 上以 root 运行")
    uses_ngrok = a.edge_provider == "ngrok"
    label = "ngrok authtoken" if uses_ngrok else "Cloudflare Tunnel token"
    if not sys.stdin.isatty():
        raise ValueError(f"请在 VPS 交互终端运行，以便隐藏输入 {label}")
    # getpass's fallback echoes input on unusual terminals. Fail closed there.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            token = getpass.getpass(f"{label}（输入隐藏）：").strip()
        except (getpass.GetPassWarning, EOFError):
            raise ValueError("当前终端无法隐藏输入，请通过 SSH 或 VPS 的交互终端运行") from None
    token_pattern = r"[A-Za-z0-9_-]{15,256}" if uses_ngrok else r"[A-Za-z0-9_+=/.-]{30,4096}"
    if not re.fullmatch(token_pattern, token):
        raise ValueError(f"{label} 格式有误，请从对应控制台复制令牌")
    ROOT.mkdir(mode=0o700, exist_ok=True)
    with (ROOT / "install.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        origin = ROOT / "wss.json"
        if a.origin_port == 0:
            if origin.is_file():
                a.origin_port = json.loads(origin.read_text())["inbounds"][0]["port"]
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                    probe.bind(("127.0.0.1", 0))
                    a.origin_port = probe.getsockname()[1]
        print(f"Xray 本地回源使用 127.0.0.1:{a.origin_port}。", flush=True)
        xray = xray_binary()
        if uses_ngrok:
            agent = ngrok_binary()
            edge = edge_config(a.https_edge, a.origin_port, token)
            filename, unit = "ngrok.json", "nat-relay-ngrok.service"
            agent_args = 'start --all --config "%d/config.json"'
        else:
            agent = cloudflared_binary()
            edge = (token + "\n").encode("ascii")
            filename, unit = "cloudflared-token", "nat-relay-cloudflared.service"
            agent_args = 'tunnel --no-autoupdate --protocol http2 run --token-file "%d/config.json"'
        server, keys = edge_origin(xray, ROOT / "wss-identity.json", a.origin_port, a.exit_doh)
        if uses_ngrok:
            with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
                draft = Path(tmp) / "check.json"
                atomic(draft, dump(edge).encode())
                check = subprocess.run([agent, "config", "check", "--config", draft], capture_output=True)
                if check.returncode:
                    raise ValueError("ngrok 配置检查失败，请确认代理程序是 3.39.7 或更新的 3.x 版本")
        activate(xray, server, origin, UNIT.with_name("nat-relay-wss.service"), reuse_active=True)
        activate(agent, edge, ROOT / filename, UNIT.with_name(unit), arguments=agent_args, reuse_active=True)
        print(f"正在验证 {a.https_edge}:443 的 HTTPS 和 WebSocket 握手。", flush=True)
        verify_websocket(a.https_edge, keys["path"], unit)
        export_edge_link(a.https_edge, keys, ROOT / "wss-edge.txt", "HTTPS-Edge")


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
        try:
            fcntl.flock(session, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("已有会话持有 XHTTP 锁，请回到原终端查看节点或结束该会话。") from None
        if a.xhttp_temp:
            (ROOT / "xhttp-temp.txt").unlink(missing_ok=True)
    cert = key = None
    if a.udp or a.tcp or a.xhttp_h3 or (a.xhttp_tcp and a.cert):
        import ssl

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
    if a.xhttp_temp or a.xhttp_h3 or a.xhttp_tcp:
        binary = xray_binary()
        for kind, ports in (("h3", a.xhttp_h3), ("xhttp-tcp", a.xhttp_tcp)):
            if ports:
                direct_xhttp(binary, a, keys, kind, ports, cert, key)
    lock.close()
    if a.xhttp_temp:
        def end_session(signum, frame):
            raise KeyboardInterrupt

        for sig in (signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, end_session)
        publish_carriers("temp", [], a.bootstrap_doh, a.exit_doh)
        temporary_xhttp(binary, a.origin_port, a.exit_doh, keys["nrp_egress"] if a.relay_v1 else None)


def deploy_nat_web(a):
    import fcntl
    from nat_web import caddy_binary, caddy_config, select_public_port, verify_local_site

    if os.geteuid() or not RUNTIME_UNITS.is_dir():
        raise ValueError("请在使用 systemd 的 Debian/Ubuntu VPS 上以 root 运行")
    managed_cert = Path("/etc/letsencrypt/live") / a.nat_web
    cert = a.cert or managed_cert / "fullchain.pem"
    key = a.key or managed_cert / "privkey.pem"
    temporary = not cert.is_file() or not key.is_file()
    if temporary and a.cert:
        raise ValueError("指定的 TLS 证书或私钥文件不存在。")
    ROOT.mkdir(mode=0o700, exist_ok=True)
    with (ROOT / "install.lock").open("a") as lock, tempfile.TemporaryDirectory(dir=ROOT) as tls_dir:
        fcntl.flock(lock, fcntl.LOCK_EX)
        tls_pin = cert_hash = None
        if temporary:
            cert, key = Path(tls_dir) / "cert.pem", Path(tls_dir) / "key.pem"
            run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-days", "30", "-subj", f"/CN={a.nat_web}", "-addext",
                f"subjectAltName=DNS:{a.nat_web}", "-keyout", key, "-out", cert)
            public_key = run("openssl", "pkey", "-in", key, "-pubout", "-outform", "DER",
                             stdout=subprocess.PIPE).stdout
            tls_pin = "sha256//" + base64.b64encode(hashlib.sha256(public_key).digest()).decode("ascii")
            der = run("openssl", "x509", "-in", cert, "-outform", "DER", stdout=subprocess.PIPE).stdout
            cert_hash = hashlib.sha256(der).hexdigest()
            print("已生成 30 天临时证书。探测和节点使用指纹校验，普通浏览器会提示证书未受信任。", flush=True)
        else:
            run("openssl", "verify", "-verify_hostname", a.nat_web, "-purpose", "sslserver",
                "-untrusted", cert, cert)
        public = select_public_port(a.nat_web, a.listen_port, a.public_ports, cert, key, tls_pin)
        print(f"公网 TCP {public} → VPS TCP {a.listen_port} 已验证，正在部署。", flush=True)
        caddy, xray = caddy_binary(), xray_binary()
        identity = ROOT / "nat-web-identity.json"
        keys = json.loads(identity.read_text()) if identity.exists() else credentials()
        atomic(identity, dump(keys).encode())
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            backend = probe.getsockname()[1]
        inbound = {"tag": "nat-web", "listen": "127.0.0.1", "port": backend, "protocol": "vless",
                   "settings": {"clients": [{"id": keys["uuid"]}], "decryption": "none"},
                   "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": keys["path"]}}}
        server = xray_config([inbound], a.exit_doh)
        server["routing"]["rules"].insert(0, {"type": "field", "network": "udp", "outboundTag": "deny"})
        front = caddy_config(a.nat_web, a.listen_port, backend, keys["path"], cert.read_text(), key.read_text())
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            draft = Path(tmp) / "check.json"
            atomic(draft, dump(server).encode())
            run(xray, "run", "-test", "-c", draft)
            atomic(draft, dump(front).encode())
            run(caddy, "validate", "--config", draft)
        activate(xray, server, ROOT / "nat-web-xray.json", UNIT.with_name("nat-relay-web-xray.service"))
        activate(caddy, front, ROOT / "nat-web-caddy.json", UNIT.with_name("nat-relay-web.service"),
                 arguments='run --config "%d/config.json"', bind_port=a.listen_port)
        verify_local_site(a.nat_web, a.listen_port, keys["path"], cert if temporary else None)
        params = dict(type="ws", security="tls", encryption="none",
                      host=a.nat_web, sni=a.nat_web, alpn="http/1.1", path=keys["path"])
        if cert_hash:
            params["pcs"] = cert_hash
        link = f"vless://{keys['uuid']}@{a.nat_web}:{public}?{urlencode(params)}#NAT-HTTPS"
        atomic(ROOT / "nat-web.txt", (link + "\n").encode())
        print(f"网站 https://{a.nat_web}:{public}/", link, sep="\n", flush=True)


def switch_nat_web_port(candidates):
    import fcntl
    from nat_web import PROBE_CLIENT, verify_local_site

    if os.geteuid() or not RUNTIME_UNITS.is_dir() or not sys.stdin.isatty():
        raise ValueError("请在 VPS 的 root 交互终端切换公网端口")
    source = ROOT / "nat-web.txt"
    config = ROOT / "nat-web-caddy.json"
    if not source.is_file() or not config.is_file():
        raise ValueError("尚未找到已部署的 NAT HTTPS 节点，请先运行 --nat-web。")
    with (ROOT / "install.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        current = urlsplit(source.read_text().strip())
        fields = parse_qs(current.query)
        host = domain(current.hostname or "")
        path = fields.get("path", [""])[0]
        if (current.scheme != "vless" or not current.port or not current.username or current.password
                or fields.get("type") != ["ws"] or fields.get("security") != ["tls"]
                or not re.fullmatch(r"/ws-[0-9a-f]{24}", path)):
            raise ValueError("现有节点格式不符合 NAT HTTPS 安装器的输出。")
        uuid.UUID(current.username)
        front = json.loads(config.read_text())["apps"]
        local = int(front["http"]["servers"]["nat-web"]["listen"][0].rsplit(":", 1)[1])
        run("systemctl", "is-active", "--quiet", "nat-relay-web.service", "nat-relay-web-xray.service")
        ports = ",".join(map(str, candidates))
        command = (f"& ([ScriptBlock]::Create((Invoke-RestMethod '{PROBE_CLIENT}'))) "
                   f"-HostName '{host}' -PublicPorts @({ports}) -WebSocketPath '{path}'")
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            cafile = None
            if "pcs" in fields:
                pem = front["tls"]["certificates"]["load_pem"][0]["certificate"].encode()
                der = run("openssl", "x509", "-outform", "DER", input=pem, stdout=subprocess.PIPE).stdout
                if fields["pcs"] != [hashlib.sha256(der).hexdigest()]:
                    raise ValueError("节点指纹与当前 HTTPS 配置不一致。")
                pubkey = run("openssl", "x509", "-pubkey", "-noout", input=pem, stdout=subprocess.PIPE).stdout
                spki = run("openssl", "pkey", "-pubin", "-outform", "DER", input=pubkey, stdout=subprocess.PIPE).stdout
                pin = base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")
                command += f" -TlsPin 'sha256//{pin}'"
                cafile = Path(tmp) / "cert.pem"
                atomic(cafile, pem)
            verify_local_site(host, local, path, cafile)
        print(f"当前公网 TCP {current.port} → VPS 内部 {local}。先保留旧映射。", flush=True)
        print(f"将新候选公网 TCP 端口 {ports} 映射到同一个内部端口 {local}。", flush=True)
        print("在客户端 Windows PowerShell 运行下面整行，确认列为 Verified 的端口。", command, sep="\n", flush=True)
        try:
            chosen = input("填入一个 Verified 端口，或按回车取消：").strip()
        except EOFError:
            chosen = ""
        if not chosen:
            return
        if not re.fullmatch(r"[0-9]{1,5}", chosen) or int(chosen) not in candidates:
            raise ValueError("请选择已验证的候选端口。")
        public = int(chosen)
        link = urlunsplit(current._replace(netloc=f"{current.username}@{host}:{public}"))
        atomic(source, (link + "\n").encode())
        print(f"网站 https://{host}:{public}/", link, sep="\n", flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--auto", action="store_true", help="仅输入 TCP 映射，自动选择临时 XHTTP 回源端口")
    p.add_argument("--auto-tcp", action="store_true", help="仅输入 TCP 映射，部署单进程 XHTTP/HTTP2")
    p.add_argument("--host", "--ip", dest="ip", type=entry_host, help="NAT 公网入口域名或 IPv4")
    p.add_argument("--name", type=domain, help="直连 TLS 证书域名")
    p.add_argument("--cert", type=Path, help="受信任的完整证书链")
    p.add_argument("--key", type=Path, help="对应的 PEM 私钥")
    for flag in ("--tcp", "--udp", "--snell", "--xhttp-h3"):
        p.add_argument(flag, type=mapping, metavar="PUBLIC:LOCAL")
    p.add_argument("--xhttp-tcp", type=mapping, metavar="PUBLIC:LOCAL", help="通过 NAT 映射提供 XHTTP/HTTP2，支持自动签发并固定本地证书")
    p.add_argument("--nat-web", type=domain, metavar="DOMAIN", help="先从客户端验证 NAT 映射，再部署 HTTPS 网站和代理")
    p.add_argument("--switch-web-port", action="store_true", help="验证并更换已部署 NAT HTTPS 节点的公网 TCP 端口")
    p.add_argument("--public-ports", type=public_ports, help="面板已分配的候选公网 TCP 端口，用逗号分隔")
    p.add_argument("--listen-port", type=int, default=443, help="NAT HTTPS 模式的 VPS 内部 TCP 端口，默认 443")
    p.add_argument("--xhttp-temp", action="store_true", help="为 VPS 本地 XHTTP 申请临时 HTTPS 域名")
    p.add_argument("--https-edge", type=domain, metavar="DOMAIN", help="由 HTTPS 入口提供加密 VLESS WebSocket")
    p.add_argument("--edge-provider", choices=("ngrok", "cloudflare", "localhost-run"),
                   help="出站连接器，ngrok 用 TCP 443，Cloudflare 用 TCP 7844，localhost-run 用 TCP 22")
    p.add_argument("--check-egress", action="store_true", help="仅探测 VPS 到 HTTPS 隧道网关的出站 TCP 连通性")
    p.add_argument("--quick-edge", action="store_true", help="部署纯 TCP 的临时 HTTPS 入口，无需公网端口映射、域名或令牌")
    p.add_argument("--show-quick-edge", action="store_true", help="验证当前临时域名并输出对应节点链接")
    p.add_argument("--origin-port", type=int, help="隧道的 VPS 回环 TCP 端口；临时 HTTPS 默认自动选择")
    p.add_argument("--cdn", action="store_true", help="使用已有同域名 WebSocket CDN")
    p.add_argument("--relay-v1", "--multipath", action="store_true", help="启用兼容 NRP/1 的多路径适配器")
    p.add_argument("--edge-port", type=int, default=443)
    p.add_argument("--bootstrap-doh", type=ipaddress.IPv4Address, default="1.1.1.1")
    p.add_argument("--exit-doh", type=ipaddress.IPv4Address, default="1.1.1.1")
    a = p.parse_args()
    if a.quick_edge or a.show_quick_edge:
        has_conflict = any((a.auto, a.auto_tcp, a.nat_web, a.switch_web_port, a.ip, a.name,
                            a.cert, a.key, a.tcp, a.udp, a.snell, a.xhttp_h3, a.xhttp_tcp,
                            a.xhttp_temp, a.https_edge, a.cdn, a.check_egress, a.relay_v1,
                            a.public_ports, a.edge_provider == "ngrok"))
        if has_conflict or (a.show_quick_edge and (a.quick_edge or a.origin_port is not None)):
            p.error("--quick-edge 与 --show-quick-edge 单独运行")
        a.origin_port = 0 if a.origin_port is None else a.origin_port
        a.edge_provider = a.edge_provider or "localhost-run"
        if a.origin_port != 0 and not 1024 <= a.origin_port <= 65535:
            p.error("--quick-edge 的回环端口为 1024–65535，或使用 0 自动选择")
        deploy_quick_edge(a)
        return
    if a.origin_port is None:
        a.origin_port = 8001
    a.edge_provider = a.edge_provider or "ngrok"
    if a.edge_provider == "localhost-run":
        p.error("--edge-provider localhost-run 需要 --quick-edge 或 --show-quick-edge")
    if a.auto_tcp:
        if any((a.auto, a.nat_web, a.switch_web_port, a.https_edge, a.check_egress, a.tcp, a.udp,
                a.snell, a.xhttp_h3, a.xhttp_temp, a.cdn, a.relay_v1)):
            p.error("--auto-tcp 单独部署，可用 --host 指定公网入口")
        while not a.xhttp_tcp:
            try:
                a.xhttp_tcp = mapping(input("TCP 映射（如 10882:443，端口相同可直接填一个端口）：").strip())
            except EOFError:
                p.error("终端输入已关闭，请用 --xhttp-tcp 公网端口:内部端口")
            except argparse.ArgumentTypeError as error:
                print(error, file=sys.stderr)
    if a.switch_web_port:
        if not a.public_ports or any((a.nat_web, a.auto, a.tcp, a.udp, a.snell, a.xhttp_h3, a.xhttp_tcp,
                                      a.xhttp_temp, a.https_edge, a.check_egress)):
            p.error("--switch-web-port 单独运行，并用 --public-ports 指定候选端口")
        switch_nat_web_port(a.public_ports)
        return
    if a.nat_web:
        if not a.public_ports or not 1 <= a.listen_port <= 65535:
            p.error("--nat-web 需要 --public-ports，内部端口范围为 1–65535")
        if any((a.auto, a.ip, a.name, a.tcp, a.udp, a.snell, a.xhttp_h3, a.xhttp_tcp, a.xhttp_temp,
                a.https_edge, a.cdn, a.check_egress, a.edge_provider != "ngrok")):
            p.error("--nat-web 单独部署")
        if (a.cert is None) != (a.key is None):
            p.error("--cert 和 --key 必须一起填写")
        deploy_nat_web(a)
        return
    if a.check_egress:
        if any((a.https_edge, a.auto, a.tcp, a.udp, a.snell, a.xhttp_h3, a.xhttp_tcp, a.xhttp_temp)):
            p.error("--check-egress 单独运行")
        check_edge_egress()
        return
    if a.https_edge:
        auto_port = a.edge_provider == "ngrok" and a.origin_port == 0
        if any((a.auto, a.ip, a.name, a.cert, a.key, a.tcp, a.udp, a.snell, a.xhttp_h3,
                a.xhttp_tcp, a.xhttp_temp, a.cdn)) or not (auto_port or 1024 <= a.origin_port <= 65535):
            p.error("--https-edge 单独部署，回环端口为 1024–65535；ngrok 可填 0 自动选择")
        deploy_https_edge(a)
        return
    if a.edge_provider != "ngrok":
        p.error("--edge-provider 需要 --https-edge")
    if a.auto:
        quick_setup(a)
    if a.relay_v1:
        if not all(Path(__file__).with_name(n).is_file() for n in ("relay_v1.py", "multipath.py")):
            p.error("请把 relay_v1.py、multipath.py 与 install.py 放在同一目录")
        from relay_v1 import SERVICE_PORT, EGRESS
        local = [m[1] for m in (a.tcp, a.snell, a.xhttp_tcp) if m]
        if a.xhttp_temp:
            local.append(a.origin_port)
        if set(local).intersection((SERVICE_PORT, *EGRESS)):
            p.error("NRP 保留 18930–18934 作为本地 TCP 端口")
    direct = a.tcp or a.udp or a.xhttp_h3
    if not (direct or a.snell or a.xhttp_temp or a.xhttp_tcp):
        p.error("请指定一种入站或 --xhttp-temp")
    if (direct or a.snell or a.xhttp_tcp) and not a.ip:
        a.ip = discover_ipv4()
    if a.xhttp_tcp and isinstance(a.ip, ipaddress.IPv4Address) and (not a.ip.is_global or a.ip.is_multicast):
        p.error(f"{a.ip} 不是公网 IPv4；--host 请填写面板的公网入口域名或 IPv4")
    if (direct or (a.xhttp_tcp and (a.name or a.cert or a.key))) and not (a.name and a.cert and a.key):
        p.error("直连 TLS 入站需要 --name、--cert 和 --key")
    if (a.cdn and not a.tcp) or not all(1 <= i <= 65535 for i in [a.edge_port, a.origin_port]):
        p.error("CDN 需要 --tcp；端口范围为 1–65535")
    tcp = (a.tcp, a.snell, a.xhttp_tcp)
    for group in (tcp, (a.udp, a.xhttp_h3)):
        for left, right in combinations((m for m in group if m), 2):
            if any(x == y for x, y in zip(left, right)):
                p.error("同一传输协议的两个服务不能共用公网端口或内部端口")
    if a.xhttp_temp and any(m and m[1] == a.origin_port for m in tcp):
        p.error("回源端口与其他 TCP 服务冲突")
    deploy(a)


if __name__ == "__main__":
    if sys.version_info < (3, 9):
        sys.exit("需要 Python 3.9 或更新版本。")
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
