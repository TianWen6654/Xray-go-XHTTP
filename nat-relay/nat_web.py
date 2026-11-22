"""Verify a NAT mapping from the client before deploying a direct HTTPS site."""

import base64
import html
from http.server import BaseHTTPRequestHandler, HTTPServer
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import tempfile
import time

PROBE_CLIENT = (
    "https://raw.githubusercontent.com/TianWen6654/Xray-go-XHTTP/"
    "05b5c33aaab92bfbe1e1f17284409b66cb05902d/nat-relay/Test-NatRelayPort.ps1"
)


class ProbeHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.respond("probe")

    def do_POST(self):
        self.respond("select")

    def respond(self, operation):
        session = self.server
        match = re.fullmatch(r"/nat-relay/([a-f0-9]{32})/(probe|select)/([0-9]{1,5})", self.path)
        if not match or not secrets.compare_digest(match[1], session.challenge) or match[2] != operation:
            self.send_error(404)
            return
        port = int(match[3])
        authorities = {f"{session.host}:{port}"}
        if port == 443:
            authorities.add(session.host)
        if port not in session.ports or self.headers.get("Host", "").lower() not in authorities:
            self.send_error(404)
            return
        if operation == "select" and port not in session.verified:
            self.send_error(409)
            return
        reply = f"nat-relay:{session.challenge}:{port}" if operation == "probe" else f"selected:{port}"
        data = reply.encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=ascii")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        if operation == "probe":
            session.verified.add(port)
        else:
            session.selected = port


class ProbeServer(HTTPServer):
    timeout = 0.5

    def __init__(self, listen, host, ports, cert, key):
        self.host = host
        self.ports = ports
        self.challenge = secrets.token_hex(16)
        self.verified = set()
        self.selected = None
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.minimum_version = ssl.TLSVersion.TLSv1_2
        self.tls.load_cert_chain(cert, key)
        super().__init__(listen, ProbeHandler)

    def get_request(self):
        conn, address = super().get_request()
        try:
            conn.settimeout(1.5)
            return self.tls.wrap_socket(conn, server_side=True), address
        except OSError:
            conn.close()
            raise

    def handle_error(self, request, client_address):
        # Clients can close the socket while waiting for a short-lived probe response.
        pass


def select_public_port(host, local, candidates, cert, key, tls_pin=None):
    try:
        server = ProbeServer(("0.0.0.0", local), host, candidates, cert, key)
    except ssl.SSLError:
        raise
    except OSError as exc:
        raise ValueError(f"无法启动 {local} 的预检监听：{exc}。请选择空闲的 VPS 内部 TCP 端口。") from exc
    with server:
        ports = ",".join(map(str, candidates))
        command = (
            f"& ([ScriptBlock]::Create((Invoke-RestMethod '{PROBE_CLIENT}'))) "
            f"-HostName '{host}' -PublicPorts @({ports}) -Challenge '{server.challenge}'"
        )
        if tls_pin:
            command += f" -TlsPin '{tls_pin}'"
        print(f"请将面板已分配的候选公网 TCP 端口 {ports} 临时映射到 VPS 内部 {local}。", flush=True)
        print("在要使用的客户端网络上打开 Windows PowerShell，运行下面整行。", command, sep="\n", flush=True)
        print("从已验证端口中选一个并保留其映射。等待 5 分钟，Ctrl+C 可取消。", flush=True)
        deadline = time.monotonic() + 300
        while server.selected is None and time.monotonic() < deadline:
            server.handle_request()
        if server.selected is None:
            raise ValueError("尚未收到客户端确认。可以检查 DNS、端口映射和证书链后重试。")
        return server.selected


def caddy_config(host, local, backend, path, cert, key):
    site = ("<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\">"
            "<title>HTTPS 服务</title><main><h1>HTTPS 服务在线</h1>"
            f"<p>{html.escape(host)}</p></main></html>")
    return {
        "admin": {"disabled": True, "config": {"persist": False}},
        "apps": {
            "tls": {"certificates": {"load_pem": [{"certificate": cert, "key": key}]}},
            "http": {"servers": {"nat-web": {
                "listen": [f"0.0.0.0:{local}"],
                "protocols": ["h1", "h2"],
                "automatic_https": {"disable": True},
                "tls_connection_policies": [{}],
                "routes": [
                    {"match": [{"host": [host], "path": [path]}], "terminal": True,
                     "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": f"127.0.0.1:{backend}"}]}]},
                    {"match": [{"host": [host], "path": ["/"]}], "terminal": True,
                     "handle": [{"handler": "static_response", "body": site,
                                 "headers": {"Content-Type": ["text/html; charset=utf-8"]}}]},
                    {"handle": [{"handler": "static_response", "status_code": 404}]},
                ],
            }}},
        },
    }


def verify_local_site(host, local, path, cafile=None):
    ctx = ssl.create_default_context(cafile=str(cafile) if cafile else None)
    for endpoint, expected in (("/", 200), (path, 101)):
        with socket.create_connection(("127.0.0.1", local), timeout=4) as connection:
            with ctx.wrap_socket(connection, server_hostname=host) as tls:
                headers = ""
                if expected == 101:
                    nonce = secrets.token_bytes(16)
                    headers = (
                        "Connection: Upgrade\r\nUpgrade: websocket\r\n"
                        f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {base64.b64encode(nonce).decode()}\r\n"
                    )
                tls.sendall(f"GET {endpoint} HTTP/1.1\r\nHost: {host}\r\n{headers}\r\n".encode("ascii"))
                response = http.client.HTTPResponse(tls)
                response.begin()
                if response.status != expected:
                    raise ValueError(f"本机 HTTPS 自检返回 HTTP {response.status}，预期 {expected}。")
                response.close()


def verify_tcp_tls(address, port, server_name, protocol, fingerprint=None):
    """Check a TCP listener's certificate and negotiated application protocol."""
    context = ssl.create_default_context()
    if fingerprint is not None:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols([protocol])
    with socket.create_connection((address, port), timeout=4) as connection:
        with context.wrap_socket(connection, server_hostname=server_name) as tls:
            if fingerprint is not None:
                certificate = tls.getpeercert(binary_form=True)
                if not certificate or not secrets.compare_digest(hashlib.sha256(certificate).hexdigest(), fingerprint):
                    raise ValueError("TLS 证书指纹与此节点的证书不一致。")
            if tls.selected_alpn_protocol() != protocol:
                raise ValueError(f"TLS 服务未协商出 {protocol}。")


def caddy_binary():
    import platform
    import shutil
    import tarfile
    from urllib.request import urlopen

    existing = shutil.which("caddy")
    binary = Path("/usr/local/lib/nat-relay/caddy")
    if existing or binary.is_file():
        return existing or binary
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if not arch:
        raise ValueError("此平台请先安装官方 Caddy 软件包")
    with urlopen("https://api.github.com/repos/caddyserver/caddy/releases/latest", timeout=20) as response:
        release = json.load(response)
    suffix = f"_linux_{arch}.tar.gz"
    asset = next((a for a in release["assets"] if a["name"].startswith("caddy_") and a["name"].endswith(suffix)), {})
    digest = asset.get("digest") or ""
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("官方 Caddy 发行包缺少 SHA-256 校验信息")
    binary.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=binary.parent) as tmp:
        archive = Path(tmp) / "caddy.tar.gz"
        sha = hashlib.sha256()
        with urlopen(asset["browser_download_url"], timeout=45) as response, archive.open("wb") as f:
            while chunk := response.read(128 * 1024):
                sha.update(chunk)
                f.write(chunk)
        if "sha256:" + sha.hexdigest() != digest:
            raise ValueError("Caddy 下载文件的 SHA-256 校验失败")
        staged = Path(tmp) / "caddy"
        with tarfile.open(archive, "r:gz") as package:
            member = package.getmember("caddy")
            if not member.isfile():
                raise ValueError("Caddy 发行包结构不符合预期")
            with package.extractfile(member) as src, staged.open("wb") as dst:
                shutil.copyfileobj(src, dst, 128 * 1024)
        staged.chmod(0o755)
        os.replace(staged, binary)
    return binary
