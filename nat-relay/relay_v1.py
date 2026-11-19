"""NRP/1 TCP stream adapter. Python 3.9+, no third-party dependencies."""
import argparse
import base64
import contextlib
import hmac
import ipaddress
import json
import socket
import signal
import struct
from pathlib import Path

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
    import asyncio

    for proxy_port in EGRESS:
        try:
            sock = await asyncio.to_thread(connect_socks, proxy_port, host, port, secret)
        except (OSError, ValueError):
            continue
        return await asyncio.open_connection(sock=sock)
    raise OSError("no reachable egress")


async def streams(plain, wire):
    import asyncio

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
    import asyncio
    import multipath

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
    import asyncio

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
    import asyncio
    import ssl
    import multipath

    if a.mode == "client" and str(a.config) == "-":
        import getpass

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
    import asyncio

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
