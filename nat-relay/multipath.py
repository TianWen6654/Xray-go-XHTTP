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
