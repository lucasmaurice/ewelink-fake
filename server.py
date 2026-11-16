#!/usr/bin/env python3
"""Fake eWeLink cloud: logs everything a Sonoff plug sends when its dispUrl
points here, and answers just enough of the protocol to keep it talking.

Standard library only (no pip, no egress). Listeners:
  HTTP_PORT  (8080) plain HTTP  - dispatch + websocket
  HTTPS_PORT (8443) TLS         - dispatch + websocket; TLS is started by hand
                                  so handshake failures (e.g. the plug rejecting
                                  the cert) are logged instead of swallowed
  ADMIN_PORT (9000) 127.0.0.1   - reach with `kubectl port-forward`:
      GET  /devices                  connected plugs, last register msg, params
      POST /devices/<id>/params      body {"switch":"on"} -> "update" to the plug
      POST /devices/<id>/raw         body sent to the plug as-is
"""
import asyncio
import base64
import hashlib
import json
import logging
import os
import ssl
import struct
import time
from datetime import datetime, timezone

log = logging.getLogger("ewelink")

PUBLIC_IP = os.environ.get("PUBLIC_IP", "127.0.0.1")
PUBLIC_HOST = os.environ.get("PUBLIC_HOST", "")
WS_ADVERTISED_PORT = int(os.environ.get("WS_ADVERTISED_PORT", "443"))
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))
HTTPS_PORT = int(os.environ.get("HTTPS_PORT", "8443"))
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "9000"))
TLS_CERT = os.environ.get("TLS_CERT", "/tls/tls.crt")
TLS_KEY = os.environ.get("TLS_KEY", "/tls/tls.key")

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_BODY = 1 << 20
LOG_BODY = 8000

devices = {}  # deviceid -> Device


class Device:
    def __init__(self, deviceid, apikey, send, peer, register_msg):
        self.deviceid = deviceid
        self.apikey = apikey
        self.send = send  # coroutine: send(text)
        self.peer = peer
        self.register_msg = register_msg
        self.params = {}
        self.connected_at = time.time()

    def summary(self):
        return {
            "deviceid": self.deviceid,
            "peer": self.peer,
            "connected_at": datetime.fromtimestamp(self.connected_at, timezone.utc).isoformat(),
            "register": self.register_msg,
            "params": self.params,
        }


def dumps(obj):
    return json.dumps(obj, separators=(",", ":"))


def try_json(data):
    try:
        return json.loads(data)
    except (ValueError, TypeError):
        return None


def show(data):
    text = data.decode("utf-8", "replace") if isinstance(data, bytes) else str(data)
    return text if len(text) <= LOG_BODY else text[:LOG_BODY] + f"...(+{len(text) - LOG_BODY})"


# ---------------------------------------------------------------- HTTP

async def read_request(reader):
    head = await reader.readuntil(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    method, target, version = (lines[0].split(" ", 2) + ["", ""])[:3]
    headers = {}
    for line in lines[1:]:
        if line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    body = b""
    if headers.get("transfer-encoding", "").lower() == "chunked":
        while True:
            size = int((await reader.readuntil(b"\r\n")).split(b";")[0].strip() or b"0", 16)
            if size == 0:
                await reader.readuntil(b"\r\n")
                break
            if len(body) + size > MAX_BODY:
                raise ValueError("body too large")
            body += await reader.readexactly(size)
            await reader.readexactly(2)
    elif headers.get("content-length"):
        n = int(headers["content-length"])
        if n > MAX_BODY:
            raise ValueError("body too large")
        body = await reader.readexactly(n)
    return method, target, version, headers, body


async def send_response(writer, status, body, keep_alive=True, ctype="application/json"):
    reason = {200: "OK", 400: "Bad Request", 404: "Not Found"}.get(status, "OK")
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: {ctype}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: {'keep-alive' if keep_alive else 'close'}\r\n\r\n"
    )
    writer.write(head.encode() + body)
    await writer.drain()


def route_device_http(method, target, body):
    path = target.split("?", 1)[0]
    data = try_json(body)
    if "dispatch" in path or (isinstance(data, dict) and "accept" in data):
        reply = {"error": 0, "reason": "ok", "IP": PUBLIC_IP, "port": WS_ADVERTISED_PORT}
        if PUBLIC_HOST:
            reply["domain"] = PUBLIC_HOST
        return 200, dumps(reply).encode()
    return 200, b'{"error":0}'


async def serve_http(reader, writer, peer, label, router, ws_ok):
    while True:
        try:
            method, target, version, headers, body = await asyncio.wait_for(read_request(reader), 300)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
            return
        except (asyncio.LimitOverrunError, ValueError) as e:
            log.warning("%s %s bad request: %r", label, peer, e)
            return
        log.info("%s %s %s %s headers=%s body=%s", label, peer, method, target,
                 dumps(headers), show(body))
        if ws_ok and headers.get("upgrade", "").lower() == "websocket":
            await handle_ws(reader, writer, headers, peer, label)
            return
        status, payload = await router(method, target, body)
        log.info("%s %s -> %d %s", label, peer, status, show(payload))
        keep = version == "HTTP/1.1" and headers.get("connection", "").lower() != "close"
        await send_response(writer, status, payload, keep_alive=keep)
        if not keep:
            return


# ---------------------------------------------------------------- WebSocket

def ws_frame(opcode, payload):
    n = len(payload)
    if n < 126:
        head = struct.pack("!BB", 0x80 | opcode, n)
    elif n < 65536:
        head = struct.pack("!BBH", 0x80 | opcode, 126, n)
    else:
        head = struct.pack("!BBQ", 0x80 | opcode, 127, n)
    return head + payload


async def ws_read_frame(reader):
    b1, b2 = await reader.readexactly(2)
    n = b2 & 0x7F
    if n == 126:
        (n,) = struct.unpack("!H", await reader.readexactly(2))
    elif n == 127:
        (n,) = struct.unpack("!Q", await reader.readexactly(8))
    if n > MAX_BODY:
        raise ValueError("frame too large")
    mask = await reader.readexactly(4) if b2 & 0x80 else None
    data = await reader.readexactly(n)
    if mask:
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    return bool(b1 & 0x80), b1 & 0x0F, data


async def handle_ws(reader, writer, headers, peer, label):
    key = headers.get("sec-websocket-key")
    if not key:
        await send_response(writer, 400, b'{"error":400}', keep_alive=False)
        return
    accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
    writer.write((
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())
    await writer.drain()
    log.info("%s %s websocket open", label, peer)

    lock = asyncio.Lock()

    async def send_raw(opcode, payload):
        async with lock:
            writer.write(ws_frame(opcode, payload))
            await writer.drain()

    async def send(text):
        log.info("ws %s -> %s", peer, show(text))
        await send_raw(0x1, text.encode())

    dev = None
    buf, buf_op = b"", None
    try:
        while True:
            try:
                fin, opcode, data = await asyncio.wait_for(ws_read_frame(reader), 600)
            except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
                break
            if opcode == 0x8:
                log.info("ws %s close %s", peer, data.hex())
                await send_raw(0x8, data[:2])
                break
            if opcode == 0x9:
                await send_raw(0xA, data)
                continue
            if opcode == 0xA:
                continue
            if opcode in (0x1, 0x2):
                buf, buf_op = data, opcode
            else:  # continuation
                buf += data
            if not fin:
                continue
            if buf_op == 0x2:
                log.info("ws %s <- binary %s", peer, buf.hex())
                continue
            text = buf.decode("utf-8", "replace")
            log.info("ws %s <- %s", peer, show(text))
            if text.strip() == "ping":
                await send("pong")
                continue
            msg = try_json(text)
            if not isinstance(msg, dict):
                continue
            reply, dev = device_message(msg, dev, send, peer)
            if reply is not None:
                await send(dumps(reply))
    finally:
        if dev and devices.get(dev.deviceid) is dev:
            del devices[dev.deviceid]
        log.info("%s %s websocket closed", label, peer)


def device_message(msg, dev, send, peer):
    action = msg.get("action")
    deviceid = msg.get("deviceid") or (dev.deviceid if dev else "")
    apikey = msg.get("apikey") or (dev.apikey if dev else "")
    reply = {"error": 0, "deviceid": deviceid, "apikey": apikey}
    if "sequence" in msg:
        reply["sequence"] = msg["sequence"]

    if action is None and "error" in msg:  # ack of a command we sent
        return None, dev
    if action == "register":
        dev = Device(deviceid, apikey, send, peer, msg)
        devices[deviceid] = dev
        log.info("registered device %s from %s", deviceid, peer)
        reply["config"] = {"hb": 1, "hbInterval": 145}
    elif action == "date":
        now = datetime.now(timezone.utc)
        reply["date"] = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
    elif action == "update":
        if dev and isinstance(msg.get("params"), dict):
            dev.params.update(msg["params"])
    elif action == "query":
        reply["params"] = {}
    else:
        log.info("unhandled action %r from %s, acking", action, peer)
    return reply, dev


# ---------------------------------------------------------------- admin API

async def admin_router(method, target, body):
    parts = [p for p in target.split("?", 1)[0].split("/") if p]
    if method == "GET" and parts == ["devices"]:
        return 200, dumps([d.summary() for d in devices.values()]).encode()
    if method == "POST" and len(parts) == 3 and parts[0] == "devices":
        dev = devices.get(parts[1])
        if dev is None:
            return 404, b'{"error":"device not connected"}'
        data = try_json(body)
        if not isinstance(data, dict):
            return 400, b'{"error":"body must be a JSON object"}'
        if parts[2] == "params":
            data = {
                "action": "update", "deviceid": dev.deviceid, "apikey": dev.apikey,
                "userAgent": "app", "sequence": str(int(time.time() * 1000)),
                "ts": 0, "params": data,
            }
        elif parts[2] != "raw":
            return 404, b'{"error":"unknown endpoint"}'
        await dev.send(dumps(data))
        return 200, dumps({"sent": data}).encode()
    return 404, b'{"error":"unknown endpoint"}'


# ---------------------------------------------------------------- listeners

def make_tls_context():
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(TLS_CERT, TLS_KEY)
    # Small embedded TLS stacks often only offer older RSA/CBC suites.
    ctx.set_ciphers("DEFAULT:@SECLEVEL=1")

    def on_sni(_sslobj, name, _ctx):
        log.info("TLS client hello, SNI=%r", name)

    ctx.sni_callback = on_sni
    return ctx


async def device_conn(reader, writer, tls_ctx):
    addr = writer.get_extra_info("peername") or ("?", 0)
    peer = f"{addr[0]}:{addr[1]}"
    label = "https" if tls_ctx else "http"
    log.info("%s connect from %s", label, peer)
    try:
        if tls_ctx:
            try:
                await asyncio.wait_for(writer.start_tls(tls_ctx), 20)
            except Exception as e:  # the whole point: see why the plug gives up
                log.warning("https %s TLS handshake failed: %r", peer, e)
                return
            sslobj = writer.get_extra_info("ssl_object")
            log.info("https %s TLS ok: %s %s", peer, sslobj.version(), sslobj.cipher()[0])

        async def router(method, target, body):
            return route_device_http(method, target, body)

        await serve_http(reader, writer, peer, label, router, ws_ok=True)
    except Exception:
        log.exception("%s %s error", label, peer)
    finally:
        writer.close()
        log.info("%s %s disconnected", label, peer)


async def admin_conn(reader, writer):
    try:
        await serve_http(reader, writer, "admin", "admin", admin_router, ws_ok=False)
    except Exception:
        log.exception("admin error")
    finally:
        writer.close()


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    tls_ctx = make_tls_context()
    servers = [
        await asyncio.start_server(lambda r, w: device_conn(r, w, None), "0.0.0.0", HTTP_PORT),
        await asyncio.start_server(lambda r, w: device_conn(r, w, tls_ctx), "0.0.0.0", HTTPS_PORT),
        await asyncio.start_server(admin_conn, "127.0.0.1", ADMIN_PORT),
    ]
    log.info("listening http=%d https=%d admin=127.0.0.1:%d; dispatch answers IP=%s port=%d domain=%r",
             HTTP_PORT, HTTPS_PORT, ADMIN_PORT, PUBLIC_IP, WS_ADVERTISED_PORT, PUBLIC_HOST)
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    asyncio.run(main())
