"""End-to-end test: plays a Sonoff plug against server.py's handlers.

Uses socket pairs instead of listening ports, so it runs anywhere (CI,
sandboxes) with no network. Needs a cert/key pair:
    python3 test/test_server.py tls.crt tls.key
"""
import asyncio
import base64
import json
import os
import socket
import ssl
import struct
import sys
import threading

os.environ.update(PUBLIC_IP="10.251.11.187", PUBLIC_HOST="ewelink.example",
                  TLS_CERT=sys.argv[1], TLS_KEY=sys.argv[2])
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import logging  # noqa: E402

import server  # noqa: E402

logging.basicConfig(level=logging.INFO, format="SERVER %(levelname)s %(message)s")

loop = asyncio.new_event_loop()
threading.Thread(target=loop.run_forever, daemon=True).start()
TLS = server.make_tls_context()
HANDLERS = {
    "http": lambda r, w: server.device_conn(r, w, None),
    "https": lambda r, w: server.device_conn(r, w, TLS),
    "admin": server.admin_conn,
}


async def _attach(sock, cb):
    reader = asyncio.StreamReader(limit=2 ** 16)
    proto = asyncio.StreamReaderProtocol(reader, cb)
    await asyncio.get_running_loop().connect_accepted_socket(lambda: proto, sock)


def connect(kind):
    client, srv = socket.socketpair()
    asyncio.run_coroutine_threadsafe(_attach(srv, HANDLERS[kind]), loop).result(5)
    return client


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def http(sock, method, path, body=b""):
    sock.sendall(f"{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                 f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
    resp = b""
    while b"\r\n\r\n" not in resp:
        resp += sock.recv(4096)
    head, _, rest = resp.partition(b"\r\n\r\n")
    length = next(int(l.split(b":")[1]) for l in head.split(b"\r\n")
                  if l.lower().startswith(b"content-length"))
    while len(rest) < length:
        rest += sock.recv(4096)
    return int(head.split(b" ")[1]), json.loads(rest)


def ws_send(sock, text):
    data, mask = text.encode(), os.urandom(4)
    head = (struct.pack("!BB", 0x81, 0x80 | len(data)) if len(data) < 126
            else struct.pack("!BBH", 0x81, 0x80 | 126, len(data)))
    sock.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))


def ws_recv(sock):
    _, b2 = recv_exact(sock, 2)
    n = b2 & 0x7F
    if n == 126:
        (n,) = struct.unpack("!H", recv_exact(sock, 2))
    return recv_exact(sock, n).decode()


def admin(method, path, body=None):
    s = connect("admin")
    try:
        return http(s, method, path, json.dumps(body).encode() if body is not None else b"")
    finally:
        s.close()


def plug_session(sock):
    status, reply = http(sock, "POST", "/dispatch/device",
                         json.dumps({"accept": "ws", "deviceid": "dev1", "apikey": "k"}).encode())
    assert status == 200 and reply["IP"] == "10.251.11.187" and reply["port"] == 443, reply
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall(f"GET /api/ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                 f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        resp += sock.recv(1)
    assert b" 101 " in resp, resp
    ws_send(sock, json.dumps({"action": "register", "deviceid": "dev1", "apikey": "k",
                              "userAgent": "device"}))
    assert json.loads(ws_recv(sock))["config"]["hbInterval"] == 145
    ws_send(sock, json.dumps({"action": "date", "deviceid": "dev1", "apikey": "k"}))
    assert json.loads(ws_recv(sock))["date"].endswith("Z")
    ws_send(sock, json.dumps({"action": "update", "deviceid": "dev1", "apikey": "k",
                              "sequence": "1", "params": {"switch": "off"}}))
    assert json.loads(ws_recv(sock))["sequence"] == "1"
    ws_send(sock, "ping")
    assert ws_recv(sock) == "pong"


# Plain HTTP: full session, then a command pushed through the admin API.
s = connect("http")
plug_session(s)
status, devs = admin("GET", "/devices")
assert devs[0]["params"] == {"switch": "off"}, devs
got = {}
t = threading.Thread(target=lambda: got.setdefault("msg", ws_recv(s)))
t.start()
status, _ = admin("POST", "/devices/dev1/params", {"switch": "on"})
t.join(5)
cmd = json.loads(got["msg"])
assert status == 200 and cmd["action"] == "update" and cmd["params"] == {"switch": "on"}, cmd
s.close()
assert admin("POST", "/devices/nope/params", {"switch": "on"})[0] == 404

# HTTPS with a client that accepts the cert.
ctx = ssl.create_default_context()
ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
s = ctx.wrap_socket(connect("https"), server_hostname="ewelink.example")
plug_session(s)
s.close()

# HTTPS with a strict client: it must fail, and the server must log why.
try:
    ssl.create_default_context().wrap_socket(connect("https"), server_hostname="ewelink.example")
    raise AssertionError("strict client accepted a self-signed cert")
except ssl.SSLError:
    pass

print("ALL OK")
