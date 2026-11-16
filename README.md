# ewelink-fake

A fake eWeLink cloud for running Sonoff devices without Sonoff's servers.
Point a device's dispatch URL here: it logs every request, TLS handshake and
websocket frame the device sends, and answers enough of the protocol
(`dispatch`, `register`, `date`, `update`, `query`, `ping`) to keep it
connected. Commands can then be pushed to the device through a local admin
API.

Python standard library only: no dependencies, no outbound traffic.

## Ports

| Port | Bind | Purpose |
|---|---|---|
| 8080 | 0.0.0.0 | Plain HTTP: dispatch + websocket |
| 8443 | 0.0.0.0 | TLS: dispatch + websocket. The handshake is started by hand so a device rejecting the cert is logged with the reason. |
| 9000 | 127.0.0.1 | Admin API (reach it with `kubectl port-forward`) |

## Admin API

```bash
curl localhost:9000/devices                                   # connected devices
curl -X POST localhost:9000/devices/<id>/params -d '{"switch":"on"}'  # "update" command
curl -X POST localhost:9000/devices/<id>/raw -d '{...}'               # any JSON, as-is
```

## Configuration

| Env | Default | Meaning |
|---|---|---|
| `PUBLIC_IP` | `127.0.0.1` | IP the dispatch reply sends the device to |
| `PUBLIC_HOST` | (empty) | Also sent as `domain` in the dispatch reply |
| `WS_ADVERTISED_PORT` | `443` | Port in the dispatch reply |
| `HTTP_PORT` / `HTTPS_PORT` / `ADMIN_PORT` | `8080` / `8443` / `9000` | Listeners |
| `TLS_CERT` / `TLS_KEY` | `/tls/tls.crt` / `/tls/tls.key` | Server certificate |

## Test

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=t -keyout /tmp/k -out /tmp/c
python3 test/test_server.py /tmp/c /tmp/k
```
