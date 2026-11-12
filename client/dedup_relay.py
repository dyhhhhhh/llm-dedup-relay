#!/usr/bin/env python3
"""dedup-relay: local TLS-terminating relay that deduplicates LLM API request bodies.

Install it between your LLM client (Codex / Claude Code / any HTTP client) and
your self-hosted gateway, then every incremental request only uploads the
zstd-compressed *delta* instead of the multi-megabyte full context.

Responsibilities:
  1. TLS termination (holds the real certificate for the target domain,
     auto-reloads when the cert file is renewed on disk)
  2. SNI routing: the configured upstream gets dictionary dedup; every other
     SNI is piped through the local proxy untouched (transparent for other apps)
  3. Dictionary compression: uses the previous request body as a zstd raw-content
     prefix dictionary, uploads only the delta; automatic full-body fallback
     when the server misses the dictionary (409)
  4. Everything degrades gracefully -- never worse than a direct connection.

Client requirements: Python >= 3.14 (stdlib `compression.zstd`).
"""
import ssl
import socket
import threading
import hashlib
import http.client
import os
import sys
import time
import traceback
import json

BASE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.environ.get("DEDUP_RELAY_CONFIG", os.path.join(BASE, "config.json"))

DEFAULTS = {
    "listen_host": "127.0.0.1",
    "listen_port": 443,
    # Domain whose TLS we terminate and whose requests we dedup (hosts-file
    # redirect or DNS must point this name at 127.0.0.1 on this machine).
    "upstream_host": "api.example.com",
    # Local HTTP proxy used for all outbound traffic (e.g. Clash/mihomo mixed
    # port). Set to null to connect directly.
    "proxy_host": "127.0.0.1",
    "proxy_port": 7897,
    "cert_file": os.path.join(BASE, "certs", "api.example.com.crt"),
    "key_file": os.path.join(BASE, "certs", "api.example.com.key"),
    "cache_dir": os.path.join(BASE, "cache"),
    "log_file": os.path.join(BASE, "relay.log"),
    # Bodies smaller than this are always sent plain.
    "dedup_min_bytes": 256 * 1024,
    # Bodies larger than this are never used as dictionary entries.
    "max_body_bytes": 64 * 1024 * 1024,
    "local_cache_files": 40,
    "zstd_level": 19,
    # Only use the dictionary when it actually shrinks the body by 10%+.
    "dict_gain_ratio": 0.9,
}

_keymap = {}        # route key -> sha256 of last body for that route
_lock = threading.Lock()
_cert_lock = threading.Lock()
_tls_ctx = None
_cert_mtime = 0

try:
    import compression.zstd as pz  # Python >= 3.14
except ImportError:
    pz = None


def load_config():
    cfg = dict(DEFAULTS)
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg.update(json.load(f))
    os.makedirs(cfg["cache_dir"], exist_ok=True)
    return cfg


CFG = load_config()
LOGF = CFG["log_file"]
DEDUP_MIN = CFG["dedup_min_bytes"]
MAX_BODY = CFG["max_body_bytes"]


def log(msg):
    line = time.strftime("%m-%d %H:%M:%S ") + msg
    try:
        with open(LOGF, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass
    try:
        print(line, flush=True)
    except OSError:
        pass


# ---------- local body cache (dictionary sources) ----------
def cache_get(sha):
    p = os.path.join(CFG["cache_dir"], sha + ".bin")
    if os.path.exists(p):
        try:
            with open(p, "rb") as f:
                data = f.read()
            os.utime(p)
            return data
        except OSError:
            return None
    return None


def cache_put(sha, data):
    if len(data) > MAX_BODY:
        return
    with _lock:
        p = os.path.join(CFG["cache_dir"], sha + ".bin")
        tmp = p + ".tmp"
        try:
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, p)
        except OSError:
            return
        files = [os.path.join(CFG["cache_dir"], f)
                 for f in os.listdir(CFG["cache_dir"]) if f.endswith(".bin")]
        if len(files) > CFG["local_cache_files"]:
            files.sort(key=lambda f: os.path.getmtime(f))
            for f in files[: len(files) - CFG["local_cache_files"]]:
                try:
                    os.remove(f)
                except OSError:
                    pass


# ---------- TLS context with hot reload ----------
def build_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CFG["cert_file"], CFG["key_file"])
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except Exception:
        pass
    return ctx


def get_ctx():
    with _cert_lock:
        return _tls_ctx


def cert_watch():
    global _tls_ctx, _cert_mtime
    while True:
        try:
            mt = os.path.getmtime(CFG["cert_file"])
            if _cert_mtime and mt != _cert_mtime:
                _tls_ctx = build_ctx()
                _cert_mtime = mt
                log("certificate changed on disk, TLS context reloaded")
        except OSError:
            pass
        time.sleep(60)


# ---------- SNI parsing (TLS ClientHello) ----------
def peek_sni(sock):
    try:
        data = sock.recv(16384, socket.MSG_PEEK)
    except OSError:
        return None
    if len(data) < 6 or data[0] != 0x16:
        return None
    hs = data[5:]
    if not hs or hs[0] != 0x01:
        return None
    pos = 1 + 3 + 2 + 32  # handshake hdr + version + random
    if len(hs) < pos + 1:
        return None
    sid_len = hs[pos]
    pos += 1 + sid_len
    if len(hs) < pos + 2:
        return None
    cs_len = int.from_bytes(hs[pos:pos + 2], "big")
    pos += 2 + cs_len
    if len(hs) < pos + 1:
        return None
    comp_len = hs[pos]
    pos += 1 + comp_len
    if len(hs) < pos + 2:
        return None
    ext_len = int.from_bytes(hs[pos:pos + 2], "big")
    pos += 2
    end = min(pos + ext_len, len(hs))
    while pos + 4 <= end:
        etype = int.from_bytes(hs[pos:pos + 2], "big")
        elen = int.from_bytes(hs[pos + 2:pos + 4], "big")
        pos += 4
        if pos + elen > len(hs):
            return None
        if etype == 0x0000:  # server_name
            p = pos + 2
            if p < len(hs) and hs[p] == 0 and p + 3 <= len(hs):
                nlen = int.from_bytes(hs[p + 1:p + 3], "big")
                return hs[p + 3:p + 3 + nlen].decode(errors="replace")
            return None
        pos += elen
    return None


def pipe_via_proxy(sock, host):
    """Transparent pipe for non-dedup SNIs: CONNECT through the local proxy
    (or direct when no proxy is configured), TLS untouched end-to-end."""
    try:
        t0 = time.time()
        if CFG.get("proxy_host"):
            pconn = socket.create_connection((CFG["proxy_host"], CFG["proxy_port"]), timeout=15)
            pconn.sendall(("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n"
                           % (host, host)).encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = pconn.recv(4096)
                if not chunk:
                    break
                resp += chunk
            if b" 200" not in resp.split(b"\r\n")[0]:
                sock.close()
                pconn.close()
                return
        else:
            pconn = socket.create_connection((host, 443), timeout=15)
        log("pipe %s:443 established in %.2fs" % (host, time.time() - t0))
        relay_pipe(sock, pconn)
    except Exception as e:
        log("pipe %s failed: %r" % (host, e))
        try:
            sock.close()
        except OSError:
            pass


def relay_pipe(a, b):
    def up():
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                b.sendall(d)
        except OSError:
            pass
        try:
            b.shutdown(socket.SHUT_WR)
        except OSError:
            pass
    threading.Thread(target=up, daemon=True).start()
    try:
        while True:
            d = b.recv(65536)
            if not d:
                break
            a.sendall(d)
    except OSError:
        pass
    try:
        a.close()
        b.close()
    except OSError:
        pass


# ---------- dedup HTTP handling ----------
HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
       "trailers", "transfer-encoding", "upgrade", "host", "content-length"}


class DedupHandler:
    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.rfile = conn.makefile("rb")

    def read_body(self, headers):
        try:
            ln = int(headers.get("content-length") or 0)
        except ValueError:
            ln = 0
        if ln:
            return self.rfile.read(ln)
        te = (headers.get("transfer-encoding") or "").lower()
        if "chunked" in te:
            chunks = []
            while True:
                line = self.rfile.readline().strip()
                size = int(line.split(b";")[0], 16)
                if size == 0:
                    self.rfile.readline()
                    break
                chunks.append(self.rfile.read(size))
                self.rfile.readline()
            return b"".join(chunks)
        return b""

    def handle(self):
        t0 = time.time()
        try:
            reqline = self.rfile.readline()
            if not reqline:
                return
            parts = reqline.decode("latin1").strip().split()
            if len(parts) < 3:
                log("bad request line %r" % reqline[:60])
                return
            method, path, _ver = parts[0], parts[1], parts[2]
            log("request: %s %s" % (method, path.split("?")[0]))
            headers = {}
            while True:
                line = self.rfile.readline()
                if not line or line in (b"\r\n", b"\n"):
                    break
                k, _, v = line.decode("latin1").partition(":")
                headers[k.strip().lower()] = v.strip()
            body = self.read_body(headers)
            raw_len = len(body)
            log("step1 body read: %.2fMB" % (raw_len / 1e6))

            # Per-route dictionary selection: auth token + path identifies a
            # conversation stream, so each route rolls its own dictionary.
            auth = headers.get("authorization", "")
            key = hashlib.sha1((auth + "|" + path.split("?")[0]).encode()).hexdigest()[:16]

            use_dict = False
            dict_sha = None
            blob = body
            if pz and method == "POST" and DEDUP_MIN <= raw_len <= MAX_BODY:
                dict_sha = _keymap.get(key)
                dict_body = cache_get(dict_sha) if dict_sha else None
                if dict_body:
                    try:
                        zd = pz.ZstdDict(dict_body, is_raw=True)
                        c = pz.ZstdCompressor(zstd_dict=zd.as_undigested_dict,
                                              level=CFG["zstd_level"])
                        blob = c.compress(body) + c.flush()
                        use_dict = len(blob) < raw_len * CFG["dict_gain_ratio"]
                    except Exception as e:
                        log("compress error, fallback to plain: %r" % e)
                        use_dict = False

            log("step2 upstream request: use_dict=%s blob=%.2fMB" % (use_dict, len(blob) / 1e6))
            resp_status, resp_headers, resp_stream, upconn = self.send_upstream(
                method, path, headers, blob, use_dict, dict_sha, body)
            log("step3 upstream response: %s" % resp_status)

            if use_dict and resp_status == 409:
                # server-side dictionary miss / verification failure -> resend full body
                log("dict-miss, resending full body: key=%s size=%.2fMB" % (key, raw_len / 1e6))
                try:
                    upconn.close()
                except OSError:
                    pass
                resp_status, resp_headers, resp_stream, upconn = self.send_upstream(
                    method, path, headers, body, False, None, body)

            # The body we just sent (full or delta-decoded server-side) becomes
            # the next dictionary for this route, regardless of response status.
            orig_sha = hashlib.sha256(body).hexdigest()
            if raw_len >= DEDUP_MIN:
                cache_put(orig_sha, body)
                _keymap[key] = orig_sha

            if resp_status != 200:
                # Buffer error responses fully, then forward with Content-Length
                # (streaming a non-SSE error body can hang the client).
                err_body = resp_stream.read()
                try:
                    upconn.close()
                except OSError:
                    pass
                self.conn.sendall(("HTTP/1.1 %s\r\n" % resp_status).encode())
                for k, v in resp_headers:
                    if k.lower() in ("transfer-encoding", "content-length", "connection", "x-dedup-note"):
                        continue
                    self.conn.sendall(("%s: %s\r\n" % (k, v)).encode())
                self.conn.sendall(("Content-Length: %d\r\nConnection: close\r\n\r\n"
                                   % len(err_body)).encode())
                self.conn.sendall(err_body)
                self._log_result(path, use_dict, dict_sha, raw_len, blob, resp_status,
                                 len(err_body), time.time() - t0)
                return

            self.conn.sendall(("HTTP/1.1 %s\r\n" % resp_status).encode())
            for k, v in resp_headers:
                if k.lower() in ("transfer-encoding", "content-length", "connection", "x-dedup-note"):
                    continue
                self.conn.sendall(("%s: %s\r\n" % (k, v)).encode())
            self.conn.sendall(b"Connection: close\r\n\r\n")
            total = 0
            while True:
                chunk = resp_stream.read(65536)
                if not chunk:
                    break
                self.conn.sendall(chunk)
                total += len(chunk)
            resp_stream.close()
            try:
                upconn.close()
            except OSError:
                pass
            self._log_result(path, use_dict, dict_sha, raw_len, blob, resp_status,
                             total, time.time() - t0)
        except Exception as e:
            log("handler error: %r" % e)
            log(traceback.format_exc())
        finally:
            try:
                self.conn.close()
            except OSError:
                pass

    def _log_result(self, path, use_dict, dict_sha, raw_len, blob, status, out_len, took):
        if use_dict:
            log("POST %s | dict %s | %.2fMB -> %.2fMB (%.0fx) | up=%s | out=%.3fMB | %.2fs"
                % (path.split("?")[0], dict_sha[:8] if dict_sha else "-",
                   raw_len / 1e6, len(blob) / 1e6,
                   raw_len / len(blob) if blob else 0, status, out_len / 1e6, took))
        elif raw_len >= DEDUP_MIN:
            log("POST %s | plain %.2fMB | up=%s | %.2fs"
                % (path.split("?")[0], raw_len / 1e6, status, took))

    def send_upstream(self, method, path, headers, body, use_dict, dict_sha, orig_body, attempt=1):
        """Send to the real server through the local proxy (or directly);
        returns (status, headers, stream, conn)."""
        try:
            if CFG.get("proxy_host"):
                conn = http.client.HTTPSConnection(CFG["proxy_host"], CFG["proxy_port"], timeout=300)
                conn.set_tunnel(CFG["upstream_host"], 443)
            else:
                conn = http.client.HTTPSConnection(CFG["upstream_host"], 443, timeout=300)
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", CFG["upstream_host"])
            for k, v in headers.items():
                if k.lower() in HOP or k.lower().startswith("x-dedup"):
                    continue
                conn.putheader(k, v)
            if use_dict:
                conn.putheader("X-Dedup-Base", dict_sha)
                conn.putheader("Content-Encoding", "zstd-dict-1")
            # Always declare the original body hash for large bodies so the
            # server can cache it as the next dictionary (plain turns too).
            if len(orig_body) >= DEDUP_MIN:
                conn.putheader("X-Dedup-Orig", hashlib.sha256(orig_body).hexdigest())
            conn.putheader("Content-Length", str(len(body)))
            conn.endheaders()
            if body:
                conn.send(body)
            resp = conn.getresponse()
            return resp.status, resp.getheaders(), resp, conn
        except Exception as e:
            if attempt < 3:
                log("upstream connection failed, retry (attempt=%d): %r" % (attempt, e))
                time.sleep(0.3)
                return self.send_upstream(method, path, headers, body, use_dict,
                                          dict_sha, orig_body, attempt + 1)
            raise


def serve_tls(sock, addr):
    ctx = get_ctx()
    if ctx is None:
        sock.close()
        return
    try:
        tls = ctx.wrap_socket(sock, server_side=True)
    except (ssl.SSLError, OSError) as e:
        log("TLS handshake failed (%s): %r" % (addr, e))
        try:
            sock.close()
        except OSError:
            pass
        return
    DedupHandler(tls, addr).handle()


def main():
    global _tls_ctx, _cert_mtime
    if pz is None:
        log("ERROR: compression.zstd not available; Python >= 3.14 required")
        sys.exit(1)
    for f in (CFG["cert_file"], CFG["key_file"]):
        if not os.path.exists(f):
            log("ERROR: missing certificate file: %s" % f)
            sys.exit(1)
    _tls_ctx = build_ctx()
    _cert_mtime = os.path.getmtime(CFG["cert_file"])
    threading.Thread(target=cert_watch, daemon=True).start()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen = (CFG["listen_host"], CFG["listen_port"])
    srv.bind(listen)
    srv.listen(64)
    log("dedup-relay listening on %s:%s | upstream=%s | proxy=%s:%s" %
        (listen[0], listen[1], CFG["upstream_host"],
         CFG.get("proxy_host"), CFG.get("proxy_port")))
    while True:
        sock, addr = srv.accept()
        sni = peek_sni(sock)
        if sni == CFG["upstream_host"]:
            threading.Thread(target=serve_tls, args=(sock, addr), daemon=True).start()
        else:
            host = sni if sni else CFG["upstream_host"]
            threading.Thread(target=pipe_via_proxy, args=(sock, host), daemon=True).start()


if __name__ == "__main__":
    main()
