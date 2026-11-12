#!/usr/bin/env python3
"""dedup-svc: server-side companion for llm-dedup-relay.

Sits behind your TLS terminator (Caddy/nginx) and in front of your LLM gateway
(sub2api / one-api / new-api / ...). Receives dictionary-compressed request
bodies from the local relay, decompresses them, verifies integrity, caches each
original body as the next dictionary, and forwards the plain body upstream.

Protocol (custom headers, stripped before forwarding upstream):
  X-Dedup-Base      sha256 of the dictionary (previous request body) to use
  X-Dedup-Orig      sha256 of the original (uncompressed) request body
  Content-Encoding  "zstd-dict-1"

  hit   : decompress -> verify sha256 == X-Dedup-Orig -> cache -> forward
  miss  : dictionary missing / sha mismatch / decompression error
          -> 409 {"error":"dict-miss"} so the relay resends the full body
  plain : no dedup headers -> transparent proxy (bodies carrying only
          X-Dedup-Orig are cached as future dictionaries)

Requires: python-zstandard (pip install zstandard), Python >= 3.8.
"""
import http.client
import hashlib
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import zstandard

DEFAULTS = {
    "port": 8543,
    "upstream_host": "127.0.0.1",
    "upstream_port": 8081,
    "cache_dir": os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache"),
    "log_file": os.path.join(os.path.dirname(os.path.abspath(__file__)), "svc.log"),
    "max_files": 60,
    "max_body": 64 * 1024 * 1024,
}


def load_config():
    cfg = dict(DEFAULTS)
    path = os.environ.get("DEDUP_SVC_CONFIG")
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            cfg.update(json.load(f))
    os.makedirs(cfg["cache_dir"], exist_ok=True)
    return cfg


CFG = load_config()
_lk = threading.Lock()


def log(msg):
    line = time.strftime("%m-%d %H:%M:%S ") + msg
    try:
        with open(CFG["log_file"], "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass
    try:
        print(line, flush=True)
    except OSError:
        pass


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
    if len(data) > CFG["max_body"]:
        return
    with _lk:
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
        if len(files) > CFG["max_files"]:
            files.sort(key=lambda f: os.path.getmtime(f))
            for f in files[: len(files) - CFG["max_files"]]:
                try:
                    os.remove(f)
                except OSError:
                    pass


def decomp(data, base):
    d = zstandard.ZstdCompressionDict(base, dict_type=zstandard.DICT_TYPE_RAWCONTENT)
    return zstandard.ZstdDecompressor(dict_data=d).decompress(
        data, max_output_size=CFG["max_body"])


HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
       "trailers", "transfer-encoding", "upgrade", "host", "content-length"}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):
        pass

    def _respond(self, status, payload):
        msg = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(msg)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(msg)
        except OSError:
            pass

    def _proxy(self):
        t0 = time.time()
        try:
            ln = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            ln = 0
        body = self.rfile.read(ln) if ln else b""
        raw_len = len(body)
        # Strip dedup protocol headers AND the fake content-encoding before
        # forwarding -- the upstream must see a plain body with no surprises.
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in HOP and not k.lower().startswith("x-dedup")
                   and k.lower() != "content-encoding"}
        base_sha = self.headers.get("X-Dedup-Base")
        orig_sha = self.headers.get("X-Dedup-Orig")
        is_dict = bool(base_sha and orig_sha
                       and self.headers.get("Content-Encoding") == "zstd-dict-1")

        note = "plain"
        if is_dict and body:
            base = cache_get(base_sha)
            if base is None:
                note = "dict-miss"
            else:
                try:
                    body = decomp(body, base)
                    if hashlib.sha256(body).hexdigest() == orig_sha:
                        note = "dedup base=%s %.2fMB->%.2fMB" % (
                            base_sha[:8], raw_len / 1e6, len(body) / 1e6)
                        cache_put(orig_sha, body)
                    else:
                        note = "sha-mismatch"
                except Exception as e:
                    note = "decomp-err %s" % type(e).__name__

        if note not in ("plain",) and not note.startswith("dedup "):
            # dict-miss / sha-mismatch / decomp-err -> 409, relay resends full body
            log("%s %s | %s | 409-fallback" % (self.command, self.path, note))
            self._respond(409, {"error": "dict-miss"})
            return

        # Cache plain bodies declared with X-Dedup-Orig (first turn of a
        # conversation becomes the dictionary for later turns).
        if orig_sha:
            cache_put(orig_sha, body)

        headers["Content-Length"] = str(len(body))
        try:
            conn = http.client.HTTPConnection(CFG["upstream_host"], CFG["upstream_port"],
                                              timeout=300)
            conn.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
            headers.setdefault("Host", "%s:%s" % (CFG["upstream_host"], CFG["upstream_port"]))
            for k, v in headers.items():
                conn.putheader(k, v)
            conn.endheaders()
            if body:
                conn.send(body)
            resp = conn.getresponse()

            self.send_response(resp.status)
            self.send_header("X-Dedup-Note", note)
            for k, v in resp.getheaders():
                if k.lower() in ("transfer-encoding", "content-length", "connection"):
                    continue
                self.send_header(k, v)
            self.send_header("Connection", "close")
            self.end_headers()
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
            conn.close()
            log("%s %s | %s | upstream=%s | %.2fs"
                % (self.command, self.path, note, resp.status, time.time() - t0))
        except Exception as e:
            log("%s %s | upstream error %r" % (self.command, self.path, e))
            self._respond(502, {"error": "upstream-failed"})

    do_POST = _proxy
    do_GET = _proxy
    do_PUT = _proxy
    do_DELETE = _proxy
    do_PATCH = _proxy
    do_OPTIONS = _proxy
    do_HEAD = _proxy


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", CFG["port"]), Handler)
    srv.daemon_threads = True
    log("dedup-svc listening on 127.0.0.1:%d -> %s:%s"
        % (CFG["port"], CFG["upstream_host"], CFG["upstream_port"]))
    srv.serve_forever()
