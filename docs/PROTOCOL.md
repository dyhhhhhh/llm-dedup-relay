# The llm-dedup-relay Wire Protocol

This document specifies the custom protocol layers that `dedup-relay` (client)
and `dedup-svc` (server) add on top of plain HTTPS. Everything is designed to
be invisible to clients and upstream APIs that do not opt in.

## 1. Overview

```
client app ──TLS──> dedup-relay (local) ──HTTPS──> Caddy/nginx ──HTTP──> dedup-svc ──HTTP──> gateway
                    TLS terminated here            routes by header      decompress+verify
```

## 2. Request headers

The relay adds zero or more of these headers; the server strips them all
before forwarding upstream:

| Header | Meaning |
|---|---|
| `X-Dedup-Orig: <hex sha256>` | SHA-256 of the **original, uncompressed** request body. Present on every request whose body is >= `dedup_min_bytes`, compressed or not. |
| `X-Dedup-Base: <hex sha256>` | SHA-256 of the dictionary body to use (the previous request body on the same route). Only present when the body is dictionary-compressed. |
| `Content-Encoding: zstd-dict-1` | Marks the body as zstd-compressed with a raw-content prefix dictionary. Only present together with `X-Dedup-Base`. |

A request falls into one of three classes:

1. **Plain small** (< `dedup_min_bytes`): no dedup headers at all. Forwarded untouched.
2. **Plain large** (>= `dedup_min_bytes`): carries only `X-Dedup-Orig`. The
   server caches the body so it can serve as a dictionary for future requests
   on the same route. This is how the first turn of a conversation is primed.
3. **Dictionary-compressed**: carries `X-Dedup-Orig`, `X-Dedup-Base`,
   `Content-Encoding: zstd-dict-1`, and a zstd frame whose compression
   dictionary is the raw bytes identified by `X-Dedup-Base`.

## 3. Dictionary compression details

- Dictionary type: **raw content** (zstd "prefix" style). Both ends must treat
  the dictionary as raw bytes, not as a trained zstd dictionary.
  - Client (Python >= 3.14 stdlib):
    `ZstdDict(dict_bytes, is_raw=True)` then
    `ZstdCompressor(zstd_dict=zd.as_undigested_dict, level=19)`
  - Server (python-zstandard):
    `ZstdCompressionDict(dict_bytes, dict_type=DICT_TYPE_RAWCONTENT)` then
    `ZstdDecompressor(dict_data=d).decompress(blob, max_output_size=...)`
- Compression level: 19 (configurable).
- The relay only uses the dictionary when the compressed blob is smaller than
  90% of the original (`dict_gain_ratio`). Otherwise it sends plain.

## 4. Route identity and dictionary rolling

A **route** is identified by `sha1(authorization_header + "|" + request_path)`.
Each route rolls its own dictionary independently:

1. On every request with body >= `dedup_min_bytes`, after sending, the relay
   stores `body -> cache[sha256(body)]` and sets `route.last = sha256(body)`.
2. On the next request on the same route, the relay uses `cache[route.last]`
   as the dictionary if present.
3. Both plain-large and dictionary-compressed requests update the route
   dictionary, **regardless of response status** — the request body is what
   the client will prefix-extend next turn, so it always becomes the next
   dictionary.

Concurrent requests on the same route are assumed serialized (true for LLM
agent loops). Interleaving requests on one route would degrade compression
ratios but never correctness, because of the sha256 verification below.

## 5. Server behavior

Given a dictionary-compressed request:

1. Look up `cache[X-Dedup-Base]`. Missing -> respond `409`.
2. Decompress the body with that dictionary. Decompression error -> `409`.
3. Verify `sha256(decompressed) == X-Dedup-Orig`. Mismatch -> `409`.
4. On success: cache the decompressed body under `X-Dedup-Orig`, forward the
   plain body upstream with all dedup headers stripped (including
   `Content-Encoding` — the upstream must never see the fake encoding).

The `409` response body is `{"error":"dict-miss"}`. Any 409 makes the relay
immediately resend the **full plain body** (up to 3 attempts on transport
errors). This is the safety net: a cold server cache, an LRU eviction, a
cache dir wipe — all degrade to one wasted round trip, never to data loss.

## 6. Response handling

- `200` responses are streamed chunk-by-chunk (SSE works).
- Non-200 responses are fully buffered server-side (by the relay) and
  forwarded with an explicit `Content-Length` to avoid streaming hangs.
- The server adds `X-Dedup-Note: <note>` to every response for debugging;
  the relay strips it before replying to the client.

## 7. TLS termination and SNI routing

The relay listens on (by default) `127.0.0.1:443` and:

- Parses the TLS ClientHello SNI without consuming bytes (`MSG_PEEK`).
- If SNI == `upstream_host`: terminate TLS with the locally held real
  certificate for that domain, handle HTTP there (dedup logic).
- Any other SNI: pipe raw bytes through the local proxy via HTTP CONNECT —
  other apps sharing the hosts redirect keep working end-to-end, TLS intact.

The certificate must be the real certificate of `upstream_host` (clients do
not trust anything else). The typical setup: Caddy on the server does
ACME issuance; a cron/scheduled task copies the cert+key to the relay host;
the relay hot-reloads on mtime change (checked every 60s).

## 8. Python version compatibility

- Client uses stdlib `compression.zstd` (PEP 784, Python 3.14+). The
  `ZstdDict(..., is_raw=True)` + `as_undigested_dict` path is what makes
  raw-content prefix dictionaries work.
- On older Pythons, replace the client compression calls with the
  `zstandard` package (same wire format, `DICT_TYPE_RAWCONTENT`); the server
  side already uses `zstandard` and works on 3.8+.

## 9. Threat model / privacy notes

- Cached bodies on both ends are **plaintext request bodies**. Treat both
  disks as sensitive; wipe `cache/` dirs if needed. LRU caps bound the
  exposure (40 files local, 60 server by default).
- Integrity is guaranteed by sha256 verification — a wrong/missing dictionary
  can never silently corrupt a request; it can only trigger a full resend.
- The wire between relay and server is normal HTTPS.
