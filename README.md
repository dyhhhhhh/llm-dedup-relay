# llm-dedup-relay

**把 LLM 大上下文请求的上传量压缩三个数量级。** 针对自建 LLM API 网关（sub2api / one-api / new-api 等）的透明增量上传加速器：增量请求只上传 KB 级的 zstd 字典压缩增量，而不是几 MB 的完整上下文。

English docs: see [docs/PROTOCOL.md](docs/PROTOCOL.md)。README 主体为中文（目标用户为「本地跑 Codex / Claude Code + 远程中转网关」的人群）。

---

## 痛点

本地跑 Codex / Claude Code，API 走远程自建网关时：

- 512K 级上下文的请求体动辄 **5–8 MB**
- 家宽上行通常只有 30 Mbps，一次增量请求的上传就要 **30–40 秒**
- 服务端 prompt cache 只省**钱和 TTFT**，不省**上传带宽**——每个请求依然全量上传

## 原理

LLM 会话的请求体是**滚动追加**的：每个新请求 = 上一个请求体 + 新增内容。这正好是 zstd 前缀字典压缩的完美场景：

```
Codex ──hosts 重定向──> dedup-relay (本机, TLS 终结)
    │
    ├─ 首轮: 全量上传, body 预缓存为字典
    ├─ 增量轮: 用上一轮 body 作 zstd 原始内容前缀字典
    │          5–8 MB  ──压缩──▶  KB 级增量
    │          (实测 822× ~ 11166×)
    ▼
mihomo/Clash 隧道 ──▶ Caddy (按 X-Dedup-Orig 头路由)
    ▼
dedup-svc (服务器): zstd 解压 + sha256 完整性校验
    ├─ 命中: 缓存原 body 作下轮字典 ─▶ 转发网关
    └─ 未命中/校验失败: 409 ─▶ 本机 relay 自动 ×3 全量回退
```

**设计原则：永远不比直连差。** 字典未命中、sha 校验失败、压缩异常、出站失败——所有故障路径都自动降级为全量直传，对客户端完全透明。

## 实测数据

真实 Codex 会话（gpt-6-luna，285–440K token 上下文，家宽 30 Mbps 上行，经 Hysteria2 隧道）：

| 轮次 | 原始请求体 | 实际上传 | 压缩比 | 上游结果 |
|---|---|---|---|---|
| 首轮（新会话） | 2.83 MB | 2.83 MB（全量，预缓存字典） | 1× | 200 |
| 增量轮 1 | 2.88 MB | **0.03 MB** | **85×** | 200 |
| 增量轮 2 | 2.97 MB | **0.00 MB** | **822×** | 200 |
| 增量轮 3 | 2.99 MB | **0.02 MB** | **149×** | 200 |
| 压力测试（合成数据） | 4.35 MB | **0.00 MB** | **11166×** | 400* |

\* 400 为测试体格式的预期拒绝（假 body），去重层完全透明——服务器解压+sha256 校验通过后才转发。

**效果**：原本 6–8 MB 请求体在 30 Mbps 上行要跑 30–40 秒，现在增量轮传输时间归零，总首字延迟只剩上游 TTFT（160K 上下文约 10s，为 OpenAI 侧固有开销）。

## 适用场景

✅ 适合：
- 本地跑 Codex / Claude Code / 任何滚动追加上下文的 LLM 客户端
- API 走远程自建网关（sub2api / one-api / new-api），上行带宽有限
- 会话上下文大（100K+ token），多轮对话频繁

❌ 不适合：
- API 直连官方端点（无法在官方服务器前插 dedup-svc）
- 每次请求都是全新上下文（无前缀相关性，压缩比≈1，自动回退全量，无损失但无收益）

## 目录结构

```
llm-dedup-relay/
├── client/                  # 本机 relay (Python >= 3.14, 纯标准库)
│   ├── dedup_relay.py       # TLS 终结 + SNI 路由 + 字典压缩
│   └── config.example.json
├── server/                  # 服务器端 (Python >= 3.8 + zstandard)
│   ├── dedup_svc.py         # 解压 + sha256 校验 + 字典缓存 + 转发
│   ├── config.example.json
│   ├── dedup-svc.service    # systemd 单元
│   └── Caddyfile.snippet    # Caddy 站点片段
└── docs/
    └── PROTOCOL.md          # 协议规范（自定义头、回退语义、安全考量）
```

## 快速开始

### 服务器端

```bash
# 1. 安装依赖
pip install zstandard

# 2. 部署
sudo mkdir -p /opt/dedup-svc
sudo cp server/dedup_svc.py server/config.example.json /opt/dedup-svc/
sudo cp server/config.example.json /opt/dedup-svc/config.json   # 改端口
sudo cp server/dedup-svc.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now dedup-svc

# 3. Caddy 站点片段
# 把 server/Caddyfile.snippet 合入你的 Caddyfile，替换域名和上游端口
sudo systemctl reload caddy
```

### 本机客户端（Windows / Linux）

```bash
# 1. Python >= 3.14（需要标准库 compression.zstd）
python client/dedup_relay.py   # 配置见 client/config.example.json

# 2. hosts 重定向（让客户端流量先过 relay）
#    Windows: C:\Windows\System32\drivers\etc\hosts
#    Linux:   /etc/hosts
127.0.0.1  api.example.com

# 3. 证书：relay 需要 upstream 域名的真实证书做 TLS 终结
#    推荐用 Caddy 在服务器自动续期，然后定时同步到本机 certs/
#    （参考 docs/PROTOCOL.md 的证书同步节）
```

客户端零配置：Codex / Claude Code 照常填 `https://api.example.com`，hosts 重定向让流量先过 relay，其余全部透明。

## 配置说明

### client/config.json

| 键 | 默认 | 说明 |
|---|---|---|
| `upstream_host` | — | 目标 API 域名（hosts 重定向到 127.0.0.1） |
| `listen_host` / `listen_port` | 127.0.0.1:443 | relay 监听地址 |
| `proxy_host` / `proxy_port` | 127.0.0.1:7897 | 出站走的本地代理（Clash/mihomo mixed 端口），`null` 直连 |
| `cert_file` / `key_file` | — | upstream 域名的真实证书（TLS 终结用） |
| `dedup_min_bytes` | 262144 | body 小于此值永远全量直传 |
| `max_body_bytes` | 67108864 | body 大于此值不作为字典 |
| `zstd_level` | 19 | zstd 压缩级别 |
| `dict_gain_ratio` | 0.9 | 压缩后须小于原始 90% 才走字典（否则全量） |

### server/config.json

| 键 | 默认 | 说明 |
|---|---|---|
| `port` | 8543 | dedup-svc 监听（仅 127.0.0.1，由 Caddy 反代） |
| `upstream_host` / `upstream_port` | 127.0.0.1:8081 | 实际网关地址 |
| `max_files` | 60 | 字典缓存 LRU 上限 |
| `max_body` | 67108864 | 不缓存超大 body |

## 安全考量

- **字典与 body 缓存均为明文请求体**，存储在 `cache/` 目录（本机 + 服务器）。如果你的 API 请求包含敏感内容，请确保这两台机器的磁盘安全，或定期清理 cache 目录。
- sha256 完整性校验防止字典错位导致的静默数据损坏——校验失败一律 409 回退全量，**不会静默损坏数据**。
- 协议头（`X-Dedup-*`、`Content-Encoding: zstd-dict-1`）在 dedup-svc 转发上游前全部剥离，上游网关看到的永远是普通明文请求。
- relay 与服务器之间走 HTTPS（relay 持真实证书 TLS 终结后经代理出站），压缩体在公网段也是密文。

## 限制与已知问题

- 客户端需要 Python >= 3.14（标准库 `compression.zstd`）。低版本可改用 `zstandard` 库（见 PROTOCOL.md 的兼容性节）。
- 每条路由（Authorization + path）滚动各自的字典，多会话并发互不干扰；但同一路由的请求必须串行（LLM 客户端天然如此）。
- 响应体不做压缩（SSE 流式响应通常远小于请求体，收益有限）。

## 协议细节

见 [docs/PROTOCOL.md](docs/PROTOCOL.md)：自定义头语义、409 回退语义、字典滚动规则、证书同步、低版本 Python 兼容方案。

## License

MIT
