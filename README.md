# 辐射剂量事件遥测网关

接收监测站通过不稳定专网上报的剂量事件（`POST /api/telemetry/events`，JSON 或 gzip 压缩 JSON），
对每一条报文做设备身份认证、时效检查、防篡改与防重放，只接纳完全合法的事件。

* 纯 Python 3.11 标准库实现，无 pip 依赖。
* 持久化 nonce（SQLite + WAL），**并发请求与服务重启后同站点 nonce 至多成功一次**。
* 成功返回 `202` 与稳定事件摘要；各类失败返回可区分的状态码和错误码。
* 默认测试密钥开箱即用（`config/keys.json`）。

## 快速开始（Docker）

```bash
docker compose up -d --build                 # 默认宿主机端口 8080
HOST_PORT=9090 docker compose up -d --build  # 自定义宿主机端口
curl http://localhost:8080/healthz
```

## 一次性验证服务 verify

```bash
docker compose run --rm verify
echo $?   # 0 表示全部通过；非零汇总了任一阶段的失败
```

`verify` 依次执行：

1. **单元/集成测试**（35 个，含并发 nonce 抢占与重启持久化）；
2. **构建确认**（运行于已构建镜像内即证明镜像构建成功；`--docker-build` 可在宿主机显式构建）；
3. **签名 / gzip / 并发防重放冒烟**（对健康网关真实发 HTTP 请求）。

无 Docker 环境下可在本机等价运行：

```bash
python3 -m smoke.run_all --spawn   # 自动临时拉起网关，退出码语义相同
# 或
bash scripts/verify.sh
```

## 认证与签名约定

请求头：

| 请求头 | 含义 |
|---|---|
| `X-Station` | 站点标识 |
| `X-Key-Id` | 密钥编号 |
| `X-Timestamp` | 发送时刻（Unix 秒 或 ISO-8601，支持 `Z`） |
| `X-Nonce` | 随机串（≤128 字符） |
| `X-Signature` | Base64(HMAC-SHA256) |
| `Content-Encoding` | 可选，`gzip` 表示载荷为 gzip 压缩 JSON |

待签名内容为以下七项以换行连接（UTF-8）：

```
POST
/api/telemetry/events
<X-Station>
<X-Key-Id>
<X-Timestamp>
<X-Nonce>
<SHA-256 十六进制摘要：传输原始字节（gzip 时为压缩后字节）>
```

用该站点密钥做 HMAC-SHA256，标准 Base64 后放入 `X-Signature`。
验签发生在解压之前，因此截获后改动任何一个字节都会使摘要和签名失效。

## 处理顺序与失败码

处理严格按以下顺序，首个失败即返回；**只有完全成功接纳的请求才写入 nonce，任何失败都不占用 nonce**。

| 阶段 | HTTP 状态 | `error` |
|---|---|---|
| 缺少认证头 | 401 | `missing_auth_headers` |
| 站点/密钥未登记 | 401 | `unknown_key` |
| 密钥未生效 / 已过期 | 403 | `key_not_yet_valid` / `expired_key` |
| 时间戳无法解析 | 400 | `invalid_timestamp` |
| 与网关时间相差超过 5 分钟 | 440 | `time_out_of_bounds` |
| HMAC 签名错误 | 401 | `invalid_signature` |
| gzip 数据损坏 | 415 | `invalid_gzip` |
| 非 JSON 载荷 | 422 | `malformed_json` |
| 事件字段不合法 | 422 | `invalid_event` |
| 同站点 nonce 重复 | 409 | `duplicate_nonce` |
| **成功** | **202** | — |

> 时间越界使用显式的非标准状态码 `440`，以便与 400 等其他客户端错误明确区分。

密钥还必须处于其自身有效期（`not_before` ≤ 网关当前时间 ≤ `not_after`）。

## 成功响应

```json
{
  "status": "accepted",
  "event_id": "evt-0001",
  "station": "ST01",
  "received_seq": 7,
  "received_at": "2026-10-05T01:18:43.631049+00:00",
  "digest": "c2f3…（64 位十六进制）"
}
```

`digest` 为事件内容的规范 JSON（排序键、紧凑分隔符）SHA-256，
与字段顺序、空白及是否经 gzip 传输无关，重复上报同一事件内容时摘要保持稳定。

## 事件格式

```json
{
  "event_id": "evt-0001",
  "station": "ST01",
  "measured_at": "2026-10-05T01:18:00Z",
  "dose_uSv": 0.37
}
```

`event_id`（非空字符串）、`measured_at`（ISO-8601）、`dose_uSv`（有限非负数）为必填；
若携带 `station`，必须与认证站点一致。

## 密钥配置

`config/keys.json`（容器内 `/app/config/keys.json`，可用 `TELEMETRY_KEYS_FILE` 覆盖）：

```json
{
  "keys": [
    {
      "station": "ST01",
      "key_id": "k1",
      "secret": "base64 编码的 HMAC 密钥",
      "not_before": "2024-01-01T00:00:00Z",
      "not_after":  "2030-12-31T23:59:59Z"
    }
  ]
}
```

默认仓库提供三个测试密钥：ST01/k1、ST02/k1（有效），ST03/key-expired（已过期，供测试区分）。
生产部署请替换并以只读方式挂载自己的密钥文件。

## 其他环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `HOST` / `PORT` | `0.0.0.0` / `8080` | 监听地址与容器内端口 |
| `HOST_PORT` | `8080` | Compose 映射的宿主机端口 |
| `TELEMETRY_DB` | `/data/nonces.db` | nonce SQLite 路径（命名卷持久化） |
| `TELEMETRY_KEYS_FILE` | `/app/config/keys.json` | 密钥配置文件 |

## 目录结构

```
app/            网关实现（config/signing/events/nonce_store/server）
config/keys.json 默认测试密钥
tests/          35 个单元/集成/E2E 测试（标准库 unittest）
smoke/          线上冒烟与 verify 聚合入口（run_all）
scripts/verify.sh 无 Docker 时的本机验证脚本
Dockerfile, docker-compose.yml
```
