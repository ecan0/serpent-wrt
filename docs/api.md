# HTTP API

The API is intended for localhost operation. Enable it with:

```yaml
api_enabled: true
api_bind: 127.0.0.1:8080
```

## Endpoints

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/healthz` | GET | Liveness check. |
| `/status` | GET | Feed path/count, enforcement diagnostics, uptime, detector config, build metadata. |
| `/stats` | GET | Flow, detection, suppression, dedup, and block counters. |
| `/detections/recent` | GET | Last 100 detections in memory. |
| `/blocked` | GET | Current nftables blocked set contents. |
| `/reload` | POST | Reload threat feed from disk. |
| `/feed` | GET | List normalized local threat feed entries. |
| `/feed` | PUT | Replace the local threat feed with validated entries. |
| `/feed/validate` | POST | Validate one entry or a candidate entry list without writing. |
| `/feed/add` | POST | Add one IPv4/IP-CIDR feed entry and reload if changed. |
| `/feed/remove` | POST | Remove one feed entry and reload if changed. |

## Examples

```sh
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/status
curl http://127.0.0.1:8080/stats
curl http://127.0.0.1:8080/detections/recent
curl -X POST http://127.0.0.1:8080/reload
```

Threat feed operations:

```sh
curl http://127.0.0.1:8080/feed

curl -X POST http://127.0.0.1:8080/feed/validate \
  -d '{"entry":"198.51.100.1"}'

curl -X POST http://127.0.0.1:8080/feed/add \
  -d '{"entry":"198.51.100.1"}'

curl -X POST http://127.0.0.1:8080/feed/remove \
  -d '{"entry":"198.51.100.1"}'

curl -X PUT http://127.0.0.1:8080/feed \
  -d '{"entries":["198.51.100.1","203.0.113.0/24"]}'
```

The API validates feed entries before writing them. Successful feed mutations
reload the daemon feed automatically.
