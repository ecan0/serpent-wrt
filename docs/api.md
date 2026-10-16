# HTTP API

The API is intended for localhost operation. Enable it with:

```yaml
api_enabled: true
api_bind: 127.0.0.1:8080
```

The API has no authentication, authorization, or TLS. Keep it on loopback and
use an SSH tunnel for remote administration. A non-loopback bind generates a
configuration warning but remains operator-controlled. Do not expose it to a
LAN or WAN: feed endpoints can modify the active threat feed.

Only the methods listed below are accepted. Other methods return `405 Method Not Allowed`.
JSON mutation requests must contain exactly one object and remain at or below 1 MiB.

## Endpoints

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/healthz` | GET | Liveness check. |
| `/status` | GET | Collector mode and poll status, feed, enforcement, uptime, detector config, and build metadata. |
| `/stats` | GET | Flow, detection, suppression, dedup, and block counters. |
| `/detections/recent` | GET | Last 100 detections. Optional `run_id` and `case_id` query values filter records. |
| `/blocked` | GET | Current IPv4 and IPv6 nftables timed-set contents. This does not prove packet drops. |
| `/reload` | POST | Reload threat feed from disk. |
| `/feed` | GET | List normalized local threat feed entries. |
| `/feed` | PUT | Replace the local threat feed with validated entries. |
| `/feed/validate` | POST | Validate one entry or a candidate entry list without writing. |
| `/feed/add` | POST | Add one IPv4/IPv6 IP-or-CIDR feed entry and reload if changed. |
| `/feed/remove` | POST | Remove one feed entry and reload if changed. |

`/healthz` and `/status.status: "ok"` report API liveness, not collector readiness.
`started_at` is the engine start time. `uptime_seconds` is the elapsed time since that start.

The collector fields have these meanings:

| Field | Meaning |
| --- | --- |
| `configured` | Collector mode from the effective configuration. |
| `active` | Selected mode, including snapshot fallback. This does not prove successful collection. |
| `fallback_error` | Netlink startup or stream failure. Successful snapshot polls do not clear this diagnostic. |
| `last_successful_poll` | Time when the latest snapshot completed and the tracker accepted its result. Absent before success and during native netlink operation. |
| `last_poll_error` | Latest snapshot failure. Absent before failure. The next successful snapshot clears it without loss of the prior success time. |
| `snapshot_overflow` | Latest successful snapshot exceeded the retained-flow limit. A failed poll preserves this value. |
| `new_flow_detection_ready` | A complete snapshot baseline exists after the latest successful poll, or the netlink event stream is active. False before collection, after a poll failure, during overflow, and after engine exit. |

A successful snapshot can exceed capacity. Its success timestamp does not prove detection readiness.
The first complete snapshot establishes a baseline without historical detections.
After overflow, the next complete snapshot establishes a new baseline.
Readiness does not prove traffic delivery, full detector-window coverage, or packet drops.
Poll timestamps use RFC 3339 format with fractional seconds and a timezone offset.

`log_level` filters stdout and syslog only.
At `error`, warn-level detections and timed-set events disappear from both outputs.
Recent API detections, counters, suppression, and response behavior remain independent of that filter.

## Detection Records

`/detections/recent` retains the original conntrack destination in `dst_ip` and `dst_port`.
When a snapshot proves DNAT, `translated_dst_ip` and `translated_dst_port` contain the translated endpoint.
`port_scan` and `ext_scan` records also contain `distinct_port_count` and sorted `observed_dst_ports` at the episode threshold.

When `event_context` is set, detection records also include `run_id` and `case_id`.
The same fields appear in stdout and remote syslog.
Use both query values together. A request with only one returns `400 Bad Request`.

```json
{
  "detector": "port_scan",
  "dst_ip": "198.51.100.20",
  "dst_port": 443,
  "distinct_port_count": 3,
  "observed_dst_ports": [22, 80, 443]
}
```

## Event and API Compatibility

Before 1.0, a minor release can change API and event contracts.
Patch releases preserve existing endpoint behavior and field meanings.
Releases can add optional fields and endpoints.
Clients must ignore unknown JSON fields.
Document breaking changes in the changelog with a migration note.

## Examples

```sh
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/status
curl http://127.0.0.1:8080/stats
curl http://127.0.0.1:8080/detections/recent
curl 'http://127.0.0.1:8080/detections/recent?run_id=run-123&case_id=case-456'
curl -X POST http://127.0.0.1:8080/reload
```

Threat feed operations:

```sh
curl http://127.0.0.1:8080/feed

curl -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:8080/feed/validate \
  -d '{"entry":"198.51.100.1"}'

curl -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:8080/feed/add \
  -d '{"entry":"198.51.100.1"}'

curl -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:8080/feed/remove \
  -d '{"entry":"198.51.100.1"}'

curl -H 'Content-Type: application/json' \
  -X PUT http://127.0.0.1:8080/feed \
  -d '{"entries":["198.51.100.1","203.0.113.0/24"]}'
```

The API validates feed entries before writing them. Successful feed mutations
reload the daemon feed automatically.
