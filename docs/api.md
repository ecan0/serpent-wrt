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

## rpcd Management Adapter (Development)

The daemon source includes a fixed `serpent-wrt rpcd list` and
`serpent-wrt rpcd call <method>` executable-plugin interface.
rpcd passes call parameters as one JSON object on stdin.
rpcd adds the top-level `ubus_rpc_session` field to authenticated calls.
The adapter removes this transport field before it decodes method parameters.
It rejects other unknown fields.
The adapter accepts fixed method names and does not accept command paths,
shell text, arbitrary URLs, or generic file access.

Its methods provide overview, configuration revision and validation, guarded
configuration apply, service controls, paged feed listing, feed validation and
mutation, and reload.
Configuration stays in YAML.
The API origin comes only from the installed config and must be a literal
loopback address.
HTTP redirects and proxy environment variables are disabled.

The fixed `/usr/libexec/rpcd/serpent` wrapper and `luci-app-serpent` ACL source
are staged for the LuCI package.
That package and its menu are not installed yet.
The daemon package does not install or expose this adapter to web sessions.
Do not use a browser UI claim until PR8 and the real LuCI session ACL checks pass.

| rpcd method | Parameters | ACL access |
| --- | --- | --- |
| `overview` | none | read |
| `config_get` | none | read |
| `config_validate` | `document` JSON object string | read |
| `config_apply` | `document`, `revision` strings | write |
| `service` | `action` string | write |
| `feed_list` | `offset`, `limit` integers | read |
| `feed_validate` | `document` entries-array string | read |
| `feed_add`, `feed_remove` | `entry` string | write |
| `feed_replace` | `document` entries-array string | write |
| `feed_reload` | none | write |

`feed_list` defaults to offset 0 and limit 100.
Its limit is 1 through 100, and its result returns `next_offset: null` at the end.
The adapter limits requests to 1 MiB, configuration documents to 256 KiB, and feed changes to 20,000 entries.
It uses a revision hash, one administration lock, a temporary configuration file, and atomic replacement.
If apply fails, it restores the prior bytes and restarts the prior running service once.
It returns a rollback failure as an explicit error.
For a stopped service, feed edits use the existing file helpers.
For a running service, feed edits use the existing loopback routes.
If the running API is disabled or unavailable, feed writes fail instead of changing only the file.
The adapter reports API sources as unavailable when it cannot read them.

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

## Enforcement Status

Development builds add these fields under `/status.enforcement`:

| Field | Meaning |
| --- | --- |
| `packet_drop_enabled` | The explicit configuration flag for forwarded source-address drops |
| `packet_drop_state` | `disabled`, `ready`, or `failed`, from the configuration and active kernel policy |
| `packet_drop_error` | The prerequisite, ownership, active-rule, or residual-chain error |

`ready` requires valid prerequisites, the forward hook, and both family-set rule references.
A disabled configuration does not hide an owned chain that remains present after failed cleanup.
The same fields appear at the top level of `nftcheck --format json`.
Set-write counters and `/blocked` do not measure packet drops.
Use receiver observations and drop-rule counters for packet-path evidence.

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
