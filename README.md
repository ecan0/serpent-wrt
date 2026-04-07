# serpent-wrt

[![CI](https://github.com/ecan0/serpent-wrt/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/ecan0/serpent-wrt/actions/workflows/ci.yml)
[![Go 1.26](https://img.shields.io/badge/go-1.26-blue.svg)](https://golang.org/dl/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A lightweight threat intelligence and enforcement daemon for OpenWRT routers.

serpent-wrt monitors network connections using Linux conntrack metadata, detects suspicious activity with behavioral heuristics, and enforces blocks via nftables — all without packet capture, without a database, and with a minimal memory footprint. Designed for constrained devices with as little as 64 MB RAM.

---

## Why conntrack, not packet capture?

tcpdump and libpcap copy every packet to userspace. On a router with 64 MB RAM and a 400 MHz MIPS CPU, this creates constant per-packet CPU overhead, memory pressure from ring buffers, and flash wear from any PCAP storage — for threat signals that don't require payload inspection.

The Linux kernel already maintains a compact per-flow state table in `nf_conntrack`. Reading `/proc/net/nf_conntrack` costs a single file read per poll cycle regardless of traffic volume.

| | Packet capture | conntrack |
|---|---|---|
| CPU cost | per-packet | per-poll-cycle |
| Memory | ring buffer + reassembly | flat kernel table |
| Data | every byte | per-flow metadata |
| Disk writes | optional PCAP files | none |
| Enforcement | separate stack | reuses existing nftables |

---

## Architecture

```
/proc/net/nf_conntrack
          │
          ▼
      collector  ── poll interval ──▶  FlowRecord{proto, src, dst, ports, state}
          │
          ▼
  ┌──────────────────────────────────┐
  │           detectors              │
  │  ├── feed_match  (threat feed)   │
  │  ├── fanout      (many dsts)     │
  │  ├── port_scan   (many ports)    │
  │  └── beacon      (C2 intervals)  │
  └──────────────────────────────────┘
          │ Detection event
          ▼
      event logger  ──▶  NDJSON to stdout
          │               (+ optional remote syslog)
          ▼
      nftables enforcer  ──▶  inet blocked_ips set
```

---

## Features

- Conntrack-based flow collection — no packet capture
- Local IP/CIDR threat feed with hot-reload via `SIGHUP`
- Four behavioral detectors: feed match, outbound fanout, port scan, beaconing
- nftables enforcement via named sets with kernel-managed timeouts
- Structured NDJSON logging to stdout
- Optional remote syslog forwarding (UDP/TCP) for SIEM integration
- Optional localhost-only HTTP API
- Single static binary — no database, no systemd dependency, procd-compatible

---

## Building

```sh
# Native binary
make build          # → bin/serpent-wrt

# Cross-compile for OpenWRT targets
make cross          # → bin/serpent-wrt-linux-{mipsle,mips,armv7,arm64,amd64}

# x86/generic (i386) — 32-bit OpenWRT VMs
GOOS=linux GOARCH=386 go build -o bin/serpent-wrt-linux-386 ./cmd/serpent-wrt

# Run tests
make test
```

**Supported targets:** `linux/mipsle`, `linux/mips`, `linux/arm` (v7), `linux/arm64`, `linux/amd64`, `linux/386`

---

## Deployment

### First-time setup

```sh
# Copy init script, config, and threat feed to router
make deploy-setup DEPLOY_HOST=root@<router-ip>

# Build and push the binary (x86/generic)
make deploy-x86 DEPLOY_HOST=root@<router-ip>
```

### Manual

```sh
scp bin/serpent-wrt-linux-armv7 root@router:/usr/sbin/serpent-wrt
scp configs/serpent-wrt.example.yaml root@router:/etc/serpent-wrt/serpent-wrt.yaml
scp testdata/threat-feed.txt root@router:/etc/serpent-wrt/threat-feed.txt

# Enable and start via procd
scp contrib/init.d/serpent-wrt root@router:/etc/init.d/serpent-wrt
ssh root@router "/etc/init.d/serpent-wrt enable && /etc/init.d/serpent-wrt start"
```

### Hot-reload threat feed

```sh
# Reload without restarting — triggers via procd reload or directly:
kill -HUP $(pidof serpent-wrt)
```

---

## Configuration

See [`configs/serpent-wrt.example.yaml`](configs/serpent-wrt.example.yaml) for a fully annotated example.

```yaml
poll_interval: 5s
threat_feed_path: /etc/serpent-wrt/threat-feed.txt

enforcement_enabled: false   # set true once nftables is verified working
block_duration: 1h

# Skip destinations in these subnets (LAN traffic)
lan_cidrs:
  - 192.168.1.0/24

nft_table: serpent_wrt
nft_set: blocked_ips

log_level: info

api_enabled: true
api_bind: 127.0.0.1:8080

# Optional: forward JSON events to a remote syslog target (e.g. Wazuh on port 514)
# syslog_target: "10.0.0.10:514"
# syslog_proto: "udp"   # or "tcp"

detectors:
  fanout:
    distinct_dst_threshold: 50
    window: 60s
  scan:
    distinct_port_threshold: 30
    window: 60s
  beacon:
    min_hits: 5
    tolerance: 3s
    window: 5m
```

---

## Threat feed format

Plain text, one IPv4 address or CIDR per line. Lines beginning with `#` and blank lines are ignored.

```
# example
1.2.3.4
185.220.101.0/24
```

---

## Detectors

| Detector | Triggers when | Key config |
|---|---|---|
| `feed_match` | Destination IP/CIDR is in the threat feed | `threat_feed_path` |
| `fanout` | A source contacts too many distinct destinations in a window | `distinct_dst_threshold`, `window` |
| `port_scan` | A source probes too many distinct ports in a window | `distinct_port_threshold`, `window` |
| `beacon` | A source contacts the same destination at a regular interval | `min_hits`, `tolerance`, `window` |

All detectors operate on connection metadata only. ESTABLISHED TCP flows are excluded from the beacon detector to avoid false positives from persistent connections.

---

## API

Available when `api_enabled: true`. Bound to localhost only.

| Endpoint | Method | Description |
|---|---|---|
| `/healthz` | GET | `{"status":"ok"}` |
| `/stats` | GET | Runtime counters (flows seen, detections by type, blocks applied) |
| `/reload` | POST | Hot-reload threat feed from disk |
| `/detections/recent` | GET | Last 100 detections |

---

## Logging

NDJSON to stdout, one event per line:

```json
{"time":"2025-01-01T00:00:00Z","level":"warn","type":"detection","detector":"feed_match","src_ip":"192.168.1.5","dst_ip":"1.2.3.4","dst_port":443,"message":"connection to threat feed entry 1.2.3.4"}
{"time":"2025-01-01T00:00:00Z","level":"warn","type":"enforcement","src_ip":"192.168.1.5","message":"blocked 192.168.1.5 triggered by feed_match"}
```

When `syslog_target` is configured, each event is also forwarded as a JSON string in the syslog MSG field. Compatible with Wazuh, Graylog, and any RFC 3164 syslog receiver.

---

## Limitations

- **IPv4 only** — IPv6 conntrack entries are skipped
- **Polling, not event-driven** — conntrack is read on a fixed interval; phase 5 will replace this with netlink streaming
- **No DNS correlation** — domain names are not resolved or tracked
- **No payload inspection** — by design; see rationale above
- **nft subprocess** — enforcement shells out to `nft`; acceptable at this scale
- **No persistent state** — detection history and block state are lost on restart
- **Local threat feed only** — no remote feed sync in MVP

---

## Roadmap

| Phase | Status | Scope |
|---|---|---|
| 1 | done | Config, flow model, events, feed, conntrack collector |
| 2 | done | Feed match, fanout, port scan, bounded state store |
| 3 | done | nftables enforcer, runtime pipeline, stats, API |
| 4 | done | Beaconing detector, procd init script, tests, remote syslog |
| 5 | planned | Netlink conntrack events, dnsmasq integration, IPv6, eBPF/XDP, LuCI |

---

## License

[MIT](LICENSE)
