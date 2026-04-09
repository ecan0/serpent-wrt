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
      direction classifier
      (skip: unroutable, broadcast, self)
          │
          ├── LAN → WAN ──────────────────────────────────┐
          │   ┌──────────────────────────────────────────┐ │
          │   │  feed_match  (threat feed hit)           │ │
          │   │  fanout      (many distinct destinations) │ │
          │   │  port_scan   (many distinct ports)        │ │
          │   │  beacon      (periodic C2 cadence)        │ │
          │   └──────────────────────────────────────────┘ │
          │                                                 │
          └── WAN → LAN ──────────────────────────────────┘
              ┌──────────────────────────────────────────┐
              │  ext_scan    (external recon: many ports) │
              │  brute_force (spray: same port, many hosts│
              └──────────────────────────────────────────┘
                        │ Detection event
                        ▼
                  dedup filter  ──▶  suppress repeat alerts (sliding window)
                        │
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
- Six behavioral detectors across outbound and inbound directions
- Direction-aware routing: LAN→WAN detectors (fanout, port scan, beacon, feed match) run independently from WAN→LAN detectors (ext_scan, brute_force)
- Broadcast, loopback, link-local, and router-self traffic automatically filtered before any detector sees it
- Dedup suppression collapses repeated alerts from the same source within a configurable window
- nftables enforcement via named sets with kernel-managed timeouts
- Structured NDJSON logging to stdout
- Optional remote syslog forwarding (UDP/TCP) for SIEM integration — auto-reconnects on failure
- Optional localhost-only HTTP API
- Single static binary — no database, no systemd dependency, procd-compatible

---

## Building

```sh
# Native binary
make build          # → bin/serpent-wrt

# Cross-compile for OpenWRT targets
make cross          # → bin/serpent-wrt-linux-{mipsle,mips,armv7,arm64,amd64}

# x86/generic — 32-bit OpenWRT VMs (uname -m = i686)
GOOS=linux GOARCH=386 go build -o bin/serpent-wrt-linux-386 ./cmd/serpent-wrt

# Run tests
make test
```

**Supported targets:** `linux/mipsle`, `linux/mips`, `linux/arm` (v7), `linux/arm64`, `linux/amd64`, `linux/386`

> **Note:** OpenWRT x86 images typically report `i686`. Use `GOARCH=386`, not `amd64`. An amd64 binary will be silently interpreted as a shell script and crash.

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

Many OpenWRT builds omit `sftp-server`, so `scp` and `rsync` fail. Transfer files via stdin instead:

```sh
# Stop the service before overwriting the binary (avoids "Text file busy")
ssh root@router '/etc/init.d/serpent-wrt stop'

# Transfer binary
ssh root@router 'cat > /usr/sbin/serpent-wrt && chmod +x /usr/sbin/serpent-wrt' \
  < bin/serpent-wrt-linux-386

# Transfer config and feed
ssh root@router 'cat > /etc/serpent-wrt/serpent-wrt.yaml' \
  < configs/serpent-wrt.example.yaml
ssh root@router 'cat > /etc/serpent-wrt/threat-feed.txt' \
  < testdata/threat-feed.txt

# Transfer init script, enable, and start
ssh root@router 'cat > /etc/init.d/serpent-wrt && chmod +x /etc/init.d/serpent-wrt' \
  < contrib/init.d/serpent-wrt
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

# LAN CIDRs — used for direction classification (LAN→WAN vs WAN→LAN)
lan_cidrs:
  - 192.168.1.0/24

# Router's own IPs — flows sourced from these are filtered before detectors run.
# Add every interface IP (LAN, WAN, loopback is automatic).
self_ips:
  - 192.168.1.1

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
  ext_scan:
    distinct_port_threshold: 15
    window: 60s
  brute_force:
    threshold: 5
    window: 60s
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

All detectors operate on connection metadata only — no payload inspection.

**Outbound (LAN → WAN)**

| Detector | Triggers when | Key config |
|---|---|---|
| `feed_match` | Source or destination IP/CIDR matches the threat feed | `threat_feed_path` |
| `fanout` | An internal host contacts too many distinct external destinations | `distinct_dst_threshold`, `window` |
| `port_scan` | An internal host probes too many distinct ports on one target | `distinct_port_threshold`, `window` |
| `beacon` | An internal host contacts the same destination at a regular interval | `min_hits`, `tolerance`, `window` |

**Inbound (WAN → LAN)**

| Detector | Triggers when | Key config |
|---|---|---|
| `ext_scan` | An external IP probes many distinct ports on one internal host | `distinct_port_threshold`, `window` |
| `brute_force` | An external IP hits the same service port across many internal hosts | `threshold`, `window` |

ESTABLISHED TCP flows are excluded from the beacon detector to avoid false positives from persistent connections. The `feed_match` detector checks both source and destination to catch inbound connections from known-bad IPs.

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

When `syslog_target` is configured, each event is also forwarded as a JSON string in the syslog MSG field. Compatible with Wazuh, Graylog, and any RFC 3164 syslog receiver. The sender re-dials automatically on write failure, so brief SIEM restarts do not permanently break remote forwarding.

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
| 2 | done | Feed match, fanout, port scan, bounded sliding-window state store |
| 3 | done | nftables enforcer, runtime pipeline, stats, API |
| 4 | done | Beaconing detector, procd init script, tests, remote syslog, self-healing UDP writer |
| 5 | done | Inbound WAN detection (ext_scan, brute_force), direction classifier, dedup suppression, broadcast/self filter |
| 6 | planned | Netlink conntrack events, dnsmasq integration, IPv6, eBPF/XDP on capable targets, LuCI plugin |

---

## License

[MIT](LICENSE)
