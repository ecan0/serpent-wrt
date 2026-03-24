# serpent-wrt

A lightweight threat intelligence and enforcement daemon for OpenWRT routers.

serpent-wrt detects suspicious network activity using conntrack connection
metadata and enforces blocks via nftables — without packet capture, without a
database, and without heavy disk I/O. Designed for constrained devices with as
little as 64 MB RAM.

---

## Why not tcpdump / packet capture?

tcpdump and libpcap operate on raw packet streams. Every frame transiting the
router is copied to userspace, buffered, and parsed individually. On a router
with 64 MB RAM and a 400 MHz MIPS CPU this creates:

- Constant per-packet CPU overhead from syscalls and frame parsing
- Memory pressure from ring buffers and TCP reassembly state
- Flash wear from any PCAP storage
- Complexity that exceeds the actual threat model for a home or SMB router

Most threats detectable at a border router do not require payload inspection.
Suspicious destinations, port scan behavior, outbound fanout, and C2 beaconing
intervals are all identifiable from **connection metadata alone**.

## Why conntrack + nftables?

The Linux kernel's netfilter connection tracking subsystem (`nf_conntrack`)
already maintains a compact per-flow state table for every active connection —
maintained by the kernel, not userspace. Reading `/proc/net/nf_conntrack` costs
a single file read per poll cycle regardless of traffic volume.

| | Packet capture | conntrack |
|---|---|---|
| CPU cost | per-packet | per-poll-cycle |
| Memory | ring buffer + reassembly | flat kernel table |
| Data | every byte | per-flow metadata |
| Disk writes | optional PCAP files | none |
| Integration | separate stack | reuses existing nftables |

nftables sets provide O(1) IP lookup for block decisions and support
kernel-managed timeouts — no userspace expiry loop needed.

---

## Architecture

```
/proc/net/nf_conntrack  (fallback: conntrack -L)
          │
          ▼
      collector  (poll interval)
          │ FlowRecord{proto, src, dst, ports, state}
          ▼
  ┌────────────────────────────────────┐
  │           detectors                │
  │  ├── feed_match  (threat feed IP)  │
  │  ├── fanout      (many dst IPs)    │
  │  ├── port_scan   (many dst ports)  │
  │  └── beacon      (periodic C2)     │
  └────────────────────────────────────┘
          │ Detection
          ▼
      event logger  (NDJSON → stdout)
          │
          ▼
      nftables enforcer  (nft CLI, idempotent)
          │
          ▼
   inet table / blocked_ips set
```

---

## Features

- Conntrack-based flow collection via `/proc/net/nf_conntrack`
- Local IP/CIDR threat feed with hot-reload (`SIGHUP`)
- Four behavioral detectors: feed match, outbound fanout, port scan, beaconing
- Dynamic nftables blocking via named sets with kernel-managed timeouts
- Structured JSON logging (NDJSON) to stdout
- Optional localhost-only HTTP API (`/healthz`, `/stats`, `/reload`, `/detections/recent`)
- Single static binary — no database, no systemd dependency

---

## MVP Limitations

- **IPv4 only** — IPv6 conntrack entries are skipped
- **Polling, not event-driven** — conntrack is read on a fixed interval;
  Phase 5 will replace this with netlink event streaming
- **No DNS correlation** — domain names are not resolved or tracked
- **No payload inspection** — intentional; see design rationale above
- **nft subprocess** — enforcement shells out to `nft`; acceptable at MVP scale
- **No persistent state** — blocked IPs and detection history are lost on restart
- **Local threat feed only** — no remote feed sync in MVP

---

## Building

```sh
# Native
make build          # → bin/serpent-wrt

# OpenWRT cross-compilation
make cross          # → bin/serpent-wrt-linux-{mipsle,mips,armv7,arm64,amd64}

# Tests
make test
```

## Deployment

```sh
scp bin/serpent-wrt-linux-armv7 root@router:/usr/local/sbin/serpent-wrt
scp configs/serpent-wrt.example.yaml root@router:/etc/serpent-wrt/serpent-wrt.yaml
scp testdata/threat-feed.txt root@router:/etc/serpent-wrt/threat-feed.txt

ssh root@router serpent-wrt --config /etc/serpent-wrt/serpent-wrt.yaml
```

Hot-reload the threat feed without restarting:

```sh
kill -HUP $(pidof serpent-wrt)
```

## Configuration

See [`configs/serpent-wrt.example.yaml`](configs/serpent-wrt.example.yaml) for all options.

```yaml
poll_interval: 5s
threat_feed_path: /etc/serpent-wrt/threat-feed.txt
enforcement_enabled: true
block_duration: 1h
lan_cidrs:
  - 192.168.1.0/24
nft_table: serpent_wrt
nft_set: blocked_ips
api_enabled: true
api_bind: 127.0.0.1:8080
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

## Threat Feed Format

Plain text, one IPv4 address or CIDR per line. `#` comments and blank lines are ignored.

```
# example
1.2.3.4
185.220.101.0/24
```

## API

| Endpoint | Method | Description |
|---|---|---|
| `/healthz` | GET | Returns `{"status":"ok"}` |
| `/stats` | GET | Runtime counters (flows, detections, blocks) |
| `/reload` | POST | Hot-reload threat feed from disk |
| `/detections/recent` | GET | Last 100 detections |

## Logging

NDJSON to stdout, one event per line:

```json
{"time":"...","level":"warn","type":"detection","detector":"feed_match","src_ip":"192.168.1.5","dst_ip":"1.2.3.4","dst_port":443,"message":"connection to threat feed entry 1.2.3.4"}
{"time":"...","level":"warn","type":"enforcement","src_ip":"192.168.1.5","message":"blocked 192.168.1.5 triggered by feed_match"}
```

---

## Roadmap

| Phase | Status | Items |
|---|---|---|
| 1 | done | config, flow model, events, feed, collector |
| 2 | done | state store, feed match, fanout, port scan, beacon |
| 3 | done | nftables enforcer, runtime pipeline, API |
| 4 | planned | procd init script, tests polish, docs |
| 5 | future | netlink conntrack events, dnsmasq integration, IPv6, eBPF/XDP, LuCI |

## License

[MIT](LICENSE)
