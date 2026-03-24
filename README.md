# serpent-wrt

A lightweight threat intelligence and enforcement daemon for OpenWRT routers.

serpent-wrt detects suspicious network activity using connection metadata (no packet capture) and enforces blocks via nftables — designed to run on constrained devices with as little as 64MB RAM.

## Features

- Conntrack-based flow collection via `/proc/net/nf_conntrack`
- Local IP/CIDR threat feed matching
- Behavioral detectors: outbound fanout, port scan, beaconing
- Dynamic nftables blocking via named sets
- Structured JSON logging to stdout
- Optional localhost-only HTTP management API (`/healthz`, `/stats`, `/reload`, `/detections/recent`)
- Single static binary, no database, no systemd dependency

## Requirements

- OpenWRT or Linux with `nf_conntrack` and `nftables`
- Go 1.26+ (for building from source)

## Building

```sh
make build
# Output: bin/serpent-wrt
```

## Running

```sh
make run
# Uses ./configs/serpent-wrt.example.yaml
```

Or directly:

```sh
./bin/serpent-wrt --config /etc/serpent-wrt.yaml
```

## Configuration

See [`configs/serpent-wrt.example.yaml`](configs/serpent-wrt.example.yaml) for all options.

Key settings:

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
```

## Threat Feed Format

A plain text file, one entry per line — IPv4 addresses or CIDRs:

```
1.2.3.4
10.0.0.0/8
```

## Architecture

```
conntrack collector -> FlowRecord normalization -> detectors -> event pipeline -> nftables enforcer
```

**Detectors:**
- `feed` — matches flow IPs against the local threat feed
- `fanout` — flags hosts contacting an unusual number of distinct destinations
- `scan` — flags hosts hitting many distinct ports on a target
- `beacon` — detects periodic outbound connections suggesting C2 beaconing

**Enforcer:** shells out to `nft` to insert IPs into a named nftables set. Idempotent.

## Design Goals

- Low RAM and CPU overhead suitable for 64–256MB routers
- Bounded in-memory state with TTLs and size limits
- No packet capture, no PCAP storage, no databases
- Single binary deployment

## License

[MIT](LICENSE)
