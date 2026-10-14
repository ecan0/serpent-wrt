# Configuration

Start from [configs/serpent-wrt.example.yaml](../configs/serpent-wrt.example.yaml).

Validate before start or reload:

```sh
serpent-wrt --config /etc/serpent-wrt/serpent-wrt.yaml configtest
serpent-wrt --config /etc/serpent-wrt/serpent-wrt.yaml configtest --effective
serpent-wrt --config /etc/serpent-wrt/serpent-wrt.yaml configtest --effective --format json
```

## Minimal Shape

```yaml
poll_interval: 5s
collector: polling
threat_feed_path: /etc/serpent-wrt/threat-feed.txt
profile: home

lan_cidrs:
  - 198.51.100.0/24
  - 2001:db8:100::/64

self_ips:
  - 198.51.100.1
  - 2001:db8:100::1

lease_enrichment: true
dnsmasq_leases_path: /tmp/dhcp.leases

api_enabled: true
api_bind: 127.0.0.1:8080

enforcement_enabled: false
block_duration: 1h
nft_table: serpent_wrt
nft_set: blocked_ips


dedup_window: 5m
```

The daemon uses `<nft_set>_v4` and `<nft_set>_v6` for IPv4 and IPv6 addresses.
Keep the base name at 252 bytes or fewer to leave room for the family suffix.

## Important Fields

### Collector

The default collector uses snapshots and requires no userspace event tool.
The `netlink` collector consumes only NEW connection events through
`conntrack -E -e NEW`. Repeated snapshots do not create new observations.
Install the optional OpenWrt `conntrack` package first:

```sh
apk add conntrack
```

If the command cannot start or its event stream ends, the daemon records a
failure in `/status`. It then uses snapshot mode until restart.

- `lan_cidrs` defines outbound versus inbound flow direction.

- `self_ips` filters router-originated management traffic, such as NTP and DHCP.

- `profile` applies detector defaults. `home` is baseline.
  `homelab` and `quiet` raise thresholds, and `paranoid` lowers them.

- `lease_enrichment` reads dnsmasq leases and adds hostname/MAC context when available.

- `enforcement_enabled` defaults to `false`.
  When true, the daemon populates the configured family-specific nftables set.

- `nft_table` and `nft_set` identify the table and set-name prefix.
  The daemon appends `_v4` and `_v6` to the set prefix.
  Firewall policy must use the correct set before an entry affects traffic.

- `dedup_window` suppresses repeated signals without detector-owned episode state.

- `event_context` can add `run_id` and `case_id` to each detection event.
  Set both values together. The daemon writes them to stdout, the API, and
  remote syslog. They support event correlation; they do not control detection.

- `syslog_target` and `syslog_proto` forward JSON events to a SIEM.

- `api_bind` must remain loopback-only.
  The API has no authentication or TLS and includes threat-feed mutation endpoints.

## Suppression Rules

Suppression rules filter expected scanners, monitors, and health checks before
the daemon writes logs, stores recent events, updates stats-by-type, or enforces.

```yaml
suppression_rules:
  - name: trusted scanner
    detectors: [port_scan, ext_scan]
    src_addrs:
      - 198.51.100.50
  - name: external SSH health check
    detectors: [brute_force]
    src_addrs:
      - 198.51.100.10/32
    dst_ports: [22]
```

Matchers are `detectors`, `src_addrs`, `dst_addrs`, and `dst_ports`.
Address matchers accept IPv4 or IPv6 addresses and CIDRs.

## Detector Thresholds

```yaml
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
    min_interval: 5s
    exclude_ports: [53, 123]
  ext_scan:
    distinct_port_threshold: 15
    window: 60s
  brute_force:
    threshold: 5
    window: 60s
```

Explicit detector settings override profile defaults.

The first conntrack snapshot is a baseline.
Later snapshots process each tuple only when it first appears.
A tuple that remains in the table does not create more beacon samples.
A tuple that leaves and later reappears counts as new.
Snapshot time sets beacon cadence. Precision depends on `poll_interval`.

`port_scan` and `ext_scan` emit once when the time-window count of distinct ports reaches the threshold.
Each record includes the threshold count and a sorted port array.
Expiry rearms the episode when the count drops below the threshold.
Each distinct-value threshold must be 256 or lower.
`beacon.min_hits` must be 64 or lower.
`serpent-wrt nftcheck` validates both set definitions without rule changes, even when enforcement is disabled.

## Retained State Limits

Each distinct-value tracker retains at most 1,024 keys, 256 values per key, and 4,096 values total.
Each beacon detector retains at most 512 source/destination pairs, 64 timestamps per pair, and 8,192 timestamps total.
When a value or sample limit is full, the detector rejects new state and keeps the values it already retains.
Configuration thresholds cannot exceed the per-key value limit.
These limits bound detector state. They do not set a total process-memory budget.
