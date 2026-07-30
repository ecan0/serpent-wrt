# Configuration

Start from [configs/serpent-wrt.example.yaml](../configs/serpent-wrt.example.yaml).

Validate before starting or reloading:

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

self_ips:
  - 198.51.100.1

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

## Important Fields

### Collector

`collector: polling` is the default and requires no userspace event tool.
`collector: netlink` consumes only NEW connection events through
`conntrack -E -e NEW`, which avoids treating repeated snapshots as new
observations. Install the optional OpenWrt `conntrack` package before enabling
it:

```sh
apk add conntrack
```

If the command cannot start or its event stream exits, serpent-wrt records the
failure in `/status` and automatically returns to polling until restart.

- `lan_cidrs` defines outbound vs inbound flow direction.
- `self_ips` prevents router-originated management, NTP, DHCP, and similar
  traffic from becoming detections.
- `profile` applies detector defaults. `home` is baseline, `homelab` and
  `quiet` raise thresholds, and `paranoid` lowers thresholds.
- `lease_enrichment` reads dnsmasq leases and adds hostname/MAC context when
  available.
- `enforcement_enabled` defaults to `false`; when enabled, the daemon populates
  the configured timed nftables set.
- `nft_table` and `nft_set` identify that set. A separately managed firewall
  drop rule must reference it before entries affect traffic.
- `dedup_window` suppresses repeated alerts from the same detector/source/target
  combination.
- `syslog_target` and `syslog_proto` forward JSON events to a SIEM.
- `api_bind` should remain loopback-only. The API has no authentication or TLS
  and includes threat-feed mutation endpoints.

## Suppression Rules

Suppression rules quiet expected scanners, monitors, and health checks before
logging, recent-event storage, stats-by-type increments, or enforcement.

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

Each rule matches only when every configured dimension matches. Supported
matchers are `detectors`, `src_addrs`, `dst_addrs`, and `dst_ports`; address
matchers accept IPv4 addresses or CIDRs.

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

`min_interval` rejects bursty observations. `exclude_ports` is especially
important with the polling collector because one long-lived UDP conntrack entry
can be observed in multiple snapshots. Excluding DNS and NTP is a conservative
starting point, not a substitute for validating beacon alerts on the target
router.
