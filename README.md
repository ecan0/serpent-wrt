# serpent-wrt

[![CI](https://github.com/ecan0/serpent-wrt/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/ecan0/serpent-wrt/actions/workflows/ci.yml)
[![Go 1.26](https://img.shields.io/badge/go-1.26-blue.svg)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-package%20scaffold-blueviolet.svg)](openwrt/serpent-wrt)

Lightweight OpenWrt/Linux IDS, threat-intel, and optional nftables enforcement
for router-safe detection.

`serpent-wrt` watches conntrack metadata that Linux routers already maintain,
matches flows against local threat intelligence, detects common reconnaissance,
C2-like beaconing, scanning, and brute-force patterns, emits structured security
events, and can optionally block hostile IPs with nftables. It is built for
constrained OpenWrt routers: no packet capture, no payload inspection, no
database, and no heavyweight runtime stack.

## Stable MVP Status

The current codebase is a feature-complete stable MVP. It is useful today as a
small OpenWrt/Linux security daemon for local threat visibility, feed-backed
detection, operational telemetry, and optional edge enforcement.

- Router-safe by design: bounded in-memory state, conntrack polling, no packet
  capture, no DPI, and no persistent database.
- Linux/OpenWrt integration: `nf_conntrack`, procd init scripts, nftables sets,
  syslog forwarding, SDK/package checks, and runtime smoke coverage.
- Security focus: threat-intel hits, ATT&CK-aligned behavior categories such as
  reconnaissance and command-and-control patterns, and OWASP-adjacent service
  scanning and brute-force signals.
- Operator surfaces: config validation, effective-config output, feed
  management, `/status`, `/stats`, recent detections, and rollback runbooks.

## Quick Links

- [Stable MVP status](#stable-mvp-status)
- [What problem does this solve?](#what-problem-does-this-solve)
- [Detection coverage](#detection-coverage)
- [Engineering highlights](#engineering-highlights)
- [Architecture and data flow](#architecture-and-data-flow)
- [Build and test](#build-and-test)
- [Install on OpenWrt](#install-on-openwrt)
- [Configuration](#configuration)
- [Operate the daemon](#operate-the-daemon)
- [OpenWrt operational runbooks](docs/openwrt-runbooks.md)
- [Events and SIEM integration](#events-and-siem-integration)
- [Roadmap](#roadmap)

## What Problem Does This Solve?

Small routers sit at a valuable point in the network: they can see which hosts
are talking to which destinations, and they can enforce blocks close to the edge.
But many IDS and network-monitoring tools are too expensive for common OpenWrt
targets. Packet capture, deep packet inspection, databases, and large agents can
consume CPU, RAM, flash, and operational patience.

`serpent-wrt` takes a narrower path. It reads flow metadata from conntrack, looks
for security-relevant patterns, logs normalized events, and optionally inserts
temporary nftables blocks. The broader cybersecurity goal is practical detection
engineering on limited hardware: useful signals, bounded state, explainable
rules, and safe enforcement defaults.

## Who Is This For?

- OpenWrt users who want lightweight threat visibility on a router.
- Homelab operators sending router detections to Wazuh, Graylog, or syslog.
- Security students learning IDS concepts without starting from packet capture.
- Engineers evaluating constrained-device detection, Go services, and OpenWrt
  packaging.
- Reviewers looking for practical systems/security work: Linux flow
  collection, detector design, threat-intel operations, operational APIs,
  package validation, and router runtime testing.

## Why Conntrack, Not Packet Capture?

The kernel already maintains a compact connection table through `nf_conntrack`.
Reading that table once per poll cycle is much cheaper than copying every packet
to userspace.

| Capability | Packet capture | Conntrack metadata |
| --- | --- | --- |
| CPU cost | Per packet | Per poll cycle |
| Memory profile | Capture buffers and optional reassembly | Existing kernel flow table |
| Data collected | Payload and headers | Protocol, IPs, ports, state, time |
| Storage pressure | Often paired with PCAP files | None by default |
| Router fit | Heavy on small targets | Lightweight and bounded |
| Enforcement path | Separate integration | Reuses nftables |

This means `serpent-wrt` is intentionally not a full enterprise IDS. It is a
router-friendly detection layer for signals that do not need payload inspection.

## Highlights

- Conntrack-based flow collection with no packet capture.
- Direction-aware detection for LAN-to-WAN and WAN-to-LAN traffic.
- Local IPv4/IP-CIDR threat feed with SIGHUP/API reload.
- Six detectors: `feed_match`, `fanout`, `port_scan`, `beacon`, `ext_scan`, and
  `brute_force`.
- Broadcast, loopback, link-local, unroutable, and router-self filtering.
- Config-only suppression rules for expected scanners, monitors, and other
  noisy but trusted traffic.
- Detection profiles (`home`, `homelab`, `quiet`, `paranoid`) for practical
  threshold tuning without editing every detector.
- Optional read-only dnsmasq lease enrichment adds hostnames and MAC addresses
  to LAN-side detections.
- Deduplication to suppress repeated alerts while preserving meaningful
  destination-port differences.
- Structured NDJSON logs with severity, confidence, and reason metadata.
- Optional remote syslog forwarding for SIEM ingestion.
- Optional nftables blocking through named sets, kernel-managed timeouts, and
  status diagnostics for missing enforcement state.
- Localhost HTTP API for health, status, stats, reloads, detections, and blocks.
- OpenWrt package scaffold, procd init script, and optional runtime smoke
  coverage.

## Detection Coverage

All detections use connection metadata only. No payloads are inspected.

| Detector | Direction | Security outcome | ATT&CK / OWASP-adjacent signal |
| --- | --- | --- | --- |
| `feed_match` | LAN to WAN | Internal host contacts a listed IP/CIDR. | Suspicious outbound infrastructure, known-bad C2/blocklist hits, threat-intel matches. |
| `feed_match` | WAN to LAN | Known-bad external source reaches an internal host. | Threat-intel hit against exposed or forwarded services. |
| `beacon` | LAN to WAN | Host contacts the same destination on a regular cadence. | C2-like periodic communication pattern. |
| `fanout` | LAN to WAN | Host reaches too many distinct external destinations. | Discovery, staging, or unusual outbound fanout. |
| `port_scan` | LAN to WAN | Internal host probes many ports on one external target. | Reconnaissance and service enumeration. |
| `ext_scan` | WAN to LAN | External source probes many ports on one internal host. | Exposed-service scanning and reconnaissance. |
| `brute_force` | WAN to LAN | External source hits the same service port across many internal hosts. | Credential-access style brute-force or service-spray behavior. |

Detections include a stable `reason`, a severity, and a confidence score so
downstream rules can distinguish threat-feed hits, scans, service sprays, and
beacon-like behavior. These mappings are intentionally high-level; the project
does not claim formal ATT&CK technique coverage or inspect application payloads.

OWASP-adjacent value comes from edge visibility into service probing,
brute-force attempts, suspicious infrastructure contact, and scan patterns often
seen around web and application attacks, without turning the router into a full
application security scanner.

## Engineering Highlights

- Constrained Linux systems design: small Go daemon, bounded state, polling over
  packet capture, and router-friendly failure modes.
- Detection engineering: multiple flow-based detectors, stable reasons,
  severity/confidence metadata, suppression rules, deduplication, and profiles.
- Threat-intel operations: flat-file IPv4/IP-CIDR feeds, strict validation,
  CLI/API feed management, and hot reloads.
- OpenWrt delivery: package scaffold, procd init integration, representative
  cross-builds, SDK package checks, and runtime smoke validation.
- Security operations: NDJSON logs, optional syslog forwarding, `/status`,
  `/stats`, recent detections, nftables diagnostics, and rollback runbooks.

## Architecture And Data Flow

```mermaid
flowchart LR
    A["/proc/net/nf_conntrack"] --> B["collector"]
    B --> C["FlowRecord"]
    C --> D["direction classifier"]
    D --> E["LAN to WAN detectors"]
    D --> F["WAN to LAN detectors"]
    E --> G["dedup filter"]
    F --> G
    G --> H["NDJSON logger"]
    G --> I["recent detections ring"]
    G --> J["optional nftables enforcer"]
    H --> K["stdout / procd logs"]
    H --> L["optional remote syslog"]
    I --> M["localhost API"]
    J --> N["inet set with timeouts"]
```

Design invariants:

- bounded in-memory state
- no packet capture or deep packet inspection
- no persistent database
- detect-only by default
- IPv4-only for current releases
- safe operation on common OpenWrt targets

## Build And Test

```sh
# Native build
make build

# Run tests
make test

# Cross-build representative OpenWrt targets
make cross

# Run release readiness checks
make release-check

# Print build metadata
./bin/serpent-wrt -version
```

Windows workspace note for local development:

```powershell
. .\.env.local.ps1
go test ./...
go vet ./...
git diff --check
```

Supported build targets include `linux/mipsle`, `linux/mips`, `linux/arm`
(v5/v7), `linux/arm64`, `linux/riscv64`, `linux/386`, and `linux/amd64`.

OpenWrt x86/generic images often report `i686`; use `GOARCH=386`, not `amd64`,
for that target.

## Install On OpenWrt

### Package scaffold

The OpenWrt package scaffold lives in [openwrt/serpent-wrt](openwrt/serpent-wrt).
It is intended for a custom feed today. Before a tagged release, validate it in
a real OpenWrt SDK and refresh package source metadata. Public release
packaging should use a final commit or tag source and a fixed source hash rather
than the development `PKG_MIRROR_HASH:=skip` setting.

```sh
# From this repo, with a local OpenWrt SDK/buildroot:
OPENWRT_SDK=/path/to/openwrt-sdk \
  OPENWRT_PACKAGE_OVERWRITE=1 \
  make openwrt-sdk-check
```

### Manual Runtime Deploy

```sh
# OpenWrt x86/generic targets should use the 32-bit x86 build.
make deploy-x86 DEPLOY_HOST=root@<openwrt-host>
```

Manual install path:

```sh
ssh root@router 'mkdir -p /etc/serpent-wrt'

ssh root@router 'cat > /usr/sbin/serpent-wrt && chmod 0755 /usr/sbin/serpent-wrt' \
  < bin/serpent-wrt-openwrt-x86

ssh root@router 'cat > /etc/init.d/serpent-wrt && chmod 0755 /etc/init.d/serpent-wrt' \
  < openwrt/serpent-wrt/files/serpent-wrt.init

ssh root@router 'cat > /etc/serpent-wrt/serpent-wrt.yaml' \
  < openwrt/serpent-wrt/files/serpent-wrt.yaml

ssh root@router 'cat > /etc/serpent-wrt/threat-feed.txt' \
  < openwrt/serpent-wrt/files/threat-feed.txt

ssh root@router '/etc/init.d/serpent-wrt enable && /etc/init.d/serpent-wrt start'
```

## Configuration

See [configs/serpent-wrt.example.yaml](configs/serpent-wrt.example.yaml) for an
annotated configuration.

Minimal shape:

```yaml
poll_interval: 5s
threat_feed_path: /etc/serpent-wrt/threat-feed.txt
profile: home
lease_enrichment: true
dnsmasq_leases_path: /tmp/dhcp.leases

enforcement_enabled: false
block_duration: 1h

lan_cidrs:
  - 192.168.1.0/24

self_ips:
  - 192.168.1.1

nft_table: serpent_wrt
nft_set: blocked_ips

api_enabled: true
api_bind: 127.0.0.1:8080

dedup_window: 5m

suppression_rules:
  - name: trusted scanner
    detectors: [port_scan, ext_scan]
    src_addrs:
      - 192.168.1.50
  - name: external SSH health check
    detectors: [brute_force]
    src_addrs:
      - 198.51.100.10/32
    dst_ports: [22]

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

Important fields:

- `lan_cidrs` tells the daemon which flows are outbound vs inbound.
- `profile` applies detector defaults for common operating modes. `home`
  preserves the baseline defaults, `homelab` and `quiet` raise thresholds for
  noisier networks, and `paranoid` lowers thresholds for more aggressive
  alerting. Explicit detector settings always override profile defaults.
- `lease_enrichment` reads the configured dnsmasq lease file and adds
  `src_hostname`, `src_mac`, `dst_hostname`, and `dst_mac` when a detection IP
  matches a current lease. Missing lease files are treated as empty. `/status`
  reports lightweight lease cache metadata when enrichment is enabled.
- `self_ips` prevents router-originated management, NTP, DHCP, and similar
  traffic from becoming detections.
- `enforcement_enabled` defaults deployments toward detect-only operation.
- `nft_table` and `nft_set` must use conservative nft identifiers: letters,
  numbers, and underscores, with a letter or underscore first.
- `dedup_window` suppresses repeated alerts from the same detector/source/target
  combination.
- `suppression_rules` suppress expected detections before logging, recent-event
  storage, stats-by-type increments, or enforcement. Each rule matches only when
  every configured dimension matches. Supported matchers are `detectors`,
  `src_addrs`, `dst_addrs`, and `dst_ports`; address matchers accept IPv4
  addresses or CIDRs.
- `syslog_target` and `syslog_proto` can forward JSON events to a SIEM.

## Operate The Daemon

Operational runbooks for detect-only rollout, enforcement rollout, rollback,
and firewall reload recovery live in
[docs/openwrt-runbooks.md](docs/openwrt-runbooks.md).

Common OpenWrt commands:

```sh
/etc/init.d/serpent-wrt start
/etc/init.d/serpent-wrt stop
/etc/init.d/serpent-wrt restart
/etc/init.d/serpent-wrt status
/etc/init.d/serpent-wrt configtest
/etc/init.d/serpent-wrt nftcheck
/etc/init.d/serpent-wrt reload_feed
```

Validate the YAML config and referenced threat feed before starting or
reloading:

```sh
serpent-wrt configtest
serpent-wrt --config /etc/serpent-wrt/serpent-wrt.yaml configtest
serpent-wrt configtest --effective
serpent-wrt configtest --effective --format json
```

`configtest` exits non-zero for invalid configuration or feed files. It also
prints advisory warnings for valid but risky settings such as missing
`lan_cidrs`, non-loopback API binds, broad suppression rules, and aggressive
enforcement combinations. Add `--effective` to print the resolved configuration
after defaults and detection profiles have been applied. Use `--format json`
with `--effective` for automation.

Check configured nftables enforcement resources without starting the daemon:

```sh
serpent-wrt nftcheck
serpent-wrt --config /etc/serpent-wrt/serpent-wrt.yaml nftcheck
serpent-wrt nftcheck --format json
```

Hot-reload the threat feed without restarting:

```sh
kill -HUP "$(pidof serpent-wrt)"
```

Manage the configured flat feed file from the CLI:

```sh
serpent-wrt feed list
serpent-wrt feed validate
serpent-wrt feed add 198.51.100.1
serpent-wrt feed remove 198.51.100.1
```

HTTP API, available when `api_enabled: true`:

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/healthz` | GET | Liveness check. |
| `/status` | GET | Feed count/path, enforcement/nft diagnostics, uptime, detector config, build metadata. |
| `/stats` | GET | Flow, detection-by-type/severity/confidence, suppression/dedup, and block counters. |
| `/detections/recent` | GET | Last 100 detections in memory. |
| `/blocked` | GET | Current nftables blocked set contents. |
| `/reload` | POST | Reload threat feed from disk. |
| `/feed` | GET | List normalized local threat feed entries. |
| `/feed` | PUT | Replace the local threat feed with validated entries. |
| `/feed/validate` | POST | Validate one entry or a candidate entry list without writing. |
| `/feed/add` | POST | Add one IPv4/IP-CIDR feed entry and reload if changed. |
| `/feed/remove` | POST | Remove one feed entry and reload if changed. |

Example:

```sh
curl http://127.0.0.1:8080/status
curl -X POST http://127.0.0.1:8080/reload
curl http://127.0.0.1:8080/feed
curl -X POST http://127.0.0.1:8080/feed/add \
  -d '{"entry":"198.51.100.1"}'
curl -X PUT http://127.0.0.1:8080/feed \
  -d '{"entries":["198.51.100.1","203.0.113.0/24"]}'
```

## Events And SIEM Integration

Events are newline-delimited JSON on stdout and can also be forwarded to remote
syslog.

```json
{"time":"2026-01-01T00:00:00Z","level":"info","type":"system","component":"feed","action":"reload","status":"success","feed_count":42,"message":"reloaded threat feed: 42 entries"}
{"time":"2026-01-01T00:00:01Z","level":"warn","type":"detection","detector":"feed_match","severity":"high","confidence":95,"reason":"threat_feed_destination","src_ip":"192.168.1.5","src_hostname":"laptop","src_mac":"aa:bb:cc:dd:ee:ff","dst_ip":"1.2.3.4","dst_port":443,"message":"connection to threat feed entry 1.2.3.4"}
{"time":"2026-01-01T00:00:02Z","level":"warn","type":"enforcement","src_ip":"192.168.1.5","message":"blocked 192.168.1.5 triggered by feed_match"}
```

Wazuh decoder and rules live in [contrib/wazuh](contrib/wazuh). They cover the
detector names used by `serpent-wrt` and are meant to be copied into a Wazuh
deployment alongside syslog forwarding.

## Enforcement Safety

`serpent-wrt` is detect-only unless `enforcement_enabled: true`.

When enforcement is enabled, detections can add IPv4 addresses to a named
nftables set with a timeout. The kernel expires those entries; the daemon also
keeps a bounded local map so it avoids repeatedly adding the same IP.

On OpenWrt, firewall4 (`fw4`) owns the generated firewall ruleset. `serpent-wrt`
uses its own `inet` table and set for dynamic blocks; do not point it at a
fw4-managed table unless you are deliberately integrating custom firewall
includes. After a firewall reload, check `/status`: `check_state` reports
`missing_table` or `missing_set` if fw4 removed the enforcement resources.
Restart `serpent-wrt` before relying on enforcement so the daemon can recreate
its table and set.

Before enabling enforcement on a real router:

1. Confirm `/status` reports nft availability, setup state, and `check_state:
   ready`.
2. Confirm your firewall policy uses the `nft_table` and `nft_set` you expect.
3. Start with a short `block_duration`.
4. Keep console or SSH access available for rollback.
5. Disable enforcement by setting `enforcement_enabled: false` and restarting.

## Threat Feed Format

Plain text, one IPv4 address or CIDR per line. Blank lines and comments are
ignored. IPv6 entries are ignored in current releases.

```text
# example
1.2.3.4
185.220.101.0/24
```

## Project Layout

```text
cmd/serpent-wrt/        CLI entrypoint and build metadata
internal/api/           localhost management API
internal/collector/     conntrack collection and parsing
internal/config/        YAML config loading and validation
internal/detector/      feed, scan, fanout, beacon, and inbound detectors
internal/enforcer/      nftables command integration
internal/events/        NDJSON and syslog event logging
internal/feed/          local threat feed parser
internal/lease/         read-only dnsmasq lease parser/cache
internal/runtime/       detection pipeline, status, stats, and recent events
openwrt/serpent-wrt/    OpenWrt package scaffold
contrib/wazuh/          Wazuh decoder and rules
docs/                   release, roadmap, and operational documentation
```

## Roadmap

The stable MVP is complete. Current planning lives in
[docs/roadmap.md](docs/roadmap.md).

Post-MVP work is focused on package hardening, public validation, and larger
tracks such as optional netlink collection and IPv6 support. Those tracks stay
separate so the router-friendly runtime remains small.

## Limitations

- IPv4 only for current releases.
- Polling instead of netlink events.
- Hostname/MAC enrichment is limited to local dnsmasq lease data.
- No payload inspection by design.
- No persistent database or historical UI.
- Local threat feed only.
- Enforcement currently shells out to `nft`.

## Development

```sh
make release-check
```

Runtime validation is available through:

```sh
make deploy-x86 DEPLOY_HOST=root@<openwrt-host>
```

The OpenWrt smoke test validates `configtest`, feed CLI operations, API
liveness, `/status`, `/stats`, `/reload`, and service reload/restart behavior
against the deployed daemon.

Development flows through `dev`; `main` is the protected release and tag branch.
Release prep changes land in `dev` before the `dev` to `main` release PR. See
[CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
[docs/release.md](docs/release.md) for project workflow, security reporting, and
release steps.

## License

[MIT](LICENSE)
