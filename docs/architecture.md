# Architecture

`serpent-wrt` is built for constrained OpenWrt routers. It favors bounded
metadata analysis over packet capture, payload inspection, or persistent
storage.

## Why Conntrack

Linux keeps connection metadata in `nf_conntrack`. The default collector
reads that table once per poll cycle. Optional netlink mode consumes only
connection-create events through the available `conntrack` CLI.

| Capability | Packet capture | Conntrack metadata |
| --- | --- | --- |
| CPU cost | Per packet | Per poll cycle or new connection event |
| Memory profile | Capture buffers and optional reassembly | Existing kernel flow table |
| Data collected | Payload and headers | Protocol, IPs, ports, state, time |
| Storage pressure | Often paired with PCAP files | None by default |
| Router fit | Heavy on small targets | Lightweight and bounded |
| Enforcement path | Separate integration | Reuses nftables |

## Flow

```mermaid
flowchart TD
    A["nf_conntrack table"] --> B["collector"]
    B --> C["normalized flow records"]
    C --> D["direction classifier"]
    D --> E["outbound detectors"]
    D --> F["inbound detectors"]
    E --> G["suppression rules"]
    F --> G
    G --> H["dedup window"]
    H --> I["event logger"]
    H --> J["stats"]
    H --> K["recent detections ring"]
    H --> L["optional nftables enforcer"]
    I --> M["stdout / procd"]
    I --> N["remote syslog"]
    K --> O["localhost API"]
    L --> P["named nft set"]
```

## Collection Semantics

Snapshot mode is the default. The first snapshot is a baseline.
Later snapshots process each tuple only when it first appears.
A tuple that stays in the table creates no new activity.
A tuple that leaves and later returns counts as new.

The parser stops after 16,385 valid conntrack records. The extra record signals overflow.
The runtime clears its comparison history and pauses new-flow detection.
It resumes only after a complete snapshot with no more than 16,384 records.
That snapshot becomes the new baseline.
The poll interval sets cadence resolution.

`collector: netlink` runs `conntrack -E -e NEW` and records each new event once.
It uses event receipt time for cadence analysis.
The `conntrack` CLI is optional, not a required daemon dependency.
If it is missing, lacks permission, or its event stream ends, serpent-wrt logs the reason and falls back to snapshots.
Snapshot mode then establishes a fresh baseline before it processes new tuples.
`/status` reports the configured and active collector plus any fallback error.

Beacon history stores at most 512 source/destination pairs, 64 timestamps per pair, and 8,192 timestamps total.
When a history limit is full, the collector drops new samples until expiry frees space.
Do not interpret these limits as a total process-memory budget.

## NAT Tuple Semantics

Conntrack snapshots retain the original tuple and the reply tuple.
The original destination stays in `dst_ip` and `dst_port`.
When the reply source differs, `translated_dst_ip` and `translated_dst_port` report the translated destination.
Direction classification uses the translated destination when present.
The `conntrack -E -e NEW` event can lack reply tuple data, so it cannot establish DNAT translation alone.

## Scan Alert Semantics

`port_scan` and `ext_scan` emit one alert when the count in the time window first reaches its threshold.
The alert includes `distinct_port_count` and the sorted `observed_dst_ports` at the threshold.
Expiry rearms the episode when the distinct-port count drops below the threshold.
A later threshold event starts a new alert episode.

Each distinct-value tracker stores at most 1,024 keys, 256 values per key, and 4,096 values total.
When a value limit is full, the tracker rejects new distinct values and preserves values it already stores.
The detector can therefore miss activity after a state limit.
Configuration rejects thresholds above the per-key value limit.

## Enforcement Boundary

When `enforcement_enabled` is true, the daemon validates its nft batch with `nft --check` before it applies the batch.
It creates one `ipv4_addr` set and one `ipv6_addr` set in the configured inet table.
The configured set name is the base name. The daemon adds `_v4` or `_v6` to each set name.

`serpent-wrt nftcheck` parses the set definitions even when enforcement is disabled.
It does not apply a ruleset or prove packet drops.

The daemon does not create a base chain or packet-drop rule.
An operator-managed firewall policy must use the correct family set.
`/blocked`, `blocks_applied`, and nft readiness report set management, not packet drops.
For OpenWrt, a supported fw4 package include is the preferred future integration
instead of ad hoc runtime rules. Until that integration exists, verify the full
ruleset and an actual packet-flow test before you claim enforcement works.

## Detectors

| Detector | Direction | Security outcome |
| --- | --- | --- |
| `feed_match` | LAN to WAN | Internal host contacts a listed IP/CIDR. |
| `feed_match` | WAN to LAN | Known-bad external source reaches an internal host. |
| `beacon` | LAN to WAN | Host contacts the same destination on a regular cadence. |
| `fanout` | LAN to WAN | Host reaches too many distinct external destinations. |
| `port_scan` | LAN to WAN | Internal host probes many ports on one external target. |
| `ext_scan` | WAN to LAN | External source probes many ports on one internal host. |
| `brute_force` | WAN to LAN | External source hits the same service port across many internal hosts. |

Detection events include original and translated destination fields for DNAT snapshots.
Scan events include the threshold count and sorted distinct ports when the detector reaches its threshold.

## Invariants

- Bounded in-memory state.
- Detect-only by default.
- No packet capture or payload inspection.
- No persistent database.
- IPv4 and IPv6 flow metadata are supported.
- Snapshot mode is the default collector and fallback when netlink is unavailable.
