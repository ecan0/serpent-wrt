# Roadmap

`serpent-wrt` is scoped for OpenWrt routers: low CPU, bounded memory, no packet
capture, no DPI, no database, and no heavy runtime dependencies.

## Status

The stable MVP is complete. It is a lightweight OpenWrt/Linux IDS and optional
nftables enforcement daemon with conntrack polling, local threat-intel feeds,
core flow-based detectors, structured logs, optional syslog forwarding, bounded
in-memory state, a localhost API, OpenWrt packaging, and runtime smoke coverage.

## Released

### v0.1.0

- Baseline daemon, config loading, `configtest`, and build metadata.
- Conntrack flow collection and detectors for feed matches, fanout, port scans,
  beaconing, external scans, and brute-force patterns.
- Structured detection events with severity, confidence, and stable reasons.
- Local threat-feed API for list, validate, add, remove, and replace.
- OpenWrt package scaffold, procd init script, and smoke test.

### v0.2.0

- Config-only suppression rules.
- Detection profiles: `home`, `homelab`, `quiet`, and `paranoid`.
- nftables diagnostics in `/status` and `serpent-wrt nftcheck`.
- Read-only dnsmasq lease enrichment.
- Detection counters by type, severity, and confidence bucket.
- `configtest` warnings for risky but valid settings.

## Stable MVP Release Track

### v0.3.1 - stable MVP positioning

Goal: present the current tool clearly as a useful cyber/Linux/threat-intel
project without adding more runtime features.

- `configtest --effective` human output.
- `configtest --effective --format json`.
- `/stats` counters for dedup-suppressed detections and failed block attempts.
- OpenWrt runbooks for detect-only rollout, enforcement rollout, rollback, and
  firewall reload recovery.
- Feed CLI commands: list, validate, add, and remove.
- OpenWrt SDK/package release checks.
- README, changelog, and roadmap framing for stable MVP status, detection
  coverage, and engineering highlights.

## Post-MVP Tracks

### Package hardening

- Tagged release archive source and fixed package hash.
- Move more package and runtime validation to public runners where practical.

### Optional netlink collector

Prototype conntrack netlink events as an optional collector. Polling must remain
the fallback path, and netlink must not become a mandatory runtime dependency.

### IPv6 support

Add IPv6 parsing, detection, status, config, feed, and enforcement support as a
dedicated release track.

### DNS context

Consider dnsmasq log or query correlation beyond the current read-only lease
enrichment.

## Not Planned For Near-Term Releases

- Packet capture, PCAP storage, or deep packet inspection.
- Database persistence or a historical dashboard.
- Remote threat-feed sync engines.
- ML or anomaly scoring.
- Mandatory eBPF/XDP, mandatory netlink, or other heavy platform requirements.
- LuCI or Wazuh expansion work.
