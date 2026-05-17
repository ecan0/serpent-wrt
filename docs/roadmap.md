# Roadmap

`serpent-wrt` is scoped for OpenWrt routers: low CPU, bounded memory, no packet
capture, no DPI, no database, and no heavy runtime dependencies.

## Status

The MVP is complete. It includes conntrack polling, local feed matching, core
detectors, structured logs, optional syslog forwarding, bounded in-memory state,
the localhost API, nftables enforcement, OpenWrt packaging, and runtime smoke
coverage.

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

## Next

### v0.3.0 - operator visibility

Goal: easier rollout and troubleshooting without increasing runtime weight.

- `configtest --effective` human output.
- `configtest --effective --format json`.
- `/stats` counters for dedup-suppressed detections and failed block attempts.
- OpenWrt runbooks for detect-only rollout, enforcement rollout, rollback, and
  firewall reload recovery.
- Release and CI cleanup that keeps private test infrastructure out of public
  release notes.

### v0.3.1 - feed and package polish

Goal: less manual custom-feed releases and local feed operations.

- Feed CLI commands: list, validate, add, and remove.
- OpenWrt SDK/package release checks.
- Release artifact naming and checksum validation.
- Replace `PKG_MIRROR_HASH:=skip` for public release packaging.

## Later

### Optional netlink collector

Prototype conntrack netlink events as an optional collector. Polling must remain
the fallback path, and netlink must not become a mandatory runtime dependency.

### IPv6 support

Add IPv6 parsing, detection, status, config, feed, and enforcement support as a
dedicated release track.

### DNS context

Consider dnsmasq log or query correlation beyond the current read-only lease
enrichment.

### Public runtime CI

Move more package and runtime validation to public runners where practical.

## Not Planned For Near-Term Releases

- Packet capture, PCAP storage, or deep packet inspection.
- Database persistence or a historical dashboard.
- Remote threat-feed sync engines.
- ML or anomaly scoring.
- Mandatory eBPF/XDP, mandatory netlink, or other heavy platform requirements.
- LuCI or Wazuh expansion work.
