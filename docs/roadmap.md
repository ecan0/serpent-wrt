# Roadmap

`serpent-wrt` is scoped for OpenWrt routers: low CPU, bounded memory, no packet
capture, no DPI, no database, and no heavy runtime dependencies.

## Status

The MVP feature set is implemented: conntrack polling, local threat-intel
matching, flow heuristics, structured logs, optional syslog, bounded in-memory
state, a loopback API, OpenWrt packaging, timed nftables set management, and
runtime smoke coverage. Production enforcement and beacon accuracy still need
the validation work below.

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

## Recommended Next Iterations

Prioritize correctness evidence over additional detectors:

1. **Complete the firewall contract.** Ship and test an OpenWrt fw4 include (or
   another explicit policy integration) that references the timed set. Extend
   `nftcheck` and router tests to verify the referencing rule and an actual
   blocked flow, not only table/set existence.
2. **Fix connection-observation semantics.** Distinguish new conntrack entries
   from repeated polling snapshots before calling observations a beacon cadence.
   Add packet/flow fixtures and false-positive tests for long-lived UDP,
   retransmitted TCP handshakes, DNS, NTP, and QUIC.
3. **Build a labeled detection corpus.** Keep sanitized conntrack fixtures for
   normal home, homelab, scan, and feed-hit traffic. Report precision-oriented
   regression results and memory/CPU measurements on 64 MB and 128 MB targets.
4. **Harden the intentional self-hosted CI path.** Keep the project-controlled
   runners, but isolate the serpent-wrt instance, minimize host credentials and
   network reachability, gate untrusted contributors, and prefer disposable
   workspaces or ephemeral runner instances where practical.
5. **Finish operator semantics.** Implement or remove currently ineffective
   configuration such as `log_level`, expose last successful poll/error status,
   and document stable event/API compatibility expectations before 1.0.

Threat-feed provenance, signature/checksum policy, a software bill of materials,
and reproducible release attestations should accompany these tracks.

## Post-MVP Tracks

### Package hardening

- Tagged release archive source and fixed package hash.
- Harden the intentional self-hosted build path and add release provenance,
  SBOM, and attestation outputs without moving routine CI off those runners.

### Optional netlink collector

Prototype conntrack netlink events as an optional collector. Polling must remain
the fallback path, and netlink must not become a mandatory runtime dependency.

### IPv6 support

- IPv4 and IPv6 parsing, detection, status, config, feed, suppression, and
  enforcement support are implemented and covered by tests.

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
