# Roadmap

`serpent-wrt` is scoped for OpenWrt routers: low CPU, bounded memory, no packet
capture, no DPI, no database, and no heavy runtime dependencies.

## Status

The released MVP uses conntrack and local threat-intel checks.
It also has flow heuristics, structured events, optional syslog, a loopback API,
OpenWrt packages, and timed nftables set updates.
The unreleased correctness update changes snapshot semantics, DNAT
classification, nft parser validation, scan alerts, and state limits.
The update is not release validated until the isolated pre-release E2E gate
passes on a candidate build.

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

Prioritize the pre-release E2E gate before additional detectors:

1. **Validate the correctness update.** Build an immutable candidate and run
   the bounded pre-release E2E in a separate test environment. Require route,
   receiver, and conntrack proof before detector results. Verify stdout, API,
   Wazuh manager, and indexed IDs.

2. **Check the installed Wazuh contract.** Confirm rule IDs, original and
   translated destination fields, scan port arrays, and index field types.

3. **Preserve behavior evidence.** Keep negative and boundary cases for
   snapshot collection, netlink events, DNAT, scan episodes, and state overflow.
   Record resource limits by device, build, config, workload, and duration.

4. **Finish operator semantics.** Implement or remove currently ineffective
   configuration such as `log_level`, expose last successful poll/error status,
   and document stable event/API compatibility expectations before 1.0.

5. **Keep packet-drop enforcement separate.** Parser acceptance and set updates
   do not prove packet drops. Plan fw4 integration only as a separate response
   policy with its own rollback and packet-path gate.

Do not require a router-model matrix or multi-router performance benchmark.
Keep broader package-install work conditional on a community release.

Threat-feed provenance, signature/checksum policy, a software bill of materials,
and reproducible release attestations remain release work.

## Post-MVP Tracks

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
