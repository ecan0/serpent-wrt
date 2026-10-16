# Roadmap

`serpent-wrt` is scoped for OpenWrt routers: low CPU, bounded retained state,
no packet capture, no DPI, no database, and no heavy runtime dependencies.

## Current Status

The current MVP release candidate is not released.
The planned candidate version is `0.5.0-rc.1`.
Its APK package version is `0.5.0_pre1-r1`.
An earlier correctness candidate passed a 19-case IPv4 E2E gate on an
OpenWrt x86/generic test target.
Recovery and live-state checks also passed for that candidate.

That result does not cover the later operator changes.
It also does not cover ARM runtime behavior, IPv6 E2E, or packet drops.
The operator changes still require the current CI gate, an OpenWrt smoke test,
and the final candidate gate.

## Released

### v0.1.0

- Baseline daemon, config load, `configtest`, and build metadata.
- Conntrack flow collection and detectors for feed matches, fanout, port scans,
  beacon-like cadence, inbound scans, and service spray.
- Structured events with severity, confidence, and stable reasons.
- Local feed API operations for list, validate, add, remove, and replace.
- OpenWrt package scaffold, procd init script, and smoke test.

### v0.2.0

- Config-only suppression rules.
- Detection profiles: `home`, `homelab`, `quiet`, and `paranoid`.
- nftables diagnostics in `/status` and `serpent-wrt nftcheck`.
- Read-only dnsmasq lease enrichment.
- Detection counters by type, severity, and confidence bucket.
- `configtest` warnings for risky but valid settings.

## MVP Release Scope

This section fixes the MVP scope. Do not add features to this list during the
release candidate work.

The MVP release retains these features:

- Local IPv4 and IPv6 threat feeds with IP and CIDR entries.
- Strict candidate validation and atomic in-memory feed reload.
- `feed_match`, `fanout`, `port_scan`, `beacon`, `ext_scan`, and
  `brute_force` detectors.
- The `home`, `homelab`, `quiet`, and `paranoid` profiles.
- Suppression rules, event deduplication, severity, confidence, and stable
  reasons.
- Read-only dnsmasq lease enrichment.
- Structured stdout events, optional remote syslog, and the loopback API.
- Event output levels `info`, `warn`, and `error`.
  The filter applies to stdout and remote syslog, not API detections or counters.
- Collector poll status with liveness, poll success, error, `snapshot_overflow`,
  and `new_flow_detection_ready` fields.
- Bounded detector state, a bounded recent-event ring, and bounded dedup state.
- Detect-only operation by default.
- Optional timed nftables set updates for IPv4 and IPv6 addresses.

Timed-set updates do not install a firewall rule.
They do not prove that the firewall dropped a packet.

## MVP Limits

- The collector reads conntrack metadata. It does not capture packets or inspect
  payloads.
- The package contains a comment-only feed example. An operator must acquire
  and maintain threat data.

- Feed validation checks address syntax. It does not verify origin, reputation,
  freshness, ownership, or license terms.
- Feed add and replace operations accept at most 20,000 entries.
  API validate requests accept at most 20,000 input entries.
  Direct file load and the `serpent-wrt feed validate` command do not enforce
  that entry limit.

- The API has no authentication, authorization, or TLS. Keep it on loopback.
- The API retains the latest 100 detections.
- A complete snapshot accepts at most 16,384 conntrack records. Detection pauses
  until a complete baseline follows an overflow.

- Each distinct-value tracker retains at most 1,024 keys, 256 values per key,
  and 4,096 values total.
- Beacon state retains at most 512 pairs, 64 samples per pair, and 8,192 samples
  total.
- The dedup cache retains at most 4,096 entries.
- These caps bound retained runtime state. They do not define a total
  process-memory limit or a safe feed size.

- IPv6 code paths remain in scope, but live IPv6 E2E is not release evidence.
- ARM package builds remain in scope, but ARM runtime behavior is unverified.

## Runtime And Build Classes

APK is the canonical OpenWrt package format for this release.

| Class | MVP status | Required claim boundary |
| --- | --- | --- |
| OpenWrt 25.12 x86/generic, 32-bit x86 | Runtime validation class | The final immutable candidate must pass package smoke and the authorized E2E gate. |
| OpenWrt 25.12 x86/64 | APK build target | A package build does not prove runtime support. |
| OpenWrt 25.12 mediatek/filogic, ARM64 | APK build target | A package build does not prove ARM runtime support. |
| Generic MIPS, MIPSLE, ARMv5, ARMv7, ARM64, RISC-V 64, and x86-64 | Direct cross-build targets | Compilation is the only release claim without target runtime evidence. |

The MVP runtime support claim covers only the x86/generic target class.
It applies to the exact firmware and package versions in the final evidence.

The APK workflow uses pinned OpenWrt 25.12.5 SDKs.
The prior disposable x86/generic gate used OpenWrt 25.12.1 firmware.
Record both versions in evidence. Do not describe them as the same artifact.

## MVP Release Criteria

The release candidate must meet all criteria below:

1. Select one full source commit on `dev`.
   The `CI Gate` result for that commit must pass.

2. Build `0.5.0-rc.1` branch APKs from that exact commit.
   The APK package version must be `0.5.0_pre1-r1`.
   Do not set a release tag or publish release assets during candidate checks.

3. Record the source commit, source tree, candidate version, APK SHA-256, SBOM
   SHA-256, and installed binary SHA-256.

4. Verify APK install, upgrade, restart, detect-only rollout, invalid config,
   feed reload, and rollback on the x86/generic runtime class.
   The upgrade must preserve the installed config and feed.

5. Record the effective config, build metadata, collector readiness, feed count,
   detector output, stdout events, syslog events, and API results.

6. Record bounded resource samples and their method, interval, workload, and
   duration. Compare them with the approved gate limits.

7. Run a fresh, authorized, bounded E2E gate against the same immutable
   candidate. Historical E2E results do not satisfy this criterion.

8. Promote the validated `dev` content through the normal PR into `main`.
   Require `CI Gate` on that PR.

9. Stop before a tag or GitHub Release. Publication requires separate approval.

Any candidate content change invalidates the package and runtime evidence.
Start the candidate gate again with new hashes after such a change.

## Remaining MVP Work

1. Complete the operator semantics for effective log levels and collector poll
   status.
2. Verify the APK install, upgrade, reload, and rollback workflow.
3. Validate the immutable release candidate and preserve its evidence.
4. Use the normal release PR from `dev` into `main`.

Do not add detectors to complete these items.

## Later Work Outside This Release

- A packet-drop policy with explicit fw4 integration, rollback, and packet-path
  evidence.
- Live IPv6 E2E and runtime checks for ARM or other device classes.
- Broader community package work.
- DNS query or dnsmasq log correlation beyond read-only lease enrichment.

Do not require a router-model matrix or a multi-router performance benchmark.

## Not Planned For Near-Term Releases

- Packet capture, PCAP storage, or deep packet inspection.
- Database persistence or a historical dashboard.
- Automatic remote feed synchronization.
- Remote administration.
- ML or anomaly scores.
- A plugin framework.
- Mandatory eBPF, XDP, or netlink.
- LuCI expansion.
