# Week Plan: Open-Source Polish + SOC Refinement

**Status: COMPLETE** — all 8 tasks shipped, CI green, PR #2 open against main.

**serpent-wrt** is a Go threat intelligence daemon for OpenWRT routers. It polls `/proc/net/nf_conntrack`, classifies flows by direction (LAN→WAN vs WAN→LAN), runs 6 behavioral detectors, deduplicates alerts via a sliding window, and emits NDJSON to stdout + optional UDP/TCP syslog. Single static binary, <10MB RAM, no database, no packet capture.

---

## Completed

1. **Configurable dedup window** — `DedupWindow` in config, default 5m, threaded through Engine. Test with 50ms window covering suppression + expiry.
2. **Direction classification tests** — extracted `processFlow`, 4 tests: outbound skips inbound detectors, inbound skips outbound detectors, unroutable dropped, self dropped.
3. **State store benchmark** — `BenchmarkTrackerAddParallel` (~3μs/op, 40B/alloc, no contention).
4. **GET /blocked endpoint** — shells out to `nft list set`, parses elements, returns `{"blocked":[...]}`. Empty array when enforcement disabled.
5. **CONTRIBUTING.md** — tests, cross-compile, adding detectors, bounded state, constraints.
6. **Scrub hardcoded lab values** — one hit fixed (`192.168.99.10` → `10.0.0.10` in config comment).
7. **docs/threat-feeds.md** — format, 5 free sources, SIGHUP reload, cron automation, size guidance.
8. **contrib/wazuh/** — optional decoder XML, rules XML (100200–100207), README with MITRE ATT&CK mapping.

Also fixed: gofmt formatting, Go 1.26.1 → 1.26.2 for 4 stdlib vulns.

---

## Future work (Phase 6+)

These are candidates for a future plan, not current scope:

- **IPv6 support** — extend flow model, direction classifier, and nftables set type
- **Netlink conntrack events** — replace polling with streaming for lower latency
- **dnsmasq log integration** — domain-based detection (DGA, known-bad domains)
- **eBPF/XDP** — on hardware that supports it, for wire-speed enforcement
- **Domain reputation** — extend feed to support domain entries
- **LuCI integration** — web UI for OpenWRT dashboard
- **Additional detectors** — lateral movement (if same-subnet visibility available), DNS tunneling

---

**Hard constraints (always apply):**
- No new dependencies without justification
- No abstractions for one-off operations
- No database, no persistence, no packet capture
- No unbounded maps or slices
- SIEM integration is strictly optional — core stays platform-agnostic
