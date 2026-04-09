# Week Plan: Open-Source Polish + SOC Refinement

## Context

serpent-wrt is a lightweight Go threat intelligence daemon for OpenWRT routers. It reads
`/proc/net/nf_conntrack`, classifies flows by direction, runs 6 behavioral detectors, deduplicates
alerts, and emits NDJSON to stdout + UDP syslog to Wazuh. Single static binary, <10MB RAM.

All 6 detectors are working and tested. All 6 Wazuh rules fire. Dedup suppression is working.
Code is on the `dev` branch.

The goal for this week is:
1. Open-source readiness (clean, documented, no hardcoded lab values)
2. SOC setting refinements (configurable dedup, better API, threshold tuning guide)
3. Code quality (readable, testable, no unnecessary complexity)
4. Performance confidence (benchmark under load, verify no memory growth)

---

## Priority Order

### 1. Configurable dedup window (small, high value)

`internal/runtime/runtime.go` has a hardcoded 5-minute dedup window. Make it a config field.

- Add `DedupWindow time.Duration yaml:"dedup_window"` to `Config` (default 5m in `applyDefaults`)
- Pass it through to wherever dedup is applied in runtime
- Add to `configs/serpent-wrt.example.yaml` with comment
- Update `runtime_test.go` to cover non-default window

### 2. Missing tests: direction classification

`runtime.go` `poll()` routes flows to inbound vs outbound detectors. This logic is not directly
tested — only the sub-functions (`isLAN`, `isSelf`, `isUnroutable`) are tested.

Add integration-style tests in `runtime_test.go` using a fake FlowRecord to verify:
- Outbound flow (LAN src, WAN dst) does NOT trigger ext_scan/brute_force
- Inbound flow (WAN src, LAN dst) does NOT trigger fanout/port_scan/beacon
- Unroutable src is dropped (no detector fires)
- Self src is dropped (no detector fires)

These require exposing a `processFlow(r flow.FlowRecord)` method on Engine (currently inlined in
poll), or testing through the stats counter.

### 3. State store benchmark

`internal/state/state.go` is the critical path. Add a benchmark in `state_test.go`:

```go
func BenchmarkTrackerAdd(b *testing.B) {
    t := state.NewTracker(60*time.Second, 1024)
    b.RunParallel(func(pb *testing.PB) {
        i := 0
        for pb.Next() {
            t.Add(fmt.Sprintf("key-%d", i%100), fmt.Sprintf("val-%d", i))
            i++
        }
    })
}
```

Goal: confirm no lock contention under concurrent load representative of a busy router
(~50 flows/sec, 10 goroutines).

### 4. API: blocked IPs endpoint

`/detections/recent` exists but there's no way to query what's currently blocked in nftables.

Add `GET /blocked` to `internal/api/api.go`:
- Shells out `nft list set inet serpent_wrt blocked_ips` and returns parsed JSON
- Same pattern as existing enforcer (nft subprocess is already accepted)
- Keep it simple: `{"blocked": ["1.2.3.4", "5.6.7.8"]}`

### 5. CONTRIBUTING.md (required for open source)

Write `CONTRIBUTING.md` at repo root covering:
- How to run tests (`make test`)
- How to cross-compile for OpenWRT targets (`make cross`)
- How to test against a real router (point to ARCHITECTURE.md for conntrack context)
- Detector addition guide: implement `Check(FlowRecord) *Detection` + `Prune()`, register in runtime
- State: what the sliding window guarantees, why bounded matters on constrained hardware
- What NOT to add (see CONSTRAINTS.md)

### 6. Scrub hardcoded lab values

Before any public release, audit for lab-specific values that would confuse external users:
- Search for `10.20.0`, `192.168.99`, `192.0.2`, `toghouse`, `ecan0` in non-test files
- `configs/serpent-wrt.example.yaml` should use generic RFC 1918 addresses
- Any hardcoded SIEM IPs in docs should use placeholder like `<SIEM-IP>`
- `testdata/threat-feed.txt` is fine (RFC 5737 test addresses)

### 7. Threat feed sourcing guide

Add `docs/threat-feeds.md`:
- What format serpent-wrt expects (one IP or CIDR per line, # comments)
- Free feed sources: Abuse.ch Feodo, CINS Score, Spamhaus DROP, Emerging Threats
- How to download and hot-reload: `curl ... > /etc/serpent-wrt/threat-feed.txt && kill -HUP $(pidof serpent-wrt)`
- Guidance on size: keep under a few thousand entries on 64MB devices

### 8. Wazuh integration as proper contrib/

Move Wazuh decoder and rules from ad-hoc deployment into the repo:
- `contrib/wazuh/decoder-serpent-wrt.xml`
- `contrib/wazuh/rules-serpent-wrt.xml`
- `contrib/wazuh/README.md` — install steps, alert level table, OWASP/ATT&CK mapping

---

## What NOT to do this week

- No new detectors (Phase 6 scope)
- No database or persistence
- No IPv6 (Phase 6)
- No LuCI plugin (Phase 6)
- No netlink event streaming (Phase 6)
- No refactoring that isn't directly needed by the above tasks
- No adding error handling for impossible cases

---

## Continuation Prompt

Use this prompt to pick up the work:

---

**serpent-wrt** is a Go threat intelligence daemon for OpenWRT. Repo is at
`/Users/sintax/Projects/serpent-wrt`, working branch is `dev`. All 6 detectors and tests pass.
Read CLAUDE.md, ARCHITECTURE.md, and CONSTRAINTS.md before touching anything.

Work through `docs/week-plan.md` in priority order. The most important items are:

1. Make the dedup window configurable (`DedupWindow` in config, default 5m)
2. Add direction classification tests in `runtime_test.go` (verify inbound flows don't hit outbound
   detectors and vice versa) — this may require extracting `processFlow` from `poll()`
3. Add `BenchmarkTrackerAdd` parallel benchmark in `internal/state/state_test.go`
4. Add `GET /blocked` to the HTTP API — parse `nft list set` output, return JSON
5. Write `CONTRIBUTING.md`
6. Scrub hardcoded lab IPs/hostnames from non-test, non-demo files
7. Write `docs/threat-feeds.md`
8. Move Wazuh XML files to `contrib/wazuh/` with a README

After each item: run `go test ./...`, commit to `dev` with a focused commit message.
Do not combine unrelated changes in one commit.

Constraints: no new dependencies, no abstractions for one-off operations, no backwards-compat shims,
no docstrings on unchanged functions. Stay within what the task actually requires.

---
