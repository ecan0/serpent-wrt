# Week Plan: Open-Source Polish + SOC Refinement

**serpent-wrt** is a Go threat intelligence daemon for OpenWRT routers. It polls `/proc/net/nf_conntrack`, classifies flows by direction (LAN→WAN vs WAN→LAN), runs 6 behavioral detectors, deduplicates alerts via a sliding window, and emits NDJSON to stdout + UDP syslog to Wazuh. Single static binary, <10MB RAM, no database, no packet capture.

Repo: `/Users/sintax/Projects/serpent-wrt`, branch: `dev`. All 6 detectors pass tests. All 6 Wazuh rules fire in the lab. Read `CLAUDE.md`, `ARCHITECTURE.md`, and `CONSTRAINTS.md` before touching anything.

---

Work through these in order. After each item: `go test ./...`, then commit to `dev` with a focused message. Do not combine unrelated changes in one commit.

---

**1. Configurable dedup window**

The dedup refire window is hardcoded in `internal/runtime/runtime.go`. Add `DedupWindow time.Duration \`yaml:"dedup_window"\`` to `internal/config/config.go` with a default of `5m` in `applyDefaults`. Thread it through to wherever dedup is applied in the runtime. Add it to `configs/serpent-wrt.example.yaml` with a comment. Add a test in `runtime_test.go` that uses a non-default window.

**2. Direction classification tests**

`poll()` in `internal/runtime/runtime.go` routes flows to inbound vs outbound detectors. This logic is untested. Extract it into a `processFlow(r flow.FlowRecord)` method on `Engine`, then add tests in `runtime_test.go` verifying:
- Outbound flow (LAN src, WAN dst) does not increment ext_scan or brute_force state
- Inbound flow (WAN src, LAN dst) does not increment fanout, port_scan, or beacon state
- Unroutable src is dropped before any detector runs
- Self src is dropped before any detector runs

Test through stats counters or by asserting `Check()` returns nil on the appropriate detector after feeding a flow through `processFlow`.

**3. State store benchmark**

Add to `internal/state/state_test.go`:

```go
func BenchmarkTrackerAddParallel(b *testing.B) {
    t := NewTracker(60*time.Second, 1024)
    b.RunParallel(func(pb *testing.PB) {
        i := 0
        for pb.Next() {
            t.Add(fmt.Sprintf("key-%d", i%100), fmt.Sprintf("val-%d", i))
            i++
        }
    })
}
```

Run with `go test -bench=. -benchmem ./internal/state/`. Goal: confirm no lock contention or memory growth under concurrent load.

**4. `GET /blocked` API endpoint**

Add to `internal/api/api.go`. Shell out `nft list set inet <table> <set>`, parse the output, return `{"blocked":["1.2.3.4",...]}`. Use the table/set names from config. Return an empty array (not an error) if enforcement is disabled or the set doesn't exist yet. Follow the same pattern as the existing enforcer subprocess calls.

**5. `CONTRIBUTING.md`**

Write at repo root. Cover: how to run tests, how to cross-compile for OpenWRT targets, how to add a detector (implement `Check(FlowRecord) *Detection` + `Prune()`, register in runtime, add tests), what the sliding window guarantees and why bounded state matters on constrained hardware, and what not to add (point to `CONSTRAINTS.md`). No fluff.

**6. Scrub hardcoded lab values**

Search non-test, non-demo files for `10.20.0`, `192.168.99`, `192.0.2`, `toghouse`. Replace with generic RFC 1918 addresses or `<YOUR-IP>` placeholders. The example config, any docs, and any inline comments are the likely locations. `testdata/` and `test-wrt-iac/` are exempt.

**7. `docs/threat-feeds.md`**

Write a short guide: the feed format serpent-wrt expects, free feed sources (Abuse.ch Feodo Tracker, Spamhaus DROP, CINS Score, Emerging Threats compromised IPs), how to download and hot-reload without restart (`curl ... > /etc/serpent-wrt/threat-feed.txt && kill -HUP $(pidof serpent-wrt)`), and size guidance (keep under a few thousand entries on 64MB devices).

**8. `contrib/wazuh/`**

Move the Wazuh decoder and rules out of ad-hoc deployment and into the repo:
- `contrib/wazuh/decoder-serpent-wrt.xml`
- `contrib/wazuh/rules-serpent-wrt.xml`
- `contrib/wazuh/README.md` — install steps, alert level table with OWASP/ATT&CK mapping for all 6 detection types

---

**Hard constraints:**
- No new dependencies
- No new detectors (Phase 6 scope)
- No abstractions for one-off operations
- No docstrings on functions you didn't change
- No error handling for cases that can't happen
- No database, no persistence, no packet capture
