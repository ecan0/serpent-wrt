# Contributing to serpent-wrt

## Running tests

```sh
go test ./...
```

All tests must pass before committing. No external services or hardware required.

## Cross-compiling for OpenWRT

serpent-wrt builds as a static binary for common OpenWRT targets:

```sh
make cross
```

This produces binaries under `bin/` for:

| Target | GOOS/GOARCH |
|--------|-------------|
| MIPS (big-endian) | `linux/mips` |
| MIPS (little-endian) | `linux/mipsle` |
| ARMv7 | `linux/arm` (GOARM=7) |
| ARM64 / AArch64 | `linux/arm64` |
| x86-64 | `linux/amd64` |

To build a single target manually:

```sh
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o bin/serpent-wrt-linux-arm64 ./cmd/serpent-wrt
```

## Adding a detector

1. Create `internal/detector/<name>.go` with a struct that holds a `*state.Tracker`.
2. Implement two methods:
   - `Check(flow.FlowRecord) *Detection` — inspect the flow, update state, return a `*Detection` when the threshold is crossed or `nil` otherwise.
   - `Prune()` — call `Tracker.Prune()` to evict expired state.
3. Add a constructor `New<Name>(...)` that initialises the Tracker with the detector's window and max-entries cap.
4. Register the detector in `internal/runtime/runtime.go`:
   - Add the field to `Engine`.
   - Construct it in `NewEngine`.
   - Call `Check()` in `processFlow` under the correct direction (outbound or inbound).
   - Call `Prune()` in `Engine.prune()`.
5. If the detector needs tuning parameters, add a config struct in `internal/config/config.go` and a section in `configs/serpent-wrt.example.yaml`.
6. Add tests in `internal/detector/` — cover threshold triggers, sub-threshold non-triggers, and window expiry.

## Sliding window and bounded state

Every detector's state lives in a `state.Tracker`, which is a key→set map bounded by:

- **Time**: values older than the window are evicted on every `Add()` call.
- **Entries**: when `maxEntries` is reached, the stalest key is evicted.

This guarantees memory stays bounded on devices with as little as 64MB RAM. When writing new detectors or modifying state logic:

- Never use unbounded maps or slices.
- Always set a `maxEntries` cap.
- Call `Prune()` periodically (the runtime does this every N poll cycles).

## What not to add

Read `CONSTRAINTS.md` before proposing changes. In short:

- No packet capture or deep packet inspection.
- No database or persistent event store.
- No heavy dependencies.
- No unbounded memory growth.
- No abstractions for one-off operations.
