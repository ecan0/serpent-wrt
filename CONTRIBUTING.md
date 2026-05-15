# Contributing to serpent-wrt

## Branch workflow

`dev` is the active integration branch. `main` is protected and should only move
through release PRs from `dev`; release tags are cut from `main`.

Use `feature/<slice-name>` branches for product and IDS work. Use
`ci/<slice-name>` branches for CI, release-process, and repository automation
work. Open PRs into `dev` first, including release prep changes such as
changelog, README release status, version defaults, and OpenWrt package
metadata.

After release prep lands in `dev`, open the release PR from `dev` to `main` and
tag the release from the merged `main` commit. If a release-only fix ever lands
on `main`, immediately back-sync `main` into `dev` with a normal merge PR rather
than a squash PR, so `dev` remains the true integration line.

## Running tests

```sh
go test ./...
```

All tests must pass before committing. No external services or hardware required.

## Cross-compiling for OpenWrt

serpent-wrt builds as a static binary for common OpenWrt targets:

```sh
make cross
```

This produces binaries under `bin/` for:

| Target | GOOS/GOARCH |
|--------|-------------|
| MIPS (big-endian) | `linux/mips` |
| MIPS (little-endian) | `linux/mipsle` |
| ARMv5 | `linux/arm` (GOARM=5) |
| ARMv7 | `linux/arm` (GOARM=7) |
| ARM64 / AArch64 | `linux/arm64` |
| RISC-V 64 | `linux/riscv64` |
| x86 | `linux/386` |
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

serpent-wrt is designed for constrained OpenWrt routers. In short:

- No packet capture or deep packet inspection.
- No database or persistent event store.
- No heavy dependencies.
- No unbounded memory growth.
- No abstractions for one-off operations.

For security issues, follow `SECURITY.md` and avoid posting sensitive details in
public issues.
