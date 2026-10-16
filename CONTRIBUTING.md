# Contributing to serpent-wrt

## Branch workflow

`dev` is the active integration branch.
`main` is protected. Only release PRs from `dev` can update it.
Cut release tags from the merged `main` commit.

Use `feature/<slice-name>` branches for product and IDS work.
Use `ci/<slice-name>` branches for CI, release-process, and repository automation.
Open PRs into `dev` first. This includes release prep changes such as changelog, README release status, version defaults, and package metadata.

Send small CI or package fixes that unblock release assets to `dev` first.
This rule also applies when the affected workflow runs from `main`.
Only a user-approved emergency release hotfix can bypass this path.

After release prep lands in `dev`, open a release PR from `dev` to `main`.
Tag the release from the merged `main` commit.
If a release-only fix lands on `main`, open a normal merge PR from `main` to `dev`.
Do not use a squash PR for this back-sync.
Keep `dev` as the integration branch.

## Running tests

```sh
go test ./...
```

All tests must pass before committing. No external services or hardware required.

For release prep or package metadata changes, run the local release check:

```sh
make release-check
```

This runs tests, vet, whitespace checks, package helper safety checks, and
representative OpenWrt target builds.

All pull requests use GitHub-hosted runners, including same-repository PRs.
Only trusted pushes to `dev` use the repository's self-hosted runner.
Private runner configuration remains outside this repository.

`CI Gate` requires successful change detection and workflow/shell checks on every run.
Runtime changes also require native and cross-builds, CLI smoke checks, race tests,
32-bit x86 tests, vet, lint, and vulnerability checks.
Documentation-only changes skip the runtime jobs, not workflow validation.
Failed, canceled, or missing required jobs fail the gate.
Workflow shell steps use Bash with fail-fast pipeline handling.

Go jobs cache modules and compiled packages through `setup-go`.
Actions use full commit SHA pins with release comments.
Dependabot targets `dev` for weekly action updates after its configuration reaches the default branch.
The APK workflow remains separate from the PR gate because SDK builds take longer.
Do not copy hostnames, credentials, tokens, or private network details into public files.

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

1. Use `state.Tracker` for rolling distinct-value windows. Bound all other retained values and samples explicitly.
2. Implement `Check(flow.FlowRecord) *Detection` and `Prune()`. Return one detection at the contract's threshold or episode transition.
3. Set a window and entry cap in the constructor. The tracker also enforces its per-key and total value caps.
4. Register the detector in `internal/runtime/runtime.go`:
   - Add the field to `Engine`.
   - Construct it in `NewEngine`.
   - Call `Check()` in `processFlow` under the correct direction (outbound or inbound).
   - Call `Prune()` in `Engine.prune()`.
5. If the detector needs tuning parameters, add a config struct in `internal/config/config.go` and a section in `configs/serpent-wrt.example.yaml`.
6. Add tests in `internal/detector/` — cover threshold triggers, sub-threshold non-triggers, and window expiry.

## Sliding window and bounded state

Each `state.Tracker` has these limits:

- 1,024 keys.
- 256 values per key.
- 4,096 values total.

When a value limit is full, the tracker rejects new distinct values and keeps current values.
Each beacon detector retains at most 512 pairs, 64 samples per pair, and 8,192 samples total.
Each polling snapshot can contain at most 16,384 tuples for new-flow detection.
When a snapshot exceeds that limit, the runtime pauses new-flow detection until it can build a complete baseline.
These limits bound tracker and beacon state, not total process memory.

Call `Prune()` periodically.
Do not claim a router memory budget from these caps alone.

## What not to add

serpent-wrt is designed for constrained OpenWrt routers. In short:

- No packet capture or deep packet inspection.
- No database or persistent event store.
- No heavy dependencies.
- No unbounded memory growth.
- No abstractions for one-off operations.

For security issues, follow `SECURITY.md` and avoid posting sensitive details in
public issues.
