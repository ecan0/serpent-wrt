# Release Checklist

This checklist is for project releases and OpenWrt package refreshes.

## Branch Flow

- `dev` is the active integration branch.
- `main` is the protected release branch and tag source.
- Product and IDS work must use `feature/<slice-name>` branches that target
  `dev`.
- CI, release-process, and repository automation work must use
  `ci/<slice-name>` branches that target `dev`.
- Release prep branches must start from `dev` and return to `dev` first.
  Promote `dev` to `main` only after that merge.

- Small fixes for CI or packages still target `dev` first.
  This rule also applies to workflows that publish release assets from `main`.
  Use the normal release PR unless the user declares an emergency release hotfix.
- Do not commit or merge directly into `main` or `dev` for routine work.

- If a release-only fix lands on `main`, immediately open a normal merge PR from
  `main` back into `dev` so the release branch does not drift ahead of
  integration. Do not squash that back-sync PR.

## ARM64 Evidence Before v1.0

The private gate provides `scripts/serpent-arm-check.py` for separately authorized household reads.
Do not use the disposable deployment command for a household router.
The read-only contract pins one SSH host, executable SHA-256, and positive CPU count.
The command requires strict host-key checks and an absent or empty evidence directory.
It records architecture, kernel, firmware, memory, package identity, executable hash, and bounded resource samples.

Use one-second sample intervals and a total time limit of 300 seconds.
Retain these ceilings unless the owner approves a revised private contract:

| Metric | Ceiling |
| --- | --- |
| Daemon RSS | 131072 KiB |
| CPU, percent of one core | 50 |
| Open file descriptors | 128 |
| Complete router conntrack table | 1024 entries |
| Local evidence | 8388608 bytes |
| SIEM delivery, in a separately authorized detection case | 30 seconds |

Do not describe RSS as total daemon-and-helper memory.
Do not describe conntrack as fixture-only traffic.
Stop on an excess resource value, missing metric, process identity change, CPU-count change, or transport error.
Do not retry automatically.
If baseline conntrack exceeds the ceiling, request a revised private contract.

Read-only samples alone do not satisfy ARM runtime acceptance.
Require separate evidence for collection, one approved detection, and API/stdout or configured syslog delivery.
Installation, restart, configuration changes, firewall changes, and controlled traffic require additional authority.
Keep host identities, contracts, and raw evidence private.

## Repeatable Performance Comparisons

Run the local feed and tracker benchmarks with the repository Go version:

```sh
go test -run '^$' -bench 'Benchmark(FeedContains|TrackerAddParallel)' -benchmem -count=5 ./internal/feed ./internal/state
```

`BenchmarkFeedContains` uses feeds with 1000, 10000, and 20000 entries.
Each feed has equal IPv4/IPv6 exact-address and CIDR populations.
Each size covers exact hits, misses, and CIDR hits for both address families.
CIDR hits use the last prefix of each family.
The benchmark creates files and parses addresses outside the timed loop.
It reports allocations and retains the lookup result.

`BenchmarkTrackerAddParallel` includes its `fmt.Sprintf` allocations.
Do not describe those allocations as daemon-only cost.
Local benchmark results do not establish device performance.
Do not change the matcher or detector limits from benchmark assumptions.

For device comparisons, retain the feed hash, workload, Go version, firmware, sample interval, and duration.
Use identical values before and after a proposed change.
Keep ARM, IPv4, and IPv6 results separate.
Retain the approved resource ceilings.
An optimization needs a measured problem, unchanged detection results, and a repeated comparison before merge.

## Separate Live IPv6 Evidence

The private gate retains schema version 1 for historical IPv4 contracts.
Schema version 2 accepts separate IPv4 or IPv6 contracts without an input claim of success.
Do not rewrite historical approved inputs or evidence.

For IPv6, require three distinct `/64` networks under `2001:db8::/32` on isolated lab links.
Retain the existing management and SIEM transport addresses.
Do not add NAT66, a default IPv6 route, or household traffic.
Validate topology, address families, and allowlists before device access.
The worker uses IPv6-only sockets and checks each send interval against the explicit isolated route.

Require IPv6 feed IP/CIDR matches, LAN/self classification, suppression, deduplication, and all six detectors.
Retain existing below-threshold, threshold, expiry/rearm, benign, and invalid-feed semantics.
Keep the IPv4 DNAT case IPv4-only.
Compare original/reply tuples and run/case markers across conntrack, API, stdout, and configured SIEM output.
Compare IPv6 addresses by parsed value.
Collect separate resource samples.

Local validators and loopback socket checks do not establish live IPv6 acceptance.
Require reviewed private candidate inputs, an immutable artifact, a recovery snapshot, and separate disposable-lab authority.
Stop on the first unexpected route, resource excess, missing marker, or recovery failure.
Do not retry automatically.

## Managed-Drop Candidate Gate

Keep packet drops disabled until a separately authorized disposable OpenWrt run passes the packet-path checks.
Local namespace checks establish kernel transaction and cache behavior only.
They do not establish fw4 reload, procd, firmware, or forwarded-packet acceptance.

Require receiver delivery in detect-only mode before activation.
After an approved detection, require receiver non-delivery and increased drop-rule counters for a new flow from the selected source.
Require delivery from an unlisted control source and unchanged router-bound management access.
Cover IPv4, IPv6, timeout expiry, firewall reload, service restart, policy disable, and rollback.
Check offloading refusal and foreign-chain conflicts without global changes.

Record the exact source, package, firmware, configuration, tuples, destinations, duration, and recovery procedure before authority.
Do not authorize household drops under the ARM read-only contract.
Stop on failed activation or recovery.
Keep the prior rules intact.

The development recipe retains its published source tag and literal archive hash.
Do not publish its new lifecycle files as an old daemon version.
After the next milestone tag exists, calculate its actual archive hash.
Update the feed recipe in a separate commit.
Build candidate artifacts from the selected source commit through the existing explicit source/version override.
Do not put an archive's own hash inside that archive.

## Authenticated Management Development

The daemon source now implements the fixed rpcd executable-plugin command.
It validates configuration, compares revision tokens, writes the YAML file atomically, and restores prior bytes after a failed apply.
It restarts only a previously running service.
The RPC feed methods page list results and use fixed loopback API routes for a running daemon.
They use local feed-file helpers when the daemon is stopped.

The fixed rpcd wrapper and method-scoped ACL source are in
`openwrt/luci-app-serpent/root`.
They are not installed by the daemon recipe.
The LuCI package, menu, and browser views are not implemented yet.
Do not claim browser management access until PR8 installs the wrapper and ACL and G passes on an authorized LuCI target.
Do not increase rpcd's global input limit.

## MVP Candidate Gate

This gate validates one immutable candidate from green `dev`.
It ends after the normal release PR into `main`.
Do not create a tag or publish a GitHub Release without separate approval.
Do not mark a step complete without its recorded evidence.

### 1. Select The Source

1. Merge release preparation into `dev` through a PR.
2. Require a successful `CI Gate` for the new `dev` commit.
3. Use a clean worktree at that exact commit.
4. Run the local release check:

   ```sh
   make release-check
   ```

   This runs Go tests, vet, whitespace checks, package helper safety checks,
   and representative OpenWrt cross-builds.
5. Record the full commit, tree, version, and CI run URL:

   ```sh
   git rev-parse HEAD
   git rev-parse HEAD^{tree}
   git show -s --format='%H %T %cI'
   ```

The candidate must not change after this point.
Any content change requires a new candidate, new hashes, and a new runtime gate.

### 2. Build Branch APKs

APK is the canonical package format for this gate.
The MVP candidate version is `0.5.0-rc.1`.
The APK package version is `0.5.0_pre1-r1`.

Dispatch `OpenWrt APK Packages` from `dev` or `main`.
Set `ref` to the full candidate commit.
Use build mode:

```sh
source_commit=<full-dev-commit>
candidate_version=0.5.0-rc.1
gh workflow run openwrt-apk.yml --ref dev \
  -f mode=build \
  -f ref="$source_commit" \
  -f package_version="$candidate_version" \
  -f candidate_channel=testing
```

Record the workflow run ID, the workflow ref commit, and the candidate commit.
The workflow takes its trusted helpers from the workflow ref.
It records that helper revision separately from the package source.
It pins the package source to the commit in `ref`.

`package_version` is required for build mode.
There is no default placeholder version.
The workflow uses pinned OpenWrt 25.12.5 SDKs.
It creates APKs for x86/64, x86/generic, and mediatek/filogic.
These package builds do not prove runtime support.
An incomplete target set fails the candidate.

The build jobs produce unsigned canonical APKs.
The signing job runs in the protected `serpent-release` environment.
It signs the APKs and each `packages.adb`, then publishes the public key.
A missing signing secret fails before any signed candidate exists.

Download the single verified candidate artifact:

```sh
gh run download <run-id> --name serpent-verified-candidate --dir candidate
```

`candidate.json` records the source commit and tree, helper and workflow
revisions, SDK and feed pins, package hashes, SBOM hashes, and the signing-key
fingerprint.
The per-target `serpent-apk-input-<slug>` artifacts remain unsigned build
inputs and are not the release path.

Release asset names use the target suffix:
`serpent-wrt-<apk-version>-r<release>-<slug>.apk`, with a matching
`serpent-wrt-<slug>.cdx.json` and `SHA256SUMS-<slug>`.
The build SBOM name stays `serpent-wrt-<slug>.cdx.json`.

Verify each APK provenance attestation:

```sh
gh attestation verify serpent-wrt-0.5.0_pre1-r1-x86-generic.apk \
  --repo ecan0/serpent-wrt
```

Repeat the command for each target APK.
Record the APK and CycloneDX SBOM SHA-256 values for all targets.
Do not attach candidate artifacts to a GitHub Release.


### 3. Verify The Package Workflow

Use an authorized, disposable OpenWrt x86/generic target.
Keep strict SSH host verification active for every device command.
Do not use a private host name, address, key path, or topology name in public
evidence.

Run these package cases:

1. Install the candidate APK on a clean target.
2. Start in detect-only mode.
3. Replace the config with an invalid candidate and confirm safe rejection.
4. Reload a valid IPv4 and IPv6 local feed.
5. Upgrade from the prior package to the candidate.
6. Confirm that the package preserves the installed config and feed.
7. Restart the service and confirm successful collection.
8. Roll back to the prior package and config.
9. Confirm service recovery after rollback.

Transfer each candidate APK to the target and install it from the trusted
repository, or from the local file with `--allow-untrusted` when the candidate
was not published to a repository.
Do not run `apk upgrade` on the target. A mass upgrade changes unrelated
packages and invalidates the runtime evidence.
Keep the prior APK file on the target until the case set completes.

The package declares these files as conffiles:

```text
/etc/serpent-wrt/serpent-wrt.yaml
/etc/serpent-wrt/threat-feed.txt
```

Record file hashes and marker values before and after the upgrade.
Record any `.apk-new` or equivalent package-manager result.
Do not infer preservation only from the package recipe.

Run these checks on the installed candidate:

```sh
/usr/sbin/serpent-wrt -version
apk list --installed serpent-wrt
sha256sum /usr/sbin/serpent-wrt
/etc/init.d/serpent-wrt configtest
serpent-wrt --config /etc/serpent-wrt/serpent-wrt.yaml \
  configtest --effective --format json
/etc/init.d/serpent-wrt status
curl -s http://127.0.0.1:8080/healthz
curl -s http://127.0.0.1:8080/status
curl -s http://127.0.0.1:8080/stats
```

On apk3, `apk info -v serpent-wrt` does not report the installed version
reliably. Use `apk list --installed serpent-wrt` instead.

The binary must report `0.5.0-rc.1` and the candidate source commit.
The package manager must report `0.5.0_pre1-r1`.
The installed binary SHA-256 must remain the same for all candidate runs.

### 4. Record Effective State And Resources

Preserve the effective configuration JSON and `/status` output.
Preserve the collector fields below. Apply the absence rules in [the API contract](api.md).

- `configured`
- `active`
- `fallback_error`
- `last_successful_poll`
- `last_poll_error`
- `snapshot_overflow`
- `new_flow_detection_ready`

It must also include the feed count, enforcement state, detector thresholds,
and build metadata.
Redact private network values before any public report.

Record resource data for the candidate under the approved workload:

- RSS samples and their maximum for the daemon. Record `VmHWM` separately when available.
- CPU sample method, interval, duration, and maximum value.
- Open file descriptor count.
- Conntrack table count. Distinguish this count from the parsed snapshot size.
- Feed entry count.
- Evidence size.

On the target, use these commands for the point-in-time process record:

```sh
pid="$(pidof serpent-wrt)"
grep -E '^(VmRSS|VmHWM|Threads):' "/proc/$pid/status"
ls -1 "/proc/$pid/fd" | wc -l
wc -l /proc/net/nf_conntrack
```

State the sampler definitions with the results.
Do not describe a gate ceiling as measured use or a steady-state target.
Do not describe daemon RSS as helper-process RSS.

### 5. Run The Final E2E Gate

Use the one authorized final gate for the immutable candidate.
Use a bounded run, a fixed case set, a fixed candidate APK, and an approved
recovery plan.
Do not repeat the final gate or use an unbounded repair loop.

The final gate must confirm these outcomes:

- The exact candidate APK and installed binary hashes match the evidence record.
- Detect-only remains the default.
- IPv4 feed matches and each retained heuristic produce the expected events.
- Negative, dedup, boundary, reload, and restart cases pass.
- Stdout, remote syslog, and API records preserve the expected event fields.
- Collector status separates liveness, poll success, overflow, and readiness.
- Resource observations remain within the approved gate limits.
- Recovery and rollback complete.

Retain focused behavioral test results for suppression and the log-output filter.
Do not claim that the fixed live case set covers behavior that it does not exercise.

The historical 19-case IPv4 result applies only to its earlier candidate.
It does not validate operator changes or this final candidate.
ARM runtime behavior and IPv6 E2E remain unverified unless this gate adds that
evidence.

Keep private contracts, topology, and raw lab evidence outside this repository.
Use only generic runtime classes and redacted results in public release notes.

### 6. Promote Without Publication

1. Confirm that the candidate commit, tree, package hashes, and evidence match.
2. Open the normal release PR from `dev` into `main`.
3. Require `CI Gate`.
4. Do not change candidate content in the release PR.
5. If the merge creates a new commit, confirm that its tree matches the
   validated source tree.
6. Stop after the PR merges.

Do not tag or publish a release in this candidate-validation stage.

## Release Trust Claims

Run the local signing suite against an extracted pinned SDK.
Without `SERPENT_TEST_SDK` that suite skips, and a skip is not a pass:

```sh
SERPENT_TEST_SDK=/path/to/openwrt-sdk-25.12.5 \
  python3 -m unittest discover -s scripts -p 'test_apk_repository.py' -v
```

The workflow creates a CycloneDX SBOM and `SHA256SUMS` for each target.
It also creates GitHub provenance and SBOM attestations for each APK.
The checksum file itself is not a detached signature.

A verified provenance attestation links APK bytes to a GitHub workflow run.
It does not prove runtime behavior, source safety, or reproducible output.
An SBOM attestation links the APK to the supplied component inventory.
It does not prove that the inventory is complete for every SDK component.

The workflow pins SDK archives by SHA-256 and pins the OpenWrt packages feed by
commit.
Those pins define build inputs.
They do not establish reproducible builds.

Do not claim reproducibility until an independent rebuild produces identical APK and binary hashes from the recorded inputs.

The workflow signs each APK and each `packages.adb` with one ECDSA P-256
release key from the protected `serpent-release` environment.
It publishes only `serpent-wrt.pem` and that key's SHA-256 fingerprint.
The private key never enters source control, caches, artifacts, or logs.
`apk --keys-dir <dir> verify <packages.adb>` must succeed with that public key
and fail without it.
That accepted-and-rejected pair is the repository trust evidence.

A package-level `apk verify` result is not a trust gate for these APKs.
Target install, upgrade, and rollback from the trusted repository remain the
required lifecycle evidence.
Use `--allow-untrusted` only for a local file that the repository key did not sign.
Trust for a local file comes from the recorded APK SHA-256 values and the
provenance attestation, not from a signature.
State the SBOM and provenance attestations as build-file evidence only.

## Publication After Separate Approval

After approval, tag the unchanged release content from `main`:

```sh
git tag -s vX.Y.Z
git push origin vX.Y.Z
```

Publishing the GitHub Release does not build APKs.
The Release body must select one verified candidate:

```text
Serpent-Candidate-Run: <numeric workflow run id>
Serpent-Candidate-Digest: sha256:<64 lowercase hex>
Serpent-Channel: testing
```

The publication job downloads that exact `serpent-verified-candidate` artifact
by digest, requires the release tag to resolve to the candidate source commit,
and uploads only missing assets.
An existing asset with different bytes fails the run instead of overwriting it.
It deploys the complete Pages artifact once.

A manual `mode=promote` dispatch performs the same digest-bound promotion for an
existing Release.
Promote a `stable` channel only with explicit release authority and a stable
index that the candidate already signed.
Record the published APK hashes and verify their attestations.
A rebuild can change the bytes.
If the hashes differ, require new runtime evidence before a release-validation claim.
Delete temporary release branches after publication completes.

## OpenWrt Package Refresh

1. Use a tagged release archive plus a fixed `PKG_HASH` for public package
   refreshes. Do not publish package metadata that depends on
   `PKG_MIRROR_HASH:=skip`.
2. Update `openwrt/serpent-wrt/Makefile`:

   - `PKG_SOURCE_DATE`
   - `PKG_SOURCE_VERSION` to the full release tag commit SHA used for runtime
     build metadata
   - `PKG_SOURCE_URL` / `PKG_SOURCE` if the tag names change
   - `PKG_HASH` to the SHA-256 for the release archive
   - `PKG_RELEASE`
   - `PKG_MAINTAINER`

3. Run local package scaffold checks:

   ```sh
   go test ./internal/packagecheck
   ```

4. Validate with a real OpenWrt SDK:

   ```sh
   OPENWRT_SDK=/path/to/openwrt-sdk \
     OPENWRT_PACKAGE_OVERWRITE=1 \
     make openwrt-sdk-check
   ```

   Set `OPENWRT_FEEDS_UPDATE=1` if the SDK lacks the packages feed.
   The script stages `openwrt/serpent-wrt` into the SDK.
   It runs `package/serpent-wrt/check` and `package/serpent-wrt/compile`.

   To produce local APK artifacts from a downloaded SDK, set `OPENWRT_SDK_URL` and `OPENWRT_SDK_SHA256`.
   Then run:

   ```sh
   make openwrt-apk
   ```

   For repeated local or self-hosted builds, set `OPENWRT_APK_REUSE_WORK_DIR=1`.
   Set `OPENWRT_APK_WORK_DIR` to a persistent directory outside this repository.
   The default work directory is under `${TMPDIR:-/tmp}`.
   Thus, the OpenWrt Go bootstrap does not inherit the repository module.

   The helper records the SDK URL and SHA-256 after download verification.
   It reuses the work directory only when those values match.
   It skips feed setup when the SDK has the packages feed.
   Package builds default to `-j$(nproc)`.
   Use `OPENWRT_MAKE_JOBS` or `OPENWRT_MAKE_FLAGS` to set another concurrency limit.

   The workflow cache key includes the runner platform, target, SDK checksum,
   packages-feed commit, build helpers, and package recipe.
   The workflow restores only an exact key.
   A key change requires one cold build for each target.
   The workflow saves the cache only after package compilation succeeds.

5. Install the package on an OpenWrt test target.
6. Run:

   ```sh
   /etc/init.d/serpent-wrt configtest
   /bin/sh /tmp/serpent-wrt-ci/test.sh
   /etc/init.d/serpent-wrt status
   ```

   `scripts/openwrt-runtime-test.sh` copies `openwrt/serpent-wrt/test.sh`
   to `/tmp/serpent-wrt-ci/test.sh` on the target. If you install the package
   without that helper, copy the test script to that path first.

## Upstream OpenWrt Notes

Keep the custom release recipe and the community recipe in this repository.
The custom recipe is in `openwrt/serpent-wrt`.
The community recipe is in `contrib/openwrt-packages/net/serpent-wrt`.
It pins the published v0.5.0 archive and its literal source hash.
The upstream `openwrt/packages` repository expects it at `net/serpent-wrt`.
Use a temporary export or patch for submission. Keep this repository as the source of truth.
Keep `luci-app-serpent` in the custom feed for v1.0.
Any later LuCI submission belongs in `openwrt/luci/applications/luci-app-serpent`, with `../../luci.mk`.

Use a completed milestone tag and the SHA-256 of its actual archive bytes.
Keep that archive's own hash outside the archive.
Update the custom recipe in the next feed commit after the tag exists.
Set package release 1 for a new source version.
Increment it for package-only changes.
Preserve `+nftables-json +kmod-nf-conntrack` and the managed-drop dependency `+firewall4`.

The initial upstream commit subject is `serpent-wrt: add package`.
Require the maintainer's real name and email for matching author and `Signed-off-by`.
The existing maintainer handle is not a DCO identity.
Do not create a signed-off commit or public submission without that identity and separate submission authority.

For submission, export the in-repo community recipe to `net/serpent-wrt` in a temporary `openwrt/packages` worktree.
Require source download/hash validation and actual package creation:

```sh
./scripts/feeds update packages
./scripts/feeds install serpent-wrt
make package/serpent-wrt/download V=s
make package/serpent-wrt/compile V=s
```

Use a fresh snapshot SDK for the upstream layout.
Keep third-party builds on the pinned 25.12 SDKs.
Record these as separate build results.
The completed local layout checks use released v0.5.0 sources, not current unreleased firewall changes.
Do not reuse them as a new candidate's package or runtime evidence.
Upstream review and acceptance do not block the third-party release.
