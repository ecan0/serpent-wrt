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

Dispatch `OpenWrt APK Packages` from `dev`.
Set `ref` to the full candidate commit.
Leave `release_tag` empty:

```sh
source_commit=<full-dev-commit>
candidate_version=0.5.0-rc.1
gh workflow run openwrt-apk.yml --ref dev \
  -f ref="$source_commit" \
  -f package_version="$candidate_version"
```

Record the workflow run ID, the workflow ref commit, and the candidate commit.
The workflow takes its build helpers from the workflow ref.
It pins the package source to the commit in `ref`.

Set `package_version` explicitly.
An empty value creates `0.4.0-e2e.<run-number>`, not the candidate version.
The workflow uses pinned OpenWrt 25.12.5 SDKs.
It creates APKs for x86/64, x86/generic, and mediatek/filogic.
These package builds do not prove runtime support.

Download the workflow artifacts without a release tag:

```sh
gh run download <run-id> --dir candidate-artifacts
```

For each target, verify the workflow checksum file:

```sh
cd candidate-artifacts/serpent-wrt-apk-x86-generic
sha256sum -c SHA256SUMS-x86-generic
```

Verify each APK provenance attestation.
The artifact name is `serpent-wrt-<apk-version>-r<release>-<slug>.apk`.
For this candidate the x86/generic name is
`serpent-wrt-0.5.0_pre1-r1-x86-generic.apk`:

```sh
gh attestation verify serpent-wrt-0.5.0_pre1-r1-x86-generic.apk \
  --repo ecan0/serpent-wrt
```

Repeat the command for each target APK.
Record the APK and CycloneDX SBOM SHA-256 values for all targets.
The workflow writes the SBOM as `serpent-wrt-<slug>.cdx.json`.
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

Transfer each APK to the target and install it with `apk add` from the local
file path. The candidate APK has no trusted release signature, so the install
command needs `--allow-untrusted`.
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
Do not claim an APK signature trust chain unless release evidence verifies that
signature and its trusted key.

The workflow has no APK signature step.
It does not create a release signature for the APK.
Do not describe an install as signature verification.
The target install uses `apk add --allow-untrusted` for the local APK, so OpenWrt
does not check a package signature.
Trust for this release comes from the recorded APK SHA-256 values, the provenance
attestation, and the release record.
State the SBOM and provenance attestations as build-file evidence only.

## Publication After Separate Approval

After approval, tag the unchanged release content from `main`:

```sh
git tag -s vX.Y.Z
git push origin vX.Y.Z
```

Publish the GitHub Release only after tag approval.
The release trigger builds APKs and attaches each APK, SBOM, and checksum file.
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

For an `openwrt/packages` submission, confirm the expected include path for the Go package helper.
Follow the OpenWrt commit style with `Signed-off-by`.
