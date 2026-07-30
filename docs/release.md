# Release Checklist

This checklist is for project releases and OpenWrt package refreshes.

## Branch Flow

- `dev` is the active integration branch.
- `main` is the protected release branch and tag source.
- Product and IDS work should use `feature/<slice-name>` branches targeting
  `dev`.
- CI, release-process, and repository automation work should use
  `ci/<slice-name>` branches targeting `dev`.
- Release prep branches should start from `dev`, land back in `dev` first, and
  only then promote `dev` to `main`.
- Small CI/package fixes, including fixes for workflows that publish release
  assets from `main`, still target `dev` first. Promote them to `main` through
  the normal release PR path unless the user explicitly declares an emergency
  release hotfix.
- Do not commit or merge directly into `main` or `dev` for routine work.
- If a release-only fix lands on `main`, immediately open a normal merge PR from
  `main` back into `dev` so the release branch does not drift ahead of
  integration. Do not squash that back-sync PR.

## Project Release

1. Confirm `dev` is green in CI and create a release prep branch from `dev`.
2. Update `CHANGELOG.md`, README release status, and OpenWrt package metadata on
   the release prep branch.
   Keep release notes and PR text infrastructure-neutral: do not name private
   hosts, IP addresses, or SSH key paths. Refer to target classes such as
   "OpenWrt x86/generic test target" or public CI runners instead.
3. Open the release prep PR into `dev` and require `CI Gate`.
4. Run the local release check from a clean worktree:

   ```sh
   make release-check
   ```

   This runs Go tests, vet, whitespace checks, OpenWrt package metadata checks,
   and representative OpenWrt target builds.

5. When runtime credentials are available, run the OpenWrt smoke test against a
   representative test target. OpenWrt x86/generic images often report
   i386/i686-compatible CPUs, so use the 32-bit x86 build for that target class:

   ```sh
   make deploy-x86 DEPLOY_HOST=root@<openwrt-host>
   ```

   Use [openwrt-runbooks.md](openwrt-runbooks.md) for the detect-only,
   enforcement, rollback, and firewall reload recovery checks that surround
   runtime validation.

   On trusted `dev` pushes, CI performs the same install and smoke test on the
   `openwrt-x86-64` VM defined by `test-wrt-iac`. The repository variable
   `OPENWRT_X86_64_HOST` supplies its local-network management address and the
   `DEPLOY_KEY` secret supplies SSH authentication. The VM uses the
   x86/generic OpenWrt image, so the 32-bit binary is intentional despite the
   VM's x86-64 host architecture.

6. After the release prep PR merges, open the release PR from `dev` to `main`
   and require `CI Gate`.
7. After the release PR merges, tag the release from `main`:

   ```sh
   git tag -s vX.Y.Z
   git push origin vX.Y.Z
   ```

8. Publish the GitHub Release. The `OpenWrt APK Packages` workflow runs on
   published releases, builds APKs from official OpenWrt 25.12 SDKs, and
   attaches each target's APK, CycloneDX SBOM, and `SHA256SUMS` file. It also
   creates GitHub build-provenance and SBOM attestations for every APK. For an
   existing release, run the workflow manually and set `release_tag`.

   Verify a downloaded package against this repository:

   ```sh
   gh attestation verify serpent-wrt-<version>-<target>.apk \
     --repo ecan0/serpent-wrt
   ```
9. Delete temporary release branches after the tag, release, and package
   artifacts are published.

## OpenWrt Package Refresh

1. Use a tagged release archive plus a fixed `PKG_HASH` for public package
   refreshes. Do not publish package metadata that depends on
   `PKG_MIRROR_HASH:=skip`.
2. Update `openwrt/serpent-wrt/Makefile`:

   - `PKG_SOURCE_DATE`
   - `PKG_SOURCE_VERSION` to the full release tag commit SHA used for runtime
     build metadata
   - `PKG_SOURCE_URL` / `PKG_SOURCE` if the tag naming scheme changes
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

   Set `OPENWRT_FEEDS_UPDATE=1` if the SDK does not already have the packages
   feed installed. The script stages `openwrt/serpent-wrt` into the SDK and
   runs `package/serpent-wrt/check` and `package/serpent-wrt/compile`.

   To produce local APK artifacts from a downloaded SDK instead of an
   existing SDK directory, set `OPENWRT_SDK_URL` and `OPENWRT_SDK_SHA256`, then
   run:

   ```sh
   make openwrt-apk
   ```

   For repeated local or self-hosted runner builds, set
   `OPENWRT_APK_REUSE_WORK_DIR=1` and point `OPENWRT_APK_WORK_DIR` at a
   persistent directory outside this repository. The APK helper defaults its
   work directory under `${TMPDIR:-/tmp}` so OpenWrt's Go bootstrap does not
   inherit the repository module. It records the SDK URL and SHA-256 after the
   verified download, reuses the work directory only when those values match,
   skips feed setup when the packages feed is already installed, and defaults
   package builds to `-j$(nproc)`. Override with `OPENWRT_MAKE_JOBS` or
   `OPENWRT_MAKE_FLAGS` when a runner needs a lower or fixed concurrency level.

5. Install the resulting package on an OpenWrt test target.
6. Run:

   ```sh
   /etc/init.d/serpent-wrt configtest
   /bin/sh /tmp/serpent-wrt-ci/test.sh
   /etc/init.d/serpent-wrt status
   ```

## Upstream OpenWrt Notes

The current package is shaped for a custom feed. If submitting to
`openwrt/packages`, confirm the expected include path for the Go package helper
and follow OpenWrt commit style with `Signed-off-by`.
