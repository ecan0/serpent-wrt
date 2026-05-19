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

6. After the release prep PR merges, open the release PR from `dev` to `main`
   and require `CI Gate`.
7. After the release PR merges, tag the release from `main`:

   ```sh
   git tag -s vX.Y.Z
   git push origin vX.Y.Z
   ```

8. Delete temporary release branches after the tag and release are published.

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
