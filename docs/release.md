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
3. Open the release prep PR into `dev` and require `CI Gate`.
4. Run local tests from a clean worktree:

   ```sh
   go test ./...
   go vet ./...
   git diff --check
   make build-openwrt-targets
   ```

5. Run the OpenWrt runtime smoke test from `mgmt-01` against the lab target.
   The current x86/generic lab image reports `i386_pentium4`, so keep using
   the 32-bit x86 build:

   ```sh
   SSH_KEY_PATH=$HOME/.ssh/toghouse_ops_ed25519 \
     make deploy-x86 DEPLOY_HOST=root@openwrt-x86-test.ecan.pro
   ```

6. After the release prep PR merges, open the release PR from `dev` to `main`
   and require `CI Gate`.
7. After the release PR merges, tag the release from `main`:

   ```sh
   git tag -s vX.Y.Z
   git push origin vX.Y.Z
   ```

8. Delete temporary release branches after the tag and release are published.

## OpenWrt Package Refresh

1. Prefer a tagged release archive plus a fixed hash for public releases. The
   current package Makefile is acceptable for custom-feed development, but
   `PKG_MIRROR_HASH:=skip` should not be used for an upstream or public package
   submission.
2. Update `openwrt/serpent-wrt/Makefile`:

   - `PKG_SOURCE_DATE`
   - `PKG_SOURCE_VERSION` to the full release commit SHA, or switch to a tag
     archive source after the tag exists
   - `PKG_MIRROR_HASH` / `PKG_HASH` to a fixed value for release packaging
   - `PKG_RELEASE`
   - `PKG_MAINTAINER`

3. Run local package scaffold checks:

   ```sh
   go test ./internal/packagecheck
   ```

4. Validate with a real OpenWrt SDK:

   ```sh
   ./scripts/feeds update -a
   ./scripts/feeds install -a
   make package/serpent-wrt/check V=s
   make package/serpent-wrt/compile V=s
   ```

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
