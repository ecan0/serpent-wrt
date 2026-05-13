# Release Checklist

This checklist is for project releases and OpenWrt package refreshes.

## Project Release

1. Confirm `main` is green in CI.
2. Run local tests:

   ```sh
   go test ./...
   go vet ./...
   make build-openwrt-targets
   ```

3. Run the OpenWrt runtime smoke test against the lab target:

   ```sh
   make deploy-x86 DEPLOY_HOST=root@openwrt-x86-64
   ```

4. Update `CHANGELOG.md`.
5. Tag the release:

   ```sh
   git tag -s vX.Y.Z
   git push origin vX.Y.Z
   ```

## OpenWrt Package Refresh

1. Prefer a tagged release archive plus a fixed hash for public releases. The
   current package Makefile is acceptable for custom-feed development, but
   `PKG_MIRROR_HASH:=skip` should not be used for a public package submission.
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
