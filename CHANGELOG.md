# Changelog

All notable changes to serpent-wrt will be documented in this file.

This project follows semantic versioning for tagged releases.

## Unreleased

### Changed

- OpenWrt package scaffold now uses a tagged release archive with a fixed
  SHA-256 source hash instead of `PKG_MIRROR_HASH:=skip`.
- Added a GitHub Actions workflow for building OpenWrt APK artifacts from
  SHA-verified official 25.12 SDK downloads and attaching them to published
  releases.
- OpenWrt package validation now prepares SDK `.config` noninteractively and
  depends on `nftables-json`, matching the stable package name.
- OpenWrt package CI now targets OpenWrt 25.12.4 SDKs, keeps verbose SDK make
  output opt-in with `OPENWRT_MAKE_FLAGS`, and preserves the package build patch
  for the Go 1.26.2 toolchain provided by the 25.12 packages feed.
- CI now runs the pinned `govulncheck` release with the Go version from
  `go.mod`. The active module and CI toolchain are Go 1.26.5 for current
  standard-library security fixes; OpenWrt package builds retain the
  release-tarball patch for the 25.12 package toolchain.
- CI maintenance refreshed GitHub Actions checkout/cache majors and the pinned
  `golangci-lint` and `govulncheck` tool releases.
- HTTP routes now enforce documented methods, and feed mutation requests reject
  trailing JSON values.

## v0.3.1 - 2026-05-17

### Added

- Stable MVP README and roadmap positioning for the current OpenWrt/Linux IDS,
  threat-intel, and optional nftables enforcement scope.
- Detection coverage framing for threat-intel hits, reconnaissance/discovery,
  C2-like beaconing, scanning, and brute-force behavior using conntrack
  metadata only.
- Engineering highlights for constrained Linux design, detection engineering,
  OpenWrt packaging, structured security events, and operational validation.
- `serpent-wrt configtest --effective` for printing the resolved configuration
  after defaults and detection profiles have been applied.
- JSON output for `serpent-wrt configtest --effective --format json`.
- `/stats` counters for dedup-suppressed detections and failed block attempts.
- Feed CLI commands for listing, validating, adding, and removing flat-file
  IPv4/IP-CIDR threat-feed entries.
- OpenWrt SDK package check helper for staging the package scaffold into an SDK
  and running package check/compile targets when available.

### Changed

- Roadmap language now treats artifact checksums, fixed package hashes, IPv6,
  netlink, DNS context, and public runtime CI as post-MVP work while keeping
  LuCI, Wazuh, and feed sync out of near-term scope.
- OpenWrt smoke coverage now exercises feed CLI validation and add/list/remove
  operations after package install.

## v0.2.0 - 2026-05-14

### Added

- Config-only suppression rules for expected scanner, monitor, or noisy service
  detections, with a `/stats` counter for suppressed detections.
- `/status` nft diagnostics for missing enforcement table/set state, including
  firewall-reload hints when resources disappear after setup.
- Detection profiles (`home`, `homelab`, `quiet`, `paranoid`) for practical
  detector threshold presets with explicit per-detector overrides.
- `serpent-wrt nftcheck` and an OpenWrt init helper for checking configured
  nftables enforcement resources without starting the daemon.
- JSON output for `serpent-wrt nftcheck --format json`.
- Optional read-only dnsmasq lease enrichment for detection hostnames and MAC
  addresses in logs and recent detection API responses.
- Lease cache status metadata in `/status` when lease enrichment is enabled.
- Detection counters by type, severity, and confidence bucket in `/stats`.
- `configtest` advisory warnings for valid but risky settings, including broad
  suppression rules, non-loopback API binds, and paranoid enforcement.

### Fixed

- Feed replacement now handles Windows rename semantics during local tests.

## v0.1.0 - 2026-05-13

### Added

- OpenWrt feed package scaffold under `openwrt/serpent-wrt`.
- procd-compatible init script, default OpenWrt config, and package smoke test.
- Build metadata through `serpent-wrt -version`.
- Cross-build checks for representative OpenWrt router architectures.
- Runtime smoke test against a representative OpenWrt x86/generic test target.
- Detection events now include severity, confidence, and stable reason metadata.
- `serpent-wrt configtest` for validating the YAML config and referenced threat
  feed before starting or reloading.
- OpenWrt smoke coverage for `configtest`, API liveness, `/status`, `/stats`,
  `/reload`, and service reload/restart behavior.
- Local threat-feed management API for listing, validating, adding, removing,
  and replacing flat-file feed entries.

### Changed

- CI now validates common OpenWrt target builds and the optional runtime install
  path.
- OpenWrt init scripts now fail start/reload clearly when config validation
  fails.
- Release docs now call out the custom-feed package metadata refresh and the
  need for fixed source hashes before public package submission.

### Security

- Public repository hygiene and security reporting policy.
- nftables table and set names are constrained to conservative identifiers
  before they are used to construct nft commands.
