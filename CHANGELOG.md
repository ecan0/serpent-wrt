# Changelog

All notable changes to serpent-wrt will be documented in this file.

This project follows semantic versioning for tagged releases.

## Unreleased

### Added

- Config-only suppression rules for expected scanner, monitor, or noisy service
  detections, with a `/stats` counter for suppressed detections.
- `/status` nft diagnostics for missing enforcement table/set state, including
  firewall-reload hints when resources disappear after setup.
- Detection profiles (`home`, `homelab`, `quiet`, `paranoid`) for practical
  detector threshold presets with explicit per-detector overrides.
- `serpent-wrt nftcheck` and an OpenWrt init helper for checking configured
  nftables enforcement resources without starting the daemon.
- Optional read-only dnsmasq lease enrichment for detection hostnames and MAC
  addresses in logs and recent detection API responses.

## v0.1.0 - 2026-05-13

### Added

- OpenWrt feed package scaffold under `openwrt/serpent-wrt`.
- procd-compatible init script, default OpenWrt config, and package smoke test.
- Build metadata through `serpent-wrt -version`.
- Cross-build checks for representative OpenWrt router architectures.
- Runtime smoke test against the current OpenWrt x86/generic lab VM.
- Detection events now include severity, confidence, and stable reason metadata.
- `serpent-wrt configtest` for validating the YAML config and referenced threat
  feed before starting or reloading.
- OpenWrt smoke coverage for `configtest`, API liveness, `/status`, `/stats`,
  `/reload`, and service reload/restart behavior.
- Local threat-feed management API for listing, validating, adding, removing,
  and replacing flat-file feed entries.

### Changed

- CI now validates common OpenWrt target builds and the lab runtime install path.
- OpenWrt init scripts now fail start/reload clearly when config validation
  fails.
- Release docs now call out the custom-feed package metadata refresh and the
  need for fixed source hashes before public package submission.

### Security

- Public repository hygiene and security reporting policy.
- nftables table and set names are constrained to conservative identifiers
  before they are used to construct nft commands.
