# Changelog

All notable changes to serpent-wrt will be documented in this file.

This project follows semantic versioning once tagged releases begin. Until then,
changes are grouped under `Unreleased`.

## Unreleased

### Added

- OpenWrt feed package scaffold under `openwrt/serpent-wrt`.
- procd-compatible init script, default OpenWrt config, and package smoke test.
- Build metadata through `serpent-wrt -version`.
- Cross-build checks for representative OpenWrt router architectures.
- Runtime smoke test against the current OpenWrt x86/generic lab VM.

### Changed

- CI now validates common OpenWrt target builds and the lab runtime install path.

### Security

- Public repository hygiene and security reporting policy.
