# Changelog

This changelog lists notable serpent-wrt changes.

The project uses semantic versions for tagged releases.

## v0.5.0 - 2026-10-17

### Added

- `/status` reports the latest successful snapshot poll and the latest poll error.
- `/status` separates snapshot overflow and new-flow detection readiness from API liveness and successful collection.

### Fixed

- OpenWrt service restart rejects invalid configuration before it stops the active process.
- Device helpers place strict host-key verification before custom SSH and SCP options.
- Release download references now match the published v0.4.0 assets.

### Changed

- CI Gate now rejects failed change detection and incomplete required jobs.
- CI validates workflows and shell syntax, runs race and 32-bit tests, and exercises the native CLI.
- Pull requests use hosted runners. Only trusted `dev` pushes use the repository runner.
- GitHub Actions use current release SHAs. Go caches and exact-key SDK caches reduce repeated build work.
- `log_level` now filters stdout and syslog events at the configured minimum level.
- `log_level` accepts only `info`, `warn`, or `error`. Replace unsupported values with one of these levels before upgrade. The default remains `info`. At `error`, warn-level detections no longer reach stdout or syslog.
- MVP release criteria now separate runtime validation, package builds, feed trust, provenance, and reproducibility.
- Snapshot mode uses the first conntrack snapshot as a baseline and processes each new tuple once. Netlink fallback sets a fresh baseline.
- DNAT snapshots retain the original and translated destination tuples. Direction classification uses the translated endpoint, and events expose both.
- Port-scan detectors now emit one alert per threshold episode with the count and sorted distinct ports. Expiry below threshold rearms the next episode.
- Tracker and beacon state now use per-key and total limits. Config rejects detector thresholds above the per-key limit.
- Optional `event_context` adds `run_id` and `case_id` to detection events on stdout, API, and syslog. The recent-detections API can filter on both fields.
- Wazuh rule IDs now match the documented detector mappings.
- Conntrack collection stops after the flow limit plus one overflow marker. It no longer retains a full oversized snapshot or fallback command output.
- Enforcement now validates nft batch syntax before apply and uses separate IPv4 and IPv6 sets.

## v0.4.0 - 2026-08-01

### Changed

- OpenWrt package scaffold now uses a tagged release archive with a fixed
  SHA-256 source hash instead of `PKG_MIRROR_HASH:=skip`.

- Added a GitHub Actions workflow that builds OpenWrt APK artifacts from
  SHA-verified official 25.12 SDK downloads and attaches them to releases.

- OpenWrt package validation now prepares SDK `.config` noninteractively and
  depends on `nftables-json`, the stable package name.

- OpenWrt package CI now targets pinned 25.12.5 SDKs. The package feed supplies
  Go 1.26.9, so package builds no longer need a language-version downgrade patch.

- CI and the module now use Go 1.26.9. This resolves standard-library advisories
  that affected Go 1.26.5.

- CI maintenance refreshed GitHub Actions checkout/cache majors and the pinned
  `golangci-lint` and `govulncheck` tool releases.

- Fork pull requests run build, test, lint, and vulnerability checks on
  GitHub-hosted runners. Trusted branches retain the project-controlled runner
  path and do not expose it to untrusted code.

- OpenWrt release artifacts include target-specific CycloneDX SBOMs. APKs
  receive GitHub build-provenance and SBOM attestations.

- Threat-feed loads and reloads reject malformed or unsupported entries
  atomically instead of silently dropping bad lines.

- HTTP routes enforce documented methods. Feed mutation requests reject
  trailing JSON values.

- Daemon startup emits configuration warnings. These warnings distinguish
  nftables timed-set updates from an external packet-drop rule.

- Documentation records polling/beacon limits and the nftables set-only
  enforcement boundary.

- IPv4 and IPv6 addresses/CIDRs are supported in feeds, conntrack parsing,
  suppression rules, LAN/self-IP configuration, status events, and nftables
  timed-set enforcement.

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
  after the daemon applies defaults and detection profiles.
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
