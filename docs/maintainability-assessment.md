# Maintainability and OpenWrt IDS assessment

## Conclusion

**[INFERENCE] Continue development, but correct the current contracts before you expand the feature set.**
The project has a manageable size and a useful metadata-only scope.
It is a candidate for a focused OpenWrt IDS, not a verified general-purpose IDS or a self-contained IPS.
The present evidence does not establish safe resource use on small consumer routers.

The main constraints are not a lack of detectors.
They are incomplete memory limits, connection-observation semantics, NAT visibility, and an invalid nftables set datatype in the local check.
A larger feature set before these corrections will increase maintenance cost without more evidence for detection confidence.

Assessment date: 2026-10-11.
This assessment uses source inspection and local execution.
`[INFERENCE]` marks conclusions that the available execution evidence does not directly prove.
Hardware and firmware statements from adjacent repositories describe declared targets, not current device state.

## Scope and stack

The repository contains 26 production Go files with 4,459 lines and 16 Go test files with 4,753 lines.
These counts exclude generated binaries and external repositories.
The module requests Go 1.26.5 and has one direct dependency, `gopkg.in/yaml.v3`.
See [module definition](../go.mod#L1-L5).

The daemon collects TCP/UDP conntrack metadata, classifies direction, applies six detectors, suppresses duplicate alerts, and emits NDJSON.
It also supports a local feed, lease enrichment, optional syslog, an HTTP API, and optional nftables set updates.
See [runtime construction](../internal/runtime/runtime.go#L154-L206) and [flow dispatch](../internal/runtime/runtime.go#L340-L377).

The current scope excludes packet capture, payload inspection, and a persistent database.
The current roadmap also excludes remote feed synchronization, ML, and near-term LuCI or Wazuh expansion.
See [design constraints](../README.md#L97-L104) and [non-goals](roadmap.md#L105-L112).
These boundaries remain appropriate for this assessment.

Per-router firmware compatibility is outside the project scope.
Architecture builds, runtime dependencies, and package contracts remain relevant.
The reference devices do not imply a required router-by-router support matrix.

Read-only reference scope also includes:

- `~/Projects/test-wrt-iac`, for the Proxmox OpenWrt target and synthetic traffic tools.
- A user-confirmed ARM64 household router is a possible later runtime target.

The user identified an ARM64 household router as a possible target.
No device, Proxmox service, or external infrastructure received a connection during this assessment.

## Maintainability findings

### M1 — The core is small enough to maintain

The runtime keeps detector selection explicit.
The API uses a small engine interface, and the feed supports atomic replacement of its in-memory state.
These are useful boundaries without a large framework.
See [detector dispatch](../internal/runtime/runtime.go#L340-L377), [API interface](../internal/api/api.go#L23-L34), and [feed replacement](../internal/feed/feed.go#L26-L38).

The runtime caps recent detections at 100 and deduplication keys at 4,096.
These are real limits, unlike some broader resource claims.
See [runtime limits](../internal/runtime/runtime.go#L23-L27) and [deduplication](../internal/runtime/runtime.go#L394-L403).

**[INFERENCE]** The code does not need a rewrite, a plugin framework, or a generic detection language.
Its present module structure can support targeted corrections.
The main maintenance risk is a difference between stated behavior and actual behavior, not excessive code volume.

### M2 — Several installation paths have different contracts

The SDK package installs a procd service, active configuration, feed, and conffile declarations.
The legacy GL.iNet IPK helper stages only example configuration and feed files, with no service and no declared dependencies.
See [SDK install contract](../openwrt/serpent-wrt/Makefile#L40-L60) and [legacy IPK contents](../scripts/package-glinet.sh#L33-L69).

The package init script exposes `nftcheck`, but the separate contrib init script does not.
See [package commands](../openwrt/serpent-wrt/files/serpent-wrt.init#L11-L20) and [contrib commands](../contrib/init.d/serpent-wrt#L11-L16).
The Makefile still installs the contrib script through `deploy-setup`.
See [deployment setup](../Makefile#L110-L118).

**[INFERENCE]** One canonical package/service contract will cost less to maintain than these divergent paths.
The legacy helper is not evidence of equivalent support for vendor firmware.

### M3 — Tests provide a useful baseline, but some checks verify text rather than behavior

The complete local test suite passed.
However, package checks largely assert source substrings, regular expressions, and file existence.
The nftables tests accept the generated script text or replace nft execution with a success stub.
See [package checks](../internal/packagecheck/openwrt_package_test.go#L12-L119) and [nft tests](../internal/enforcer/enforcer_test.go#L57-L101).

The router smoke script requires disabled enforcement and the presence of a `flows_seen` field.
It does not require a positive flow count or an actual detection.
See [router smoke assertions](../openwrt/serpent-wrt/test.sh#L16-L23) and [status checks](../openwrt/serpent-wrt/test.sh#L45-L54).

**[INFERENCE]** Green tests do not establish packet-path correctness, package installation behavior, or safe router resource use.
The local nft parser failure demonstrates this difference directly.

### M4 — Operational status and configuration need clearer semantics

`/healthz` always returns `ok`.
`/status` also sets its top-level status to `ok`, while separate fields report collector fallback.
A failed snapshot logs an error but does not store a last-success timestamp in collector status.
See [liveness](../internal/api/api.go#L77-L83), [status fields](../internal/runtime/status.go#L35-L40), [status construction](../internal/runtime/status.go#L160-L172), and [snapshot failure](../internal/runtime/runtime.go#L322-L337).

The local daemon smoke confirmed `ok` status after its synthetic event stream ended.
Its collector fields correctly reported the return to `polling`.
This proves liveness and fallback status, not successful collection from a router.

The configuration exposes `log_level`, but the logger has no level filter.
The smoke used `log_level: error` and still produced `info` and `warn` events.
See [configuration field](../internal/config/config.go#L20-L41), [logger](../internal/events/events.go#L117-L155), and [logger construction](../cmd/serpent-wrt/main.go#L320-L336).

### M5 — The deployment helper is not a safe check for the household router

The runtime helper disables SSH host verification by default.
It replaces the binary, service, configuration, and feed, then restarts the service.
See [SSH options](../scripts/openwrt-runtime-test.sh#L32-L39) and [remote mutations](../scripts/openwrt-runtime-test.sh#L42-L61).

The CI deployment condition uses `always()` without a predecessor-success condition.
The CI gate does not include the deployment job.
See [deployment condition](../.github/workflows/ci.yml#L163-L178) and [gate dependencies](../.github/workflows/ci.yml#L222-L227).

**[INFERENCE]** Treat this helper as a disposable-lab deployment operation, not a diagnostic command for a household router.
A failed prerequisite can still lead to deployment on the configured development target.
No deployment command ran in this assessment.

## IDS capabilities and limitations

### D1 — The implemented signals have a useful but narrow purpose

| Signal | Current definition | Important limit |
| --- | --- | --- |
| `feed_match` | Either endpoint matches a local IP/CIDR feed. | Feed quality and direction classification determine coverage. |
| `fanout` | One source has many distinct destination IPs. | This is not proof of compromise. |
| `port_scan`, `ext_scan` | One source/target pair has many destination ports. | Metadata does not prove exploit attempts. |
| `brute_force` | One external source reaches one service across distinct internal hosts. | Repeated password attempts against one host do not produce this distinct-host signal. |
| `beacon` | Repeated observations of a source/destination pair have regular intervals. | Repeated snapshots can produce the same pattern without new connections. |

The [documented detector table](architecture.md#L75-L89) describes the intended directions.
The [service-spray implementation](../internal/detector/bruteforce.go#L20-L46) counts hosts, not authentication failures.
The [beacon implementation](../internal/detector/beacon.go#L50-L103) samples local observation time.

**[INFERENCE]** Position the product as a conntrack-based detector for suspicious network metadata and local threat intelligence.
Do not present its confidence values as measured probabilities of compromise.
No labeled accuracy study formed part of this assessment.

### D2 — DNAT can remove the LAN destination from detection scope

The parser retains only the original tuple and discards the reply tuple.
The runtime applies inbound detectors only when the retained destination belongs to a configured LAN prefix.
See [tuple parser](../internal/collector/collector.go#L164-L220) and [direction dispatch](../internal/runtime/runtime.go#L351-L370).

The synthetic DNAT fixture contained a public original destination and a private reply source.
The parser retained the public destination and original port.
The actual daemon counted the fixture as one flow but emitted no detection, even though the external source was in its feed.

**[INFERENCE]** Common port-forward traffic can therefore bypass inbound feed, scan, and service-spray detection.
Real kernel NAT formats, hairpin NAT, and target firewall paths still need device evidence.
A direct routed LAN destination is not equivalent to a translated destination.

### D3 — Snapshot observations are not new connections

The collector assigns the current time to a snapshot and returns every parsed record.
The runtime processes the whole snapshot again on each cycle.
The tracker refreshes each observed value, while beacon records each eligible observation.
See [snapshot construction](../internal/collector/collector.go#L111-L119), [snapshot dispatch](../internal/runtime/runtime.go#L322-L337), [tracker refresh](../internal/state/state.go#L37-L59), and [beacon samples](../internal/detector/beacon.go#L50-L83).

A local probe supplied the identical UDP record six times at short regular intervals.
It produced two beacon alerts with scaled time thresholds.
This was a synthetic semantic check, not an accuracy measurement with the default profile.

**[INFERENCE]** A long-lived entry can appear as repeated activity.
Short connections between snapshots can remain invisible.
Optional NEW events improve the observation source, but detectors still use local evaluation time rather than `FlowRecord.SeenAt`.
The architecture already acknowledges the beacon problem.
See [documented caveat](architecture.md#L44-L60).

### D4 — Enforcement is not ready for a compatibility claim

The generated script declares `type inet_addr` in an inet table.
A read-only check with local nftables v1.1.6 rejected that datatype.
See [script generation](../internal/enforcer/nft.go#L202-L213) and the verification record below.

The daemon creates a set and elements, not a packet-drop rule.
Its readiness check only checks table and set existence.
See [readiness check](../internal/enforcer/nft.go#L54-L80) and [enforcement boundary](architecture.md#L62-L73).

The enforcer also caches successful entries until their expected expiry.
It does not reconcile that cache with an external set flush.
All set-list errors return an empty success result.
See [entry cache](../internal/enforcer/nft.go#L95-L111) and [set-list errors](../internal/enforcer/nft.go#L138-L147).

**[INFERENCE]** Keep detect-only operation separate from any future IPS claim.
Both address families need real parser, rule, packet-drop, timeout, and firewall-reload evidence.
The local failure is not a test of the nft version on either OpenWrt target.

### D5 — API safety depends on the operator

The API permits feed changes without authentication.
Configuration validates address syntax but permits a non-loopback bind with a nonfatal diagnostic.
See [HTTP server](../internal/api/api.go#L41-L70), [address validation](../internal/config/config.go#L199-L206), and [diagnostic](../internal/config/warnings.go#L23-L25).

**[INFERENCE]** Preserve loopback administration as the default boundary.
A remote API expansion requires a separate security decision.
The [API documentation](api.md#L3-L17) states this risk accurately.

## Resource and platform considerations

### R1 — Source-key limits do not establish a memory budget

The tracker limits source keys, but each key contains a map with no value-count limit.
Every insertion scans that map for expired values.
Beacon limits source/destination keys but not timestamps per key.
It copies and sorts timestamp history during evaluation.
See [tracker state](../internal/state/state.go#L14-L59) and [beacon history](../internal/detector/beacon.go#L34-L83), [score calculation](../internal/detector/beacon.go#L138-L166).

The local probe created a tracker with one allowed source and retained 10,000 distinct values under that source.
This demonstrates the distinction between a key limit and a value limit.
It does not establish a safe upper bound for a router.

The direct feed loader has no entry-count limit and searches CIDRs linearly.
The management path has a 20,000-entry limit, but direct file loads do not apply it.
The probe loaded 20,001 distinct IPs through the direct loader.
See [feed lookup and loader](../internal/feed/feed.go#L41-L117) and [managed limit](../internal/feed/manage.go#L179-L199).

Snapshots also allocate a slice for the full table.
The CLI fallback first buffers the complete command output.
See [collector allocation paths](../internal/collector/collector.go#L103-L119).

**[INFERENCE]** A busy source, large table, or large feed can exceed the intended resource profile.
Tracker insertion across many distinct values has quadratic cumulative scan work within an active window.
A key-count limit alone cannot support the [64 MB claim](../CONTRIBUTING.md#L87-L98).

### R2 — Slow external operations can stall the pipeline

The snapshot CLI command has no context or explicit timeout.
Syslog uses synchronous writes and `net.Dial`, without application deadlines.
The runtime emits the event before it proceeds with counters and enforcement.
See [snapshot command](../internal/collector/collector.go#L103-L108), [syslog transport](../internal/events/events.go#L84-L114), and [event dispatch](../internal/runtime/runtime.go#L406-L429).

**[INFERENCE]** A slow command or TCP syslog peer can delay detection.
No stress or backpressure measurement ran in this assessment.
These paths need bounded behavior before a broader device-support claim.

### R3 — Concrete reference targets reduce uncertainty, but do not replace measurements

| Target | Repository evidence | Assessment use |
| --- | --- | --- |
| Proxmox x86 test VM | One vCPU, 256 MiB RAM, 1 GiB disk, x86/generic OpenWrt 25.12.1 image. | A useful functional target. Its name does not establish a 64-bit guest. |
| Optional ARM64 VM | QEMU full-system emulation, 256 MiB RAM, one core, disabled by default. | Architecture compatibility, not consumer ARM performance. |
| User-confirmed ARM target | ARM64 household router. | A possible real-device reference with household availability constraints. |
| APK matrix | OpenWrt 25.12.4 x86/64, x86/generic, mediatek/filogic. | Declared package targets, not all consumer firmware variants. |
| Other architectures | Local builds passed for ARMv5, ARMv7, MIPS, MIPSLE, and RISC-V64. | Compilation evidence only. |

Sources: [VM resources](../../test-wrt-iac/terraform/main.tf#L86-L113), [image and optional ARM defaults](../../test-wrt-iac/terraform/variables.tf#L95-L125), [ARM emulation](../../test-wrt-iac/terraform/main.tf#L172-L208), and [APK matrix](../.github/workflows/openwrt-apk.yml#L34-L50).

The original project also includes a GL.iNet MT7986AV/Cortex-A53 ARM64 package helper.
See [hardware label](../scripts/package-glinet.sh#L1-L8).
**[INFERENCE]** This hardware context does not establish the exact model or current firmware of the household router.
The inspected router records did not establish its RAM, free flash, CPU allowance, or traffic workload.

The test VM README describes UEFI and an Internet WAN interface.
Its Terraform instead selects SeaBIOS and an isolated WAN bridge.
See [README topology](../../test-wrt-iac/README.md#L8-L26) and [declared VM topology](../../test-wrt-iac/terraform/main.tf#L86-L129).
Use the source distinction in a future lab review rather than assume the diagram is current.

The traffic generator provides useful scenario scripts, but it is not a verified detection corpus.
Its fanout default is 20 attempts, below the daemon home threshold of 50.
Its README also maps DNS and SYN scenarios to detector types that the daemon does not implement.
See [fanout defaults](../../test-wrt-iac/traffic-gen/scripts/fanout.sh#L6-L11), [home profile](../internal/config/config.go#L94-L101), [scenario table](../../test-wrt-iac/traffic-gen/README.md#L157-L166), and [actual dispatch](../internal/runtime/runtime.go#L354-L370).

The traffic VM has a management gateway and a separate WAN interface without a gateway.
The fanout script does not bind an interface or assert a route.
See [traffic VM routes](../../test-wrt-iac/terraform/test-vms.tf#L184-L197) and [traffic command](../../test-wrt-iac/traffic-gen/scripts/fanout.sh#L23-L36).
**[INFERENCE]** An isolated bridge alone does not prove that each generated connection crosses the test router.
No traffic generator ran during this assessment.

### R4 — Binary size is not runtime memory or throughput

These stripped, static local builds used Go 1.26.8, not an OpenWrt SDK.
Sizes are uncompressed file bytes.

| Architecture | Bytes |
| --- | ---: |
| amd64 | 7106722 |
| 386 | 6844578 |
| arm64 | 6619298 |
| ARMv7 | 6881442 |
| ARMv5 | 6946978 |
| MIPS softfloat | 7798977 |
| MIPSLE softfloat | 7798977 |
| RISC-V64 | 6291618 |

The user reports prior ad hoc resource measurements.
This assessment did not receive their values or measurement conditions.
No target RSS, peak heap, CPU use, flash headroom, or routing-throughput result is available in this assessment.
No numerical resource budget was supplied.
A 256 MiB virtual guest and an ARM compilation result cannot establish suitability for a 64 MiB consumer router.

An MVP document can record those measurements with the device, build, configuration, workload, duration, method, and observed values.
Label ad hoc observations separately from repeatable measurements and guaranteed limits.
Do not infer broad resource limits from one device.
This documentation option does not require a new benchmark program or measurements on every router.
The source-level retention risks in R1 remain separate from the user's resource observations.

Firmware without `/proc/net/nf_conntrack` needs the CLI fallback even in default mode.
The package declares the kernel module and nftables dependency, but not the conntrack CLI.
See [collector fallback](../internal/collector/collector.go#L18-L36) and [package dependencies](../openwrt/serpent-wrt/Makefile#L34-L40).
**[INFERENCE]** Document the collector prerequisites independently of CPU architecture.
This dependency contract does not require per-router firmware certification.

## Verification results

### Local commands

The installed toolchain reported `go version go1.26.8-X:nodwarf5 linux/amd64`.
All Go commands used this offline environment:

```sh
GOTOOLCHAIN=local
GOPROXY=off
GOSUMDB=off
GOFLAGS=-mod=readonly
GOCACHE=/tmp/serpent-assessment-bmojojuk/go-cache
GOTMPDIR=/tmp/serpent-assessment-bmojojuk/go-tmp
```

No toolchain or dependency installation occurred.
The temporary paths identify this assessment run, not persistent project files.

| Command or action | Exit/result | Scope |
| --- | --- | --- |
| `go test -count=1 ./...` | 0 | All packages with tests passed. `internal/flow` has no test files. |
| `go vet ./...` | 0 | No diagnostics. |
| Native static build | 0 | Built and executed the actual CLI and daemon. |
| Seven additional architecture builds | 0 each | Compiled only. |
| `nft --version` | 0 | nftables v1.1.6. |
| `nft describe inet_addr` | 0 | Output described an invalid datatype. Exit status alone did not establish support. |
| `nft --check --file -` | 1 | Rejected `inet_addr`. Also reported insufficient netlink permissions. No rules changed. |
| CLI version/config/feed checks | 0 each | Temporary config and feed only. |
| Detect-only `nftcheck` | 0 | Returned `skipped`, not enforcement success. |
| Synthetic daemon/API scenarios | 0 on SIGTERM | Local loopback requests and fixture records only. |
| Temporary Go behavior probe | 0 | Assertions confirmed state, feed, beacon, and tuple observations. |

The exact native build command was:

```sh
CGO_ENABLED=0 go build -trimpath '-ldflags=-s -w' \
  -o /tmp/serpent-assessment-bmojojuk/serpent-wrt ./cmd/serpent-wrt
```

Each cross-build used the same command shape with `CGO_ENABLED=0`, `GOOS=linux`, and these values:

| `GOARCH` | Extra environment | Output suffix after `serpent-wrt-` |
| --- | --- | --- |
| `386` | None | `x86` |
| `arm64` | None | `arm64` |
| `arm` | `GOARM=7` | `armv7` |
| `arm` | `GOARM=5` | `armv5` |
| `mips` | `GOMIPS=softfloat` | `mips` |
| `mipsle` | `GOMIPS=softfloat` | `mipsle` |
| `riscv64` | None | `riscv64` |

The nft check received this generated script on standard input:

```nft
add table inet serpent_wrt
add set inet serpent_wrt blocked_ips { type inet_addr; flags timeout; }
```

The output included:

```text
Error: unknown datatype inet_addr
netlink: Error: cache initialization failed: Operation not permitted
```

No privileged retry occurred.

### Actual daemon and API smoke

The temporary configuration selected `netlink`, a one-hour fallback poll interval, disabled enforcement, and a loopback API on an ephemeral port.
It disabled lease enrichment and remote syslog.
Its LAN prefix was `192.168.1.0/24`, and its feed contained `198.51.100.2`.
A temporary executable named `conntrack` emitted synthetic NEW records.
This was a deliberate fixture, not a connection to the kernel event source.
No fallback poll occurred before shutdown.

The CLI commands used this exact prefix:

```sh
/tmp/serpent-assessment-bmojojuk/serpent-wrt
```

Arguments and observed results:

- `-version`: returned development build metadata.
- `--config /tmp/serpent-assessment-bmojojuk/smoke.yaml configtest --effective --format json`: returned `status: ok`.
- `--config /tmp/serpent-assessment-bmojojuk/smoke.yaml feed validate`: accepted one entry.
- `--config /tmp/serpent-assessment-bmojojuk/smoke.yaml nftcheck --format json`: returned `status: skipped`.
- `--banner never --config /tmp/serpent-assessment-bmojojuk/smoke.yaml`: started the real daemon, twice for separate scenarios.

Python standard-library HTTP requests exercised these loopback operations:

- `GET /healthz`, `/status`, and `/stats`: HTTP 200.
- `POST /feed/add` with `{"entry":"203.0.113.9"}`: HTTP 200 and feed count two.
- `GET /feed`: contained exactly the two expected entries.
- `POST /feed/remove` for that entry: HTTP 200 and feed count one.
- `POST /feed/add` with `{"entry":"not-an-ip"}`: HTTP 400.

The first daemon scenario used this DNAT-shaped fixture:

```text
[NEW] tcp 6 120 SYN_SENT src=198.51.100.2 dst=203.0.113.10 sport=50000 dport=8443 src=192.168.1.10 dst=198.51.100.2 sport=443 dport=50000
```

Result: one observed flow, no detection, and a reported return to `polling` after fixture EOF.
The second scenario added two identical outbound records:

```text
[NEW] tcp 6 120 SYN_SENT src=192.168.1.10 dst=198.51.100.2 sport=50001 dport=443
```

Result: three observed flows, one `feed_match`, one duplicate suppression, and zero block attempts.
The recent-detection response identified the expected LAN source and feed destination.
Both daemon processes exited zero after SIGTERM.

### Temporary behavior probe

Command: `go run . /tmp/serpent-assessment-bmojojuk/large-feed.txt`.
The command ran in `/tmp/serpent-assessment-bmojojuk/probe`.
A temporary module imported the real repository packages through a local module replacement.
It made no repository changes.

Assertions confirmed:

- `Tracker(time.Hour, 1)` retained 10,000 distinct values under one source key.
- `Feed.Load` accepted 20,001 distinct IPs, above the management limit of 20,000.
- Six identical UDP observations produced two beacon alerts with a 1 ms minimum interval and 50 ms tolerance.
- The synthetic DNAT record retained destination `203.0.113.10` and port `8443`, not the translated reply endpoint.

These probes establish specific behavior, not maximum capacity or real-world detection accuracy.

## Verification limits

- No device access, deployment, package installation, or network configuration change occurred.
- No SDK location was configured. SDK package builds and APK installation did not run.
- `golangci-lint`, `govulncheck`, and the real conntrack CLI were not available through `PATH`.
- No vulnerability-database check, race-detector run, benchmark, or sustained load test ran.
- `make build` and `make release-check` did not run as aggregates. They can download dependencies and write repository binaries.
- Direct offline commands covered tests, vet, and architecture builds instead. See [Makefile dependencies](../Makefile#L19-L24) and [release target](../Makefile#L89-L102).
- No real NAT, IPv6 packet path, flow offload, procd lifecycle, firewall reload, or packet-drop result is available.
- No current household router model, firmware version, installed package version, or resource allowance was retrieved.
- Published APKs, checksums, attestations, and current CI runs were not independently checked.
- The two adjacent repositories are local references. Their links require the same sibling-directory layout.

## Development recommendations

These are scope decisions, not an implementation sequence.

**Retain:** one metadata-only daemon, local feeds, structured events, detect-only defaults, explicit detector logic, and optional off-router analysis.

**Correct before expansion:** memory limits, observation semantics, NAT direction, nftables compatibility, readiness semantics, and ineffective configuration.
The findings above supply the evidence for these recommendations.

**Strengthen evidence:** behavioral fixtures, controlled traffic paths, and resource documentation.
Use the Proxmox guest for functional evidence.
Use the original ARM router only under a separately approved device-access and recovery contract.
Do not equate ARM emulation with ARM performance.

**Community-release option:** improve package installation instructions and actual package installation checks if the user selects a broader community release.
This is not a prerequisite for the present MVP scope.

**Defer:** additional detectors, remote administration, automatic feed synchronization, a database, dashboards, DPI, ML, and a generic plugin framework.
These features do not resolve the observed constraints.

**[INFERENCE]** Focused correction and validation can preserve six-month maintainability.
Broad expansion now will multiply unsupported claims and platform obligations.

## Decisions for the next phase

The [next-phase prompt](next-phase-planning-prompt.md) preserves this assessment for a separate plan.
That phase needs explicit decisions about:

- Runtime prerequisites, package formats, and minimum device class, without per-router firmware compatibility requirements.
- How to record the user's ad hoc resource measurements in an MVP document, and whether formal budgets are necessary.
- Detect-only scope versus a separately verified response policy.
- The definition of a flow observation and of each heuristic confidence value.
- Canonical package/service paths and release support obligations.
- Authority to use the disposable VM, original ARM router, and external tools.

No implementation change or implementation plan forms part of this assessment.
