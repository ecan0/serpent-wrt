# Existing-release end-to-end report

The assessment completed and restored the lab.
All six detector-positive paths reached the Wazuh indexer.
The release produced a beacon false positive and missed a DNAT feed match.
The installed nft parser rejected the enforcement set definition.

## Run identity and scope

| Item | Observed value |
| --- | --- |
| Run ID | `20261013T201544Z_e449b06d` |
| Controller start, UTC | `2026-10-13T20:16:16.553839Z` |
| First network mutation, UTC | `2026-10-13T20:16:42.151466Z` |
| Controller completion, UTC | `2026-10-13T20:31:33.751085Z` |
| Mutation-to-completion interval | 891.600 seconds |
| Controller exit | 0: cases complete and restoration passed |
| Diagnostic replays | 0 |
| Installed version | `0.4.0` |
| Installed commit | `eb6bd111b7a7` |
| Installed build date | `2026-08-01T22:03:36Z` |
| Binary SHA-256, before and after | `10e5925527bc89a637b184e3baf63de0ea7fd1f09346ce7815376c4e4d0cbc76` |
| Source branch base | `origin/dev`, `eb6bd111b7a71fde08efb74760e1970d73798829` |
| Work branch | `ci/existing-release-e2e` |
| Private evidence directory | `$HOME/.local/state/serpent-wrt/e2e/$RUN_ID`, mode `0700` |

Exit 0 means that the controller completed the assessment and restored the lab.
It does not mean that every product expectation passed.
Exit 2 means incomplete execution with successful restoration.
Exit 3 means failed restoration.

The run used the installed binary, not a new build.
The run changed only temporary lab resources and the test-owned daemon configuration.
The household router remained unchanged.
The run did not change packages, persistent network files, DNS, VM definitions, or original product files.
The run left synthetic Wazuh alerts in the shared logs and index.

One preparation-only run ended with exit 2 after a controller review.
That run sent no fixture traffic and passed restoration.
Its private evidence remains under run ID `20261013T195730Z_24f8cd48`.
The final run used a new directory and corrected controller behavior before traffic.

## Baseline and prerequisites

The original service was active, with an empty active feed and no syslog target.
Its LAN classification covered only `192.168.1.0/24`.
Its poll interval was `10s`.
The firewall service was inactive, and nftables had no tables.
The IPv4 forward flag was already enabled and remained unchanged.

These conditions did not provide the required test path.
The temporary corrections supplied isolated routes, receiver aliases, conntrack observation, and a syslog target.
They did not repair product defects.

| Role | Installed tools used or checked |
| --- | --- |
| Router | OpenWrt `25.12.1`, kernel `6.12.74`, `i686`, target `x86/generic`; conntrack `1.4.8-r1`; nftables-json `1.1.6-r2`; curl `8.21.0-r1`; BusyBox `1.37.0-r6`; Dropbear `2025.89-r1`. |
| Generator | Python `3.12.14-r0`; OpenSSH client `10.2_p1-r0`; sudo `1.9.17_p2-r0`; BusyBox `1.37.0-r30`; iproute2-minimal `6.17.0-r0`; musl `1.2.5-r23`. |
| SIEM | Python `3.11.2-1+b1`; iptables `1.8.9-2`; sudo `1.9.13p3-1+deb12u4`; OpenSSH client `1:9.2p1-2+deb12u10`; coreutils `9.1-1`; iproute2 `6.1.0-3`. |
| SIEM services and extra checks | Wazuh manager/indexer/dashboard `4.14.7-1`; Filebeat `7.10.2-2`; curl `7.88.1-10+deb12u15`; jq `1.6-2.1+deb12u2`; OpenSSL `3.0.20-1~deb12u2`; tcpdump `4.99.3-1`. |

All required tools passed their capability checks.
No package correction or VM snapshot rollback was necessary.
The controller used local SSH deadlines instead of a router timeout utility.
The archive supplied file metadata instead of a router stat utility.
The run did not install nft on SIEM.
The installed generator scenario scripts remained unchanged and did not execute.

The router exposed `/proc/net/nf_conntrack` for snapshots.
Its UDP conntrack timeout was 60 seconds, with a stream timeout of 180 seconds.
The TCP established timeout was 7440 seconds.
The run did not change these values.
Host UTC checks stayed within the two-second gate.
The run did not adjust clocks.

## Local CI change and verification

The workflow push branches now include `dev` and `ci/existing-release-e2e`.
The filter initializes `code_changed` from the `E2E_BRANCH` environment expression.
The original path matcher can also enable the check jobs.
The build, test, lint, scan, CI Gate, and fork runner rules remain unchanged.

The deployment condition remains exactly:

```yaml
if: always() && needs.changes.outputs.code_changed == 'true' && github.ref == 'refs/heads/dev' && github.event_name == 'push'
```

| Local verification | Result |
| --- | --- |
| `actionlint .github/workflows/ci.yml`, actionlint `1.7.12` | Passed. |
| `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test ./internal/packagecheck` | Passed. |
| Test-branch push, documentation-only change | Full check jobs enabled; deployment false. |
| Test-branch pull request, documentation-only change | Full check jobs enabled; deployment false. |
| Unrelated documentation-only pull request | Full check jobs not required. |
| Ordinary code change on a `dev` push | Full check jobs enabled; existing deployment condition true. |
| Remote CI execution | Unverified; no publication occurred. |

Only the workflow and this report changed in the product repository.
The two original assessment documents match their original hashes.
No commit, push, pull request, merge, or deployment occurred.
Local validation does not establish cloud runner access or remote check results.

## Effective configuration and finite inputs

Each launch passed the installed binary's `configtest --effective --format json`.
The object below is the exact common effective configuration, with private endpoint parameters in place of their values.
The input table specifies every case difference.
The private files retain the unredacted effective object for each case.

`ROUTER_MANAGEMENT_IP`, `ROUTER_SIEM_IP`, and `SIEM_SYSLOG_IP` identify role endpoints, not additional fixture destinations.
The config path was `/tmp/serpent-e2e-${RUN_ID}/case.yaml`.
The temporary feed path remained constant across cases.

```json
{
  "poll_interval": "1s",
  "collector": "polling",
  "threat_feed_path": "/tmp/serpent-e2e-${RUN_ID}/feed.txt",
  "profile": "home",
  "lease_enrichment": false,
  "dnsmasq_leases_path": "",
  "enforcement_enabled": false,
  "block_duration": "1h",
  "lan_cidrs": [
    "192.168.100.0/24"
  ],
  "self_ips": [
    "${ROUTER_MANAGEMENT_IP}",
    "192.168.100.1",
    "${ROUTER_SIEM_IP}"
  ],
  "nft_table": "serpent_wrt",
  "nft_set": "blocked_ips",
  "log_level": "info",
  "api_enabled": true,
  "api_bind": "127.0.0.1:8080",
  "syslog_target": "${SIEM_SYSLOG_IP}:514",
  "syslog_proto": "udp",
  "dedup_window": "5m",
  "detectors": {
    "fanout": {
      "distinct_dst_threshold": 50,
      "window": "1m"
    },
    "scan": {
      "distinct_port_threshold": 30,
      "window": "1m"
    },
    "beacon": {
      "min_hits": 5,
      "tolerance": "3s",
      "window": "5m",
      "min_interval": "5s",
      "exclude_ports": [
        53,
        123
      ]
    },
    "ext_scan": {
      "distinct_port_threshold": 15,
      "window": "1m"
    },
    "brute_force": {
      "threshold": 5,
      "window": "1m"
    }
  },
  "suppression_rules": []
}
```

Destination suffixes in the input table refer to `198.18.0.N`.
Every sender socket used source `192.168.100.50` and device `eth1`.
Source ports followed `40000 + case_number*100 + connection_index`.
The route gate used case number 0 and source port 40000.

| Number | Case | Exact destination input | Source ports | LAN classification | Collector / poll interval | Feed file contents |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `benign` | .10:18180, one TCP connection. | `40100` | `192.168.100.0/24` | `polling` / `1s` | `Empty` |
| 2 | `feed_destination_dedup` | .10:18180, TCP offsets 0 and 6 seconds. | `40200–40201` | `192.168.100.0/24` | `polling` / `1s` | `198.18.0.10` |
| 3 | `feed_source` | .10:18180, one inbound TCP connection. | `40300` | `198.18.0.0/24` | `polling` / `1s` | `192.168.100.50` |
| 4 | `fanout_49` | .10–.58:18180, 49 TCP connections. | `40400–40448` | `192.168.100.0/24` | `polling` / `1s` | `Empty` |
| 5 | `fanout_50` | .10–.59:18180, 50 TCP connections. | `40500–40549` | `192.168.100.0/24` | `polling` / `1s` | `Empty` |
| 6 | `outbound_ports_29` | .10, TCP ports 18180–18208. | `40600–40628` | `192.168.100.0/24` | `polling` / `1s` | `Empty` |
| 7 | `outbound_ports_30` | .10, TCP ports 18180–18209. | `40700–40729` | `192.168.100.0/24` | `polling` / `1s` | `Empty` |
| 8 | `inbound_ports_14` | .10, TCP ports 18180–18193. | `40800–40813` | `198.18.0.0/24` | `polling` / `1s` | `Empty` |
| 9 | `inbound_ports_15` | .10, TCP ports 18180–18194. | `40900–40914` | `198.18.0.0/24` | `polling` / `1s` | `Empty` |
| 10 | `spray_4` | .10–.13:18180, four inbound TCP connections. | `41000–41003` | `198.18.0.0/24` | `polling` / `1s` | `Empty` |
| 11 | `spray_5` | .10–.14:18180, five inbound TCP connections. | `41100–41104` | `198.18.0.0/24` | `polling` / `1s` | `Empty` |
| 12 | `feed_reload_rejection` | .10:18180, then .10:18181 after the two reloads. | `41200–41201` | `192.168.100.0/24` | `polling` / `1s` | `Empty → 198.18.0.10 → not-an-ip` |
| 13 | `genuine_beacon` | .10:18180, UDP offsets 0, 12, 24, 36, 48 seconds. | `41300–41304` | `192.168.100.0/24` | `netlink` / `1s` | `Empty` |
| 14 | `polling_single_datagram` | .10:18180, one UDP datagram. | `41400` | `192.168.100.0/24` | `polling` / `10s` | `Empty` |
| 15 | `netlink_single_datagram` | .10:18180, one UDP datagram. | `41500` | `192.168.100.0/24` | `netlink` / `1s` | `Empty` |
| 16 | `dnat_classification` | 192.168.100.200:18443 → 198.18.0.10:18180, one TCP connection. | `41600` | `198.18.0.0/24` | `polling` / `1s` | `192.168.100.50` |

All TCP cases held successful connections for at least five seconds after the last connection opened.
The shortest measured TCP hold was 5.021 seconds.
Each ordinary TCP case observed 31 seconds after sender release.
The reload case observed 43 seconds, and each UDP case observed 55 seconds.
Each negative boundary case used the same observation duration as its positive pair.

The receiver remained silent for UDP.
Each UDP initiation sent exactly one byte, `X`.
TCP sent no application payload.

The sender limited socket creation and connection initiation to ten per second.
It validated the full destination and port allowlists before it opened a socket.
It persisted bound tuples before the controller released traffic.
The controller copied those tuples to the router rollback journal before release.

Receivers bound only selected aliases and ports, with `SO_BINDTODEVICE=eth1`.
They accepted only the test source.
Receiver limits were 128 simultaneous sockets, 100 TCP accepts, 100 datagrams, and 90 seconds.

The genuine beacon's measured offsets were `0`, `12.051188`, `24.006251`, `36.006956`, and `48.008512` seconds.
Both netlink cases retained an active netlink collector through their final API checks.
Neither case used `polling` fallback.

## Stage-by-stage results

The route gate passed before detector traffic.
Route lookups selected the isolated generator interface, router SIEM interface, and SIEM return interface.
The receiver accepted the held TCP connection.
Router conntrack showed its original source and `ESTABLISHED` state.
The household gateway did not carry fixture traffic.

The table excludes the route gate and includes both reload connections.
Each manager alert ID had exactly one indexed document with the same ID and tuple.
A zero index count also required a conclusive zero-hit query across all six detectors.

| Case | Initiations | Receiver | Conntrack tuples | Stdout events | API detections | Manager alerts | Index documents | Outcome |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `benign` | 1 | 1 | 1 | 0 | 0 | 0 | 0 | Pass |
| `feed_destination_dedup` | 2 | 2 | 2 | 1 | 1 | 1 | 1 | Pass |
| `feed_source` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | Pass |
| `fanout_49` | 49 | 49 | 49 | 0 | 0 | 0 | 0 | Pass |
| `fanout_50` | 50 | 50 | 50 | 1 | 1 | 1 | 1 | Pass |
| `outbound_ports_29` | 29 | 29 | 29 | 0 | 0 | 0 | 0 | Pass |
| `outbound_ports_30` | 30 | 30 | 30 | 30 | 30 | 30 | 30 | Pass |
| `inbound_ports_14` | 14 | 14 | 14 | 0 | 0 | 0 | 0 | Pass |
| `inbound_ports_15` | 15 | 15 | 15 | 15 | 15 | 15 | 15 | Pass |
| `spray_4` | 4 | 4 | 4 | 0 | 0 | 0 | 0 | Pass |
| `spray_5` | 5 | 5 | 5 | 1 | 1 | 1 | 1 | Pass |
| `feed_reload_rejection` | 2 | 2 | 2 | 2 | 2 | 2 | 2 | Pass |
| `genuine_beacon` | 5 | 5 | 5 | 1 | 1 | 1 | 1 | Pass |
| `polling_single_datagram` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | Observed false positive |
| `netlink_single_datagram` | 1 | 1 | 1 | 0 | 0 | 0 | 0 | Pass |
| `dnat_classification` | 1 | 1 | 1 | 0 | 0 | 0 | 0 | Failed detection |

All sender, receiver, and conntrack counts agreed.
All emitted detection tuples and reasons agreed with API records and manager alerts.
Every manager alert used the expected installed rule ID and decoder `serpent-wrt`.
All 53 manager alert IDs matched indexed documents with the same source, detector, destination, and port where applicable.
No index query overflow or duplicate document appeared.
No packet loss, syslog loss, rule mismatch, or missing index stage appeared in these cases.

### Positive receipts and installed rule identity

Each row identifies an observed alert ID that also matched an indexed document.
Scan rows show one example from their full port sets, not a collapsed episode.
Fanout omits destination and port fields.
Service spray omits the destination field.

| Detector | Installed rule | Repository rule | Example alert ID | Destination / port | Observed reason |
| --- | --- | --- | --- | --- | --- |
| `feed_match` | 100202 | 100202 | `1791922793.810785` | `198.18.0.10` / `18180` | `threat_feed_destination` |
| `fanout` | 100204 | 100203 | `1791922926.974730` | `Absent` / `Absent` | `outbound_distinct_destinations` |
| `port_scan` | 100203 | 100204 | `1791923008.1082116` | `198.18.0.10` / `18207` | `outbound_distinct_ports` |
| `ext_scan` | 100206 | 100206 | `1791923088.1215467` | `198.18.0.10` / `18184` | `inbound_distinct_ports` |
| `brute_force` | 100207 | 100207 | `1791923166.1335407` | `Absent` / `18180` | `inbound_service_spray` |
| `beacon` | 100205 | 100205 | `1791923305.1476090` | `198.18.0.10` / `18180` | `regular_connection_cadence` |

The installed fanout and outbound scan rule IDs differ from [the repository rules](../contrib/wazuh/rules-serpent-wrt.xml#L33-L46).
The assessment used installed IDs and did not change the integration.
The feed-source case used reason `threat_feed_source` and rule `100202`.
Full receipt IDs and tuples remain in `verified-case-stages.json` and the per-case evidence files.

### Feed reload and rejection

The initial held connection produced no feed alert with the empty feed.
The valid reload added `198.18.0.10` and emitted one feed match.

The malformed input was exactly `not-an-ip`.
The daemon logged `status=failure` with `line 1: invalid IP address "not-an-ip"`.
The active feed count remained one.
The second connection to port 18181 emitted a feed match and reached the indexer.
This different destination port avoided a deduplication collision.

The destination-feed case emitted one alert for two source ports.
Its API deduplication counter increased to 55.
This result confirms deduplication for that controlled case, not general precision or recall.

### Beacon comparison

The five-initiation netlink case emitted a beacon after the fifth NEW event.
The one-initiation `polling` case also emitted a beacon and reached the indexer.
The one-initiation netlink control produced no detection or indexed alert.

The `polling` result is a false positive from one observed initiation, not a genuine detector-positive case.
The probe records the actual result without a required false-positive outcome.
The 60-second UDP conntrack lifetime allowed repeated snapshots within the observation window.

**[INFERENCE]** Repeated snapshot evaluations supplied cadence samples without new connections.
This explanation agrees with [snapshot timestamps](../internal/collector/collector.go#L111-L119) and [beacon observation timestamps](../internal/detector/beacon.go#L60-L83).
The netlink control separates NEW events from snapshot repetition on this path.

### DNAT classification gap

The receiver accepted the translated connection, and conntrack showed `ESTABLISHED` state.
The original tuple was `192.168.100.50:41600 → 192.168.100.200:18443`.
The reply tuple contained `198.18.0.10:18180 → 192.168.100.50:41600`.
The inbound LAN classification was only `198.18.0.0/24`, and the feed contained the source address.

The direct inbound feed-source case emitted an indexed alert.
The DNAT case emitted no detection at stdout, API, manager, or index stages.
The first missing stage was daemon detection, not packet delivery or SIEM transport.

**[INFERENCE]** The daemon classified the original destination rather than the translated LAN endpoint.
This explanation agrees with [original-tuple extraction](../internal/collector/collector.go#L164-L204) and [direction dispatch](../internal/runtime/runtime.go#L351-L371).
The run removed the DNAT alias, table, and exact tuple after this probe.

### Enforcement parser

The run checked the exact release script shape against nftables `1.1.6`:

```nft
add table inet serpent_parser_20261013T201544Z_e449b06d
add set inet serpent_parser_20261013T201544Z_e449b06d blocked_ips { type inet_addr; flags timeout; }
```

`nft --check -f -` returned exit 1.
It reported `Error: unknown datatype inet_addr` and `Error: set definition does not specify key`.
The script matches [the release set definition](../internal/enforcer/nft.go#L203-L206).
The run did not apply this script or enable enforcement.
This result proves parser rejection on this installed target, not packet-drop behavior or firmware-wide compatibility.

## SIEM access and delay observations

Read-only indexer health returned HTTP 200 with green cluster status.
Field capabilities confirmed keyword types for `id`, `data.src_ip`, `data.detector`, `data.dst_port`, and `rule.id`.
The `timestamp` field was a date.

A privileged process loaded client certificates directly through Python SSL.
No credential or private key bytes entered the evidence output, command arguments, repository, or chat.
All index requests used GET, normal CA verification, and hostname verification.
The run did not refresh, update, or delete an index.

The dashboard loopback HTTPS request returned a verified 302 redirect to `/app/login?`.
The configured dashboard hostname failed certificate verification with `hostname_mismatch`.
The run did not change certificates or bypass TLS verification.
Interactive dashboard login remains unverified.
Indexed alerts prove searchable stored events, not an authenticated dashboard session.

| Observation | Minimum seconds | Maximum seconds | Meaning |
| --- | --- | --- | --- |
| Stdout event to manager timestamp difference | 0.031326 | 0.034806 | Cross-host UTC difference, without clock-offset calibration. |
| Stdout event to confirmed index query completion | 9.838011 | 41.232318 | Upper bound on visibility delay, including deliberate case observation and query time. |

One-second clock samples verified two-second agreement, not subsecond synchronization.
The timestamp differences are not calibrated subsecond latency measurements.
Index queries began after the case observation window.
The run did not measure the exact time when each index document first became visible.

Eight positive cases found all IDs in the first `polling` round.
The `polling` false-positive case required three rounds before its indexed document matched.
Optional tcpdump transport capture did not run, because the required stages agreed.

## Bounded resource observations

The guest exposed one CPU and `MemTotal=244280 kB`.
The sampler read daemon status/stat, router CPU stat, memory information, and conntrack count once per second.
It verified the owned PID and its process start tick.
No sample showed PID reuse.

The idle row uses the first 30 samples of the 30-second idle baseline.
Its elapsed value measures the interval between the first and last samples.
Other rows include startup, traffic, observation, and evidence-query time for that fresh daemon.

| Case | Samples | Elapsed seconds | Max RSS kB | Max VmHWM kB | Min MemAvailable kB | Max conntrack count | Daemon CPU ticks/second |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `idle` | 30 | 29 | 7236 | 7236 | 180644 | 35 | 0.000000 |
| `benign` | 36 | 36 | 8096 | 8096 | 179488 | 61 | 0.027778 |
| `feed_destination_dedup` | 36 | 35 | 8744 | 8744 | 178476 | 86 | 0.057143 |
| `feed_source` | 36 | 35 | 9460 | 9460 | 177732 | 102 | 0.057143 |
| `fanout_49` | 41 | 40 | 10472 | 10472 | 176512 | 154 | 0.125000 |
| `fanout_50` | 41 | 40 | 10544 | 10544 | 175896 | 149 | 0.100000 |
| `outbound_ports_29` | 39 | 39 | 11416 | 11416 | 175232 | 132 | 0.102564 |
| `outbound_ports_30` | 39 | 38 | 11524 | 11544 | 174940 | 132 | 0.105263 |
| `inbound_ports_14` | 38 | 37 | 10284 | 10284 | 175912 | 118 | 0.054054 |
| `inbound_ports_15` | 38 | 37 | 10452 | 10452 | 175764 | 123 | 0.054054 |
| `spray_4` | 36 | 35 | 9596 | 9596 | 176224 | 113 | 0.057143 |
| `spray_5` | 37 | 36 | 10024 | 10024 | 175416 | 115 | 0.055556 |
| `feed_reload_rejection` | 49 | 48 | 10500 | 10500 | 175508 | 118 | 0.062500 |
| `genuine_beacon` | 60 | 59 | 6448 | 6448 | 178984 | 123 | 0.000000 |
| `polling_single_datagram` | 64 | 63 | 6788 | 6788 | 178432 | 107 | 0.000000 |
| `netlink_single_datagram` | 60 | 59 | 6408 | 6408 | 178640 | 81 | 0.000000 |
| `dnat_classification` | 37 | 36 | 9144 | 9144 | 175924 | 90 | 0.055556 |

There were 210 scenario initiations and one separate route-gate connection.
The largest case held 50 fixture TCP connections.
Conntrack counts also include SSH control traffic and unrelated namespace state.
The observation rule activated conntrack hooks for the namespace, not only its selected packet tuple.
The rule did not change packet verdicts.
This observation effect explains why aggregate conntrack counts exceed fixture counts.

CPU values are raw daemon user/system ticks per elapsed second.
They exclude helper-process CPU and do not assume `CLK_TCK` or CPU percentages.
The run did not measure routing throughput, peak heap, sustained load, or long-lived state retention.
A fresh daemon per case limits what this sample establishes about memory growth.
The sample does not establish a guaranteed budget or suitability for a 64 MiB consumer router.
The user reported prior ad hoc observations, but their values and conditions were not available for comparison.

## Restoration and ownership

The controller's finally path stopped owned workers before network removal.
It stopped the test daemon and removed only worker-recorded conntrack tuples.
A verified already-absent tuple counted as complete cleanup.
It removed the DNAT resources, observation table, exact iptables exceptions, routes, and aliases.
It restored the original service state after network cleanup.
It did not rewrite unchanged original files or change service enablement.

Host-local guards passed a no-mutation dry-run before setup.
The guards used atomic heartbeats, a 120-second expiry, and a 45-minute absolute limit.
The controller renewed each heartbeat every ten seconds.

| Restoration check | Result |
| --- | --- |
| Router binary hash and original API configuration/feed | Match. |
| Original router configuration/feed/init contents, permissions, ownership, timestamps, and link metadata | Match to the verified archive. |
| Original router daemon | Active through the original init script. |
| Router firewall service and nft tables | Inactive service; original empty ruleset. |
| All hosts: IPv4 addresses, routes, routing rules, and relevant sysctls | Match. |
| SIEM INPUT/OUTPUT policies and full iptables rules | Match; INPUT DROP and OUTPUT ACCEPT. |
| SIEM integration/configuration hashes and four service states | Match; services active. |
| Generator scenario script hashes | Match. |
| Package inventories on all hosts | Match; no package changes. |
| Owned processes and ownership/PID markers | None remain. |
| Guards and three owned remote temporary directories | Guards exited; directories removed after evidence copy. |
| Configuration conflicts or restoration errors | None. |

The original backup archive SHA-256 was `31bb975017f072332b2e94c0c3e1083c239ed27e3c9b0da8d73c3a6bd33c2e80`.
The controller verified that checksum after transfer.
A post-restoration archive matched the original file metadata and content hashes.

| Original file | SHA-256 | After restoration |
| --- | --- | --- |
| `/etc/serpent-wrt/serpent-wrt.yaml` | `ab7a4352fc65c319f0ab8340a9ca4985b3fde111ddd5a525e4e631093ef0e639` | Match |
| `/etc/serpent-wrt/threat-feed.txt` | `723747de41ad8f83076f666369306c56a09f1ba60f4918a4963263a7aff905e1` | Match |
| `/etc/init.d/serpent-wrt` | `d8bd4628deede4d7ad1e87cde060a6edd4b1f55e7c9e3640b9e3ec9350bb3965` | Match |
| `/var/ossec/etc/rules/serpent-wrt-rules.xml` | `9fb23b05f885e9491915f129d20b2245e02c2af8fb922b0a7b584946e9a16072` | Match |
| `/var/ossec/etc/decoders/serpent-wrt.xml` | `3877affb0144152dce80cc62f852a2220f11b0ff1e648c890cca2dcaa53a0249` | Match |
| `/var/ossec/etc/ossec.conf` | `61e9cc171415e0ecb157812fd72531fba043d2b3caf2eab5009516db0fba033a` | Match |
| `/etc/filebeat/filebeat.yml` | `37ab859d45c2393df049ab900f3f2b42c06859f4de27e9f175d3bf5b30258212` | Match |

Restoration cannot recover the original daemon's counters or uptime.
It cannot erase legitimate new audit records, and the run did not attempt that action.
Cleanup left unrelated conntrack state and management SSH flows intact.
Synthetic alerts remain as evidence.

No permanent infrastructure change occurred.
The run did not copy transient aliases or routes into Terraform or Ansible defaults.
`test-wrt-iac` retains ownership of VM definitions, guest prerequisites, and syslog contracts.
`toghouse-monorepo` retains ownership of host/inventory context, CA trust, and DNS convergence.
Future permanent changes across these contracts require consistent repository changes on separate short-lived branches.

## Ranked recommendations

| Rank | Class | Evidence and next work | Owner |
| --- | --- | --- | --- |
| 1 | Product behavior | One polling UDP initiation produced an indexed beacon. Define cadence from connection initiations in both collector modes. | serpent-wrt collector/detector contract. |
| 2 | Product behavior | DNAT packet delivery succeeded, but the source-feed detection disappeared. Define original and translated tuple classification. | serpent-wrt flow/classification contract. |
| 3 | Product behavior | The installed nft parser rejected `inet_addr`. Validate supported set datatypes before any enforcement claim. | serpent-wrt enforcer and release checks. |
| 4 | Product alert noise | One outbound scan produced 30 alerts, and one inbound scan produced 15 alerts. Define episode-level alert identity without discarding port evidence. | serpent-wrt runtime/API/syslog contract. |
| 5 | Lab drift and integration | Stock LAN/feed/syslog/observation state did not supply this lab path. Installed scan/fanout IDs differ from repository IDs. Version the installed integration and define explicit lab readiness. | test-wrt-iac and serpent-wrt integration. |
| 6 | Lab access defect | Dashboard hostname TLS verification failed. Align the certificate hostname and trust contract without insecure workarounds. | SIEM certificate owner and toghouse-monorepo trust/inventory context. |
| 7 | Unverified resource risk | This finite sample does not establish sustained memory bounds. Define retention limits and record workloads before resource guarantees. | serpent-wrt state/detector contract. |
| 8 | Optional community-release package work | Runtime prerequisites existed here. SDK/package builds, package installation, and wider firmware compatibility did not run. Keep that work separate from this fixed-release assessment. | Release/package owners. |

The scan counts are observed destination-port deduplication keys, not collapsed episodes.
[The runtime key](../internal/runtime/runtime.go#L386-L391) includes the destination port.
The service-spray case exercised destination spread, not passwords or authentication failures.
The run did not implement any recommendation or repair a product defect.

## Command manifest and private evidence

The commands below use role parameters instead of private management addresses and key paths.
`ROUTER_SSH`, `GENERATOR_SSH`, and `SIEM_SSH` contain the role-specific SSH targets.
`SSH_IDENTITY` identifies the local identity file.
`D` is `/tmp/serpent-e2e-$RUN_ID`.
`TABLE` is `serpent_e2e_$RUN_ID`, and `DNAT_TABLE` is `serpent_dnat_$RUN_ID`.
All derived identifiers contain only letters, digits, and underscores.

### Controller and SSH envelope

```sh
python3 "$HOME/.local/state/serpent-wrt/e2e/$RUN_ID/controller.py"   --run-id "$RUN_ID" --router "$ROUTER_SSH"   --generator "$GENERATOR_SSH" --siem "$SIEM_SSH"   --identity "$SSH_IDENTITY" --max-live-seconds 1800   --max-replays 1 --pause-before-live

ssh -o BatchMode=yes -o StrictHostKeyChecking=yes   -o ConnectTimeout=8 -o ConnectionAttempts=1 -o IdentitiesOnly=yes   -i "$SSH_IDENTITY" "$ROLE_SSH" "$REMOTE_COMMAND"
```

The controller applied a local subprocess timeout to every SSH call.
Control calls used 20 seconds, and bounded evidence calls used 40 seconds.
Workers had an 85-second maximum lifetime in this run.
Generator and SIEM commands used `sudo -n /bin/sh -c` with quoted command text.
The pause flags allowed parent verification before network setup, daemon launch, and scenario traffic.
They did not bypass the finally path or guards.

### Baseline, guard, and daemon commands

```sh
sha256sum /usr/sbin/serpent-wrt
/usr/sbin/serpent-wrt --version
/etc/init.d/serpent-wrt status
/etc/init.d/firewall status
curl --max-time 3 -fsS http://127.0.0.1:8080/status
curl --max-time 3 -fsS http://127.0.0.1:8080/stats
ip -4 address show
ip -4 route show table all
ip rule show
nft list ruleset
iptables -S
sysctl net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.conf.eth1.rp_filter
apk info -v -e conntrack nftables-json curl busybox dropbear
apk info -v -e python3 openssh-client-default sudo busybox iproute2-minimal musl
dpkg-query -W python3 iptables sudo openssh-client coreutils iproute2 curl jq openssl tcpdump wazuh-manager wazuh-indexer wazuh-dashboard filebeat

umask 077
mkdir -m 700 "$D"
/bin/sh "$D/guard.sh" "$D" dry-run
setsid /bin/sh "$D/guard.sh" "$D" < /dev/null > "$D/guard.log" 2>&1 &
date +%s > "$D/heartbeat.next" && mv "$D/heartbeat.next" "$D/heartbeat"
tar -cpf "$D/original.tar" /etc/serpent-wrt /etc/init.d/serpent-wrt
/etc/init.d/serpent-wrt stop
/usr/sbin/serpent-wrt --config "$D/case.yaml" configtest --effective --format json
setsid /usr/sbin/serpent-wrt --banner never --config "$D/case.yaml"
curl --max-time 3 -fsS http://127.0.0.1:8080/detections/recent
```

The manifest lists command families and their exact parameters.
`operations.jsonl` retains every controller host command, deadline, exit, and response.
The private worker source specifies PID ownership checks, redirection, and atomic result files.
No broad process kill, firewall flush, or conntrack flush occurred.

### Isolated network and rule commands

```sh
# Router
ip address add 192.168.100.1/24 dev eth1
ip route add 198.18.0.0/24 via "$SIEM_SYSLOG_IP" dev eth2
nft --check -f "$D/observe.nft"
nft -f "$D/observe.nft"

# Generator, through sudo -n
ip route add 198.18.0.0/24 via 192.168.100.1 dev eth1
ip route get 198.18.0.10

# SIEM, through sudo -n; N covers 1 through 60
ip route add 192.168.100.0/24 via "$ROUTER_SIEM_IP" dev eth1
ip address add "198.18.0.$N/32" dev lo
iptables -w 5 -I INPUT 1 -i eth1 -s 192.168.100.50/32   -m iprange --dst-range 198.18.0.1-198.18.0.60 -p tcp --dport 18180:18209   -m comment --comment "${TABLE}_tcp" -j ACCEPT
iptables -w 5 -I INPUT 1 -i eth1 -s 192.168.100.50/32   -m iprange --dst-range 198.18.0.1-198.18.0.60 -p udp --dport 18180   -m comment --comment "${TABLE}_udp" -j ACCEPT
```

The observation batch was:

```nft
add table inet TABLE
add chain inet TABLE observe { type filter hook prerouting priority filter; policy accept; }
add rule inet TABLE observe iifname "eth1" ip saddr 192.168.100.50 ip daddr 198.18.0.0/24 ct state new counter
```

The DNAT probe added `192.168.100.200/32 dev eth1` and checked this separate batch before application:

```nft
add table ip DNAT_TABLE
add chain ip DNAT_TABLE prerouting { type nat hook prerouting priority dstnat; policy accept; }
add rule ip DNAT_TABLE prerouting iifname "eth1" ip saddr 192.168.100.50 ip daddr 192.168.100.200 tcp dport 18443 dnat to 198.18.0.10:18180
```

### Workers, tuple checks, and read-only SIEM commands

```sh
python3 "$D/traffic_worker.py" "$D/CASE_receiver.request.json"
python3 "$D/traffic_worker.py" "$D/CASE_sender.request.json"
python3 "$D/siem_evidence.py" "$D/evidence-N.request.json"
conntrack -L -f ipv4 -p "$PROTO" --orig-src 192.168.100.50   --orig-dst "$DST" --sport "$SPORT" --dport "$DPORT"
conntrack -D -f ipv4 -p "$PROTO" --orig-src 192.168.100.50   --orig-dst "$DST" --sport "$SPORT" --dport "$DPORT"
```

The input table and archived request files specify each worker request.
The evidence reader used the alert-file device, inode, size, and bounded UTC case window.
It accepted only appended complete JSON lines for the exact test source and detector semantics.
It retained only timestamp, alert ID, rule, decoder, detector, reason, and test tuple fields.
No alert-file rotation or truncation occurred.

A privileged SIEM process used this SSL and GET request shape:

```python
ctx = ssl.create_default_context(cafile=INDEXER_CA)
ctx.load_cert_chain(CLIENT_CERT, CLIENT_KEY)
request = urllib.request.Request(
    'https://127.0.0.1:9200/wazuh-alerts-*/_search',
    data=json.dumps(body).encode(),
    method='GET',
    headers={'Content-Type': 'application/json'},
)
```

The observed destination-feed receipt supplied this positive search body:

```json
{
  "size": 100,
  "_source": ["id", "timestamp", "rule.id", "decoder.name", "data.type", "data.detector", "data.reason", "data.src_ip", "data.dst_ip", "data.dst_port"],
  "query": {
    "bool": {
      "filter": [
        {"term": {"id": "1791922793.810785"}},
        {"term": {"data.src_ip": "192.168.100.50"}},
        {"term": {"data.detector": "feed_match"}},
        {"range": {"timestamp": {"gte": "2026-10-13T20:19:49.490597Z", "lte": "2026-10-13T20:20:26.274792Z"}}}
      ]
    }
  }
}
```

The archived requests retain the actual case timestamps.
Negative queries omitted the ID filter and covered every detector.
The worker verified exact ID and tuple equality client-side.
Positive query retries used two-second intervals and a 30-second limit.

### Restoration commands

```sh
/bin/sh "$D/stop_owned.sh" "$D"
/bin/sh "$D/rollback.sh" "$D" no-service
# Each successful mutation had its own marker and full inverse specification.
nft delete table ip "$DNAT_TABLE"
ip address del 192.168.100.200/32 dev eth1
nft delete table inet "$TABLE"
# Delete each iptables exception with -D INPUT and its full original specification.
# Delete only the routes and aliases that this run successfully added.
/etc/init.d/serpent-wrt start
# After baseline comparisons and private archive copy:
touch "$D/cancel_guard"
# After guard exit and zero owned process/marker checks:
rm -rf "$D"
```

Private evidence includes `summary.json`, per-case JSON/effective configs, `operations.jsonl`, three host archives, and the verified original backup.
`verified-case-stages.json` contains receipt IDs, tuple equality checks, hold times, and delay bounds.
`resource-summary.json` contains raw-sample calculations.
`original-file-metadata-verification.json` and `restoration-followup.json` contain the final ownership, metadata, package, and sysctl checks.
`worker-hashes.json` identifies the exact controller and worker source.

## Failed, unavailable, and unverified checks

| Status | Check |
| --- | --- |
| Failed product expectation | DNAT source-feed detection, despite receiver and translated conntrack proof. |
| Failed parser prerequisite for enforcement | Release `inet_addr` set definition on the installed nft parser. |
| Observed weak point | Polling beacon alert from one silent UDP initiation. |
| Observed access defect | Dashboard hostname TLS verification. |
| Unavailable | None of the required runtime tools, collectors, or SIEM stages. |
| Unverified | Interactive dashboard login, independent SIEM native nft policy, actual packet drops, IPv6 packet paths, household-router behavior, sustained capacity, firmware matrix, package installation, and remote CI. |

The run did not enumerate independent SIEM native nft chains.
The bounded listener gate passed through the current policy.

The assessment establishes the available IPv4 VM path and its bounded behavior.
It does not establish general detection accuracy, Internet-scale load capacity, or cross-router compatibility.
