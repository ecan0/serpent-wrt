# Threat Feeds

## Shipped Feed And Trust Boundary

The OpenWrt package installs `/etc/serpent-wrt/threat-feed.txt`.
That file contains comments and documentation addresses only.
It does not contain current threat data.

The project does not mirror, select, or update an operational feed.
An operator must select a source and acquire the data manually.
The source list below gives examples only.
It does not endorse a provider or promise that its URL, format, or terms remain
unchanged.

`serpent-wrt` has no automatic remote-feed client.
The daemon does not verify feed checksums or signatures.

## Feed Format

Use one entry on each line:

- One IPv4 or IPv6 address, such as `198.51.100.1` or `2001:db8::1`.
- One IPv4 or IPv6 CIDR, such as `198.51.100.0/24` or `2001:db8::/32`.

The parser trims space around each line.
It ignores blank lines and full lines that start with `#`.
It does not accept inline comments or semicolon comments.
Remove source-specific fields before validation.

The parser normalizes addresses and CIDRs for use.
A malformed non-comment line rejects the complete candidate.
A failed daemon reload keeps the prior in-memory feed active.

Example:

```text
# Documentation entries only
198.51.100.1
2001:db8::/32
```

Set the path in `serpent-wrt.yaml`:

```yaml
threat_feed_path: /etc/serpent-wrt/threat-feed.txt
```

## Validation Limits

Feed validation confirms only these properties:

- Each data line is an IPv4 address, an IPv6 address, or a CIDR.
- The parser can read the complete file.
- A managed API add, replace, or validate request has no more than 20,000 input
  entries.

Validation does not confirm these properties:

- Source identity or file authenticity.
- Indicator reputation, freshness, ownership, or routeability.
- Data license or provider terms.
- Expected entry count or coverage.
- A checksum or signature.

The 20,000-entry limit applies to the managed API requests and to the
`serpent-wrt feed add` command.
It does not apply to a manually replaced file, the `serpent-wrt feed validate`
command, or the daemon file load.
The loader can read duplicate CIDRs, and a valid feed can contain zero entries.
Do a count and size check before each manual installation.

## Manual Source And Integrity Policy

Use this policy for each operational feed:

1. Record the provider name, exact URL, retrieval time, and applicable terms.
2. Download to a new file in the destination directory.
   Do not write a download directly to the active feed.
3. If the provider supplies a detached signature, verify it against a pinned
   provider key.
   Record the key fingerprint and the signature result.
4. If the provider supplies a checksum through an independent trusted channel,
   verify the raw download against that checksum.
5. If the provider supplies neither item, record that the origin lacks
   cryptographic verification.
   HTTPS alone does not create a signed feed artifact.
6. Record the SHA-256 of the raw download.
7. Convert the provider format to the `serpent-wrt` format.
8. Record the SHA-256 and entry count of the converted candidate.
9. Validate the converted candidate before replacement.
10. Replace the active file atomically, reload it, and confirm the active count.

A checksum from the same download location can detect corruption.
It does not independently authenticate the provider.
A local SHA-256 identifies the acquired bytes but does not prove their origin.

Keep feed trust records outside the public repository when they contain private
operations data.
Do not describe a feed as signed unless you verified a provider signature and
its key.

## Example Manual Acquisition

The commands below show a manual Feodo Tracker acquisition.
Review the provider terms and current format before you use the example.

```sh
set -eu

feed=/etc/serpent-wrt/threat-feed.txt
raw="$(mktemp "${feed}.raw.XXXXXX")"
candidate="$(mktemp "${feed}.new.XXXXXX")"
candidate_config="$(mktemp /tmp/serpent-wrt-feed-config.XXXXXX)"
backup="$(mktemp "${feed}.bak.XXXXXX")"
trap 'rm -f "$raw" "$candidate" "$candidate_config" "$backup"' EXIT

curl --fail --show-error --location --proto '=https' --tlsv1.2 \
  https://feodotracker.abuse.ch/downloads/ipblocklist.txt \
  > "$raw"
sha256sum "$raw"

sed 's/[[:space:]]*;.*$//; /^#/d; /^[[:space:]]*$/d' \
  "$raw" > "$candidate"
test -s "$candidate"
sha256sum "$candidate"
chmod 0644 "$candidate"  # keep the mode from the package install
printf 'threat_feed_path: "%s"\n' "$candidate" > "$candidate_config"
serpent-wrt --config "$candidate_config" feed validate

cp -p "$feed" "$backup"
mv "$candidate" "$feed"
if /etc/init.d/serpent-wrt reload_feed; then
  rm -f "$backup"
else
  mv "$backup" "$feed"
  /etc/init.d/serpent-wrt reload_feed
  exit 1
fi

curl --fail --silent --show-error http://127.0.0.1:8080/status
```

Compare `feed.count` in `/status` with the validated entry count.

The example records local hashes.
It does not verify a provider checksum or signature because the example does not
define a provider trust artifact.
Do not put this procedure in cron.
The MVP requires manual acquisition and review.

## Example Sources

These sources are not part of the package:

| Feed | URL | Expected source format |
| --- | --- | --- |
| Abuse.ch Feodo Tracker | `https://feodotracker.abuse.ch/downloads/ipblocklist.txt` | IP addresses and `#` comments |
| Spamhaus DROP | `https://www.spamhaus.org/drop/drop.txt` | CIDRs and semicolon fields |
| CINS Army Score | `https://cinsscore.com/list/ci-badguys.txt` | IP addresses |
| Emerging Threats compromised IPs | `https://rules.emergingthreats.net/blockrules/compromised-ips.txt` | IP addresses |

Confirm the current URL, terms, format, and trust material with the provider.
Convert all source-specific fields before validation.

## Local CLI Operations

The CLI manages the configured local file without the API:

```sh
serpent-wrt feed list
serpent-wrt feed validate
serpent-wrt feed add 198.51.100.1
serpent-wrt feed remove 198.51.100.1
```

Use `--config` when the config is not at the default path:

```sh
serpent-wrt --config ./serpent-wrt.yaml feed list
```

`add` and `remove` update the file only.
Reload the daemon with `reload_feed`, `SIGHUP`, or the API reload endpoint.

## Local API Operations

The loopback API can manage the configured local file.
It validates IPv4 and IPv6 addresses and CIDRs.
Managed imports collapse normalized duplicates and accept at most 20,000 input
entries.
Successful add, remove, and replace operations reload the feed.

List normalized entries:

```sh
curl http://127.0.0.1:8080/feed
```

Validate one entry or a replacement list without a file update:

```sh
curl -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:8080/feed/validate \
  -d '{"entry":"198.51.100.1"}'

curl -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:8080/feed/validate \
  -d '{"entries":["198.51.100.1","203.0.113.0/24"]}'
```

Add or remove one entry:

```sh
curl -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:8080/feed/add \
  -d '{"entry":"198.51.100.1"}'

curl -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:8080/feed/remove \
  -d '{"entry":"198.51.100.1"}'
```

Replace the full feed:

```sh
curl -H 'Content-Type: application/json' \
  -X PUT http://127.0.0.1:8080/feed \
  -d '{"entries":["198.51.100.1","203.0.113.0/24"]}'
```

Keep the API on loopback.
It has no authentication, authorization, or TLS.

## Size Policy

The managed 20,000-entry limit is a write guardrail.
It is not a memory guarantee for a constrained router.
Direct file load has no entry limit.

Measure RSS and feed reload time on the release runtime class.
Use the final candidate, effective config, feed count, and representative
workload.
Reduce the feed when measurements exceed the approved release limits.
