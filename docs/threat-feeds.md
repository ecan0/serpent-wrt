# Threat Feeds

## Feed format

serpent-wrt reads a plain-text file with one entry per line. Each entry is either:

- A single IPv4 address: `198.51.100.1`
- A CIDR block: `198.51.100.0/24`

Blank lines and lines starting with `#` are ignored.

Loading and reloading are strict: any other non-comment line rejects the whole
candidate feed, and a failed reload leaves the previous in-memory feed active.

Example:

```
# Feodo Tracker botnet C2s
198.51.100.1
203.0.113.0/24
```

Configure the path in `serpent-wrt.yaml`:

```yaml
threat_feed_path: /etc/serpent-wrt/threat-feed.txt
```

## Free feed sources

| Feed | URL | Format | Notes |
|------|-----|--------|-------|
| Abuse.ch Feodo Tracker | `https://feodotracker.abuse.ch/downloads/ipblocklist.txt` | One IP per line | Botnet C2 IPs, updated every 5 minutes |
| Spamhaus DROP | `https://www.spamhaus.org/drop/drop.txt` | CIDR, semicolon comments | eDROP was merged into DROP in April 2024; update no more than hourly. |
| CINS Army Score | `https://cinsscore.com/list/ci-badguys.txt` | One IP per line | IPs with poor reputation, updated daily |
| Emerging Threats compromised IPs | `https://rules.emergingthreats.net/blockrules/compromised-ips.txt` | One IP per line | Known compromised hosts |

Some feeds include semicolon comments. Strip those comments before validation;
do not stream downloads directly over the active file.

## Validated, atomic download and reload

Stage downloads in the same directory, require HTTPS success, validate the
candidate through the CLI, and restore the previous file if validation fails:

```sh
feed=/etc/serpent-wrt/threat-feed.txt
config=/etc/serpent-wrt/serpent-wrt.yaml
tmp="$(mktemp "${feed}.XXXXXX")"
backup="${feed}.bak"
trap 'rm -f "$tmp"' EXIT

curl --fail --show-error --location --proto '=https' --tlsv1.2 \
  https://feodotracker.abuse.ch/downloads/ipblocklist.txt \
  | sed 's/[[:space:]]*;.*$//; /^#/d; /^[[:space:]]*$/d' > "$tmp"

cp -p "$feed" "$backup"
mv "$tmp" "$feed"
if serpent-wrt --config "$config" feed validate; then
  /etc/init.d/serpent-wrt reload_feed
  rm -f "$backup"
else
  mv "$backup" "$feed"
  exit 1
fi
```

`reload_feed` validates again before signaling the daemon. The daemon also
rejects an invalid candidate during reload and retains its prior in-memory
entries.

## Local CLI management

The CLI manages the configured flat feed file without enabling the localhost
API:

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

`add` and `remove` update the file only. Reload the running daemon afterward
with `reload_feed`, `SIGHUP`, or the API reload endpoint.

## Local API management

The localhost API can manage the configured flat feed file. Entries are
validated as IPv4 addresses or IPv4 CIDRs, duplicate imports are collapsed, and
writes are bounded to 20,000 entries. Successful add/remove/replace operations
reload the daemon feed automatically.

List normalized entries:

```sh
curl http://127.0.0.1:8080/feed
```

Validate one entry or a candidate replacement list without writing:

```sh
curl -X POST http://127.0.0.1:8080/feed/validate \
  -d '{"entry":"198.51.100.1"}'

curl -X POST http://127.0.0.1:8080/feed/validate \
  -d '{"entries":["198.51.100.1","203.0.113.0/24"]}'
```

Add or remove one entry:

```sh
curl -X POST http://127.0.0.1:8080/feed/add \
  -d '{"entry":"198.51.100.1"}'

curl -X POST http://127.0.0.1:8080/feed/remove \
  -d '{"entry":"198.51.100.1"}'
```

Replace/import the full feed:

```sh
curl -X PUT http://127.0.0.1:8080/feed \
  -d '{"entries":["198.51.100.1","203.0.113.0/24"]}'
```

For cron automation, put the validated sequence above in a root-owned script,
make it executable only by root, and invoke that script from `/etc/crontabs/root`.
Avoid download-to-active-file one-liners: an HTTP error page, interrupted
download, or malformed source must not replace the last known-good feed.

## Size guidance

On devices with 64MB RAM, keep the feed under a few thousand entries. Each entry consumes memory for IP parsing and lookup. Rough guidance:

- **< 5,000 entries**: safe on all targets
- **5,000 - 20,000 entries**: fine on 128MB+ devices
- **> 20,000 entries**: test memory usage before deploying to constrained hardware

Prefer curated, high-confidence feeds (Feodo Tracker, Spamhaus DROP) over large aggregated lists. A small, accurate feed is more useful than a large, noisy one on resource-constrained routers.
