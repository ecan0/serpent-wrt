# Threat Feeds

## Feed format

serpent-wrt reads a plain-text file with one entry per line. Each entry is either:

- A single IPv4 address: `198.51.100.1`
- A CIDR block: `198.51.100.0/24`

Blank lines and lines starting with `#` are ignored.

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
| Spamhaus DROP | `https://www.spamhaus.org/drop/drop.txt` | CIDR, semicolon comments | Hijacked netblocks, updated daily |
| Spamhaus EDROP | `https://www.spamhaus.org/drop/edrop.txt` | CIDR, semicolon comments | Extended DROP, updated daily |
| CINS Army Score | `https://cinsscore.com/list/ci-badguys.txt` | One IP per line | IPs with poor reputation, updated daily |
| Emerging Threats compromised IPs | `https://rules.emergingthreats.net/blockrules/compromised-ips.txt` | One IP per line | Known compromised hosts |

Some feeds include comment lines (`;` or `#` prefixed). serpent-wrt ignores `#` lines. For feeds using `;` comments, strip them before loading:

```sh
curl -s https://www.spamhaus.org/drop/drop.txt | sed 's/;.*//' | grep -v '^$' > /etc/serpent-wrt/threat-feed.txt
```

## Downloading and hot-reloading

serpent-wrt reloads the feed on `SIGHUP` without restart:

```sh
# Download fresh feed
curl -s https://feodotracker.abuse.ch/downloads/ipblocklist.txt \
  | grep -v '^#' | grep -v '^$' \
  > /etc/serpent-wrt/threat-feed.txt

# Signal serpent-wrt to reload
kill -HUP $(pidof serpent-wrt)
```

Or use the API if enabled:

```sh
curl -X POST http://127.0.0.1:8080/reload
```

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

To automate, add a cron job:

```sh
# /etc/crontabs/root (OpenWRT cron)
0 */6 * * * curl -s https://feodotracker.abuse.ch/downloads/ipblocklist.txt | grep -v '^#' | grep -v '^$' > /etc/serpent-wrt/threat-feed.txt && kill -HUP $(pidof serpent-wrt)
```

## Size guidance

On devices with 64MB RAM, keep the feed under a few thousand entries. Each entry consumes memory for IP parsing and lookup. Rough guidance:

- **< 5,000 entries**: safe on all targets
- **5,000 - 20,000 entries**: fine on 128MB+ devices
- **> 20,000 entries**: test memory usage before deploying to constrained hardware

Prefer curated, high-confidence feeds (Feodo Tracker, Spamhaus DROP) over large aggregated lists. A small, accurate feed is more useful than a large, noisy one on resource-constrained routers.
