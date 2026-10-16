# OpenWrt Operational Runbooks

These runbooks define the supported APK rollout and recovery procedures.
Use [the installation guide](openwrt-install.md) for package installation and upgrade.
The package config path is:

```sh
/etc/serpent-wrt/serpent-wrt.yaml
```

Keep the first production rollout detect-only.
Enable enforcement only after the configuration, API, nftables diagnostics, and logs are stable.

## Common Checks

Run these before and after each rollout step:

```sh
/etc/init.d/serpent-wrt configtest
/etc/init.d/serpent-wrt status
serpent-wrt --config /etc/serpent-wrt/serpent-wrt.yaml configtest --effective
serpent-wrt --config /etc/serpent-wrt/serpent-wrt.yaml nftcheck
```

If the API is enabled on loopback:

```sh
wget -q -O - http://127.0.0.1:8080/healthz
wget -q -O - http://127.0.0.1:8080/status
wget -q -O - http://127.0.0.1:8080/stats
wget -q -O - http://127.0.0.1:8080/detections/recent
```

Useful OpenWrt log checks:

```sh
logread -e serpent-wrt
/etc/init.d/serpent-wrt status
```

## Detect-Only Rollout

1. Install or upgrade the APK with [the installation guide](openwrt-install.md).
2. Keep enforcement disabled:

   ```yaml
   enforcement_enabled: false
   ```

3. Set `lan_cidrs` and `self_ips` for the router and protected LANs.
4. Choose a conservative profile such as `home`, `homelab`, or `quiet`.
5. Validate the config and feed:

   ```sh
   /etc/init.d/serpent-wrt configtest
   serpent-wrt --config /etc/serpent-wrt/serpent-wrt.yaml configtest --effective
   ```

With enforcement disabled, `serpent-wrt nftcheck` validates set syntax and makes no rule changes.
Parser acceptance does not prove packet drops.

6. Start or restart the daemon:

   ```sh
   /etc/init.d/serpent-wrt enable
   /etc/init.d/serpent-wrt restart
   ```

7. Watch logs, status, stats, and recent detections for at least one normal
   traffic window:

   ```sh
   logread -f -e serpent-wrt
   wget -q -O - http://127.0.0.1:8080/status
   wget -q -O - http://127.0.0.1:8080/stats
   wget -q -O - http://127.0.0.1:8080/detections/recent
   ```

8. Tune before enforcement:

   - Add `suppression_rules` for trusted scanners and network monitors.
   - Raise detector thresholds or use the `quiet` profile for noisy networks.
   - Confirm that lease enrichment reports only current hostnames.
   - Confirm `/stats` shows detections and suppressions that match expectations.

## Timed Set And Firewall Policy Rollout

`enforcement_enabled` controls timed nftables set updates.
The daemon validates both address-family set definitions before it applies them.
It does not install a base chain or drop rule. Entries have no traffic effect
until a separately managed firewall policy uses the correct family set.

Do not read `blocks_applied`, `/blocked`, or a successful `nftcheck` as proof
that packets were dropped. Keep console or out-of-band access available when
you test a firewall policy.

1. Complete detect-only checks and threshold adjustments first.

2. Design the firewall integration for the target OpenWrt release. For fw4,
   prefer a version-controlled nftables include managed by the package or local
   configuration. Confirm its chain, hook, direction, and source-address
   semantics with `fw4 print`. Do not add an ad hoc rule that disappears on the
   next firewall reload.

   OpenWrt documents the supported include positions under
   [Firewall configuration: Includes](https://openwrt.org/docs/guide-user/firewall/firewall_configuration#includes_2203_and_later_with_fw4).

3. Verify the installed policy actually references the configured set:

   ```sh
   fw4 print
   nft -a list ruleset
   ```

The ruleset must use `@blocked_ips_v4` and `@blocked_ips_v6` in the correct address-family paths.

4. Enable short-lived timed-set updates:

   ```yaml
   enforcement_enabled: true
   block_duration: 5m
   nft_table: serpent_wrt
   nft_set: blocked_ips
   ```

5. Validate and restart:

   ```sh
   /etc/init.d/serpent-wrt configtest
   /etc/init.d/serpent-wrt restart
   /etc/init.d/serpent-wrt nftcheck
   wget -q -O - http://127.0.0.1:8080/status
   ```

6. In a disposable lab, add a known test address to the set or trigger a
   controlled detection. Test a forwarded flow from that address.
   Verify the set entry and packet counters on the firewall rule:

   ```sh
   wget -q -O - http://127.0.0.1:8080/blocked
   nft list set inet serpent_wrt blocked_ips_v4
   nft list set inet serpent_wrt blocked_ips_v6
   ```

7. Reload the firewall and repeat the rule-reference and packet-flow checks.
   Only increase `block_duration` after the policy survives reload and the
   end-to-end traffic test passes.

## Package Rollback

Use the exact prior APK and the backup from the upgrade procedure.
Do not use `apk upgrade` for rollback.

The rollback restores the prior config, feed, world constraints, autostart state, and active/stopped state.
It also checks the installed `serpent-wrt` package identity.

```sh
set -eu
BACKUP=/root/serpent-wrt-pre-upgrade
test -f "$BACKUP/serpent-wrt-previous.apk"
test -f "$BACKUP/serpent-wrt.yaml"
test -f "$BACKUP/threat-feed.txt"
test -f "$BACKUP/installed-files.sha256"
test -f "$BACKUP/serpent-wrt-package.before"
test -f "$BACKUP/apk-packages.before"
test -f "$BACKUP/world"

cp -p "$BACKUP/world" /etc/apk/world

apk --allow-untrusted add --simulate "$BACKUP/serpent-wrt-previous.apk"
apk --allow-untrusted add "$BACKUP/serpent-wrt-previous.apk"
cp -p "$BACKUP/world" /etc/apk/world

cp -p "$BACKUP/serpent-wrt.yaml" /etc/serpent-wrt/serpent-wrt.yaml
cp -p "$BACKUP/threat-feed.txt" /etc/serpent-wrt/threat-feed.txt
sha256sum -c "$BACKUP/installed-files.sha256"
/etc/init.d/serpent-wrt configtest

if test -f "$BACKUP/service-enabled"; then
  /etc/init.d/serpent-wrt enable
else
  /etc/init.d/serpent-wrt disable
fi

if test -f "$BACKUP/service-running"; then
  /etc/init.d/serpent-wrt restart
  /etc/init.d/serpent-wrt status
else
  /etc/init.d/serpent-wrt stop
fi

apk list --installed serpent-wrt > "$BACKUP/serpent-wrt-package.after-rollback"
cmp "$BACKUP/serpent-wrt-package.before" \
  "$BACKUP/serpent-wrt-package.after-rollback"
apk list --installed > "$BACKUP/apk-packages.after-rollback"
cmp "$BACKUP/apk-packages.before" "$BACKUP/apk-packages.after-rollback"
cmp "$BACKUP/world" /etc/apk/world
logread -e serpent-wrt
```

The explicit APK path selects the prior package version.
The rollback also restores `/etc/apk/world`, because `apk add` of a package file
writes a package-identity constraint to that file.
If `configtest` fails, do not stop the active process.
Correct the files or restore a valid backup before another restart.

`apk` can leave `.apk-new` side files for changed package defaults.
Review each side file after `configtest` passes.
Remove the side files that are not necessary.

Keep the backup until all package and runtime checks pass.

## Enforcement Rollback

Use this procedure when enforcement causes false positives or connectivity risk.

1. Disable enforcement in the config:

   ```sh
   cp /etc/serpent-wrt/serpent-wrt.yaml /etc/serpent-wrt/serpent-wrt.yaml.rollback
   sed -i 's/^enforcement_enabled:.*/enforcement_enabled: false/' /etc/serpent-wrt/serpent-wrt.yaml
   ```

   If the field is absent from the top level, add `enforcement_enabled: false`.

2. Validate and restart:

   ```sh
   /etc/init.d/serpent-wrt configtest
   /etc/init.d/serpent-wrt restart
   ```

3. Clear timed-set entries if immediate removal is required:

   ```sh
   nft flush set inet serpent_wrt blocked_ips_v4
   nft flush set inet serpent_wrt blocked_ips_v6
   ```

   If the table or set prefix differs from the defaults, use the configured
   `nft_table` and `nft_set` values. Append `_v4` or `_v6` to the set prefix.

4. Confirm that the daemon uses detect-only mode and traffic works.

   ```sh
   /etc/init.d/serpent-wrt status
   wget -q -O - http://127.0.0.1:8080/status
   wget -q -O - http://127.0.0.1:8080/stats
   logread -e serpent-wrt
   ```

5. Tune thresholds, profiles, feeds, and suppression rules before you enable enforcement again.

## Firewall Reload Recovery

OpenWrt firewall4 (`fw4`) owns its generated nftables ruleset.
It can remove custom nft resources during reload.
Local integration determines this behavior.
`serpent-wrt` reports this through `/status` and `nftcheck`.

1. After any firewall reload, check serpent-wrt nft diagnostics:

   ```sh
   /etc/init.d/firewall reload
   /etc/init.d/serpent-wrt nftcheck
   wget -q -O - http://127.0.0.1:8080/status
   ```

2. If diagnostics report `missing_table` or `missing_set`, restart
   `serpent-wrt` so it recreates its resources:

   ```sh
   /etc/init.d/serpent-wrt restart
   /etc/init.d/serpent-wrt nftcheck
   ```

3. Confirm the nft set exists:

   ```sh
   nft list table inet serpent_wrt
   nft list set inet serpent_wrt blocked_ips_v4
   nft list set inet serpent_wrt blocked_ips_v6
   ```

4. If resources disappear after each firewall reload, review the local fw4 includes.
   Do not select a fw4-managed table unless your firewall policy requires it.
   Use a dedicated table and set for independent daemon resources.

## Invalid Configuration

Create a candidate beside the installed config.
Do not replace the installed config before validation succeeds.

```sh
set -eu
CONF=/etc/serpent-wrt/serpent-wrt.yaml
cp -p "$CONF" "$CONF.candidate"
vi "$CONF.candidate"
serpent-wrt --config "$CONF.candidate" configtest --effective
cp -p "$CONF" "$CONF.rollback"
mv "$CONF.candidate" "$CONF"
/etc/init.d/serpent-wrt restart
```

The restart command validates the installed config before it stops the service.
An invalid config leaves the current service process active.

## Validated Feed Reload

The daemon keeps its current in-memory feed until it receives a valid reload.
First, create and edit a candidate feed.

```sh
FEED=/etc/serpent-wrt/threat-feed.txt
cp -p "$FEED" "$FEED.candidate"
vi "$FEED.candidate"
```

Keep a rollback copy.
Then place the candidate at the configured path and validate it.

```sh
set -eu
CONF=/etc/serpent-wrt/serpent-wrt.yaml
FEED=/etc/serpent-wrt/threat-feed.txt
cp -p "$FEED" "$FEED.rollback"
mv "$FEED.candidate" "$FEED"
if ! serpent-wrt --config "$CONF" feed validate; then
  cp -p "$FEED.rollback" "$FEED"
  exit 1
fi
if ! /etc/init.d/serpent-wrt reload_feed; then
  cp -p "$FEED.rollback" "$FEED"
  exit 1
fi
```

The init command validates the config and feed before it sends `SIGHUP`.
The runtime keeps its prior feed if a later load fails.

Check the reload event and the active feed:

```sh
logread -e serpent-wrt
wget -q -O - http://127.0.0.1:8080/feed
```

Use a validated restart for other config changes:

```sh
/etc/init.d/serpent-wrt configtest
/etc/init.d/serpent-wrt restart
```

## Release Smoke Checklist

For release or package validation on a representative OpenWrt target:

```sh
apk list --installed serpent-wrt
/etc/init.d/serpent-wrt configtest
serpent-wrt --config /etc/serpent-wrt/serpent-wrt.yaml feed validate
/etc/init.d/serpent-wrt nftcheck
/etc/init.d/serpent-wrt status
wget -q -O - http://127.0.0.1:8080/healthz
wget -q -O - http://127.0.0.1:8080/status
wget -q -O - http://127.0.0.1:8080/stats
wget -q -O - --post-data='' http://127.0.0.1:8080/reload
/etc/init.d/serpent-wrt reload_feed
/etc/init.d/serpent-wrt restart
logread -e serpent-wrt
```
