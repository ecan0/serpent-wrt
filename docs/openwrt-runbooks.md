# OpenWrt Operational Runbooks

These runbooks cover practical OpenWrt rollout, enforcement, rollback, and
firewall reload recovery flows. They assume a package or manual install using
the standard config path:

```sh
/etc/serpent-wrt/serpent-wrt.yaml
```

Keep the first production rollout detect-only. Enable enforcement only after
configuration, API health, nftables diagnostics, and logs are stable.

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
curl -s http://127.0.0.1:8080/healthz
curl -s http://127.0.0.1:8080/status
curl -s http://127.0.0.1:8080/stats
curl -s http://127.0.0.1:8080/detections/recent
```

Useful OpenWrt log checks:

```sh
logread -e serpent-wrt
/etc/init.d/serpent-wrt status
```

## Detect-Only Rollout

1. Install or update the binary, init script, config, and local threat feed.
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

6. Start or restart the daemon:

   ```sh
   /etc/init.d/serpent-wrt enable
   /etc/init.d/serpent-wrt restart
   ```

7. Watch logs, status, stats, and recent detections for at least one normal
   traffic window:

   ```sh
   logread -f -e serpent-wrt
   curl -s http://127.0.0.1:8080/status
   curl -s http://127.0.0.1:8080/stats
   curl -s http://127.0.0.1:8080/detections/recent
   ```

8. Tune before enforcement:

   - Add `suppression_rules` for expected scanners and monitoring hosts.
   - Raise detector thresholds or use the `quiet` profile for noisy networks.
   - Confirm lease enrichment is useful and not reporting stale hostnames.
   - Confirm `/stats` shows detections and suppressions that match expectations.

## Timed Set And Firewall Policy Rollout

`enforcement_enabled` controls timed nftables set updates. The current daemon
creates the configured table and set and inserts detected source IPs, but it
does **not** install a base chain or drop rule. An entry has no traffic effect
until a separately managed firewall policy references the set.

Do not interpret `blocks_applied`, `/blocked`, or a successful `nftcheck` as
proof that packets were dropped. Keep console or out-of-band access available
while testing any firewall policy.

1. Complete a clean detect-only tuning window first.

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

   The ruleset must contain a rule that references `@blocked_ips` (or the
   configured set name) in the intended forwarding path.

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
   curl -s http://127.0.0.1:8080/status
   ```

6. In a disposable lab, add a known test address to the set or trigger a
   controlled detection, then test a real forwarded flow from that address.
   Verify both the set entry and packet counters on the referencing rule:

   ```sh
   curl -s http://127.0.0.1:8080/blocked
   nft list set inet serpent_wrt blocked_ips
   nft -a list ruleset
   ```

7. Reload the firewall and repeat the rule-reference and packet-flow checks.
   Only increase `block_duration` after the policy survives reload and the
   end-to-end traffic test passes.

## Rollback

Use this when enforcement causes false positives, connectivity risk, or unknown
router behavior.

1. Disable enforcement in the config:

   ```sh
   cp /etc/serpent-wrt/serpent-wrt.yaml /etc/serpent-wrt/serpent-wrt.yaml.rollback
   sed -i 's/^enforcement_enabled:.*/enforcement_enabled: false/' /etc/serpent-wrt/serpent-wrt.yaml
   ```

   If the setting is not present at the top level, edit the file manually and
   add `enforcement_enabled: false`.

2. Validate and restart:

   ```sh
   /etc/init.d/serpent-wrt configtest
   /etc/init.d/serpent-wrt restart
   ```

3. Clear timed-set entries if immediate removal is required:

   ```sh
   nft flush set inet serpent_wrt blocked_ips
   ```

   If the table or set names differ from the defaults, use the configured
   `nft_table` and `nft_set` names.

4. Confirm the daemon is detect-only and traffic has recovered:

   ```sh
   /etc/init.d/serpent-wrt status
   curl -s http://127.0.0.1:8080/status
   curl -s http://127.0.0.1:8080/stats
   logread -e serpent-wrt
   ```

5. Tune thresholds, profiles, feeds, and suppression rules before re-enabling
   enforcement.

## Firewall Reload Recovery

OpenWrt firewall4 (`fw4`) owns its generated nftables ruleset. A firewall reload
can remove custom nft resources depending on local integration. `serpent-wrt`
reports this through `/status` and `nftcheck`.

1. After any firewall reload, check serpent-wrt nft diagnostics:

   ```sh
   /etc/init.d/firewall reload
   /etc/init.d/serpent-wrt nftcheck
   curl -s http://127.0.0.1:8080/status
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
   nft list set inet serpent_wrt blocked_ips
   ```

4. If resources disappear again after every firewall reload, review local fw4
   includes and avoid pointing `serpent-wrt` at a fw4-managed table. Use a
   dedicated table and set unless intentionally integrating with custom firewall
   policy.

## Feed And Config Reload

Threat feed reloads do not require a full service restart:

```sh
/etc/init.d/serpent-wrt reload_feed
curl -s -X POST http://127.0.0.1:8080/reload
```

Use a full restart for config changes:

```sh
/etc/init.d/serpent-wrt configtest
/etc/init.d/serpent-wrt restart
```

## Release Smoke Checklist

For release or package validation on a representative OpenWrt target:

```sh
/etc/init.d/serpent-wrt configtest
/etc/init.d/serpent-wrt nftcheck
/etc/init.d/serpent-wrt status
curl -s http://127.0.0.1:8080/healthz
curl -s http://127.0.0.1:8080/status
curl -s http://127.0.0.1:8080/stats
curl -s -X POST http://127.0.0.1:8080/reload
/etc/init.d/serpent-wrt reload
/etc/init.d/serpent-wrt restart
logread -e serpent-wrt
```
