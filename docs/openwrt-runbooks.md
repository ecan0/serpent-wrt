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

## Enforcement Rollout

Only enable enforcement after a clean detect-only window. Keep console or
out-of-band access available for the first enforcement test.

1. Use a short block duration for the first pass:

   ```yaml
   enforcement_enabled: true
   block_duration: 5m
   nft_table: serpent_wrt
   nft_set: blocked_ips
   ```

2. Validate the config and nft resource plan:

   ```sh
   /etc/init.d/serpent-wrt configtest
   /etc/init.d/serpent-wrt nftcheck
   serpent-wrt --config /etc/serpent-wrt/serpent-wrt.yaml nftcheck --format json
   ```

3. Restart the daemon so it creates or verifies the configured nft table and
   set:

   ```sh
   /etc/init.d/serpent-wrt restart
   /etc/init.d/serpent-wrt status
   ```

4. Confirm `/status` reports enforcement enabled and nft diagnostics are ready:

   ```sh
   curl -s http://127.0.0.1:8080/status
   ```

   The nft diagnostic fields should report `setup_state` and `check_state`
   values consistent with ready resources. Investigate `missing_table`,
   `missing_set`, `check_error`, or `last_error` before relying on blocks.

5. Watch block counters and current blocks:

   ```sh
   curl -s http://127.0.0.1:8080/stats
   curl -s http://127.0.0.1:8080/blocked
   nft list set inet serpent_wrt blocked_ips
   ```

6. If enforcement behaves as expected, increase `block_duration` gradually.

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

3. Clear active dynamic blocks if immediate unblock is required:

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
