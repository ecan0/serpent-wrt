# OpenWrt APK Installation

This guide defines the supported package workflow for `serpent-wrt`.
APK is the package format for the OpenWrt 25.12 release line.
Do not use the legacy IPK helper for this workflow.

## Release APKs

The `OpenWrt APK Packages` workflow uses official OpenWrt SDKs.
It attaches target-specific APKs and `SHA256SUMS` files to each GitHub Release.

Current v0.4.0 r4 assets:

- `serpent-wrt-0.4.0-r4-x86-64.apk`
- `serpent-wrt-0.4.0-r4-x86-generic.apk`
- `serpent-wrt-0.4.0-r4-mediatek-filogic.apk`
- `SHA256SUMS-x86-64`
- `SHA256SUMS-x86-generic`
- `SHA256SUMS-mediatek-filogic`

Release page: <https://github.com/ecan0/serpent-wrt/releases/tag/v0.4.0>

Select the APK for the OpenWrt target class.
An x86/generic target can report an `i686` machine type.
Use the x86/generic APK for that target class.

The package workflow currently pins OpenWrt 25.12.5 SDKs.
A target can use a different OpenWrt 25.12 patch release.
Record the SDK release and the target firmware release in test evidence.

For a branch build, set `ref` and `package_version` in the workflow.
The APK metadata uses `_preN` for prerelease builds.
The binary keeps the requested `package_version`.
The workflow pins the source archive to that commit.
It does not attach a branch APK to a release.

## Verify The Artifact

Download the APK and its target-specific `SHA256SUMS` file.
Verify the checksum before you transfer the APK.

```sh
APK=serpent-wrt-0.4.0-r4-x86-generic.apk
SUMS=SHA256SUMS-x86-generic
sha256sum --ignore-missing -c "$SUMS"
```

Release APKs include provenance attestations and an SBOM.
Follow [the release process](release.md) for those checks.
A provenance attestation does not prove a reproducible build.

The install command uses `--allow-untrusted` for a local APK.
Thus, you must verify the checksum and expected release source first.

## Verify The SSH Host

Get the target host-key fingerprint through a trusted channel.
Add the verified key to a dedicated or default `known_hosts` file.
Then confirm that the file contains the target key.

```sh
TARGET=root@openwrt-target
KNOWN_HOSTS="$HOME/.ssh/known_hosts"
ssh-keygen -F openwrt-target -f "$KNOWN_HOSTS"
```

Use `StrictHostKeyChecking=yes` for every device command.
Do not use `StrictHostKeyChecking=no` or an empty known-hosts file.

## Initial Package Installation

Transfer the verified APK with strict host-key checks.

```sh
scp -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$KNOWN_HOSTS" \
  "$APK" "$TARGET:/tmp/serpent-wrt.apk"
```

First, simulate the package transaction.
Then install and validate the package.

```sh
ssh -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$KNOWN_HOSTS" \
  "$TARGET" '
set -eu
apk --allow-untrusted add --simulate /tmp/serpent-wrt.apk
apk --allow-untrusted add /tmp/serpent-wrt.apk
/etc/init.d/serpent-wrt configtest
/etc/init.d/serpent-wrt enable
/etc/init.d/serpent-wrt start
/etc/init.d/serpent-wrt status
'
```

If you do not want `apk` to use the network, add the global option `--network=no`:

```sh
apk --network=no --allow-untrusted add /tmp/serpent-wrt.apk
```

`apk` then uses only the local package cache.
The target must already have the package dependencies.

The package installs these local data files:

- `/etc/serpent-wrt/serpent-wrt.yaml`
- `/etc/serpent-wrt/threat-feed.txt`

The package recipe marks both files as configuration files.

## Package Upgrade

Keep the verified prior APK before you start an upgrade.
The prior APK gives the rollback transaction an exact package identity.

Set `PRIOR_APK` to the installed, known-good package artifact.
Set `NEXT_APK` to the verified upgrade artifact.

```sh
PRIOR_APK=serpent-wrt-previous.apk
NEXT_APK=serpent-wrt-next.apk

scp -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$KNOWN_HOSTS" \
  "$PRIOR_APK" "$TARGET:/tmp/serpent-wrt-previous.apk"
scp -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$KNOWN_HOSTS" \
  "$NEXT_APK" "$TARGET:/tmp/serpent-wrt-next.apk"
```

Create one protected backup directory for the transaction.
Use a different directory or remove the old directory before a later upgrade.

```sh
ssh -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$KNOWN_HOSTS" \
  "$TARGET" '
set -eu
BACKUP=/root/serpent-wrt-pre-upgrade
test ! -e "$BACKUP"
mkdir -p "$BACKUP"
chmod 0700 "$BACKUP"
cp -p /etc/serpent-wrt/serpent-wrt.yaml "$BACKUP/"
cp -p /etc/serpent-wrt/threat-feed.txt "$BACKUP/"
cp -p /tmp/serpent-wrt-previous.apk "$BACKUP/"
cp -p /etc/apk/world "$BACKUP/world"
sha256sum \
  /etc/serpent-wrt/serpent-wrt.yaml \
  /etc/serpent-wrt/threat-feed.txt \
  > "$BACKUP/installed-files.sha256"
apk list --installed serpent-wrt > "$BACKUP/serpent-wrt-package.before"
apk list --installed > "$BACKUP/apk-packages.before"
if /etc/init.d/serpent-wrt enabled; then
  touch "$BACKUP/service-enabled"
fi
if /etc/init.d/serpent-wrt status >/dev/null 2>&1; then
  touch "$BACKUP/service-running"
fi
/etc/init.d/serpent-wrt configtest
apk --allow-untrusted add --simulate /tmp/serpent-wrt-next.apk
apk --allow-untrusted add /tmp/serpent-wrt-next.apk
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
else
  /etc/init.d/serpent-wrt stop
fi
apk list --installed serpent-wrt
'
```

This procedure restores the exact pre-upgrade configuration and feed.
The backup keeps `/etc/apk/world`, because `apk add` of a package file writes a
package-identity constraint to that file.
It also keeps the prior autostart and active/stopped states.
The init script validates both files before it stops the current service.
If validation fails, the restart command leaves the current service process active.

APK can create `.apk-new` files when package defaults change.
Review those files after the service is stable.
Do not replace local files without a successful `configtest`.

Do not use `apk upgrade` for this package workflow.
OpenWrt warns against a mass package upgrade.
Use `apk add` only for the selected local APK.

For a package rollback, use [the package rollback runbook](openwrt-runbooks.md#package-rollback).

## Runtime Validation

Run these checks after installation, upgrade, or rollback:

```sh
/etc/init.d/serpent-wrt configtest
/etc/init.d/serpent-wrt nftcheck
/etc/init.d/serpent-wrt status
wget -q -O - http://127.0.0.1:8080/healthz
wget -q -O - http://127.0.0.1:8080/status
wget -q -O - http://127.0.0.1:8080/stats
logread -e serpent-wrt
```

The default collector reads the connection table at intervals.
For connection-create events, install the optional `conntrack` CLI.
Then set `collector: netlink`.

```sh
apk -U add conntrack
```

## Package Build

The package recipe is in [openwrt/serpent-wrt](../openwrt/serpent-wrt).
It uses a tagged release archive with a fixed source hash.

Validate the recipe with a local OpenWrt SDK or buildroot:

```sh
OPENWRT_SDK=/path/to/openwrt-sdk \
  OPENWRT_PACKAGE_OVERWRITE=1 \
  make openwrt-sdk-check
```

Build APK artifacts from an SDK URL:

```sh
OPENWRT_SDK_URL=<sdk-url> \
OPENWRT_SDK_SHA256=<sdk-sha256> \
make openwrt-apk
```

For repeated builds, set `OPENWRT_APK_REUSE_WORK_DIR=1`.
Set `OPENWRT_APK_WORK_DIR` to a persistent directory outside this repository.

Operational runbooks: [openwrt-runbooks.md](openwrt-runbooks.md).
