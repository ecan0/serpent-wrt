# OpenWrt Install

This project ships package metadata for custom OpenWrt feeds and publishes APK
release artifacts for selected OpenWrt 25.12 targets.

![OpenWrt APK banner](assets/openwrt-apk-banner.svg)

## Release APKs

The `OpenWrt APK Packages` workflow builds target-specific APKs from official
OpenWrt SDKs and attaches them to GitHub Releases with matching `SHA256SUMS`
files.

Current v0.3.1 r4 assets:

- `serpent-wrt-0.3.1-r4-x86-64.apk`
- `serpent-wrt-0.3.1-r4-x86-generic.apk`
- `serpent-wrt-0.3.1-r4-mediatek-filogic.apk`
- `SHA256SUMS-x86-64`
- `SHA256SUMS-x86-generic`
- `SHA256SUMS-mediatek-filogic`

Release page: <https://github.com/ecan0/serpent-wrt/releases/tag/v0.3.1>

## Package Scaffold

The package scaffold lives in [openwrt/serpent-wrt](../openwrt/serpent-wrt).
It uses a tagged release archive with a fixed source hash.

Validate with a local OpenWrt SDK/buildroot:

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

For repeated local or self-hosted runner builds, set
`OPENWRT_APK_REUSE_WORK_DIR=1` and point `OPENWRT_APK_WORK_DIR` at a persistent
directory outside this repository.

## Manual Runtime Deploy

For an OpenWrt x86/generic test target:

```sh
make deploy-x86 DEPLOY_HOST=root@openwrt-target
```

OpenWrt x86/generic images often report `i686`; use the 32-bit x86 build for
that target.

Manual install path:

```sh
ssh root@openwrt-target 'mkdir -p /etc/serpent-wrt'

ssh root@openwrt-target 'cat > /usr/sbin/serpent-wrt && chmod 0755 /usr/sbin/serpent-wrt' \
  < bin/serpent-wrt-openwrt-x86

ssh root@openwrt-target 'cat > /etc/init.d/serpent-wrt && chmod 0755 /etc/init.d/serpent-wrt' \
  < openwrt/serpent-wrt/files/serpent-wrt.init

ssh root@openwrt-target 'cat > /etc/serpent-wrt/serpent-wrt.yaml' \
  < openwrt/serpent-wrt/files/serpent-wrt.yaml

ssh root@openwrt-target 'cat > /etc/serpent-wrt/threat-feed.txt' \
  < openwrt/serpent-wrt/files/threat-feed.txt

ssh root@openwrt-target '/etc/init.d/serpent-wrt enable && /etc/init.d/serpent-wrt start'
```

## Runtime Validation

```sh
/etc/init.d/serpent-wrt configtest
/etc/init.d/serpent-wrt nftcheck
curl -s http://127.0.0.1:8080/healthz
curl -s http://127.0.0.1:8080/status
curl -s http://127.0.0.1:8080/stats
```

Operational runbooks: [openwrt-runbooks.md](openwrt-runbooks.md).
