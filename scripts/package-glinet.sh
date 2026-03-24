#!/bin/sh
# package-glinet.sh — build an OpenWRT .ipk for GL.iNet MT7986AV routers
#
# Target: MediaTek Filogic 830 (MT7986AV), ARM Cortex-A53, aarch64
# OpenWRT architecture string: aarch64_cortex-a53
#
# Requirements:
#   - Go toolchain on the build host
#   - ar (GNU binutils; on macOS: brew install binutils && export PATH="/opt/homebrew/opt/binutils/bin:$PATH")
#
# Usage:
#   sh scripts/package-glinet.sh
#   VERSION=0.2.0 sh scripts/package-glinet.sh

set -e

BINARY=serpent-wrt
VERSION=${VERSION:-0.1.0-dev}
ARCH=aarch64_cortex-a53
OUTDIR=bin
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)

cd "$REPO_ROOT"
mkdir -p "$OUTDIR"

echo "==> Building $BINARY for $ARCH (GOOS=linux GOARCH=arm64)..."
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" \
    -o "${OUTDIR}/${BINARY}-linux-arm64" ./cmd/serpent-wrt

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

# Stage binary
mkdir -p "${STAGE}/data/usr/sbin"
cp "${OUTDIR}/${BINARY}-linux-arm64" "${STAGE}/data/usr/sbin/serpent-wrt"
chmod 755 "${STAGE}/data/usr/sbin/serpent-wrt"

# Stage default config and example feed
mkdir -p "${STAGE}/data/etc/serpent-wrt"
cp configs/serpent-wrt.example.yaml "${STAGE}/data/etc/serpent-wrt/serpent-wrt.yaml.example"
cp testdata/threat-feed.txt         "${STAGE}/data/etc/serpent-wrt/threat-feed.txt.example"

# control file
mkdir -p "${STAGE}/control"
cat > "${STAGE}/control/control" <<EOF
Package: ${BINARY}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: ecan0
Depends:
Section: net
Description: Lightweight threat intelligence and enforcement daemon for OpenWRT.
 Collects conntrack metadata, runs behavioral detectors, and blocks suspicious
 IPs via nftables. No packet capture. No database. Single binary.
EOF

# debian-binary marker
printf '2.0\n' > "${STAGE}/debian-binary"

# Build the ipk (ar archive of three tar.gz members)
PKG="${OUTDIR}/${BINARY}_${VERSION}_${ARCH}.ipk"
(
    cd "${STAGE}"
    tar -czf control.tar.gz -C control .
    tar -czf data.tar.gz    -C data    .
    ar r "${REPO_ROOT}/${PKG}" debian-binary control.tar.gz data.tar.gz
)

echo "==> Created: ${PKG}"
echo ""
echo "Install on router:"
echo "  scp ${PKG} root@<router-ip>:/tmp/"
echo "  ssh root@<router-ip> opkg install /tmp/$(basename ${PKG})"
