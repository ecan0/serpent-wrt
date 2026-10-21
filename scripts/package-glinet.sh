#!/bin/sh
# Legacy opkg package for aarch64_cortex-a53 GL.iNet firmware.
# Canonical OpenWrt 25.12 releases use the SDK APK recipe.
# Requires GNU tar for root-owned package members.
set -eu

VERSION=${VERSION:-0.1.0-dev}
ARCH=aarch64_cortex-a53
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUTDIR=${OPENWRT_IPK_OUT_DIR:-"$REPO_ROOT/bin"}
mkdir -p "$OUTDIR"
OUTDIR=$(cd "$OUTDIR" && pwd)

case "$VERSION" in
	''|*[!A-Za-z0-9.+~-]*) echo "invalid package version" >&2; exit 2 ;;
esac

BINARY=${OPENWRT_BINARY:-}
if [ -z "$BINARY" ]; then
	BINARY="$OUTDIR/serpent-wrt-linux-arm64"
	COMMIT=$(git -C "$REPO_ROOT" rev-parse HEAD)
	BUILD_DATE=$(git -C "$REPO_ROOT" show -s --format=%cs HEAD)
	(
		cd "$REPO_ROOT"
		GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath \
			-ldflags="-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.buildDate=$BUILD_DATE" \
			-o "$BINARY" ./cmd/serpent-wrt
	)
fi
[ -f "$BINARY" ] || { echo "missing ARM executable: $BINARY" >&2; exit 2; }

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT HUP INT TERM
mkdir -p "$STAGE/data/usr/sbin" "$STAGE/data/etc/init.d" \
	"$STAGE/data/etc/serpent-wrt" "$STAGE/control"
cp "$BINARY" "$STAGE/data/usr/sbin/serpent-wrt"
cp "$REPO_ROOT/openwrt/serpent-wrt/files/serpent-wrt.init" "$STAGE/data/etc/init.d/serpent-wrt"
cp "$REPO_ROOT/openwrt/serpent-wrt/files/serpent-wrt.yaml" "$STAGE/data/etc/serpent-wrt/serpent-wrt.yaml"
cp "$REPO_ROOT/openwrt/serpent-wrt/files/threat-feed.txt" "$STAGE/data/etc/serpent-wrt/threat-feed.txt"
chmod 755 "$STAGE/data/usr/sbin/serpent-wrt" "$STAGE/data/etc/init.d/serpent-wrt"
chmod 600 "$STAGE/data/etc/serpent-wrt/serpent-wrt.yaml"
chmod 644 "$STAGE/data/etc/serpent-wrt/threat-feed.txt"

cat > "$STAGE/control/control" <<EOF
Package: serpent-wrt
Version: $VERSION
Architecture: $ARCH
Maintainer: ecan0
Depends: libc, nftables-json, kmod-nf-conntrack, firewall4
Section: net
Description: Conntrack threat detection and timed nftables sets.
 Legacy opkg compatibility package. Managed fw4 packet drops are not installed.
EOF
cat > "$STAGE/control/conffiles" <<'EOF'
/etc/serpent-wrt/serpent-wrt.yaml
/etc/serpent-wrt/threat-feed.txt
EOF
cat > "$STAGE/control/prerm" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT:-}" ] && exit 0
if [ -x /etc/init.d/serpent-wrt ]; then
	/etc/init.d/serpent-wrt stop || exit 1
fi
EOF
chmod 755 "$STAGE/control/prerm"
printf '2.0\n' > "$STAGE/debian-binary"

PKG="$OUTDIR/serpent-wrt_${VERSION}_${ARCH}.ipk"
(
	cd "$STAGE"
	tar --numeric-owner --owner=0 --group=0 -czf control.tar.gz -C control .
	tar --numeric-owner --owner=0 --group=0 -czf data.tar.gz -C data .
	tar --numeric-owner --owner=0 --group=0 -czf "$PKG" ./debian-binary ./control.tar.gz ./data.tar.gz
)
printf 'Created: %s\n' "$PKG"
