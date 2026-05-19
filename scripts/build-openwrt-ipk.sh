#!/bin/sh

set -eu

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
SDK_URL=${OPENWRT_SDK_URL:-}
SDK_SHA256=${OPENWRT_SDK_SHA256:-}
WORK_DIR=${OPENWRT_IPK_WORK_DIR:-"$REPO_ROOT/.openwrt-ipk-work"}
OUT_DIR=${OPENWRT_IPK_OUT_DIR:-"$REPO_ROOT/artifacts/openwrt-ipk"}
SUMS_NAME=${OPENWRT_IPK_SUMS_NAME:-SHA256SUMS}
TARGETS=${OPENWRT_PACKAGE_TARGETS:-"package/serpent-wrt/check package/serpent-wrt/compile"}

if [ -z "$SDK_URL" ]; then
	echo "OPENWRT_SDK_URL is required" >&2
	exit 2
fi

if [ -z "$SDK_SHA256" ]; then
	echo "OPENWRT_SDK_SHA256 is required" >&2
	exit 2
fi

if ! command -v sha256sum >/dev/null 2>&1; then
	echo "sha256sum is required" >&2
	exit 2
fi

rm -rf "$WORK_DIR" "$OUT_DIR"
mkdir -p "$WORK_DIR" "$OUT_DIR"

SDK_ARCHIVE="$WORK_DIR/openwrt-sdk.tar.zst"

if command -v curl >/dev/null 2>&1; then
	curl -fL --retry 3 --retry-delay 5 -o "$SDK_ARCHIVE" "$SDK_URL"
elif command -v wget >/dev/null 2>&1; then
	wget -O "$SDK_ARCHIVE" "$SDK_URL"
else
	echo "curl or wget is required" >&2
	exit 2
fi

printf '%s  %s\n' "$SDK_SHA256" "$SDK_ARCHIVE" | sha256sum -c -
tar -C "$WORK_DIR" -xf "$SDK_ARCHIVE"

SDK=$(find "$WORK_DIR" -maxdepth 1 -type d -name 'openwrt-sdk-*' | sort | head -n 1)
if [ -z "$SDK" ]; then
	echo "failed to find extracted OpenWrt SDK directory in $WORK_DIR" >&2
	exit 2
fi

(
	cd "$SDK"
	./scripts/feeds update packages
	./scripts/feeds install golang
)

OPENWRT_SDK="$SDK" \
	OPENWRT_PACKAGE_OVERWRITE=1 \
	OPENWRT_FEEDS_UPDATE=0 \
	OPENWRT_PACKAGE_TARGETS="$TARGETS" \
	sh "$REPO_ROOT/scripts/openwrt-package-check.sh"

find "$SDK/bin" -type f -name 'serpent-wrt_*.ipk' -exec cp -v {} "$OUT_DIR"/ \;

count=$(find "$OUT_DIR" -type f -name 'serpent-wrt_*.ipk' | wc -l | tr -d ' ')
if [ "$count" -eq 0 ]; then
	echo "no serpent-wrt IPK artifacts were produced" >&2
	exit 1
fi

(
	cd "$OUT_DIR"
	sha256sum serpent-wrt_*.ipk > "$SUMS_NAME"
)

echo "Produced $count IPK artifact(s) in $OUT_DIR"
