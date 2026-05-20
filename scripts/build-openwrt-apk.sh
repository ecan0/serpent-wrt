#!/bin/sh

set -eu

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
SDK_URL=${OPENWRT_SDK_URL:-}
SDK_SHA256=${OPENWRT_SDK_SHA256:-}
TMP_ROOT=${TMPDIR:-/tmp}
WORK_DIR=${OPENWRT_APK_WORK_DIR:-"$TMP_ROOT/serpent-wrt-openwrt-apk"}
OUT_DIR=${OPENWRT_APK_OUT_DIR:-"$REPO_ROOT/artifacts/openwrt-apk"}
SUMS_NAME=${OPENWRT_APK_SUMS_NAME:-SHA256SUMS}
TARGETS=${OPENWRT_PACKAGE_TARGETS:-"package/serpent-wrt/check package/serpent-wrt/compile"}
REUSE_WORK_DIR=${OPENWRT_APK_REUSE_WORK_DIR:-0}

if [ "${OPENWRT_MAKE_FLAGS+x}" = "x" ]; then
	MAKE_FLAGS=$OPENWRT_MAKE_FLAGS
else
	MAKE_JOBS=${OPENWRT_MAKE_JOBS:-}
	if [ -z "$MAKE_JOBS" ]; then
		if command -v nproc >/dev/null 2>&1; then
			MAKE_JOBS=$(nproc)
		else
			MAKE_JOBS=2
		fi
	fi
	MAKE_FLAGS="-j$MAKE_JOBS"
fi

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

rm -rf "$OUT_DIR"
if [ "$REUSE_WORK_DIR" != "1" ]; then
	rm -rf "$WORK_DIR"
fi
mkdir -p "$WORK_DIR" "$OUT_DIR"

SDK_ARCHIVE="$WORK_DIR/openwrt-sdk.tar.zst"
SDK_URL_FILE="$WORK_DIR/.sdk-url"
SDK_SHA256_FILE="$WORK_DIR/.sdk-sha256"

SDK=
if [ "$REUSE_WORK_DIR" = "1" ] &&
	[ -f "$SDK_URL_FILE" ] &&
	[ -f "$SDK_SHA256_FILE" ] &&
	[ "$(cat "$SDK_URL_FILE")" = "$SDK_URL" ] &&
	[ "$(cat "$SDK_SHA256_FILE")" = "$SDK_SHA256" ]; then
	SDK=$(find "$WORK_DIR" -maxdepth 1 -type d -name 'openwrt-sdk-*' | sort | head -n 1)
	if [ -n "$SDK" ] && [ -f "$SDK/rules.mk" ]; then
		echo "Reusing OpenWrt SDK work dir: $SDK"
	else
		SDK=
	fi
fi

if [ -z "$SDK" ]; then
	rm -rf "$WORK_DIR"
	mkdir -p "$WORK_DIR"

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
	printf '%s\n' "$SDK_URL" > "$SDK_URL_FILE"
	printf '%s\n' "$SDK_SHA256" > "$SDK_SHA256_FILE"

	SDK=$(find "$WORK_DIR" -maxdepth 1 -type d -name 'openwrt-sdk-*' | sort | head -n 1)
	if [ -z "$SDK" ]; then
		echo "failed to find extracted OpenWrt SDK directory in $WORK_DIR" >&2
		exit 2
	fi
fi

if [ ! -f "$SDK/feeds/packages/lang/golang/golang-package.mk" ] ||
	[ ! -f "$SDK/package/feeds/packages/golang/Makefile" ]; then
	(
		cd "$SDK"
		./scripts/feeds update packages
		./scripts/feeds install golang
	)
else
	echo "Reusing installed OpenWrt packages feed"
fi

if [ -d "$SDK/bin" ]; then
	echo "Removing stale serpent-wrt APK artifacts from SDK bin directory"
	find "$SDK/bin" -type f -name 'serpent-wrt-*.apk' -delete
fi

OPENWRT_SDK="$SDK" \
	OPENWRT_PACKAGE_OVERWRITE=1 \
	OPENWRT_FEEDS_UPDATE=0 \
	OPENWRT_PACKAGE_TARGETS="$TARGETS" \
	OPENWRT_MAKE_FLAGS="$MAKE_FLAGS" \
	sh "$REPO_ROOT/scripts/openwrt-package-check.sh"

find "$SDK/bin" -type f -name 'serpent-wrt-*.apk' -exec cp -v {} "$OUT_DIR"/ \;

count=$(find "$OUT_DIR" -type f -name 'serpent-wrt-*.apk' | wc -l | tr -d ' ')
if [ "$count" -eq 0 ]; then
	echo "no serpent-wrt APK artifacts were produced" >&2
	exit 1
fi

(
	cd "$OUT_DIR"
	find . -maxdepth 1 -type f -name 'serpent-wrt-*.apk' |
		sort |
		while IFS= read -r artifact; do
			sha256sum "$artifact"
		done > "$SUMS_NAME"
)

echo "Produced $count OpenWrt APK artifact(s) in $OUT_DIR"
