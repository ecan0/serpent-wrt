#!/bin/sh

set -eu

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
SDK=${OPENWRT_SDK:-}

if [ -z "$SDK" ]; then
	if [ -f rules.mk ] && [ -d scripts ] && [ -d package ]; then
		SDK=$(pwd)
	else
		echo "OPENWRT_SDK is required unless running from an OpenWrt SDK root" >&2
		exit 2
	fi
fi

SDK=$(cd "$SDK" && pwd)
PACKAGE_SRC="$REPO_ROOT/openwrt/serpent-wrt"
PACKAGE_DST="$SDK/package/serpent-wrt"
TARGETS=${OPENWRT_PACKAGE_TARGETS:-"package/serpent-wrt/check package/serpent-wrt/compile"}

if [ ! -f "$SDK/rules.mk" ] || [ ! -d "$SDK/scripts" ] || [ ! -d "$SDK/package" ]; then
	echo "OPENWRT_SDK does not look like an OpenWrt SDK/buildroot: $SDK" >&2
	exit 2
fi

if [ ! -f "$SDK/feeds/packages/lang/golang/golang-package.mk" ]; then
	if [ "${OPENWRT_FEEDS_UPDATE:-0}" = "1" ]; then
		(
			cd "$SDK"
			./scripts/feeds update packages
			./scripts/feeds install golang
		)
	else
		echo "missing feeds/packages/lang/golang/golang-package.mk" >&2
		echo "run with OPENWRT_FEEDS_UPDATE=1 or install the packages feed first" >&2
		exit 2
	fi
fi

if [ -e "$PACKAGE_DST" ]; then
	if [ "${OPENWRT_PACKAGE_OVERWRITE:-0}" != "1" ]; then
		echo "package destination already exists: $PACKAGE_DST" >&2
		echo "set OPENWRT_PACKAGE_OVERWRITE=1 to refresh it" >&2
		exit 2
	fi
	rm -rf "$PACKAGE_DST"
fi

mkdir -p "$(dirname "$PACKAGE_DST")"
cp -R "$PACKAGE_SRC" "$PACKAGE_DST"

for target in $TARGETS; do
	(
		cd "$SDK"
		make "$target" V=s
	)
done
