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
PACKAGE_SRC_REL=${OPENWRT_PACKAGE_SRC:-openwrt/serpent-wrt}
PACKAGE_SRC="$REPO_ROOT/$PACKAGE_SRC_REL"
if [ ! -d "$PACKAGE_SRC" ]; then
	echo "OpenWrt package source does not exist: $PACKAGE_SRC" >&2
	exit 2
fi
PACKAGE_DST="$SDK/package/serpent-wrt"
TARGETS=${OPENWRT_PACKAGE_TARGETS:-"package/serpent-wrt/check package/serpent-wrt/compile"}
MAKE_FLAGS=${OPENWRT_MAKE_FLAGS:-}
DIAGNOSTIC_MAKE_FLAGS=${OPENWRT_DIAGNOSTIC_MAKE_FLAGS:--j1 V=s}

run_make() {
	if [ -n "$MAKE_FLAGS" ]; then
		# shellcheck disable=SC2086
		make "$@" $MAKE_FLAGS
	else
		make "$@"
	fi
}

run_make_with_diagnostics() {
	target=$1

	run_make "$target" && return 0
	status=$?
	if [ -z "$DIAGNOSTIC_MAKE_FLAGS" ]; then
		return "$status"
	fi

	echo "OpenWrt make target failed: $target" >&2
	echo "Retrying with OPENWRT_DIAGNOSTIC_MAKE_FLAGS='$DIAGNOSTIC_MAKE_FLAGS' for diagnostics..." >&2

	old_make_flags=$MAKE_FLAGS
	MAKE_FLAGS=$DIAGNOSTIC_MAKE_FLAGS
	if run_make "$target"; then
		diag_status=0
	else
		diag_status=$?
	fi
	MAKE_FLAGS=$old_make_flags

	if [ "$diag_status" -eq 0 ]; then
		return "$status"
	fi
	return "$diag_status"
}

if [ ! -f "$SDK/rules.mk" ] || [ ! -d "$SDK/scripts" ] || [ ! -d "$SDK/package" ]; then
	echo "OPENWRT_SDK does not look like an OpenWrt SDK/buildroot: $SDK" >&2
	exit 2
fi

if [ "${OPENWRT_FEEDS_UPDATE:-0}" = "1" ]; then
	packages_ref=${OPENWRT_PACKAGES_REF:-}
	if [ -n "$packages_ref" ]; then
		case "$packages_ref" in
			*[!0-9a-f]*)
				echo "OPENWRT_PACKAGES_REF must be a lowercase Git commit SHA" >&2
				exit 2
				;;
		esac
		if [ "${#packages_ref}" -ne 40 ]; then
			echo "OPENWRT_PACKAGES_REF must be a 40-character Git commit SHA" >&2
			exit 2
		fi

		source_feed_conf="$SDK/feeds.conf"
		if [ ! -f "$source_feed_conf" ]; then
			source_feed_conf="$SDK/feeds.conf.default"
		fi
		if [ ! -f "$source_feed_conf" ]; then
			echo "OpenWrt SDK has no feeds.conf or feeds.conf.default" >&2
			exit 2
		fi
		feed_conf_tmp="$SDK/feeds.conf.tmp"
		cp "$source_feed_conf" "$feed_conf_tmp"
		sed -i -E \
			"s|^(src-git packages [^ ]+)\\^.*$|\\1^$packages_ref|" \
			"$feed_conf_tmp"
		if ! grep -E -q "^src-git packages [^ ]+\\^${packages_ref}$" "$feed_conf_tmp"; then
			rm -f "$feed_conf_tmp"
			echo "Could not pin the OpenWrt packages feed to $packages_ref" >&2
			exit 2
		fi
		mv "$feed_conf_tmp" "$SDK/feeds.conf"
		echo "Pinned OpenWrt packages feed to $packages_ref"
	fi
	(
		cd "$SDK"
		./scripts/feeds update packages
		./scripts/feeds install golang
	)
elif [ ! -f "$SDK/feeds/packages/lang/golang/golang-package.mk" ]; then
	echo "missing feeds/packages/lang/golang/golang-package.mk" >&2
	echo "run with OPENWRT_FEEDS_UPDATE=1 or install the packages feed first" >&2
	exit 2
fi

if [ -e "$PACKAGE_DST" ]; then
	if [ "${OPENWRT_PACKAGE_OVERWRITE:-0}" != "1" ]; then
		echo "package destination already exists: $PACKAGE_DST" >&2
		echo "set OPENWRT_PACKAGE_OVERWRITE=1 to refresh it" >&2
		exit 2
	fi
# Remove only the SDK copy when the user sets OPENWRT_PACKAGE_OVERWRITE=1.
	rm -rf "$PACKAGE_DST"
fi

mkdir -p "$(dirname "$PACKAGE_DST")"
cp -R "$PACKAGE_SRC" "$PACKAGE_DST"

(
	cd "$SDK"
	make defconfig
)

for target in $TARGETS; do
	(
		cd "$SDK"
		run_make_with_diagnostics "$target"
	)
done
