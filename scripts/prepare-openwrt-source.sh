#!/bin/sh
# Pin the OpenWrt recipe to one already-resolved source commit and create the
# deterministic local source archive used by the SDK build.  The caller owns
# the checkout; this helper only rewrites the package recipe in that checkout.
set -eu

SOURCE_ROOT=${SOURCE_ROOT:-}
SOURCE_COMMIT=${SOURCE_COMMIT:-}
PACKAGE_VERSION=${PACKAGE_VERSION:-}
APK_VERSION=${APK_VERSION:-}
SOURCE_ARCHIVE=${SOURCE_ARCHIVE:-}

fail() {
	echo "prepare-openwrt-source: $*" >&2
	exit 2
}

[ -n "$SOURCE_ROOT" ] || fail "SOURCE_ROOT is required"
[ -n "$SOURCE_COMMIT" ] || fail "SOURCE_COMMIT is required"
[ -n "$PACKAGE_VERSION" ] || fail "PACKAGE_VERSION is required"
[ -n "$APK_VERSION" ] || fail "APK_VERSION is required"
[ -n "$SOURCE_ARCHIVE" ] || fail "SOURCE_ARCHIVE is required"

case "$SOURCE_COMMIT" in
	*[!0-9a-f]* | '') fail "SOURCE_COMMIT must be a lowercase commit SHA" ;;
esac
[ "${#SOURCE_COMMIT}" -eq 40 ] || fail "SOURCE_COMMIT must be a full 40-character SHA"
case "$PACKAGE_VERSION" in
	*[!A-Za-z0-9.+-]* | '') fail "PACKAGE_VERSION has unsupported characters" ;;
esac
case "$APK_VERSION" in
	*[!A-Za-z0-9._+-]* | '') fail "APK_VERSION has unsupported characters" ;;
esac
for value in "$PACKAGE_VERSION" "$APK_VERSION" "$SOURCE_ARCHIVE"; do
	case "$value" in
		*'|'* | *'&'* | *'
'*) fail "a source value contains an unsafe replacement character" ;;
	esac
done

case "$SOURCE_ARCHIVE" in
	*/*) ;;
	*) fail "SOURCE_ARCHIVE must include a directory" ;;
esac
mkdir -p "$(dirname "$SOURCE_ARCHIVE")"
archive_dir=$(cd "$(dirname "$SOURCE_ARCHIVE")" && pwd)
archive_name=$(basename "$SOURCE_ARCHIVE")
case "$archive_name" in
	*[!A-Za-z0-9._+-]* | '') fail "SOURCE_ARCHIVE basename has unsupported characters" ;;
esac
archive="$archive_dir/$archive_name"

[ -d "$SOURCE_ROOT" ] || fail "SOURCE_ROOT is not a directory: $SOURCE_ROOT"
[ -f "$SOURCE_ROOT/openwrt/serpent-wrt/Makefile" ] ||
	fail "missing openwrt/serpent-wrt/Makefile under SOURCE_ROOT"
[ -d "$SOURCE_ROOT/.git" ] || fail "SOURCE_ROOT must be a git checkout"

actual_commit=$(git -C "$SOURCE_ROOT" rev-parse HEAD)
[ "$actual_commit" = "$SOURCE_COMMIT" ] ||
	fail "checkout is $actual_commit, expected $SOURCE_COMMIT"
git -C "$SOURCE_ROOT" cat-file -e "$SOURCE_COMMIT^{commit}" ||
	fail "source commit is unavailable"

source_date=$(git -C "$SOURCE_ROOT" show -s --format=%cs "$SOURCE_COMMIT")
case "$source_date" in
	[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;;
	*) fail "source commit has an invalid commit date: $source_date" ;;
esac

source_subdir="serpent-wrt-$APK_VERSION"
archive_tmp="$archive_dir/.${archive_name}.tar.$$"
archive_part="$archive_dir/.${archive_name}.$$"
trap 'rm -f "$archive_tmp" "$archive_part"' EXIT HUP INT TERM

git -C "$SOURCE_ROOT" archive --format=tar \
	--prefix="$source_subdir/" \
	--output="$archive_tmp" "$SOURCE_COMMIT"
gzip -n -c "$archive_tmp" > "$archive_part"
mv "$archive_part" "$archive"
rm -f "$archive_tmp"
trap - EXIT HUP INT TERM
chmod 0644 "$archive"

source_hash=$(sha256sum "$archive" | cut -d' ' -f1)
case "$source_hash" in
	*[!0-9a-f]* | '') fail "could not hash the source archive" ;;
esac
[ "${#source_hash}" -eq 64 ] || fail "invalid source archive hash"

recipe="$SOURCE_ROOT/openwrt/serpent-wrt/Makefile"
tmp="$recipe.tmp.$$"
trap 'rm -f "$tmp"' EXIT HUP INT TERM

sed -E \
	-e "s|^PKG_VERSION:=.*|PKG_VERSION:=$APK_VERSION|" \
	-e "s|^PKG_SOURCE_DATE:=.*|PKG_SOURCE_DATE:=$source_date|" \
	-e "s|^PKG_SOURCE_VERSION:=.*|PKG_SOURCE_VERSION:=$SOURCE_COMMIT|" \
	-e "s|^PKG_SOURCE_SUBDIR:=.*|PKG_SOURCE_SUBDIR:=$source_subdir|" \
	-e "s|^PKG_SOURCE_URL:=.*|PKG_SOURCE_URL:=file://$archive_dir|" \
	-e "s|^PKG_HASH:=.*|PKG_HASH:=$source_hash|" \
	-e "s|^([[:space:]]*main\.version=).*|\\1$PACKAGE_VERSION \\\\|" \
	"$recipe" > "$tmp"
mv "$tmp" "$recipe"
rm -f "$tmp"

[ "$(sed -n 's/^PKG_VERSION:=//p' "$recipe")" = "$APK_VERSION" ] ||
	fail "failed to pin PKG_VERSION"
[ "$(sed -n 's/^PKG_SOURCE_DATE:=//p' "$recipe")" = "$source_date" ] ||
	fail "failed to pin PKG_SOURCE_DATE"
[ "$(sed -n 's/^PKG_SOURCE_VERSION:=//p' "$recipe")" = "$SOURCE_COMMIT" ] ||
	fail "failed to pin PKG_SOURCE_VERSION"
[ "$(sed -n 's/^PKG_SOURCE_SUBDIR:=//p' "$recipe")" = "$source_subdir" ] ||
	fail "failed to pin PKG_SOURCE_SUBDIR"
[ "$(sed -n 's/^PKG_SOURCE_URL:=//p' "$recipe")" = "file://$archive_dir" ] ||
	fail "failed to pin PKG_SOURCE_URL"
[ "$(sed -n 's/^PKG_HASH:=//p' "$recipe")" = "$source_hash" ] ||
	fail "failed to pin PKG_HASH"
# The package version is the OpenWrt APK version; the binary reports the human
# release version.  PKG_RELEASE remains the recipe's own package revision.
grep -Fq "main.version=$PACKAGE_VERSION" "$recipe" ||
	fail "failed to pin main.version"

echo "Pinned source: commit=$SOURCE_COMMIT tree=$(git -C "$SOURCE_ROOT" rev-parse "$SOURCE_COMMIT^{tree}")"
echo "Package: version=$APK_VERSION release=$(sed -n 's/^PKG_RELEASE:=//p' "$recipe")"
echo "Source archive: $archive sha256=$source_hash"
