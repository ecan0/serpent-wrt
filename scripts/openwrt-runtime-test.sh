#!/bin/sh

set -eu

BINARY=${OPENWRT_BINARY:-bin/serpent-wrt-openwrt-x86-64}
INIT=${OPENWRT_INIT:-openwrt/serpent-wrt/files/serpent-wrt.init}
CONFIG=${OPENWRT_CONFIG:-openwrt/serpent-wrt/files/serpent-wrt.yaml}
FEED=${OPENWRT_FEED:-openwrt/serpent-wrt/files/threat-feed.txt}
TEST=${OPENWRT_TEST:-openwrt/serpent-wrt/test.sh}
REMOTE_TMP=${OPENWRT_REMOTE_TMP:-/tmp/serpent-wrt-ci}
OPENWRT_USER=${OPENWRT_USER:-root}

if [ -n "${OPENWRT_TARGET:-}" ]; then
	TARGET=$OPENWRT_TARGET
elif [ -n "${OPENWRT_HOST:-}" ]; then
	case "$OPENWRT_HOST" in
		*@*) TARGET=$OPENWRT_HOST ;;
		*) TARGET="$OPENWRT_USER@$OPENWRT_HOST" ;;
	esac
else
	echo "OPENWRT_HOST or OPENWRT_TARGET is required" >&2
	exit 1
fi

for file in "$BINARY" "$INIT" "$CONFIG" "$FEED" "$TEST"; do
	if [ ! -f "$file" ]; then
		echo "missing required file: $file" >&2
		exit 1
	fi
done

SSH=${SSH:-ssh}
SCP=${SCP:-scp}
SCP_OPTS=${SCP_OPTS:--O}
SSH_OPTS=${OPENWRT_SSH_OPTS:--o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null}
KEY_OPT=

if [ -n "${SSH_KEY_PATH:-}" ]; then
	KEY_OPT="-i $SSH_KEY_PATH"
fi

$SSH $KEY_OPT $SSH_OPTS "$TARGET" "mkdir -p '$REMOTE_TMP' /etc/serpent-wrt"
$SCP $SCP_OPTS $KEY_OPT $SSH_OPTS "$BINARY" "$TARGET:$REMOTE_TMP/serpent-wrt"
$SCP $SCP_OPTS $KEY_OPT $SSH_OPTS "$INIT" "$TARGET:$REMOTE_TMP/serpent-wrt.init"
$SCP $SCP_OPTS $KEY_OPT $SSH_OPTS "$CONFIG" "$TARGET:$REMOTE_TMP/serpent-wrt.yaml"
$SCP $SCP_OPTS $KEY_OPT $SSH_OPTS "$FEED" "$TARGET:$REMOTE_TMP/threat-feed.txt"
$SCP $SCP_OPTS $KEY_OPT $SSH_OPTS "$TEST" "$TARGET:$REMOTE_TMP/test.sh"

$SSH $KEY_OPT $SSH_OPTS "$TARGET" "
	set -eu
	mv '$REMOTE_TMP/serpent-wrt' /usr/sbin/serpent-wrt
	mv '$REMOTE_TMP/serpent-wrt.init' /etc/init.d/serpent-wrt
	mv '$REMOTE_TMP/serpent-wrt.yaml' /etc/serpent-wrt/serpent-wrt.yaml
	mv '$REMOTE_TMP/threat-feed.txt' /etc/serpent-wrt/threat-feed.txt
	chmod 0755 /usr/sbin/serpent-wrt /etc/init.d/serpent-wrt '$REMOTE_TMP/test.sh'
	chmod 0644 /etc/serpent-wrt/serpent-wrt.yaml /etc/serpent-wrt/threat-feed.txt
	/etc/init.d/serpent-wrt enable
	/etc/init.d/serpent-wrt restart
	/bin/sh '$REMOTE_TMP/test.sh'
	/etc/init.d/serpent-wrt status
"
