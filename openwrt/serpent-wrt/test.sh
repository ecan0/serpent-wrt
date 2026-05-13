#!/bin/sh

set -eu

command -v serpent-wrt >/dev/null
command -v wget >/dev/null

test -x /usr/sbin/serpent-wrt
test -x /etc/init.d/serpent-wrt
test -f /etc/serpent-wrt/serpent-wrt.yaml
test -f /etc/serpent-wrt/threat-feed.txt

/bin/sh -n /etc/init.d/serpent-wrt
serpent-wrt -h 2>&1 | grep -q "path to config file"
serpent-wrt -version | grep -q "serpent-wrt version="
serpent-wrt --config /etc/serpent-wrt/serpent-wrt.yaml configtest | grep -q "config OK"
/etc/init.d/serpent-wrt configtest | grep -q "config OK"

api_get() {
	path=$1
	tries=10
	while [ "$tries" -gt 0 ]; do
		if body=$(wget -q -T 2 -O - "http://127.0.0.1:8080$path" 2>/dev/null); then
			printf '%s\n' "$body"
			return 0
		fi
		tries=$((tries - 1))
		sleep 1
	done
	echo "API GET $path did not become ready" >&2
	return 1
}

api_post() {
	path=$1
	wget -q -T 3 -O - --post-data='' "http://127.0.0.1:8080$path"
}

api_get /healthz | grep -q '"status":"ok"'
api_get /status | grep -q '"setup_state":"disabled"'
api_get /stats | grep -q '"flows_seen"'
api_post /reload | grep -q '"status":"reloaded"'

/etc/init.d/serpent-wrt reload
/etc/init.d/serpent-wrt restart
/etc/init.d/serpent-wrt status
api_get /healthz | grep -q '"status":"ok"'
