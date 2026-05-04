#!/bin/sh

set -eu

command -v serpent-wrt >/dev/null

test -x /usr/sbin/serpent-wrt
test -x /etc/init.d/serpent-wrt
test -f /etc/serpent-wrt/serpent-wrt.yaml
test -f /etc/serpent-wrt/threat-feed.txt

/bin/sh -n /etc/init.d/serpent-wrt
serpent-wrt -h 2>&1 | grep -q "path to config file"
serpent-wrt -version | grep -q "serpent-wrt version="
