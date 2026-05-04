BINARY  := serpent-wrt
VERSION ?= 0.1.0-dev
COMMIT  ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)
LDFLAGS := -trimpath -ldflags="-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)"

DEPLOY_HOST ?= root@openwrt-x86-64
DEPLOY_BIN  := /usr/sbin/serpent-wrt
DEPLOY_CONF := /etc/serpent-wrt
SSH         := ssh
SCP         := scp -O

.PHONY: build cross build-openwrt-x86-64 run test fmt lint clean deps openwrt-docs ipk-glinet deploy-setup deploy-x86-64 deploy-x86 openwrt-runtime-test

deps:
	go mod download

build: deps
	mkdir -p bin
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/serpent-wrt

# Cross-compile for common OpenWrt targets.
cross: deps
	mkdir -p bin
	GOOS=linux GOARCH=mipsle                  go build $(LDFLAGS) -o bin/$(BINARY)-linux-mipsle   ./cmd/serpent-wrt
	GOOS=linux GOARCH=mips                    go build $(LDFLAGS) -o bin/$(BINARY)-linux-mips     ./cmd/serpent-wrt
	GOOS=linux GOARCH=arm   GOARM=7           go build $(LDFLAGS) -o bin/$(BINARY)-linux-armv7    ./cmd/serpent-wrt
	GOOS=linux GOARCH=arm64                   go build $(LDFLAGS) -o bin/$(BINARY)-linux-arm64    ./cmd/serpent-wrt
	GOOS=linux GOARCH=amd64                   go build $(LDFLAGS) -o bin/$(BINARY)-linux-amd64    ./cmd/serpent-wrt

build-openwrt-x86-64: deps
	mkdir -p bin
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY)-openwrt-x86-64 ./cmd/serpent-wrt

run:
	go run ./cmd/serpent-wrt --config ./configs/serpent-wrt.example.yaml

test:
	go test ./...

fmt:
	go fmt ./...

lint:
	go vet ./...

clean:
	rm -rf bin/

openwrt-docs:
	powershell -ExecutionPolicy Bypass -File scripts/fetch-openwrt-dev-guide.ps1

# First-time VM setup: copies init script, config, and threat feed.
# Override target with: make deploy-setup DEPLOY_HOST=root@<ip>
deploy-setup:
	$(SSH) $(DEPLOY_HOST) "mkdir -p $(DEPLOY_CONF)"
	$(SCP) contrib/init.d/serpent-wrt $(DEPLOY_HOST):/etc/init.d/serpent-wrt
	$(SSH) $(DEPLOY_HOST) "chmod 755 /etc/init.d/serpent-wrt"
	$(SCP) configs/serpent-wrt.openwrt.yaml $(DEPLOY_HOST):$(DEPLOY_CONF)/serpent-wrt.yaml
	$(SCP) testdata/threat-feed.txt $(DEPLOY_HOST):$(DEPLOY_CONF)/threat-feed.txt
	$(SSH) $(DEPLOY_HOST) "/etc/init.d/serpent-wrt enable"
	@echo "Setup complete on $(DEPLOY_HOST). Run 'make deploy-x86-64' to push the binary and run smoke checks."

openwrt-runtime-test: build-openwrt-x86-64
	OPENWRT_HOST=$(DEPLOY_HOST) OPENWRT_BINARY=bin/$(BINARY)-openwrt-x86-64 sh scripts/openwrt-runtime-test.sh

deploy-x86-64: openwrt-runtime-test

deploy-x86: deploy-x86-64

# Legacy direct .ipk assembly for GL.iNet MT7986AV (aarch64_cortex-a53).
# Prefer the feed package in openwrt/ for reproducible SDK/buildroot builds.
# Requires GNU ar. On macOS: brew install binutils
# then export PATH="/opt/homebrew/opt/binutils/bin:$PATH"
ipk-glinet:
	VERSION=$(VERSION) sh scripts/package-glinet.sh
