BINARY  := serpent-wrt
VERSION ?= 0.2.0
COMMIT  ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)
LDFLAGS := -trimpath -ldflags="-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)"

DEPLOY_HOST ?= root@openwrt-x86-64
DEPLOY_BIN  := /usr/sbin/serpent-wrt
DEPLOY_CONF := /etc/serpent-wrt
SSH         := ssh
SCP         := scp -O

.PHONY: build cross build-openwrt-targets build-openwrt-mips build-openwrt-mipsle
.PHONY: build-openwrt-armv5 build-openwrt-armv7 build-openwrt-arm64
.PHONY: build-openwrt-riscv64 build-openwrt-x86 build-openwrt-x86-64
.PHONY: run test fmt lint clean deps openwrt-docs ipk-glinet deploy-setup
.PHONY: deploy-x86-64 deploy-x86 openwrt-runtime-test

deps:
	go mod download

build: deps
	mkdir -p bin
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/serpent-wrt

# Cross-compile for common OpenWrt targets.
cross: build-openwrt-targets

build-openwrt-targets: build-openwrt-mips build-openwrt-mipsle
build-openwrt-targets: build-openwrt-armv5 build-openwrt-armv7 build-openwrt-arm64
build-openwrt-targets: build-openwrt-riscv64 build-openwrt-x86 build-openwrt-x86-64

build-openwrt-mips: deps
	mkdir -p bin
	GOOS=linux GOARCH=mips GOMIPS=softfloat go build $(LDFLAGS) -o bin/$(BINARY)-openwrt-mips ./cmd/serpent-wrt

build-openwrt-mipsle: deps
	mkdir -p bin
	GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build $(LDFLAGS) -o bin/$(BINARY)-openwrt-mipsle ./cmd/serpent-wrt

build-openwrt-armv5: deps
	mkdir -p bin
	GOOS=linux GOARCH=arm GOARM=5 go build $(LDFLAGS) -o bin/$(BINARY)-openwrt-armv5 ./cmd/serpent-wrt

build-openwrt-armv7: deps
	mkdir -p bin
	GOOS=linux GOARCH=arm GOARM=7 go build $(LDFLAGS) -o bin/$(BINARY)-openwrt-armv7 ./cmd/serpent-wrt

build-openwrt-arm64: deps
	mkdir -p bin
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY)-openwrt-arm64 ./cmd/serpent-wrt

build-openwrt-riscv64: deps
	mkdir -p bin
	GOOS=linux GOARCH=riscv64 go build $(LDFLAGS) -o bin/$(BINARY)-openwrt-riscv64 ./cmd/serpent-wrt

build-openwrt-x86: deps
	mkdir -p bin
	GOOS=linux GOARCH=386 go build $(LDFLAGS) -o bin/$(BINARY)-openwrt-x86 ./cmd/serpent-wrt

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
	@echo "Setup complete on $(DEPLOY_HOST). Run 'make deploy-x86' to push the binary and run smoke checks."

# The current lab VM is named openwrt-x86-64, but it runs OpenWrt x86/generic
# (i386_pentium4). Keep the runtime deploy on the 32-bit x86 build.
openwrt-runtime-test: build-openwrt-x86
	OPENWRT_HOST=$(DEPLOY_HOST) OPENWRT_BINARY=bin/$(BINARY)-openwrt-x86 sh scripts/openwrt-runtime-test.sh

deploy-x86: openwrt-runtime-test

deploy-x86-64: deploy-x86

# Legacy direct .ipk assembly for GL.iNet MT7986AV (aarch64_cortex-a53).
# Prefer the feed package in openwrt/ for reproducible SDK/buildroot builds.
# Requires GNU ar. On macOS: brew install binutils
# then export PATH="/opt/homebrew/opt/binutils/bin:$PATH"
ipk-glinet:
	VERSION=$(VERSION) sh scripts/package-glinet.sh
