BINARY  := serpent-wrt
VERSION ?= 0.1.0-dev
LDFLAGS := -trimpath -ldflags="-s -w"

.PHONY: build cross run test fmt lint clean deps ipk-glinet

deps:
	go mod download

build: deps
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/serpent-wrt

# Cross-compile for common OpenWRT targets.
cross: deps
	GOOS=linux GOARCH=mipsle                  go build $(LDFLAGS) -o bin/$(BINARY)-linux-mipsle   ./cmd/serpent-wrt
	GOOS=linux GOARCH=mips                    go build $(LDFLAGS) -o bin/$(BINARY)-linux-mips     ./cmd/serpent-wrt
	GOOS=linux GOARCH=arm   GOARM=7           go build $(LDFLAGS) -o bin/$(BINARY)-linux-armv7    ./cmd/serpent-wrt
	GOOS=linux GOARCH=arm64                   go build $(LDFLAGS) -o bin/$(BINARY)-linux-arm64    ./cmd/serpent-wrt
	GOOS=linux GOARCH=amd64                   go build $(LDFLAGS) -o bin/$(BINARY)-linux-amd64    ./cmd/serpent-wrt

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

# Build an OpenWRT .ipk for GL.iNet MT7986AV (aarch64_cortex-a53).
# Requires GNU ar. On macOS: brew install binutils
# then export PATH="/opt/homebrew/opt/binutils/bin:$PATH"
ipk-glinet:
	VERSION=$(VERSION) sh scripts/package-glinet.sh
