BINARY=serpent-wrt

.PHONY: build run test fmt lint

build:
	go build -o bin/$(BINARY) ./cmd/serpent-wrt

run:
	go run ./cmd/serpent-wrt --config ./configs/serpent-wrt.example.yaml

test:
	go test ./...

fmt:
	go fmt ./...

lint:
	go vet ./...
