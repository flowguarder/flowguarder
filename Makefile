.PHONY: build test lint vet generate clean

build:
	go build -o bin/flowguarder ./cmd/flowguarder

test:
	go test ./...

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not found, skipping lint"; \
	fi

vet:
	go vet ./...

generate:
	@echo "no-op"

clean:
	rm -rf bin/
