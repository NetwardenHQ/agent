# Netwarden Agent Build Configuration
BINARY_NAME=netwarden
VERSION=$(shell cat VERSION 2>/dev/null || echo "1.0.0")
BUILD_DATE=$(shell date "+%Y-%m-%d %H:%M:%S")
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Build flags
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION) -X 'main.buildDate=$(BUILD_DATE)' -X main.gitCommit=$(GIT_COMMIT)"

# Default target
.PHONY: all
all: clean build

# Build for current platform
.PHONY: build
build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/netwarden

# Cross-compile for all platforms
.PHONY: build-all
build-all: clean
	@echo "Building for all platforms..."
	
	# Linux AMD64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 ./cmd/netwarden
	
	# Linux ARM64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-arm64 ./cmd/netwarden
	
	# Linux ARM (32-bit)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-arm ./cmd/netwarden
	
	# Windows AMD64
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-windows-amd64.exe ./cmd/netwarden
	
	# Windows ARM64
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-windows-arm64.exe ./cmd/netwarden
	
	# macOS AMD64
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-amd64 ./cmd/netwarden
	
	# macOS ARM64 (Apple Silicon)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-arm64 ./cmd/netwarden

# Individual platform builds
.PHONY: linux
linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 ./cmd/netwarden
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-arm64 ./cmd/netwarden
	CGO_ENABLED=0 GOOS=linux GOARCH=arm go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-arm ./cmd/netwarden

.PHONY: windows
windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-windows-amd64.exe ./cmd/netwarden
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-windows-arm64.exe ./cmd/netwarden

.PHONY: macos
macos:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-amd64 ./cmd/netwarden
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-arm64 ./cmd/netwarden

# Development build (with debug info)
.PHONY: dev
dev:
	CGO_ENABLED=0 go build -race -o bin/$(BINARY_NAME)-dev ./cmd/netwarden

# Test the agent
.PHONY: test
test:
	go test -v ./...

# Run the agent (development)
.PHONY: run
run: build
	./bin/$(BINARY_NAME) -config netwarden.conf

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf bin/
	mkdir -p bin/

# Install dependencies
.PHONY: deps
deps:
	go mod download
	go mod tidy

# Use existing full configuration template
# The full config is available at build/netwarden.conf.example (147 lines)

# Package releases
.PHONY: package
package: build-all
	@echo "Creating release packages..."
	cd bin && \
	tar -czf $(BINARY_NAME)-linux-amd64.tar.gz $(BINARY_NAME)-linux-amd64 && \
	tar -czf $(BINARY_NAME)-linux-arm64.tar.gz $(BINARY_NAME)-linux-arm64 && \
	tar -czf $(BINARY_NAME)-linux-arm.tar.gz $(BINARY_NAME)-linux-arm && \
	zip $(BINARY_NAME)-windows-amd64.zip $(BINARY_NAME)-windows-amd64.exe && \
	zip $(BINARY_NAME)-windows-arm64.zip $(BINARY_NAME)-windows-arm64.exe && \
	tar -czf $(BINARY_NAME)-darwin-amd64.tar.gz $(BINARY_NAME)-darwin-amd64 && \
	tar -czf $(BINARY_NAME)-darwin-arm64.tar.gz $(BINARY_NAME)-darwin-arm64

# Check binary sizes
.PHONY: size
size: build-all
	@echo "Binary sizes:"
	@ls -lh bin/ | grep $(BINARY_NAME)

# Show build info
.PHONY: info
info:
	@echo "Binary: $(BINARY_NAME)"
	@echo "Version: $(VERSION)"
	@echo "Build time: $(BUILD_TIME)"
	@echo "Git commit: $(GIT_COMMIT)"

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build      - Build for current platform"
	@echo "  build-all  - Cross-compile for all platforms"
	@echo "  linux      - Build for Linux AMD64"
	@echo "  windows    - Build for Windows AMD64"
	@echo "  macos      - Build for macOS (both AMD64 and ARM64)"
	@echo "  dev        - Development build with race detection"
	@echo "  test       - Run tests"
	@echo "  run        - Build and run agent"
	@echo "  clean      - Clean build artifacts"
	@echo "  deps       - Install/update dependencies"
	@echo "  config     - Full config available at build/netwarden.conf.example"
	@echo "  package    - Create release packages"
	@echo "  size       - Show binary sizes"
	@echo "  info       - Show build information"
	@echo "  help       - Show this help"