CC ?= gcc
GO ?= $(or $(shell command -v go 2>/dev/null),/usr/local/go/bin/go)
CFLAGS ?= -std=c11 -Wall -Wextra -Werror
BUILD_DIR ?= /var/lib/oncache/build/FNCache/tests
TARGET := $(BUILD_DIR)/abi-layout
BEHAVIOR_TARGET := $(BUILD_DIR)/bpf-behavior
RUN ?= sudo -n
INCLUDES := -I../bpf/include
BPF_DIR := ../bpf
NORMAL_OBJ := $(BUILD_DIR)/bpf-normal/tc_prog_kern.o
ADJUST_OBJ := $(BUILD_DIR)/bpf-fail-adjust/tc_prog_kern.o
STORE_OBJ := $(BUILD_DIR)/bpf-fail-store/tc_prog_kern.o
REDIRECT_OBJ := $(BUILD_DIR)/bpf-fail-redirect/tc_prog_kern.o
INTEGRATION_BUILD_DIR ?= $(BUILD_DIR)/m2-integration
INTEGRATION_BPF_OBJ := $(INTEGRATION_BUILD_DIR)/bpf/tc_prog_kern.o

.PHONY: all test test-bpf test-m2-integration test-m2-local-runtime helm-lint helm-template helm-test clean

all: $(TARGET)

$(TARGET): abi_layout.c ../bpf/include/oncache_abi.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CFLAGS) $(INCLUDES) -o "$@" "$<"

test: $(TARGET)
	"$(TARGET)"

$(NORMAL_OBJ):
	$(MAKE) -C "$(BPF_DIR)" BUILD_DIR="$(BUILD_DIR)/bpf-normal"

$(ADJUST_OBJ):
	$(MAKE) -C "$(BPF_DIR)" BUILD_DIR="$(BUILD_DIR)/bpf-fail-adjust" CFLAGS="-DONCACHE_TEST_FAIL_ADJUST_ROOM"

$(STORE_OBJ):
	$(MAKE) -C "$(BPF_DIR)" BUILD_DIR="$(BUILD_DIR)/bpf-fail-store" CFLAGS="-DONCACHE_TEST_FAIL_STORE_BYTES"

$(REDIRECT_OBJ):
	$(MAKE) -C "$(BPF_DIR)" BUILD_DIR="$(BUILD_DIR)/bpf-fail-redirect" CFLAGS="-DONCACHE_TEST_FAIL_REDIRECT"

$(BEHAVIOR_TARGET): bpf_behavior_test.c ../bpf/include/oncache_abi.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CFLAGS) $(INCLUDES) -o "$@" "$<" $$(pkg-config --libs libbpf) -lpthread

test-bpf: $(BEHAVIOR_TARGET) $(NORMAL_OBJ) $(ADJUST_OBJ) $(STORE_OBJ) $(REDIRECT_OBJ)
	$(RUN) "$(BEHAVIOR_TARGET)" "$(NORMAL_OBJ)" "$(ADJUST_OBJ)" "$(STORE_OBJ)" "$(REDIRECT_OBJ)"

$(INTEGRATION_BPF_OBJ):
	$(MAKE) -C "$(BPF_DIR)" BUILD_DIR="$(INTEGRATION_BUILD_DIR)/bpf"

test-m2-integration: $(INTEGRATION_BPF_OBJ)
	$(RUN) env ONCACHE_M2_INTEGRATION=1 ONCACHE_BPF_ELF="$(abspath $(INTEGRATION_BPF_OBJ))" "$(GO)" test -tags=integration -count=1 ../tests/integration

M2_LOCAL_BUILD_DIR ?= $(BUILD_DIR)/m2-local-runtime
M2_LOCAL_BIN := $(M2_LOCAL_BUILD_DIR)/oncache-agent
M2_RUNTIME_MANIFEST ?=
M2_RUNTIME_PIN_ROOT ?=
M2_RUNTIME_STATE_PATH ?=
M2_RUNTIME_MARKER_COMMENT ?=
M2_RUNTIME_UNDERLAY_IFNAME ?=
M2_RUNTIME_CLEANUP ?= 0

$(M2_LOCAL_BIN):
	@mkdir -p "$(M2_LOCAL_BUILD_DIR)"
	$(GO) build -o "$@" ../cmd/oncache-agent

test-m2-local-runtime: $(M2_LOCAL_BIN)
	test -n "$(M2_RUNTIME_MANIFEST)"
	test -n "$(M2_RUNTIME_PIN_ROOT)"
	test -n "$(M2_RUNTIME_STATE_PATH)"
	test -n "$(M2_RUNTIME_MARKER_COMMENT)"
	test -n "$(M2_RUNTIME_UNDERLAY_IFNAME)"
	$(RUN) env PATH="/opt/oncache/bin:/opt/oncache/sbin:/usr/local/go/bin:/usr/lib/llvm-18/bin:/usr/local/sbin:/usr/sbin:/sbin:$$PATH" ONCACHE_M2_LOCAL=1 ONCACHE_AGENT_BIN="$(abspath $(M2_LOCAL_BIN))" ONCACHE_STATIC_MANIFEST="$(abspath $(M2_RUNTIME_MANIFEST))" ONCACHE_M2_PIN_ROOT="$(M2_RUNTIME_PIN_ROOT)" ONCACHE_M2_STATE_PATH="$(M2_RUNTIME_STATE_PATH)" ONCACHE_M2_MARKER_COMMENT="$(M2_RUNTIME_MARKER_COMMENT)" ONCACHE_M2_UNDERLAY_IFNAME="$(M2_RUNTIME_UNDERLAY_IFNAME)" ONCACHE_M2_CLEANUP="$(M2_RUNTIME_CLEANUP)" "$(GO)" test -tags=integration -count=1 -run '^TestM2LocalStaticRuntime$$' ../tests/integration

HELM ?= helm
CHART_DIR ?= ../charts/oncache

helm-lint:
	command -v "$(HELM)" >/dev/null
	"$(HELM)" lint "$(CHART_DIR)"

helm-template:
	command -v "$(HELM)" >/dev/null
	"$(HELM)" template oncache "$(CHART_DIR)"

helm-test:
	command -v "$(HELM)" >/dev/null
	@set -eu; \
	rendered="$$(mktemp)"; \
	trap 'rm -f "$$rendered"' EXIT; \
	"$(HELM)" template oncache "$(CHART_DIR)" \
		--set config.server.listenAddress=:9191 \
		--set metrics.port=9191 \
		--set metrics.enabled=true >"$$rendered"; \
	grep -Fq 'listenAddress: ":9191"' "$$rendered"; \
	grep -Fq 'containerPort: 9191' "$$rendered"; \
	grep -Fq '      port: 9191' "$$rendered"; \
	grep -Fq 'targetPort: http' "$$rendered"; \
	"$(HELM)" template oncache "$(CHART_DIR)" \
		--set 'config.server.listenAddress=[::1]:9191' \
		--set metrics.port=9191 >/dev/null; \
	if "$(HELM)" template oncache "$(CHART_DIR)" \
		--set config.server.listenAddress=:9191 \
		--set metrics.port=9090 \
		--set metrics.enabled=true >/dev/null 2>&1; then \
		echo "expected mismatched HTTP ports to fail Helm rendering"; \
		exit 1; \
	fi; \
	if "$(HELM)" template oncache "$(CHART_DIR)" \
		--set config.server.listenAddress=::1 \
		--set metrics.port=1 >/dev/null 2>&1; then \
		echo "expected raw IPv6 listen address without a port to fail Helm rendering"; \
		exit 1; \
	fi

clean:
	rm -f "$(TARGET)" "$(BEHAVIOR_TARGET)"

-include Makefile.m3e2e
-include Makefile.m4e2e
