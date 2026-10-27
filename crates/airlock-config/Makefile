SHELL := bash
.SHELLFLAGS := -euo pipefail -c
ROOT := $(abspath ../..)
LOG_DIR := $(ROOT)/.airlock-logs/rusix-topology
TARGET_DIR := $(ROOT)/crates/target
CAPTURE_SENDER ?= $(ROOT)/crates/target/debug/airlock-sys-gui-service
CAPTURE_RECEIVER ?= $(ROOT)/crates/target/debug/airlock-vm-service
PLANNER ?= $(ROOT)/crates/target/debug/airlock-dom0-service
# An explicit inspection scenario, not an observation of the running machine.
RUNNING_VMS ?= sys-net sys-firewall sys-gui sys-ctrl usr-assistant usr-home

.PHONY: build generate generate-machine generate-desktop generate-packages generate-flakes generate-runtime check verify review plan

build:
	@mkdir -p "$(LOG_DIR)"
	cargo build -p airlock-config --examples --bin airlock-config --locked --target-dir "$(TARGET_DIR)" --message-format=json > "$(LOG_DIR)/build-artifacts.jsonl" 2> "$(LOG_DIR)/build.log"

AIRLOCK_PREPARED_CACHE ?= $(ROOT)/target/nix

prepare generate generate-packages generate-desktop generate-machine generate-flakes generate-runtime generate-all: build
	"$(TARGET_DIR)/debug/airlock-config" prepare "$(ROOT)" "$(AIRLOCK_PREPARED_CACHE)"


check:
	@mkdir -p "$(LOG_DIR)"
	$(MAKE) -C "$(ROOT)" rust-fmt-check 2>&1 | tee "$(LOG_DIR)/fmt.log"
	cargo clippy -p airlock-config --all-targets --locked --target-dir "$(TARGET_DIR)" -- -D warnings 2>&1 | tee "$(LOG_DIR)/clippy.log"

# Evaluation consumes explicitly prepared sources, authoring tools and Cargo receipts.
verify:
	$(MAKE) -C "$(ROOT)" test-nix AIRLOCK_RUSIX_LOG_DIR="$(LOG_DIR)"

# Review and planning consume explicit evaluation artifacts selected by the caller.
BASELINE ?=
CANDIDATE ?=
review:
	@test -n "$(BASELINE)" -a -n "$(CANDIDATE)" || { echo 'Set BASELINE and CANDIDATE to evaluated machine JSON files' >&2; exit 1; }
	"$(TARGET_DIR)/debug/airlock-config" diff "$(BASELINE)" "$(CANDIDATE)"

plan:
	@test -n "$(BASELINE)" -a -n "$(CANDIDATE)" || { echo 'Set BASELINE and CANDIDATE to evaluated machine JSON files' >&2; exit 1; }
	"$(TARGET_DIR)/debug/airlock-config" plan "$(PLANNER)" \
	  "$(BASELINE)" "$(CANDIDATE)" "$(LOG_DIR)/plan" $(RUNNING_VMS)

# Preparation verifies an existing content-addressed artifact before reuse.
.PHONY: prepare generate-all check-generated
check-generated: prepare
