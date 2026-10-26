SHELL := bash

ifneq ($(wildcard /run/media/user/data/.),)
AIRLOCK_DATA_ROOT ?= /run/media/user/data/airlock
endif

ifneq ($(strip $(AIRLOCK_DATA_ROOT)),)
AIRLOCK_VM_DIR ?= $(AIRLOCK_DATA_ROOT)/vm
AIRLOCK_LOG_DIR ?= $(AIRLOCK_DATA_ROOT)/logs
AIRLOCK_QUBES_CACHE_DIR ?= $(AIRLOCK_DATA_ROOT)/cache/rpms
AIRLOCK_RESULT_LINK_DIR ?= $(AIRLOCK_DATA_ROOT)/result-links
AIRLOCK_NIX_ROOT ?= $(AIRLOCK_DATA_ROOT)/nix-root
AIRLOCK_NIX_STORE ?= $(AIRLOCK_NIX_ROOT)
TMPDIR ?= $(AIRLOCK_DATA_ROOT)/tmp
XDG_CACHE_HOME ?= $(AIRLOCK_DATA_ROOT)/cache/xdg
export AIRLOCK_DATA_ROOT
export AIRLOCK_VM_DIR
export AIRLOCK_LOG_DIR
export AIRLOCK_QUBES_CACHE_DIR
export AIRLOCK_RESULT_LINK_DIR
export AIRLOCK_NIX_ROOT
export AIRLOCK_NIX_STORE
export TMPDIR
export XDG_CACHE_HOME
endif

AIRLOCK_DEV ?= $(if $(AIRLOCK_DEV_BIN),$(AIRLOCK_DEV_BIN) with-environment --,./crates/airlock-dev/scripts/airlock-dev.sh)
AIRLOCK_NIX ?= $(AIRLOCK_DEV) nix --
VM_IMAGE_MODE ?= dev
ifeq ($(VM_IMAGE_MODE),dev)
VM_IMAGE_MODE_SUFFIX := dev
else ifeq ($(VM_IMAGE_MODE),release)
VM_IMAGE_MODE_SUFFIX := release
else
$(error VM_IMAGE_MODE must be dev or release)
endif
VM_IMAGE_ATTR ?= airlock-vm-$(VM_IMAGE_MODE_SUFFIX)-image
VM_GUI_IMAGE_ATTR ?= airlock-vm-gui-$(VM_IMAGE_MODE_SUFFIX)-image
VM_GUI_CONFIG_IMAGE_ATTR ?= airlock-vm-gui-config-$(VM_IMAGE_MODE_SUFFIX)-image
VM_GUI_CONFIG_NETWORK_DEBUG_IMAGE_ATTR ?= airlock-vm-gui-config-network-debug-image
VM_GUI_MINIMAL_IMAGE_ATTR ?= airlock-vm-gui-minimal-image
VM_GUI_MINIMAL_DIR ?= $(or $(AIRLOCK_DATA_ROOT),$(CURDIR)/.airlock)/vm-gui-minimal
VM_GUI_MINIMAL_SSH_PORT ?= 2332
AIRLOCK_VM_GDK_BACKEND ?= x11
VM_PARALLEL_IMAGE_ATTR ?= $(VM_GUI_CONFIG_IMAGE_ATTR)
VM_PARALLEL_IMAGE_LINK ?= $(AIRLOCK_RESULT_LINK_DIR)/$(VM_PARALLEL_IMAGE_ATTR)-parallel-shared-result
VM_PARALLEL_BASELINE_ROOT ?= $(or $(AIRLOCK_DATA_ROOT),$(CURDIR)/.airlock)/vm-baselines
VM_PARALLEL_BASELINE_DIR ?= $(VM_PARALLEL_BASELINE_ROOT)/$(VM_PARALLEL_IMAGE_ATTR)-setup
VM_PARALLEL_BASELINE_DISK ?= $(VM_PARALLEL_BASELINE_DIR)/$(VM_PARALLEL_IMAGE_ATTR).qcow2
VM_PARALLEL_BASELINE_OVMF_VARS ?= $(VM_PARALLEL_BASELINE_DIR)/$(VM_PARALLEL_IMAGE_ATTR)-OVMF_VARS.fd
VM_PARALLEL_BASELINE_LOG_DIR ?= $(or $(AIRLOCK_LOG_DIR),$(CURDIR)/.airlock-logs)/vm-baseline
VM_PARALLEL_BASELINE_SSH_PORT ?= 2299
VM_PARALLEL_SSH_BASE_PORT ?= 2300
VM_SLOW_SERIAL_VM_DIR ?= $(or $(AIRLOCK_DATA_ROOT),$(CURDIR)/.airlock)/vm-slow-serial
VM_SLOW_SERIAL_SSH_PORT ?= 2310
VM_FLOW_RUN_SETUP_CONFIG ?= 1

VM_PREBUILD_ATTRS := \
	packages.x86_64-linux.airlock-setup-config \
	packages.x86_64-linux.airlock-config-inputs-import \
	packages.x86_64-linux.airlock-config-vms-smoke \
	packages.x86_64-linux.airlock-nix-closure-domain-smoke \
	packages.x86_64-linux.airlock-dom0-service \
	packages.x86_64-linux.airlock-qubes-vm-kernel \
	$(VM_GUI_CONFIG_IMAGE_ATTR)

TEST_LOG_DIR = $${AIRLOCK_LOG_DIR:-.airlock-logs}
TEST_JOBS ?= 4
TEST_VM_JOBS ?= 2
TEST_WARM_VM_MEMORY ?= 16384

# One committed configuration, one whole-machine release. No per-VM switches.
DEPLOY_PROFILE ?= usb-lab
DEPLOY_DEVELOPMENT_SHELL ?= 0
DEPLOY_HOST_REPAIR ?= 0
DEPLOY_TARGET ?=
DEPLOY_BRIDGE_VM ?=
.PHONY: machine-gui-style-plan machine-gui-style-apply
machine-gui-style-plan machine-gui-style-apply:
	crates/airlock-dev/scripts/airlock-dev.sh gui-style $(patsubst machine-gui-style-%,%,$@) --target "$(DEPLOY_TARGET)"
.PHONY: machine-build machine-plan machine-apply machine-status machine-verify machine-resume machine-rollback machine-guest-plan machine-guest-apply usr-assistant-machine-source
machine-build machine-plan machine-apply machine-status machine-verify machine-resume machine-rollback:
	crates/airlock-dev/scripts/airlock-dev.sh deploy $(patsubst machine-%,%,$@) --profile "$(DEPLOY_PROFILE)" $(if $(DEPLOY_TARGET),--target "$(DEPLOY_TARGET)",) $(if $(filter 1,$(DEPLOY_DEVELOPMENT_SHELL) $(DEPLOY_HOST_REPAIR)),--development-shell,) $(if $(filter 1,$(DEPLOY_HOST_REPAIR)),--host-repair,) $(if $(filter 1,$(UPDATE_COORDINATOR)),--update-coordinator,) $(if $(DEPLOY_BRIDGE_VM),--bridge-vm "$(DEPLOY_BRIDGE_VM)",)
machine-guest-plan machine-guest-apply:
	@test -n "$(DEPLOY_TARGET)" || { echo 'set DEPLOY_TARGET to the Tailscale usr-assistant host'; exit 2; }
	@test -n "$(ADMISSION_RECEIPT)" || { echo 'set ADMISSION_RECEIPT to the receipt path inside usr-assistant'; exit 2; }
	crates/airlock-dev/scripts/airlock-dev.sh deploy $(patsubst machine-%,%,$@) --profile "$(DEPLOY_PROFILE)" --target "$(DEPLOY_TARGET)" --receipt "$(ADMISSION_RECEIPT)" $(if $(filter 1,$(UPDATE_COORDINATOR)),--update-coordinator) $(if $(filter 1,$(DEPLOY_DEVELOPMENT_SHELL)),--development-shell,)
usr-assistant-machine-source:
	@test -n "$(DEPLOY_TARGET)" || { echo 'set DEPLOY_TARGET to the Tailscale usr-assistant host'; exit 2; }
	crates/airlock-dev/scripts/airlock-dev.sh source push --target "$(DEPLOY_TARGET)"
VM_SLOW_DEFAULT_PARALLEL_FLOW_IDS = vm-config-flow vm-nix-closure-flow
VM_SLOW_PARALLEL_FLOW_IDS = $(VM_SLOW_DEFAULT_PARALLEL_FLOW_IDS) vm-config-boot-flow
VM_SLOW_SERIAL_FLOW_IDS = vm-config-boot-activate-flow vm-pool-admission-flow
VM_SLOW_FLOW_IDS = $(VM_SLOW_PARALLEL_FLOW_IDS) $(VM_SLOW_SERIAL_FLOW_IDS)
VM_SLOW_SELECTED_PARALLEL_FLOW_IDS = $(filter $(VM_SLOW_PARALLEL_FLOW_IDS),$(TESTS))
VM_SLOW_SELECTED_SERIAL_FLOW_IDS = $(filter $(VM_SLOW_SERIAL_FLOW_IDS),$(TESTS))
VM_SLOW_SELECTED_UNKNOWN_FLOW_IDS = $(filter-out $(VM_SLOW_FLOW_IDS),$(TESTS))
VM_SLOW_DEFAULT_PARALLEL_TARGETS = $(foreach test,$(VM_SLOW_DEFAULT_PARALLEL_FLOW_IDS),system_vm::vm_flow_$(subst -,_,$(test)))
VM_SLOW_SELECTED_PARALLEL_TARGETS = $(foreach test,$(VM_SLOW_SELECTED_PARALLEL_FLOW_IDS),system_vm::vm_flow_$(subst -,_,$(test)))
VM_SLOW_SELECTED_SERIAL_TARGETS = $(foreach test,$(VM_SLOW_SELECTED_SERIAL_FLOW_IDS),system_vm::vm_flow_$(subst -,_,$(test)))
VM_SLOW_SERIAL_TARGETS = $(foreach test,$(VM_SLOW_SERIAL_FLOW_IDS),system_vm::vm_flow_$(subst -,_,$(test)))

.PHONY: ensure-generated-dirs build test-quick test-nix test-warm test-slow vm-prebuild-shared vm-parallel-prebuild-image vm-parallel-prebuild-baseline vm-image vm-image-dry-run vm-run vm-ssh vm-gui-image vm-gui-image-dry-run vm-gui-run vm-gui-config-image vm-gui-config-image-dry-run vm-gui-config-run vm-gui-config-network-debug-image vm-gui-config-network-debug-run vm-gui-check vm-gui-smoke vm-warm-start vm-warm-sync vm-warm-apply vm-warm-test-config vm-config-setup vm-config-flow vm-config-warm-flow vm-config-boot-flow vm-config-boot-activate-flow vm-nix-closure-flow vm-nix-closure-warm-flow disk-usage gc-auto gc-roots gc-dry-run gc clean clean-generated clean-vm clean-vm-disks clean-result-links clean-logs clean-cache

ensure-generated-dirs:
ifneq ($(strip $(AIRLOCK_DATA_ROOT)),)
	@mkdir -p "$(AIRLOCK_VM_DIR)" "$(AIRLOCK_LOG_DIR)" "$(AIRLOCK_QUBES_CACHE_DIR)" "$(AIRLOCK_RESULT_LINK_DIR)" "$(AIRLOCK_NIX_ROOT)" "$(TMPDIR)" "$(XDG_CACHE_HOME)"
else
	@:
endif

build: ensure-generated-dirs
	$(AIRLOCK_NIX) build .#nixosConfigurations.test.config.system.build.toplevel --out-link "$(AIRLOCK_RESULT_LINK_DIR)/test-system" --print-build-logs --show-trace

# Execution consumes prepared Cargo artifacts; it never builds missing tools.
test-quick: test-native

.PHONY: ctrl-build ctrl-preview ctrl-check
CTRL_BUILD_METHOD ?= cargo
ctrl-build: dev-tools-build
	"$(IMAGE_TOOLS_DIR)/airlock-dev" --repository-root "$(CURDIR)" ctrl-artifact build --builder "$(CTRL_BUILD_METHOD)"

# Nix supplies the native GUI libraries on NixOS. Only this app is built/run.
CTRL_PREVIEW_ARGS ?= --demo
ctrl-preview:
	$(AIRLOCK_NIX) run ./crates\#airlock-sys-ctrl-gui --no-write-lock-file -- $(CTRL_PREVIEW_ARGS)

ctrl-check: rust-spacing
	cargo fmt --manifest-path crates/Cargo.toml --all -- --check
	cargo clippy --locked --manifest-path crates/Cargo.toml -p airlock-sys-ctrl-gui -- -D warnings

.PHONY: airlock-nix-build airlock-nix-check
airlock-nix-build:
	cargo build --locked --release --manifest-path crates/Cargo.toml -p airlock-nix-core -p airlock-cli -p airlock-sys-ctrl-service

airlock-nix-check: rust-spacing
	cargo fmt --manifest-path crates/Cargo.toml -p airlock-nix-core -p airlock-cli -p airlock-sys-ctrl-service -- --check
	cargo clippy --locked --manifest-path crates/Cargo.toml -p airlock-nix-core -p airlock-cli -p airlock-sys-ctrl-service --all-targets -- -D warnings

.PHONY: airlock-dom0-build airlock-dom0-check
airlock-dom0-build:
	cargo build --locked --release --manifest-path crates/Cargo.toml -p airlock-dom0-service

airlock-dom0-check: rust-spacing
	cargo fmt --manifest-path crates/Cargo.toml -p airlock-dom0-service -- --check
	cargo clippy --locked --manifest-path crates/Cargo.toml -p airlock-dom0-service --all-targets -- -D warnings

.PHONY: rust-fmt rust-fmt-check rust-spacing rust-spacing-fix rust-style-test rust-doc rust-check
# Independent source-owned authoring crates use explicitly prepared offline dependencies.
AIRLOCK_CARGO_VENDOR ?= /etc/airlock/authoring/vendor
AUTHORING_CRATES := airlock-machine crates/airlock-config/templates/initial-runtime-config
RUST_STYLE_MANIFEST := tools/rust-style/Cargo.toml
STORE_PACKER_MANIFEST := crates/airlock-store-packer/Cargo.toml

rust-fmt:
	cargo fmt --manifest-path crates/Cargo.toml --all
	cargo fmt --manifest-path $(RUST_STYLE_MANIFEST) --all
	cargo fmt --manifest-path $(STORE_PACKER_MANIFEST) --all
	@for crate in $(AUTHORING_CRATES); do cargo fmt --manifest-path "$$crate/Cargo.toml" --all || exit; done

rust-fmt-check:
	cargo fmt --manifest-path crates/Cargo.toml --all -- --check
	cargo fmt --manifest-path $(RUST_STYLE_MANIFEST) --all -- --check
	cargo fmt --manifest-path $(STORE_PACKER_MANIFEST) --all -- --check
	@for crate in $(AUTHORING_CRATES); do cargo fmt --manifest-path "$$crate/Cargo.toml" --all -- --check || exit; done

rust-spacing:
	cargo run --locked --quiet --manifest-path $(RUST_STYLE_MANIFEST) --bin check-rust-spacing

# The checker also runs rustfmt before inserting blank lines, including with --root.
rust-spacing-fix: rust-fmt
	cargo run --locked --quiet --manifest-path $(RUST_STYLE_MANIFEST) --bin check-rust-spacing -- --fix

rust-style-test:
	cargo test --locked --manifest-path $(RUST_STYLE_MANIFEST)

rust-doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked --manifest-path crates/Cargo.toml
	CARGO_TARGET_DIR="$(abspath $(or $(CARGO_TARGET_DIR),crates/target))" RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked --manifest-path $(STORE_PACKER_MANIFEST)

rust-check: rust-fmt-check rust-spacing rust-style-test rust-doc rust-authoring-check native-integration-build
	cargo clippy --workspace --all-targets --all-features --locked --manifest-path crates/Cargo.toml -- -D warnings
	cargo clippy --all-targets --locked --manifest-path $(RUST_STYLE_MANIFEST) -- -D warnings
	CARGO_TARGET_DIR="$(abspath $(or $(CARGO_TARGET_DIR),crates/target))" cargo clippy --all-targets --locked --manifest-path $(STORE_PACKER_MANIFEST) -- -D warnings
	cargo test --workspace --all-features --locked --manifest-path crates/Cargo.toml
	CARGO_TARGET_DIR="$(abspath $(or $(CARGO_TARGET_DIR),crates/target))" cargo test --locked --manifest-path $(STORE_PACKER_MANIFEST)

.PHONY: verify verify-prepare
# Explicit prover preparation is separate from ordinary Cargo and test-quick.
verify:
	cargo run --locked --manifest-path crates/Cargo.toml -p airlock-dev -- verify

verify-prepare:
	cargo run --locked --manifest-path crates/Cargo.toml -p airlock-dev -- verify --prepare

# Preparation archives the complete locked source graph; execution below remains offline.
NIX_TEST_LOG_DIR := $(CURDIR)/.airlock-logs/nix-tests
AIRLOCK_RUSIX_SOURCES ?= $(NIX_TEST_LOG_DIR)/sources.json
export AIRLOCK_RUSIX_SOURCES
.PHONY: test-nix-prepare
test-nix-prepare: test-fixtures-build test-reports-build
	@mkdir -p "$(NIX_TEST_LOG_DIR)"
	"$(dir $(NATIVE_TEST_RUNNER))airlock-config" prepare "$(CURDIR)" "$(CURDIR)/target/nix" > "$(NIX_TEST_LOG_DIR)/prepared-source"
	$(AIRLOCK_NIX) flake archive --json --no-write-lock-file "$$(cat "$(NIX_TEST_LOG_DIR)/prepared-source")" > "$(NIX_TEST_LOG_DIR)/archive.json"
	"$(dir $(NATIVE_TEST_RUNNER))airlock-test-report" sources "$(NIX_TEST_LOG_DIR)/archive.json" "$(if $(filter 1,$(AIRLOCK_USE_HOST_NIX_STORE)),/,$(AIRLOCK_NIX_ROOT))" "$(AIRLOCK_RUSIX_SOURCES)"

# Pure offline projections and package builds have separate, explicit lanes.
test-nix: ensure-generated-dirs
	AIRLOCK_PREPARED_SOURCE="$${AIRLOCK_PREPARED_SOURCE:-$$(cat "$(NIX_TEST_LOG_DIR)/prepared-source")}" "$(NATIVE_TEST_RUNNER)" "$(NATIVE_TEST_RECEIPT)" --ignored nix:: --skip remote_ --skip package_ $(NATIVE_TEST_ARGS)

.PHONY: test-packages test-uplink-vm test-input-vm test-native-runtime test-native-systemd test-native-storage-linux
test-packages:
	AIRLOCK_PREPARED_SOURCE="$${AIRLOCK_PREPARED_SOURCE:-$$(cat "$(NIX_TEST_LOG_DIR)/prepared-source")}" "$(NATIVE_TEST_RUNNER)" "$(NATIVE_TEST_RECEIPT)" --ignored package_ $(NATIVE_TEST_ARGS)

test-uplink-vm:
	"$(NATIVE_TEST_RUNNER)" "$(NATIVE_TEST_RECEIPT)" --ignored --exact packaged::vm_uplink_hotplug --nocapture

test-input-vm:
	"$(NATIVE_TEST_RUNNER)" "$(NATIVE_TEST_RECEIPT)" --ignored --exact packaged::vm_installed_input_receivers --nocapture

test-native-runtime:
	"$(NATIVE_TEST_RUNNER)" "$(NATIVE_TEST_RECEIPT)" --ignored external_tool_packaged_runtime_ --nocapture

test-native-systemd:
	AIRLOCK_RUN_SYSTEMD_ORDER_TEST=1 "$(NATIVE_TEST_RUNNER)" "$(NATIVE_TEST_RECEIPT)" --ignored user_systemd_ --nocapture

test-native-storage-linux:
	"$(NATIVE_TEST_RUNNER)" "$(NATIVE_TEST_RECEIPT)" --ignored privileged_linux_storage --nocapture

.PHONY: vm-gui-minimal-image vm-gui-minimal-run vm-gui-minimal-ssh

.PHONY: usb-dev-prepare-inputs usb-builder-offline-check usb-dev-image usb-dev-write usb-dev-help

.PHONY: check-publish
check-publish:
	crates/airlock-dev/scripts/airlock-dev.sh check-publish

# Cargo calls the debug profile "dev"; receipts must describe the selected build.
NATIVE_BUILD_PROFILE ?= release

.PHONY: dev-tools-build
dev-tools-build:
	@mkdir -p "$(CURDIR)/.airlock-logs"
	cargo build --locked --profile $(NATIVE_BUILD_PROFILE) --manifest-path crates/Cargo.toml -p airlock-dev --message-format=json-render-diagnostics > "$(CURDIR)/.airlock-logs/dev-build.jsonl"

# Prepare Rust-authored fixtures explicitly; execution never builds its own tools.
.PHONY: test-fixtures-build
test-fixtures-build: native-test-fixtures-build runtime-config-build
	cargo build --locked --manifest-path crates/Cargo.toml -p airlock-config --bin airlock-config --example test_fixtures --example candidate_fixture

# Use explicitly prepared authoring dependencies for the source-owned candidate compiler.
AUTHORING_TEST_VENDOR = $(if $(wildcard $(AIRLOCK_CARGO_VENDOR)/.),$(AIRLOCK_CARGO_VENDOR),$(CURDIR)/.airlock-cache/authoring-vendor)
.PHONY: runtime-config-build
runtime-config-build:
	CARGO_TARGET_DIR="$(abspath $(or $(CARGO_TARGET_DIR),crates/target))" $(MAKE) -C crates/airlock-config/templates/initial-runtime-config build AIRLOCK_APPS="$(CURDIR)/crates" AIRLOCK_CARGO_VENDOR="$(AUTHORING_TEST_VENDOR)"

# Cargo owns dependency/feature resolution for process-boundary test drivers too.
.PHONY: native-test-fixtures-build
native-test-fixtures-build:
	cargo build --locked --profile $(NATIVE_BUILD_PROFILE) --manifest-path crates/Cargo.toml -p airlock-dom0-service --example test_input

.PHONY: image-tools-build
IMAGE_TOOLS_DIR ?= $(abspath $(or $(CARGO_TARGET_DIR),crates/target))/$(if $(filter dev,$(NATIVE_BUILD_PROFILE)),debug,$(NATIVE_BUILD_PROFILE))
IMAGE_BUILD_ARTIFACTS ?= $(CURDIR)/.airlock-logs/image-build.jsonl
image-tools-build:
	@mkdir -p "$(dir $(IMAGE_BUILD_ARTIFACTS))"
	cargo build --locked --profile $(NATIVE_BUILD_PROFILE) --manifest-path crates/Cargo.toml -p airlock-image --message-format=json-render-diagnostics > "$(IMAGE_BUILD_ARTIFACTS)"

USB_PUBLIC_KEY ?= $(HOME)/.ssh/id_ed25519.pub
USB_INSECURE_DEV_PASSWORD ?= 0
USB_DEV_PASSWORD_ARGS = $(if $(filter 1,$(USB_INSECURE_DEV_PASSWORD)),--insecure-dev-password,)

.PHONY: usb-dom0-console-image usb-dom0-console-write usb-dev-install

# The Rust wrapper must run before prerequisites, including native tool compilation.
ifeq ($(AIRLOCK_IMAGE_BUILD_LIMITED),1)
usb-dev-install: image-tools-build
	@$(AIRLOCK_DEV) usb-build-provision --usb-bin "$(IMAGE_TOOLS_DIR)/airlock-usb" --serial "$(USB_SERIAL)" --public-key "$(USB_PUBLIC_KEY)" --result-link-dir "$(or $(AIRLOCK_RESULT_LINK_DIR),$(CURDIR)/.airlock)" $(if $(AIRLOCK_NIX_ROOT),--nix-root "$(AIRLOCK_NIX_ROOT)",) --resize-backup-dir "$(or $(AIRLOCK_LOG_DIR),/var/log/airlock)/usb-root-expansion" $(USB_DEV_PASSWORD_ARGS)

usb-dom0-console-image: ensure-generated-dirs
	$(AIRLOCK_NIX) build .#airlock-usb-dom0-console-image --out-link "$(or $(AIRLOCK_RESULT_LINK_DIR),$(CURDIR)/.airlock)/usb-dom0-console-image" --print-build-logs
endif

usb-dom0-console-write: image-tools-build
	@test -n "$(USB_SERIAL)" || (echo "Set USB_SERIAL to the exact USB serial" >&2; exit 2)
	sudo "$(IMAGE_TOOLS_DIR)/airlock-usb" write-latest --result-link "$(or $(AIRLOCK_RESULT_LINK_DIR),$(CURDIR)/.airlock)/usb-dom0-console-image" --nix-root "$(AIRLOCK_NIX_ROOT)" --serial "$(USB_SERIAL)" --write

usb-dev-prepare-inputs: ensure-generated-dirs
	@set -eu; \
	seed_archive="$(or $(AIRLOCK_TMPDIR),$(CURDIR)/.airlock)/airlock-machine-seed.tar.gz"; \
	offline_inputs="$(or $(AIRLOCK_TMPDIR),$(CURDIR)/.airlock)/airlock-machine-offline-inputs.json"; \
	archive_json="$(or $(AIRLOCK_TMPDIR),$(CURDIR)/.airlock)/airlock-machine-flake-archive.json"; \
	crates/airlock-dev/scripts/airlock-dev.sh source seed --reuse --output "$$seed_archive" >/dev/null; \
	$(AIRLOCK_NIX) flake archive --no-update-lock-file --json path:./airlock-machine > "$$archive_json"; \
	crates/airlock-dev/scripts/airlock-dev.sh source offline-inputs --repository airlock-machine --output "$$offline_inputs" < "$$archive_json"

# Force both offline trials and publish a fresh passing receipt.
ifeq ($(AIRLOCK_IMAGE_BUILD_LIMITED),1)
usb-builder-offline-check: image-tools-build usb-dev-prepare-inputs
	@set -eu; \
	seed_archive="$(or $(AIRLOCK_TMPDIR),$(CURDIR)/.airlock)/airlock-machine-seed.tar.gz"; \
	offline_inputs="$(or $(AIRLOCK_TMPDIR),$(CURDIR)/.airlock)/airlock-machine-offline-inputs.json"; \
	closure="$$(AIRLOCK_MACHINE_SEED_ARCHIVE="$$seed_archive" AIRLOCK_MACHINE_OFFLINE_INPUTS="$$offline_inputs" $(AIRLOCK_NIX) build --impure .#airlock-usb-builder-input-closure --no-link --print-out-paths)"; \
	nix_bin="$$(AIRLOCK_MACHINE_SEED_ARCHIVE="$$seed_archive" AIRLOCK_MACHINE_OFFLINE_INPUTS="$$offline_inputs" $(AIRLOCK_NIX) eval --impure --raw .#airlock-usb-builder-nix.outPath)/bin/nix"; \
	prepared_source="$$(crates/airlock-dev/scripts/airlock-dev.sh source prepare | jq -er .source)"; \
	"$(IMAGE_TOOLS_DIR)/airlock-image-check" \
	  --closure "$$closure" --machine airlock-machine --prepared-machine "$$prepared_source/airlock-machine" --manifest "$$offline_inputs" --seed-archive "$$seed_archive" \
	  --source-store-root "$(if $(filter 1,$(AIRLOCK_USE_HOST_NIX_STORE)),/,$(AIRLOCK_NIX_ROOT))" --nix-bin "$$nix_bin" \
	  --log-dir "$(or $(AIRLOCK_LOG_DIR),$(CURDIR)/.airlock-logs)/offline-builder-gate" \
	  --cache-dir "$(or $(AIRLOCK_DATA_ROOT),$(CURDIR)/.airlock)/cache/offline-builder-gate" \
	  --temporary-root "$(or $(AIRLOCK_TMPDIR),$(TMPDIR),$(CURDIR)/.airlock)" --force

usb-dev-image: image-tools-build usb-dev-prepare-inputs
	@set -eu; \
	seed_archive="$(or $(AIRLOCK_TMPDIR),$(CURDIR)/.airlock)/airlock-machine-seed.tar.gz"; \
	offline_inputs="$(or $(AIRLOCK_TMPDIR),$(CURDIR)/.airlock)/airlock-machine-offline-inputs.json"; \
	closure="$$(AIRLOCK_MACHINE_SEED_ARCHIVE="$$seed_archive" AIRLOCK_MACHINE_OFFLINE_INPUTS="$$offline_inputs" $(AIRLOCK_NIX) build --impure .#airlock-usb-builder-input-closure --no-link --print-out-paths)"; \
	nix_bin="$$(AIRLOCK_MACHINE_SEED_ARCHIVE="$$seed_archive" AIRLOCK_MACHINE_OFFLINE_INPUTS="$$offline_inputs" $(AIRLOCK_NIX) eval --impure --raw .#airlock-usb-builder-nix.outPath)/bin/nix"; \
	prepared_source="$$(crates/airlock-dev/scripts/airlock-dev.sh source prepare | jq -er .source)"; \
	"$(IMAGE_TOOLS_DIR)/airlock-image-check" \
	  --closure "$$closure" --machine airlock-machine --prepared-machine "$$prepared_source/airlock-machine" --manifest "$$offline_inputs" --seed-archive "$$seed_archive" \
	  --source-store-root "$(if $(filter 1,$(AIRLOCK_USE_HOST_NIX_STORE)),/,$(AIRLOCK_NIX_ROOT))" --nix-bin "$$nix_bin" \
	  --log-dir "$(or $(AIRLOCK_LOG_DIR),$(CURDIR)/.airlock-logs)/offline-builder-gate" \
	  --cache-dir "$(or $(AIRLOCK_DATA_ROOT),$(CURDIR)/.airlock)/cache/offline-builder-gate" \
	  --temporary-root "$(or $(AIRLOCK_TMPDIR),$(TMPDIR),$(CURDIR)/.airlock)" \
	  --image-command $(AIRLOCK_NIX) build --impure .#airlock-usb-dev-image --out-link "$(or $(AIRLOCK_RESULT_LINK_DIR),$(CURDIR)/.airlock)/usb-dev-image" --print-build-logs
else
usb-dom0-console-image usb-builder-offline-check usb-dev-image usb-dev-install:
	@$(AIRLOCK_DEV) check-image-source
	@$(AIRLOCK_DEV) build-budget -- $(MAKE) --no-print-directory AIRLOCK_IMAGE_BUILD_LIMITED=1 $@
endif

usb-dev-write: image-tools-build
	@test -n "$(USB_SERIAL)" || (echo "Set USB_SERIAL to the exact USB serial, e.g. make usb-dev-write USB_SERIAL=YOUR_USB_SERIAL" >&2; exit 2)
	sudo "$(IMAGE_TOOLS_DIR)/airlock-usb" write-latest --result-link "$(or $(AIRLOCK_RESULT_LINK_DIR),$(CURDIR)/.airlock)/usb-dev-image" --nix-root "$(AIRLOCK_NIX_ROOT)" --serial "$(USB_SERIAL)" --write

usb-dev-help: image-tools-build
	"$(IMAGE_TOOLS_DIR)/airlock-usb" --help

vm-gui-minimal-image: ensure-generated-dirs
	$(AIRLOCK_NIX) build .#$(VM_GUI_MINIMAL_IMAGE_ATTR) --out-link "$(AIRLOCK_RESULT_LINK_DIR)/gui-minimal-image" --print-build-logs

vm-gui-minimal-run: ensure-generated-dirs
	AIRLOCK_VM_DIR="$(VM_GUI_MINIMAL_DIR)" AIRLOCK_VM_SSH_PORT="$(VM_GUI_MINIMAL_SSH_PORT)" AIRLOCK_VM_IMAGE_ATTR="$(VM_GUI_MINIMAL_IMAGE_ATTR)" AIRLOCK_VM_MEMORY="$${AIRLOCK_VM_MEMORY:-8192}" AIRLOCK_VM_SYSNET_NIC=0 $(AIRLOCK_DEV) with-environment nested run

vm-gui-minimal-ssh:
	AIRLOCK_VM_SSH_PORT="$(VM_GUI_MINIMAL_SSH_PORT)" $(AIRLOCK_DEV) with-environment nested ssh

.PHONY: vm-gpu-lab-image vm-gpu-lab-run vm-gpu-lab-test

vm-gpu-lab-image: ensure-generated-dirs
	$(AIRLOCK_NIX) build .#airlock-vm-gpu-lab-image --out-link "$(AIRLOCK_RESULT_LINK_DIR)/sys-gpu-lab-image" --print-build-logs

vm-gpu-lab-run: ensure-generated-dirs
	AIRLOCK_VM_DIR="$(or $(AIRLOCK_DATA_ROOT),$(CURDIR)/.airlock)/vm-gpu-lab" AIRLOCK_VM_SSH_PORT=2322 AIRLOCK_VM_IMAGE_ATTR=airlock-vm-gpu-lab-image $(AIRLOCK_DEV) with-environment nested run

vm-gpu-lab-test: ensure-generated-dirs
	@mkdir -p "$(TEST_LOG_DIR)"
	AIRLOCK_RUN_GPU_LAB_TESTS=1 "$(NATIVE_TEST_RUNNER)" "$(NATIVE_TEST_RECEIPT)" --target integration --ignored --exact system_vm::gpu_lab_vm --nocapture

test-warm: ensure-generated-dirs
	@mkdir -p "$(TEST_LOG_DIR)"
	AIRLOCK_RUN_VM_TESTS=1 AIRLOCK_SKIP_GC_AUTO=1 AIRLOCK_VM_STAGED_STEPS="$(TESTS)" AIRLOCK_VM_MEMORY="$${AIRLOCK_VM_MEMORY:-$(TEST_WARM_VM_MEMORY)}" "$(NATIVE_TEST_RUNNER)" "$(NATIVE_TEST_RECEIPT)" --target integration --ignored --exact system_vm::staged_configuration --nocapture

test-slow: export AIRLOCK_SKIP_GC_AUTO = 1
test-slow: $(if $(TESTS),$(if $(VM_SLOW_SELECTED_PARALLEL_FLOW_IDS),vm-parallel-prebuild-baseline,ensure-generated-dirs),vm-parallel-prebuild-baseline)
	@mkdir -p "$(TEST_LOG_DIR)"
ifneq ($(strip $(TESTS)),)
ifneq ($(strip $(VM_SLOW_SELECTED_UNKNOWN_FLOW_IDS)),)
	$(error unknown slow TESTS value(s): $(VM_SLOW_SELECTED_UNKNOWN_FLOW_IDS))
endif
ifneq ($(strip $(VM_SLOW_SELECTED_PARALLEL_FLOW_IDS)),)
	AIRLOCK_RUN_VM_TESTS=1 AIRLOCK_VM_PARALLEL_LANES="$(TEST_VM_JOBS)" AIRLOCK_VM_PARALLEL_SSH_BASE_PORT="$(VM_PARALLEL_SSH_BASE_PORT)" AIRLOCK_VM_PARALLEL_IMAGE_ATTR="$(VM_PARALLEL_IMAGE_ATTR)" AIRLOCK_VM_PARALLEL_IMAGE_LINK="$(VM_PARALLEL_IMAGE_LINK)" AIRLOCK_VM_PARALLEL_BASELINE_DISK="$(VM_PARALLEL_BASELINE_DISK)" AIRLOCK_VM_PARALLEL_BASELINE_OVMF_VARS="$(VM_PARALLEL_BASELINE_OVMF_VARS)" "$(NATIVE_TEST_RUNNER)" "$(NATIVE_TEST_RECEIPT)" --target integration --ignored --exact $(VM_SLOW_SELECTED_PARALLEL_TARGETS) --test-threads=$(TEST_VM_JOBS) --nocapture
endif
ifneq ($(strip $(VM_SLOW_SELECTED_SERIAL_FLOW_IDS)),)
	AIRLOCK_RUN_VM_TESTS=1 AIRLOCK_VM_DIR="$(VM_SLOW_SERIAL_VM_DIR)" AIRLOCK_VM_SSH_PORT="$(VM_SLOW_SERIAL_SSH_PORT)" "$(NATIVE_TEST_RUNNER)" "$(NATIVE_TEST_RECEIPT)" --target integration --ignored --exact $(VM_SLOW_SELECTED_SERIAL_TARGETS) --nocapture
endif
else
	AIRLOCK_RUN_VM_TESTS=1 AIRLOCK_VM_PARALLEL_LANES="$(TEST_VM_JOBS)" AIRLOCK_VM_PARALLEL_SSH_BASE_PORT="$(VM_PARALLEL_SSH_BASE_PORT)" AIRLOCK_VM_PARALLEL_IMAGE_ATTR="$(VM_PARALLEL_IMAGE_ATTR)" AIRLOCK_VM_PARALLEL_IMAGE_LINK="$(VM_PARALLEL_IMAGE_LINK)" AIRLOCK_VM_PARALLEL_BASELINE_DISK="$(VM_PARALLEL_BASELINE_DISK)" AIRLOCK_VM_PARALLEL_BASELINE_OVMF_VARS="$(VM_PARALLEL_BASELINE_OVMF_VARS)" "$(NATIVE_TEST_RUNNER)" "$(NATIVE_TEST_RECEIPT)" --target integration --ignored --exact $(VM_SLOW_DEFAULT_PARALLEL_TARGETS) --test-threads=$(TEST_VM_JOBS) --nocapture
	AIRLOCK_RUN_VM_TESTS=1 AIRLOCK_VM_DIR="$(VM_SLOW_SERIAL_VM_DIR)" AIRLOCK_VM_SSH_PORT="$(VM_SLOW_SERIAL_SSH_PORT)" AIRLOCK_SKIP_GC_AUTO=1 "$(NATIVE_TEST_RUNNER)" "$(NATIVE_TEST_RECEIPT)" --target integration --ignored --exact $(VM_SLOW_SERIAL_TARGETS) --nocapture
endif

vm-prebuild-shared: ensure-generated-dirs gc-auto
	$(AIRLOCK_NIX) build $(foreach attr,$(VM_PREBUILD_ATTRS),.#$(attr)) --no-link --print-build-logs --show-trace

vm-parallel-prebuild-image: ensure-generated-dirs gc-auto
	@mkdir -p "$(TEST_LOG_DIR)"
	$(AIRLOCK_DEV) with-environment nested image "$(VM_PARALLEL_IMAGE_ATTR)" "$(VM_PARALLEL_IMAGE_LINK)" > "$(TEST_LOG_DIR)/vm-parallel-shared-image-path.txt"

vm-parallel-prebuild-baseline: vm-parallel-prebuild-image
	@mkdir -p "$(TEST_LOG_DIR)" "$(VM_PARALLEL_BASELINE_LOG_DIR)"
	AIRLOCK_VM_IMAGE_ATTR="$(VM_PARALLEL_IMAGE_ATTR)" AIRLOCK_VM_SHARED_IMAGE_LINK="$(VM_PARALLEL_IMAGE_LINK)" AIRLOCK_VM_BASELINE_DIR="$(VM_PARALLEL_BASELINE_DIR)" AIRLOCK_VM_BASELINE_DISK="$(VM_PARALLEL_BASELINE_DISK)" AIRLOCK_VM_BASELINE_OVMF_VARS="$(VM_PARALLEL_BASELINE_OVMF_VARS)" AIRLOCK_VM_BASELINE_LOG_DIR="$(VM_PARALLEL_BASELINE_LOG_DIR)" AIRLOCK_VM_BASELINE_SSH_PORT="$(VM_PARALLEL_BASELINE_SSH_PORT)" $(AIRLOCK_DEV) with-environment nested baseline

vm-image: ensure-generated-dirs gc-auto
	$(AIRLOCK_NIX) build .#$(VM_IMAGE_ATTR) --out-link "$(AIRLOCK_RESULT_LINK_DIR)/$(VM_IMAGE_ATTR)" --print-build-logs --show-trace

vm-image-dry-run: ensure-generated-dirs
	$(AIRLOCK_NIX) build .#$(VM_IMAGE_ATTR) --dry-run --show-trace

vm-run: ensure-generated-dirs gc-auto
	AIRLOCK_VM_IMAGE_ATTR="$(VM_IMAGE_ATTR)" $(AIRLOCK_DEV) with-environment nested run

vm-ssh: ensure-generated-dirs
	$(AIRLOCK_DEV) with-environment nested ssh

vm-gui-image: ensure-generated-dirs gc-auto
	$(AIRLOCK_NIX) build .#$(VM_GUI_IMAGE_ATTR) --out-link "$(AIRLOCK_RESULT_LINK_DIR)/$(VM_GUI_IMAGE_ATTR)" --print-build-logs --show-trace

vm-gui-image-dry-run: ensure-generated-dirs
	$(AIRLOCK_NIX) build .#$(VM_GUI_IMAGE_ATTR) --dry-run --show-trace

vm-gui-run: ensure-generated-dirs gc-auto
	AIRLOCK_VM_IMAGE_ATTR="$(VM_GUI_IMAGE_ATTR)" AIRLOCK_VM_DISPLAY=gtk $(AIRLOCK_DEV) with-environment nested run

vm-gui-config-image: ensure-generated-dirs gc-auto
	$(AIRLOCK_NIX) build .#$(VM_GUI_CONFIG_IMAGE_ATTR) --out-link "$(AIRLOCK_RESULT_LINK_DIR)/$(VM_GUI_CONFIG_IMAGE_ATTR)" --print-build-logs --show-trace

vm-gui-config-image-dry-run: ensure-generated-dirs
	$(AIRLOCK_NIX) build .#$(VM_GUI_CONFIG_IMAGE_ATTR) --dry-run --show-trace

vm-gui-config-run: ensure-generated-dirs gc-auto
	GDK_BACKEND="$(AIRLOCK_VM_GDK_BACKEND)" AIRLOCK_VM_IMAGE_ATTR="$(VM_GUI_CONFIG_IMAGE_ATTR)" AIRLOCK_VM_DISPLAY=gtk $(AIRLOCK_DEV) with-environment nested run

vm-gui-config-network-debug-image: ensure-generated-dirs gc-auto
	$(AIRLOCK_NIX) build .#$(VM_GUI_CONFIG_NETWORK_DEBUG_IMAGE_ATTR) --out-link "$(AIRLOCK_RESULT_LINK_DIR)/$(VM_GUI_CONFIG_NETWORK_DEBUG_IMAGE_ATTR)" --print-build-logs --show-trace

vm-gui-config-network-debug-run: ensure-generated-dirs gc-auto
	AIRLOCK_VM_IMAGE_ATTR="$(VM_GUI_CONFIG_NETWORK_DEBUG_IMAGE_ATTR)" AIRLOCK_VM_DISPLAY=gtk $(AIRLOCK_DEV) with-environment nested run

vm-gui-check: ensure-generated-dirs gc-auto
	AIRLOCK_AUTO_GC_AFTER_RUN=1 AIRLOCK_BOOTSTRAP_QUBES=0 AIRLOCK_RUN_QUBES_SMOKE=0 AIRLOCK_RUN_GUI_SMOKE=0 $(AIRLOCK_DEV) with-environment nested smoke

vm-gui-smoke: ensure-generated-dirs gc-auto
	AIRLOCK_AUTO_GC_AFTER_RUN=1 $(AIRLOCK_DEV) with-environment nested smoke

vm-warm-start: ensure-generated-dirs
	@if $(AIRLOCK_DEV) with-environment nested ssh true >/dev/null 2>&1; then \
		printf 'nested dom0 already reachable on AIRLOCK_VM_SSH_PORT=%s\n' "$${AIRLOCK_VM_SSH_PORT:-2222}"; \
	else \
		AIRLOCK_KEEP_VM=1 AIRLOCK_VM_SKIP_BASE_BUILD=0 AIRLOCK_VM_IMAGE_ATTR="$(VM_GUI_CONFIG_IMAGE_ATTR)" AIRLOCK_VM_DISPLAY=none AIRLOCK_VM_FRESH=0 AIRLOCK_BOOTSTRAP_QUBES=0 AIRLOCK_RUN_SETUP_CONFIG=0 AIRLOCK_RUN_CONFIG_INPUTS_IMPORT=0 AIRLOCK_RUN_CONFIG_VMS_SMOKE=0 AIRLOCK_RUN_NIX_CLOSURE_SMOKE=0 AIRLOCK_RUN_QUBES_SMOKE=0 AIRLOCK_RUN_GUI_SMOKE=0 $(AIRLOCK_DEV) with-environment nested smoke; \
	fi

vm-warm-sync: ensure-generated-dirs
	AIRLOCK_SYNC_DOM0_TOOLS=1 $(AIRLOCK_DEV) with-environment nested sync


vm-warm-apply: ensure-generated-dirs
	AIRLOCK_KEEP_VM=1 AIRLOCK_REUSE_WARM_VM=1 AIRLOCK_SYNC_DOM0_TOOLS=1 AIRLOCK_NESTED_WARM_STOP_NIX_DOMAINS=1 AIRLOCK_VM_SKIP_BASE_BUILD=1 AIRLOCK_VM_IMAGE_ATTR="$(VM_GUI_CONFIG_IMAGE_ATTR)" AIRLOCK_VM_DISPLAY=none AIRLOCK_VM_FRESH=0 AIRLOCK_BOOTSTRAP_QUBES=0 AIRLOCK_RUN_SETUP_CONFIG=1 AIRLOCK_RUN_CONFIG_INPUTS_IMPORT=1 AIRLOCK_RUN_CONFIG_VMS_SMOKE=0 AIRLOCK_RUN_NIX_CLOSURE_SMOKE=0 AIRLOCK_RUN_QUBES_SMOKE=0 AIRLOCK_RUN_GUI_SMOKE=0 $(AIRLOCK_DEV) with-environment nested smoke

vm-warm-test-config: ensure-generated-dirs
	AIRLOCK_KEEP_VM=1 AIRLOCK_REUSE_WARM_VM=1 AIRLOCK_SYNC_DOM0_TOOLS=1 AIRLOCK_NESTED_WARM_STOP_NIX_DOMAINS=1 AIRLOCK_VM_SKIP_BASE_BUILD=1 AIRLOCK_VM_IMAGE_ATTR="$(VM_GUI_CONFIG_IMAGE_ATTR)" AIRLOCK_VM_DISPLAY=none AIRLOCK_VM_FRESH=0 AIRLOCK_BOOTSTRAP_QUBES=0 AIRLOCK_RUN_SETUP_CONFIG=1 AIRLOCK_RUN_CONFIG_INPUTS_IMPORT=0 AIRLOCK_RUN_CONFIG_VMS_SMOKE=1 AIRLOCK_RUN_NIX_CLOSURE_SMOKE=0 AIRLOCK_RUN_QUBES_SMOKE=0 AIRLOCK_RUN_GUI_SMOKE=0 $(AIRLOCK_DEV) with-environment nested smoke

vm-config-setup: ensure-generated-dirs gc-auto
	AIRLOCK_AUTO_GC_AFTER_RUN=1 AIRLOCK_VM_IMAGE_ATTR="$(VM_GUI_CONFIG_IMAGE_ATTR)" AIRLOCK_VM_DISPLAY=none AIRLOCK_BOOTSTRAP_QUBES=0 AIRLOCK_RUN_SETUP_CONFIG=1 AIRLOCK_RUN_QUBES_SMOKE=0 AIRLOCK_RUN_GUI_SMOKE=0 $(AIRLOCK_DEV) with-environment nested smoke

vm-config-flow: ensure-generated-dirs gc-auto
	AIRLOCK_AUTO_GC_AFTER_RUN=1 AIRLOCK_VM_IMAGE_ATTR="$(VM_GUI_CONFIG_IMAGE_ATTR)" AIRLOCK_VM_DISPLAY=none AIRLOCK_VM_FRESH=1 AIRLOCK_BOOTSTRAP_QUBES=0 AIRLOCK_RUN_SETUP_CONFIG=$(VM_FLOW_RUN_SETUP_CONFIG) AIRLOCK_RUN_CONFIG_VMS_SMOKE=1 AIRLOCK_RUN_QUBES_SMOKE=0 AIRLOCK_RUN_GUI_SMOKE=0 $(AIRLOCK_DEV) with-environment nested smoke

vm-config-warm-flow: ensure-generated-dirs gc-auto
	AIRLOCK_AUTO_GC_AFTER_RUN=1 AIRLOCK_VM_IMAGE_ATTR="$(VM_GUI_CONFIG_IMAGE_ATTR)" AIRLOCK_VM_DISPLAY=none AIRLOCK_VM_FRESH=0 AIRLOCK_BOOTSTRAP_QUBES=0 AIRLOCK_RUN_SETUP_CONFIG=1 AIRLOCK_RUN_CONFIG_VMS_SMOKE=1 AIRLOCK_RUN_QUBES_SMOKE=0 AIRLOCK_RUN_GUI_SMOKE=0 $(AIRLOCK_DEV) with-environment nested smoke

vm-config-boot-flow: ensure-generated-dirs gc-auto
	AIRLOCK_AUTO_GC_AFTER_RUN=1 AIRLOCK_VM_IMAGE_ATTR="$(VM_GUI_CONFIG_IMAGE_ATTR)" AIRLOCK_VM_DISPLAY=none AIRLOCK_VM_FRESH=1 AIRLOCK_BOOTSTRAP_QUBES=0 AIRLOCK_RUN_SETUP_CONFIG=$(VM_FLOW_RUN_SETUP_CONFIG) AIRLOCK_RUN_CONFIG_VMS_SMOKE=1 AIRLOCK_CONFIG_DOM0_SYSTEM_SWITCH_ACTION=boot AIRLOCK_RUN_QUBES_SMOKE=0 AIRLOCK_RUN_GUI_SMOKE=0 $(AIRLOCK_DEV) with-environment nested smoke

vm-config-boot-activate-flow: ensure-generated-dirs gc-auto
	$(AIRLOCK_DEV) with-environment nested boot-flow

vm-nix-closure-flow: ensure-generated-dirs gc-auto
	AIRLOCK_AUTO_GC_AFTER_RUN=1 AIRLOCK_VM_IMAGE_ATTR="$(VM_GUI_CONFIG_IMAGE_ATTR)" AIRLOCK_VM_DISPLAY=none AIRLOCK_VM_FRESH=1 AIRLOCK_BOOTSTRAP_QUBES=0 AIRLOCK_RUN_SETUP_CONFIG=$(VM_FLOW_RUN_SETUP_CONFIG) AIRLOCK_RUN_CONFIG_VMS_SMOKE=0 AIRLOCK_RUN_NIX_CLOSURE_SMOKE=1 AIRLOCK_RUN_QUBES_SMOKE=0 AIRLOCK_RUN_GUI_SMOKE=0 $(AIRLOCK_DEV) with-environment nested smoke

vm-nix-closure-warm-flow: ensure-generated-dirs gc-auto
	AIRLOCK_AUTO_GC_AFTER_RUN=1 AIRLOCK_KEEP_VM=1 AIRLOCK_SYNC_DOM0_TOOLS=1 AIRLOCK_VM_SKIP_BASE_BUILD=1 AIRLOCK_VM_IMAGE_ATTR="$(VM_GUI_CONFIG_IMAGE_ATTR)" AIRLOCK_VM_DISPLAY=none AIRLOCK_VM_FRESH=0 AIRLOCK_BOOTSTRAP_QUBES=0 AIRLOCK_RUN_SETUP_CONFIG=1 AIRLOCK_RUN_CONFIG_VMS_SMOKE=0 AIRLOCK_RUN_NIX_CLOSURE_SMOKE=1 AIRLOCK_RUN_QUBES_SMOKE=0 AIRLOCK_RUN_GUI_SMOKE=0 $(AIRLOCK_DEV) with-environment nested smoke

vm-pool-admission-flow: ensure-generated-dirs gc-auto
	AIRLOCK_KEEP_VM=1 AIRLOCK_VM_IMAGE_ATTR=airlock-vm-pool-admission-test-image AIRLOCK_VM_DISPLAY=none AIRLOCK_VM_FRESH=1 AIRLOCK_BOOTSTRAP_QUBES=0 AIRLOCK_RUN_SETUP_CONFIG=1 AIRLOCK_RUN_CONFIG_INPUTS_IMPORT=0 AIRLOCK_RUN_CONFIG_VMS_SMOKE=0 AIRLOCK_RUN_NIX_CLOSURE_SMOKE=0 AIRLOCK_RUN_QUBES_SMOKE=0 AIRLOCK_RUN_GUI_SMOKE=0 $(AIRLOCK_DEV) with-environment nested smoke
	crates/airlock-dev/scripts/airlock-dev.sh pool-smoke

disk-usage:
	$(AIRLOCK_DEV) clean disk-usage

gc-auto: ensure-generated-dirs
	@if [ "$${AIRLOCK_SKIP_GC_AUTO:-0}" = "1" ]; then \
		printf 'gc-auto skipped: AIRLOCK_SKIP_GC_AUTO=1\n'; \
	else \
		$(AIRLOCK_DEV) gc auto; \
	fi

gc-roots: ensure-generated-dirs
	$(AIRLOCK_DEV) gc roots

gc-dry-run: ensure-generated-dirs
	$(AIRLOCK_DEV) gc dry-run

gc: ensure-generated-dirs
	$(AIRLOCK_DEV) gc run

clean: clean-generated

clean-generated: clean-vm-workdirs clean-logs

clean-vm: clean-vm-workdirs

clean-vm-disks:
	$(AIRLOCK_DEV) clean vm-disks

clean-vm-workdirs:
	$(AIRLOCK_DEV) clean vm-workdirs

clean-result-links:
	$(AIRLOCK_DEV) clean result-links

clean-logs:
	$(AIRLOCK_DEV) clean logs

clean-cache:
	$(AIRLOCK_DEV) clean cache

.PHONY: rust-authoring-check
rust-authoring-check:
	@for crate in $(AUTHORING_CRATES); do \
	  $(MAKE) -C "$$crate" rust-check AIRLOCK_APPS="$(CURDIR)/crates" AIRLOCK_CARGO_VENDOR="$(AIRLOCK_CARGO_VENDOR)" || exit; \
	done

# Emit a complete Rust-authored Nix source tree under target/nix before evaluation.
.PHONY: prepare
prepare:
	$(MAKE) --no-print-directory -C crates/airlock-config prepare

# Bootstrap authoring with Cargo before a Nix flake exists.
.PHONY: prepare-dependencies
prepare-dependencies:
	@mkdir -p .airlock-cache
	cargo vendor --locked --manifest-path crates/Cargo.toml --versioned-dirs .airlock-cache/authoring-vendor > .airlock-cache/authoring-vendor-config.toml

# Prepared source is independent of image disks and the guarded Nix store.
PREPARED_KEEP ?= 3

.PHONY: prepared-prune prepared-prune-apply
prepared-prune:
	crates/airlock-dev/scripts/airlock-dev.sh source prune --keep "$(PREPARED_KEEP)"

prepared-prune-apply:
	crates/airlock-dev/scripts/airlock-dev.sh source prune --keep "$(PREPARED_KEEP)" --apply

# Preparation is explicit; quick/native execution reads Cargo's executable receipt only.
NATIVE_TEST_RECEIPT ?= $(CURDIR)/.airlock-logs/native-integration-build.jsonl
NATIVE_TEST_RUNNER := $(abspath $(or $(CARGO_TARGET_DIR),crates/target))/debug/airlock-test-runner
.PHONY: test-reports-build
test-reports-build:
	cargo build --locked --manifest-path crates/Cargo.toml -p airlock-tests --bin airlock-test-report

.PHONY: native-integration-build test-native test-native-mounts test-native-desktop test-native-javascript
native-integration-build:
	@mkdir -p "$(dir $(NATIVE_TEST_RECEIPT))"
	cargo build --locked --manifest-path crates/Cargo.toml -p airlock-nix-core -p airlock-dom0-service -p airlock-cli -p airlock-config -p airlock-image -p airlock-tests -p airlock-qubes-python -p airlock-vm-service -p airlock-sys-gui-service -p airlock-sys-gui-setup -p airlock-sys-ctrl-gui -p airlock-dev -p airlock-diagnostics --features airlock-diagnostics/runtime
	"$(dir $(NATIVE_TEST_RUNNER))airlock-dev" --repository-root "$(CURDIR)" ctrl-artifact record --binary "$(dir $(NATIVE_TEST_RUNNER))airlock-sys-ctrl-gui"
	cargo build --locked --manifest-path crates/Cargo.toml -p airlock-dom0-service --example test_input -p airlock-config --example test_fixtures --example candidate_fixture -p airlock-tests --example qubes_objects
	"$(dir $(NATIVE_TEST_RUNNER))airlock-test-peer" prepare-memory "$(CURDIR)/crates/patches/qubes-linux-utils/memory-accounting.h" "$(dir $(NATIVE_TEST_RUNNER))memory-accounting.so"
	"$(dir $(NATIVE_TEST_RUNNER))airlock-test-peer" prepare-gui-tests "$(CURDIR)/crates/patches" "$(dir $(NATIVE_TEST_RUNNER))gui-c-fixtures"
	cargo test --workspace --all-features --locked --manifest-path crates/Cargo.toml --no-run --message-format=json > "$(NATIVE_TEST_RECEIPT)"

test-native:
	"$(NATIVE_TEST_RUNNER)" "$(NATIVE_TEST_RECEIPT)" --all --test-threads=$(TEST_JOBS) $(NATIVE_TEST_ARGS)

test-native-mounts:
	"$(NATIVE_TEST_RUNNER)" "$(NATIVE_TEST_RECEIPT)" --ignored namespace_ --test-threads=$(TEST_JOBS)
	"$(NATIVE_TEST_RUNNER)" "$(NATIVE_TEST_RECEIPT)" --ignored storage::cleanup_refuses_bind_mounts

test-native-desktop:
	"$(NATIVE_TEST_RUNNER)" "$(NATIVE_TEST_RECEIPT)" --ignored desktop_ --skip nix:: --test-threads=$(TEST_JOBS)

test-native-javascript:
	"$(NATIVE_TEST_RUNNER)" "$(NATIVE_TEST_RECEIPT)" --ignored javascript_

.PHONY: test-native-tools
test-native-tools:
	"$(NATIVE_TEST_RUNNER)" "$(NATIVE_TEST_RECEIPT)" --all --ignored external_tool_ --skip external_tool_packaged_runtime_
