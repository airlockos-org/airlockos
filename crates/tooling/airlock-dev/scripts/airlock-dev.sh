#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
# Bootstrap native workstation tools; Rust selects the data/store environment.
bootstrap=(cargo build --quiet --locked --manifest-path "$ROOT/crates/Cargo.toml" -p airlock-dev)
if [[ "${1:-}" == build-budget || "${1:-}" == check-image-source ]]; then
    # Before Rust policy is available, confine its own compiler and linker to one allowed CPU.
    bootstrap_cpu="$(awk '/^Cpus_allowed_list:/ { split($2, cpus, /[,-]/); print cpus[1] }' /proc/self/status)"
    taskset --cpu-list "$bootstrap_cpu" "${bootstrap[@]}" --jobs 1
else
    "${bootstrap[@]}"
fi
exec "${CARGO_TARGET_DIR:-$ROOT/crates/target}/debug/airlock-dev" --repository-root "$ROOT" with-environment -- "$@"
