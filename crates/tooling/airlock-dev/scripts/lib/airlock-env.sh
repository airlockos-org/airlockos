#!/usr/bin/env bash
# Compatibility exports for external callers; environment policy lives in Rust.
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../../.." && pwd)}"
_AIRLOCK_ENV_NATIVE="${AIRLOCK_DEV_BIN:-$ROOT/crates/tooling/airlock-dev/scripts/airlock-dev.sh}"
_AIRLOCK_ENV_EXPORTS="$("$_AIRLOCK_ENV_NATIVE" --repository-root "$ROOT" environment exports)" || return
eval "$_AIRLOCK_ENV_EXPORTS"
unset _AIRLOCK_ENV_EXPORTS

airlock_store_uses_chroot() { "$_AIRLOCK_ENV_NATIVE" --repository-root "$ROOT" environment uses-chroot; }

airlock_physical_store_path() { "$_AIRLOCK_ENV_NATIVE" --repository-root "$ROOT" environment physical "$1"; }

airlock_physical_path_list() { "$_AIRLOCK_ENV_NATIVE" --repository-root "$ROOT" environment physical-list "$1"; }

airlock_store_path_root() { "$_AIRLOCK_ENV_NATIVE" --repository-root "$ROOT" environment store-root "$1"; }

airlock_run_store_path() { "$_AIRLOCK_ENV_NATIVE" --repository-root "$ROOT" environment run-store -- "$@"; }

airlock_exec_store_path() { exec "$_AIRLOCK_ENV_NATIVE" --repository-root "$ROOT" environment run-store -- "$@"; }
