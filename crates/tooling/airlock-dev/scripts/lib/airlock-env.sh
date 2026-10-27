#!/usr/bin/env bash
# Compatibility exports for external callers; environment policy lives in Rust.
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../../.." && pwd)}"
if [[ -z "${AIRLOCK_DEV_BIN:-}" ]]; then
    make --no-print-directory -C "$ROOT" dev-tools-bootstrap || return
    _AIRLOCK_ENV_NATIVE="$(cd "$ROOT" && realpath "${CARGO_TARGET_DIR:-crates/target}/debug/airlock-dev")" || return
else
    _AIRLOCK_ENV_NATIVE="$AIRLOCK_DEV_BIN"
fi
_AIRLOCK_ENV_EXPORTS="$("$_AIRLOCK_ENV_NATIVE" --repository-root "$ROOT" environment exports)" || return
eval "$_AIRLOCK_ENV_EXPORTS"
unset _AIRLOCK_ENV_EXPORTS

airlock_store_uses_chroot() { "$_AIRLOCK_ENV_NATIVE" --repository-root "$ROOT" environment uses-chroot; }

airlock_physical_store_path() { "$_AIRLOCK_ENV_NATIVE" --repository-root "$ROOT" environment physical "$1"; }

airlock_physical_path_list() { "$_AIRLOCK_ENV_NATIVE" --repository-root "$ROOT" environment physical-list "$1"; }

airlock_store_path_root() { "$_AIRLOCK_ENV_NATIVE" --repository-root "$ROOT" environment store-root "$1"; }

airlock_run_store_path() { "$_AIRLOCK_ENV_NATIVE" --repository-root "$ROOT" environment run-store -- "$@"; }

airlock_exec_store_path() { exec "$_AIRLOCK_ENV_NATIVE" --repository-root "$ROOT" environment run-store -- "$@"; }
