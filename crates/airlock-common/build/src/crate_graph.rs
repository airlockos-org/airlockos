//! Select the upstream generator used before evaluating prepared crate builds.

use rusix::interop::raw::NixValue;

/// Generator release whose metadata and template contracts preparation relies on.
pub const VERSION: &str = "0.15.0";

/// Select crate2nix from the caller's locked Nixpkgs, refusing an unnoticed version change.
pub fn generator(pkgs: &NixValue) -> NixValue {
    let package = pkgs.clone().select("crate2nix");
    NixValue::if_else(
        package.clone().select("version").equals(VERSION),
        package,
        NixValue::builtin("throw").call("Airlock preparation requires crate2nix 0.15.0"),
    )
}
