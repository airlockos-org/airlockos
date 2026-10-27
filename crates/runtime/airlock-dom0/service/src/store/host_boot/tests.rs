//! Boot selection must identify one exact system before storage assembly starts.

use super::boot_system;

/// Ambiguous roots and escaping specialisations cannot select a host generation.
#[test]
fn rejects_ambiguous_or_escaping_init_paths() {
    for cmdline in [
        "",
        "init=/bin/init",
        "init=/nix/store/../init",
        "init=/nix/store/a/b/init",
        "init=/nix/store/a/init init=/nix/store/b/init",
        "init=/nix/store/a/specialisation/../init",
        "init=/nix/store/a/specialisation/x/y/init",
    ] {
        assert!(boot_system(cmdline).is_err(), "{cmdline:?}");
    }
}

/// A specialisation remains part of the selected system identity.
#[test]
fn preserves_exact_selected_system() {
    for suffix in ["", "/specialisation/usb-lab"] {
        let system = format!("/nix/store/{hash}-system{suffix}", hash = "a".repeat(32));
        assert_eq!(
            boot_system(&format!("quiet init={system}/init")).unwrap(),
            system
        );
    }
}
