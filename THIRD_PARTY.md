# Third-party source and attribution

The root MIT license covers original Airlock contributions. It does not
relicense vendored source, copied upstream code, derived patches, fetched
packages, firmware, artwork, or built OS images. Preserve each upstream's
copyright, license, and redistribution requirements.

## Sources

| Source | Relationship |
| --- | --- |
| [CertainLach/nixos-qubes](https://github.com/CertainLach/nixos-qubes) | Vendored Qubes/NixOS packaging and module base, with local compatibility fixes. |
| [NixOS/nixpkgs](https://github.com/NixOS/nixpkgs) | Locked NixOS/Xen modules and packages; individual package licenses vary. |
| [Qubes OS](https://github.com/QubesOS) | Existing control, RPC, policy, GUI, storage, and VM lifecycle stack. |
| [Xen](https://xenproject.org/) and [libvirt](https://libvirt.org/) | Upstream virtualization stack and packaging patches. |
| [GNOME Shell](https://gitlab.gnome.org/GNOME/gnome-shell), [pyxdg](https://gitlab.freedesktop.org/xdg/pyxdg), and [EROFS utilities](https://git.kernel.org/pub/scm/linux/kernel/git/xiang/erofs-utils.git/) | Targeted derived patches for integration and storage fixes. |

Exact fetched revisions are recorded in the flake locks and package definitions.
Patch directories group changes by upstream project; patch headers retain
provenance. A package's Nix license metadata is not a license grant for all
source in this repository.

## Website

The landing page, public user documentation, bundled Inter font, and font
license notices are maintained in the sibling `website` project. Its
`THIRD_PARTY.md` records the website asset provenance.

## Rust development tooling

The declaration-spacing checker in `tools/rust-style/src/main.rs` is adapted from
Rusix's `crates/rusix-derive/src/bin/check-rust-spacing.rs` (local source supplied
for this change). Its MIT copyright and terms are retained in
[`tools/rust-style/LICENSE.rusix`](tools/rust-style/LICENSE.rusix).

## Application typeface

`airlock-sys-ctrl-gui` bundles Inter by the Inter Project Authors under the SIL Open
Font License 1.1. The original website WOFF2 source, native TTF instances and
license are retained in [`crates/runtime/airlock-sys-ctrl/gui/assets/fonts/`](crates/runtime/airlock-sys-ctrl/gui/assets/fonts/README.md),
which records the upstream revision, checksum and regeneration procedure.
These font files retain their own license rather than Airlock's MIT license.

## Outstanding vendored-source terms

The inspected `nixos-qubes` snapshot has no LICENSE/COPYING file or explicit
source-license grant in its README. Upstream's license endpoint returned HTTP 404
on 2026-10-11; no license grant was established. Do not assume its repository source is covered by either
Airlock's MIT license or the licenses of the packages it builds. Clarify the
vendored modules/packaging terms with upstream before public redistribution;
retain provenance and do not add an invented license to that directory.

This licensing question is not resolved by adding MIT for original Airlock code.

Shared upstream patches live in [`crates/patches`](crates/patches), grouped by
upstream project with their provenance retained. The vendored `nixos-qubes`
source lives in [`crates/vendor/nixos-qubes`](crates/vendor/nixos-qubes), including
its original provenance and Airlock compatibility notes. Machine and application
inputs select the same committed Airlock snapshot.

## Rusix

`crates/vendor/rusix` contains the MIT-licensed Rusix source from
https://github.com/rndhouse/rusix.
The snapshot includes the local integration commits used by Airlock configuration;
upstream license and Nixpkgs attribution files are preserved. `AIRLOCK-PIN` records
the source identity.
