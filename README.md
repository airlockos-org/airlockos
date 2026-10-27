<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/airlock-wordmark-thin-red-dark.svg">
    <img alt="AirlockOS" src="docs/assets/airlock-wordmark-thin-red-light.svg" height="64">
  </picture>
</p>

AirlockOS uses the [Qubes](https://www.qubes-os.org/) architecture, with machine
configuration written in Rust and built through Nix. Xen runs all virtual
machines (VMs), including dom0, the privileged control VM.

- [NixOS](https://nixos.org/) for dom0, the desktop, networking, and user applications.
- Whole-machine updates and system generation rollback.
- Shared global Nix store with read-only per-VM closure views.
- Persistent private VM data across updates and rollback.
- Qubes VM isolation, device assignment, and inter-VM RPC policy.
- GNOME desktop displaying applications from multiple VMs.

[![VM layout: Xen runs dom0 and the system and user VMs. Dom0 manages the shared Nix store and provides read-only closure views to the other VMs.](docs/assets/system-overview.svg)](docs/assets/system-overview.svg)

AirlockOS is under active development. Qubes OS security equivalence has not
been established. See [Security](SECURITY.md) for limitations and reporting.

Original code is [MIT licensed](LICENSE). Dependencies retain their own terms;
see [third-party notices](THIRD_PARTY.md).
