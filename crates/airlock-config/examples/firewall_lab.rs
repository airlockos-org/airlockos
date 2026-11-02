//! Author the minimum Linux services and client initrd for the existing Xen/QEMU lab.
//! This exports committed integration sources and a build expression; it never deploys.

use anyhow::{Context, Result};
use rusix::{
    interop::{
        NixExpression, NixPath,
        raw::{NixRepresentation, NixValue},
    },
    nix_record,
};
use std::{
    path::{Path, PathBuf},
    process::Command,
};

/// Retain an explicit immutable source path in the generated build graph.
fn source(path: &Path) -> Result<NixValue> {
    let path = path.canonicalize()?;
    Ok(NixPath::from_source_text(path.to_string_lossy().into_owned()).as_expression())
}

/// Export committed Git trees with Git/tar, so unpublished development pins use
/// their local bytes instead of being fetched from public submodule URLs.
fn export(repository: &Path, destination: &Path) -> Result<()> {
    std::fs::create_dir_all(destination)?;
    let archive = destination.with_extension("tar");
    let status = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["archive", "--format=tar", "HEAD"])
        .arg("--output")
        .arg(&archive)
        .status()?;
    anyhow::ensure!(
        status.success(),
        "cannot archive committed integration source"
    );
    let status = Command::new("tar")
        .arg("-xf")
        .arg(&archive)
        .arg("-C")
        .arg(destination)
        .status()?;
    std::fs::remove_file(archive)?;
    anyhow::ensure!(
        status.success(),
        "cannot extract committed integration source"
    );
    Ok(())
}

/// Build one expression from a committed compatible integration checkout.
fn main() -> Result<()> {
    let integration = PathBuf::from(
        std::env::args()
            .nth(1)
            .context("usage: firewall_lab INTEGRATION_CHECKOUT")?,
    )
    .canonicalize()?;
    let revision = Command::new("git")
        .args([
            "-C",
            integration.to_str().context("UTF-8 source path")?,
            "rev-parse",
            "HEAD",
        ])
        .output()?;
    anyhow::ensure!(
        revision.status.success(),
        "integration revision is unavailable"
    );
    let revision = String::from_utf8(revision.stdout)?.trim().to_owned();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("workspace parent")?;
    let fixture = source(&root.join("tooling/airlock-dev/firewall-peer"))?;
    let fixture_manifest = source(&root.join("tooling/airlock-dev/firewall-peer/Cargo.toml"))?;
    let fixture_lock = source(&root.join("tooling/airlock-dev/firewall-peer/Cargo.lock"))?;
    let fixture_source = source(&root.join("tooling/airlock-dev/firewall-peer/src"))?;
    let qubes = root.join("vendor/nixos-qubes/pkgs/by-name/qu");
    let vchan_package = source(&qubes.join("qubes-core-vchan-xen/package.nix"))?;
    let db_package = source(&qubes.join("qubes-core-qubesdb/package.nix"))?;
    let submodules = Command::new("git")
        .arg("-C")
        .arg(&integration)
        .args(["submodule", "status", "--recursive"])
        .output()?;
    anyhow::ensure!(
        submodules.status.success(),
        "cannot inspect integration pins"
    );
    anyhow::ensure!(
        String::from_utf8(submodules.stdout)?
            .lines()
            .all(|line| line.starts_with(' ')),
        "integration submodules must match their committed pins"
    );
    let logs = root
        .parent()
        .context("repository parent")?
        .join(".airlock-logs");
    std::fs::create_dir_all(&logs)?;
    let temporary = tempfile::Builder::new()
        .prefix(&format!("firewall-integration-{revision}-"))
        .tempdir_in(logs)?;
    export(&integration, temporary.path())?;
    for relative in [
        "vendor/hermit-kernel",
        "vendor/rust-vmm-xen",
        "vendor/rust-vmm-xen/rust-vmm-ci",
    ] {
        export(
            &integration.join(relative),
            &temporary.path().join(relative),
        )?;
    }
    // Publish a source path only after every committed tree has been exported.
    // Keeping it alongside the expression lets a later Nix invocation consume it.
    let snapshot = temporary.keep();
    let integration =
        NixValue::builtin("getFlake").call(format!("path:{path}", path = snapshot.display()));
    let output = integration.bind(|integration| {
        NixValue::builtin("import").call(integration.clone().select("inputs.nixpkgs")).call(nix_record! { "system": "x86_64-linux" }).bind(|pkgs| {
            let peer = pkgs.clone().select("pkgsStatic.rustPlatform.buildRustPackage").call(nix_record! {
                "pname": "airlock-firewall-lab-peer", "version": "0.1.0", "src": pkgs.clone().select("lib.fileset.toSource").call(nix_record! {
                    "root": fixture.clone(), "fileset": pkgs.clone().select("lib.fileset.unions").call(NixValue::list([fixture_manifest, fixture_lock.clone(), fixture_source])),
                }),
                "cargoLock": nix_record! { "lockFile": fixture_lock },
                "cargoBuildFlags": NixValue::list(["--bins".into()]),
            });
            peer.bind(|peer| {
                let modules = pkgs.clone().select("makeModulesClosure").call(nix_record! {
                    "kernel": pkgs.clone().select("linuxPackages.kernel.modules"),
                    "rootModules": NixValue::list(["xen-netfront".into()]), "allowMissing": false,
                    "firmware": pkgs.clone().select("runCommand").call("firewall-lab-no-firmware").call(nix_record! {}).call("mkdir -p $out/lib/firmware"),
                });
                let initrd = pkgs.clone().select("makeInitrd").call(nix_record! { "contents": NixValue::list([
                    nix_record! { "object": rusix::nix_text!("{peer}/bin/client", peer=peer.clone()), "symlink": "/init" },
                    nix_record! { "object": rusix::nix_text!("{busybox}/bin", busybox=pkgs.clone().select("pkgsStatic.busybox")), "symlink": "/bin" },
                    nix_record! { "object": rusix::nix_text!("{modules}/lib/modules", modules=modules), "symlink": "/lib/modules" },
                    nix_record! { "object": rusix::nix_text!("{kmod}/bin/modprobe", kmod=pkgs.clone().select("kmod")), "symlink": "/sbin/modprobe" },
                    nix_record! { "object": rusix::nix_text!("{iproute}/bin/ip", iproute=pkgs.clone().select("iproute2")), "symlink": "/sbin/ip" },
                ]) });
                let vchan = pkgs.clone().select("callPackage").call(vchan_package).call(nix_record! { "qubes-vmm-xen": pkgs.clone().select("xen") });
                let database = pkgs.clone().select("callPackage").call(db_package).call(nix_record! { "qubes-core-vchan-xen": vchan });
                let settings = nix_record! {
                    "daemon": rusix::nix_text!("{daemon}/bin/qubesdb-daemon", daemon=database.clone().select("daemon")),
                    "database": database.clone().to_text(),
                    "dnsmasq": rusix::nix_text!("{dnsmasq}/bin/dnsmasq", dnsmasq=pkgs.clone().select("dnsmasq")),
                    "ip": rusix::nix_text!("{iproute}/bin/ip", iproute=pkgs.clone().select("iproute2")),
                    "kernel": rusix::nix_text!("{kernel}/bzImage", kernel=pkgs.clone().select("linuxPackages.kernel")),
                    "initrd": rusix::nix_text!("{initrd}/initrd", initrd=initrd.clone()),
                };
                let module = nix_record! {
                    // QEMU has no external NIC. Both allowed and forbidden
                    // listeners must be reachable on this isolated lab link.
                    "networking": nix_record! { "firewall": nix_record! { "enable": false } },
                    "environment": nix_record! { "etc": nix_record! { "airlock-firewall-lab.json": nix_record! { "text": NixValue::builtin("toJSON").call(settings) } } },
                };
                let lab = integration.clone().select("lib.x86_64-linux.buildLab").call(nix_record! { "extraModules": NixValue::list([module]) });
                nix_record! { "lab": lab, "peer": peer, "initrd": initrd, "kernel": integration.clone().select("packages.x86_64-linux.hermit-kernel") }
            })
        })
    });
    let generated =
        rusix::compile_value(output).map_err(|error| anyhow::anyhow!(error.render(root)))?;
    print!("{source}", source = generated.source);
    Ok(())
}
