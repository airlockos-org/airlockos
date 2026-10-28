//! Build VM boot filesystems and manifests for Airlock's shared read-only Nix store.
//! Qubes supplies the kernel and writable private volume independently of these artifacts.

use crate::{Application, Workspace};
use rusix::{
    interop::{
        Package,
        raw::{NixRepresentation, NixValue},
    },
    nix_record, nix_text,
};

/// Route an upstream image builder through the native seed-validation boundary.
/// The original builder and arguments remain unchanged after the checked seed, topology and host.
/// Nix observes these deferred values; the native command performs integrity and completeness checks.
pub fn checked_image_builder(
    native: &NixValue,
    seed: &NixValue,
    topology: &NixValue,
    host: &NixValue,
    original: &NixValue,
) -> NixValue {
    nix_record! {
        "builder": nix_text!("{native}/bin/airlock-dom0-service", native = native.clone()),
        "args": NixValue::concat_lists([
            NixValue::list([
                "storage".into(), "image".into(), "assemble-host".into(),
                seed.clone().to_text(), topology.clone().to_text(),
                "--profile".into(), "normal".into(), "--host".into(), host.clone().to_text(),
                "--".into(), original.clone().select("builder").to_text(),
            ]),
            original.clone().select("args"),
        ]),
    }
}

/// Stage an upstream NixOS raw disk inside its output directory before the assembly VM starts.
/// Publication then renames the file within that directory instead of moving it from build scratch.
/// Evaluation fails if the upstream staging assignment, earlier output-directory creation or raw
/// publication hook changes. Call only for raw images produced by NixOS's `make-disk-image.nix`.
pub fn raw_disk_in_output(lib: &NixValue, image: NixValue) -> NixValue {
    lib.clone().select("overrideDerivation").call(image).call(NixValue::function(|old| {
        let preparation = old.clone().select("preVM");
        let staging = "diskImage=nixos.raw";
        let parts = lib.clone().select("splitString").call(staging).call(preparation.clone());
        let valid = NixValue::builtin("length").call(parts.clone()).equals(2_i64)
            .and(lib.clone().select("hasInfix").call("mkdir $out")
                .call(NixValue::builtin("head").call(parts)))
            .and(lib.clone().select("hasInfix").call("mv $diskImage $out/")
                .call(old.select("postVM")));
        let definitions = nix_record! {
            "preVM": NixValue::builtin("replaceStrings")
                .call(NixValue::list([staging.into()]))
                .call(NixValue::list([r#"diskImage="$out/nixos.raw""#.into()]))
                .call(preparation),
        };

        NixValue::if_else(valid, definitions, NixValue::builtin("throw").call(
            "Upstream raw disk assembly no longer exposes the expected output-directory, staging and publication hooks."
        ))
    }))
}

/// Target packages and application sources used to construct a VM's boot artifacts.
pub struct Images<'a> {
    /// Package set for the target architecture, including statically linked early-boot tools.
    pub pkgs: &'a NixValue,
    /// Application sources used by the native storage-descriptor writer.
    pub workspace: &'a Workspace,
}

impl Images<'_> {
    /// Build a deterministic boot filesystem, sharing one identity across VMs of equal capacity.
    /// Capacity is in MiB. VM names never enter this recipe; Qubes owns writable VM identity.
    /// The separate `metadata` output contains the native service's root descriptor.
    pub fn root(&self, size_mib: NixValue) -> Package {
        let native = Application::PrepareBoot.build(self.pkgs, self.workspace);
        let script = nix_text!(
            r#"
            exec {native}/bin/airlock-prepare-boot root --out "$out" --metadata "$metadata" \
              --size-mib {size} --busybox {busybox}/bin/busybox \
              --init {init}/bin/airlock-vm-init --dom0 {dom0}/bin/airlock-dom0-service
        "#,
            native = native,
            size = size_mib,
            busybox = self.pkgs.clone().select("pkgsStatic.busybox"),
            init = Application::VmInit.build(self.pkgs, self.workspace),
            dom0 = Application::Dom0.build(self.pkgs, self.workspace)
        );

        Package::from_expression(
            self.pkgs
                .clone()
                .select("runCommand")
                .call("airlock-nix-closure-root-image")
                .call(nix_record! {
                    "outputs": NixValue::list(["out".into(), "metadata".into()]),
                    "nativeBuildInputs": self.packages(&[
                        "coreutils", "e2fsprogs", "fakeroot", "findutils",
                    ]),
                    "preferLocalBuild": true,
                    "allowSubstitutes": false,
                })
                .call(script),
        )
    }

    /// Record a closure's store paths without constructing or copying its shared store image.
    /// The runtime storage service prepares EROFS views from this admitted closure manifest.
    pub fn manifest(
        &self,
        name: NixValue,
        roots: NixValue,
        device: NixValue,
        mountpoint: NixValue,
    ) -> Package {
        self.closure_manifest(name, roots, device, mountpoint, false)
    }

    /// Verify installed boot commands against the exact VM closure before publishing its manifest.
    pub fn boot_manifest(
        &self,
        name: NixValue,
        roots: NixValue,
        device: NixValue,
        mountpoint: NixValue,
    ) -> Package {
        self.closure_manifest(name, roots, device, mountpoint, true)
    }

    /// Generic payload closures contain data roots; only boot closures contain NixOS systems to inspect.
    fn closure_manifest(
        &self,
        name: NixValue,
        roots: NixValue,
        device: NixValue,
        mountpoint: NixValue,
        boot: bool,
    ) -> Package {
        let closure = self
            .pkgs
            .clone()
            .select("closureInfo")
            .call(nix_record! { "rootPaths": roots.clone() });
        let root_paths = NixValue::builtin("map")
            .call(NixValue::builtin("toString"))
            .call(roots);
        let settings = self.pkgs.clone().select("writeText").call("closure-settings.json")
            .call(NixValue::builtin("toJSON").call(nix_record! {
                "name": name.clone(), "device": device, "mountpoint": mountpoint, "root_paths": root_paths,
            }));
        let preflight: NixValue = if boot {
            nix_text!(
                "--launcher {launcher}/bin/airlock-exec --readelf {binutils}/bin/readelf",
                launcher = Application::Launcher.build(self.pkgs, self.workspace),
                binutils = self.pkgs.clone().select("binutils"),
            )
            .into()
        } else {
            "".into()
        };
        let script = nix_text!(
            r#"
            exec {native}/bin/airlock-prepare-boot manifest --out "$out" \
              --paths {closure}/store-paths --settings {settings} \
              {preflight}
        "#,
            native = Application::PrepareBoot.build(self.pkgs, self.workspace),
            closure = closure,
            settings = settings,
            preflight = preflight,
        );

        Package::from_expression(
            self.pkgs
                .clone()
                .select("runCommand")
                .call(nix_text!("{name}-store-closure", name = name))
                .call(nix_record! {
                    "nativeBuildInputs": self.packages(&["coreutils", "jq"]),
                    "preferLocalBuild": true,
                    "allowSubstitutes": false,
                })
                .call(script),
        )
    }

    /// Select build executables from the same package set as the artifacts they produce.
    fn packages(&self, names: &[&str]) -> NixValue {
        NixValue::list(names.iter().map(|name| self.pkgs.clone().select(name)))
    }
}
