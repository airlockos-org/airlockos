//! Export only source inputs and send the same inert archive to the existing staging and validator services.

use super::io::{self, Operation};
use crate::process::Files;
use anyhow::{Context, Result, ensure};
use flate2::{Compression, write::GzEncoder};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

/// Fixed input set already consumed by configuration authoring and validation.
const INPUTS: &[(&str, &str)] = &[
    ("nixpkgs", "nixpkgs"),
    ("nixpkgs-libvirt_10_5", "nixpkgsLibvirt105"),
    ("nixos-qubes", "nixosQubes"),
    ("airlock-support", "airlockSupport"),
    ("airlock-apps", "airlockApps"),
];

/// Find the root store object without losing a manifest's path into that object.
fn store_root(source: &str) -> Result<PathBuf> {
    let suffix = source
        .strip_prefix("/nix/store/")
        .context("config input is not a Nix store path")?;
    let name = suffix
        .split('/')
        .next()
        .filter(|name| !name.is_empty() && *name != "." && *name != "..")
        .context("config input has no store object identity")?;
    ensure!(
        !source.contains("//")
            && !Path::new(source)
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir)),
        "unsafe config input path"
    );
    Ok(PathBuf::from("/nix/store").join(name))
}

/// Export the exact manifest roots, rejecting references that would import runtime dependencies.
pub(super) fn execute() -> Result<()> {
    let mut operation = Operation::new("config-inputs-import")?;
    let root = io::path("AIRLOCK_CONFIG_INPUTS_SOURCE", "/etc/airlock/config-inputs");
    let manifest_path = io::path("AIRLOCK_CONFIG_INPUTS_MANIFEST", root.join("manifest.json"));
    let service = io::setting(
        "AIRLOCK_CONFIG_INPUTS_IMPORT_SERVICE",
        "airlock.Config.InputsImport",
    );
    let staging = io::setting("AIRLOCK_CONFIG_STAGING_VM", "sys-config-staging");
    let validator = io::setting("AIRLOCK_CONFIG_VALIDATOR_VM", "sys-config-validator");
    let wait: u64 = io::setting("AIRLOCK_CONFIG_INPUTS_QREXEC_TIMEOUT", "600").parse()?;
    let mut archive_bytes = 0;
    let mut export_bytes = 0;
    let mut roots = BTreeSet::new();
    let result: Result<()> = (|| {
        let temporary = tempfile::tempdir()?;
        let manifest = if manifest_path.is_file() {
            Some(crate::state::configuration::<Value>(&manifest_path)?)
        } else {
            None
        };
        let mut normalized = json!({"schema":"airlock.config-inputs.v1","inputs":{}});
        for (name, legacy) in INPUTS {
            ensure!(
                root.join(name).is_dir(),
                "missing config input directory: {root}/{name}",
                root = root.display()
            );
            let source = match &manifest {
                Some(manifest) => {
                    let value = if manifest["schema"] == "airlock.config-inputs.v1"
                        && manifest["inputs"].is_object()
                    {
                        &manifest["inputs"][*name]
                    } else {
                        &manifest[*legacy]
                    };
                    value
                        .as_str()
                        .filter(|source| !source.is_empty())
                        .with_context(|| {
                            format!("config input manifest is missing path for: {name}")
                        })?
                        .to_owned()
                }
                None => fs::canonicalize(root.join(name))?
                    .to_str()
                    .context("non-UTF-8 config input path")?
                    .into(),
            };
            let store = store_root(&source)?;
            let references = operation.text(
                "nix-store",
                &["-q", "--references", store.to_str().unwrap()],
            )?;
            ensure!(
                references
                    .lines()
                    .all(|reference| reference == store.to_string_lossy()),
                "config input has Nix store references and would pull runtime baggage: {name} -> {references}"
            );
            roots.insert(store);
            normalized["inputs"][*name] = json!(source);
        }
        io::save(&temporary.path().join("manifest.json"), &normalized)?;
        let mut paths = File::create(temporary.path().join("store-paths"))?;
        for root in &roots {
            writeln!(paths, "{root}", root = root.display())?;
        }
        let mut args = vec!["--export".into()];
        args.extend(roots.iter().map(|path| path.as_os_str().to_owned()));
        let export = temporary.path().join("store-export.nar");
        operation.transfer(
            "nix-store",
            &args,
            Files {
                input: None,
                output: &export,
                errors: &operation.file("config-inputs-export.stderr.log"),
                limit: 8 * 1024 * 1024 * 1024,
            },
            &[],
        )?;
        let compressed = temporary.path().join("store-export.nar.gz");
        let mut gzip = GzEncoder::new(File::create(&compressed)?, Compression::fast());
        std::io::copy(&mut File::open(export)?, &mut gzip)?;
        gzip.finish()?;
        export_bytes = compressed.metadata()?.len();
        let archive = temporary.path().join("config-inputs.tar");
        let mut tar = tar::Builder::new(File::create(&archive)?);
        for name in ["manifest.json", "store-paths", "store-export.nar.gz"] {
            tar.append_path_with_name(temporary.path().join(name), name)?;
        }
        tar.finish()?;
        drop(tar);
        archive_bytes = archive.metadata()?.len();
        for vm in [&staging, &validator] {
            let _: airlock_nix_core::identity::GuestName = vm.parse()?;
            operation.start(vm)?;
            operation
                .transfer(
                    "qrexec-client",
                    &[
                        "-d".into(),
                        vm.into(),
                        "-T".into(),
                        "-w".into(),
                        wait.to_string().into(),
                        format!("DEFAULT:QUBESRPC {service}+ dom0").into(),
                    ],
                    Files {
                        input: Some(&archive),
                        output: &operation.file(&format!("config-inputs-import-{vm}.stdout.log")),
                        errors: &operation.file(&format!("config-inputs-import-{vm}.stderr.log")),
                        limit: 16 * 1024 * 1024,
                    },
                    &[],
                )
                .with_context(|| format!("config input import failed for {vm}"))?;
        }
        Ok(())
    })();
    let receipt = json!({"schema":"airlock.config-inputs-import.v1","status":if result.is_ok() {"passed"} else {"failed"},"reason":match &result {Ok(()) => "configuration inputs imported".into(),Err(error) => format!("{error:#}")},"source_root":root,"service":service,"staging":staging,"validator":validator,"archive_bytes":archive_bytes,"store_export_bytes":export_bytes,"store_path_count":roots.len(),"timestamp":time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?});
    io::save(&operation.file("config-inputs-import.json"), &receipt)?;
    println!("{receipt}");
    result
}
