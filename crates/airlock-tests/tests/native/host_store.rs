//! Sealed host boot selections are checksum-bound to retained pool generations and independent boot artifacts.

use crate::{
    common::{self, store::Store},
    storage_integrity::snapshot,
};
use anyhow::Result;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

/// One admitted host, exact boot metadata and a disposable EFI partition.
struct Host {
    // Owns the immutable system tree and retained pool generation.
    store: Store,
    // Retained registration and image digests validated before selecting a boot entry.
    record: Value,
    // Private EFI files; no real firmware variables or host boot partition are accessed.
    esp: PathBuf,
}

impl Host {
    /// Admit a host generation and construct the minimum valid Xen PE boot entry.
    fn new() -> Result<Self> {
        let store = Store::new()?;
        fs::write(
            store
                .physical
                .join(Path::new(&store.system).file_name().unwrap())
                .join("kernel.elf"),
            b"fixture executable",
        )?;
        let receipt = common::json(
            store
                .command(&["pool", "admit", "--pool-root"])
                .arg(&store.pool)
                .args([
                    "--domain",
                    "dom0",
                    "--system",
                    &store.system,
                    "--closure-source",
                ])
                .arg(&store.closure)
                .arg("--physical-store-root")
                .arg(&store.physical)
                .args(["--verify-mode", "tree", "--activate", "false"]),
            None,
        )?;
        let manifest = PathBuf::from(receipt["manifest"].as_str().unwrap());
        let registration = manifest.parent().unwrap().join("registration");
        fs::write(
            &registration,
            format!(
                "{system}\n{hash}\n42\n\n0\n",
                system = store.system,
                hash = "0".repeat(64)
            ),
        )?;
        let mut record = json!({
            "schema": "airlock.host-store.v1", "system": store.system, "generation": receipt["generation"],
            "manifest": manifest, "registration": registration, "closure_hash": receipt["closure_hash"],
            "metadata_image": receipt["canonical_metadata_image"], "blob_map": receipt["canonical_blob_map"]
        });
        for field in ["registration", "metadata_image", "blob_map"] {
            let bytes = fs::read(record[field].as_str().unwrap())?;
            record[format!("{field}_sha256")] =
                json!(format!("{hash:x}", hash = Sha256::digest(bytes)));
        }
        store.run(&[
            "pool",
            "mark-running",
            "--pool-root",
            store.pool_text(),
            "--domain",
            "dom0",
            "--generation",
            &receipt["generation"].to_string(),
            "--volume",
            "host-retained",
        ])?;
        let boots = store.pool.join("host/boots");
        fs::create_dir_all(&boots)?;
        let name = PathBuf::from(&store.system).file_name().unwrap().to_owned();
        fs::write(
            boots.join(name).with_extension("json"),
            serde_json::to_vec(&record)?,
        )?;
        let esp = store.temporary.path().join("esp");
        fs::create_dir_all(esp.join("loader/entries"))?;
        fs::create_dir_all(esp.join("EFI/nixos"))?;
        fs::write(
            esp.join("loader/loader.conf"),
            "default xen-host.conf\ntimeout 5\n",
        )?;
        fs::write(esp.join("EFI/nixos/kernel"), b"kernel")?;
        fs::write(esp.join("EFI/nixos/initrd"), b"initramfs")?;
        let config = format!(
            "kernel=kernel init={system}/init\nramdisk=initrd\n",
            system = store.system
        );
        fs::write(esp.join("EFI/nixos/xen.efi"), pe(&config))?;
        fs::write(
            esp.join("loader/entries/xen-host.conf"),
            format!(
                r"title NixOS
version Generation 7 test
efi /EFI/nixos/xen.efi
# airlock-generation 7
# airlock-role normal
# airlock-system {system}
# airlock-revision {revision}
# airlock-timestamp 1790778600
",
                system = store.system,
                revision = "a".repeat(40)
            ),
        )?;
        Ok(Self { store, record, esp })
    }

    /// Construct an offline host operation using only the private pool and EFI partition.
    fn command(&self, arguments: &[&str]) -> Command {
        let mut command = self.store.command(&["host", "--offline", "--pool-root"]);
        command
            .arg(&self.store.pool)
            .arg("--efi-directory")
            .arg(&self.esp)
            .args(arguments);
        command
    }

    /// Run a successful command through its native JSON boundary.
    fn run(&self, arguments: &[&str]) -> Result<Value> {
        common::json(&mut self.command(arguments), None)
    }

    /// Copy admitted bytes into an image seed and apply the production runtime path convention.
    fn image_seed(&self) -> Result<PathBuf> {
        let seed = self.store.temporary.path().join("image-seed");
        let pool = seed.join("pool");
        let old = self.store.pool.to_str().unwrap();
        let installed = "/var/lib/airlock/closure-store";
        for (relative, (bytes, _)) in snapshot(&self.store.pool)? {
            let path = pool.join(relative);
            fs::create_dir_all(path.parent().unwrap())?;
            if path.extension().is_some_and(|s| s == "json") {
                let mut value: Value = serde_json::from_slice(&bytes)?;
                relocate_seed_json(&mut value, old, installed);
                fs::write(path, serde_json::to_vec(&value)?)?;
            } else {
                fs::write(path, bytes)?;
            }
        }
        let boots = pool.join("host/boots");
        for entry in fs::read_dir(boots)? {
            let path = entry?.path();
            let mut record: Value = serde_json::from_slice(&fs::read(&path)?)?;
            let map =
                pool.join(Path::new(record["blob_map"].as_str().unwrap()).strip_prefix(installed)?);
            record["blob_map_sha256"] =
                json!(format!("{hash:x}", hash = Sha256::digest(fs::read(map)?)));
            fs::write(path, serde_json::to_vec(&record)?)?;
        }
        let mut fingerprints = json!({});
        for (relative, (bytes, _)) in snapshot(&pool)? {
            fingerprints[relative.to_str().unwrap()] = json!({"size":bytes.len(), "sha256":format!("{hash:x}", hash = Sha256::digest(&bytes))});
        }
        fs::write(
            seed.join("pool-fingerprints.json"),
            serde_json::to_vec(&fingerprints)?,
        )?;
        Ok(seed)
    }
}

/// Relocate fixture records together, including retained map and manifest references.
fn relocate_seed_json(value: &mut Value, old: &str, installed: &str) {
    match value {
        Value::String(text)
            if text == old
                || text
                    .strip_prefix(old)
                    .is_some_and(|tail| tail.starts_with('/')) =>
        {
            *text = format!("{installed}{tail}", tail = &text[old.len()..]);
        }
        Value::Array(values) => {
            for value in values {
                relocate_seed_json(value, old, installed);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                relocate_seed_json(value, old, installed);
            }
        }
        _ => {}
    }
}

/// A real packaged manifest gates assembly of a mixed topology; receipts and missing artifacts cannot bypass it.
#[test]
fn mixed_image_assembly_requires_checked_seed_and_complete_host_artifacts() -> Result<()> {
    let host = Host::new()?;
    let seed = host.image_seed()?;
    let root = host.store.temporary.path();
    let topology_path = root.join("topology.json");
    let marker = root.join("assembly-started.json");
    let linux = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-linux";
    let mut topology = json!({"schema":"airlock.qubes-topology.v1", "domains":{
        "sys-clipboard":{
            "class":"HermitVM", "netvm":null, "template":null, "features":{"qrexec":"","gui":""},
            "prefs":{"memory":32,"maxmem":32,"vcpus":1,"kernel":"","virt_mode":"pvh","guivm":null,"audiovm":null},
            "backend":{"type":"hermit","system":{"source":host.store.system},"artifact":{
                "schema":"airlock.hermit-pvh.v1", "executable":format!("{system}/kernel.elf", system = host.store.system),
                "bytes":64,"sha256":"a".repeat(64),"source_revision":"b".repeat(40),
                "integration_revision":"c".repeat(40),"build_lock":"d".repeat(64),"authority":"disconnected"}}
        },
        "usr-home":{
            "class":"StandaloneVM","template":null,"netvm":null,
            "backend":{"type":"nix-closure","system":{"source":linux},
                "root":{"source":format!("{linux}/root.img")},"kernel":{"name":"qubes-kernel"},
                "store":{"source":linux,"mode":"shared-closure","device":"/dev/xvde","blobDevice":"/dev/xvdf",
                    "mountpoint":"/nix/store","viewBackend":"erofs-objectmap"}}
        }
    }});
    fs::write(&topology_path, serde_json::to_vec(&topology)?)?;
    let command = |operation: &str| {
        let mut command = host.store.command(&["image", operation]);
        command.arg(&seed).arg(&topology_path).args([
            "--profile",
            "normal",
            "--host",
            &host.store.system,
        ]);
        command
    };
    let checked = common::json(&mut command("verify-host"), None)?;
    assert_eq!(checked["guests"], 2);
    let mut assemble = command("assemble-host");
    assemble
        .arg("--")
        .arg(common::binary("AIRLOCK_TEST_PEER_BIN", "airlock-test-peer"))
        .arg("image-assembly")
        .arg(&marker);
    common::run(&mut assemble, None)?.checked()?;
    let started: Value = serde_json::from_slice(&fs::read(&marker)?)?;
    assert_eq!(started["seed"], seed.to_str().unwrap());
    assert_eq!(started["host"], host.store.system);
    assert_eq!(started["profile"], "normal");
    assert_eq!(started["topology"], checked["topology"]);
    fs::remove_file(&marker)?;

    #[cfg(feature = "qubes")]
    {
        use airlock_deployment_core::boot::artifacts::Profile;
        use airlock_machine_core::boot::artifacts::SelectedBoot;
        // Root disks have separate artifact checks and are excluded from duplicate byte hashing.
        let disk = seed.join("pool/root.img");
        fs::write(&disk, b"original disk")?;
        let selection = SelectedBoot::new(
            Profile::Normal,
            host.store.system.parse()?,
            topology.clone(),
        )?;
        let evidence = airlock_dom0_service::VerifiedImageSeed::verify(&seed, selection)?;
        fs::write(&disk, b"changed disk")?;
        let arguments = ["image-assembly".into(), marker.clone().into_os_string()];
        let failure = evidence
            .assemble(
                common::binary("AIRLOCK_TEST_PEER_BIN", "airlock-test-peer").as_os_str(),
                &arguments,
            )
            .unwrap_err();
        assert!(failure.to_string().contains("verified image input changed"));
        assert!(
            !marker.exists(),
            "changed seed must never reach the upstream builder"
        );
    }

    let missing = "/nix/store/dddddddddddddddddddddddddddddddd-missing-clipboard";
    topology["domains"]["sys-clipboard"]["backend"]["system"]["source"] = json!(missing);
    topology["domains"]["sys-clipboard"]["backend"]["artifact"]["executable"] =
        json!(format!("{missing}/kernel.elf"));
    fs::write(&topology_path, serde_json::to_vec(&topology)?)?;
    let failed = common::run(&mut assemble, None)?;
    assert!(!failed.status.success());
    assert!(
        String::from_utf8_lossy(&failed.stdout).contains("sys-clipboard: boot artifact absent")
    );
    assert!(!marker.exists());

    fs::write(&topology_path, serde_json::to_vec(&checked)?)?;
    assert!(
        !common::run(&mut assemble, None)?.status.success(),
        "a saved success receipt cannot stand in for the selected topology"
    );
    assert!(!marker.exists());
    Ok(())
}

/// The fixture's flat ASCII host record uses the existing canonical JSON fingerprint protocol.
fn binding(record: &Value) -> Result<String> {
    let fields = record
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, value)| {
            Ok(format!(
                "{key}: {value}",
                key = serde_json::to_string(key)?,
                value = serde_json::to_string(value)?
            ))
        })
        .collect::<Result<Vec<_>>>()?
        .join(", ");
    Ok(format!(
        "{hash:x}",
        hash = Sha256::digest(format!("{{{fields}}}").as_bytes())
    ))
}

/// A checked deployment passes the exact immutable generation observed before boot preparation.
fn expected(host: &Host) -> Result<Vec<String>> {
    Ok(vec![
        "--expected-system".into(),
        host.store.system.clone(),
        "--expected-generation".into(),
        host.record["generation"].to_string(),
        "--expected-record".into(),
        binding(&host.record)?,
    ])
}

/// A complete checked receipt selects the same sealed generation as the administrative path.
#[test]
fn checked_host_selection_preserves_the_observed_generation() -> Result<()> {
    let host = Host::new()?;
    host.run(&["seal-boot", "--keep-default"])?;
    let mut select = host.command(&["select", &host.store.system]);
    select.args(expected(&host)?);
    assert_eq!(common::json(&mut select, None)?, host.record);
    Ok(())
}

/// Stale identities fail before boot, machine-binding or installation effects, even after a valid observation.
#[test]
fn changed_host_record_cannot_reach_a_checked_boot_effect() -> Result<()> {
    for operation in [
        "select",
        "seal-boot",
        "bind-machine",
        "install-boot-isolated",
    ] {
        let host = Host::new()?;
        host.run(&["seal-boot", "--keep-default"])?;
        let arguments = expected(&host)?;
        let mut changed = host.record.clone();
        changed["changed_after_observation"] = json!(true);
        let name = PathBuf::from(&host.store.system)
            .file_name()
            .unwrap()
            .to_owned();
        fs::write(
            host.store
                .pool
                .join("host/boots")
                .join(name)
                .with_extension("json"),
            serde_json::to_vec(&changed)?,
        )?;
        // The new record remains internally valid. The checked request must reject its changed identity.
        host.run(&["validate", &host.store.system])?;
        let before = fs::read(host.esp.join("loader/loader.conf"))?;
        let mut command = if operation == "seal-boot" {
            host.command(&[operation, "--keep-default"])
        } else {
            host.command(&[operation, &host.store.system])
        };
        command.args(&arguments);
        let output = common::run(&mut command, None)?;
        assert!(
            !output.status.success(),
            "accepted changed record for {operation}"
        );
        let rejection: Value = serde_json::from_slice(&output.stdout)?;
        assert!(
            rejection["error"]
                .as_str()
                .unwrap()
                .contains("host generation changed"),
            "{operation}: {rejection}"
        );
        assert_eq!(fs::read(host.esp.join("loader/loader.conf"))?, before);
        assert!(!host.store.pool.join("host/selected.json").exists());
    }
    Ok(())
}

/// Partial or substituted nominal identities cannot silently downgrade a checked request to administration.
#[test]
fn checked_host_cli_rejects_partial_and_substituted_identity() -> Result<()> {
    let host = Host::new()?;
    host.run(&["seal-boot", "--keep-default"])?;
    let before = fs::read(host.esp.join("loader/loader.conf"))?;
    for (index, value) in [
        (1, "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-other"),
        (3, "2"),
        (3, "0"),
        (5, "bad-hash"),
    ] {
        let mut arguments = expected(&host)?;
        arguments[index] = value.into();
        let mut command = host.command(&["select", &host.store.system]);
        command.args(arguments);
        assert!(!common::run(&mut command, None)?.status.success());
    }
    let isolated = common::run(
        &mut host.command(&["install-boot-isolated", &host.store.system]),
        None,
    )?;
    assert!(!isolated.status.success());
    let rejection: Value = serde_json::from_slice(&isolated.stdout)?;
    assert!(
        rejection["error"]
            .as_str()
            .unwrap()
            .contains("checked generation or explicit administration"),
        "{rejection}"
    );
    let mut partial = host.command(&["select", &host.store.system]);
    partial.args(["--expected-generation", "1"]);
    assert!(!common::run(&mut partial, None)?.status.success());
    assert_eq!(fs::read(host.esp.join("loader/loader.conf"))?, before);
    assert!(!host.store.pool.join("host/selected.json").exists());
    Ok(())
}

/// Encode one bounded PE configuration section; scenarios corrupt its declared length or contents explicitly.
pub(super) fn pe(config: &str) -> Vec<u8> {
    let mut bytes = vec![0; 512 + config.len()];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[60..64].copy_from_slice(&128_u32.to_le_bytes());
    bytes[128..132].copy_from_slice(b"PE\0\0");
    bytes[134..136].copy_from_slice(&1_u16.to_le_bytes());
    bytes[152..160].copy_from_slice(b".config\0");
    bytes[168..172].copy_from_slice(&(config.len() as u32).to_le_bytes());
    bytes[172..176].copy_from_slice(&512_u32.to_le_bytes());
    bytes[512..].copy_from_slice(config.as_bytes());
    bytes
}

/// Only the requested host record is read, and a retained running pin is mandatory for boot selection.
#[test]
fn host_boot_validation_requires_the_retained_generation() -> Result<()> {
    let host = Host::new()?;
    fs::write(
        host.store.pool.join("host/boots/newer.json"),
        b"{broken unrelated boot",
    )?;
    assert_eq!(host.run(&["validate", &host.store.system])?, host.record);
    fs::remove_file(host.store.pool.join("running/dom0/1/host-retained.json"))?;
    assert!(
        !common::run(&mut host.command(&["validate", &host.store.system]), None)?
            .status
            .success()
    );
    Ok(())
}

/// Changed registration, image or extent-map bytes cannot alter the selected boot configuration.
#[test]
fn host_boot_selection_checks_every_retained_digest() -> Result<()> {
    for field in ["registration", "metadata_image", "blob_map"] {
        let host = Host::new()?;
        let path = std::path::Path::new(host.record[field].as_str().unwrap());
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
        fs::write(path, b"corrupted")?;
        let before = fs::read(host.esp.join("loader/loader.conf"))?;
        assert!(
            !common::run(&mut host.command(&["select", &host.store.system]), None)?
                .status
                .success()
        );
        assert_eq!(fs::read(host.esp.join("loader/loader.conf"))?, before);
        assert!(!host.store.pool.join("host/selected.json").exists());
    }
    Ok(())
}

/// Sealing is idempotent and checksum-bound; the selected host remains protected from retirement.
#[test]
fn sealed_host_boot_is_independent_idempotent_and_protected() -> Result<()> {
    let host = Host::new()?;
    host.run(&["seal-boot", "--keep-default"])?;
    assert!(
        host.esp
            .join("loader/entries/airlock-xen-host.conf")
            .is_file()
    );
    assert!(!host.esp.join("loader/entries/xen-host.conf").exists());
    host.run(&["select", &host.store.system])?;
    assert!(
        fs::read_to_string(host.esp.join("loader/loader.conf"))?
            .contains("default airlock-xen-host.conf")
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(host.store.pool.join("host/selected.json"))?)?,
        host.record
    );
    let before = snapshot(&host.esp)?;
    host.run(&["seal-boot", "--keep-default"])?;
    assert_eq!(snapshot(&host.esp)?, before);
    assert!(
        !common::run(&mut host.command(&["retire", &host.store.system]), None)?
            .status
            .success()
    );
    assert_eq!(snapshot(&host.esp)?, before);
    fs::write(host.esp.join("EFI/airlock/initrd"), b"damaged initramfs")?;
    assert!(
        !common::run(&mut host.command(&["select", &host.store.system]), None)?
            .status
            .success()
    );
    Ok(())
}

/// Ambiguous or oversized Xen configuration is rejected before publishing a sealed loader entry.
#[test]
fn host_boot_sealing_refuses_unbounded_or_ambiguous_configuration() -> Result<()> {
    for damage in ["oversized-config", "duplicate-kernel"] {
        let host = Host::new()?;
        let path = host.esp.join("EFI/nixos/xen.efi");
        let mut bytes = fs::read(&path)?;
        if damage == "oversized-config" {
            bytes[168..172].copy_from_slice(&(2_u32 * 1024 * 1024).to_le_bytes());
            bytes.resize(512 + 2 * 1024 * 1024, 0);
        } else {
            bytes = pe(&format!(
                "kernel=kernel init={system}/init\nkernel=kernel init={system}/init\nramdisk=initrd\n",
                system = host.store.system
            ));
        }
        fs::write(path, bytes)?;
        let before = fs::read(host.esp.join("loader/loader.conf"))?;
        assert!(
            !common::run(&mut host.command(&["seal-boot"]), None)?
                .status
                .success()
        );
        assert_eq!(fs::read(host.esp.join("loader/loader.conf"))?, before);
        assert!(
            !fs::read_dir(host.esp.join("loader/entries"))?
                .filter_map(std::result::Result::ok)
                .any(|entry| entry
                    .file_name()
                    .as_encoded_bytes()
                    .starts_with(b"airlock-"))
        );
    }
    Ok(())
}
