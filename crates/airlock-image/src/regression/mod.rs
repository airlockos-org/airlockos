//! Exercise image contracts directly through the implementation; process integration tests own external tool peers.

mod process;

mod gate;

#[cfg(feature = "qubes")]
use crate::runtime;

use crate::{acceptance, usb};
use anyhow::Result;
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
};

/// USB identity, mutable destinations and existing private files fail closed before any disk operation.
#[test]
fn usb_paths_and_private_files_preserve_explicit_ownership() -> Result<()> {
    for device in [
        "/dev/sda",
        "/dev/nvme0n1",
        "/",
        "/dev/disk/by-id/ata-disk",
        "/dev/disk/by-id/usb-test/../other",
    ] {
        let result = usb::device::by_id(Path::new(device));
        assert!(result.unwrap_err().to_string().contains("whole-disk"));
    }
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    symlink("/tmp", root.join("home"))?;
    for relative in ["home/user/.ssh", "../outside", "/etc/passwd"] {
        assert!(usb::personalize::beneath(root, Path::new(relative)).is_err());
    }
    let path = root.join("existing");
    fs::write(&path, "keep")?;
    let write = |data: &[u8]| {
        usb::personalize::private_file(
            &path,
            data,
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
            false,
        )
    };
    assert!(write(b"replacement").is_err());
    assert_eq!(fs::read(&path)?, b"keep");
    fs::remove_file(&path)?;
    write(b"private")?;
    assert_eq!(path.metadata()?.permissions().mode() & 0o777, 0o600);
    assert_eq!(usb::personalize::password(true)?, "password");
    Ok(())
}

/// Missing or malformed device counters do not prevent an otherwise valid image operation.
#[test]
fn device_progress_counters_are_optional_and_checked() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("stat");
    assert_eq!(usb::progress::stats(&path), None);
    for text in ["", "bad data", "0 0 0 0 0 0 -1 0 0"] {
        fs::write(&path, text)?;
        assert_eq!(usb::progress::stats(&path), None);
    }
    fs::write(&path, "0 0 0 0 0 0 32768 0 1")?;
    assert_eq!(usb::progress::stats(&path), Some((32768 * 512, 1)));
    Ok(())
}

/// Describe the actual seed layout while allowing individual corruption of its disk and partition identities.
fn table() -> Value {
    json!({"label": "gpt", "device": "/dev/sdc", "id": "disk-id", "sectorsize": 512, "lastlba": 67108830,
    "partitions": [
        {"node": "/dev/sdc1", "start": 16384, "size": 2082816, "type": "C12A7328-F81F-11D2-BA4B-00A0C93EC93B", "uuid": "esp-id"},
        {"node": "/dev/sdc2", "start": 2099200, "size": 65007616, "type": "0FC63DAF-8483-4772-8E79-3D69D8477DE4", "uuid": "root-id"}
    ]})
}

/// Root growth accepts only the expected GPT geometry and preserves every disk and partition identity.
#[test]
fn root_growth_rejects_unexpected_geometry_and_changed_identities() -> Result<()> {
    let before: usb::growth::Table = serde_json::from_value(table())?;
    usb::growth::checked_layout(
        &before,
        Path::new("/dev/sdc"),
        Path::new("/dev/sdc2"),
        62495129600,
    )?;
    assert_eq!(before.partitions[1].start, 2099200);
    for damage in [
        "mbr", "extra", "overlap", "sector", "identity", "beyond", "type", "overflow",
    ] {
        let mut value = table();
        match damage {
            "mbr" => value["label"] = json!("dos"),
            "extra" => {
                let partition = value["partitions"][0].clone();
                value["partitions"].as_array_mut().unwrap().push(partition);
            }
            "overlap" => value["partitions"][1]["start"] = json!(40),
            "sector" => value["sectorsize"] = json!(4096),
            "identity" => value["partitions"][1]["uuid"] = json!(""),
            "beyond" => value["partitions"][1]["size"] = json!(1_000_000_000_000_u64),
            "type" => value["partitions"][1]["type"] = json!("different"),
            "overflow" => value["partitions"][1]["size"] = json!(u64::MAX),
            _ => unreachable!(),
        }
        let table = serde_json::from_value(value)?;
        assert!(
            usb::growth::checked_layout(
                &table,
                Path::new("/dev/sdc"),
                Path::new("/dev/sdc2"),
                62495129600
            )
            .is_err(),
            "accepted {damage}"
        );
    }
    let mut expanded = table();
    expanded["lastlba"] = json!(122060766_u64);
    expanded["partitions"][1]["size"] = json!(122060767_u64 - 2099200);
    usb::growth::checked_result(&before, &serde_json::from_value(expanded.clone())?)?;
    for damage in ["start", "uuid", "esp", "disk", "shrink", "not-full"] {
        let mut after = expanded.clone();
        match damage {
            "start" => after["partitions"][1]["start"] = json!(20),
            "uuid" => after["partitions"][1]["uuid"] = json!("changed"),
            "esp" => after["partitions"][0]["size"] = json!(2082817),
            "disk" => after["id"] = json!("other"),
            "shrink" => after["partitions"][1]["size"] = json!(1),
            "not-full" => {
                after["partitions"][1]["size"] =
                    json!(after["partitions"][1]["size"].as_u64().unwrap() - 2048)
            }
            _ => unreachable!(),
        }
        assert!(
            usb::growth::checked_result(&before, &serde_json::from_value(after)?).is_err(),
            "accepted {damage}"
        );
    }
    assert!(!usb::growth::fills_disk(&before, 62495129600));
    let mut full = table();
    full["lastlba"] = json!(62495129600_u64 / 512 - 34);
    full["partitions"][1]["size"] = json!(61420322304_u64 / 512);
    assert!(usb::growth::fills_disk(
        &serde_json::from_value(full)?,
        62495129600
    ));
    Ok(())
}

/// Firmware inputs are bounded regular files with a complete VFCT header and valid ACPI checksum.
#[test]
fn personalization_firmware_rejects_corrupt_and_special_files() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("vfct");
    let mut bytes = vec![0; 36];
    bytes[..4].copy_from_slice(b"VFCT");
    bytes[4..8].copy_from_slice(&36_u32.to_le_bytes());
    bytes[9] = 0_u8.wrapping_sub(bytes.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte)));
    fs::write(&path, &bytes)?;
    assert_eq!(usb::personalize::vfct(&path)?, bytes);
    bytes[35] ^= 1;
    fs::write(&path, bytes)?;
    assert!(usb::personalize::vfct(&path).is_err());
    let fifo = temporary.path().join("fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR,
        0,
    )?;
    assert!(usb::personalize::vfct(&fifo).is_err());
    Ok(())
}

/// Logical input references cannot escape a selected store object or smuggle query parameters.
#[test]
fn offline_source_references_encode_store_names_and_reject_traversal() -> Result<()> {
    let root = format!("/nix/store/{hash}-source", hash = "a".repeat(32));
    assert_eq!(acceptance::input_reference(&root)?, format!("path:{root}"));
    for directory in ["apps", "crates", "crates/vendor/nixos-qubes"] {
        assert_eq!(
            acceptance::input_reference(&format!("{root}/{directory}"))?,
            format!("path:{root}/{directory}")
        );
    }
    for suffix in ["/../escape", "/a/./b", "/a//b", "/a\nb"] {
        assert!(acceptance::input_reference(&format!("{root}{suffix}")).is_err());
    }
    let root = format!("{root}?dir=evil");
    assert_eq!(
        acceptance::input_reference(&format!("{root}/apps"))?,
        format!(
            "path:{root}/apps",
            root = root.replace('?', "%3F").replace('=', "%3D")
        )
    );
    Ok(())
}

/// Store-relative links resolve inside the selected physical store, including linked parent directories.
#[test]
fn offline_tools_cannot_escape_the_selected_physical_store() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let base = format!("/nix/store/{hash}-source", hash = "a".repeat(32));
    let other = format!("/nix/store/{hash}-tools", hash = "b".repeat(32));
    let source = root.join(base.trim_start_matches('/'));
    let target = root.join(other.trim_start_matches('/'));
    fs::create_dir_all(source.join("bin"))?;
    fs::create_dir_all(source.join("libexec"))?;
    fs::create_dir(&target)?;
    let tool = source.join("libexec/nix");
    fs::write(&tool, b"nix")?;
    symlink("../libexec/nix", source.join("bin/nix"))?;
    assert_eq!(
        acceptance::store_file(root, &format!("{base}/bin/nix"))?,
        tool
    );
    fs::remove_file(source.join("bin/nix"))?;
    symlink("/bin/sh", source.join("bin/nix"))?;
    assert!(acceptance::store_file(root, &format!("{base}/bin/nix")).is_err());
    fs::remove_file(source.join("bin/nix"))?;
    fs::remove_dir(source.join("bin"))?;
    fs::write(target.join("nix"), b"tool")?;
    symlink(&other, source.join("bin"))?;
    assert_eq!(
        acceptance::store_file(root, &format!("{base}/bin/nix"))?,
        target.join("nix")
    );
    for destination in [root, Path::new("bin")] {
        fs::remove_file(source.join("bin"))?;
        symlink(destination, source.join("bin"))?;
        assert!(acceptance::store_file(root, &format!("{base}/bin/nix")).is_err());
    }
    Ok(())
}

/// Finding a build result cannot follow an image symlink outside its selected output directory.
#[test]
fn usb_result_discovery_stays_within_its_store_output() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("physical");
    let logical = format!("/nix/store/{hash}-image", hash = "a".repeat(32));
    let output = root.join(logical.trim_start_matches('/'));
    fs::create_dir_all(&output)?;
    let image = output.join("seed.img");
    fs::write(&image, b"fixture")?;
    let link = temporary.path().join("result");
    symlink(logical, &link)?;
    assert_eq!(usb::result_image(&link, Some(&root))?, image);
    fs::remove_file(&image)?;
    let outside = temporary.path().join("outside.img");
    fs::write(&outside, b"outside")?;
    symlink(outside, image)?;
    assert!(usb::result_image(&link, Some(&root)).is_err());
    Ok(())
}

/// Parse the real domain label declaration before asking the image planner to allocate upstream indices.
#[cfg(feature = "qubes")]
fn domain_label(label: Value, color: Value) -> Result<Value> {
    let domain: runtime::model::Domain = serde_json::from_value(json!({
        "class": "StandaloneVM", "label": label, "features": {"airlock-label-color": color},
        "backend": {"type": "nix-closure", "system": {"source": "/nix/store/00000000000000000000000000000000-system"}, "root": {"source": "/nix/store/00000000000000000000000000000000-root/root.img"},
            "store": {"source": "/nix/store/00000000000000000000000000000000-prepared", "mode": "shared-closure", "device": "/dev/xvde", "blobDevice": "/dev/xvdf", "mountpoint": "/nix/store", "viewBackend": "erofs-objectmap"}, "kernel": {"name": "kernel"}, "state": {"persistent_size": null}}
    }))?;
    Ok(json!({"label": label, "color": runtime::model::custom_color(&domain)?}))
}

/// Image custom labels preserve upstream indices, deduplicate names and refuse recoloring or invalid declarations.
#[test]
#[cfg(feature = "qubes")]
fn image_labels_preserve_defaults_and_reject_conflicting_colours() -> Result<()> {
    let existing: Vec<runtime::qubes::Label> = serde_json::from_value(json!([
        {"index": 1, "color": "0xcc0000", "name": "red"},
        {"index": 8, "color": "0x000000", "name": "black"}
    ]))?;
    for (name, color) in [("khaki", "0x6b7a3d"), ("light-gray", "0xd3d3d3")] {
        let domain = domain_label(json!(name), json!(color))?;
        let additions = runtime::qubes::labels(&[domain.clone(), domain.clone()], &existing, 8)?;
        assert_eq!(
            serde_json::to_value(&additions)?,
            json!([{"index": 9, "name": name, "color": color}])
        );
        let mut known = existing.clone();
        known.extend(additions);
        assert!(runtime::qubes::labels(&[domain.clone(), domain.clone()], &known, 8)?.is_empty());
        let conflicting: Vec<runtime::qubes::Label> =
            serde_json::from_value(json!([{"index": 9, "name": name, "color": "0xffffff"}]))?;
        assert!(
            runtime::qubes::labels(&[domain], &conflicting, 8)
                .err()
                .unwrap()
                .to_string()
                .contains("colour differs")
        );
    }
    for color in [json!("not-a-color"), json!("#6b7a3d"), json!(42)] {
        assert!(domain_label(json!("khaki"), color).is_err());
    }
    assert!(domain_label(json!("red"), json!("0xffffff")).is_err());
    Ok(())
}

/// Trial account files are materialized from host links without carrying host Nix settings or resolvers.
#[test]
fn trial_environment_materializes_only_the_required_account_files() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let source = root.join("host-etc");
    fs::create_dir(&source)?;
    for name in ["passwd", "group", "nsswitch.conf"] {
        fs::write(root.join(name), format!("{name}\n"))?;
        symlink(root.join(name), source.join(name))?;
    }
    let target = root.join("trial-etc");
    acceptance::trial::prepare_etc(&target, &source)?;
    for name in ["passwd", "group", "nsswitch.conf"] {
        assert!(!target.join(name).is_symlink());
        assert_eq!(fs::read_to_string(target.join(name))?, format!("{name}\n"));
    }
    assert!(fs::read_to_string(target.join("hosts"))?.contains("localhost"));
    assert_eq!(fs::read_to_string(target.join("resolv.conf"))?, "");
    assert!(!target.join("nix").exists());
    Ok(())
}

/// Offline changes affect only a temporary prepared checkout and keep its captured revision and baseline module intact.
#[test]
fn trial_changes_preserve_the_prepared_source_and_original_module() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let machine = temporary.path().join("prepared-machine");
    let module = Path::new("generated/machine/usr-home.nix");
    fs::create_dir_all(machine.join(module).parent().unwrap())?;
    let artifact = rusix::nixos::compile_module(&rusix::nixos::NixosModule::empty())
        .map_err(|error| anyhow::anyhow!(error.render(Path::new("."))))?;
    fs::write(machine.join(module), &artifact.module.source)?;
    fs::write(machine.join("flake.lock"), "{}\n")?;
    let revision = "a".repeat(40);
    fs::write(
        machine.join("airlock-source.json"),
        serde_json::to_vec(&json!({"revision": revision, "dirty": false}))?,
    )?;
    for (change, marker) in [
        ("etc-marker", "offline gate marker"),
        ("service-setting", "90s"),
    ] {
        let target = temporary.path().join(change);
        acceptance::trial::checkout(&machine, &target, change.try_into()?, &revision)?;
        let updated = fs::read_to_string(target.join(module))?;
        assert_eq!(updated.matches(marker).count(), 1);
        assert_ne!(updated, artifact.module.source);
        assert_eq!(
            fs::read_to_string(
                target.join(module.with_file_name("usr-home-offline-baseline.nix"))
            )?,
            artifact.module.source
        );
        assert_eq!(
            fs::read(target.join("flake.lock"))?,
            fs::read(machine.join("flake.lock"))?
        );
    }
    assert_eq!(
        fs::read_to_string(machine.join(module))?,
        artifact.module.source
    );
    Ok(())
}
