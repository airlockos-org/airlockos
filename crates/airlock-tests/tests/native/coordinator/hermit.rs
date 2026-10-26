//! Exercise reviewed mixed-machine transactions with a diskless, deliberately halted VM.
//! Xen execution is tested separately; these namespace tests never execute the fixture ELF.

use super::*;
use std::os::unix::fs::PermissionsExt;

/// A bounded static PVH layout for admission, with distinct bytes in each generation.
fn executable(version: u8) -> Vec<u8> {
    let mut bytes = vec![0; 256];
    bytes[..8].copy_from_slice(b"\x7fELF\x02\x01\x01\xff");
    for (offset, size, value) in [
        (16, 2, 2_u64),
        (18, 2, 62),
        (20, 4, 1),
        (24, 8, 0x2000f0),
        (32, 8, 64),
        (52, 2, 64),
        (54, 2, 56),
        (56, 2, 2),
        (64, 4, 1),
        (68, 4, 5),
        (80, 8, 0x200000),
        (88, 8, 0x200000),
        (96, 8, 256),
        (104, 8, 256),
        (112, 8, 4096),
        (120, 4, 4),
        (128, 8, 192),
        (152, 8, 24),
        (192, 4, 4),
        (196, 4, 8),
        (200, 4, 18),
        (208, 8, 0x2000f0),
    ] {
        bytes[offset..offset + size].copy_from_slice(&value.to_le_bytes()[..size]);
    }
    bytes[204..208].copy_from_slice(b"Xen\0");
    bytes[255] = version;
    bytes
}

/// Add an immutable executable to the namespace store and return its isolated declaration.
fn declaration(machine: &Machine, version: u8) -> Result<Value> {
    let system = store("clipboard", u64::from(version));
    let file = machine
        .path("view")
        .join(Path::new(&system).file_name().unwrap())
        .join("kernel.elf");
    fs::create_dir_all(file.parent().unwrap())?;
    let bytes = executable(version);
    fs::write(&file, &bytes)?;
    fs::set_permissions(file, fs::Permissions::from_mode(0o444))?;
    let artifact = json!({
        "schema":"airlock.hermit-pvh.v1", "executable":format!("{system}/kernel.elf"),
        "sha256":format!("{digest:x}", digest=Sha256::digest(&bytes)), "bytes":bytes.len(),
        "source_revision": if version == 1 { revision() } else { "e".repeat(40) },
        "integration_revision":"c".repeat(40),"build_lock":lock_hash(),"authority":"disconnected"
    });
    Ok(json!({
        "class":"HermitVM", "netvm":null,"template":null,"devices":{},"services":{},
        "prefs":{"virt_mode":"pvh","kernel":"","memory":32,"maxmem":32,"vcpus":1,
            "guivm":null,"audiovm":null,"autostart":false},
        "features":{"qrexec":"","gui":""},
        "backend":{"type":"hermit","system":{"source":system},"artifact":artifact}
    }))
}

/// Add Hermit to both real coordinator inputs without manufacturing Linux pool receipts for it.
fn mixed() -> Result<Machine> {
    let mut machine = Machine::new()?;
    for (release, version) in [(&machine.baseline, 1), (&machine.candidate, 2)] {
        let path = machine.physical(release).join("topology.json");
        let mut topology = read(&path)?;
        topology["domains"]["sys-clipboard"] = declaration(&machine, version)?;
        save(path, &topology)?;
    }
    let baseline = read(machine.physical(&machine.baseline).join("topology.json"))?
        ["domains"]["sys-clipboard"].clone();
    let artifact: airlock_nix_core::hermit_artifact::Descriptor =
        serde_json::from_value(baseline["backend"]["artifact"].clone())?;
    machine.data["selected"]["sys-clipboard"] = json!(1);
    machine.data["features"]["sys-clipboard"] = json!({
        "airlock-system-source":baseline["backend"]["system"]["source"],
        "airlock-hermit-artifact":serde_json::to_string(&artifact)?
    });
    machine.persist()?;
    Ok(machine)
}

/// Both recovery choices retain source approval and publish the exact Hermit generation.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_mixed_hermit_failure_recovers_through_the_checked_plan() -> Result<()> {
    for recovery in ["resume", "rollback"] {
        let mut machine = mixed()?;
        error(
            &machine.run(&["apply", &machine.candidate], None, false)?,
            "human-approved",
        );
        machine.approve(None)?;
        machine.data["fail"] = json!("airlock-setup-config");
        machine.persist()?;
        machine.run(&["apply", &machine.candidate], None, false)?;
        assert_eq!(
            read(machine.path("machine/latest.json"))?["phase"],
            "failed"
        );

        machine.reload()?;
        machine.data.as_object_mut().unwrap().remove("fail");
        machine.persist()?;
        let result = machine.run(&[recovery], None, true)?;
        assert_eq!(result["phase"], "complete");
        let expected = store("clipboard", if recovery == "resume" { 2 } else { 1 });
        assert_eq!(result["observed"]["sys-clipboard"]["selected"], expected);
        assert!(result["observed"]["sys-clipboard"]["running"].is_null());
        machine.run(&["verify"], None, true)?;
        assert!(!machine.calls()?.iter().any(|call| {
            call[0]
                .as_str()
                .is_some_and(|name| name.starts_with("storage-"))
                && call
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|arg| arg == "sys-clipboard")
        }));
    }
    Ok(())
}

/// Approval cannot turn a subsequently substituted executable into an admitted generation.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_hermit_image_is_rechecked_before_deployment_effects() -> Result<()> {
    let machine = mixed()?;
    machine.approve(None)?;
    machine.run(&["prepared-check", &machine.candidate], None, true)?;
    let system = store("clipboard", 2);
    let path = machine
        .path("view")
        .join(Path::new(&system).file_name().unwrap())
        .join("kernel.elf");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    let mut bytes = fs::read(&path)?;
    bytes[255] ^= 1;
    fs::write(&path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o444))?;

    error(
        &machine.run(&["apply", &machine.candidate], None, false)?,
        "digest mismatch",
    );
    assert!(!machine.path("machine/latest.json").exists());
    assert!(!machine.calls()?.iter().any(|call| {
        ["qvm-shutdown", "qvm-start", "nix-env"]
            .iter()
            .any(|command| call[0] == *command)
    }));
    Ok(())
}
