//! Explicit privileged coverage exercises actual loop, device-mapper and EROFS reads in a private mount namespace.

use crate::common::{self, store::Store};
use airlock_vm_service::support;
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, path::PathBuf, process::Command, time::Duration};

/// Own every mount and attachment so a failed assertion cannot leave the fixture's devices active.
struct Linux {
    // Owns only private source/pool files and the real native service binary.
    store: Store,
    // Successful native attachment receipts identify exactly which mappings may be detached.
    attached: Vec<Value>,
    // Successfully mounted scratch paths, removed in reverse order before detaching their data devices.
    mounted: Vec<PathBuf>,
}

impl Linux {
    /// Select real EROFS indexing and the production device-mapper storage path explicitly.
    fn command(&self, args: &[&str]) -> Result<Command> {
        let mut command = self.store.command(args);
        command
            .env("AIRLOCK_MKFS_EROFS", common::tool("mkfs.erofs")?)
            .env("AIRLOCK_CLOSURE_STORE_INDEX_SOURCE", "dm");
        Ok(command)
    }

    /// Decode successful native storage replies while retaining their original diagnostics.
    fn run(&self, args: &[&str]) -> Result<Value> {
        common::json(&mut self.command(args)?, None)
    }
}

impl Linux {
    /// Verify that every owned mount/mapping is detached before publishing a successful device-cleanup receipt.
    fn cleanup(&mut self) -> Result<()> {
        while let Some(path) = self.mounted.last() {
            common::run(Command::new("umount").arg(path), None)?.checked()?;
            self.mounted.pop();
        }
        while let Some(receipt) = self.attached.last() {
            self.run(&[
                "pool",
                "detach-blob-view",
                "--pool-root",
                self.store.pool_text(),
                "--domain",
                receipt["domain"].as_str().unwrap(),
                "--generation",
                &receipt["generation"].to_string(),
            ])?;
            self.attached.pop();
        }
        if let Ok(entries) = fs::read_dir(self.store.pool.join("objects/segments")) {
            for entry in entries {
                let path = entry?.path();
                if path.extension().is_none_or(|extension| extension != "blob") {
                    continue;
                }
                let loops = || -> Result<Vec<u8>> {
                    common::run(
                        Command::new("losetup").arg("-j").arg(&path).args([
                            "--output",
                            "NAME",
                            "--noheadings",
                        ]),
                        None,
                    )?
                    .checked()
                };
                for device in String::from_utf8(loops()?)?.lines() {
                    common::run(Command::new("losetup").args(["-d", device.trim()]), None)?
                        .checked()?;
                }
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                while !String::from_utf8(loops()?)?.trim().is_empty() {
                    ensure!(
                        std::time::Instant::now() < deadline,
                        "owned loop device did not detach: {path:?}"
                    );
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
        Ok(())
    }
}

impl Drop for Linux {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Exact closure membership, immutable reads and shared extents survive detaching another generation's real block-device view.
#[test]
#[ignore = "explicit root-only loop/device-mapper/EROFS validation in a private mount namespace"]
fn privileged_linux_storage() -> Result<()> {
    ensure!(
        rustix::process::geteuid().is_root(),
        "run explicitly as root with prepared loop/device-mapper/EROFS tools"
    );
    if std::env::var_os("AIRLOCK_TEST_LINUX_STORAGE_CHILD").is_none() {
        let mut command = Command::new(common::tool("unshare")?);
        command
            .args(["--mount", "--propagation", "private"])
            .arg(std::env::current_exe()?)
            .args([
                "--ignored",
                "--exact",
                "storage_linux::privileged_linux_storage",
                "--nocapture",
            ])
            .env("AIRLOCK_TEST_LINUX_STORAGE_CHILD", "1");
        support::run(&mut command, None, Duration::from_secs(180))?.checked()?;
        return Ok(());
    }
    for tool in [
        "dmsetup",
        "losetup",
        "mount",
        "umount",
        "blockdev",
        "mkfs.erofs",
    ] {
        common::tool(tool)?;
    }
    let store = Store::new()?;
    let common_path = store.system.clone();
    fs::write(
        store
            .physical
            .join(common_path.rsplit('/').next().unwrap())
            .join("payload"),
        format!("{common_path}\n"),
    )?;
    let private = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-private";
    let directory = store.physical.join(private.rsplit('/').next().unwrap());
    fs::create_dir(&directory)?;
    fs::write(directory.join("payload"), format!("{private}\n"))?;
    let mut linux = Linux {
        store,
        attached: Vec::new(),
        mounted: Vec::new(),
    };
    let mut manifests = Vec::new();
    for (index, paths) in [
        vec![common_path.as_str()],
        vec![common_path.as_str(), private],
    ]
    .into_iter()
    .enumerate()
    {
        let closure = linux
            .store
            .temporary
            .path()
            .join(format!("closure-{index}"));
        fs::write(&closure, format!("{paths}\n", paths = paths.join("\n")))?;
        let domain = format!("linux-probe-{index}");
        let receipt = common::json(
            linux
                .command(&["pool", "admit", "--pool-root"])?
                .arg(&linux.store.pool)
                .args([
                    "--domain",
                    &domain,
                    "--system",
                    paths.last().unwrap(),
                    "--closure-source",
                ])
                .arg(closure)
                .arg("--physical-store-root")
                .arg(&linux.store.physical)
                .args(["--verify-mode", "tree"]),
            None,
        )?;
        let manifest: Value =
            serde_json::from_slice(&fs::read(receipt["manifest"].as_str().unwrap())?)?;
        let attachment = linux.run(&[
            "pool",
            "attach-blob-view",
            "--pool-root",
            linux.store.pool_text(),
            "--domain",
            &domain,
            "--generation",
            &receipt["generation"].to_string(),
        ])?;
        let device = attachment["device"].as_str().unwrap().to_owned();
        linux.attached.push(attachment);
        assert_eq!(
            String::from_utf8(
                common::run(Command::new("blockdev").args(["--getro", &device]), None)?
                    .checked()?
            )?
            .trim(),
            "1"
        );
        let mount = linux.store.temporary.path().join(format!("mount-{index}"));
        fs::create_dir(&mount)?;
        common::run(
            Command::new("mount")
                .args([
                    "-t",
                    "erofs",
                    "-o",
                    &format!("ro,loop,device={device}"),
                    manifest["store"]["metadata_image"].as_str().unwrap(),
                ])
                .arg(&mount),
            None,
        )?
        .checked()?;
        linux.mounted.push(mount.clone());
        let actual = fs::read_dir(&mount)?
            .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
            .collect::<Result<BTreeSet<_>>>()?;
        let expected = paths
            .iter()
            .map(|path| path.rsplit('/').next().unwrap().to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected);
        for path in paths {
            assert_eq!(
                fs::read_to_string(mount.join(path.rsplit('/').next().unwrap()).join("payload"))?,
                format!("{path}\n")
            );
        }
        let path = mount
            .join(common_path.rsplit('/').next().unwrap())
            .join("payload");
        assert_eq!(
            fs::write(path, "modified").unwrap_err().raw_os_error(),
            Some(rustix::io::Errno::ROFS.raw_os_error())
        );
        manifests.push(manifest);
    }
    let extents = |manifest: &Value| -> Result<Vec<Value>> {
        let mapping: Value = serde_json::from_slice(&fs::read(
            manifest["store"]["canonical_blob_map"].as_str().unwrap(),
        )?)?;
        Ok(mapping["extents"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["object"] == common_path.rsplit('/').next().unwrap())
            .map(|entry| {
                json!([
                    entry["segment_id"],
                    entry["segment_offset"],
                    entry["length"]
                ])
            })
            .collect())
    };
    let shared = extents(&manifests[0])?;
    assert!(!shared.is_empty());
    assert_eq!(shared, extents(&manifests[1])?);
    common::run(Command::new("umount").arg(&linux.mounted[0]), None)?.checked()?;
    linux.mounted.remove(0);
    let first = linux.attached[0].clone();
    linux.run(&[
        "pool",
        "detach-blob-view",
        "--pool-root",
        linux.store.pool_text(),
        "--domain",
        first["domain"].as_str().unwrap(),
        "--generation",
        &first["generation"].to_string(),
    ])?;
    linux.attached.remove(0);
    assert_eq!(
        fs::read_to_string(
            linux.mounted[0]
                .join(common_path.rsplit('/').next().unwrap())
                .join("payload")
        )?,
        format!("{common_path}\n")
    );
    let logs = airlock_tests::system::logs("closure-store-linux-storage")?;
    linux.cleanup()?;
    drop(linux);
    fs::write(
        logs.join("result.json"),
        serde_json::to_vec_pretty(
            &json!({"schema": "airlock.closure-store-linux-storage.v1", "status": "passed", "real_loop_dm_erofs": true, "shared_extents": shared, "exact_closure_membership": true, "writes_rejected": true, "peer_survives_detach": true, "devices_cleaned_up": true}),
        )?,
    )?;
    Ok(())
}
