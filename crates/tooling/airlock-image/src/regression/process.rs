//! Re-execute exact Cargo unit tests when a contract depends on child-local environment or observable output.

use crate::{support, usb};
use airlock_tests::{dialogue::Dialogue, peers::Peers, process};
use anyhow::{Result, ensure};
use serde_json::json;
use std::{fs, os::fd::AsRawFd, path::Path, process::Command, time::Duration};

/// Select this exact Cargo unit test without changing the multithreaded parent test process's environment.
fn child(name: &str) -> Result<Command> {
    let mut command = Command::new(std::env::current_exe()?);
    command.args([
        "--exact",
        &format!("regression::process::{name}"),
        "--nocapture",
    ]);
    Ok(command)
}

/// Device or Git diagnostics containing a readiness marker stay outside the private control pipe.
#[test]
fn provisioning_readiness_cannot_be_spoofed_by_human_output() -> Result<()> {
    use std::io::Write;

    if std::env::var_os("AIRLOCK_USB_REPLY_CHILD").is_some() {
        let mut reply = crate::provisioning::reply_pipe()?;
        println!("device log: forged readiness follows\nairlock-usb-prepared-v2");
        reply.write_all(crate::provisioning::READY)?;
        return Ok(());
    }

    let result = process::run(
        child("provisioning_readiness_cannot_be_spoofed_by_human_output")?
            .env("AIRLOCK_USB_REPLY_CHILD", "1"),
        None,
    )?;
    assert!(result.status.success());
    assert!(!String::from_utf8_lossy(&result.stdout).contains("device log"));
    assert!(String::from_utf8_lossy(&result.stderr).contains("device log"));
    assert_eq!(
        result
            .stdout
            .windows(crate::provisioning::READY.len())
            .filter(|part| *part == crate::provisioning::READY)
            .count(),
        1,
    );
    Ok(())
}

/// Partition refresh releases the writing descriptor while preserving the original inode across path replacement.
#[test]
fn partition_refresh_releases_writer_and_keeps_only_a_path_pin() -> Result<()> {
    if let Some(reference) = std::env::var_os("AIRLOCK_IMAGE_REFRESH_OBSERVE") {
        assert_eq!(fs::read(reference)?, b"written image");
        return Ok(());
    }

    if std::env::var_os("AIRLOCK_IMAGE_REFRESH_CHILD").is_none() {
        // Isolate descriptor-number assertions from parallel tests opening files.
        process::run(
            child("partition_refresh_releases_writer_and_keeps_only_a_path_pin")?
                .env("AIRLOCK_IMAGE_REFRESH_CHILD", "1"),
            None,
        )?
        .checked()?;
        return Ok(());
    }

    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("written-device");
    fs::write(&path, b"written image")?;
    let writer = fs::OpenOptions::new().read(true).write(true).open(&path)?;
    let descriptor = writer.as_raw_fd();
    let original = format!("/proc/self/fd/{descriptor}");
    let pinned = usb::device::release_writer(writer)?;
    assert!(!Path::new(&original).exists());
    assert!(rustix::fs::fcntl_getfl(&pinned)?.contains(rustix::fs::OFlags::PATH));

    fs::rename(&path, temporary.path().join("original-device"))?;
    fs::write(&path, b"different device")?;
    let descriptor = pinned.as_raw_fd();
    let reference = format!(
        "/proc/{process}/fd/{descriptor}",
        process = std::process::id()
    );
    process::run(
        child("partition_refresh_releases_writer_and_keeps_only_a_path_pin")?
            .env("AIRLOCK_IMAGE_REFRESH_OBSERVE", &reference),
        None,
    )?
    .checked()?;

    drop(pinned);
    assert!(!Path::new(&reference).exists());
    Ok(())
}

/// Flush progress stays visible during a blocked operation and never prints completion after a failed flush.
#[test]
fn flush_progress_is_observable_before_completion() -> Result<()> {
    if let Ok(path) = std::env::var("AIRLOCK_IMAGE_PROGRESS_PATH") {
        return usb::progress::waiting_at(
            "Flushing USB device",
            Some(path.into()),
            Duration::from_millis(10),
            || {
                std::thread::sleep(Duration::from_millis(500));
                ensure!(
                    std::env::var("AIRLOCK_IMAGE_PROGRESS_FAIL").as_deref() != Ok("1"),
                    "device disconnected"
                );
                Ok(())
            },
        );
    }
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("stat");
    fs::write(&path, "0 0 0 0 0 0 0 0 2\n")?;
    let mut process = Dialogue::spawn(
        child("flush_progress_is_observable_before_completion")?
            .env("AIRLOCK_IMAGE_PROGRESS_PATH", &path),
    )?;
    loop {
        let line = String::from_utf8(process.line(Duration::from_secs(2))?)?;
        if line.contains("waiting for completion") {
            break;
        }
    }
    fs::write(&path, "0 0 0 0 0 0 32768 0 1\n")?;
    let mut observed = false;
    let mut completed = false;
    while !completed {
        let line = String::from_utf8(process.line(Duration::from_secs(2))?)?;
        if line.contains("+0.02 GiB written") {
            assert!(line.contains("1 I/O in flight"));
            assert!(!line.contains("completed after"));
            observed = true;
        }
        completed = line.contains("completed after");
    }
    assert!(observed);
    assert!(process.finish()?.success());
    let output = process::run(
        child("flush_progress_is_observable_before_completion")?
            .env("AIRLOCK_IMAGE_PROGRESS_PATH", path)
            .env("AIRLOCK_IMAGE_PROGRESS_FAIL", "1"),
        None,
    )?;
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("completed after"));
    Ok(())
}

/// A filesystem repair status is accepted only for clean or corrected filesystems; diagnostic output follows the result.
#[test]
fn filesystem_checks_and_command_diagnostics_preserve_exit_semantics() -> Result<()> {
    if std::env::var("AIRLOCK_IMAGE_CHECK_CHILD").as_deref() == Ok("1") {
        return usb::growth::check_ext4(Path::new("partition"));
    }
    if std::env::var("AIRLOCK_IMAGE_REPORT_CHILD").as_deref() == Ok("1") {
        return support::reported(
            Command::new("sh").args([
                "-c",
                r#"
printf 'normal output\n'
printf 'diagnostic\n' >&2
exit "$AIRLOCK_IMAGE_REPORT_EXIT"
"#,
            ]),
            None,
            &[0],
        );
    }
    for code in [0, 1, 2, 4, 8] {
        let mut peers = Peers::new()?;
        peers.rules(
            "e2fsck",
            json!([{"args": ["-f", "-p", "partition"], "exit": code}]),
        )?;
        let base = child("filesystem_checks_and_command_diagnostics_preserve_exit_semantics")?;
        let mut command = peers.command(base.get_program())?;
        command
            .args(base.get_args())
            .env("AIRLOCK_IMAGE_CHECK_CHILD", "1");
        let output = process::run(&mut command, None)?;
        assert_eq!(output.status.success(), code <= 1);
        if code > 1 {
            assert!(String::from_utf8_lossy(&output.stderr).contains("Filesystem check failed"));
        }
    }
    for code in [0, 2] {
        let output = process::run(
            child("filesystem_checks_and_command_diagnostics_preserve_exit_semantics")?
                .env("AIRLOCK_IMAGE_REPORT_CHILD", "1")
                .env("AIRLOCK_IMAGE_REPORT_EXIT", code.to_string()),
            None,
        )?;
        let stream = if code == 0 {
            &output.stdout
        } else {
            &output.stderr
        };
        assert!(String::from_utf8_lossy(stream).contains("normal output\ndiagnostic\n"));
        assert_eq!(output.status.success(), code == 0);
    }
    support::reported(
        Command::new("sh").args([
            "-c",
            r#"
IFS= read -r line
test "$line" = ', +'
"#,
        ]),
        Some(b", +\n".to_vec()),
        &[0],
    )?;
    Ok(())
}

/// Partition-table writes settle before identity checks; mutation, settlement and identity failures stop the operation.
#[test]
fn partition_changes_settle_before_identity_checks_and_stop_on_failure() -> Result<()> {
    if let Some(root) = std::env::var_os("AIRLOCK_IMAGE_TABLE_CHILD") {
        let root = Path::new(&root);
        return usb::growth::change_table(
            Command::new("sfdisk").args(["--relocate", "gpt-bak-std", "/dev/test-usb"]),
            None,
            || {
                assert_eq!(fs::read(root.join("partition-link"))?, b"recreated");
                fs::write(root.join("identity-checked"), b"")?;
                ensure!(
                    std::env::var("AIRLOCK_IMAGE_TABLE_IDENTITY").as_deref() == Ok("same"),
                    "USB identity changed"
                );
                Ok(())
            },
        );
    }

    for (mutation, settle, identity) in [
        (0, 0, "same"),
        (1, 0, "same"),
        (0, 1, "same"),
        (0, 0, "changed"),
    ] {
        let mut peers = Peers::new()?;
        peers.rules(
            "sfdisk",
            json!([{
                "args":["--relocate", "gpt-bak-std", "/dev/test-usb"], "exit":mutation,
            }]),
        )?;
        peers.rules(
            "udevadm",
            json!([{
                "args":["settle"], "exit":settle, "write":{"partition-link":"recreated"},
            }]),
        )?;
        let base = child("partition_changes_settle_before_identity_checks_and_stop_on_failure")?;
        let mut command = peers.command(base.get_program())?;
        command
            .args(base.get_args())
            .env("AIRLOCK_IMAGE_TABLE_CHILD", peers.path(""))
            .env("AIRLOCK_IMAGE_TABLE_IDENTITY", identity);
        let result = process::run(&mut command, None)?;
        assert_eq!(
            result.status.success(),
            mutation == 0 && settle == 0 && identity == "same"
        );
        assert_eq!(
            peers.path("identity-checked").exists(),
            mutation == 0 && settle == 0
        );
        let calls = peers.calls()?;
        assert_eq!(calls.len(), if mutation == 0 { 2 } else { 1 });
        assert_eq!(calls[0]["command"], "sfdisk");
        if mutation == 0 {
            assert_eq!(calls[1]["command"], "udevadm");
        }
    }
    Ok(())
}

/// Kernel partition size is checked after udev settles, and stale geometry stops before any filesystem resize.
#[test]
fn kernel_size_requires_settled_matching_geometry() -> Result<()> {
    if std::env::var("AIRLOCK_IMAGE_SIZE_CHILD").as_deref() == Ok("1") {
        return usb::growth::kernel_size(Path::new("/dev/sdc2"), 61420322304);
    }
    for actual in [61420322304_u64, 33283899392] {
        let mut peers = Peers::new()?;
        peers.rules(
            "udevadm",
            json!([{"args": ["settle"], "write": {"settled": ""}}]),
        )?;
        peers.rules("blockdev", json!([{"args": ["--getsize64", "/dev/sdc2"], "exists": "settled", "stdout": actual.to_string()}]))?;
        let base = child("kernel_size_requires_settled_matching_geometry")?;
        let mut command = peers.command(base.get_program())?;
        command
            .args(base.get_args())
            .env("AIRLOCK_IMAGE_SIZE_CHILD", "1");
        let output = process::run(&mut command, None)?;
        assert_eq!(output.status.success(), actual == 61420322304);
        if actual != 61420322304 {
            assert!(String::from_utf8_lossy(&output.stderr).contains("Unplug/replug"));
        }
        assert_eq!(peers.calls()?.len(), 2);
    }
    Ok(())
}

/// A recorded marker and invented block inventory cannot authorize personalization of an unrelated filesystem.
#[test]
fn mounted_image_marker_cannot_substitute_for_disk_identity() -> Result<()> {
    if let Ok(root) = std::env::var("AIRLOCK_IMAGE_MOUNT_ROOT") {
        return usb::device::check_mount(Path::new(&root), None).map(|_| ());
    }
    let mut peers = Peers::new()?;
    let source = peers.path("device");
    fs::write(&source, b"")?;
    peers.rules("findmnt", json!([{"stdout": json!({"filesystems": [{"source": source, "fstype": "ext4"}]}).to_string()}]))?;
    peers.rules("lsblk", json!([{"stdout": json!({"blockdevices": [{"name": "/dev/test-usb", "type": "disk", "size": 100,
        "ro": false, "tran": "usb", "children": [{"name": source, "type": "part", "size": 100, "ro": false, "label": "airlock-usb"}]}]}).to_string()}]))?;
    for marker in ["airlock-usb-dev-v1\n", "airlock-usb-dev-v2\n"] {
        fs::write(peers.path("airlock-usb-image"), marker)?;
        let base = child("mounted_image_marker_cannot_substitute_for_disk_identity")?;
        let mut command = peers.command(base.get_program())?;
        command
            .args(base.get_args())
            .env("AIRLOCK_IMAGE_MOUNT_ROOT", peers.path(""));
        let output = process::run(&mut command, None)?;
        assert!(!output.status.success());
        if marker.contains("v1") {
            assert!(String::from_utf8_lossy(&output.stderr).contains("Missing USB image marker"));
        }
    }
    Ok(())
}

/// Empty or mismatched password confirmation is refused through an actual controlling terminal.
#[test]
#[ignore = "requires explicitly prepared util-linux script and systemd-ask-password"]
fn external_tool_password_prompt_validates_empty_and_confirmation() -> Result<()> {
    if std::env::var("AIRLOCK_IMAGE_PASSWORD_CHILD").as_deref() == Ok("1") {
        println!(
            "{password}",
            password = serde_json::to_string(&usb::personalize::password(false)?)?
        );
        return Ok(());
    }
    let base = child("external_tool_password_prompt_validates_empty_and_confirmation")?;
    let mut words = vec![process::quote(base.get_program().to_str().unwrap())];
    words.extend(
        base.get_args()
            .map(|arg| process::quote(arg.to_str().unwrap())),
    );
    words.push("--ignored".into());
    let script = words.join(" ");
    for (answers, expected) in [
        (vec!["password", "password"], "\"password\""),
        (vec![""], "cannot be empty"),
        (vec!["password", "different"], "Passwords differ"),
    ] {
        let mut terminal = Dialogue::spawn(
            Command::new("script")
                .args([
                    "--quiet",
                    "--return",
                    "--flush",
                    "--echo",
                    "never",
                    "--command",
                    &script,
                    "/dev/null",
                ])
                .env("AIRLOCK_IMAGE_PASSWORD_CHILD", "1"),
        )?;
        for (index, answer) in answers.iter().enumerate() {
            let prompt = if index == 0 {
                "New local dom0 password"
            } else {
                "Confirm password:"
            };
            terminal.until(prompt.as_bytes(), Duration::from_secs(5))?;
            terminal.send(format!("{answer}\n").as_bytes())?;
        }
        terminal.until(expected.as_bytes(), Duration::from_secs(5))?;
        assert_eq!(terminal.finish()?.success(), expected == "\"password\"");
    }
    Ok(())
}

/// Invalid keys, missing commits and invalid firmware fail before a password prompt or source copy can begin.
#[test]
#[ignore = "requires explicitly prepared ssh-keygen and git"]
fn external_tool_personalization_validates_inputs_before_credentials_or_disk_access() -> Result<()>
{
    use clap::Parser;

    /// Parse the real personalization settings without entering a USB operation.
    #[derive(Parser)]
    struct Options {
        // Production source, key and firmware options passed through unchanged.
        #[command(flatten)]
        settings: usb::personalize::Settings,
    }

    for damage in [
        "invalid-key",
        "multiple-keys",
        "private-key",
        "missing-commit",
        "firmware",
    ] {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path();
        let key = root.join("key");
        let public = root.join("key.pub");
        process::run(
            Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&key),
            None,
        )?
        .checked()?;
        match damage {
            "invalid-key" => fs::write(&public, "not a public key")?,
            "multiple-keys" => {
                let bytes = fs::read(&public)?;
                fs::write(&public, bytes.repeat(2))?;
            }
            "private-key" => {
                fs::copy(&key, &public)?;
            }
            _ => {}
        }
        let repository = root.join("repo");
        process::run(
            Command::new("git").args(["init", "-q"]).arg(&repository),
            None,
        )?
        .checked()?;
        fs::write(repository.join("file"), "uncommitted")?;
        let mut arguments = vec![
            "prepare".to_owned(),
            "--repo".into(),
            repository.to_str().unwrap().into(),
            "--public-key".into(),
            public.to_str().unwrap().into(),
        ];
        if damage == "firmware" {
            let firmware = root.join("invalid.vfct");
            fs::write(&firmware, b"invalid")?;
            arguments.extend(["--amd-vfct".into(), firmware.to_str().unwrap().into()]);
        }
        let result = Options::try_parse_from(arguments)?.settings.prepare();
        let error = format!(
            "{error:#}",
            error = result.err().expect("invalid personalization was accepted")
        );
        assert!(!error.to_lowercase().contains("password"));
        assert!(!error.contains("airlock-usb-source"));
        if damage == "missing-commit" {
            assert!(error.contains("requires a committed source HEAD"));
        } else {
            assert!(error.to_lowercase().contains("key") || error.contains("VFCT"));
        }
    }
    Ok(())
}

/// Actual GPT tools expand a temporary image while the native geometry checks preserve disk and partition UUIDs.
#[test]
#[ignore = "requires explicitly prepared util-linux sfdisk"]
fn external_tool_gpt_expansion_preserves_partition_identities() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let image = temporary.path().join("disk.img");
    fs::File::create(&image)?.set_len(64 * 1024 * 1024)?;
    process::run(
        Command::new("sfdisk").arg(&image),
        Some(b"label: gpt\nsize=8M, type=U\ntype=L\n".to_vec()),
    )?
    .checked()?;
    let table = || -> Result<usb::growth::Table> {
        let output = process::json(Command::new("sfdisk").arg("--json").arg(&image), None)?;
        Ok(serde_json::from_value(output["partitiontable"].clone())?)
    };
    let before = table()?;
    fs::OpenOptions::new()
        .write(true)
        .open(&image)?
        .set_len(128 * 1024 * 1024)?;
    process::run(
        Command::new("sfdisk")
            .args(["--lock=yes", "--relocate", "gpt-bak-std"])
            .arg(&image),
        None,
    )?
    .checked()?;
    process::run(
        Command::new("sfdisk")
            .args([
                "--lock=yes",
                "--wipe=never",
                "--wipe-partitions=never",
                "-N",
                "2",
            ])
            .arg(&image),
        Some(b", +\n".to_vec()),
    )?
    .checked()?;
    let after = table()?;
    let partition = std::path::PathBuf::from(format!("{image}2", image = image.display()));
    usb::growth::checked_layout(&after, &image, &partition, image.metadata()?.len())?;
    usb::growth::checked_result(&before, &after)?;
    assert!(after.partitions[1].size > before.partitions[1].size);
    Ok(())
}

/// Actual ext4 growth fills a temporary image without changing the filesystem UUID.
#[test]
#[ignore = "requires explicitly prepared e2fsprogs and blkid"]
fn external_tool_ext4_growth_preserves_filesystem_identity() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let image = temporary.path().join("root.ext4");
    fs::File::create(&image)?.set_len(32 * 1024 * 1024)?;
    process::run(
        Command::new("mkfs.ext4")
            .args(["-q", "-L", "airlock-usb"])
            .arg(&image),
        None,
    )?
    .checked()?;
    let uuid = || {
        process::run(
            Command::new("blkid")
                .args(["-s", "UUID", "-o", "value"])
                .arg(&image),
            None,
        )?
        .checked()
    };
    let before = uuid()?;
    usb::growth::check_ext4(&image)?;
    fs::OpenOptions::new()
        .write(true)
        .open(&image)?
        .set_len(64 * 1024 * 1024)?;
    process::run(Command::new("resize2fs").arg(&image), None)?.checked()?;
    usb::growth::check_ext4(&image)?;
    assert_eq!(uuid()?, before);
    let text = String::from_utf8(
        process::run(Command::new("dumpe2fs").arg("-h").arg(&image), None)?.checked()?,
    )?;
    let field = |name: &str| -> Result<u64> {
        Ok(text
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .ok_or_else(|| anyhow::anyhow!("missing ext4 field {name}"))?
            .trim()
            .parse()?)
    };
    assert_eq!(
        field("Block count:")? * field("Block size:")?,
        image.metadata()?.len()
    );
    Ok(())
}

/// Isolated trial databases register only admitted paths while source placeholders reveal no host store contents.
#[test]
#[ignore = "requires explicitly prepared Nix; uses only disposable stores"]
fn external_tool_trial_store_registers_only_selected_paths() -> Result<()> {
    use std::collections::BTreeSet;

    let temporary = tempfile::tempdir()?;
    let source = temporary.path().join("source-store");
    let mut paths = Vec::new();
    for name in ["first", "second"] {
        let path = temporary.path().join(name);
        fs::create_dir(&path)?;
        fs::write(path.join("value"), "ordinary input\n")?;
        let output = process::run(
            Command::new("nix")
                .args(["--extra-experimental-features", "nix-command", "--store"])
                .arg(&source)
                .args(["store", "add-path"])
                .arg(path),
            None,
        )?
        .checked()?;
        paths.push(String::from_utf8(output)?.trim().to_owned());
    }
    let registration = String::from_utf8(
        process::run(
            Command::new("nix-store")
                .arg("--store")
                .arg(&source)
                .arg("--dump-db"),
            None,
        )?
        .checked()?,
    )?;
    let trial = temporary.path().join("trial-store");
    crate::acceptance::trial::prepare_store(
        &trial,
        &source,
        &paths.iter().cloned().collect::<BTreeSet<_>>(),
        &registration,
        &BTreeSet::from([paths[0].clone()]),
    )?;
    for path in paths {
        let staged = trial.join(path.trim_start_matches('/'));
        assert!(staged.is_dir() && !staged.is_symlink());
        assert_eq!(fs::read_dir(staged)?.count(), 0);
        process::run(
            Command::new("nix")
                .args(["--extra-experimental-features", "nix-command", "--store"])
                .arg(&trial)
                .arg("path-info")
                .arg(path),
            None,
        )?
        .checked()?;
    }
    Ok(())
}
