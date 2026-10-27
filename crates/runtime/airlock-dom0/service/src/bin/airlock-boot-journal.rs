//! Persist the initramfs journal while it arrives, including failed activation.

#![forbid(unsafe_code)]
use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

fn capture(journalctl: &Path, root: &Path) -> Result<()> {
    let directory = root.join("var/log/airlock-boot");
    let mut ancestor = directory.as_path();
    while ancestor != root {
        ensure!(!ancestor.is_symlink(), "journal path contains a symlink");
        ancestor = ancestor.parent().context("journal root ancestor")?;
    }

    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;

    let id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let id = id.trim();
    ensure!(
        id.len() == 36 && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
        "invalid kernel boot identity"
    );

    let path = directory.join(format!("{id}-initrd.log"));
    let mut output = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(&path)?;
    ensure!(
        output.metadata()?.is_file() && output.metadata()?.nlink() == 1,
        "journal destination is not a regular file"
    );
    output.set_permissions(fs::Permissions::from_mode(0o600))?;
    File::open(&directory)?.sync_all()?;
    println!("Airlock: saving early boot journal to {}", path.display());

    let mut child = airlock_nix_core::runtime::process::OwnedChild(
        Command::new(journalctl)
            .args([
                "--boot",
                "--follow",
                "--no-pager",
                "--output=short-monotonic",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(output.try_clone()?))
            .spawn()?,
    );
    let mut pipe = child.0.stdout.take().context("journal output")?;
    let mut bytes = [0; 65536];

    loop {
        let count = match pipe.read(&mut bytes) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            other => other?,
        };
        if count == 0 {
            break;
        }
        output.write_all(&bytes[..count])?;
        output.sync_all()?;
    }

    output.sync_all()?;
    ensure!(
        child.0.wait()?.success(),
        "early boot journal recorder exited unsuccessfully"
    );
    Ok(())
}

fn execute() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.as_slice() == ["--help"] {
        println!(
            "Usage: airlock-boot-journal JOURNALCTL [--root SYSROOT]\nPersist the early journal to SYSROOT/var/log/airlock-boot (default /sysroot)."
        );
        return Ok(());
    }
    ensure!(
        args.len() == 1 || (args.len() == 3 && args[1] == "--root"),
        "use airlock-boot-journal JOURNALCTL [--root SYSROOT]"
    );
    let root = if args.len() == 3 {
        PathBuf::from(&args[2])
    } else {
        "/sysroot".into()
    };
    ensure!(
        root.is_absolute() && !root.is_symlink(),
        "journal root must be an absolute real directory"
    );
    capture(Path::new(&args[0]), &root)
}

fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("airlock-boot-journal: {error:#}");
            ExitCode::FAILURE
        }
    }
}
