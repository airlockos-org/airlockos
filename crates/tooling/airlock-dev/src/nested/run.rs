//! QEMU image/overlay preparation; upstream QEMU and Nix retain their existing roles.

use super::*;
use std::os::unix::{fs::PermissionsExt, process::CommandExt};

/// Delete only a generated file or symlink, refusing a directory at a selected state path.
fn remove(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file() || metadata.is_symlink(),
                "refusing to remove non-file VM state: {path}",
                path = path.display()
            );
            fs::remove_file(path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

/// Select exactly one root-level disk image; declaration ordering cannot change the choice.
fn disk(output: &Path) -> Result<PathBuf> {
    let mut images = Vec::new();
    for entry in fs::read_dir(output)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file()
            && path
                .extension()
                .is_some_and(|ext| ext == "qcow2" || ext == "img")
        {
            images.push(path);
        }
    }
    ensure!(
        images.len() == 1,
        "expected one qcow2/raw image under {output}, found {count}",
        output = output.display(),
        count = images.len()
    );
    Ok(images.remove(0))
}

/// Retain only the configured number of stale regular overlay backups.
fn prune(directory: &Path, disk: &Path, keep: u64) -> Result<()> {
    let prefix = format!(
        "{name}.",
        name = disk.file_name().context("overlay name")?.to_string_lossy()
    );
    let mut backups = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(&prefix) && name.ends_with(".bak") && entry.file_type()?.is_file() {
            backups.push(entry.path());
        }
    }
    backups.sort();
    backups.reverse();
    for backup in backups.into_iter().skip(keep.try_into()?) {
        fs::remove_file(backup)?;
    }
    Ok(())
}

/// Prepare the explicitly selected overlay and replace this process with upstream QEMU.
pub(super) fn execute(context: &Context) -> Result<u8> {
    let directory = path("AIRLOCK_VM_DIR", context.root.join(".airlock-vm"));
    let links = path(
        "AIRLOCK_RESULT_LINK_DIR",
        context.root.join(".airlock/result-links"),
    );
    let attribute = setting("AIRLOCK_VM_IMAGE_ATTR", "airlock-vm-dev-image");
    ensure!(
        !attribute.is_empty()
            && attribute
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "invalid image attribute"
    );
    let fresh = toggle("AIRLOCK_VM_FRESH", false)?;
    let skip = toggle("AIRLOCK_VM_SKIP_BASE_BUILD", false)?;
    let iommu = toggle("AIRLOCK_VM_IOMMU", true)?;
    let sysnet = toggle("AIRLOCK_VM_SYSNET_NIC", true)?;
    let keep = number("AIRLOCK_VM_BACKUP_RETENTION", 1)?;
    let display = setting("AIRLOCK_VM_DISPLAY", "none");
    ensure!(
        ["none", "gtk", "sdl"].contains(&display.as_str()),
        "unsupported VM display: {display}"
    );
    ensure!(
        Path::new("/dev/kvm").exists(),
        "/dev/kvm is missing; nested Xen needs KVM"
    );
    ensure!(
        fs::read_to_string("/proc/cpuinfo")?
            .lines()
            .filter(|line| line.starts_with("flags") || line.starts_with("Features"))
            .any(|line| line
                .split_whitespace()
                .any(|flag| ["vmx", "svm"].contains(&flag))),
        "CPU does not expose vmx or svm"
    );
    fs::create_dir_all(&directory)?;
    fs::create_dir_all(&links)?;
    let output_link = directory.join(format!("{attribute}-result"));
    let (logical, physical) = if skip {
        let source = fs::canonicalize(&output_link)
            .context("skip-base-build requested but result link is missing")?;
        (source.clone(), source)
    } else {
        let logical = PathBuf::from(context.build(&attribute, None)?);
        let physical = environment::physical(&logical);
        link(&physical, &output_link)?;
        (logical, physical)
    };
    let selected = disk(&physical)?;
    let nix_image = logical.join(selected.strip_prefix(&physical)?);
    let base = path("AIRLOCK_VM_BACKING_IMAGE", &nix_image);
    ensure!(
        environment::physical(&base).is_file(),
        "VM backing image is not a file: {base}",
        base = base.display()
    );
    let qemu = context.build("qemu-kvm", Some(&links.join("qemu-kvm-result")))?;
    let utils = context.build("qemu-utils", Some(&links.join("qemu-utils-result")))?;
    let ovmf = context.build("ovmf-fd", Some(&links.join("ovmf-fd-result")))?;
    let image_program = PathBuf::from(&utils).join("bin/qemu-img");
    let inspect = |source: &Path| -> Result<Value> {
        Ok(serde_json::from_str(&support::text(
            context
                .store(&image_program)?
                .args(["info", "--output=json"])
                .arg(source),
        )?)?)
    };
    let format = inspect(&base)?["format"]
        .as_str()
        .context("base image format missing")?
        .to_owned();
    ensure!(
        ["raw", "qcow2"].contains(&format.as_str()),
        "unsupported base image format: {format}"
    );
    let overlay = directory.join(format!("{attribute}.qcow2"));
    let variables = directory.join(format!("{attribute}-OVMF_VARS.fd"));
    if fresh {
        remove(&overlay)?;
        remove(&variables)?;
    }
    if overlay.exists() && inspect(&overlay)?["backing-filename"].as_str() != base.to_str() {
        let nonce = crate::transport::nonce()?;
        fs::rename(
            &overlay,
            overlay.with_file_name(format!(
                "{attribute}.qcow2.{time}-{nonce}.bak",
                time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs()
            )),
        )?;
        prune(&directory, &overlay, keep)?;
    }
    if !overlay.exists() {
        support::output(
            context
                .store(&image_program)?
                .args(["create", "-f", "qcow2", "-F", &format, "-b"])
                .arg(&base)
                .arg(&overlay),
        )?;
    }
    if !variables.exists() {
        let source = path(
            "AIRLOCK_VM_OVMF_VARS_TEMPLATE",
            environment::physical(Path::new(&ovmf)).join("FV/OVMF_VARS.fd"),
        );
        ensure!(source.is_file(), "OVMF variables template is missing");
        fs::copy(source, &variables)?;
        let mut permissions = fs::metadata(&variables)?.permissions();
        permissions.set_mode(permissions.mode() | 0o200);
        fs::set_permissions(&variables, permissions)?;
    }
    let machine = if iommu {
        "q35,accel=kvm,kernel-irqchip=split"
    } else {
        "q35,accel=kvm"
    };
    let monitor = directory.join(format!("{attribute}.monitor"));
    if let Ok(metadata) = fs::symlink_metadata(&monitor) {
        ensure!(!metadata.is_dir(), "monitor path is a directory");
        fs::remove_file(&monitor)?;
    }
    let mut command = context.store(&PathBuf::from(qemu).join("bin/qemu-system-x86_64"))?;
    command.args([
        "-machine",
        machine,
        "-cpu",
        "host,migratable=off",
        "-smp",
        &setting("AIRLOCK_VM_SMP", "4"),
        "-m",
        &setting("AIRLOCK_VM_MEMORY", "12288"),
        "-drive",
        &format!("if=pflash,format=raw,readonly=on,file={ovmf}/FV/OVMF_CODE.fd"),
        "-drive",
        &format!(
            "if=pflash,format=raw,file={path}",
            path = variables.display()
        ),
    ]);
    if iommu {
        command.args(["-device", "intel-iommu,intremap=on,caching-mode=on"]);
    }
    command.args([
        "-drive",
        &format!(
            "if=virtio,format=qcow2,file={path},discard=unmap",
            path = overlay.display()
        ),
        "-vga",
        &setting("AIRLOCK_VM_VGA", "std"),
        "-device",
        "virtio-net-pci,netdev=net0",
        "-netdev",
        &format!(
            "user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22",
            port = setting("AIRLOCK_VM_SSH_PORT", "2222")
        ),
    ]);
    if sysnet {
        command.args([
            "-device",
            "virtio-net-pci,disable-legacy=on,iommu_platform=on,vectors=0,netdev=sysnet0",
            "-netdev",
            "user,id=sysnet0",
        ]);
    }
    command.args([
        "-device",
        "virtio-rng-pci",
        "-monitor",
        &format!("unix:{path},server=on,wait=off", path = monitor.display()),
        "-no-reboot",
        "-display",
        match display.as_str() {
            "gtk" => "gtk,gl=off",
            "sdl" => "sdl",
            _ => "none",
        },
        "-serial",
    ]);
    if display == "none" {
        command.arg("mon:stdio");
    } else {
        let serial = directory.join("serial.log");
        File::create(&serial)?;
        command.arg(format!("file:{serial}", serial = serial.display()));
    }
    println!(
        "starting VM\n  image attr: .#{attribute}\n  backing: {base} ({format})\n  disk: {overlay}\n  monitor: {monitor}",
        base = base.display(),
        overlay = overlay.display(),
        monitor = monitor.display()
    );
    use std::io::Write;
    std::io::stdout().flush()?;
    Err(command.exec().into())
}
