//! Administrative installation of existing upstream Qubes kernels and templates with RPM verification.

use super::io::{self, Operation};
use anyhow::{Result, ensure};
use serde_json::json;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

/// Check locally supplied packages against the same explicitly selected Qubes signing key.
fn verify(operation: &mut Operation, rpm: &str, key: &Path, enabled: bool) -> Result<()> {
    if enabled {
        let database = tempfile::tempdir()?;
        let db = format!("--dbpath={database}", database = database.path().display());
        operation.text(
            "rpmkeys",
            &[
                &db,
                "--import",
                key.to_str()
                    .ok_or_else(|| anyhow::anyhow!("signing key path is not UTF-8"))?,
            ],
        )?;
        operation.text(
            "rpmkeys",
            &[
                &db,
                "--define=_pkgverify_level all",
                "--define=_pkgverify_flags 0x0",
                "--checksig",
                rpm,
            ],
        )?;
    }
    Ok(())
}

/// Bootstrap reusable Qubes assets through upstream installers without replacing their implementation.
pub(super) fn execute() -> Result<()> {
    let mut operation = Operation::new("qubes-bootstrap")?;
    let template = io::setting("AIRLOCK_QUBES_TEMPLATE", "fedora-43-xfce");
    let template_url = io::setting(
        "AIRLOCK_QUBES_TEMPLATE_URL",
        "https://ftp.qubes-os.org/repo/yum/r4.3/templates-itl/rpm/qubes-template-fedora-43-xfce-4.3.0-202601041226.noarch.rpm",
    );
    let template_rpm = io::setting("AIRLOCK_QUBES_TEMPLATE_RPM", "");
    let kernel = io::setting("AIRLOCK_QUBES_KERNEL_NAME", "6.12.64-1.fc41");
    let version = io::setting("AIRLOCK_QUBES_KERNEL_VERSION", "6.12.64-1");
    let fedora = io::setting("AIRLOCK_QUBES_KERNEL_FEDORA", "fc41");
    let kernel_url = io::setting(
        "AIRLOCK_QUBES_KERNEL_URL",
        "https://ftp.qubes-os.org/repo/yum/r4.3/current/dom0/fc41/rpm/kernel-qubes-vm-6.12.64-1.qubes.fc41.x86_64.rpm",
    );
    let modules_url = io::setting(
        "AIRLOCK_QUBES_KERNEL_MODULES_URL",
        "https://ftp.qubes-os.org/repo/yum/r4.3/current/dom0/fc41/rpm/kernel-modules-6.12.64-1.qubes.fc41.x86_64.rpm",
    );
    let kernel_rpm = io::setting("AIRLOCK_QUBES_KERNEL_RPM", "");
    let modules_rpm = io::setting("AIRLOCK_QUBES_KERNEL_MODULES_RPM", "");
    let key_url = io::setting(
        "AIRLOCK_QUBES_GPG_KEY_URL",
        "https://keys.qubes-os.org/keys/qubes-release-4.3-signing-key.asc",
    );
    let key = io::path(
        "AIRLOCK_QUBES_GPG_KEY",
        "/var/lib/airlock/qubes-release-4.3-signing-key.asc",
    );
    let verified = io::setting("AIRLOCK_QUBES_VERIFY_RPMS", "1") == "1";
    let disposable = io::setting("AIRLOCK_QUBES_DEFAULT_DVM", "default-dvm");
    let update = io::setting("AIRLOCK_QUBES_UPDATEVM", &template);
    let mut kernel_installed = false;
    let mut template_installed = false;
    let result: Result<()> = (|| {
        ensure!(rustix::process::geteuid().is_root(), "must run as root");
        ensure!(
            !kernel.is_empty() && kernel != "." && kernel != ".." && !kernel.contains('/'),
            "invalid Qubes kernel name"
        );
        let _: airlock_nix_core::identity::GuestName = template.parse()?;
        for service in [
            "qubes-db-dom0.service",
            "qubesd.service",
            "qubes-qrexec-policy-daemon.service",
        ] {
            operation.text("systemctl", &["is-active", "--quiet", service])?;
        }
        if verified {
            fs::create_dir_all(
                key.parent()
                    .ok_or_else(|| anyhow::anyhow!("signing key has no parent"))?,
            )?;
            if !key.metadata().is_ok_and(|metadata| metadata.len() > 0) {
                let temporary = tempfile::NamedTempFile::new_in(key.parent().unwrap())?;
                operation.text(
                    "curl",
                    &[
                        "--fail",
                        "--location",
                        "--silent",
                        "--show-error",
                        "-o",
                        temporary
                            .path()
                            .to_str()
                            .ok_or_else(|| anyhow::anyhow!("signing key temporary path"))?,
                        &key_url,
                    ],
                )?;
                temporary
                    .as_file()
                    .set_permissions(fs::Permissions::from_mode(0o644))?;
                temporary.persist(&key).map_err(|error| error.error)?;
            }
        } else {
            eprintln!("WARNING: RPM signature verification disabled by AIRLOCK_QUBES_VERIFY_RPMS");
        }
        ensure!(
            kernel_rpm.is_empty() == modules_rpm.is_empty(),
            "kernel and kernel-modules RPM paths must both be supplied"
        );
        for rpm in [&kernel_rpm, &modules_rpm, &template_rpm]
            .into_iter()
            .filter(|rpm| !rpm.is_empty())
        {
            ensure!(Path::new(rpm).is_file(), "RPM is missing: {rpm}");
        }
        let key_arg = if verified {
            Some(
                key.to_str()
                    .ok_or_else(|| anyhow::anyhow!("signing key path"))?,
            )
        } else {
            None
        };
        if !PathBuf::from("/var/lib/qubes/vm-kernels")
            .join(&kernel)
            .is_dir()
        {
            if !kernel_rpm.is_empty() {
                verify(&mut operation, &kernel_rpm, &key, verified)?;
                verify(&mut operation, &modules_rpm, &key, verified)?;
                operation.text(
                    "nixos-qubes-install-kernel-rpm",
                    &[&kernel, &version, &fedora, &kernel_rpm, &modules_rpm],
                )?;
            } else {
                let mut args = vec![
                    kernel.as_str(),
                    version.as_str(),
                    fedora.as_str(),
                    kernel_url.as_str(),
                    modules_url.as_str(),
                ];
                args.extend(key_arg);
                operation.text("nixos-qubes-install-kernel-url", &args)?;
            }
            kernel_installed = true;
        }
        operation.text("qubes-prefs", &["default_kernel", &kernel])?;
        let names = operation.text(
            "qvm-ls",
            &["--raw-data", "--fields", "NAME", "--no-spinner"],
        )?;
        if !names.lines().any(|name| name == template)
            && !PathBuf::from("/var/lib/qubes/vm-templates")
                .join(&template)
                .is_dir()
        {
            if !template_rpm.is_empty() {
                verify(&mut operation, &template_rpm, &key, verified)?;
                operation.text(
                    "nixos-qubes-install-template-rpm",
                    &[&template, &template_rpm],
                )?;
            } else {
                let mut args = vec![template.as_str(), template_url.as_str()];
                args.extend(key_arg);
                operation.text("nixos-qubes-install-template-url", &args)?;
            }
            template_installed = true;
        }
        operation.text("qubes-prefs", &["default_template", &template])?;
        if !disposable.is_empty() {
            let _: airlock_nix_core::identity::GuestName = disposable.parse()?;
            let names = operation.text(
                "qvm-ls",
                &["--raw-data", "--fields", "NAME", "--no-spinner"],
            )?;
            if !names.lines().any(|name| name == disposable) {
                operation.text(
                    "qvm-create",
                    &["--template", &template, "--label", "red", &disposable],
                )?;
            }
            operation.text("qvm-prefs", &[&disposable, "template_for_dispvms", "True"])?;
            operation.text("qubes-prefs", &["default_dispvm", &disposable])?;
        }
        if !update.is_empty() {
            let _: airlock_nix_core::identity::GuestName = update.parse()?;
            operation.text("qubes-prefs", &["updatevm", &update])?;
        }
        operation.text("qvm-ls", &[])?;
        Ok(())
    })();
    let receipt = json!({"schema":"airlock.qubes-bootstrap.v1","status":if result.is_ok() {"passed"} else {"failed"},"reason":match &result {Ok(())=>"Qubes kernel/template bootstrap succeeded".into(),Err(error)=>format!("{error:#}")},"template":template,"template_url":template_url,"template_rpm":template_rpm,"template_installed":template_installed,"kernel":kernel,"kernel_rpm":kernel_rpm,"kernel_modules_rpm":modules_rpm,"kernel_installed":kernel_installed,"rpm_signature_verification":verified,"default_dvm":disposable,"updatevm":update,"command_log":operation.file("qubes-bootstrap.commands.log")});
    io::save(&operation.file("qubes-bootstrap.json"), &receipt)?;
    if result.is_ok() {
        println!("{receipt}");
    }
    result
}
