//! Bounded file-backed configuration transport and archive handling shared by local protocol commands.

use crate::process::{Files, Runner};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

/// Maximum aggregate candidate archive size accepted or produced by this compatibility protocol.
const ARCHIVE_LIMIT: u64 = 8 * 1024 * 1024 * 1024;

/// Local operation evidence, separate from approval and durable deployment authority.
pub(super) struct Operation {
    /// Directory containing this operation's protocol payloads and informational receipts.
    pub directory: PathBuf,
    /// Append-only trace of commands requested by this operation.
    log: File,
}

/// Resolve a nonempty runtime override, retaining shell defaults without requiring UTF-8 paths.
pub(super) fn path(key: &str, default: impl AsRef<Path>) -> PathBuf {
    std::env::var_os(key)
        .filter(|value| !value.is_empty())
        .map_or_else(|| default.as_ref().to_owned(), PathBuf::from)
}

/// Read a nonempty protocol override, preserving its supplied spelling.
pub(super) fn setting(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.into())
}

/// Read an optional informational receipt; absence or invalid JSON remains visibly null.
pub(super) fn optional(path: &Path) -> Value {
    crate::state::read(path).unwrap_or(Value::Null)
}

/// Publish one complete informational JSON receipt, without claiming filesystem durability.
pub(super) fn save(path: &Path, value: &Value) -> Result<()> {
    crate::setup_config::report::save(path, value)
}

impl Operation {
    /// Create the fixed log namespace for one installed compatibility command.
    pub fn new(name: &str) -> Result<Self> {
        let directory = path("AIRLOCK_LOG_DIR", "/var/log/airlock");
        fs::create_dir_all(&directory)?;
        let log = File::create(directory.join(format!("{name}.commands.log")))?;
        Ok(Self { directory, log })
    }

    /// Resolve a fixed receipt or payload filename beneath this operation's evidence directory.
    pub fn file(&self, name: &str) -> PathBuf {
        self.directory.join(name)
    }

    /// Run a small textual command with existing bounded process ownership and diagnostics.
    pub fn text(&mut self, program: &str, args: &[&str]) -> Result<String> {
        writeln!(self.log, "+ {program} {args:?}")?;
        let output = Runner::default().capture(
            program,
            &args.iter().map(OsString::from).collect::<Vec<_>>(),
            Duration::from_secs(600),
            &[],
        )?;
        self.log.write_all(&output.stdout)?;
        self.log.write_all(&output.stderr)?;
        ensure!(
            !output.limited && output.status.success(),
            "{program} failed: {stderr}",
            stderr = String::from_utf8_lossy(&output.stderr)
        );
        Ok(String::from_utf8(output.stdout)?
            .trim_end_matches('\n')
            .into())
    }

    /// Stream a helper's files under a deadline, retaining diagnostics even when the helper fails.
    pub fn transfer(
        &mut self,
        program: &str,
        args: &[OsString],
        files: Files<'_>,
        env: &[(OsString, OsString)],
    ) -> Result<()> {
        writeln!(self.log, "+ {program} {args:?}")?;
        let errors = files.errors.to_owned();
        let status =
            Runner::default().files(program, args, Duration::from_secs(3600), env, files)?;
        ensure!(
            status.success(),
            "{program} failed ({status}); see {errors}",
            errors = errors.display()
        );
        Ok(())
    }

    /// Keep both output streams in one named action log while preserving failure diagnostics.
    pub fn logged(
        &mut self,
        program: &str,
        args: &[OsString],
        log: &Path,
        env: &[(OsString, OsString)],
    ) -> Result<()> {
        let errors = log.with_extension("stderr.log");
        let result = self.transfer(
            program,
            args,
            Files {
                input: None,
                output: log,
                errors: &errors,
                limit: 16 * 1024 * 1024,
            },
            env,
        );
        if errors.is_file() {
            OpenOptions::new()
                .append(true)
                .open(log)?
                .write_all(&fs::read(&errors)?)?;
        }
        result
    }

    /// Run an existing qrexec service with an optional archive input and fixed dom0 caller identity.
    pub fn rpc(
        &mut self,
        vm: &str,
        service: &str,
        input: Option<&Path>,
        output: &Path,
        errors: &Path,
    ) -> Result<()> {
        self.transfer(
            "qrexec-client",
            &[
                "-d".into(),
                vm.into(),
                "-T".into(),
                "-w".into(),
                "120".into(),
                format!("DEFAULT:QUBESRPC {service}+ dom0").into(),
            ],
            Files {
                input,
                output,
                errors,
                limit: ARCHIVE_LIMIT,
            },
            &[],
        )
    }

    /// Enforce the existing offline VM configuration before sending configuration artifacts.
    pub fn offline(&mut self, vm: &str) -> Result<()> {
        let netvm = self.text("qvm-prefs", &[vm, "netvm"])?;
        ensure!(
            ["", "none", "None"].contains(&netvm.as_str()),
            "config VM is not offline: {vm} netvm={netvm}"
        );
        let provides = self.text("qvm-prefs", &[vm, "provides_network"])?;
        ensure!(
            !["true", "True"].contains(&provides.as_str()),
            "config VM provides network: {vm}"
        );
        Ok(())
    }

    /// Start an existing configuration VM if it is not already running.
    pub fn start(&mut self, vm: &str) -> Result<()> {
        self.text("qvm-check", &[vm])?;
        if self.text("qvm-check", &["--running", vm]).is_err() {
            self.text("qvm-start", &[vm])?;
        }
        Ok(())
    }

    /// Refuse these local privileged operations outside a healthy Qubes control domain.
    pub fn control_domain(&mut self) -> Result<()> {
        let capabilities =
            fs::read_to_string(path("AIRLOCK_XEN_CAPABILITIES", "/proc/xen/capabilities"))?;
        ensure!(
            capabilities
                .split_whitespace()
                .any(|word| word == "control_d"),
            "host is not a Xen control domain"
        );
        for service in [
            "qubes-db-dom0.service",
            "qubesd.service",
            "qubes-qrexec-policy-daemon.service",
        ] {
            self.text("systemctl", &["is-active", "--quiet", service])?;
        }
        Ok(())
    }
}

/// Validate exact flat regular members before extracting; duplicates and links are rejected.
pub(super) fn unpack(
    source: &Path,
    destination: &Path,
    allowed: &[&str],
    required: &[&str],
) -> Result<()> {
    let input = File::open(source)?;
    ensure!(
        input.metadata()?.len() <= ARCHIVE_LIMIT,
        "candidate archive exceeds its size limit"
    );
    let mut archive = tar::Archive::new(input);
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let member = entry.path()?.into_owned();
        let member = member.to_str().context("non-UTF-8 candidate member")?;
        ensure!(
            allowed.contains(&member),
            "unexpected candidate tar member: {member}"
        );
        ensure!(
            seen.insert(member.to_owned()),
            "duplicate candidate tar member: {member}"
        );
        ensure!(
            entry.header().entry_type().is_file(),
            "candidate tar member is not a regular file: {member}"
        );
        total = total
            .checked_add(entry.size())
            .context("archive size overflow")?;
        ensure!(
            total <= ARCHIVE_LIMIT,
            "candidate contents exceed size limit"
        );
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination.join(member))?;
        std::io::copy(&mut entry, &mut output)?;
    }
    ensure!(
        required.iter().all(|member| seen.contains(*member)),
        "candidate tar is missing required members"
    );
    Ok(())
}

/// Extract the last structured service result from interleaved diagnostic lines.
pub(super) fn result(path: &Path, schema: &str) -> Result<Value> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 16 * 1024 * 1024,
        "service result exceeds its limit"
    );
    String::from_utf8(bytes)?
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .rfind(|value| value["schema"] == schema)
        .context("service did not emit result JSON")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one archive member using its real type rather than asserting generated script text.
    fn member(archive: &mut tar::Builder<File>, kind: tar::EntryType) -> Result<()> {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(kind);
        header.set_mode(0o600);
        header.set_size(0);
        if kind.is_symlink() {
            header.set_link_name("/outside")?;
        }
        header.set_cksum();
        archive.append_data(&mut header, "manifest.json", std::io::empty())?;
        Ok(())
    }

    /// Links, duplicate members and missing required payloads cannot reach extraction consumers.
    #[test]
    fn flat_archive_rejects_links_duplicates_and_missing_members() -> Result<()> {
        for case in 0..3 {
            let directory = tempfile::tempdir()?;
            let file = directory.path().join("input.tar");
            let mut archive = tar::Builder::new(File::create(&file)?);
            member(
                &mut archive,
                if case == 0 {
                    tar::EntryType::Symlink
                } else {
                    tar::EntryType::Regular
                },
            )?;
            if case == 1 {
                member(&mut archive, tar::EntryType::Regular)?;
            }
            archive.finish()?;
            drop(archive);
            let output = tempfile::tempdir()?;
            assert!(
                unpack(
                    &file,
                    output.path(),
                    &["manifest.json", "config.bundle"],
                    &["manifest.json", "config.bundle"]
                )
                .is_err()
            );
        }
        Ok(())
    }
}
