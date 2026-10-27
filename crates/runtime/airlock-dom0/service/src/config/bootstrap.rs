//! Initialize staging from the existing vault-current protocol without replacing a staged worktree.

use super::io::{self, Operation};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::FileTypeExt,
    path::Path,
    thread,
    time::{Duration, Instant},
};

/// Retry only transient endpoint connection errors; protocol failures are never treated as success.
fn rpc(
    operation: &mut Operation,
    vm: &str,
    service: &str,
    input: Option<&Path>,
    output: &Path,
    errors: &Path,
) -> Result<()> {
    let runtime = io::path("AIRLOCK_QREXEC_RUN_DIR", "/var/run/qubes");
    let seconds: u64 = io::setting("AIRLOCK_CONFIG_QREXEC_READY_WAIT_SECONDS", "120").parse()?;
    for attempt in 0..3 {
        if runtime.is_dir() {
            let socket = runtime.join(format!("qrexec.{vm}"));
            let deadline = Instant::now()
                .checked_add(Duration::from_secs(seconds))
                .context("qrexec wait too large")?;
            let ready = || {
                socket
                    .metadata()
                    .is_ok_and(|metadata| metadata.file_type().is_socket())
            };
            while !ready() && Instant::now() < deadline {
                thread::sleep(Duration::from_secs(1));
            }
            ensure!(ready(), "qrexec endpoint did not become ready for {vm}");
        }
        match operation.rpc(vm, service, input, output, errors) {
            Ok(()) => return Ok(()),
            Err(error) => {
                let diagnostic = fs::read_to_string(errors).unwrap_or_default();
                let transient = diagnostic.contains("connect ")
                    && diagnostic.contains("/qrexec.")
                    && (diagnostic.contains(": No such file or directory")
                        || diagnostic.contains(": Connection refused"));
                if !transient || attempt == 2 {
                    return Err(error);
                }
                thread::sleep(Duration::from_secs(2));
            }
        }
    }
    unreachable!()
}

/// Transfer the vault's current inert bundle and require the staging import's passing result.
pub(super) fn execute() -> Result<()> {
    let mut operation = Operation::new("config-current-bootstrap")?;
    let vault = io::setting("AIRLOCK_CONFIG_VAULT_VM", "sys-config-vault");
    let staging = io::setting("AIRLOCK_CONFIG_STAGING_VM", "sys-config-staging");
    let export = io::setting(
        "AIRLOCK_CONFIG_CURRENT_EXPORT_SERVICE",
        "airlock.Config.ExportCurrent",
    );
    let import = io::setting(
        "AIRLOCK_CONFIG_CURRENT_IMPORT_SERVICE",
        "airlock.Config.ImportCurrent",
    );
    let archive = operation.file("config-current-bootstrap-current.tar");
    let output = operation.file("config-current-bootstrap-import.stdout.log");
    let mut commit = String::new();
    let result: Result<()> = (|| {
        let capabilities = fs::read_to_string(io::path(
            "AIRLOCK_XEN_CAPABILITIES",
            "/proc/xen/capabilities",
        ))?;
        ensure!(
            capabilities
                .split_whitespace()
                .any(|word| word == "control_d"),
            "host is not a Xen control domain"
        );
        for vm in [&vault, &staging] {
            let _: airlock_nix_core::identity::GuestName = vm.parse()?;
            operation.start(vm)?;
        }
        let export_errors = operation.file("config-current-bootstrap-export.stderr.log");
        rpc(
            &mut operation,
            &vault,
            &export,
            None,
            &archive,
            &export_errors,
        )?;
        let temporary = tempfile::tempdir()?;
        io::unpack(
            &archive,
            temporary.path(),
            &["config.bundle", "manifest.json"],
            &["config.bundle", "manifest.json"],
        )?;
        let manifest: Value = crate::state::read(&temporary.path().join("manifest.json"))?;
        ensure!(
            manifest["schema"] == "airlock.config-candidate.v1",
            "vault current manifest is invalid"
        );
        commit = manifest["commit"]
            .as_str()
            .context("vault current manifest has no commit")?
            .into();
        io::save(
            &operation.file("config-current-bootstrap-manifest.json"),
            &manifest,
        )?;
        let import_errors = operation.file("config-current-bootstrap-import.stderr.log");
        rpc(
            &mut operation,
            &staging,
            &import,
            Some(&archive),
            &output,
            &import_errors,
        )?;
        let reply: Value = crate::state::read(&output)?;
        ensure!(
            reply["schema"] == "airlock.config-staging-import-current.v1"
                && reply["status"] == "passed",
            "staging import did not emit a passing result"
        );
        Ok(())
    })();
    let mut receipt = json!({"schema":"airlock.config-current-bootstrap.v1","status":if result.is_ok() {"passed"} else {"failed"},"reason":match &result {Ok(())=>"sys-config-vault current exported and sys-config-staging initialized".into(),Err(error)=>format!("{error:#}")},"vault":vault,"staging":staging,"export_service":export,"import_service":import,"candidate_commit":commit,"archive_bytes":archive.metadata().map(|metadata| metadata.len()).unwrap_or(0),"import":io::optional(&output)});
    for (key, file) in [
        ("manifest", "config-current-bootstrap-manifest.json"),
        ("current_archive", "config-current-bootstrap-current.tar"),
        ("command_log", "config-current-bootstrap.commands.log"),
        (
            "export_stderr",
            "config-current-bootstrap-export.stderr.log",
        ),
        (
            "import_stdout",
            "config-current-bootstrap-import.stdout.log",
        ),
        (
            "import_stderr",
            "config-current-bootstrap-import.stderr.log",
        ),
    ] {
        receipt[key] = json!(operation.file(file));
    }
    io::save(&operation.file("config-current-bootstrap.json"), &receipt)?;
    if result.is_ok() {
        println!("{receipt}");
    }
    result
}
