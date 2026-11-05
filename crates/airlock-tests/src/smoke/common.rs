//! Bounded Qubes command adapters and structured evidence for explicitly invoked smoke tests.

use airlock_nix_core::runtime::process;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

/// Resolve a nonempty string override with the same defaults as the installed commands.
pub(super) fn setting(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.into())
}

/// Resolve a filesystem override without treating path contents as command syntax.
pub(super) fn path(key: &str, default: impl AsRef<Path>) -> PathBuf {
    std::env::var_os(key)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| default.as_ref().to_owned())
}

/// Write a complete informational test receipt in the selected evidence directory.
pub(super) fn save(path: &Path, value: &Value) -> Result<()> {
    fs::create_dir_all(path.parent().context("smoke receipt parent")?)?;
    let mut temporary = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
    serde_json::to_writer_pretty(&mut temporary, value)?;
    writeln!(temporary)?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

/// Parse exactly the committed-main predicate; upstream tracking and ahead/behind counts are informational.
pub(super) fn clean_main(text: &str) -> bool {
    let committed = text.lines().any(|line| {
        line.strip_prefix("# branch.oid ")
            .is_some_and(|oid| oid != "(initial)" && !oid.is_empty())
    });
    let main = text.lines().any(|line| line == "# branch.head main");
    committed && main && text.lines().all(|line| line.starts_with('#'))
}

/// Exact Qubes VM spelling used for script/feature targets and evidence filenames.
pub(super) fn vm(name: &str) -> Result<&str> {
    ensure!(
        name.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)),
        "invalid smoke VM name: {name}"
    );
    Ok(name)
}

/// Parse the existing line-oriented probes without letting a missing field become success.
pub(super) fn fields(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| {
            line.split_once('=')
                .map(|(key, value)| (key.into(), value.into()))
        })
        .collect()
}

/// One live scenario's command evidence, without any automatic activation during tests.
pub(super) struct Session {
    /// Directory containing this scenario's receipt and diagnostic files.
    pub directory: PathBuf,
    /// Scenario's existing receipt/log prefix.
    pub name: String,
    /// Recorded helper argv and outcomes; observations never grant deployment authority.
    log: fs::File,
}

impl Session {
    /// Select the installed default log directory or an explicit isolated fixture path.
    pub fn new(name: &str, root: Option<&Path>, local_default: bool) -> Result<Self> {
        let default = if local_default {
            let root = root.map(Path::to_owned).unwrap_or(std::env::current_dir()?);
            if rustix::fs::access(&root, rustix::fs::Access::WRITE_OK).is_ok() {
                airlock_dev_paths::path("AIRLOCK_LOG_DIR", "logs")?
            } else {
                path(
                    "XDG_STATE_HOME",
                    PathBuf::from(std::env::var_os("HOME").context("HOME is missing")?)
                        .join(".local/state"),
                )
                .join("airlock")
            }
        } else {
            PathBuf::from("/var/log/airlock")
        };
        let directory = path("AIRLOCK_LOG_DIR", default);
        fs::create_dir_all(&directory)?;
        let log = fs::File::create(directory.join(format!("{name}.commands.log")))?;
        Ok(Self {
            directory,
            name: name.into(),
            log,
        })
    }

    /// Resolve one fixed evidence filename beneath this scenario's selected directory.
    pub fn file(&self, name: &str) -> PathBuf {
        self.directory.join(name)
    }

    /// Execute a bounded tool and retain its complete bounded streams before interpreting success.
    pub fn run(
        &mut self,
        command: &mut Command,
        input: Option<Vec<u8>>,
        output: &str,
    ) -> Result<String> {
        self.run_for(command, input, output, Duration::from_secs(3600))
    }

    /// Execute a probe under its own finite deadline, including pipe collection.
    pub fn run_for(
        &mut self,
        command: &mut Command,
        input: Option<Vec<u8>>,
        output: &str,
        timeout: Duration,
    ) -> Result<String> {
        writeln!(
            self.log,
            "+ {program:?} {args:?}",
            program = command.get_program(),
            args = command.get_args().collect::<Vec<_>>()
        )?;
        let result = process::run(command, input, Some(timeout))?;
        let mut diagnostics = result.stdout.clone();
        diagnostics.extend_from_slice(&result.stderr);
        fs::write(self.file(output), &diagnostics)?;
        writeln!(
            self.log,
            "{outcome}",
            outcome = json!({"status":result.status.code(),"log":output})
        )?;
        let stdout = String::from_utf8(result.checked("live smoke helper")?)?;
        Ok(stdout.trim_end_matches('\n').into())
    }

    /// Run a small fixed upstream command without an input payload.
    pub fn command(&mut self, program: &str, args: &[&str], output: &str) -> Result<String> {
        self.run(Command::new(program).args(args), None, output)
    }

    /// Call one guest program with data-only arguments through the existing VMShell transport.
    pub fn remote(
        &mut self,
        guest: &str,
        program: &str,
        args: &[&str],
        input: Option<Vec<u8>>,
        output: &str,
    ) -> Result<String> {
        self.remote_for(
            guest,
            (program, args),
            input,
            output,
            Duration::from_secs(3600),
        )
    }

    /// Bound a short readiness probe separately from long source evaluation and validation.
    pub fn remote_for(
        &mut self,
        guest: &str,
        argv: (&str, &[&str]),
        input: Option<Vec<u8>>,
        output: &str,
        timeout: Duration,
    ) -> Result<String> {
        let (program, args) = argv;
        vm(guest)?;
        let command = std::iter::once(program)
            .chain(args.iter().copied())
            .map(crate_quote)
            .collect::<Vec<_>>()
            .join(" ");
        self.run_for(
            Command::new("qrexec-client").args([
                "-d",
                guest,
                &format!(
                    "{user}:{command}",
                    user = setting("AIRLOCK_QUBE_USER", "user")
                ),
            ]),
            input,
            output,
            timeout,
        )
    }

    /// Refuse mutation outside an existing healthy Xen control domain.
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
            self.command(
                "systemctl",
                &["is-active", "--quiet", service],
                "smoke-services.log",
            )?;
        }
        Ok(())
    }

    /// Start only the selected VM; Qubes retains its existing implicit dependency behavior.
    pub fn start(&mut self, guest: &str) -> Result<()> {
        vm(guest)?;
        if self
            .command("qvm-check", &["--running", guest], "smoke-power.log")
            .is_err()
        {
            self.command("qvm-start", &[guest], "smoke-start.log")?;
        }
        Ok(())
    }

    /// Check the exact guest store device, read-only mount and running generation using upstream probes.
    pub fn runtime_store(&mut self, guest: &str, output: &str) -> Result<()> {
        let reply = self.remote(
            guest,
            "airlock-vm-service",
            &["runtime", "store-check"],
            None,
            output,
        )?;
        let observed = fields(&reply);
        ensure!(
            observed.get("store_device").map(String::as_str) == Some("/dev/xvde")
                && observed
                    .get("store_options")
                    .is_some_and(|options| options.split(',').any(|option| option == "ro")),
            "guest store probe did not report the required read-only device"
        );
        Ok(())
    }

    /// Shut down and restart one selected VM through existing upstream lifecycle commands.
    pub fn restart(&mut self, guest: &str) -> Result<()> {
        if self
            .command("qvm-check", &["--running", guest], "smoke-power.log")
            .is_ok()
        {
            self.command("qvm-shutdown", &["--wait", guest], "smoke-shutdown.log")?;
        }
        self.start(guest)
    }

    /// Retain a passed or failed receipt without converting a failed helper into success.
    pub fn finish(&self, result: &Result<()>, mut record: Value) -> Result<()> {
        record["status"] = json!(if result.is_ok() { "passed" } else { "failed" });
        if let Err(error) = result {
            record["reason"] = json!(format!("{error:#}"));
        }
        save(
            &self.file(&format!("{name}.json", name = self.name)),
            &record,
        )?;
        println!("{record}");
        Ok(())
    }
}

/// Quote one guest argv component; remote shells perform only transport parsing, not scenario logic.
pub(super) fn crate_quote(value: &str) -> String {
    airlock_tests::process::quote(value)
}

/// Interpret both upstream row layouts while keeping store and store-data distinct.
pub(super) fn has_volume(listing: &str, volume: &str) -> bool {
    listing.lines().skip(1).any(|line| {
        let columns = line.split_whitespace().collect::<Vec<_>>();
        columns.get(2) == Some(&volume)
            || columns
                .first()
                .is_some_and(|value| value.ends_with(&format!("/{volume}")))
    })
}

/// Read the upstream volume list and refuse failed or partial tool output.
pub(super) fn check_volume(guest: &str, volume: &str) -> Result<()> {
    vm(guest)?;
    let output = process::run(
        Command::new("qvm-volume").args(["list", guest]),
        None,
        Some(Duration::from_secs(60)),
    )?
    .checked("Qubes volume observation")?;
    ensure!(
        has_volume(&String::from_utf8(output)?, volume),
        "Qubes volume list omits {guest}:{volume}"
    );
    Ok(())
}
