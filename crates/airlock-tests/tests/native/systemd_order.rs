//! An explicit user-systemd regression checks daemon restart dependencies using uniquely named inert units.

use crate::common;
use anyhow::{Context, Result, ensure};
use serde_json::json;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{Duration, Instant},
};

/// Own only this scenario's user units and remove them even when an assertion fails.
struct Units {
    // Local user manager executable, never the system manager.
    systemctl: PathBuf,
    // Runtime user unit directory; only named entries below are created or removed.
    directory: PathBuf,
    // Names include a temporary random suffix to avoid collisions with other sessions.
    names: [String; 3],
}

impl Units {
    /// Run a bounded command against the current user manager.
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(&self.systemctl);
        command.arg("--user").args(args);
        command
    }
}

impl Drop for Units {
    fn drop(&mut self) {
        for action in ["stop", "reset-failed"] {
            let _ = common::run(self.command(&[action]).args(&self.names), None);
        }
        for name in &self.names {
            let _ = fs::remove_file(self.directory.join(name));
        }
        let _ = common::run(&mut self.command(&["daemon-reload"]), None);
    }
}

/// Wants permits a daemon to restart during setup; Requires cancels the dependent job, and either setup/daemon failure still blocks startup.
#[test]
#[ignore = "explicitly opt into uniquely named inert user-systemd units"]
fn user_systemd_bootstrap_restart_keeps_failure_dependencies() -> Result<()> {
    ensure!(
        std::env::var("AIRLOCK_RUN_SYSTEMD_ORDER_TEST").as_deref() == Ok("1"),
        "set AIRLOCK_RUN_SYSTEMD_ORDER_TEST=1"
    );
    let systemctl = common::tool("systemctl")?;
    let runtime =
        PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR").context("user runtime directory")?);
    for (dependency, setup_ok, daemon_ok, expected) in [
        ("Requires", true, true, false),
        ("Wants", true, true, true),
        ("Wants", false, true, false),
        ("Wants", true, false, false),
    ] {
        let temporary = tempfile::tempdir()?;
        let prefix = format!(
            "airlock-order-{nonce}",
            nonce = temporary.path().file_name().unwrap().to_string_lossy()
        );
        let names = ["daemon", "setup", "vm"].map(|role| format!("{prefix}-{role}.service"));
        let directory = runtime.join("systemd/user");
        fs::create_dir_all(&directory)?;
        let units = Units {
            systemctl: systemctl.clone(),
            directory,
            names,
        };
        common::run(&mut units.command(&["show-environment"]), None)?.checked()?;
        let [daemon, setup, vm] = &units.names;
        let peer = common::peer();
        let marker = temporary.path().join("started");
        let definitions = [
            format!(
                r"[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={command}
",
                command = common::tool("true")?.display()
            ),
            format!(
                r"[Unit]
Wants={daemon}
After={daemon}
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={peer} systemd-order-setup {systemctl} {daemon} {daemon_ok} {setup_ok}
",
                peer = peer.display(),
                systemctl = systemctl.display()
            ),
            format!(
                r"[Unit]
Requires={setup}
{dependency}={daemon}
After={setup} {daemon}
[Service]
Type=oneshot
RemainAfterExit=yes
Restart=no
ExecStartPre={systemctl} --user is-active --quiet {daemon}
ExecStart={peer} systemd-order-start {marker}
",
                systemctl = systemctl.display(),
                peer = peer.display(),
                marker = marker.display()
            ),
        ];
        for (name, definition) in units.names.iter().zip(definitions) {
            fs::write(units.directory.join(name), definition)?;
        }
        common::run(&mut units.command(&["daemon-reload"]), None)?.checked()?;
        let result = common::run(&mut units.command(&["start", vm]), None)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let state = common::run(
                &mut units.command(&["show", setup, "-p", "ActiveState", "--value"]),
                None,
            )?
            .checked()?;
            if String::from_utf8_lossy(&state).trim() != "activating" {
                break;
            }
            ensure!(Instant::now() < deadline, "inert bootstrap never settled");
            std::thread::sleep(Duration::from_millis(50));
        }
        let states = common::run(
            units.command(&["show"]).args(&units.names).args([
                "-p",
                "Id",
                "-p",
                "ActiveState",
                "-p",
                "Result",
            ]),
            None,
        )?
        .checked()?;
        let logs = airlock_dev_paths::path("AIRLOCK_LOG_DIR", "logs")?.join("gui-gpu-boot-order");
        fs::create_dir_all(&logs)?;
        fs::write(
            logs.join(format!("{dependency}-{setup_ok}-{daemon_ok}.json")),
            serde_json::to_vec_pretty(&json!({
                "dependency": dependency, "setup_ok": setup_ok, "daemon_ok": daemon_ok, "success": result.status.success(),
                "stdout": String::from_utf8_lossy(&result.stdout), "stderr": String::from_utf8_lossy(&result.stderr),
                "states": String::from_utf8_lossy(&states), "vm_started": marker.exists()
            }))?,
        )?;
        assert_eq!(marker.exists(), expected);
        assert_eq!(result.status.success(), expected);
    }
    Ok(())
}
