//! Coordinate mode boundaries, preflight and explicit candidate application.

use super::{
    Session, common,
    guests::{backend, persistence},
    settings::Scenario,
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::process::Command;

impl Scenario {
    /// Dispatch the selected modes without advancing past their documented stopping points.
    pub(super) fn run(&self, session: &mut Session, record: &mut Value) -> Result<()> {
        self.prepare(session)?;

        if matches!(self.mode.as_str(), "full" | "preflight") {
            self.preflight(session)?;
        }
        if self.mode == "preflight" {
            return Ok(());
        }

        if matches!(self.mode.as_str(), "full" | "stage-candidate") {
            super::stage(
                session,
                &self.staging,
                &json!({"created":self.created,"message":self.message,"action":self.action}),
                "test runtime config changes",
            )?;
        }
        if self.mode == "stage-candidate" {
            return Ok(());
        }

        if matches!(self.mode.as_str(), "full" | "apply-candidate") {
            self.apply(session)?;
        }
        if self.mode == "apply-candidate" {
            return Ok(());
        }

        self.post_apply(session, record)
    }

    /// Validate inputs and require an existing healthy control domain before mutation.
    fn prepare(&self, session: &mut Session) -> Result<()> {
        ensure!(
            [
                "full",
                "preflight",
                "stage-candidate",
                "apply-candidate",
                "post-apply"
            ]
            .contains(&self.mode.as_str()),
            "unsupported AIRLOCK_CONFIG_VMS_SMOKE_MODE: {mode}",
            mode = self.mode
        );
        ensure!(
            matches!(self.action.as_str(), "switch" | "boot"),
            "AIRLOCK_CONFIG_DOM0_SYSTEM_SWITCH_ACTION must be switch or boot"
        );
        for guest in [&self.staging, &self.validator, &self.vault, &self.created] {
            common::vm(guest)?;
        }

        session.control_domain()?;
        for guest in [&self.staging, &self.validator, &self.vault] {
            session.command("qvm-check", &[guest], "config-vms-domain-exists.log")?;
        }

        Ok(())
    }

    /// Check configuration VMs, persistence and initialized repositories before staging.
    fn preflight(&self, session: &mut Session) -> Result<()> {
        for (label, guest) in [
            ("config-vault", &self.vault),
            ("config-staging", &self.staging),
            ("config-validator", &self.validator),
        ] {
            self.preflight_guest(session, guest, label)?;
        }

        if common::setting("AIRLOCK_CONFIG_VMS_IMPORT_INPUTS", "1") == "1" {
            session.command(
                "airlock-config-inputs-import",
                &[],
                "config-vms-config-inputs-import.log",
            )?;
        }
        session.command(
            "airlock-config-bootstrap-current",
            &[],
            "config-vms-config-current-bootstrap.log",
        )?;
        for (guest, command, label) in [
            (
                &self.staging,
                "airlock-config-staging-init",
                "config-staging",
            ),
            (
                &self.validator,
                "airlock-config-validator-init",
                "config-validator",
            ),
        ] {
            session.remote(
                guest,
                command,
                &[],
                None,
                &format!("config-vms-{label}-init.log"),
            )?;
        }

        for (guest, label, directory) in [
            (&self.vault, "config-vault", "airlock-config-vault"),
            (&self.staging, "config-staging", "airlock-config"),
        ] {
            let status = session.remote(
                guest,
                "git",
                &[
                    "-C",
                    &format!("/home/{user}/{directory}", user = self.user),
                    "status",
                    "--porcelain=v2",
                    "--branch",
                    "--untracked-files=all",
                ],
                None,
                &format!("config-vms-{label}-repo-status.log"),
            )?;
            ensure!(
                common::clean_main(&status),
                "{guest} repository is not initialized cleanly"
            );
        }

        Ok(())
    }

    /// Check one configuration VM's boot, qrexec identity, store and home persistence.
    fn preflight_guest(&self, session: &mut Session, guest: &str, label: &str) -> Result<()> {
        backend(session, guest, label)?;
        session.start(guest)?;
        let uname = session.remote(
            guest,
            "uname",
            &["-a"],
            None,
            &format!("config-vms-{label}-uname.log"),
        )?;
        ensure!(
            uname.contains("Linux"),
            "{guest} uname output did not contain Linux"
        );
        let guest_user = session.remote(
            guest,
            "id",
            &["-un"],
            None,
            &format!("config-vms-{label}-user.log"),
        )?;
        ensure!(
            guest_user == self.user,
            "{guest} qrexec user was not {user}",
            user = self.user
        );
        session.runtime_store(guest, &format!("config-vms-{label}-store-mount.log"))?;
        let dom0_user = common::setting(
            "AIRLOCK_DOM0_USER",
            &common::setting("SUDO_USER", "airlock"),
        );
        let mut sync = if rustix::process::geteuid().is_root() {
            let mut command = Command::new("runuser");
            command.args(["-u", &dom0_user, "--", "qvm-sync-appmenus"]);
            command
        } else {
            Command::new("qvm-sync-appmenus")
        };
        session.run(
            sync.arg(guest),
            None,
            &format!("config-vms-{label}-appmenus.log"),
        )?;
        persistence(session, guest, label, &self.message)?;

        Ok(())
    }

    /// Apply only the selected candidate using the existing role bindings and stage.
    fn apply(&self, session: &mut Session) -> Result<()> {
        session.run(
            Command::new("airlock-config-apply")
                .args([
                    "--apply",
                    "--staging",
                    &self.staging,
                    "--validator",
                    &self.validator,
                    "--vault",
                    &self.vault,
                ])
                .env("AIRLOCK_CONFIG_APPLY_STAGE", &self.stage_name)
                .env(
                    "AIRLOCK_CONFIG_APPLY_NIX_OFFLINE",
                    common::setting("AIRLOCK_CONFIG_APPLY_NIX_OFFLINE", "0"),
                ),
            None,
            "config-vms-apply.log",
        )?;

        Ok(())
    }
}
