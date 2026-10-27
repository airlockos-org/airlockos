//! Verify applied topology, policy, host activation, guest runtime and independent archives.

use super::{
    Session, common,
    guests::{backend, persistence},
    host::host,
    settings::Scenario,
    verification::{closure, results, vault_evidence},
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::fs;

impl Scenario {
    /// Verify the applied candidate, then publish complete archival evidence after all checks pass.
    pub(super) fn post_apply(&self, session: &mut Session, record: &mut Value) -> Result<()> {
        let topology = self.topology(session)?;
        self.policy(session)?;
        self.host(session, record)?;
        self.created_guest(session)?;
        self.archives(session, record)?;

        record["applied_topology"] = topology;
        Ok(())
    }

    /// Check native closure descriptors and role declarations before observing live effects.
    fn topology(&self, session: &Session) -> Result<Value> {
        let topology: Value =
            serde_json::from_slice(&fs::read(session.file("config-apply-topology.json"))?)?;
        common::save(&session.file("config-vms-applied-topology.json"), &topology)?;
        for guest in [&self.staging, &self.validator, &self.vault, &self.created] {
            ensure!(
                closure(&topology, guest),
                "applied topology does not define a native closure VM: {guest}"
            );
        }
        ensure!(
            topology["prefs"]["default_kernel"] == ""
                && topology["templates"] == json!({})
                && topology["kernels"] == json!({}),
            "applied topology did not preserve native-only boot resources"
        );
        for (guest, color, flag, role) in [
            (
                &self.vault,
                "black",
                "airlock-config-authority",
                "sys-config-vault",
            ),
            (
                &self.staging,
                "gray",
                "airlock-config-staging",
                "sys-config-staging",
            ),
            (
                &self.validator,
                "blue",
                "airlock-config-validator",
                "sys-config-validator",
            ),
        ] {
            let declaration = &topology["domains"][guest];
            ensure!(
                declaration["label"] == color
                    && declaration["netvm"].is_null()
                    && declaration["prefs"]["include_in_backups"] == true
                    && declaration["features"][flag] == "1",
                "configuration role declaration differs: {guest}"
            );
            if role != "sys-config-staging" {
                ensure!(
                    declaration["features"]["airlock-role"] == role,
                    "configuration role feature differs: {guest}"
                );
            }
        }
        ensure!(
            topology["domains"][&self.staging]["features"]["airlock-config-applied-message"]
                == self.message
                && topology["domains"][&self.created]["features"]["airlock-created-from-config"]
                    == "1"
                && topology["domains"][&self.created]["features"]["airlock-created-from-config-message"]
                    == self.message,
            "applied test features differ from the staged message"
        );
        Ok(topology)
    }

    /// Check generated rules and exercise the vault policy probe through qrexec.
    fn policy(&self, session: &mut Session) -> Result<()> {
        let policy = fs::read_to_string(
            common::path(
                "AIRLOCK_QUBES_POLICY_DIR",
                "/var/lib/airlock/qubes-policy.d",
            )
            .join("90-airlock.policy"),
        )?;
        ensure!(
            policy
                .lines()
                .any(|line| line == "airlock.PolicyProbe * dom0 sys-config-vault allow")
                && policy
                    .lines()
                    .any(|line| line == "airlock.PolicyProbe * @anyvm @anyvm deny"),
            "generated qrexec policy is missing PolicyProbe rules"
        );
        fs::write(session.file("config-vms-qrexec-policy.log"), &policy)?;
        let probe = session.command(
            "qrexec-client",
            &[
                "-d",
                &self.vault,
                "-T",
                "-w",
                "120",
                "DEFAULT:QUBESRPC airlock.PolicyProbe+ dom0",
            ],
            "config-vms-qrexec-policy-probe.log",
        )?;
        ensure!(
            probe.lines().any(|line| line
                == format!(
                    "airlock-policy-probe role=sys-config-vault user={user}",
                    user = self.user
                )),
            "generated qrexec policy probe output did not match expected value"
        );
        Ok(())
    }

    /// Retain the host activation receipt and require the staging restart requirement.
    fn host(&self, session: &mut Session, record: &mut Value) -> Result<()> {
        let (host_apply, status) = host(session, &self.message, &self.action, &self.reason)?;
        record["dom0_system_apply"] = host_apply;
        record["config_status"] = status;
        ensure!(
            record["config_status"]["pending_vm_restarts"]["required"] == true
                && record["config_status"]["pending_vm_restarts"]["domains"]
                    .as_array()
                    .is_some_and(|domains| domains.contains(&json!(self.staging))),
            "running staging VM restart requirement was lost"
        );
        Ok(())
    }

    /// Verify applied features, native boot and persistent home state in the new VM.
    fn created_guest(&self, session: &mut Session) -> Result<()> {
        for (guest, feature, log) in [
            (
                &self.staging,
                "airlock-config-applied-message",
                "config-vms-applied-feature.log",
            ),
            (
                &self.created,
                "airlock-created-from-config-message",
                "config-vms-created-qube-feature.log",
            ),
        ] {
            ensure!(
                session.command("qvm-features", &[guest, feature], log)? == self.message,
                "applied config feature did not match expected value for {guest}"
            );
        }

        backend(session, &self.created, "created-qube")?;
        session.start(&self.created)?;
        let uname = session.remote(
            &self.created,
            "uname",
            &["-a"],
            None,
            "config-vms-created-qube-uname.log",
        )?;
        ensure!(
            uname.contains("Linux"),
            "created qube uname did not contain Linux"
        );
        ensure!(
            session.remote(
                &self.created,
                "id",
                &["-un"],
                None,
                "config-vms-created-qube-user.log"
            )? == self.user,
            "created qube qrexec user differs"
        );
        session.runtime_store(&self.created, "config-vms-created-qube-store-mount.log")?;
        persistence(session, &self.created, "created-qube", &self.message)?;
        Ok(())
    }

    /// Cross-check apply receipts and the vault before exposing complete success evidence.
    fn archives(&self, session: &mut Session, record: &mut Value) -> Result<()> {
        let archived: Value =
            serde_json::from_slice(&fs::read(session.file("config-archive.json"))?)?;
        let applied: Value = serde_json::from_slice(&fs::read(session.file("config-apply.json"))?)?;
        ensure!(
            archived["status"] == "passed"
                && archived["candidate_commit"] == archived["validation_commit"]
                && archived["candidate_commit"] == archived["vault_archive"]["candidate_commit"]
                && archived["validation"]["status"] == "passed",
            "config archive JSON did not pass"
        );
        ensure!(
            applied["status"] == "passed"
                && applied["setup"]["status"] == "passed"
                && applied["deployment"]["status"] == "passed"
                && applied["deployment_archive"]["status"] == "passed"
                && applied["system_apply_result"] == record["dom0_system_apply"]
                && applied["setup"]["restart_required"] == true
                && applied["setup"]["restart_actions"]
                    .as_array()
                    .is_some_and(|actions| actions
                        .iter()
                        .any(|action| action["domain"] == self.staging
                            && action["type"] == "domain-feature")),
            "config apply JSON did not pass"
        );
        results(
            &archived,
            &applied,
            &record["config_status"],
            &[&self.staging, &self.validator, &self.vault, &self.created],
            &self.action,
            &self.reason,
        )?;
        vault_evidence(
            session,
            &self.vault,
            &self.user,
            if self.action == "boot" {
                "skipped"
            } else {
                "passed"
            },
        )?;

        record["archive"] = archived;
        record["apply"] = applied;
        Ok(())
    }
}
