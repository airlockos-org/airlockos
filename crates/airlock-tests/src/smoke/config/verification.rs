//! Check materialized declarations and independent configuration archival evidence.

use super::Session;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

/// Recognize the complete materialized closure descriptor consumed by setup, independently of observed VM state.
pub(super) fn closure(topology: &Value, name: &str) -> bool {
    let domain = &topology["domains"][name];
    let backend = &domain["backend"];
    domain["class"] == "StandaloneVM"
        && domain["template"].is_null()
        && backend["type"] == "nix-closure"
        && backend["template"].is_null()
        && ["system", "root", "store"].iter().all(|key| {
            backend[*key]["source"]
                .as_str()
                .is_some_and(|source| source.starts_with("/nix/store/"))
                && backend[*key]["source_ref"].is_null()
        })
        && backend["root"]["source"]
            .as_str()
            .is_some_and(|source| source.ends_with("/root.img"))
        && backend["store"]["mode"] == "shared-closure"
        && backend["store"]["view_backend"] == "erofs-objectmap"
        && backend["store"]["blob_device"] == "/dev/xvdf"
        && backend["store"]["mountpoint"] == "/nix/store"
        && backend["store"]["device"] == "/dev/xvde"
        && backend["store"]["read_only"] == true
}

/// Audit the selected authority/result relationships, including dependency-generated restart evidence.
pub(super) fn results(
    archive: &Value,
    apply: &Value,
    status: &Value,
    guests: &[&str],
    action: &str,
    reason: &str,
) -> Result<()> {
    let staging = guests[0];
    for (field, name) in [
        ("staging", guests[0]),
        ("validator", guests[1]),
        ("vault", guests[2]),
    ] {
        ensure!(
            archive[field] == name && apply[field] == name,
            "configuration result substituted a role identity"
        );
    }
    let archival: airlock_nix_core::configuration::ArchivedConfiguration =
        serde_json::from_value(archive.clone()).context("configuration archival schema differs")?;
    archival.check()?;
    for name in [
        "nix-eval-airlock-topology",
        "airlock-topology-json",
        "nix-eval-airlock-system",
        "airlock-system-json",
        "nix-system-source-refs-dry-run",
    ] {
        ensure!(
            archive["validation"]["checks"]
                .as_array()
                .is_some_and(|checks| checks
                    .iter()
                    .any(|check| check["name"] == name && check["status"] == "passed")),
            "validation check did not pass: {name}"
        );
    }
    for guest in guests {
        ensure!(
            status["topology"]["domain_names"]
                .as_array()
                .is_some_and(|names| names.contains(&json!(guest))),
            "status omitted a declared VM"
        );
    }
    for guest in &guests[..3] {
        ensure!(
            status["qvm"]["managed_domains"]
                .as_array()
                .is_some_and(|domains| domains.iter().any(|domain| domain["name"] == *guest)),
            "status omitted a managed configuration VM"
        );
    }
    ensure!(
        status["qrexec_policy"]["exists"] == true
            && status["deployment"]["current"]["status"] == "passed"
            && status["deployment"]["last_attempt"]["status"] == "passed"
            && status["deployment"]["current"]["candidate_commit"]
                == status["apply"]["candidate_commit"]
            && status["deployment"]["current_apply"]["status"] == "passed",
        "deployment status and candidate bindings disagree"
    );
    ensure!(
        status["pending_vm_restarts"]["actions"]
            .as_array()
            .is_some_and(|actions| actions
                .iter()
                .any(|action| action["domain"] == staging && action["type"] == "domain-feature")),
        "status lost staging feature restart evidence"
    );
    let host = &apply["system_apply_result"];
    ensure!(
        apply["schema"] == "airlock.config-apply.v1"
            && apply["archive"]["status"] == "passed"
            && apply["deployment"]["schema"] == "airlock.config-deployment.v1"
            && apply["deployment_archive"]["schema"] == "airlock.config-vault-deployment.v1"
            && apply["deployment"]["system_apply"] == *host,
        "deployment archival changed the applied host result"
    );
    ensure!(
        apply["setup"]["domains_changed"].as_u64().is_some()
            && apply["setup"]["features_changed"]
                .as_u64()
                .is_some_and(|count| count >= 1),
        "setup did not retain configuration-change evidence"
    );
    let required = action == "boot";
    for pending in [
        &status["pending_reboot"],
        &status["system"]["pending_reboot"],
    ] {
        ensure!(
            pending["required"] == required,
            "status reboot requirements disagree"
        );
        if required {
            ensure!(
                pending["actions"]
                    .as_array()
                    .is_some_and(|actions| actions.len() == 1)
                    && pending["reasons"] == json!([reason]),
                "status lost boot actions or reasons"
            );
        } else {
            ensure!(
                pending["actions"].as_array().is_some_and(Vec::is_empty)
                    && pending["reasons"].as_array().is_some_and(Vec::is_empty),
                "status retained consumed boot actions"
            );
        }
    }
    ensure!(
        status["system"]["host_system_profile_resolved_target"] == host["host_system_source"],
        "status selected a different host source"
    );
    if !required {
        ensure!(
            status["system"]["run_current_system_target"] == host["host_system_source"]
                && status["system"]["run_current_system_resolved_target"]
                    == host["host_system_source"],
            "status running generation differs from activation"
        );
    }
    Ok(())
}

/// Observe the vault's independent persisted documents and pointer agreement, rather than trusting dom0 reports alone.
pub(super) fn vault_evidence(
    session: &mut Session,
    vault: &str,
    user: &str,
    expected_actions: &str,
) -> Result<()> {
    let repo = format!("/home/{user}/airlock-config-vault");
    session.remote(
        vault,
        "cat",
        &[&format!("{repo}/latest-candidate")],
        None,
        "config-vms-config-vault-archive-tree.log",
    )?;
    session.remote(
        vault,
        "find",
        &[
            &format!("{repo}/candidates"),
            "-maxdepth",
            "3",
            "-type",
            "f",
        ],
        None,
        "config-vms-config-vault-archive-tree.log",
    )?;
    let latest = session.remote(
        vault,
        "cat",
        &[&format!("{repo}/latest-deployment")],
        None,
        "config-vms-vault-latest.log",
    )?;
    let attempt = session.remote(
        vault,
        "cat",
        &[&format!("{repo}/latest-deployment-attempt")],
        None,
        "config-vms-vault-attempt.log",
    )?;
    ensure!(
        latest == attempt
            && !latest.is_empty()
            && latest != "."
            && latest != ".."
            && latest
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte)),
        "vault deployment pointers disagree"
    );
    let directory = format!("{repo}/deployments/{latest}");
    session.remote(
        vault,
        "test",
        &["-d", &directory],
        None,
        "config-vms-vault-directory.log",
    )?;
    for (file, schema, expected) in [
        ("deployment.json", "airlock.config-deployment.v1", "passed"),
        ("apply.json", "airlock.config-apply.v1", "passed"),
        ("setup.json", "airlock.setup-config.v1", "passed"),
        ("topology.json", "airlock.qubes-topology.v1", ""),
        (
            "systemd-actions.json",
            "airlock.systemd-actions.v1",
            expected_actions,
        ),
    ] {
        let text = session.remote(
            vault,
            "cat",
            &[&format!("{directory}/{file}")],
            None,
            &format!("config-vms-vault-{file}"),
        )?;
        let value: Value = serde_json::from_str(&text)?;
        ensure!(
            value["schema"] == schema && (expected.is_empty() || value["status"] == expected),
            "vault deployment artifact differs: {file}"
        );
        if file == "deployment.json" {
            ensure!(
                value["systemd_actions"]["status"] == expected_actions,
                "vault deployment lost service-action status"
            );
        }
    }
    session.remote(
        vault,
        "find",
        &[&directory, "-maxdepth", "2", "-type", "f"],
        None,
        "config-vms-config-vault-deployment-tree.log",
    )?;
    Ok(())
}
