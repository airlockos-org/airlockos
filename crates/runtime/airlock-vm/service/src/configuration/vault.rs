//! Archive validated source and deployment evidence without editing staging or evaluating received source.

use super::{Config, io, workspace};
use airlock_nix_core::{
    configuration::{
        CandidateDocuments, CandidateFiles, SubmittedConfiguration, ValidatedConfiguration,
        ValidationRecord, file_hash,
    },
    identity::GitRevision,
};
use anyhow::{Context, Result, ensure};
use serde_json::json;
use std::{
    fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::Command,
};

/// Candidate wire artifacts; only the optional prepared source may be absent.
const CANDIDATE: &[&str] = &[
    "config.bundle",
    "validation.json",
    "manifest.json",
    "topology.json",
    "system.json",
    "prepared-source.tar",
];

/// Required deployment documents already accepted by the vault protocol.
const DOCUMENTS: &[(&str, Option<&str>)] = &[
    ("deployment.json", Some("airlock.config-deployment.v1")),
    ("apply.json", Some("airlock.config-apply.v1")),
    ("archive.json", Some("airlock.config-archive.v1")),
    ("setup.json", Some("airlock.setup-config.v1")),
    ("topology.json", Some("airlock.qubes-topology.v1")),
    ("validated-topology.json", Some("airlock.qubes-topology.v1")),
    ("template-builds.json", Some("airlock.template-builds.v1")),
    (
        "nix-domain-builds.json",
        Some("airlock.nix-domain-builds.v1"),
    ),
    (
        "nix-domain-materializations.json",
        Some("airlock.nix-domain-materializations.v1"),
    ),
    (
        "unsupported-domain-backends.json",
        Some("airlock.unsupported-domain-backends.v1"),
    ),
    (
        "domain-references.json",
        Some("airlock.domain-references.v1"),
    ),
    ("system.json", Some("airlock.system.v1")),
    ("resolved-system.json", Some("airlock.system.v1")),
    ("system-plan.json", None),
    ("system-apply.json", Some("airlock.system-apply.v1")),
    ("system-builds.json", Some("airlock.system-builds.v1")),
    ("systemd-actions.json", Some("airlock.systemd-actions.v1")),
    ("validation.json", None),
    ("manifest.json", None),
];

/// Fixed diagnostic names accepted below the logs directory, never arbitrary archive paths.
const LOGS: &[&str] = &[
    "apply.commands.log",
    "archive.stdout.log",
    "archive.stderr.log",
    "setup.stdout.log",
    "setup.stderr.log",
    "template-builds.log",
    "nix-domain-builds.log",
    "system-builds.log",
    "system-apply.log",
    "profile-activation.log",
    "host-system-activation.log",
    "systemd-actions.log",
    "clone.log",
    "checkout.log",
];

/// Validate an evidence-directory identity before joining it to persistent storage.
fn identity(value: &str) -> Result<&str> {
    ensure!(
        !value.is_empty()
            && value != "."
            && value != ".."
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte)),
        "invalid deployment id: {value}"
    );
    Ok(value)
}

/// Replace the vault's current snapshot link and stage its informational pointer records.
fn current(repo: &Path, revision: &GitRevision) -> Result<()> {
    let target = PathBuf::from("candidates")
        .join(revision.as_str())
        .join("snapshot");
    ensure!(
        repo.join(&target).is_dir(),
        "current candidate snapshot is missing: {revision}"
    );
    let temporary = tempfile::tempdir_in(repo)?;
    symlink(&target, temporary.path().join("current"))?;
    fs::rename(temporary.path().join("current"), repo.join("current"))?;
    fs::write(repo.join("latest-current"), format!("{revision}\n"))?;
    io::git(repo, &["add", "latest-current", "current"])?;
    Ok(())
}

/// Create or repair the vault's archive and trusted initial runtime baseline.
pub(super) fn init(config: &Config) -> Result<()> {
    let repo = io::path("AIRLOCK_CONFIG_ARCHIVE_PATH", &config.archive);
    fs::create_dir_all(&repo)?;
    if !repo.join(".git").is_dir() {
        io::run(Command::new("git").args(["init", "-b", "main"]).arg(&repo))?;
    }
    for directory in ["candidates", "deployments"] {
        fs::create_dir_all(repo.join(directory))?;
        fs::write(repo.join(directory).join(".gitkeep"), [])?;
    }
    fs::write(
        repo.join("README.md"),
        "# Airlock Configuration Vault\n\nThis repository archives Airlock configuration baselines, candidates, and\ndeployment records written by dom0.\n\nThe `current` link points at the latest config snapshot used to initialize\nan editable sys-config-staging worktree.\n",
    )?;
    io::git(
        &repo,
        &[
            "add",
            "README.md",
            "candidates/.gitkeep",
            "deployments/.gitkeep",
        ],
    )?;
    if let Ok(latest) = fs::read_to_string(repo.join("latest-current")) {
        let revision: GitRevision = latest
            .lines()
            .next()
            .context("empty current pointer")?
            .parse()?;
        if repo
            .join("candidates")
            .join(revision.as_str())
            .join("snapshot")
            .is_dir()
        {
            current(&repo, &revision)?;
            io::commit(
                &repo,
                "repair current config pointer",
                "Airlock Config Vault",
                "airlock-config-vault@localhost",
            )?;
            return Ok(());
        }
    }
    if let Ok(latest) = fs::read_to_string(repo.join("latest-deployment"))
        && let Some(id) = latest.lines().next()
    {
        let file = repo
            .join("deployments")
            .join(identity(id)?)
            .join("deployment.json");
        if file.is_file() {
            let record = io::read(&file)?;
            let revision: GitRevision = record["candidate_commit"]
                .as_str()
                .context("latest deployment has no candidate commit")?
                .parse()?;
            current(&repo, &revision)?;
            io::commit(
                &repo,
                &format!("record current config from deployment {id}"),
                "Airlock Config Vault",
                "airlock-config-vault@localhost",
            )?;
            return Ok(());
        }
    }
    let temporary = tempfile::tempdir()?;
    let initial = temporary.path().join("initial");
    workspace::seed(config, &initial)?;
    let inputs = io::path("AIRLOCK_CONFIG_INPUTS_PATH", &config.public_inputs);
    workspace::relocate(config, &initial, &inputs)?;
    io::run(
        Command::new("git")
            .args(["init", "-b", "main"])
            .arg(&initial),
    )?;
    io::git(&initial, &["add", "."])?;
    if workspace::ready(&inputs) {
        workspace::lock(config, &initial)?;
        io::git(&initial, &["add", "flake.lock"])?;
    }
    io::commit(
        &initial,
        "init airlock config candidate",
        "Airlock Initial Runtime Config",
        "airlock-initial-runtime-config@localhost",
    )?;
    let revision: GitRevision = io::git(&initial, &["rev-parse", "HEAD"])?.parse()?;
    let archive = repo.join("candidates").join(revision.as_str());
    fs::create_dir_all(&archive)?;
    io::git(
        &initial,
        &[
            "bundle",
            "create",
            archive.join("config.bundle").to_str().unwrap(),
            "HEAD",
            "refs/heads/main",
        ],
    )?;
    io::save(
        &archive.join("manifest.json"),
        &json!({"schema":"airlock.config-candidate.v1","commit":revision,"branch":"main","source_role":"sys-config-vault","source":"initial-runtime-config"}),
    )?;
    // Archive committed files only; authoring outputs must not enter the vault snapshot.
    let snapshot = archive.join("snapshot");
    fs::create_dir_all(&snapshot)?;
    let source = io::run(Command::new("git").arg("-C").arg(&initial).args([
        "archive",
        "--format=tar",
        "HEAD",
    ]))?;
    tar::Archive::new(source.as_slice()).unpack(&snapshot)?;
    io::save(
        &archive.join("metadata.json"),
        &json!({"schema":"airlock.config-vault-current.v1","status":"current","candidate_commit":revision,"branch":"main","source":"initial-runtime-config","snapshot":snapshot,"bundle":archive.join("config.bundle")}),
    )?;
    fs::write(repo.join("latest-candidate"), format!("{revision}\n"))?;
    current(&repo, &revision)?;
    io::git(
        &repo,
        &["add", &format!("candidates/{revision}"), "latest-candidate"],
    )?;
    io::commit(
        &repo,
        &format!("initialize current config baseline {revision}"),
        "Airlock Config Vault",
        "airlock-config-vault@localhost",
    )?;
    Ok(())
}

/// Export the current candidate selected by deployment evidence, falling back to current/candidate pointers.
pub(super) fn export(config: &Config) -> Result<()> {
    init(config)?;
    let repo = io::path("AIRLOCK_CONFIG_ARCHIVE_PATH", &config.archive);
    let mut selected = None;
    if let Ok(latest) = fs::read_to_string(repo.join("latest-deployment"))
        && let Some(id) = latest.lines().next()
    {
        let record = repo
            .join("deployments")
            .join(identity(id)?)
            .join("deployment.json");
        if record.is_file() {
            selected = io::read(&record)?["candidate_commit"]
                .as_str()
                .filter(|value| !value.is_empty() && *value != "null")
                .map(str::to_owned);
        }
    }
    for pointer in ["latest-current", "latest-candidate"] {
        if selected.is_none() {
            selected = fs::read_to_string(repo.join(pointer))
                .ok()
                .and_then(|value| value.lines().next().map(str::to_owned));
        }
    }
    let selected: GitRevision = selected
        .context("vault has no current candidate")?
        .parse()?;
    let directory = repo.join("candidates").join(selected.as_str());
    let manifest = io::read(&directory.join("manifest.json"))?;
    ensure!(
        manifest["schema"] == "airlock.config-candidate.v1"
            && manifest["commit"] == selected.as_str(),
        "current config manifest does not match selected candidate"
    );
    io::export(&directory, &["config.bundle", "manifest.json"])
}

/// Archive one validated candidate as inert source, without running its authoring or evaluation code.
pub(super) fn candidate(config: &Config) -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let archive = io::receive(temporary.path())?;
    io::unpack(&archive, temporary.path(), CANDIDATE, &CANDIDATE[..5])?;
    let (revision, _) = io::bundle(temporary.path())?;
    let validation: ValidationRecord = airlock_nix_core::state::read_json(
        &temporary.path().join("validation.json"),
        16 * 1024 * 1024,
    )?;
    let source = SubmittedConfiguration {
        commit: revision.clone(),
        bundle: file_hash(&temporary.path().join("config.bundle"))?,
        manifest: file_hash(&temporary.path().join("manifest.json"))?,
    };
    let prepared = temporary.path().join("prepared-source.tar");
    let _validated = ValidatedConfiguration::check(
        &source,
        validation,
        CandidateDocuments::read(temporary.path())?,
        CandidateFiles {
            bundle_commit: revision.clone(),
            bundle: source.bundle.clone(),
            prepared: if prepared.exists() {
                Some(file_hash(&prepared)?)
            } else {
                None
            },
        },
    )?;
    let snapshot = temporary.path().join("snapshot");
    io::clone(temporary.path(), &snapshot, &revision)?;
    fs::remove_dir_all(snapshot.join(".git"))?;
    let repo = io::path("AIRLOCK_CONFIG_ARCHIVE_PATH", &config.archive);
    if !repo.join(".git").is_dir() {
        init(config)?;
    }
    let destination = repo.join("candidates").join(revision.as_str());
    fs::create_dir_all(&destination)?;
    for file in CANDIDATE.iter().chain(
        [
            "bundle-verify.log",
            "snapshot-git-clone.log",
            "snapshot-git-checkout.log",
        ]
        .iter(),
    ) {
        if temporary.path().join(file).is_file() {
            fs::copy(temporary.path().join(file), destination.join(file))?;
        }
    }
    let target = destination.join("snapshot");
    if target.exists() {
        fs::remove_dir_all(&target)?;
    }
    io::run(Command::new("cp").arg("-a").arg(snapshot).arg(&target))?;
    io::save(
        &destination.join("metadata.json"),
        &json!({"schema":"airlock.config-candidate-archive-record.v1","candidate_commit":revision,"manifest_schema":"airlock.config-candidate.v1","validation_schema":"airlock.config-validation.v2","system_schema":"airlock.system.v1","snapshot":target,"topology":destination.join("topology.json"),"system":destination.join("system.json"),"archived_by":"dom0"}),
    )?;
    fs::write(repo.join("latest-candidate"), format!("{revision}\n"))?;
    io::git(
        &repo,
        &["add", &format!("candidates/{revision}"), "latest-candidate"],
    )?;
    let changed = io::commit(
        &repo,
        &format!("archive candidate {revision}"),
        "Airlock dom0 archive",
        "airlock-dom0@localhost",
    )?;
    println!(
        "{receipt}",
        receipt = json!({"schema":"airlock.config-vault-archive.v1","status":"passed","archive_status":if changed {"archived"} else {"current"},"candidate_commit":revision,"vault_commit":io::git(&repo, &["rev-parse","HEAD"])?,"archive_repo":repo})
    );
    Ok(())
}

/// Archive one deployment attempt, validating every required document and its shared candidate identity.
pub(super) fn deployment(config: &Config) -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let archive = io::receive(temporary.path())?;
    let mut allowed = DOCUMENTS
        .iter()
        .map(|(name, _)| (*name).to_owned())
        .collect::<Vec<_>>();
    allowed.extend(LOGS.iter().map(|name| format!("logs/{name}")));
    allowed.push("resolution.json".into());
    let allowed = allowed.iter().map(String::as_str).collect::<Vec<_>>();
    let required = allowed
        .iter()
        .copied()
        .filter(|name| *name != "resolution.json")
        .collect::<Vec<_>>();
    io::unpack(&archive, temporary.path(), &allowed, &required)?;
    for (file, schema) in DOCUMENTS {
        if let Some(schema) = schema {
            ensure!(
                io::read(&temporary.path().join(file))?["schema"] == *schema,
                "unsupported deployment artifact schema: {file}"
            );
        }
    }
    let validation = io::read(&temporary.path().join("validation.json"))?;
    match validation["schema"].as_str() {
        Some("airlock.config-validation.v2") => {
            let _: ValidationRecord = serde_json::from_value(validation)?;
            let _: airlock_nix_core::configuration::ResolutionRecord =
                airlock_nix_core::state::read_json(
                    &temporary.path().join("resolution.json"),
                    16 * 1024 * 1024,
                )?;
        }
        // Historical deployment archives are evidence only; this branch grants no activation authority.
        Some("airlock.config-validation.v1") => {}
        _ => anyhow::bail!("unsupported deployment validation schema"),
    }
    let record = io::read(&temporary.path().join("deployment.json"))?;
    let id = identity(
        record["deployment_id"]
            .as_str()
            .context("deployment has no identity")?,
    )?;
    let status = record["status"]
        .as_str()
        .context("deployment has no status")?;
    ensure!(
        matches!(status, "passed" | "failed"),
        "invalid deployment status"
    );
    let revision: GitRevision = record["candidate_commit"]
        .as_str()
        .context("deployment has no candidate commit")?
        .parse()?;
    for file in ["apply.json", "archive.json"] {
        ensure!(
            io::read(&temporary.path().join(file))?["candidate_commit"] == revision.as_str(),
            "deployment candidate identity mismatch: {file}"
        );
    }
    let apply = io::read(&temporary.path().join("apply.json"))?;
    ensure!(
        apply["status"] == status && apply["deployment_id"] == id,
        "apply outcome or identity differs from deployment"
    );
    for file in ["archive.json", "domain-references.json", "validation.json"] {
        ensure!(
            io::read(&temporary.path().join(file))?["status"] == "passed",
            "deployment artifact did not pass: {file}"
        );
    }
    // A failed attempt is diagnostic evidence, never a new current baseline. Keep unknown outcomes
    // distinct from success while allowing failures before a helper could publish its receipt.
    for file in ["setup.json", "system-apply.json"] {
        let outcome = io::read(&temporary.path().join(file))?;
        let outcome = outcome["status"]
            .as_str()
            .context("missing deployment artifact status")?;
        ensure!(
            outcome == "passed"
                || (status == "failed" && matches!(outcome, "failed" | "unknown" | "skipped")),
            "inconsistent deployment artifact outcome: {file}"
        );
    }
    ensure!(
        io::read(&temporary.path().join("validation.json"))?["commit"] == revision.as_str(),
        "validation commit differs from deployment"
    );
    let repo = io::path("AIRLOCK_CONFIG_ARCHIVE_PATH", &config.archive);
    if !repo.join(".git").is_dir() {
        init(config)?;
    }
    ensure!(
        repo.join("candidates").join(revision.as_str()).is_dir(),
        "deployment references missing candidate archive"
    );
    let target = repo.join("deployments").join(id);
    ensure!(!target.try_exists()?, "deployment already exists: {id}");
    fs::create_dir_all(target.join("logs"))?;
    for file in &allowed {
        let source = temporary.path().join(file);
        if *file == "resolution.json" && !source.exists() {
            continue;
        }
        fs::copy(source, target.join(file))?;
    }
    fs::write(repo.join("latest-deployment-attempt"), format!("{id}\n"))?;
    io::git(
        &repo,
        &[
            "add",
            &format!("deployments/{id}"),
            "latest-deployment-attempt",
        ],
    )?;
    if status == "passed" {
        fs::write(repo.join("latest-deployment"), format!("{id}\n"))?;
        current(&repo, &revision)?;
        io::git(&repo, &["add", "latest-deployment"])?;
    }
    io::commit(
        &repo,
        &format!("record deployment {id}"),
        "Airlock dom0 archive",
        "airlock-dom0@localhost",
    )?;
    println!(
        "{receipt}",
        receipt = json!({"schema":"airlock.config-vault-deployment.v1","status":"passed","deployment_status":status,"deployment_id":id,"candidate_commit":revision,"vault_commit":io::git(&repo, &["rev-parse","HEAD"])?,"archive_repo":repo})
    );
    Ok(())
}
