//! Preserve editable work while importing or exporting the staging role's source artifacts.

use super::{Config, io};
use anyhow::{Context, Result, ensure};
use serde_json::json;
use std::{fs, process::Command};

/// Export only a clean committed worktree, with its branch and exact commit manifest.
pub(super) fn export(config: &Config) -> Result<()> {
    let repo = io::path("AIRLOCK_CONFIG_REPO_PATH", &config.repo);
    ensure!(
        repo.join(".git").is_dir(),
        "missing Git repo; run airlock-config-staging-init first"
    );
    let dirty = io::git(&repo, &["status", "--porcelain"])?;
    ensure!(
        dirty.is_empty(),
        "config staging worktree is dirty; commit changes before export\n{dirty}"
    );
    let temporary = tempfile::tempdir()?;
    let commit = io::git(&repo, &["rev-parse", "HEAD"])?;
    let branch = io::git(&repo, &["symbolic-ref", "--short", "HEAD"])?;
    let bundle = temporary.path().join("config.bundle");
    io::git(
        &repo,
        &[
            "bundle",
            "create",
            bundle.to_str().unwrap(),
            "HEAD",
            &format!("refs/heads/{branch}"),
        ],
    )?;
    io::save(
        &temporary.path().join("manifest.json"),
        &json!({"schema":"airlock.config-candidate.v1","commit":commit,"branch":branch,"source_role":"sys-config-staging"}),
    )?;
    io::export(temporary.path(), &["config.bundle", "manifest.json"])
}

/// Import only an absent or clean unborn worktree; dirty and divergent repositories remain untouched.
pub(super) fn import(config: &Config) -> Result<()> {
    let repo = io::path("AIRLOCK_CONFIG_REPO_PATH", &config.repo);
    let temporary = tempfile::tempdir()?;
    let archive = io::receive(temporary.path())?;
    io::unpack(
        &archive,
        temporary.path(),
        &["config.bundle", "manifest.json"],
        &["config.bundle", "manifest.json"],
    )?;
    let (commit, manifest) = io::bundle(temporary.path())?;
    let branch = manifest["branch"].as_str().unwrap_or("main");
    ensure!(
        !branch.is_empty()
            && branch
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._/-".contains(&byte)),
        "invalid current config branch"
    );
    io::run(Command::new("git").args(["check-ref-format", "--branch", branch]))?;
    let mut dirty = String::new();
    let mut current = String::new();
    let mut status = "imported";
    let mut reason = "staging initialized from sys-config-vault current";
    let replace = if repo.join(".git").is_dir() {
        dirty = io::git(&repo, &["status", "--porcelain"])?;
        match io::git(&repo, &["rev-parse", "HEAD"]) {
            Ok(value) => {
                current = value;
                if current == commit.as_str() && dirty.is_empty() {
                    status = "current";
                    reason = "staging already matches sys-config-vault current";
                } else {
                    status = "skipped";
                    reason = if dirty.is_empty() {
                        "staging already has a different committed worktree"
                    } else {
                        "staging worktree is dirty; refusing to overwrite"
                    };
                }
                false
            }
            Err(_) if dirty.is_empty() => true,
            Err(_) => {
                status = "skipped";
                reason = "staging empty Git repo is dirty; refusing to overwrite";
                false
            }
        }
    } else if repo.exists() && fs::read_dir(&repo)?.next().is_some() {
        status = "skipped";
        reason = "staging path exists and is not an empty Git repository";
        false
    } else {
        true
    };
    if replace {
        let parent = repo.parent().context("staging repository parent")?;
        fs::create_dir_all(parent)?;
        let clone = tempfile::Builder::new()
            .prefix(".staging-clone-")
            .tempdir_in(parent)?;
        let target = clone.path().join("repo");
        io::clone(temporary.path(), &target, &commit)?;
        io::git(&target, &["checkout", "-B", branch, commit.as_str()])?;
        if repo.exists() {
            fs::remove_dir_all(&repo)?;
        }
        fs::rename(target, &repo)?;
        current = commit.to_string();
    }
    println!(
        "{receipt}",
        receipt = json!({"schema":"airlock.config-staging-import-current.v1","status":"passed","import_status":status,"reason":reason,"repo":repo,"current_commit":current,"candidate_commit":commit,"dirty":dirty})
    );
    Ok(())
}

/// Validate local staging through the same native export/validator commands, retaining caller-visible receipts.
pub(super) fn validate(config: &Config, contract: &std::path::Path) -> Result<()> {
    let repo = io::path("AIRLOCK_CONFIG_REPO_PATH", &config.repo);
    ensure!(
        repo.join(".git").is_dir(),
        "missing Git repo; run airlock-config-staging-init first"
    );
    let revision = io::git(&repo, &["rev-parse", "HEAD"])?;
    let dirty = io::git(&repo, &["status", "--porcelain"])?;
    let directory = io::path("AIRLOCK_CONFIG_VALIDATION_DIR", &config.validation);
    fs::create_dir_all(directory.join("logs"))?;
    let result_path = directory.join(format!("{revision}.json"));
    if !dirty.is_empty() {
        let record = json!({"schema":"airlock.config-validation.v1","status":"failed","reason":"config staging worktree is dirty; commit changes before export","validator_role":"config-staging-local","repo":repo,"commit":revision,"checks":[{"name":"git-clean","status":"failed","details":dirty},{"name":"nix-eval-airlock-topology","status":"skipped","attr":"airlock.topology"},{"name":"nix-eval-airlock-system","status":"skipped","attr":"airlock.system"},{"name":"nix-flake-check-no-build","status":"skipped"}]});
        io::save(&result_path, &record)?;
        println!("{record}");
        anyhow::bail!("config staging worktree is dirty");
    }
    let temporary = tempfile::tempdir()?;
    let staged = temporary.path().join("staged.tar");
    let validated = directory.join(format!("validated-candidate-{revision}.tar"));
    let errors = directory
        .join("logs")
        .join(format!("staging-validator-{revision}.stderr.log"));
    let executable = std::env::current_exe()?;
    io::files(
        Command::new(&executable)
            .args(["configuration", "--config"])
            .arg(contract)
            .arg("staging-export"),
        std::path::Path::new("/dev/null"),
        &staged,
        &errors,
    )?;
    let result = io::files(
        Command::new(&executable)
            .args(["configuration", "--config"])
            .arg(contract)
            .arg("validate")
            .env("AIRLOCK_CONFIG_VALIDATION_DIR", &directory),
        &staged,
        &validated,
        &errors,
    );
    if let Err(error) = result {
        if result_path.is_file() {
            println!("{record}", record = io::read(&result_path)?);
        }
        return Err(error);
    }
    let unpack = tempfile::tempdir()?;
    let members = [
        "config.bundle",
        "validation.json",
        "manifest.json",
        "topology.json",
        "system.json",
        "prepared-source.tar",
    ];
    io::unpack(&validated, unpack.path(), &members, &members[..5])?;
    let topology = directory.join(format!("topology-{revision}.json"));
    let system = directory.join(format!("system-{revision}.json"));
    fs::copy(unpack.path().join("topology.json"), &topology)?;
    fs::copy(unpack.path().join("system.json"), &system)?;
    let mut record = io::read(&unpack.path().join("validation.json"))?;
    record["repo"] = json!(repo);
    record["validated_candidate"] = json!(validated);
    record["validator_stderr"] = json!(errors);
    for check in record["checks"]
        .as_array_mut()
        .context("validation checks must be an array")?
    {
        match check["name"].as_str().unwrap_or("") {
            "nix-eval-airlock-topology" => check["output"] = json!(topology),
            "airlock-topology-json" => check["path"] = json!(topology),
            "nix-eval-airlock-system" => check["output"] = json!(system),
            "airlock-system-json" => check["path"] = json!(system),
            _ => {}
        }
    }
    io::save(&result_path, &record)?;
    println!("{record}");
    ensure!(
        record["status"] == "passed",
        "local staging validation did not pass"
    );
    Ok(())
}
