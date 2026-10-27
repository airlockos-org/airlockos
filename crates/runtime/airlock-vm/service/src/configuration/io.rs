//! Inert archive handling and bounded helper execution for VM-local configuration protocols.

use airlock_nix_core::{identity::GitRevision, runtime::process};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

/// Hard payload budget for the existing archive-based configuration protocols.
const LIMIT: u64 = 8 * 1024 * 1024 * 1024;

/// Read a nonempty path override, retaining installed defaults without changing process-global environment.
pub(super) fn path(key: &str, fallback: &Path) -> PathBuf {
    std::env::var_os(key)
        .filter(|value| !value.is_empty())
        .map_or_else(|| fallback.to_owned(), PathBuf::from)
}

/// Read bounded, duplicate-key-free JSON from a regular protocol artifact.
pub(super) fn read(path: &Path) -> Result<Value> {
    Ok(airlock_nix_core::state::read_json(path, 16 * 1024 * 1024)?)
}

/// Replace an informational receipt atomically within its existing parent directory.
pub(super) fn save(path: &Path, value: &Value) -> Result<()> {
    let mut temporary =
        tempfile::NamedTempFile::new_in(path.parent().context("receipt directory")?)?;
    serde_json::to_writer_pretty(&mut temporary, value)?;
    writeln!(temporary)?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

/// Run a bounded local tool, keeping diagnostics off binary protocol stdout.
pub(super) fn run(command: &mut Command) -> Result<Vec<u8>> {
    Ok(
        process::run(command, None, Some(Duration::from_secs(3600)))?
            .checked("configuration helper")?,
    )
}

/// Run one Git command under an explicit repository path without changing this process's cwd.
pub(super) fn git(repo: &Path, args: &[&str]) -> Result<String> {
    let output = run(Command::new("git").arg("-C").arg(repo).args(args))?;
    Ok(String::from_utf8(output)?.trim_end_matches('\n').into())
}

/// Commit only staged changes, retaining the caller's existing vault/staging identity.
pub(super) fn commit(repo: &Path, message: &str, name: &str, email: &str) -> Result<bool> {
    let output = process::run(
        Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["diff", "--cached", "--quiet"]),
        None,
        Some(Duration::from_secs(60)),
    )?;
    match output.status.code() {
        Some(0) => Ok(false),
        Some(1) => {
            git(
                repo,
                &[
                    "-c",
                    &format!("user.name={name}"),
                    "-c",
                    &format!("user.email={email}"),
                    "commit",
                    "-m",
                    message,
                ],
            )?;
            Ok(true)
        }
        _ => {
            output.checked("git staged diff")?;
            anyhow::bail!("unexpected staged diff status")
        }
    }
}

/// Receive a bounded archive into owned temporary storage before inspecting any paths.
pub(super) fn receive(directory: &Path) -> Result<PathBuf> {
    let archive = directory.join("received.tar");
    let copied = std::io::copy(
        &mut std::io::stdin().lock().take(LIMIT + 1),
        &mut File::create(&archive)?,
    )?;
    ensure!(
        copied <= LIMIT,
        "configuration input archive exceeds its limit"
    );
    Ok(archive)
}

/// Extract only enumerated regular-file members, rejecting duplicate names and links.
pub(super) fn unpack(
    archive: &Path,
    directory: &Path,
    allowed: &[&str],
    required: &[&str],
) -> Result<()> {
    let mut archive = tar::Archive::new(File::open(archive)?);
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let member = entry.path()?.into_owned();
        let member = member
            .to_str()
            .context("non-UTF-8 configuration archive member")?;
        // A parent directory entry is unnecessary; callers create enumerated parents themselves.
        ensure!(
            allowed.contains(&member),
            "unexpected configuration tar member: {member}"
        );
        ensure!(
            seen.insert(member.to_owned()) && entry.header().entry_type().is_file(),
            "duplicate or non-regular configuration tar member: {member}"
        );
        total = total
            .checked_add(entry.size())
            .context("configuration archive size overflow")?;
        ensure!(
            total <= LIMIT,
            "configuration archive contents exceed their limit"
        );
        let path = directory.join(member);
        fs::create_dir_all(path.parent().context("archive member parent")?)?;
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        std::io::copy(&mut entry, &mut output)?;
    }
    ensure!(
        required.iter().all(|member| seen.contains(*member)),
        "configuration tar is missing required members"
    );
    Ok(())
}

/// Send only the fixed selected member set as a binary protocol response.
pub(super) fn export(directory: &Path, members: &[&str]) -> Result<()> {
    let mut archive = tar::Builder::new(std::io::stdout().lock());
    for member in members {
        archive.append_path_with_name(directory.join(member), member)?;
    }
    archive.finish()?;
    Ok(())
}

/// Verify a bundle independently of any staging/vault repository and bind it to the manifest commit.
pub(super) fn bundle(directory: &Path) -> Result<(GitRevision, Value)> {
    let manifest = read(&directory.join("manifest.json"))?;
    ensure!(
        manifest["schema"] == "airlock.config-candidate.v1",
        "unsupported candidate manifest schema"
    );
    let commit: GitRevision = manifest["commit"]
        .as_str()
        .context("candidate manifest has no commit")?
        .parse()?;
    let repo = directory.join("verify.git");
    run(Command::new("git")
        .args(["init", "--bare", "-b", "main"])
        .arg(&repo))?;
    let bundle = directory.join("config.bundle");
    let verification = git(
        &repo,
        &[
            "bundle",
            "verify",
            bundle.to_str().context("candidate bundle path")?,
        ],
    )?;
    fs::write(directory.join("bundle-verify.log"), verification)?;
    let heads = git(&repo, &["bundle", "list-heads", bundle.to_str().unwrap()])?;
    ensure!(
        heads.split_whitespace().next() == Some(commit.as_str()),
        "candidate bundle commit does not match manifest commit"
    );
    Ok((commit, manifest))
}

/// Clone the selected revision and return its exact source tree for observation or archival.
pub(super) fn clone(directory: &Path, target: &Path, commit: &GitRevision) -> Result<()> {
    let output = run(Command::new("git")
        .arg("clone")
        .arg(directory.join("config.bundle"))
        .arg(target))?;
    fs::write(directory.join("snapshot-git-clone.log"), output)?;
    let output = git(target, &["checkout", "--detach", commit.as_str()])?;
    fs::write(directory.join("snapshot-git-checkout.log"), output)?;
    Ok(())
}

/// Run a file-backed import without buffering its NAR input or allowing unbounded diagnostics.
/// The existing common child guard owns and reaps the direct upstream helper on every outcome.
pub(super) fn files(
    command: &mut Command,
    input: &Path,
    output: &Path,
    errors: &Path,
) -> Result<()> {
    use std::{process::Stdio, time::Instant};
    let output = File::create(output)?;
    let errors = File::create(errors)?;
    command
        .stdin(Stdio::from(File::open(input)?))
        .stdout(Stdio::from(output.try_clone()?))
        .stderr(Stdio::from(errors.try_clone()?));
    let mut child = process::OwnedChild(command.spawn()?);
    let deadline = Instant::now() + Duration::from_secs(3600);
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        ensure!(Instant::now() < deadline, "configuration import timed out");
        ensure!(
            output.metadata()?.len() <= 32 * 1024 * 1024
                && errors.metadata()?.len() <= 32 * 1024 * 1024,
            "configuration import output exceeded its limit"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    ensure!(status.success(), "configuration import failed: {status}");
    ensure!(
        output.metadata()?.len() <= 32 * 1024 * 1024
            && errors.metadata()?.len() <= 32 * 1024 * 1024,
        "configuration import output exceeded its limit"
    );
    Ok(())
}
