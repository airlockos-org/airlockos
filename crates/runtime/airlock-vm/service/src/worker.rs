//! Machine-source import and builds inside the existing private Qubes worker store.

use airlock_nix_core::{
    admission::AdmissionReceipt,
    identity::{GitRevision, GuestName, SourceIdentity},
    root_artifact::RootDescriptor,
    runtime::process,
    store_path::{StoreArtifact, StoreFile, StorePath},
};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use flate2::read::GzDecoder;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

/// Installed worker paths, supplied by machine configuration rather than remote payloads.
#[derive(Args)]
pub(crate) struct Request {
    /// Default machine checkout, with the existing explicit environment override retained.
    #[arg(long)]
    repo: PathBuf,
    /// Default build/admission evidence directory.
    #[arg(long)]
    state: PathBuf,
    /// Persistent private source-import scratch directory.
    #[arg(long)]
    cache: PathBuf,
    /// Default private Nix root for builds.
    #[arg(long)]
    store: PathBuf,
    /// Worker operation selected by the existing local command or qrexec endpoint.
    #[command(subcommand)]
    action: Action,
    /// Installed pinned-input manifest; tests can supply an isolated file.
    #[arg(
        long,
        default_value = "/run/airlock-builder/pool/.airlock-builder/flake-inputs.json"
    )]
    offline_inputs: PathBuf,
    /// Immutable image-built compiler with checked source inputs; mismatches fall back to Cargo.
    #[arg(
        long,
        default_value = "/etc/airlock/authoring/compiler/airlock-machine-config"
    )]
    compiler: PathBuf,
}

#[derive(Subcommand)]
enum Action {
    /// Read or import the committed machine checkout.
    Source {
        /// Read-only status or explicit archive import.
        #[command(subcommand)]
        action: Source,
    },
    /// Seed an absent checkout from an immutable, admitted shallow-repository archive.
    Seed {
        /// Immutable package containing the machine seed.
        #[arg(long)]
        archive: PathBuf,
        /// Configured checkout owner.
        #[arg(long)]
        user: String,
        /// Configured checkout group, normally the Qubes users group.
        #[arg(long, default_value = "users")]
        group: String,
    },
    /// Check build prerequisites, build a system, or submit an inactive retained generation.
    Build {
        /// Explicit build/admission operation.
        #[command(subcommand)]
        action: BuildAction,
    },
}

#[derive(Subcommand)]
enum Source {
    /// Report committed identity, seed metadata and dirty paths.
    Status,
    /// Validate an incoming bundle and replace only a clean existing checkout.
    Import {
        /// Expected full source commit supplied by the source transfer contract.
        #[arg(long)]
        revision: String,
        /// Expected SHA-256 of the checkout's locked flake inputs.
        #[arg(long)]
        lock_hash: String,
    },
}

#[derive(Subcommand)]
enum BuildAction {
    /// Check clean source, disk capacity and locked input availability.
    Preflight {
        /// Require the image's exact pinned offline inputs.
        #[arg(long)]
        offline: bool,
    },
    /// Build only the selected system without activating it.
    Build {
        /// Require the image's exact pinned offline inputs.
        #[arg(long)]
        offline: bool,
        /// Local flake installable, restricted to the prepared source.
        installable: Option<String>,
    },
    /// Submit the built closure as a retained inactive generation under existing admission policy.
    Admit {
        /// Require the image's exact pinned offline inputs.
        #[arg(long)]
        offline: bool,
        /// Exact target VM for admission; this command cannot activate it.
        target: String,
        /// Local flake installable, restricted to the prepared source.
        installable: Option<String>,
    },
}

/// Execute one bounded worker helper; failed builds never become installable strings.
fn text(command: &mut Command) -> Result<String> {
    let output = process::run(command, None, Some(Duration::from_secs(14400)))?;
    if !output.status.success() {
        eprint!(
            "{diagnostic}",
            diagnostic = String::from_utf8_lossy(&output.stderr)
        );
        return Err(crate::HelperExit {
            code: output
                .status
                .code()
                .and_then(|code| u8::try_from(code).ok())
                .unwrap_or(1),
        }
        .into());
    }
    Ok(String::from_utf8(output.stdout)?
        .trim_end_matches('\n')
        .into())
}

/// Run Git without changing the service's own working directory.
fn git(repo: &Path, args: &[&str]) -> Result<String> {
    text(Command::new("git").arg("-C").arg(repo).args(args))
}

/// Hash a regular locked-input file incrementally.
fn hash(path: &Path) -> Result<String> {
    let mut digest = Sha256::new();
    let mut file = File::open(path)?;
    let mut bytes = [0; 65536];
    loop {
        let count = file.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        digest.update(&bytes[..count]);
    }
    Ok(format!("{digest:x}", digest = digest.finalize()))
}

/// Read duplicate-key-free structured protocol input under the existing record limit.
fn read(path: &Path) -> Result<Value> {
    Ok(airlock_nix_core::state::read_json(path, 16 * 1024 * 1024)?)
}

/// Create private state without broadening permissions on an existing parent directory.
fn private(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Report imported source identity without treating a missing checkout as an error.
fn status(repo: &Path) -> Result<Value> {
    if !repo.join(".git").is_dir() {
        return Ok(
            json!({"schema":"airlock.sys-agent-machine-source-status.v1","present":false,"repo":repo}),
        );
    }
    Ok(
        json!({"schema":"airlock.sys-agent-machine-source-status.v1","present":true,"repo":repo,"revision":git(repo,&["rev-parse","HEAD"])?,"lock_hash":hash(&repo.join("flake.lock"))?,"seed_revision":git(repo,&["config","--get","airlock.seedRevision"]).unwrap_or_default(),"seed_lock_hash":git(repo,&["config","--get","airlock.seedLockHash"]).unwrap_or_default(),"dirty_paths":git(repo,&["status","--porcelain"])?.lines().count()}),
    )
}

/// Require the exact repository root and a clean checkout before replacing source or building.
fn clean(repo: &Path) -> Result<()> {
    ensure!(
        repo.is_dir()
            && Path::new(&git(repo, &["rev-parse", "--show-toplevel"])?) == fs::canonicalize(repo)?,
        "missing Git checkout or wrong repository root"
    );
    ensure!(
        repo.join("flake.lock").is_file(),
        "checkout is missing flake.lock"
    );
    ensure!(
        git(repo, &["status", "--porcelain"])?.is_empty(),
        "checkout has local edits; commit or stash them first"
    );
    Ok(())
}

/// Bind archive metadata and bundle contents before touching the existing checkout.
fn import(request: &Request, revision: &str, lock: &str) -> Result<Value> {
    ensure!(
        (40..=64).contains(&revision.len())
            && revision
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid source revision"
    );
    ensure!(
        lock.len() == 64
            && lock
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid lock hash"
    );
    private(&request.cache)?;
    private(&request.state)?;
    fs::create_dir_all(request.repo.parent().context("checkout parent")?)?;
    let temporary = tempfile::Builder::new()
        .prefix("import.")
        .tempdir_in(&request.cache)?;
    let archive_path = temporary.path().join("source.tar.gz");
    let copied = std::io::copy(
        &mut std::io::stdin().lock().take(8 * 1024 * 1024 * 1024 + 1),
        &mut File::create(&archive_path)?,
    )?;
    ensure!(
        copied > 0 && copied <= 8 * 1024 * 1024 * 1024,
        "source archive is empty or exceeds size limit"
    );
    let mut archive = tar::Archive::new(GzDecoder::new(File::open(&archive_path)?));
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let name = entry.path()?.into_owned();
        let spelling = name.to_str().context("archive path is not UTF-8")?;
        ensure!(
            spelling == "manifest.json"
                || spelling == "repo.bundle"
                || (spelling.starts_with("submodules/")
                    && spelling.ends_with(".bundle")
                    && name
                        .components()
                        .all(|component| matches!(component, std::path::Component::Normal(_)))),
            "unexpected source archive member"
        );
        ensure!(
            entry.header().entry_type().is_file() && seen.insert(name.clone()),
            "non-regular or duplicate source archive member"
        );
        total = total
            .checked_add(entry.size())
            .context("source archive size overflow")?;
        ensure!(
            total <= 8 * 1024 * 1024 * 1024,
            "source archive decoded size exceeds limit"
        );
        let target = temporary.path().join(name);
        fs::create_dir_all(target.parent().unwrap())?;
        std::io::copy(&mut entry, &mut File::create(target)?)?;
    }
    let manifest = read(&temporary.path().join("manifest.json"))?;
    ensure!(
        manifest["schema"] == "airlock.sys-agent-machine-source.v1"
            && manifest["revision"] == revision
            && manifest["lock_hash"] == lock,
        "archive identity differs from requested source"
    );
    ensure!(
        manifest["submodules"].as_array().is_none_or(Vec::is_empty),
        "source submodules are not supported by this image"
    );
    let staged = temporary.path().join("repo");
    let bundle = temporary.path().join("repo.bundle");
    let shallow: Vec<GitRevision> = manifest
        .get("shallow")
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()
        .context("invalid shallow source boundaries")?
        .unwrap_or_default();
    ensure!(
        shallow.iter().collect::<BTreeSet<_>>().len() == shallow.len(),
        "duplicate shallow source boundary"
    );
    text(Command::new("git").args(["init", "--quiet"]).arg(&staged))?;

    // A bundle omits Git's shallow metadata. Install validated object IDs before
    // fetching so Git checks the supplied graph against its declared boundary.
    // Only the private staging repository receives untrusted boundary metadata.
    if !shallow.is_empty() {
        let mut contents = shallow
            .iter()
            .map(GitRevision::as_str)
            .collect::<Vec<_>>()
            .join("\n");
        contents.push('\n');
        fs::write(staged.join(".git/shallow"), contents)?;
    }
    text(
        Command::new("git")
            .arg("-C")
            .arg(&staged)
            .args(["fetch", "--no-tags"])
            .arg(&bundle)
            .arg(revision),
    )?;
    git(&staged, &["checkout", "--detach", revision])?;
    for boundary in &shallow {
        ensure!(
            git(&staged, &["cat-file", "-t", boundary.as_str()])? == "commit",
            "shallow source boundary is not a commit"
        );
        git(
            &staged,
            &["merge-base", "--is-ancestor", boundary.as_str(), revision],
        )
        .context("shallow source boundary is not reachable from requested revision")?;
    }
    git(&staged, &["fsck", "--strict", "--no-reflogs"])?;
    ensure!(
        hash(&staged.join("flake.lock"))? == lock,
        "checked-out flake.lock differs from requested lock hash"
    );
    if request.repo.symlink_metadata().is_ok() {
        clean(&request.repo)?;
        text(
            Command::new("git")
                .arg("-C")
                .arg(&request.repo)
                .args(["fetch", "--no-tags", "--update-shallow"])
                .arg(&staged)
                .arg(revision),
        )?;
        git(&request.repo, &["checkout", "--detach", revision])?;
    } else {
        fs::rename(staged, &request.repo)?;
    }
    git(&request.repo, &["config", "airlock.seedRevision", revision])?;
    git(&request.repo, &["config", "airlock.seedLockHash", lock])?;
    status(&request.repo)
}

/// Seed only an absent checkout; the admitted archive remains a trusted immutable source artifact.
fn seed(request: &Request, archive: &Path, user: &str, group: &str) -> Result<()> {
    if request.repo.symlink_metadata().is_ok() {
        return Ok(());
    }
    private(request.cache.parent().context("seed cache parent")?)?;
    private(&request.cache)?;
    fs::create_dir_all(request.repo.parent().context("seed checkout parent")?)?;
    // The root boot service may create these parents before the user has logged in.
    // Owning only the scratch child would leave a root-owned 0700 cache inaccessible.
    text(
        Command::new("chown")
            .arg(format!("{user}:{group}"))
            .arg(request.cache.parent().context("seed cache parent")?)
            .arg(&request.cache)
            .arg(request.repo.parent().context("seed checkout parent")?),
    )?;
    let temporary = tempfile::Builder::new()
        .prefix("seed.")
        .tempdir_in(&request.cache)?;
    let mut archive = tar::Archive::new(GzDecoder::new(File::open(archive)?));
    for entry in archive.entries()? {
        let mut entry = entry?;
        let name = entry.path()?.into_owned();
        ensure!(
            name == Path::new("manifest.json") || name.starts_with("repo"),
            "unexpected seed archive member"
        );
        ensure!(
            entry.unpack_in(temporary.path())?,
            "seed archive escaped its temporary directory"
        );
    }
    let repo = temporary.path().join("repo");
    let manifest = read(&temporary.path().join("manifest.json"))?;
    ensure!(
        repo.join(".git").is_dir() && manifest["schema"] == "airlock.sys-agent-machine-seed.v1",
        "invalid machine seed"
    );
    let revision = manifest["revision"]
        .as_str()
        .context("seed source revision")?;
    let lock = manifest["lock_hash"].as_str().context("seed lock hash")?;
    ensure!(
        git(&repo, &["rev-parse", "HEAD"])? == revision
            && git(&repo, &["rev-parse", "--is-shallow-repository"])? == "true"
            && hash(&repo.join("flake.lock"))? == lock,
        "seed contents differ from declared identity"
    );
    git(&repo, &["config", "airlock.seedRevision", revision])?;
    git(&repo, &["config", "airlock.seedLockHash", lock])?;
    text(
        Command::new("chown")
            .args(["-R", &format!("{user}:{group}")])
            .arg(&repo),
    )?;
    fs::rename(repo, &request.repo)?;
    Ok(())
}

/// Checked build inputs retained together so a successful preflight cannot be replaced by stale strings.
struct Prepared {
    /// Exact prepared-source reference returned by the existing authoring command.
    source: String,
    /// Optional offline override argv validated against the checkout lock hash.
    overrides: Vec<String>,
    /// Effective immutable source identity included in admission receipts.
    revision: String,
    /// Locked source-input identity included in admission receipts.
    lock: String,
    /// Free bytes in the selected writable worker filesystem.
    available: u64,
    /// Whether the pinned inputs were evaluable without network access.
    offline_ready: bool,
}

/// Construct a worker Nix invocation without shell-owned option arrays.
fn nix(action: &str, prepared: &Prepared, offline: bool) -> Command {
    let mut command = Command::new("airlock-config-nix");
    command.args([
        "--extra-experimental-features",
        "nix-command",
        "--extra-experimental-features",
        "flakes",
        action,
    ]);
    if action == "flake" {
        command.arg("metadata");
    }
    command.arg("--no-write-lock-file");
    if offline {
        command.arg("--offline");
    }
    command.args(&prepared.overrides);
    command
}

/// Validate source, capacity and pinned input availability before any build or admission.
fn preflight(request: &Request, offline: bool) -> Result<Prepared> {
    clean(&request.repo)?;
    private(&request.state)?;
    // The builder service owns the mount hierarchy. Its root stays root-owned
    // and non-writable while Nix writes through the admitted overlay backend.
    ensure!(
        request.store.is_dir(),
        "private Nix store root is missing or not a directory: {store}",
        store = request.store.display()
    );
    let stat = rustix::fs::statvfs(&request.store)?;
    let available = stat
        .f_bavail
        .checked_mul(stat.f_frsize)
        .context("worker free-space count overflow")?;
    ensure!(
        available >= 4 * 1024 * 1024 * 1024,
        "private Nix store needs at least 4 GiB free; available={available}"
    );
    let installed = if request.compiler.is_file() {
        text(
            Command::new(&request.compiler)
                .current_dir(&request.repo)
                .arg("prepare-installed")
                .arg(request.state.join("prepared")),
        )?
    } else {
        String::new()
    };
    let source = if installed.is_empty() {
        text(
            Command::new("make")
                .args(["--silent", "-C"])
                .arg(&request.repo)
                .arg("prepare")
                .arg(format!(
                    "AIRLOCK_PREPARED_CACHE={state}/prepared",
                    state = request.state.display()
                )),
        )?
    } else {
        installed
    };
    let mut prepared = Prepared {
        source,
        overrides: Vec::new(),
        revision: git(&request.repo, &["rev-parse", "HEAD"])?,
        lock: hash(&request.repo.join("flake.lock"))?,
        available,
        offline_ready: false,
    };
    if offline {
        let manifest = read(&request.offline_inputs)?;
        ensure!(
            manifest["schema"] == "airlock.sys-agent-offline-inputs.v1"
                && manifest["lock_hash"] == prepared.lock,
            "checkout flake.lock differs from the image offline inputs"
        );
        for (name, path) in manifest["inputs"]
            .as_object()
            .context("offline input map missing")?
        {
            let path = path.as_str().context("offline input is not a path")?;
            ensure!(
                path.starts_with("/nix/store/")
                    && Path::new(path)
                        .components()
                        .all(|part| !matches!(part, std::path::Component::ParentDir))
                    && request.store.join(path.trim_start_matches('/')).is_dir(),
                "missing or invalid pinned offline source: {name}"
            );
            prepared.overrides.extend([
                "--override-input".into(),
                name.into(),
                format!("path:{path}"),
            ]);
        }
        ensure!(
            !prepared.overrides.is_empty(),
            "offline input manifest is empty"
        );
    }
    let metadata = |offline| -> Result<()> {
        text(
            nix("flake", &prepared, offline)
                .arg(&prepared.source)
                .arg("--json"),
        )?;
        Ok(())
    };
    let ready = metadata(true).is_ok();
    if offline {
        ensure!(ready, "pinned flake inputs cannot be evaluated offline");
    } else {
        metadata(false)?;
    }
    prepared.offline_ready = ready;
    Ok(prepared)
}

/// Immutable build outputs required for one bootable guest generation.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestArtifacts {
    /// VM identity supplied by the selected configuration, not by the transport caller.
    domain: GuestName,
    /// NixOS system retained in the guest's runtime closure.
    system: StorePath,
    /// Immutable boot disk, transferred sparsely by the existing artifact protocol.
    root_source: StoreFile,
    /// Separate descriptor output produced alongside that disk.
    root_metadata: StoreFile,
    /// Nix-built closure inventory, retained as the generation's immutable source.
    closure_source: StoreArtifact,
    /// Qubes kernel paired with this configuration.
    kernel_name: String,
}

/// Map validated logical store identities into the worker's private build store.
fn physical(request: &Request, logical: &str) -> PathBuf {
    request.store.join(logical.trim_start_matches('/'))
}

/// Build a local prepared-source installable and optionally admit its complete closure.
fn build(request: &Request, action: &BuildAction) -> Result<()> {
    let (offline, installable, target) = match action {
        BuildAction::Preflight { offline } => (*offline, None, None),
        BuildAction::Build {
            offline,
            installable,
        } => (*offline, installable.as_deref(), None),
        BuildAction::Admit {
            offline,
            installable,
            target,
        } => (*offline, installable.as_deref(), Some(target.as_str())),
    };
    if let Some(target) = target {
        ensure!(
            !target.is_empty()
                && target
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
            "invalid admission target"
        );
    }
    let prepared = preflight(request, offline)?;
    if matches!(action, BuildAction::Preflight { .. }) {
        println!(
            "{record}",
            record = json!({"schema":"airlock.sys-agent-machine-build-preflight.v1","repo":request.repo,"revision":prepared.revision,"lock_hash":prepared.lock,"store_root":request.store,"available_bytes":prepared.available,"offline_inputs_ready":prepared.offline_ready})
        );
        return Ok(());
    }
    let installable = installable
        .unwrap_or(".#nixosConfigurations.airlock-domain-usr-home.config.system.build.toplevel");
    let suffix = installable.strip_prefix('.').unwrap_or(installable);
    ensure!(
        suffix.starts_with('#'),
        "installable must start with .# or #"
    );
    let suffix = if target.is_some() {
        let configuration = suffix
            .strip_suffix(".config.system.build.toplevel")
            .filter(|value| value.starts_with("#nixosConfigurations."))
            .context("guest admission requires a NixOS configuration toplevel")?;
        format!("{configuration}.config.system.build.airlockGuestArtifacts")
    } else {
        suffix.to_owned()
    };
    let results: Value = serde_json::from_str(&text(
        nix("build", &prepared, offline)
            .arg(format!("{source}{suffix}", source = prepared.source))
            .args(["--no-link", "--json"]),
    )?)?;
    let output: StorePath = results[0]["outputs"]["out"]
        .as_str()
        .context("build did not return an output")?
        .parse()
        .context("build returned an invalid store output")?;
    let Some(target) = target else {
        println!("{output}");
        return Ok(());
    };
    let artifacts: GuestArtifacts =
        serde_json::from_value(read(&physical(request, output.as_str()))?)
            .context("guest build did not provide complete deployment artifacts")?;
    ensure!(
        artifacts.domain.as_str() == target,
        "built guest differs from admission target"
    );
    ensure!(
        !artifacts.kernel_name.is_empty(),
        "guest build is missing its Qubes kernel identity"
    );
    let root: RootDescriptor =
        serde_json::from_value(read(&physical(request, artifacts.root_metadata.as_str()))?)
            .context("guest build is missing valid root-image metadata")?;
    root.validate()?;
    ensure!(
        physical(request, artifacts.root_source.as_str()).is_file(),
        "guest root image is missing"
    );
    let closure = physical(request, artifacts.closure_source.as_str());
    let paths = fs::read_to_string(closure.join("store-paths"))
        .context("guest build is missing its immutable closure inventory")?;
    let paths = paths
        .lines()
        .map(str::parse::<StorePath>)
        .collect::<Result<BTreeSet<_>, _>>()?;
    ensure!(
        paths.contains(&artifacts.system),
        "built system is absent from closure metadata"
    );

    let admissions = request.state.join("admissions");
    private(&admissions)?;
    let receipt: AdmissionReceipt = serde_json::from_str(&text(
        Command::new("airlock")
            .args(["artifact", "send", "--physical-store-root"])
            .arg(request.store.join("nix/store"))
            .args([
                "--nix",
                "airlock-config-nix",
                "--domain",
                target,
                "--system",
                artifacts.system.as_str(),
                "--closure-source",
                artifacts.closure_source.as_str(),
                "--root-source",
                artifacts.root_source.as_str(),
                "--kernel-name",
                &artifacts.kernel_name,
                "--source-revision",
                &prepared.revision,
                "--lock-hash",
                &prepared.lock,
            ]),
    )?)?;
    let domain: GuestName = target.parse()?;
    let expected = SourceIdentity {
        revision: prepared.revision.parse()?,
        lock_hash: prepared.lock.parse()?,
    };
    receipt.check_transfer(&domain, &expected)?;
    ensure!(
        receipt.system == artifacts.system
            && receipt.root_source == Path::new(artifacts.root_source.as_str())
            && receipt.kernel_name == artifacts.kernel_name
            && receipt.root_artifact.as_ref() == Some(&root),
        "admission receipt differs from the complete built guest artifacts"
    );
    let file = tempfile::Builder::new()
        .prefix("admission.")
        .suffix(".json")
        .tempfile_in(&admissions)?;
    let (_, path) = file.keep()?;
    let mut receipt = receipt;
    receipt
        .diagnostics
        .insert("receipt_path".into(), json!(path));
    fs::write(&path, serde_json::to_vec_pretty(&receipt)?)?;
    println!("{receipt}", receipt = serde_json::to_string(&receipt)?);
    Ok(())
}

/// Apply the existing explicit path overrides and dispatch only the requested worker operation.
pub(crate) fn execute(mut request: Request) -> Result<()> {
    for (key, path) in [
        ("AIRLOCK_MACHINE_REPO", &mut request.repo),
        ("AIRLOCK_MACHINE_BUILD_STATE", &mut request.state),
        ("AIRLOCK_CONFIG_NIX_STORE_ROOT", &mut request.store),
    ] {
        if let Some(value) = std::env::var_os(key).filter(|value| !value.is_empty()) {
            *path = value.into();
        }
    }
    match &request.action {
        Action::Source { action } => {
            let record = match action {
                Source::Status => status(&request.repo)?,
                Source::Import {
                    revision,
                    lock_hash,
                } => import(&request, revision, lock_hash)?,
            };
            println!("{record}");
        }
        Action::Seed {
            archive,
            user,
            group,
        } => seed(&request, archive, user, group)?,
        Action::Build { action } => build(&request, action)?,
    }
    Ok(())
}
