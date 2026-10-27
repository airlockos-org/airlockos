//! Prepare immutable source artifacts without evaluating the machine configuration.

use crate::{
    repository,
    support::{self, git},
};
use airlock_nix_core::{
    identity::SourceIdentity, runtime::protocol::identity, store_path::StoreFile,
};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use flate2::{Compression, write::GzEncoder};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
};

#[derive(Args)]
pub(crate) struct Destination {
    // Clean machine repository; defaults to the parent's committed submodule.
    #[arg(long)]
    repository: Option<PathBuf>,
    // Archive or manifest path, published atomically after validation.
    #[arg(long)]
    output: PathBuf,
}

#[derive(Subcommand)]
pub(crate) enum Action {
    /// Compile Rust declarations into a separate content-addressed Nix source tree.
    Prepare {
        // Durable retention name for source used across separate processes.
        #[arg(long)]
        pin: Option<String>,
    },
    /// Preview obsolete prepared source trees; pass --apply to remove them.
    Prune {
        // Recently used disposable snapshots to retain in addition to pins and active operations.
        #[arg(long, default_value_t = 3)]
        keep: usize,
        // Remove the reported candidates. Without this flag, only report sizes and paths.
        #[arg(long)]
        apply: bool,
    },
    /// Protect a prepared tree from pruning under a durable retention name.
    Pin {
        // Existing content-addressed directory inside the configured preparation cache.
        tree: PathBuf,
        // Human-readable deployment, validation or other retention identity.
        name: String,
    },
    /// Release a retention pin without deleting its prepared tree.
    Unpin {
        // Previously assigned retention identity.
        name: String,
    },
    /// Bundle committed source history for import into usr-assistant.
    Create(Destination),
    /// Create a shallow committed checkout for first boot in an image.
    Seed {
        // Source checkout and archive destination.
        #[command(flatten)]
        destination: Destination,
        // Reuse only an archive matching both its source identity and checksum.
        #[arg(long)]
        reuse: bool,
    },
    /// Bind Nix flake archive JSON from stdin to the committed dependency lock.
    OfflineInputs(Destination),
    /// Create and stream a source bundle to the installed usr-assistant importer.
    Push {
        // SSH host for the user-facing assistant VM.
        #[arg(long)]
        target: String,
        // Optional durable copy of the exact bundle sent.
        #[arg(long)]
        output: Option<PathBuf>,
        // Clean machine checkout; defaults to the parent's pinned submodule.
        #[arg(long)]
        repository: Option<PathBuf>,
    },
}

fn selected(root: &Path, explicit: Option<&Path>) -> Result<PathBuf> {
    match explicit {
        Some(path) => Ok(fs::canonicalize(path)?),
        None => Ok(repository::local(root)?.0),
    }
}

fn report(source: &SourceIdentity, output: &Path) -> Value {
    json!({"revision":source.revision,"lock_hash":source.lock_hash,"archive":output})
}

pub(crate) fn bundle(repo: &Path, destination: &Path) -> Result<SourceIdentity> {
    let temporary = tempfile::tempdir()?;
    let (identity, mut archive) =
        airlock_nix_core::runtime::source::source_archive(repo, temporary.path())?;

    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut output = tempfile::NamedTempFile::new_in(parent)?;
    std::io::copy(&mut archive, &mut output)?;
    output.as_file().sync_all()?;
    output.persist(destination)?;
    File::open(parent)?.sync_all()?;

    Ok(identity)
}

fn seed(repo: &Path, destination: &Path, reuse: bool) -> Result<Value> {
    let source = identity(repo)?;
    ensure!(
        git(repo, &["submodule", "status", "--recursive"])?.is_empty(),
        "source seeds with submodules are unsupported"
    );
    let receipt = destination.with_file_name(format!(
        "{}.identity.json",
        destination
            .file_name()
            .context("seed filename")?
            .to_string_lossy()
    ));
    if reuse
        && let Ok(saved) = support::json(&receipt)
        && saved["source"] == serde_json::to_value(&source)?
        && support::hash(destination).is_ok_and(|hash| saved["sha256"] == hash)
    {
        ensure!(
            identity(repo)? == source,
            "machine source changed while checking seed reuse"
        );
        return Ok(report(&source, destination));
    }

    let temporary = tempfile::tempdir()?;
    let checkout = temporary.path().join("repo");
    support::output(
        Command::new("git")
            .args(["clone", "--depth", "1", "--"])
            .arg(repository::file_uri(repo)?)
            .arg(&checkout),
    )?;
    ensure!(
        identity(&checkout)? == source
            && git(&checkout, &["rev-parse", "--is-shallow-repository"])? == "true",
        "shallow seed revision differs from source"
    );
    let manifest = json!({"schema":"airlock.sys-agent-machine-seed.v1","revision":source.revision,"lock_hash":source.lock_hash});

    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut output = tempfile::NamedTempFile::new_in(parent)?;
    {
        let gzip = GzEncoder::new(output.as_file_mut(), Compression::fast());
        let mut archive = tar::Builder::new(gzip);
        archive.follow_symlinks(false);
        archive.append_dir_all("repo", &checkout)?;
        let bytes = serde_json::to_vec(&manifest)?;
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        archive.append_data(&mut header, "manifest.json", bytes.as_slice())?;
        archive.into_inner()?.finish()?.flush()?;
    }
    ensure!(
        identity(repo)? == source,
        "machine source changed while preparing seed"
    );
    output.as_file().sync_all()?;
    output.persist(destination)?;
    File::open(parent)?.sync_all()?;
    support::record(
        &receipt,
        &json!({"schema":"airlock.source-seed-receipt.v1","source":source,"sha256":support::hash(destination)?}),
    )?;

    Ok(report(&source, destination))
}

fn store_path(value: &str) -> Result<()> {
    if value
        .parse::<airlock_nix_core::store_path::StorePath>()
        .is_err()
    {
        let _: StoreFile = value.parse()?;
    }
    Ok(())
}

fn relative(parent: &str, relative: &str) -> Result<String> {
    ensure!(
        relative.starts_with("./"),
        "archived input lacks a store path"
    );
    let root = parent.split('/').take(4).collect::<Vec<_>>().join("/");
    let mut path = PathBuf::from(parent);
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(value) => path.push(value),
            Component::CurDir => {}
            Component::ParentDir => {
                ensure!(
                    path != Path::new(&root) && path.pop(),
                    "local input escapes archived source"
                );
            }
            _ => anyhow::bail!("invalid local input path"),
        }
    }
    ensure!(
        path.starts_with(&root) && path != Path::new(&root),
        "local input escapes archived source"
    );
    Ok(path
        .to_str()
        .context("non-UTF-8 archived source")?
        .to_owned())
}

fn collect(
    nodes: &Value,
    archived: &Value,
    parent: &str,
    node_id: &str,
    prefix: &str,
    output: &mut BTreeMap<String, String>,
    depth: usize,
) -> Result<()> {
    ensure!(
        depth <= 64 && output.len() < 10000,
        "archived input graph exceeds limit"
    );

    for (name, node) in archived.as_object().context("invalid archived inputs")? {
        ensure!(
            node.is_object()
                && !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
            "invalid archived input: {name}"
        );
        let key = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let id = nodes[node_id]["inputs"][name]
            .as_str()
            .context("unexpected followed archived input")?;
        let mut path = match node.get("path") {
            Some(value) => value
                .as_str()
                .context("archived input lacks a store path")?
                .to_owned(),
            None => relative(
                parent,
                nodes[id]["locked"]["path"]
                    .as_str()
                    .context("archived input lacks a store path")?,
            )?,
        };
        store_path(&path)?;
        if let Some(directory) = nodes[id]["locked"].get("dir") {
            let directory = directory
                .as_str()
                .context("invalid archived flake directory")?;
            ensure!(
                directory.is_empty()
                    || directory
                        .split('/')
                        .all(|s| !matches!(s, "" | "." | "..") && !s.chars().any(char::is_control)),
                "invalid archived flake directory"
            );
            if !directory.is_empty() {
                path.push('/');
                path.push_str(directory);
            }
        }
        store_path(&path)?;
        output.insert(key.clone(), path.clone());
        if let Some(children) = node.get("inputs") {
            collect(nodes, children, &path, id, &key, output, depth + 1)?;
        }
    }
    Ok(())
}

fn offline(repo: &Path, destination: &Path) -> Result<Value> {
    let source = identity(repo)?;
    let lock = support::json(&repo.join("flake.lock"))?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(32 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 32 * 1024 * 1024,
        "flake archive JSON exceeds limit"
    );
    let archive: Value = airlock_nix_core::runtime::decode(&bytes)?;
    let root = archive["path"]
        .as_str()
        .context("machine flake archive lacks a store path")?;
    let _: airlock_nix_core::store_path::StorePath = root.parse()?;

    let mut inputs = BTreeMap::new();
    collect(
        &lock["nodes"],
        &archive["inputs"],
        root,
        lock["root"].as_str().context("flake lock root")?,
        "",
        &mut inputs,
        0,
    )?;
    ensure!(!inputs.is_empty(), "machine flake archive has no inputs");
    ensure!(
        identity(repo)? == source,
        "machine source changed while preparing offline inputs"
    );

    support::record(
        destination,
        &json!({"schema":"airlock.sys-agent-offline-inputs.v1","revision":source.revision,"lock_hash":source.lock_hash,"inputs":inputs}),
    )?;
    Ok(json!({"manifest":destination,"inputs":inputs.len()}))
}

pub(crate) fn push(
    root: &Path,
    target: &str,
    repo: Option<&Path>,
    destination: Option<&Path>,
) -> Result<Value> {
    crate::transport::target(target)?;
    let repo = selected(root, repo)?;
    let temporary = tempfile::tempdir()?;
    let archive = destination
        .map(Path::to_owned)
        .unwrap_or_else(|| temporary.path().join("source.tar.gz"));
    let source = bundle(&repo, &archive)?;
    let importer = std::env::var("AIRLOCK_DEPLOY_SOURCE_COMMAND")
        .unwrap_or_else(|_| "airlock-usr-assistant-machine-source".into());
    let script = support::join(&[
        &importer,
        "import",
        "--revision",
        source.revision.as_str(),
        "--lock-hash",
        source.lock_hash.as_str(),
    ]);

    let result = Command::new("ssh")
        .arg("--")
        .arg(target)
        .arg(script)
        .stdin(Stdio::from(File::open(&archive)?))
        .status()?;
    ensure!(
        result.success(),
        "usr-assistant import failed with exit code {:?}",
        result.code()
    );
    Ok(report(&source, &archive))
}

pub(crate) fn execute(root: &Path, action: Action) -> Result<()> {
    let result = match action {
        Action::Prepare { pin } => {
            let (tree, _lease) = repository::prepare_leased(root)?;
            if let Some(name) = pin {
                airlock_config::preparation::cache::pin(
                    &repository::prepared_cache(root),
                    &tree,
                    &name,
                )
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            }

            json!({"source": tree, "flake": format!("path:{path}", path = tree.display())})
        }
        Action::Prune { keep, apply } => serde_json::to_value(
            airlock_config::preparation::cache::prune(
                &repository::prepared_cache(root),
                keep,
                apply,
            )
            .map_err(|error| anyhow::anyhow!("{error}"))?,
        )?,
        Action::Pin { tree, name } => {
            airlock_config::preparation::cache::pin(
                &repository::prepared_cache(root),
                &tree,
                &name,
            )
            .map_err(|error| anyhow::anyhow!("{error}"))?;
            json!({"pin": name, "source": tree})
        }
        Action::Unpin { name } => {
            airlock_config::preparation::cache::unpin(&repository::prepared_cache(root), &name)
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            json!({"released": name})
        }
        Action::Create(dest) => {
            let repo = selected(root, dest.repository.as_deref())?;
            let source = bundle(&repo, &dest.output)?;
            report(&source, &dest.output)
        }
        Action::Seed {
            destination: dest,
            reuse,
        } => seed(
            &selected(root, dest.repository.as_deref())?,
            &dest.output,
            reuse,
        )?,
        Action::OfflineInputs(dest) => {
            offline(&selected(root, dest.repository.as_deref())?, &dest.output)?
        }
        Action::Push {
            target,
            repository,
            output,
        } => push(root, &target, repository.as_deref(), output.as_deref())?,
    };
    support::print(&result)
}
