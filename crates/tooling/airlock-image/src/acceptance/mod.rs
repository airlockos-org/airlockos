//! Prove that pinned builder inputs can build small VM changes without networking.

mod change;

pub(crate) mod trial;

use change::TrialChange;

use crate::support::{atomic_json, digest, file_digest, json, output, read};
use airlock_nix_core::store_path::StorePath;
use anyhow::{Context, Result, ensure};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};

const RECEIPT_SCHEMA: &str = "airlock.offline-builder-receipt.v1";

const REPORT_SCHEMA: &str = "airlock.offline-builder-gate.v2";

/// Generated personal VM module modified only inside isolated acceptance checkouts.
pub(crate) const MODULE: &str = "generated/machine/usr-home.nix";

/// Exercise both filesystem contents and an upstream service setting without networking.
pub(crate) const SCENARIOS: [(&str, TrialChange); 2] = [
    ("etc-marker", TrialChange::EtcMarker),
    ("service-setting", TrialChange::ServiceSetting),
];

#[derive(Parser)]
#[command(
    about = "Cached offline acceptance trials using only the image's pinned inputs",
    version
)]
pub(crate) struct Args {
    // Logical closure directory containing store-paths and Nix registration.
    #[arg(long)]
    closure: PathBuf,
    // Clean committed configuration repository to exercise in temporary copies.
    #[arg(long)]
    machine: PathBuf,
    // Complete emitted machine tree, kept outside the committed source checkout.
    #[arg(long)]
    prepared_machine: PathBuf,
    // Exact pinned flake-source manifest used by the image.
    #[arg(long)]
    manifest: PathBuf,
    // Exact committed source archive supplied to the image.
    #[arg(long)]
    seed_archive: PathBuf,
    // Physical root holding the isolated Nix store, or / for the host store.
    #[arg(long)]
    source_store_root: PathBuf,
    // Logical Nix executable from the builder closure.
    #[arg(long)]
    nix_bin: PathBuf,
    // Persistent acceptance diagnostics and final machine-readable report.
    #[arg(long)]
    log_dir: PathBuf,
    // Passing receipts and immutable snapshots keyed by their input fingerprint.
    #[arg(long)]
    cache_dir: PathBuf,
    // Location for temporary, independently registered trial stores.
    #[arg(long)]
    temporary_root: PathBuf,
    // Maximum wall-clock seconds for each isolated build trial.
    #[arg(long, default_value = "1800", value_parser = clap::value_parser!(u64).range(1..))]
    timeout: u64,
    // Discard a previous receipt and prove both trials again.
    #[arg(long)]
    force: bool,
    // Optional image builder and arguments, invoked only after acceptance.
    #[arg(long, num_args = 1.., allow_hyphen_values = true)]
    image_command: Vec<OsString>,
}

#[derive(Deserialize)]
struct Manifest {
    // Source manifest format produced by the repository preparation command.
    schema: String,
    // Machine lock bytes must match before using any prepared source input.
    lock_hash: String,
    // Exact committed configuration whose source was archived.
    revision: airlock_nix_core::identity::GitRevision,
    // Flake input names mapped to paths inside the pinned store closure.
    inputs: BTreeMap<String, String>,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct TrialResult {
    // New NixOS system built without preseeded final outputs or substituters.
    system: StorePath,
    // Trial duration for diagnostics; cache validation requires a finite value.
    elapsed_seconds: f64,
}

struct Inputs {
    // Keep the closure metadata and every builder input rooted until checks and publication finish.
    _roots: tempfile::TempDir,
    // Committed machine revision, checked again before publishing evidence.
    revision: String,
    // Digest of the machine lock file used by both trials and the image.
    lock_hash: String,
    // Exact admitted object roots; no other host store objects are mounted.
    paths: BTreeSet<String>,
    // Registered Nix metadata for the admitted closure.
    registration: String,
    // Pinned flake input spellings, preserving subdirectory identities.
    sources: BTreeMap<String, String>,
    // Manifest bytes parsed above; later hashes must describe that same snapshot.
    manifest_hash: String,
    // Path-list bytes used to create the trial store, including their ordering.
    paths_hash: String,
}

pub(crate) fn physical(root: &Path, logical: &str) -> Result<PathBuf> {
    store_root(logical)?;
    ensure!(
        Path::new(logical)
            .components()
            .skip(1)
            .all(|c| matches!(c, std::path::Component::Normal(_))),
        "invalid logical store path"
    );
    Ok(root.join(logical.trim_start_matches('/')))
}

pub(crate) fn store_root(path: &str) -> Result<String> {
    let object = path
        .strip_prefix("/nix/store/")
        .context("input is outside the Nix store")?
        .split('/')
        .next()
        .context("missing store object")?;
    let root = format!("/nix/store/{object}");
    let _: StorePath = root.parse()?;
    ensure!(
        !path.split('/').skip(3).any(|part| part.is_empty()
            || part == "."
            || part == ".."
            || part.chars().any(char::is_control)),
        "invalid store source path"
    );
    Ok(root)
}

/// Select the actual source directory for both flake and raw-source inputs.
/// A `dir` query changes flake lookup but leaves a raw input's source at the repository root.
pub(crate) fn input_reference(path: &str) -> Result<String> {
    store_root(path)?;
    let mut encoded = String::new();
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || b"/-._~".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }

    Ok(format!("path:{encoded}"))
}

pub(crate) fn store_file(root: &Path, logical: &str) -> Result<PathBuf> {
    store_root(logical)?;
    let mut resolved = PathBuf::from("nix/store");
    let mut pending = std::collections::VecDeque::from(
        Path::new(logical)
            .strip_prefix("/nix/store")?
            .components()
            .map(|part| part.as_os_str().to_owned())
            .collect::<Vec<_>>(),
    );
    let mut links = 0;
    while let Some(part) = pending.pop_front() {
        if part == "." {
            continue;
        }
        if part == ".." {
            ensure!(
                resolved.pop() && resolved.starts_with("nix/store"),
                "Nix tool link escapes its store"
            );
            continue;
        }
        let candidate = root.join(&resolved).join(&part);
        let info = fs::symlink_metadata(&candidate)?;
        if info.is_symlink() {
            links += 1;
            ensure!(
                links <= 40,
                "Nix tool has too many symbolic links: {logical}"
            );
            let target = fs::read_link(&candidate)?;
            let target = if target.is_absolute() {
                store_root(target.to_str().context("non-UTF-8 tool link")?)?;
                resolved = PathBuf::from("nix/store");
                target.strip_prefix("/nix/store")?.to_owned()
            } else {
                target
            };
            for component in target.components().rev() {
                pending.push_front(component.as_os_str().to_owned());
            }
        } else {
            resolved.push(part);
        }
    }
    ensure!(
        resolved != Path::new("nix/store"),
        "Nix tool is not a store object"
    );
    Ok(root.join(resolved))
}

fn git(args: &Args, arguments: &[&str]) -> Result<String> {
    output(
        Command::new("git")
            .arg("-C")
            .arg(&args.machine)
            .args(arguments),
    )
}

/// Bind offline trials to a clean source revision and every byte in its prepared machine tree.
fn prepared_identity(args: &Args, inputs: &Inputs) -> Result<String> {
    let source = json(&args.prepared_machine.join("airlock-source.json"))?;
    ensure!(
        source["revision"] == inputs.revision && source["dirty"] == false,
        "prepared machine does not match the committed source"
    );
    ensure!(
        file_digest(&args.prepared_machine.join("flake.lock"))? == inputs.lock_hash,
        "prepared machine lock differs from committed source"
    );
    let mut files = BTreeMap::new();
    prepared_files(&args.prepared_machine, &args.prepared_machine, &mut files)?;

    Ok(digest(&serde_json::to_vec(&files)?))
}

/// Inventory prepared files without following links or capturing workstation build output.
fn prepared_files(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, String>,
) -> Result<()> {
    ensure!(
        !directory.join(".git").exists(),
        "offline trials require prepared source without Git metadata"
    );
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            prepared_files(root, &path, files)?;
        } else {
            let content = if metadata.file_type().is_symlink() {
                digest(fs::read_link(&path)?.as_os_str().as_encoded_bytes())
            } else {
                file_digest(&path)?
            };
            files.insert(
                path.strip_prefix(root)?.to_string_lossy().into_owned(),
                format!("{mode:o}:{content}", mode = metadata.mode()),
            );
        }
    }

    Ok(())
}

fn source_unchanged(args: &Args, inputs: &Inputs) -> Result<()> {
    ensure!(
        git(args, &["status", "--porcelain"])?.is_empty()
            && git(args, &["rev-parse", "HEAD"])? == inputs.revision
            && file_digest(&args.machine.join("flake.lock"))? == inputs.lock_hash,
        "machine source changed during offline acceptance"
    );
    Ok(())
}

fn inputs(args: &Args) -> Result<Inputs> {
    ensure!(
        git(args, &["status", "--porcelain"])?.is_empty(),
        "machine source must be committed before the offline gate"
    );
    let revision = git(args, &["rev-parse", "HEAD"])?;
    let lock_hash = file_digest(&args.machine.join("flake.lock"))?;
    let manifest_bytes = read(&args.manifest, 32 * 1024 * 1024)?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
    ensure!(
        manifest.revision.as_str() == revision,
        "offline input manifest differs from machine revision"
    );
    ensure!(
        manifest.schema == "airlock.sys-agent-offline-inputs.v1",
        "invalid offline input manifest"
    );
    ensure!(
        manifest.lock_hash == lock_hash,
        "offline input manifest differs from machine lock"
    );
    ensure!(
        !manifest.inputs.is_empty(),
        "offline input manifest has no inputs"
    );
    for path in manifest.inputs.values() {
        store_root(path)?;
    }

    let closure = physical(
        &args.source_store_root,
        args.closure.to_str().context("closure path is not UTF-8")?,
    )?;
    let path_bytes = read(&closure.join("store-paths"), 32 * 1024 * 1024)?;
    let paths: BTreeSet<_> = std::str::from_utf8(&path_bytes)?
        .lines()
        .map(str::to_owned)
        .collect();
    ensure!(!paths.is_empty(), "invalid builder input closure");
    for path in &paths {
        let _: StorePath = path.parse()?;
    }

    let roots = tempfile::Builder::new()
        .prefix("airlock-builder-roots-")
        .tempdir_in(&args.temporary_root)?;
    output(
        Command::new("nix-store")
            .arg("--store")
            .arg(&args.source_store_root)
            .arg("--add-root")
            .arg(roots.path().join("input"))
            .arg("--indirect")
            .arg("--realise")
            .arg(&args.closure)
            .args(&paths),
    )?;
    for path in &paths {
        ensure!(
            physical(&args.source_store_root, path)?.exists(),
            "builder input closure is incomplete after realization"
        );
    }
    for path in manifest.inputs.values() {
        ensure!(
            paths.contains(&store_root(path)?),
            "flake source is absent from builder input closure"
        );
    }
    let nix_path = args.nix_bin.to_str().context("Nix path is not UTF-8")?;
    ensure!(
        paths.contains(&store_root(nix_path)?) && nix_path.ends_with("/bin/nix"),
        "builder Nix is absent from builder input closure"
    );

    let registration = String::from_utf8(read(&closure.join("registration"), 32 * 1024 * 1024)?)?;
    Ok(Inputs {
        _roots: roots,
        revision,
        lock_hash,
        paths,
        registration,
        sources: manifest.inputs,
        manifest_hash: digest(&manifest_bytes),
        paths_hash: digest(&path_bytes),
    })
}

fn executable(name: &str) -> Result<PathBuf> {
    let paths = std::env::var_os("PATH").context("PATH unavailable")?;
    std::env::split_paths(&paths)
        .map(|directory| directory.join(name))
        .find(|p| p.is_file())
        .with_context(|| format!("{name} is unavailable"))
}

fn identity(args: &Args, inputs: &Inputs) -> Result<(Value, String)> {
    let closure = physical(
        &args.source_store_root,
        args.closure.to_str().context("closure UTF-8")?,
    )?;
    ensure!(
        file_digest(&closure.join("registration"))? == digest(inputs.registration.as_bytes()),
        "builder registration changed during offline acceptance"
    );

    ensure!(
        file_digest(&args.manifest)? == inputs.manifest_hash,
        "builder manifest changed during offline acceptance"
    );
    ensure!(
        file_digest(&closure.join("store-paths"))? == inputs.paths_hash,
        "builder path list changed during offline acceptance"
    );

    let prepared = prepared_identity(args, inputs)?;
    let hashes = json!({
        "prepared_machine": prepared,
        "seed_archive": file_digest(&args.seed_archive)?,
        "manifest": inputs.manifest_hash,
        "closure_paths": inputs.paths_hash,
        "registration": digest(inputs.registration.as_bytes()),
        "runner": file_digest(&std::env::current_exe()?)?,
        "nix_binary": file_digest(&store_file(
            &args.source_store_root, args.nix_bin.to_str().context("Nix UTF-8")?
        )?)?,
        "bwrap_binary": file_digest(&executable("bwrap")?)?,
        "image_authoring": file_digest(Path::new("crates/airlock-config/src/flakes/development.rs"))?,
        "prepared_store": file_digest(Path::new("crates/airlock-config/src/image/store.rs"))?,
    });
    let value = json!({
        "schema": RECEIPT_SCHEMA,
        "revision": inputs.revision,
        "lock_hash": inputs.lock_hash,
        "closure": args.closure,
        "nix_bin": args.nix_bin,
        "host_nix_version": output(Command::new("nix").arg("--version"))?,
        "target_system": "x86_64-linux",
        "trial_timeout_seconds": args.timeout,
        "source_store_root": fs::canonicalize(&args.source_store_root)?,
        "isolation": "bwrap-unshare-net-empty-store-no-substitutes-sandbox-v2",
        "paths": inputs.paths.len(),
        "hashes": hashes,
    });
    let fingerprint = digest(&serde_json::to_vec(&value)?);
    Ok((value, fingerprint))
}

pub(crate) fn valid_receipt(path: &Path, fingerprint: &str, identity: &Value) -> Option<Value> {
    let receipt = json(path).ok()?;
    if receipt["schema"] != RECEIPT_SCHEMA
        || receipt["fingerprint"] != fingerprint
        || receipt["status"] != "passed"
        || receipt["identity"] != *identity
    {
        return None;
    }
    let scenarios = receipt["scenarios"].as_object()?;
    let evidence = receipt["evidence"].as_object()?;
    if scenarios.len() != SCENARIOS.len() || evidence.len() != SCENARIOS.len() {
        return None;
    }
    for (name, _) in SCENARIOS {
        let result: TrialResult = serde_json::from_value(scenarios.get(name)?.clone()).ok()?;
        if !result.elapsed_seconds.is_finite() || result.elapsed_seconds < 0.0 {
            return None;
        }
        let files = evidence.get(name)?.as_object()?;
        if files.len() != 2 {
            return None;
        }
        for suffix in ["stdout", "stderr"] {
            if !Path::new(files.get(suffix)?.as_str()?).is_file() {
                return None;
            }
        }
    }
    Some(receipt)
}

fn lock(path: &Path, reason: &str) -> Result<File> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file()
            && file.metadata()?.nlink() == 1
            && file.metadata()?.uid() == rustix::process::geteuid().as_raw(),
        "acceptance lock must be a single-link regular file owned by this user"
    );
    if let Err(error) =
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
    {
        if error != rustix::io::Errno::WOULDBLOCK {
            return Err(error.into());
        }
        let mut owner = String::new();
        file.seek(SeekFrom::Start(0))?;
        (&file).take(4096).read_to_string(&mut owner)?;
        eprintln!("Offline acceptance is locked: {owner}");
        anyhow::bail!(
            "another offline acceptance operation owns {}",
            path.display()
        );
    }

    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    serde_json::to_writer(
        &mut file,
        &json!({
            "pid": std::process::id(),
            "entity": "airlock-image-check",
            "reason": reason,
        }),
    )?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(file)
}

fn run_gate(args: &Args, report: &mut Value, output: Option<&Path>) -> Result<()> {
    let inputs = inputs(args)?;
    let (identity_value, fingerprint) = identity(args, &inputs)?;
    report["fingerprint"] = json!(fingerprint);
    report["revision"] = json!(inputs.revision);
    report["lock_hash"] = json!(inputs.lock_hash);
    report["baseline_paths"] = json!(inputs.paths.len());

    let receipt_path = args.cache_dir.join(format!("{fingerprint}.json"));
    let _lock = lock(
        &args.cache_dir.join(format!("{fingerprint}.lock")),
        "verify pinned builder inputs",
    )?;
    if let Some(cached) =
        valid_receipt(&receipt_path, &fingerprint, &identity_value).filter(|_| !args.force)
    {
        report["cache"] = json!("hit");
        report["scenarios"] = cached["scenarios"].clone();

        report["evidence"] = cached["evidence"].clone();
        println!("offline builder acceptance: cache hit {fingerprint}");
    } else {
        report["cache"] = json!(if args.force { "forced" } else { "miss" });
        println!(
            "offline builder acceptance: {} {fingerprint}",
            report["cache"].as_str().unwrap_or("miss")
        );
        if receipt_path.try_exists()? {
            fs::remove_file(&receipt_path)?;
        }

        let parent = args.log_dir.join(&fingerprint);
        fs::create_dir_all(&parent)?;
        let logs = tempfile::Builder::new()
            .prefix("trial-")
            .tempdir_in(&parent)?
            .keep();

        let temporary = tempfile::Builder::new()
            .prefix("offline-builder-gate-")
            .tempdir_in(&args.temporary_root)?;
        for (name, change) in SCENARIOS {
            report["scenarios"][name] = serde_json::to_value(trial::run(
                args,
                name,
                change,
                &inputs,
                &logs,
                temporary.path(),
            )?)?;
        }

        report["evidence"] = json!(SCENARIOS.iter().map(|(name,_)| Ok((*name,json!({"stdout":fs::canonicalize(logs.join(format!("{name}.stdout")))?,"stderr":fs::canonicalize(logs.join(format!("{name}.stderr")))?})))).collect::<Result<BTreeMap<_,_>>>()?);

        source_unchanged(args, &inputs)?;
        ensure!(
            identity(args, &inputs)?.1 == fingerprint,
            "builder inputs changed during offline trials"
        );
        atomic_json(
            &receipt_path,
            &json!({
                "schema": RECEIPT_SCHEMA,
                "status": "passed",
                "fingerprint": fingerprint,
                "identity": identity_value,
                "scenarios": report["scenarios"],
                "evidence": report["evidence"],
            }),
        )?;
    }

    source_unchanged(args, &inputs)?;
    ensure!(
        identity(args, &inputs)?.1 == fingerprint,
        "builder inputs changed before image assembly"
    );
    report["receipt"] = json!(receipt_path);
    if let Some(output) = output {
        assemble(args, &inputs, &identity_value, &fingerprint, report, output)?;
    }
    report["status"] = json!("passed");
    Ok(())
}

fn output_link(command: &[OsString]) -> Result<Option<PathBuf>> {
    if command.is_empty() {
        return Ok(None);
    }
    ensure!(
        !command
            .iter()
            .any(|arg| arg.as_encoded_bytes().starts_with(b"--out-link=")),
        "image command requires one separate --out-link argument"
    );
    let positions: Vec<_> = command
        .iter()
        .enumerate()
        .filter(|(_, word)| *word == "--out-link")
        .map(|(i, _)| i)
        .collect();
    ensure!(
        positions.len() == 1,
        "image command requires exactly one --out-link"
    );
    let target = PathBuf::from(
        command
            .get(positions[0] + 1)
            .context("image command needs --out-link value")?,
    );
    let name = target
        .file_name()
        .context("image output must name a file")?;
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    Ok(Some(fs::canonicalize(parent)?.join(name)))
}

fn assemble(
    args: &Args,
    inputs: &Inputs,
    identity_value: &Value,
    fingerprint: &str,
    report: &mut Value,
    final_link: &Path,
) -> Result<()> {
    let parent = args.cache_dir.join("snapshots");
    fs::create_dir_all(&parent)?;
    let snapshot = tempfile::Builder::new()
        .prefix(&format!("{fingerprint}-"))
        .tempdir_in(&parent)?;
    for (name, source) in [
        ("seed.tar.gz", &args.seed_archive),
        ("inputs.json", &args.manifest),
    ] {
        fs::copy(source, snapshot.path().join(name))?;
    }
    let matches = || -> Result<bool> {
        Ok(file_digest(&snapshot.path().join("seed.tar.gz"))?
            == identity_value["hashes"]["seed_archive"]
                .as_str()
                .context("seed hash")?
            && file_digest(&snapshot.path().join("inputs.json"))?
                == identity_value["hashes"]["manifest"]
                    .as_str()
                    .context("manifest hash")?)
    };
    ensure!(matches()?, "image input snapshot changed before assembly");

    let mut command = args.image_command.clone();
    if command.first().is_some_and(|s| s == "--") {
        command.remove(0);
    }
    let index = command
        .iter()
        .position(|word| word == "--out-link")
        .context("image command needs --out-link")?
        + 1;
    let link_parent = final_link.parent().context("image output parent")?;
    let staging = tempfile::Builder::new()
        .prefix(".airlock-image-")
        .tempdir_in(link_parent)?;
    let temporary_link = staging.path().join("result");
    command[index] = temporary_link.as_os_str().into();
    println!("offline builder acceptance: assembling image");

    let status = Command::new(&command[0])
        .args(&command[1..])
        .env(
            "AIRLOCK_MACHINE_SEED_ARCHIVE",
            fs::canonicalize(snapshot.path().join("seed.tar.gz"))?,
        )
        .env(
            "AIRLOCK_MACHINE_OFFLINE_INPUTS",
            fs::canonicalize(snapshot.path().join("inputs.json"))?,
        )
        .status()?;
    ensure!(status.success(), "image assembly failed with {status}");
    source_unchanged(args, inputs)?;
    ensure!(
        identity(args, inputs)?.1 == fingerprint,
        "builder inputs changed during image assembly"
    );
    ensure!(matches()?, "image input snapshot changed during assembly");
    ensure!(
        temporary_link.is_symlink(),
        "image builder returned no result link"
    );

    let result = fs::read_link(&temporary_link)?;
    let result: StorePath = result.to_str().context("non-UTF-8 image result")?.parse()?;
    // Register the final link through Nix itself. Renaming its temporary link
    // would leave the indirect GC root pointing at a now-absent pathname.
    output(
        Command::new("nix-store")
            .arg("--store")
            .arg(&args.source_store_root)
            .arg("--add-root")
            .arg(final_link)
            .arg("--indirect")
            .arg("--realise")
            .arg(result.as_str()),
    )?;
    ensure!(
        fs::read_link(final_link)? == Path::new(result.as_str()),
        "Nix published an unexpected image result"
    );
    File::open(link_parent)?.sync_all()?;
    report["image_status"] = json!("passed");
    Ok(())
}

pub(crate) fn main() -> Result<()> {
    let mut args = Args::parse();
    for path in [
        &mut args.machine,
        &mut args.prepared_machine,
        &mut args.manifest,
        &mut args.seed_archive,
        &mut args.source_store_root,
    ] {
        *path = fs::canonicalize(&path)?;
    }
    for path in [
        &mut args.log_dir,
        &mut args.cache_dir,
        &mut args.temporary_root,
    ] {
        fs::create_dir_all(&path)?;
        *path = fs::canonicalize(&path)?;
    }

    let _report_lock = lock(
        &args.log_dir.join("report.lock"),
        "record offline acceptance progress",
    )?;
    let output = output_link(&args.image_command)?;
    let _output_lock = output
        .as_ref()
        .map(|output| {
            let parent = output.parent().context("image output parent")?;
            let key = digest(output.as_os_str().as_encoded_bytes());
            lock(
                &parent.join(format!(".airlock-image-{key}.lock")),
                &format!("publish checked image at {}", output.display()),
            )
        })
        .transpose()?;

    let mut report = json!({"schema":REPORT_SCHEMA,"status":"running","scenarios":{}});
    if let Err(error) = run_gate(&args, &mut report, output.as_deref()) {
        report["status"] = json!("failed");
        report["error"] = json!(format!("{error:#}"));
        println!("offline builder acceptance: failure: {error:#}");
    }

    atomic_json(&args.log_dir.join("report.json"), &report)?;
    println!("{}", serde_json::to_string(&report)?);
    ensure!(
        report["status"] == "passed",
        "offline acceptance failed; see {}",
        args.log_dir.join("report.json").display()
    );
    Ok(())
}
