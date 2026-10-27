//! Make a committed local gitlink available without rewriting either checkout.

use crate::support::{git, output};
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const COMPONENT: &str = "airlock-machine";

pub(crate) fn root(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(fs::canonicalize(path)?);
    }

    let current = std::env::current_dir()?;
    if let Some(root) = current
        .ancestors()
        .find(|p| p.join("crates/tooling/airlock-dev/Cargo.toml").is_file())
    {
        return Ok(root.to_owned());
    }

    let built = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .context("developer source root")?;
    ensure!(
        built.join(".git").exists(),
        "run inside the Airlock checkout or supply --repository-root"
    );
    Ok(built.to_owned())
}

pub(crate) fn pinned(root: &Path, revision: &str) -> Result<String> {
    let entry = git(root, &["ls-tree", revision, "--", COMPONENT])?;
    let fields: Vec<_> = entry.split_whitespace().collect();
    ensure!(
        fields.len() == 4 && fields[..2] == ["160000", "commit"],
        "HEAD must contain the committed airlock-machine submodule pin"
    );
    let _: airlock_nix_core::identity::GitRevision = fields[2].parse()?;
    Ok(fields[2].to_owned())
}

pub(crate) fn local(root: &Path) -> Result<(PathBuf, String)> {
    let revision = pinned(root, "HEAD")?;
    let machine = root.join(COMPONENT);
    ensure!(
        machine.join(".git").exists(),
        "airlock-machine is not initialized. Run: git submodule update --init --recursive -- airlock-machine"
    );
    ensure!(
        Path::new(&git(&machine, &["rev-parse", "--show-toplevel"])?) == machine,
        "airlock-machine is not a separate Git checkout"
    );
    ensure!(
        git(&machine, &["rev-parse", "HEAD"])? == revision,
        "airlock-machine does not match the committed parent pin"
    );
    ensure!(
        git(root, &["diff", "--cached", "--name-only", "--", COMPONENT])?.is_empty(),
        "Commit the staged airlock-machine pin before building"
    );
    ensure!(
        git(&machine, &["status", "--porcelain"])?.is_empty(),
        "Commit or stash changes in airlock-machine before building"
    );
    Ok((machine, revision))
}

/// Compare committed application content rather than commit age or working edits.
pub(crate) fn check_image_source(root: &Path) -> Result<()> {
    let source = git(root, &["rev-parse", "HEAD"])?;
    let lock: serde_json::Value =
        serde_json::from_str(&git(root, &["show", &format!("{source}:flake.lock")])?)?;
    // The parent lock selects the applications actually installed by the image.
    let revision: airlock_nix_core::identity::GitRevision = lock["nodes"]["airlock-apps"]["locked"]
        ["rev"]
        .as_str()
        .context("USB image application source revision is missing")?
        .parse()?;
    let pinned = git(root, &["rev-parse", &format!("{revision}:crates")])?;
    let intended = git(root, &["rev-parse", &format!("{source}:crates")])?;
    ensure!(
        pinned == intended,
        "USB image application pin {revision} is stale: its crates/ content differs from committed HEAD {source}. Update airlock-machine/application-revision and both application locks, then commit the machine pin before rebuilding."
    );

    eprintln!("USB image application source matches committed crates/ ({revision}).");
    Ok(())
}

fn url(root: &Path) -> Result<String> {
    let modules = output(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["show", "HEAD:.gitmodules"]),
    )?;
    let bytes = crate::support::input(
        Command::new("git").args([
            "config",
            "--file",
            "-",
            "--get",
            "submodule.airlock-machine.url",
        ]),
        modules,
        std::time::Duration::from_secs(30),
    )?;
    let value = String::from_utf8(bytes)?.trim().to_owned();
    ensure!(
        !value.is_empty(),
        "The committed .gitmodules lacks airlock-machine's URL"
    );
    Ok(value)
}

pub(crate) fn file_uri(path: &Path) -> Result<String> {
    ensure!(path.is_absolute(), "file URI requires an absolute path");
    let mut encoded = String::from("file://");
    for byte in path.as_os_str().as_encoded_bytes() {
        if byte.is_ascii_alphanumeric() || b"/-._~".contains(byte) {
            encoded.push(char::from(*byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    Ok(encoded)
}

/// Resolve a local flake argument while leaving flags, remote URLs and selectors untouched.
fn local_source(root: &Path, argument: &OsStr) -> Option<(PathBuf, String)> {
    let argument = argument.to_str()?;
    let (source, selector) = argument.split_once('#').unwrap_or((argument, ""));
    let source = source.strip_prefix("path:").unwrap_or(source);
    if source.is_empty() || source.starts_with('-') {
        return None;
    }

    let path = fs::canonicalize(source).ok()?;
    let relative = if path == root {
        PathBuf::new()
    } else if path == root.join(COMPONENT) {
        PathBuf::from(COMPONENT)
    } else if path == root.join("crates") {
        PathBuf::from("crates")
    } else {
        return None;
    };
    let suffix = if argument.contains('#') {
        format!("#{selector}")
    } else {
        String::new()
    };

    Some((relative, suffix))
}

/// Keep prepared source under this checkout's ignored build output unless explicitly overridden.
pub(crate) fn prepared_cache(root: &Path) -> PathBuf {
    std::env::var_os("AIRLOCK_PREPARED_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target/nix"))
}

/// Prepare the checked local machine pin and protect its artifact throughout the caller's use.
pub(crate) fn prepare_leased(
    root: &Path,
) -> Result<(PathBuf, airlock_config::preparation::cache::Lease)> {
    local(root)?;
    airlock_config::preparation::development_leased(root, &prepared_cache(root))
        .map_err(|error| anyhow::anyhow!("{error}"))
}

/// Keep local Git redirection and prepared source available until Nix has exited.
pub(crate) struct SourceUse {
    /// Temporary Git view that supplies an unpublished local application pin.
    _redirect: Option<tempfile::TempDir>,
    /// Artifact locks held by this Nix operation, including explicit cached path arguments.
    _leases: Vec<airlock_config::preparation::cache::Lease>,
}

/// Recognize explicit cached flake paths as well as paths automatically prepared by the wrapper.
fn argument_leases(
    root: &Path,
    args: &[OsString],
) -> Result<Vec<airlock_config::preparation::cache::Lease>> {
    let cache = prepared_cache(root);
    if !cache.exists() {
        return Ok(Vec::new());
    }

    let cache = fs::canonicalize(cache)?;
    let mut trees = BTreeSet::new();
    for argument in args.iter().filter_map(|argument| argument.to_str()) {
        let path = argument.strip_prefix("path:").unwrap_or(argument);
        let path = path.split('#').next().unwrap_or(path);
        let Ok(path) = fs::canonicalize(root.join(path)) else {
            continue;
        };
        if let Some(tree) = path
            .ancestors()
            .find(|tree| tree.parent() == Some(cache.as_path()))
        {
            trees.insert(tree.to_owned());
        }
    }

    trees
        .into_iter()
        .map(|tree| {
            airlock_config::preparation::cache::lease(&cache, &tree)
                .map_err(|error| anyhow::anyhow!("{error}"))
        })
        .collect()
}

fn redirect(command: &mut Command, upstream: &str, source: &Path) -> Result<()> {
    let inherited = std::env::var("GIT_CONFIG_COUNT").unwrap_or_else(|_| "0".into());
    let mut count: usize = command
        .get_envs()
        .find(|(key, _)| *key == "GIT_CONFIG_COUNT")
        .and_then(|(_, value)| value.and_then(OsStr::to_str))
        .unwrap_or(&inherited)
        .parse()?;
    ensure!(count < 10000, "too many Git configuration entries");
    let mut urls = vec![upstream.to_owned()];
    if !upstream.contains("://")
        && let Some((host, path)) = upstream.split_once(':')
        && host.contains('@')
        && !host.contains('/')
    {
        urls.push(format!("ssh://{host}/{path}"));
    }
    let uri = file_uri(source)?;
    for original in urls {
        command.env(
            format!("GIT_CONFIG_KEY_{count}"),
            format!("url.{uri}.insteadOf"),
        );
        command.env(format!("GIT_CONFIG_VALUE_{count}"), original);
        count += 1;
    }
    command.env(format!("GIT_CONFIG_KEY_{count}"), "protocol.file.allow");
    command.env(format!("GIT_CONFIG_VALUE_{count}"), "always");
    command.env("GIT_CONFIG_COUNT", (count + 1).to_string());
    Ok(())
}

fn apps_source(command: &mut Command, root: &Path, temporary: &Path) -> Result<()> {
    let lock = root.join("flake.lock");
    if !lock.is_file() {
        return Ok(());
    }
    let lock = crate::support::json(&lock)?;
    let input = &lock["nodes"]["airlock-apps"]["locked"];
    if input["type"] != "git"
        || !matches!(input["dir"].as_str(), Some("apps" | "crates"))
        || input["submodules"] == true
    {
        return Ok(());
    }
    let revision: airlock_nix_core::identity::GitRevision = input["rev"]
        .as_str()
        .context("application source revision")?
        .parse()?;
    let upstream = input["url"].as_str().context("application source URL")?;
    // A shallow contributor clone may not contain the pinned source commit.
    // In that case Nix can fetch its published URL normally.
    let available = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["cat-file", "-e", &format!("{revision}^{{commit}}")])
        .stderr(std::process::Stdio::null())
        .status()?;
    if !available.success() {
        return Ok(());
    }

    let reference = input["ref"].as_str().unwrap_or("refs/heads/main");
    let reference = if reference.starts_with("refs/") {
        reference.to_owned()
    } else {
        format!("refs/heads/{reference}")
    };
    git(root, &["check-ref-format", &reference])?;
    let source = temporary.join("apps.git");
    output(
        Command::new("git")
            .args(["clone", "--quiet", "--bare", "--shared", "--"])
            .arg(root)
            .arg(&source),
    )?;
    git(&source, &["update-ref", &reference, revision.as_str()])?;
    git(&source, &["symbolic-ref", "HEAD", &reference])?;
    redirect(command, upstream, &source)
}

fn guard_store() -> Result<()> {
    let host = std::env::var("AIRLOCK_USE_HOST_NIX_STORE").as_deref() == Ok("1");
    let configured = std::env::var("AIRLOCK_NIX_CONFIGURED").as_deref() == Ok("1")
        && std::env::var("NIX_CONFIG")
            .unwrap_or_default()
            .lines()
            .any(|line| {
                line.split_once('=').is_some_and(|(key, value)| {
                    key.trim() == "store" && value.trim().starts_with('/')
                })
            });
    ensure!(
        host || configured,
        "Nix operations require the guarded Airlock store; use airlock-dev with-environment"
    );
    Ok(())
}

pub(crate) fn command(root: &Path, args: &[impl AsRef<OsStr>]) -> Result<(Command, SourceUse)> {
    guard_store()?;

    let args: Vec<OsString> = args.iter().map(|s| s.as_ref().to_owned()).collect();
    let requested: Vec<_> = args.iter().map(|arg| local_source(root, arg)).collect();
    let mut leases = argument_leases(root, &args)?;
    let mut command = Command::new("nix");
    if requested.iter().all(Option::is_none) {
        command.args(args);
        return Ok((
            command,
            SourceUse {
                _redirect: None,
                _leases: leases,
            },
        ));
    }

    let (prepared, lease) = prepare_leased(root)?;
    leases.push(lease);
    for (argument, local) in args.iter().zip(requested) {
        if let Some((relative, selector)) = local {
            command.arg(format!(
                "path:{path}{selector}",
                path = prepared.join(relative).display()
            ));
        } else {
            command.arg(argument);
        }
    }

    let temporary = tempfile::Builder::new()
        .prefix("airlock-app-source-")
        .tempdir()?;
    apps_source(&mut command, root, temporary.path())?;

    Ok((
        command,
        SourceUse {
            _redirect: Some(temporary),
            _leases: leases,
        },
    ))
}

pub(crate) fn nix(root: &Path, arguments: &[OsString]) -> Result<u8> {
    let (mut command, _source) = command(root, arguments)?;
    // Only human-readable build logs contain these prefixes. Keep explicit log
    // formats (including Nix's JSON event protocol) completely untouched.
    let build_logs = arguments
        .iter()
        .any(|arg| arg == "--print-build-logs" || arg == "-L");
    let explicit_format = arguments
        .iter()
        .any(|arg| arg == "--log-format" || arg.to_string_lossy().starts_with("--log-format="));
    let status = if build_logs && !explicit_format {
        crate::build_log::run(&mut command)?
    } else {
        command.status()?
    };
    Ok(status
        .code()
        .and_then(|n| u8::try_from(n).ok())
        .unwrap_or(1))
}

pub(crate) fn check_publish(root: &Path) -> Result<()> {
    let revision = pinned(root, "HEAD")?;
    let upstream = url(root)?;
    let temporary = tempfile::tempdir()?;
    git(temporary.path(), &["init", "--quiet", "--bare"])?;
    git(
        temporary.path(),
        &[
            "fetch",
            "--quiet",
            "--filter=blob:none",
            "--no-tags",
            &upstream,
            "refs/heads/main:refs/heads/main",
        ],
    )?;
    ensure!(
        Command::new("git")
            .arg("-C")
            .arg(temporary.path())
            .args(["merge-base", "--is-ancestor", &revision, "refs/heads/main"])
            .status()?
            .success(),
        "Publish the machine commit on main before publishing the parent pin"
    );
    println!("Machine pin {revision} is available from upstream main");
    Ok(())
}
