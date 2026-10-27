//! Inspect installed commands without executing them or borrowing the builder's command PATH.
//! Store membership is checked after every symlink, including interpreters and ELF dependencies.

use airlock_nix_core::{command::Contract, runtime::process};
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Component, Path, PathBuf},
    process::Command,
    time::Duration,
};

/// Read-only inspection of an existing NixOS system and its exact guest store inventory.
#[derive(Args)]
pub(crate) struct Request {
    /// Logical NixOS system root, not an image or block device.
    #[arg(long)]
    system: PathBuf,
    /// Exact store-path inventory that will be exposed to this system.
    #[arg(long)]
    paths: PathBuf,
    /// Physical location of the logical /nix/store for offline inspection.
    #[arg(long, default_value = "/nix/store")]
    store_root: PathBuf,
    /// Reference native launcher from the same application build as the installed commands.
    #[arg(long)]
    launcher: PathBuf,
    /// ELF inspection tool; inspected programs are never executed.
    #[arg(long, default_value = "readelf")]
    readelf: PathBuf,
    /// Optional machine-readable evidence path, including failed inspections.
    #[arg(long)]
    report: Option<PathBuf>,
}

/// Evidence distinguishes inspected store commands from runtime-created wrapper paths.
#[derive(Serialize)]
pub(crate) struct Report {
    // Stable evidence format for image-build and diagnostic consumers.
    schema: &'static str,
    // Logical NixOS system whose installed entry points were inspected.
    system: PathBuf,
    // Unique executables, interpreters and libraries reached from installed entry points.
    checked: BTreeSet<PathBuf>,
    // Native command contracts decoded using the runtime launcher's own schema.
    contracts: BTreeSet<PathBuf>,
    // Explicit runtime-created executables which static store inspection cannot open.
    deferred: BTreeSet<PathBuf>,
    // Per-entry failures retained together so one problem cannot conceal the next.
    errors: Vec<String>,
}

impl Report {
    /// Fail the build while retaining every independently discovered entry-point failure.
    pub(crate) fn require_success(&self) -> Result<()> {
        ensure!(
            self.errors.is_empty(),
            "boot preflight for {system}:\n{errors}",
            system = self.system.display(),
            errors = self.errors.join("\n")
        );
        Ok(())
    }
}

/// Logical store resolution never follows an absolute symlink into the workstation's store.
struct View<'a> {
    // Root of the guest's selected logical system.
    system: &'a Path,
    // Physical store directory supplied by the caller or image builder.
    physical: &'a Path,
    // Entire object names admitted to this VM's view, excluding neighbouring VM objects.
    objects: BTreeSet<PathBuf>,
}

/// A runtime-created resource is reported separately from a missing immutable dependency.
#[derive(Debug)]
struct RuntimePath {
    // Logical target which activation or the kernel supplies after boot.
    path: PathBuf,
}

impl std::fmt::Display for RuntimePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "runtime path outside the immutable store: {}",
            self.path.display()
        )
    }
}

impl std::error::Error for RuntimePath {}

impl View<'_> {
    /// Interpret only aliases established by NixOS activation, never the workstation's aliases.
    fn alias(&self, path: &Path) -> PathBuf {
        if let Ok(relative) = path.strip_prefix("/run/current-system") {
            self.system.join(relative)
        } else if let Ok(relative) = path.strip_prefix("/etc") {
            self.system.join("etc").join(relative)
        } else if path == Path::new("/bin/sh") {
            self.system.join("sw/bin/sh")
        } else if path == Path::new("/usr/bin/env") {
            self.system.join("sw/bin/env")
        } else {
            path.to_owned()
        }
    }

    /// Normalize relative symlink targets without allowing traversal above filesystem root.
    fn normalize(path: &Path) -> Result<PathBuf> {
        let mut result = PathBuf::new();
        for part in path.components() {
            match part {
                Component::RootDir => result.push("/"),
                Component::Normal(part) => result.push(part),
                Component::CurDir => {}
                Component::ParentDir => ensure!(result.pop(), "path escapes root"),
                Component::Prefix(_) => bail!("unsupported path prefix"),
            }
        }
        ensure!(result.is_absolute(), "expected an absolute path");
        Ok(result)
    }

    /// Resolve installed NixOS aliases and require every symlink destination to remain in the view.
    fn resolve(&self, path: &Path) -> Result<(PathBuf, PathBuf)> {
        let path = self.alias(path);
        let mut logical = Self::normalize(&path)?;
        for _ in 0..64 {
            let relative = logical
                .strip_prefix("/nix/store")
                .map_err(|_| RuntimePath {
                    path: logical.clone(),
                })?;
            let parts: Vec<_> = relative.components().collect();
            ensure!(!parts.is_empty(), "dependency names the store itself");
            let object = Path::new("/nix/store").join(parts[0].as_os_str());
            ensure!(
                self.objects.contains(&object),
                "dependency absent from this VM's store view: {}",
                object.display()
            );
            let mut prefix = self.physical.to_path_buf();
            let mut redirected = false;
            for (index, part) in parts.iter().enumerate() {
                prefix.push(part.as_os_str());
                let metadata = fs::symlink_metadata(&prefix).with_context(|| {
                    format!("missing installed dependency {}", logical.display())
                })?;
                if metadata.is_symlink() {
                    let target = fs::read_link(&prefix)?;
                    let parent =
                        Path::new("/nix/store").join(parts[..index].iter().collect::<PathBuf>());
                    let target = if target.is_absolute() {
                        target
                    } else {
                        parent.join(target)
                    };
                    logical = Self::normalize(
                        &self.alias(&target.join(parts[index + 1..].iter().collect::<PathBuf>())),
                    )?;
                    redirected = true;
                    break;
                }
            }
            if !redirected {
                return Ok((logical, prefix));
            }
        }
        bail!(
            "installed dependency contains a symlink loop: {}",
            path.display()
        )
    }
}

/// Native launchers and scripts are followed once; directories are separately bounded.
struct Inspector<'a> {
    // Selected immutable store view, including virtual NixOS runtime aliases.
    view: View<'a>,
    // External readelf selected by the build recipe, never by an inspected command.
    readelf: &'a Path,
    // Trusted launcher's content digest, identifying renamed or copied native commands.
    launcher: Vec<u8>,
    // Reference binary length avoids hashing unrelated large ELF programs.
    launcher_size: u64,
    // Visited /etc directory identities, preventing recursive alias loops.
    directories: BTreeSet<PathBuf>,
    // Enabled units and first-party helpers whose effective commands need inspection.
    units: BTreeSet<String>,
    // Unit dependency identities already traversed, including aliases and templates.
    visited_units: BTreeSet<String>,
    // Collected checks and failures for this selected system only.
    report: Report,
}

/// Find literal store paths in script text and argv without interpreting shell syntax.
fn references(text: &str) -> BTreeSet<PathBuf> {
    text.match_indices("/nix/store/")
        .map(|(index, _)| {
            let tail = &text[index..];
            let end = tail
                .find(|ch: char| {
                    ch.is_whitespace()
                        || matches!(
                            ch,
                            '\'' | '"' | ':' | ';' | ',' | ')' | '}' | '$' | '`' | '\\'
                        )
                })
                .unwrap_or(tail.len());
            PathBuf::from(&tail[..end])
        })
        .collect()
}

impl Inspector<'_> {
    /// Check argv's immutable objects, recursively inspecting referenced executable files.
    fn text(&mut self, text: &str, search: &[PathBuf]) -> Result<()> {
        for path in references(text) {
            let physical = match self.view.resolve(&path) {
                Ok((_, physical)) => physical,
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
                {
                    continue;
                }
                Err(error) if error.downcast_ref::<RuntimePath>().is_some() => {
                    self.report.deferred.insert(path);
                    continue;
                }
                Err(error) => return Err(error),
            };
            let metadata = fs::metadata(&physical)?;
            if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
                // An executable script may be passed as data to an explicit Python or
                // shell interpreter; its own shebang is not used in that invocation.
                let bytes = fs::read(&physical)?;
                if bytes.starts_with(b"\x7fELF") {
                    self.executable(&path, search)?;
                }
            }
        }
        Ok(())
    }

    /// Inspect an executable's interpreter, command contract and transitive dynamic dependencies.
    fn executable(&mut self, path: &Path, inherited: &[PathBuf]) -> Result<()> {
        self.inspect(path, inherited, true)
    }

    /// Libraries need readable ELF content; only programs require executable permission bits.
    fn inspect(&mut self, path: &Path, inherited: &[PathBuf], require_exec: bool) -> Result<()> {
        if path == Path::new("/run/wrappers/bin/sudo") {
            self.report.deferred.insert(path.to_owned());
            return Ok(());
        }
        let (logical, physical) = self.view.resolve(path)?;
        let metadata = fs::metadata(&physical)?;
        ensure!(
            metadata.is_file() && (!require_exec || metadata.permissions().mode() & 0o111 != 0),
            "installed command is not executable: {}",
            logical.display()
        );
        if !self.report.checked.insert(logical.clone()) {
            return Ok(());
        }
        let bytes = fs::read(&physical)?;
        if bytes.starts_with(b"#!") {
            let line = bytes
                .split(|byte| *byte == b'\n')
                .next()
                .context("empty shebang")?;
            let line = std::str::from_utf8(line)?;
            let interpreter = line[2..]
                .split_whitespace()
                .next()
                .context("missing script interpreter")?;
            self.executable(Path::new(interpreter), inherited)?;
            let script = std::str::from_utf8(&bytes)?;
            self.text(script, inherited)?;
            for line in script.lines().skip(1) {
                // Nix makeWrapper uses exec -a "$0" PROGRAM. Tokenization handles
                // quoted names without evaluating shell expansions or running code.
                let mut words = shlex::Shlex::new(line.trim());
                let Some(mut program) = words.next() else {
                    continue;
                };
                if program == "exec" {
                    while let Some(word) = words.next() {
                        match word.as_str() {
                            "-a" => {
                                words.next();
                            }
                            "-c" | "-l" => {}
                            "--" => {
                                program = words.next().unwrap_or_default();
                                break;
                            }
                            _ => {
                                program = word;
                                break;
                            }
                        }
                    }
                }
                if program.starts_with("/nix/store/")
                    && !program
                        .chars()
                        .any(|ch| matches!(ch, '$' | '*' | '?' | '['))
                {
                    self.executable(Path::new(&program), inherited)?;
                }
            }
            return Ok(());
        }
        ensure!(
            bytes.starts_with(b"\x7fELF"),
            "unrecognised executable format: {}",
            logical.display()
        );
        if metadata.len() == self.launcher_size
            && Sha256::digest(&bytes).as_slice() == self.launcher
        {
            let mut name = logical
                .file_name()
                .context("launcher filename")?
                .to_os_string();
            name.push(".json");
            let (_, contract_path) = self.view.resolve(&logical.with_file_name(name))?;
            let contract = Contract::read_path(&contract_path)?;
            self.report.contracts.insert(logical.clone());
            ensure!(
                Path::new(&contract.program).is_absolute(),
                "native command program must be absolute: {}",
                logical.display()
            );
            self.executable(Path::new(&contract.program), inherited)?;
            for value in &contract.args {
                // A complete immutable argv path is an installed resource, unlike
                // optional PATH directories or partial paths inside shell text.
                let path = value
                    .split_once('=')
                    .map_or(value.as_str(), |(_, value)| value);
                if path.starts_with("/nix/store/")
                    && !path
                        .chars()
                        .any(|ch| ch.is_whitespace() || matches!(ch, '$' | '\'' | '"' | ';'))
                {
                    self.view.resolve(Path::new(path))?;
                }
                self.text(value, inherited)?;
            }
            for value in contract.env.values().chain(contract.prefix_env.values()) {
                self.text(value, inherited)?;
            }
        }

        let output = process::run(
            Command::new(self.readelf)
                .args(["--wide", "--program-headers", "--dynamic"])
                .arg(&physical)
                .env("LC_ALL", "C"),
            None,
            Some(Duration::from_secs(15)),
        )?
        .checked("inspect executable dependencies")?;
        let output = std::str::from_utf8(&output)?;
        let mut search = inherited.to_vec();
        let mut needed = Vec::new();
        for line in output.lines() {
            if let Some((_, value)) = line.split_once("Requesting program interpreter: ") {
                let interpreter = PathBuf::from(value.trim_end_matches(']').trim());
                self.executable(&interpreter, inherited)?;
                search.push(
                    interpreter
                        .parent()
                        .context("interpreter directory")?
                        .to_owned(),
                );
            }
            let Some((_, value)) = line.split_once('[') else {
                continue;
            };
            let value = value.split(']').next().context("ELF dependency value")?;
            if line.contains("(NEEDED)") {
                needed.push(value.to_owned());
            } else if line.contains("(RPATH)") || line.contains("(RUNPATH)") {
                for directory in value.split(':') {
                    let parent = logical
                        .parent()
                        .context("executable directory")?
                        .to_string_lossy();
                    let directory = directory
                        .replace("${ORIGIN}", &parent)
                        .replace("$ORIGIN", &parent);
                    ensure!(
                        !directory.contains('$'),
                        "unsupported dynamic library search token: {directory}"
                    );
                    search.insert(0, PathBuf::from(directory));
                }
            }
        }
        for name in needed {
            let candidate = search
                .iter()
                .map(|directory| directory.join(&name))
                .find(|candidate| self.view.resolve(candidate).is_ok())
                .with_context(|| {
                    format!(
                        "{binary}: missing dynamic library {name} in declared search paths",
                        binary = logical.display()
                    )
                })?;
            self.inspect(&candidate, &search, false)?;
        }
        Ok(())
    }

    /// Inspect the actual /etc source tree and reject native binaries requested as runtime copies.
    fn etc(&mut self, path: &Path, relative: &Path) -> Result<()> {
        let entrypoint = [
            "qubes-rpc",
            "NetworkManager/dispatcher.d",
            "X11/xinit",
            "init.d",
        ]
        .iter()
        .any(|prefix| relative.starts_with(prefix));
        let (logical, physical) = match self.view.resolve(path) {
            Ok(value) => value,
            Err(error)
                if relative.starts_with("qubes-rpc")
                    && error.downcast_ref::<RuntimePath>().is_some_and(|target| {
                        target
                            .path
                            .extension()
                            .is_some_and(|extension| extension == "sock")
                    }) =>
            {
                self.report.deferred.insert(
                    error
                        .downcast_ref::<RuntimePath>()
                        .context("socket target")?
                        .path
                        .clone(),
                );
                return Ok(());
            }
            Err(error) if !entrypoint && error.downcast_ref::<RuntimePath>().is_some() => {
                self.report.deferred.insert(
                    error
                        .downcast_ref::<RuntimePath>()
                        .context("runtime path")?
                        .path
                        .clone(),
                );
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let metadata = fs::metadata(&physical)?;
        if metadata.is_dir() {
            if !self.directories.insert(logical) {
                return Ok(());
            }
            ensure!(
                self.directories.len() <= 10_000,
                "too many installed /etc directories"
            );
            let mut children = fs::read_dir(&physical)?.collect::<std::io::Result<Vec<_>>>()?;
            children.sort_by_key(|entry| entry.file_name());
            for child in children {
                let key = relative.join(child.file_name());
                if key == Path::new("static") {
                    continue;
                }
                if let Err(error) = self.etc(&path.join(child.file_name()), &key) {
                    ensure!(
                        self.report.errors.len() < 128,
                        "too many boot preflight failures"
                    );
                    self.report
                        .errors
                        .push(format!("/etc/{key}: {error:#}", key = key.display()));
                }
            }
        } else if metadata.is_file()
            && entrypoint
            && (relative.starts_with("qubes-rpc") || metadata.permissions().mode() & 0o111 != 0)
            && path.extension().is_none_or(|extension| {
                !["mode", "uid", "gid"]
                    .iter()
                    .any(|suffix| extension == *suffix)
            })
        {
            let bytes = fs::read(&physical)?;
            if !bytes.starts_with(b"#!") && !bytes.starts_with(b"\x7fELF") {
                // Qubes also supports socket service descriptors rather than executables.
                let target = std::str::from_utf8(&bytes)?.trim();
                ensure!(
                    relative.starts_with("qubes-rpc")
                        && target.starts_with('/')
                        && target.ends_with(".sock"),
                    "unrecognised executable entry point: {}",
                    relative.display()
                );
                self.report.deferred.insert(PathBuf::from(target));
                return Ok(());
            }
            if metadata.len() == self.launcher_size
                && Sha256::digest(fs::read(&physical)?).as_slice() == self.launcher
            {
                let mode = path.with_file_name(format!(
                    "{name}.mode",
                    name = path.file_name().context("entry name")?.to_string_lossy()
                ));
                if let Ok((_, mode)) = self.view.resolve(&mode) {
                    let mode = fs::read_to_string(mode)?;
                    ensure!(
                        matches!(mode.trim(), "symlink" | "direct-symlink"),
                        "native launcher would be copied without its adjacent JSON (mode {mode})",
                        mode = mode.trim()
                    );
                }
            }
            self.executable(path, &[])?;
        } else if relative.starts_with("systemd/system") && metadata.is_file() {
            let unit = fs::read_to_string(&physical)?;
            self.text(&unit, &[])?;
            if let Some(name) = relative.file_name().and_then(|name| name.to_str())
                && name.ends_with(".service")
                && (name.starts_with("airlock-")
                    || relative
                        .parent()
                        .and_then(Path::extension)
                        .is_some_and(|value| value == "wants" || value == "requires"))
            {
                self.units.insert(name.into());
            }
        }
        Ok(())
    }

    /// Apply service drop-in resets before checking commands, then follow actual startup dependencies.
    fn unit(&mut self, name: &str, required: bool) -> Result<()> {
        if self.visited_units.contains(name)
            || name.ends_with(".device")
            || name.ends_with(".mount")
        {
            return Ok(());
        }
        let directory = self.view.system.join("etc/systemd/system");
        let mut found = self.view.resolve(&directory.join(name));
        if found.is_err()
            && let Some((prefix, instance)) = name.split_once('@')
            && let Some((_, suffix)) = instance.rsplit_once('.')
        {
            found = self
                .view
                .resolve(&directory.join(format!("{prefix}@.{suffix}")));
        }
        let (logical, physical) = match found {
            Ok(value) => value,
            Err(error)
                if error
                    .downcast_ref::<RuntimePath>()
                    .is_some_and(|path| path.path == Path::new("/dev/null")) =>
            {
                return Ok(());
            }
            Err(error)
                if !required
                    && error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                self.report.deferred.insert(directory.join(name));
                return Ok(());
            }
            Err(error) => return Err(error).with_context(|| format!("startup unit {name}")),
        };
        self.visited_units.insert(name.into());
        ensure!(
            self.visited_units.len() < 10_000,
            "too many startup unit dependencies"
        );
        let mut files = vec![physical];
        let canonical = logical
            .file_name()
            .and_then(|name| name.to_str())
            .context("unit filename")?;
        let mut names = vec![canonical, name];
        names.sort();
        names.dedup();
        for alias in names {
            let directory = self
                .view
                .system
                .join("etc/systemd/system")
                .join(format!("{alias}.d"));
            if let Ok((_, physical)) = self.view.resolve(&directory) {
                let mut entries = fs::read_dir(physical)?.collect::<std::io::Result<Vec<_>>>()?;
                entries.sort_by_key(|entry| entry.file_name());
                for entry in entries {
                    if entry
                        .path()
                        .extension()
                        .is_some_and(|extension| extension == "conf")
                    {
                        files.push(self.view.resolve(&directory.join(entry.file_name()))?.1);
                    }
                }
            }
        }
        let mut values: std::collections::BTreeMap<String, Vec<String>> = Default::default();
        for file in files {
            for line in fs::read_to_string(file)?.lines() {
                let Some((key, value)) = line.split_once('=') else {
                    continue;
                };
                let key = key.trim();
                if key.starts_with("Exec")
                    || ["Requires", "Wants", "BindsTo", "Requisite"].contains(&key)
                {
                    let values = values.entry(key.into()).or_default();
                    if value.trim().is_empty() {
                        values.clear();
                    } else {
                        values.push(value.trim().to_owned());
                    }
                }
            }
        }
        for (key, values) in values {
            if ["Requires", "Wants", "BindsTo", "Requisite"].contains(&key.as_str()) {
                for dependency in values.iter().flat_map(|value| value.split_whitespace()) {
                    if dependency.contains('%') {
                        self.report.deferred.insert(directory.join(dependency));
                    } else {
                        self.unit(dependency, key != "Wants")?;
                    }
                }
            } else if [
                "ExecStart",
                "ExecStartPre",
                "ExecStartPost",
                "ExecCondition",
                "ExecStop",
                "ExecStopPost",
                "ExecReload",
            ]
            .contains(&key.as_str())
            {
                for value in values {
                    let value = value.trim_start_matches(['-', '@', ':', '+', '!']);
                    let Some(program) = value
                        .split_whitespace()
                        .next()
                        .filter(|value| !value.is_empty())
                    else {
                        continue;
                    };
                    let program = PathBuf::from(program.trim_matches('"'));
                    if program.is_absolute() {
                        self.executable(&program, &[])
                            .with_context(|| format!("{name} {key}"))?;
                    } else {
                        let mut search = vec![self.view.system.join("sw/bin")];
                        for checked in &self.report.checked {
                            if checked.ends_with("lib/systemd/systemd") {
                                search.push(
                                    checked.parent().context("systemd helper directory")?.into(),
                                );
                                search.push(
                                    checked
                                        .ancestors()
                                        .nth(3)
                                        .context("systemd package")?
                                        .join("bin"),
                                );
                            }
                        }
                        let path = search
                            .iter()
                            .map(|directory| directory.join(&program))
                            .find(|path| self.view.resolve(path).is_ok())
                            .with_context(|| {
                                format!(
                                    "{name} {key}: missing service executable {}",
                                    program.display()
                                )
                            })?;
                        self.executable(&path, &[])?;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Inspect a selected system before publishing its guest closure manifest.
pub(crate) fn check(
    system: &Path,
    paths: &Path,
    physical: &Path,
    launcher: &Path,
    readelf: &Path,
) -> Result<Report> {
    let objects: BTreeSet<PathBuf> = fs::read_to_string(paths)?
        .lines()
        .map(PathBuf::from)
        .collect();
    ensure!(
        !objects.is_empty()
            && objects
                .iter()
                .all(|path| path.parent() == Some(Path::new("/nix/store"))),
        "invalid guest store-path inventory"
    );
    let mut inspector = Inspector {
        view: View {
            system,
            physical,
            objects,
        },
        readelf,
        launcher: Sha256::digest(fs::read(launcher)?).to_vec(),
        launcher_size: fs::metadata(launcher)?.len(),
        directories: BTreeSet::new(),
        units: BTreeSet::new(),
        visited_units: BTreeSet::new(),
        report: Report {
            schema: "airlock.boot-preflight.v1",
            system: system.to_owned(),
            checked: BTreeSet::new(),
            contracts: BTreeSet::new(),
            deferred: BTreeSet::new(),
            errors: Vec::new(),
        },
    };
    eprintln!("Boot preflight: inspecting {}", system.display());
    for entry in ["activate", "init"] {
        if let Err(error) = inspector.executable(&system.join(entry), &[]) {
            inspector.report.errors.push(format!("{entry}: {error:#}"));
        }
    }
    if let Err(error) = inspector.etc(&system.join("etc"), Path::new("")) {
        inspector.report.errors.push(format!("etc: {error:#}"));
    }
    for unit in inspector.units.clone() {
        if let Err(error) = inspector.unit(&unit, true) {
            inspector.report.errors.push(format!("{unit}: {error:#}"));
        }
    }
    eprintln!(
        "Boot preflight: {} commands/libraries, {} native contracts, {} failures",
        inspector.report.checked.len(),
        inspector.report.contracts.len(),
        inspector.report.errors.len()
    );
    Ok(inspector.report)
}

/// Emit diagnostic evidence without changing the selected store or any guest filesystem.
pub(crate) fn run(request: Request) -> Result<()> {
    let launcher = if request.launcher.starts_with("/nix/store") {
        request
            .store_root
            .join(request.launcher.strip_prefix("/nix/store")?)
    } else {
        request.launcher
    };
    let report = check(
        &request.system,
        &request.paths,
        &request.store_root,
        &launcher,
        &request.readelf,
    )?;
    if let Some(path) = request.report {
        fs::write(path, serde_json::to_vec_pretty(&report)?)?;
    }
    report.require_success()
}
