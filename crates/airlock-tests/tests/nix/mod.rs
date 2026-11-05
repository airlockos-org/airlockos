//! Nix evaluates generated artifacts offline with private derivation state and explicitly archived sources in the guarded Airlock store.

mod equivalence;

mod gui;

mod machine;

mod configuration;

mod schema;

mod profiles;

mod images;

mod sources;

mod roles;

use crate::common;
use airlock_vm_service::support;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex, OnceLock, Weak},
    time::Duration,
};

/// Captured evaluation outcome, including expected rejection diagnostics.
#[derive(Clone)]
struct Reply {
    // Exit success is inspected separately for intentional module conflicts.
    success: bool,
    // Strict JSON when successful; diagnostics are retained even when decoding fails.
    stdout: String,
    // Original Nix diagnostic for provenance and rejection assertions.
    stderr: String,
    // Exact retained diagnostic path, including the fixture/input digest used by the cache.
    diagnostics: PathBuf,
}

impl Reply {
    /// Decode only successful evaluations; preserve the complete failure trace otherwise.
    fn value(&self) -> Result<Value> {
        ensure!(
            self.success,
            "Nix evaluation failed: {stderr}",
            stderr = self.stderr
        );
        Ok(serde_json::from_str(&self.stdout)?)
    }
}

/// Evaluate a small authored fixture without preparing unrelated machine exports or enabling builds.
fn evaluate_fixture(root: &Path, label: &str, fixture: &str, inputs: Value) -> Result<Reply> {
    let store =
        PathBuf::from(std::env::var_os("AIRLOCK_NIX_ROOT").context("guarded Airlock store")?);
    ensure!(
        store.is_absolute() && store != Path::new("/"),
        "select the guarded Airlock store"
    );
    let logs = PathBuf::from(
        std::env::var_os("AIRLOCK_RUSIX_LOG_DIR").context("explicit test log directory")?,
    );
    fs::create_dir_all(&logs)?;
    let driver = root.join(format!("{label}.nix"));
    let source = common::run(
        Command::new(common::binary(
            "AIRLOCK_TEST_FIXTURES_BIN",
            "examples/test_fixtures",
        ))
        .arg(fixture)
        .arg(serde_json::to_string(&inputs)?),
        None,
    )?
    .checked()?;
    fs::write(&driver, source)?;

    let mut command = Command::new("nix");
    command
        .arg("--store")
        .arg(store)
        .args([
            "--extra-experimental-features",
            "nix-command flakes",
            "--option",
            "substituters",
            "",
            "--option",
            "builders",
            "",
            "--option",
            "build-users-group",
            "",
            "--option",
            "allow-import-from-derivation",
            "false",
            "--offline",
            "eval",
            "--impure",
            "--json",
            "--eval-store",
        ])
        .arg(root.join("evaluation-store"))
        .arg("--file")
        .arg(driver)
        .env_remove("NIX_REMOTE")
        .env_remove("NIX_STORE_DIR")
        .env("NIX_CONFIG", "")
        .env("NIX_PATH", "")
        .env("NIX_CONF_DIR", root.join("config"))
        .env("NIX_USER_CONF_FILES", root.join("config/nix.conf"))
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env("XDG_STATE_HOME", root.join("state"))
        .env("XDG_DATA_HOME", root.join("data"));
    let output = support::run(&mut command, None, Duration::from_secs(60))?;
    let reply = Reply {
        success: output.status.success(),
        stdout: String::from_utf8(output.stdout)?,
        stderr: String::from_utf8(output.stderr)?,
        diagnostics: logs.join(format!("{label}.stderr")),
    };
    fs::write(&reply.diagnostics, &reply.stderr)?;
    fs::write(logs.join(format!("{label}.json")), &reply.stdout)?;
    Ok(reply)
}

/// Immutable prepared source copy and serialized cache shared by the ignored evaluation tests.
struct Nix {
    // Retains the source snapshot and isolated store while evaluation tests use it.
    temporary: tempfile::TempDir,
    // Source checkout used only for locating explicit tools and recording the revision.
    root: PathBuf,
    // Test copy containing inspection-only artifacts; the prepared input is never mutated.
    prepared: PathBuf,
    // Explicit local upstream source paths, passed as data to Rust-authored fixtures.
    sources: Value,
    // Exported bootstrap and named machine variants inside the temporary snapshot.
    generated: PathBuf,
    // Human-readable and machine-readable evaluation evidence retained outside temporary state.
    logs: PathBuf,
    // Native authoring command whose exports, review and diagnostics are exercised.
    compiler: PathBuf,
    // Explicit Cargo-built Rusix fixture emitter.
    fixtures: PathBuf,
    // Baseline deferred VM factory expression emitted by the compiler.
    bootstrap: PathBuf,
    // Current checkout identity attached to the evaluation inputs.
    revision: String,
    // Prevents concurrent access to the isolated store and reuses identical expensive projections.
    cache: Mutex<BTreeMap<String, Reply>>,
}

/// Copy a prepared tree without following symlinks or carrying build/cache directories.
fn copy_tree(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        if [
            "target",
            "__pycache__",
            ".git",
            ".airlock-logs",
            ".venv",
            ".pytest_cache",
        ]
        .iter()
        .any(|ignored| name == *ignored)
        {
            continue;
        }
        let destination = target.join(&name);
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(entry.path())?, destination)?;
        } else if kind.is_dir() {
            copy_tree(&entry.path(), &destination)?;
        } else {
            fs::copy(entry.path(), destination)?;
        }
    }
    Ok(())
}

/// Require explicit sources and tools, then add test catalogs only to a private source copy.
fn context() -> Result<Arc<Nix>> {
    static CONTEXT: OnceLock<Mutex<Weak<Nix>>> = OnceLock::new();
    let mut shared = CONTEXT
        .get_or_init(|| Mutex::new(Weak::new()))
        .lock()
        .unwrap();
    if let Some(context) = shared.upgrade() {
        return Ok(context);
    }

    // Only active tests own the snapshot. The final Arc drops its temporary store,
    // including after a failed assertion; static caches must never own TempDir.
    let context = Arc::new(Nix::new()?);
    *shared = Arc::downgrade(&context);
    Ok(context)
}

impl Nix {
    /// Snapshot inputs once so parallel authoring edits cannot affect a running evaluation batch.
    fn new() -> Result<Self> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_owned();
        let temporary = tempfile::tempdir()?;
        let prepared = temporary.path().join("source");
        let configured = std::env::var("AIRLOCK_PREPARED_SOURCE")
            .context("set AIRLOCK_PREPARED_SOURCE to an explicitly prepared tree")?;
        copy_tree(
            Path::new(configured.strip_prefix("path:").unwrap_or(&configured)),
            &prepared,
        )?;

        let sources: Value = serde_json::from_slice(&fs::read(
            std::env::var("AIRLOCK_RUSIX_SOURCES")
                .context("set AIRLOCK_RUSIX_SOURCES to offline source paths JSON")?,
        )?)?;
        for path in sources.as_object().context("source map")?.values() {
            ensure!(
                Path::new(path.as_str().context("source path")?).is_dir(),
                "missing source: {path}"
            );
        }

        let machine_identity: Value = serde_json::from_slice(&fs::read(
            prepared.join("airlock-machine/airlock-source.json"),
        )?)?;
        let lock_hash = format!(
            "{hash:x}",
            hash = Sha256::digest(fs::read(prepared.join("airlock-machine/flake.lock"))?)
        );
        fs::write(
            temporary.path().join("offline-inputs.json"),
            serde_json::to_vec(&json!({
                "schema": "airlock.sys-agent-offline-inputs.v1", "revision": machine_identity["revision"],
                "lock_hash": lock_hash, "inputs": {}
            }))?,
        )?;

        let logs = std::env::var_os("AIRLOCK_RUSIX_LOG_DIR")
            .map(PathBuf::from)
            .map_or_else(
                || {
                    airlock_dev_paths::path("AIRLOCK_LOG_DIR", "logs")
                        .map(|path| path.join("nix-tests"))
                },
                Ok,
            )?;
        fs::create_dir_all(&logs)?;

        let compiler = common::binary("AIRLOCK_RUSIX_BIN", "airlock-config");
        let fixtures = common::binary("AIRLOCK_TEST_FIXTURES_BIN", "examples/test_fixtures");
        common::run(
            Command::new(&compiler)
                .arg("inspection")
                .arg(prepared.join("crates")),
            None,
        )?
        .checked()?;

        let generated = temporary.path().join("generated");
        // Full diagnostic exports include source maps for every machine profile.
        // Their preparation budget is separate from bounded runtime helper probes.
        support::run(
            Command::new(&compiler).arg("export").arg(&generated),
            None,
            Duration::from_secs(120),
        )?
        .checked()?;

        let bootstrap = temporary.path().join("bootstrap.nix");
        fs::write(
            &bootstrap,
            common::run(Command::new(&compiler).arg("bootstrap"), None)?.checked()?,
        )?;

        let revision = String::from_utf8(
            common::run(
                Command::new("git")
                    .args(["rev-parse", "HEAD"])
                    .current_dir(&root),
                None,
            )?
            .checked()?,
        )?
        .trim()
        .to_owned();

        let value = Self {
            temporary,
            root,
            prepared,
            sources,
            generated,
            logs,
            compiler,
            fixtures,
            bootstrap,
            revision,
            cache: Mutex::new(BTreeMap::new()),
        };

        for variant in [
            "source-conflict",
            "capture-renamed",
            "capture-none",
            "capture-shared",
        ] {
            value.fixture(
                "model/export",
                json!({"variant":variant,"output":value.generated.join(variant)}),
            )?;
        }

        value.fixture(
            "model/export",
            json!({
                "variant": "bootstrap",
                "output": value.generated.join("bootstrap-fixture")
            }),
        )?;

        Ok(value)
    }

    /// Ask the Rust fixture emitter for source; JSON arguments never become executable input text.
    fn fixture(&self, name: &str, inputs: Value) -> Result<String> {
        Ok(String::from_utf8(
            common::run(
                Command::new(&self.fixtures)
                    .arg(name)
                    .arg(serde_json::to_string(&inputs)?)
                    .current_dir(&self.root),
                None,
            )?
            .checked()?,
        )?)
    }

    /// Remove ambient host-store, label and user configuration influences.
    fn environment(&self, command: &mut Command) {
        for name in [
            "NIX_REMOTE",
            "NIX_STORE_DIR",
            "NIX_STATE_DIR",
            "NIX_LOG_DIR",
            "NIX_DAEMON_SOCKET_PATH",
            "NIXOS_LABEL",
            "NIXOS_LABEL_VERSION",
        ] {
            command.env_remove(name);
        }

        // Pinned local commits are valid test inputs before publication. Keep Git
        // resolution local even with an isolated Nix fetch cache.
        let count = std::env::var("GIT_CONFIG_COUNT")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let path: String = self
            .root
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .map(|byte| {
                if byte.is_ascii_alphanumeric() || b"/-._~".contains(byte) {
                    char::from(*byte).to_string()
                } else {
                    format!("%{byte:02X}")
                }
            })
            .collect();
        command
            .env(
                format!("GIT_CONFIG_KEY_{count}"),
                format!("url.file://{path}.insteadOf"),
            )
            .env(
                format!("GIT_CONFIG_VALUE_{count}"),
                "https://github.com/airlockos-org/airlockos.git",
            )
            .env("GIT_CONFIG_COUNT", (count + 1).to_string());

        let root = self.temporary.path();
        command
            .env(
                "AIRLOCK_MACHINE_OFFLINE_INPUTS",
                root.join("offline-inputs.json"),
            )
            .env("AIRLOCK_MACHINE_SEED_ARCHIVE", "")
            .env("NIX_CONFIG", "")
            .env("NIX_PATH", "")
            .env("NIX_CONF_DIR", root.join("config"))
            .env("NIX_USER_CONF_FILES", root.join("config/nix.conf"))
            .env("XDG_CACHE_HOME", root.join("cache"))
            .env("XDG_STATE_HOME", root.join("state"))
            .env("XDG_DATA_HOME", root.join("data"));
    }

    /// Evaluate one generated expression, saving exact inputs, command and diagnostics.
    fn evaluate(&self, name: &str, fixture: &str, inputs: Value) -> Result<Reply> {
        let key = format!("{fixture}:{inputs}");
        let mut cache = self.cache.lock().unwrap();
        if let Some(value) = cache.get(&key) {
            return Ok(value.clone());
        }
        let driver = self.temporary.path().join("driver.nix");
        fs::write(&driver, self.fixture(fixture, inputs.clone())?)?;
        let store = PathBuf::from(std::env::var_os("AIRLOCK_NIX_ROOT").context(
            "set AIRLOCK_NIX_ROOT to the guarded store containing explicitly archived flake sources",
        )?);
        ensure!(
            store.is_absolute() && store != Path::new("/"),
            "select the guarded Airlock source store"
        );
        let evaluation = self.temporary.path().join("store");
        let mut command = Command::new("nix");
        self.environment(&mut command);

        // Source attribution needs Nix's structured, complete merge diagnostic.
        // Ordinary projections keep concise logs, including unexpected failures.
        let conflict = inputs["conflict"] == true || inputs["desktopConflict"] == true;
        command
            .arg("--store")
            .arg(&store)
            .args([
                "--extra-experimental-features",
                "nix-command flakes",
                "--log-format",
                if conflict { "internal-json" } else { "raw" },
                "--option",
                "substituters",
                "",
                "--option",
                "builders",
                "",
                "--option",
                "build-users-group",
                "",
                "--option",
                "allow-import-from-derivation",
                // Image cache discovery explicitly realizes closureInfo inputs. Ordinary
                // configuration checks remain evaluation-only and reject implicit builds.
                if inputs["realizeImageInputs"] == true {
                    "true"
                } else {
                    "false"
                },
                "--offline",
                "eval",
                "--impure",
                "--json",
                "--eval-store",
            ])
            .arg(&evaluation)
            .arg("--file")
            .arg(&driver);
        if conflict {
            command.arg("--show-trace");
        }

        let digest = format!("{hash:x}", hash = Sha256::digest(key.as_bytes()));
        let prefix = self
            .logs
            .join(format!("{name}-{suffix}", suffix = &digest[..16]));
        fs::write(
            prefix.with_extension("inputs.json"),
            serde_json::to_vec_pretty(&inputs)?,
        )?;
        let arguments: Vec<_> = std::iter::once(command.get_program())
            .chain(command.get_args())
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        fs::write(
            prefix.with_extension("command.json"),
            serde_json::to_vec_pretty(&arguments)?,
        )?;
        let output = support::run(&mut command, None, Duration::from_secs(300))?;
        let result = Reply {
            success: output.status.success(),
            stdout: String::from_utf8(output.stdout)?,
            stderr: String::from_utf8(output.stderr)?,
            diagnostics: prefix.with_extension("stderr"),
        };
        fs::write(prefix.with_extension("stderr"), &result.stderr)?;
        fs::write(prefix.with_extension("json"), &result.stdout)?;
        cache.insert(key, result.clone());
        Ok(result)
    }

    /// Evaluate a named machine export with structured projection and override data.
    fn machine(&self, name: &str, variant: &str, overrides: Value) -> Result<Reply> {
        let mut inputs = self.sources.clone();
        inputs.as_object_mut().unwrap().extend(
            json!({
                "machine": self.prepared.join("airlock-machine"),
                "apps": self.prepared.join("crates"),
                "generated": self.generated,
                "variant": variant,
                "revision": self.revision
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        inputs
            .as_object_mut()
            .unwrap()
            .extend(overrides.as_object().context("override object")?.clone());

        self.evaluate(name, "machine", inputs)
    }

    /// Resolve an existing prepared nixpkgs source, requiring no fetch or package build.
    fn nixpkgs(&self) -> Result<PathBuf> {
        let path = std::env::var_os("NIXPKGS_SOURCE")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(self.sources["nixpkgsSource"].as_str().unwrap()));
        ensure!(
            path.join("lib/modules.nix").is_file(),
            "missing nixpkgs source: {path:?}"
        );
        Ok(path)
    }
}

impl Nix {
    /// Emit one isolated editable candidate using explicitly prepared authoring binaries and local upstream sources.
    fn candidate(&self, name: &str) -> Result<PathBuf> {
        let directory = self.temporary.path().join(format!("candidate-{name}"));
        copy_tree(
            &self
                .prepared
                .join("crates/airlock-config/templates/initial-runtime-config"),
            &directory,
        )?;
        fs::write(
            directory.join("config-inputs.json"),
            serde_json::to_vec_pretty(&json!({
                "nixpkgs": self.sources["nixpkgsSource"], "libvirt": self.sources["libvirtSource"], "qubes": self.sources["qubesSource"],
                "machine": self.prepared.join("airlock-machine"), "applications": self.prepared.join("crates")
            }))?,
        )?;
        common::run(
            Command::new(common::binary(
                "AIRLOCK_RUNTIME_CONFIG_BIN",
                "airlock-runtime-config",
            ))
            .arg("--emit")
            .arg(&directory)
            .current_dir(&directory),
            None,
        )?
        .checked()?;
        Ok(directory)
    }
}
