//! Select the exact authoring source after normal controller approval, before compiler reuse.
//! Nix owns Git fetching, recursive hash validation and GC roots. Image metadata is
//! trusted build evidence; it permits reuse only for the same pinned Git tree.

use super::*;
use airlock_machine_planning::application_source::matches_pin;

/// One parsed application input. Nix interprets the opaque fetcher attributes.
struct Pin {
    /// Full Git identity from the machine's locked application input.
    revision: GitRevision,
    /// Recursive source hash interpreted and checked by Nix, not by a custom parser.
    hash: String,
    /// Original locked fetcher attributes, excluding the separately applied crates directory.
    fetch: Value,
}

impl Pin {
    /// Validate the supported application-input shape before delegating source retrieval to Nix.
    fn read(value: &Value) -> Result<Self> {
        ensure!(
            value["type"] == "git" && value["dir"] == "crates",
            "application source must be a locked Git input with dir=crates"
        );
        let revision = value["rev"]
            .as_str()
            .context("application input has no locked revision")?
            .parse()?;
        let hash = value["narHash"]
            .as_str()
            .context("application input has no recursive tree hash")?
            .to_owned();
        ensure!(
            !hash.is_empty(),
            "application input has an empty recursive tree hash"
        );
        let mut fetch = value.clone();
        fetch
            .as_object_mut()
            .context("application input is not an object")?
            .remove("dir");
        Ok(Self {
            revision,
            hash,
            fetch,
        })
    }
}

/// Source retained until the build helper exits; no source-selection cache grants approval.
pub(super) struct Selected {
    /// Actual compiler/Cargo input, either the image's prepared workspace or the fetched tree.
    pub(super) path: PathBuf,
    /// Exact revision shared by the machine pin, lock and source observation.
    pub(super) revision: GitRevision,
    /// Whether immutable image inputs supplied this operation's source.
    pub(super) image: bool,
    /// Nix's indirect GC root owns newly fetched source through preparation and building.
    _root: Option<tempfile::TempDir>,
}

impl Selected {
    /// Pass the same source to cached-compiler checks, Cargo and generated crate recipes.
    pub(super) fn command(&self, program: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut command = Command::new(program);
        command
            .env("AIRLOCK_APPS", &self.path)
            .env("AIRLOCK_PREPARED_APPLICATIONS", &self.path)
            .env("AIRLOCK_APPLICATION_REVISION", self.revision.as_str())
            .env(
                "AIRLOCK_CARGO_VENDOR",
                std::env::var_os("AIRLOCK_CARGO_VENDOR")
                    .unwrap_or_else(|| "/etc/airlock/authoring/vendor".into()),
            )
            .env(
                "AIRLOCK_PACKER_CARGO_VENDOR",
                std::env::var_os("AIRLOCK_PACKER_CARGO_VENDOR")
                    .unwrap_or_else(|| "/etc/airlock/authoring/packer-vendor".into()),
            );
        command
    }
}

/// Select from the reviewed lock before executing any machine compiler. A missing
/// image binding causes a normal Nix fetch; a failed fetch never falls back to image code.
pub(super) fn select(request: &Request, offline: bool) -> Result<Selected> {
    let mut revision = String::new();
    File::open(request.repo.join("application-revision"))?
        .take(129)
        .read_to_string(&mut revision)?;
    ensure!(
        revision.len() <= 128,
        "application revision file exceeds its size limit"
    );
    let requested: GitRevision = revision.trim().parse()?;
    let lock = read(&request.repo.join("flake.lock"))?;
    let root = lock["root"]
        .as_str()
        .context("dependency lock has no root")?;
    let node = lock["nodes"][root]["inputs"]["airlock-apps"]
        .as_str()
        .context("application input must reference an explicit locked node")?;
    let pin = Pin::read(&lock["nodes"][node]["locked"])?;
    ensure!(
        matches_pin(
            requested.as_str(),
            pin.revision.as_str(),
            &pin.hash,
            pin.revision.as_str(),
            &pin.hash
        ),
        "application-revision differs from the locked application source"
    );

    if request.applications_binding.try_exists()? {
        let binding = read(&request.applications_binding)?;
        ensure!(
            binding["schema"] == "airlock.authoring-applications.v1",
            "unsupported installed application-source binding"
        );
        let installed = Pin::read(&binding["locked"])?;
        if matches_pin(
            requested.as_str(),
            pin.revision.as_str(),
            &pin.hash,
            installed.revision.as_str(),
            &installed.hash,
        ) {
            let path: StorePath = binding["applications"]
                .as_str()
                .context("installed application binding has no store path")?
                .parse()?;
            let path = if Path::new(path.as_str()).is_dir() {
                PathBuf::from(path.as_str())
            } else {
                request.store.join(path.as_str().trim_start_matches('/'))
            };
            ensure!(
                path.is_dir(),
                "matching installed application source is unavailable"
            );
            return Ok(Selected {
                path: fs::canonicalize(path)?,
                revision: requested,
                image: true,
                _root: None,
            });
        }
    }

    // Keep fetcher semantics and hash validation in Nix. The separate JSON input
    // carries URLs as data, including quotes or interpolation-like text.
    let root = tempfile::Builder::new()
        .prefix("application-source-")
        .tempdir_in(&request.state)?;
    fs::write(
        root.path().join("locked.json"),
        serde_json::to_vec(&pin.fetch)?,
    )?;
    let expression = root.path().join("fetch.nix");
    // An `outPath` field would make Nix serialize this whole record as a path
    // string. Keep the observation fields available for the binding check.
    fs::write(
        &expression,
        r#"
let
  source = builtins.fetchTree (builtins.fromJSON (builtins.readFile ./locked.json));
in { path = source.outPath; inherit (source) rev narHash; }
"#,
    )?;
    let mut fetch = Command::new("airlock-config-nix");
    fetch.args(["eval", "--json", "--file"]).arg(&expression);
    if offline {
        fetch.arg("--offline");
    }
    let fetched: Value = serde_json::from_str(
        &text(&mut fetch)
            .context("selected application source is unavailable; refusing to use image source")?,
    )?;
    ensure!(
        matches_pin(
            requested.as_str(),
            pin.revision.as_str(),
            &pin.hash,
            fetched["rev"]
                .as_str()
                .context("Nix source has no revision")?,
            fetched["narHash"]
                .as_str()
                .context("Nix source has no tree hash")?
        ),
        "Nix application source differs from the reviewed pin"
    );
    let source: StorePath = fetched["path"]
        .as_str()
        .context("Nix source has no store path")?
        .parse()?;
    let mut retain = Command::new("airlock-config-nix");
    retain
        .args([
            "build",
            source.as_str(),
            "--no-write-lock-file",
            "--out-link",
        ])
        .arg(root.path().join("source"));
    if offline {
        retain.arg("--offline");
    }
    text(&mut retain)?;
    let store_source =
        fs::canonicalize(request.store.join(source.as_str().trim_start_matches('/')))?;
    let path = fs::canonicalize(store_source.join("crates"))?;
    ensure!(
        path.is_dir() && path.starts_with(&store_source),
        "selected application workspace is missing or escapes its immutable source tree"
    );
    Ok(Selected {
        path,
        revision: requested,
        image: false,
        _root: Some(root),
    })
}
