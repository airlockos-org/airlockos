//! Build immutable guest artifacts, then assemble a release in a separate evaluator.
//! Private records describe successful Nix realizations. They cannot authorize a build
//! or apply. The controller still checks source approval before invoking this worker.

use super::components::{self, MAX_GUESTS, Root, Scope};
use airlock_machine_planning::component_build::{completed, replay};
use airlock_nix_core::{
    identity::{GuestName, LockHash, SourceIdentity},
    runtime::{process, progress},
    state::{
        OperationKind, OperationOwner, RecordPermissions, RecordSnapshot, RecordWriter, StateStore,
        read_json,
    },
    store_path::StorePath,
};
use anyhow::{Context, Result, anyhow, ensure};
use rusix::{
    interop::{NixExpression, raw::NixValue},
    nix_record,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

const MAX_SLOTS: usize = MAX_GUESTS * 2 + 1;
const EVALUATION_LIMIT: Duration = Duration::from_secs(900);
const BUILD_LIMIT: Duration = Duration::from_secs(14400);
const QUERY_LIMIT: Duration = Duration::from_secs(120);
const RECORD_LIMIT: u64 = 256 * 1024;

/// Local build inputs supplied by the already authorized worker, never by an RPC payload.
pub struct Request<'a> {
    /// Published source artifact from the existing compiler and prepared-source cache.
    pub source: &'a Path,
    /// Private worker state for component records and Nix roots.
    pub state: &'a Path,
    /// Installed machine family, either `usb-lab` or `qemu-lab`.
    pub profile: &'a str,
    /// Absolute executable selecting the existing private Nix store.
    pub nix: &'a Path,
    /// Filesystem root under which the selected store exposes its logical `/nix/store`.
    pub store: &'a Path,
    /// Exact reviewed clean source in production. Local authoring may inspect dirty input.
    pub expected: Option<&'a SourceIdentity>,
}

/// A single realized `out` and its exact original recipe, using Nix's logical paths.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Recipe {
    /// Nix derivation which produced the immutable artifact.
    derivation: StorePath,
    /// Named `out` of this derivation, confirmed by Nix's realization response.
    output: StorePath,
}

/// One Nix CLI build reply. Timing and other upstream diagnostic fields are irrelevant.
#[derive(Deserialize)]
struct Realization {
    /// Recipe actually selected by Nix.
    #[serde(rename = "drvPath")]
    derivation: StorePath,
    /// Immutable path of each requested output.
    outputs: BTreeMap<String, StorePath>,
}

/// Last completed build for one component stage. Only the writer publishes this evidence.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    /// Stable stage identity, independent of its assigned retention slot.
    name: String,
    /// Full evaluation context digest, including already-realized dependency identities.
    input: LockHash,
    /// Immutable prepared source used by that evaluation.
    source: StorePath,
    /// Exact observed recipe and output, rechecked before reuse.
    recipe: Recipe,
}

type Slots = Vec<Option<Saved>>;

/// The locked profile record owns fixed retention slots; replacing a stage never
/// creates an unbounded history. A crash may leave a slot's roots newer than its
/// record. They are only retention hints: reuse rechecks the registered recipe
/// and realizes its exact output before passing it downstream.
struct Cache<'a> {
    /// Serializes writes and publishes each completed stage atomically.
    writer: RecordWriter<'a, Slots>,
    /// Opaque version bound to the record observed under that lock.
    snapshot: RecordSnapshot<Slots>,
    /// Active completion records and vacant slots, bounded by the machine size limit.
    slots: Slots,
    /// Nix's indirect roots for this profile, named only by slot number.
    links: PathBuf,
}

impl Cache<'_> {
    /// Drop obsolete retention slots and reject ambiguous persisted stage identities.
    fn open<'a>(
        store: &'a StateStore,
        profile: &str,
        links: PathBuf,
        wanted: &BTreeSet<String>,
    ) -> Result<Cache<'a>> {
        fs::create_dir_all(&links)?;
        let writer = store
            .record::<Slots>(profile.parse()?, RECORD_LIMIT)?
            .try_write(owner()?)?;
        let snapshot = writer.read()?;
        let mut slots = snapshot.value().cloned().unwrap_or_default();
        ensure!(
            slots.len() <= MAX_SLOTS,
            "component record exceeds its retention budget"
        );
        let mut names = BTreeSet::new();
        for saved in slots.iter().flatten() {
            ensure!(
                names.insert(&saved.name),
                "duplicate stage in component record"
            );
        }

        let mut changed = false;
        for (index, slot) in slots.iter_mut().enumerate() {
            if slot
                .as_ref()
                .is_some_and(|saved| !wanted.contains(&saved.name))
            {
                for kind in ["drv", "out"] {
                    match fs::remove_file(link(&links, index, kind)) {
                        Ok(()) => (),
                        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
                        Err(error) => return Err(error.into()),
                    }
                }
                *slot = None;
                changed = true;
            }
        }
        slots.resize_with(MAX_SLOTS, || None);
        let mut cache = Cache {
            writer,
            snapshot,
            slots,
            links,
        };
        if changed {
            cache.publish()?;
        }
        Ok(cache)
    }

    /// Find the existing stage slot or the first free slot without changing durable state.
    fn slot(&self, name: &str) -> Result<usize> {
        self.slots
            .iter()
            .position(|saved| saved.as_ref().is_some_and(|saved| saved.name == name))
            .or_else(|| self.slots.iter().position(Option::is_none))
            .context("component retention slots exhausted")
    }

    /// Acknowledge completion only after the existing record writer's durable commit.
    fn publish(&mut self) -> Result<()> {
        self.writer
            .commit(&self.snapshot, &self.slots, RecordPermissions::Private)?;
        self.snapshot = self.writer.read()?;
        Ok(())
    }
}

/// Fixed roots prevent arbitrary cached paths from naming filesystem effects.
fn link(directory: &Path, slot: usize, kind: &str) -> PathBuf {
    directory.join(format!("component-{slot}-{kind}"))
}

/// Diagnostic lock owner for the existing operation and record lock mechanisms.
fn owner() -> airlock_nix_core::Result<OperationOwner> {
    OperationOwner::new(
        "machine worker".into(),
        "evaluate machine components serially".into(),
        OperationKind::Build,
    )
}

/// A fixed evaluator/store selection for this operation. Nix owns store registration,
/// derivation semantics and the build budget configured for the private worker.
struct Nix<'a> {
    /// Absolute executable or installed private-store wrapper.
    program: &'a Path,
    /// Physical store root used when the evaluator opens a flake source.
    store: &'a Path,
    /// Digest of the effective evaluator configuration; raw settings can contain secrets.
    configuration: LockHash,
}

/// Use the same executable and feature set for preparation and evaluation.
fn command(program: &Path) -> Command {
    let mut command = Command::new(program);
    command.args(["--extra-experimental-features", "nix-command flakes"]);
    command
}

/// Derive a content identity using serde's deterministic encoding of the declared inputs.
fn digest(value: &impl Serialize) -> Result<LockHash> {
    Ok(format!(
        "{digest:x}",
        digest = Sha256::digest(serde_json::to_vec(value)?)
    )
    .parse()?)
}

/// Decode one bounded Nix reply using the existing duplicate-key-free reader.
fn reply<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    Ok(airlock_nix_core::state::parse_json(
        bytes,
        Path::new("Nix response"),
    )?)
}

/// Bound each child independently; no VM module graph stays resident between stages.
fn run(command: &mut Command, limit: Duration, label: &str) -> Result<Vec<u8>> {
    Ok(process::run_forwarded(command, None, Some(limit))?.checked(label)?)
}

impl<'a> Nix<'a> {
    /// Bind reuse to the full effective configuration without persisting tokens or settings.
    fn open(program: &'a Path, store: &'a Path) -> Result<Self> {
        ensure!(
            program.is_absolute() && store.is_absolute(),
            "component evaluator and store must be absolute"
        );
        let config = process::run(
            command(program).args(["config", "show", "--json"]),
            None,
            Some(QUERY_LIMIT),
        )?;
        ensure!(
            config.status.success(),
            "cannot identify effective Nix configuration"
        );
        let configuration =
            format!("{digest:x}", digest = Sha256::digest(config.stdout)).parse()?;
        Ok(Self {
            program,
            store,
            configuration,
        })
    }

    /// A prefixed private store has logical identities and separate filesystem paths.
    fn physical(&self, path: &StorePath) -> PathBuf {
        self.store.join(path.as_str().trim_start_matches('/'))
    }

    /// Query the existing store before treating a recipe as replayable.
    fn registered(&self, path: &StorePath) -> Result<bool> {
        if !path.as_str().ends_with(".drv") || !self.physical(path).is_file() {
            return Ok(false);
        }
        Ok(process::run(
            command(self.program).args(["path-info", "--json", path.as_str()]),
            None,
            Some(QUERY_LIMIT),
        )?
        .status
        .success())
    }

    /// Evaluate a single flake output in pure mode with its captured lock unchanged.
    fn evaluate(&self, root: &Root, attribute: &str, apply: &str) -> Result<Recipe> {
        let source = format!(
            "path:{path}#{attribute}",
            path = self.physical(&root.source).display()
        );
        let result: Recipe = reply(&run(
            command(self.program).args([
                "eval",
                "--json",
                "--no-update-lock-file",
                "--no-write-lock-file",
                "--option",
                "pure-eval",
                "true",
                "--apply",
                apply,
                &source,
            ]),
            EVALUATION_LIMIT,
            "evaluate component recipe",
        )?)?;
        ensure!(
            result.derivation.as_str().ends_with(".drv"),
            "Nix did not return a component derivation"
        );
        Ok(result)
    }

    /// Root the recipe object itself, then realize exactly its `out` and root that output.
    /// This also handles a collected output without evaluating the source again.
    fn realize(&self, recipe: &Recipe, directory: &Path, slot: usize) -> Result<()> {
        let expression =
            expression(NixValue::builtin("storePath").call(recipe.derivation.as_str()))?;
        let rooted = run(
            command(self.program)
                .args([
                    "build",
                    "--impure",
                    "--expr",
                    &expression,
                    "--print-out-paths",
                    "--out-link",
                ])
                .arg(link(directory, slot, "drv")),
            QUERY_LIMIT,
            "retain component recipe",
        )?;
        ensure!(
            std::str::from_utf8(&rooted)?.trim() == recipe.derivation.as_str(),
            "Nix rooted a different recipe"
        );

        let installable = format!("{derivation}^out", derivation = recipe.derivation);
        let response: Vec<Realization> = reply(&run(
            command(self.program)
                .args(["build", "--json", &installable, "--out-link"])
                .arg(link(directory, slot, "out")),
            BUILD_LIMIT,
            "realize component output",
        )?)?;
        let [result] = response.as_slice() else {
            anyhow::bail!("expected exactly one realized component")
        };
        let actual = result
            .outputs
            .get("out")
            .context("realization is missing its out output")?;
        ensure!(
            result.outputs.len() == 1
                && completed(
                    recipe.derivation.as_str(),
                    recipe.output.as_str(),
                    result.derivation.as_str(),
                    actual.as_str(),
                )
                && self.physical(actual).try_exists()?,
            "realized component differs from evaluated recipe"
        );
        Ok(())
    }
}

/// Render trusted authoring code with request values embedded only as serialized data.
fn expression(value: NixValue) -> Result<String> {
    Ok(rusix::compile_value(value)
        .map_err(|error| anyhow!("{}", error.render(Path::new("."))))?
        .source)
}

/// Keep the full dynamic request in the identity, including completed dependency pairs.
fn select_recipe(arguments: Option<&Value>) -> Result<String> {
    let arguments = arguments.map(serde_json::to_string).transpose()?;
    expression(NixValue::function(|value| {
        let selected = match &arguments {
            Some(arguments) => value.call(NixValue::builtin("fromJSON").call(arguments.clone())),
            None => value,
        };
        selected.bind(|recipe| {
            nix_record! {
                "derivation": recipe.clone().select("drvPath"),
                "output": recipe.select("outPath"),
            }
        })
    }))
}

/// Complete one stage before publishing it; incomplete or mismatched work is never evidence.
fn stage(
    nix: &Nix<'_>,
    cache: &mut Cache<'_>,
    name: &str,
    root: &Root,
    attribute: &str,
    args: Option<&Value>,
) -> Result<Saved> {
    let apply = select_recipe(args)?;
    let input = digest(&(
        "airlock.component-recipe.v1",
        &root.source,
        &root.platform,
        &root.profile,
        &root.evaluator,
        &nix.configuration,
        nix.store,
        attribute,
        &apply,
    ))?;
    let slot = cache.slot(name)?;
    let previous = cache.slots[slot].as_ref();
    let retained = match previous {
        Some(saved)
            if saved.source == root.source
                && saved.input == input
                && replay(
                    input.as_str(),
                    saved.input.as_str(),
                    nix.registered(&saved.recipe.derivation)?,
                ) =>
        {
            Some(saved.recipe.clone())
        }
        _ => None,
    };

    let mut span = progress::Span::start(&format!("component_{name}"));
    span.update(
        json!({"component":name, "reused_evaluation":retained.is_some(), "scope":root.scope}),
    );
    let recipe = match retained {
        Some(recipe) => recipe,
        None => progress::phase("evaluating_component", || {
            nix.evaluate(root, attribute, &apply)
        })
        .with_context(|| format!("evaluate {name}"))?,
    };
    progress::phase("realizing_component", || {
        nix.realize(&recipe, &cache.links, slot)
    })
    .with_context(|| format!("realize {name}"))?;

    let saved = Saved {
        name: name.into(),
        input,
        source: root.source.clone(),
        recipe,
    };
    if previous != Some(&saved) {
        cache.slots[slot] = Some(saved.clone());
        cache.publish()?;
    }
    span.complete();
    Ok(saved)
}

/// Bind the immutable machine snapshot to the controller's original clean source identity.
fn provenance(
    nix: &Nix<'_>,
    root: &Root,
    expected: Option<&SourceIdentity>,
) -> Result<SourceIdentity> {
    let source = nix.physical(&root.source);
    let identity: Value = read_json(&source.join("airlock-source.json"), 4096)?;
    let revision = identity["revision"]
        .as_str()
        .context("captured machine has no revision")?
        .parse()?;
    let lock_hash = format!(
        "{digest:x}",
        digest = Sha256::digest(fs::read(source.join("flake.lock"))?)
    )
    .parse()?;
    let observed = SourceIdentity {
        revision,
        lock_hash,
    };
    if let Some(expected) = expected {
        ensure!(
            &observed == expected && identity["dirty"] == false,
            "component source differs from the reviewed clean machine"
        );
    }
    Ok(observed)
}

/// Build a machine from the prepared roots, retaining completed stages through interruption.
/// One operation lock admits one evaluator at a time. A release is returned only
/// after every declared guest and the final host recipe have realized successfully.
/// Cache records are local observations; neither this function nor its output can apply a release.
pub fn build(request: Request<'_>) -> Result<StorePath> {
    ensure!(
        matches!(request.profile, "usb-lab" | "qemu-lab"),
        "unsupported component build profile"
    );
    let state = request.state.join("component-builds");
    fs::create_dir_all(&state)?;
    let store = StateStore::initialize(&state)?;
    let operation = store.try_operation(&"machine-evaluation".parse()?, owner()?)?;
    let nix = Nix::open(request.nix, request.store)?;
    let inputs = progress::phase("preparing_component_inputs", || {
        components::prepare(request.source, &state, request.profile, &|| {
            command(nix.program)
        })
    })
    .map_err(|error| anyhow!("{error}"))?;
    let roots = inputs.roots();
    let host = roots
        .get("dom0")
        .context("prepared source has no host component")?;
    let identity = provenance(&nix, host, request.expected)?;
    let guests: BTreeSet<_> = host.dependencies.iter().map(GuestName::as_str).collect();
    ensure!(
        guests.len() <= MAX_GUESTS
            && !guests.contains("dom0")
            && guests.len() == host.dependencies.len()
            && guests.len() + 1 == roots.len()
            && guests.iter().all(|name| roots.contains_key(*name)),
        "host component has missing, duplicate or excessive guest dependencies"
    );

    let mut wanted = BTreeSet::from(["dom0".to_owned()]);
    for name in &guests {
        wanted.insert(format!("guest-{name}"));
        if matches!(roots[*name].scope, Scope::Hermit { .. }) {
            wanted.insert(format!("native-{name}"));
        }
    }
    let mut cache = Cache::open(
        &store,
        request.profile,
        state.join("roots").join(request.profile),
        &wanted,
    )?;
    let mut evidence = BTreeMap::new();
    let mut descriptors = BTreeMap::new();
    for name in &host.dependencies {
        operation.check_path()?;
        let root = &roots[name.as_str()];
        let native = if matches!(root.scope, Scope::Hermit { .. }) {
            let result = stage(
                &nix,
                &mut cache,
                &format!("native-{name}"),
                root,
                "packages.x86_64-linux.default",
                None,
            )?;
            let recipe = result.recipe.clone();
            evidence.insert(result.name.clone(), result);
            Some(recipe)
        } else {
            None
        };
        // Native compilation is independent; topology and release provenance are
        // still derived from the current full reviewed source by its constructor.
        let args = json!({"profile":request.profile, "name":name, "native":native});
        let result = stage(
            &nix,
            &mut cache,
            &format!("guest-{name}"),
            host,
            "airlock.buildGuestComponent",
            Some(&args),
        )?;
        descriptors.insert(name, result.recipe.clone());
        evidence.insert(result.name.clone(), result);
    }

    operation.check_path()?;
    let args = json!({"profile":request.profile, "guests":descriptors, "evidence":{
        "schema":"airlock.component-builds.v1", "source":identity, "components":evidence,
    }});
    let release = stage(
        &nix,
        &mut cache,
        "dom0",
        host,
        "airlock.assembleComponentRelease",
        Some(&args),
    )?;
    operation.check_path()?;
    Ok(release.recipe.output)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A partial previous build keeps its usable stages and releases retired slots.
    #[test]
    fn partial_build_preserves_matching_stage_slots() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = StateStore::initialize(directory.path())?;
        let links = directory.path().join("roots");
        let mut cache = Cache::open(
            &store,
            "usb-lab",
            links.clone(),
            &BTreeSet::from([
                "guest-usr-home".into(),
                "guest-usr-retired".into(),
                "dom0".into(),
            ]),
        )?;
        let evidence = |name: &str| -> Result<Saved> {
            Ok(Saved {
                name: name.into(),
                input: digest(&name)?,
                source: "/nix/store/00000000000000000000000000000000-input".parse()?,
                recipe: Recipe {
                    derivation: "/nix/store/00000000000000000000000000000000-component.drv"
                        .parse()?,
                    output: "/nix/store/00000000000000000000000000000000-component".parse()?,
                },
            })
        };
        cache.slots[0] = Some(evidence("guest-usr-home")?);
        cache.slots[1] = Some(evidence("guest-usr-retired")?);
        std::os::unix::fs::symlink("retired-recipe", link(&links, 1, "drv"))?;
        cache.publish()?;
        drop(cache);

        let resumed = Cache::open(
            &store,
            "usb-lab",
            links.clone(),
            &BTreeSet::from(["guest-usr-home".into(), "dom0".into()]),
        )?;
        assert_eq!(
            resumed.slots[resumed.slot("guest-usr-home")?]
                .as_ref()
                .map(|saved| &saved.input),
            Some(&digest(&"guest-usr-home")?)
        );
        assert!(resumed.slots[resumed.slot("dom0")?].is_none());
        assert_eq!(
            fs::symlink_metadata(link(&links, 1, "drv"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        Ok(())
    }
}
