//! Query completed builds without compiling or evaluating source. Nix owns dependency
//! traversal, validity and metadata; serde owns its JSON representation. The recipe marker
//! selects reusable build inputs, never authority. Dom0 separately authenticates review.

use crate::{
    identity::{GitRevision, GuestName, LockHash, ReviewId},
    runtime::process,
    store_path::StorePath,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    process::Command,
    time::Duration,
};

/// Publication protocol, distinct from deployment and guest activation.
pub const SCHEMA: &str = "airlock.build-publication.v1";

/// Retained software namespace for admitted compilation inputs; it is never a guest activation target.
pub const DOMAIN: &str = "sys-ctrl-build-inputs";

/// Maximum reference-complete inventory accepted by the existing transfer boundary.
pub const MAX_PATHS: usize = airlock_machine_planning::build_publication::MAX_OBJECTS;

/// Uncompressed transfer ceiling, additionally restricted by receiver free space.
pub const MAX_BYTES: u64 = airlock_machine_planning::build_publication::MAX_BYTES;

/// Exact approved build and requested immutable objects. Decoding this grants no authority.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Closed protocol version checked before import.
    pub schema: String,
    /// Protected source-review request, reauthenticated in dom0 before publication.
    pub review_authorization: ReviewId,
    /// Original reviewed machine source commit.
    pub revision: GitRevision,
    /// Original reviewed dependency lock digest.
    pub lock_hash: LockHash,
    /// Guest scope; absence identifies a whole-machine build.
    pub target: Option<GuestName>,
    /// Completed build output, used as identity rather than transferred VM payload.
    pub result: StorePath,
    /// Original derivation whose declared outputs must contain that result.
    pub derivation: StorePath,
    /// Complete selected closure and its actual uncompressed NAR sizes.
    pub paths: BTreeMap<StorePath, u64>,
    /// Derivation/source metadata imported first; compiled object bytes go directly to the pool.
    pub metadata: BTreeMap<StorePath, u64>,
    /// Exact Nix dump/load registration accompanying the later pool artifact stream.
    pub registration_sha256: LockHash,
}

impl Request {
    /// Reject unsupported, oversized or incomplete request envelopes before importing bytes.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == SCHEMA,
            "unsupported build publication schema"
        );
        ensure!(
            self.derivation.as_str().ends_with(".drv"),
            "build derivation required"
        );
        ensure!(
            !self.paths.is_empty()
                && self.paths.len() <= MAX_PATHS
                && self.paths.contains_key(&self.derivation),
            "invalid build inventory"
        );
        ensure!(
            !self.metadata.is_empty()
                && self.metadata.contains_key(&self.derivation)
                && self
                    .metadata
                    .iter()
                    .all(|(path, size)| self.paths.get(path) == Some(size)),
            "derivation metadata differs from build inventory"
        );
        let total = self.paths.values().try_fold(0u64, |sum, size| {
            airlock_machine_planning::build_publication::charge(self.paths.len(), sum, *size)
                .context("build inventory exceeds its count or byte limit")
        })?;
        ensure!(
            total <= MAX_BYTES,
            "build publication exceeds transfer budget"
        );
        Ok(())
    }

    /// Compare the exact Nix registration bytes bound before pool negotiation.
    pub fn check_registration(&self, registration: &str) -> Result<()> {
        ensure!(
            registration_hash(registration)? == self.registration_sha256,
            "build registration differs from protected publication request"
        );
        Ok(())
    }

    /// Bind retries and persistence to every field, including exact package variants and sizes.
    pub fn fingerprint(&self) -> Result<LockHash> {
        Ok(format!(
            "{digest:x}",
            digest = Sha256::digest(serde_json::to_vec(self)?)
        )
        .parse()?)
    }
}

/// Installed Nix adapters; callers choose the existing worker overlay or host store.
pub struct Tools<'a> {
    /// Nix command for reading derivations and path metadata.
    pub nix: &'a str,
    /// Nix store command for querying registered closures and exporting registrations.
    pub nix_store: &'a str,
}

/// Completed-build observations split by their two transfer destinations.
pub struct Inventory {
    /// Full reference-complete compilation input closure, admitted directly into the shared pool.
    pub paths: BTreeMap<StorePath, u64>,
    /// Original derivation and its source closure, authenticated in dom0 before pool admission.
    pub metadata: BTreeMap<StorePath, u64>,
}

impl Tools<'_> {
    /// Query a completed result's recorded derivation without evaluating or building anything.
    pub fn deriver(&self, result: &StorePath) -> Result<StorePath> {
        let raw = self.run(self.nix_store, &["--query", "--deriver", result.as_str()])?;
        Ok(std::str::from_utf8(&raw)?.trim().parse()?)
    }

    fn run(&self, program: &str, args: &[&str]) -> Result<Vec<u8>> {
        Ok(process::run(
            Command::new(program).args(args),
            None,
            Some(Duration::from_secs(120)),
        )?
        .checked("query completed build inputs")?)
    }

    fn query(&self, roots: &[StorePath], outputs: bool) -> Result<BTreeSet<StorePath>> {
        let mut result = BTreeSet::new();
        for chunk in roots.chunks(128) {
            let mut args = vec!["--query", "--requisites"];
            if outputs {
                args.push("--include-outputs");
            }
            args.extend(chunk.iter().map(StorePath::as_str));
            for line in std::str::from_utf8(&self.run(self.nix_store, &args)?)?.lines() {
                result.insert(line.parse()?);
                ensure!(
                    result.len() <= MAX_PATHS,
                    "build closure exceeds object limit"
                );
            }
        }
        Ok(result)
    }

    /// Read bounded batches of recipes; Nix computes the complete dependency traversal.
    fn recipes(&self, derivation: &StorePath, result: &StorePath) -> Result<Recipes> {
        let metadata = self.query(std::slice::from_ref(derivation), false)?;
        let derivations: Vec<_> = metadata
            .iter()
            .filter(|p| p.as_str().ends_with(".drv"))
            .cloned()
            .collect();
        let mut selected = Vec::new();
        let mut outputs = BTreeMap::new();
        let mut matched_result = false;
        for chunk in derivations.chunks(32) {
            let mut args = vec!["derivation", "show", "--no-pretty"];
            args.extend(chunk.iter().map(StorePath::as_str));
            let raw: Value = serde_json::from_slice(&self.run(self.nix, &args)?)?;
            let graph = if let Some(version) = raw.get("version") {
                ensure!(version == 4, "unsupported Nix derivation JSON version");
                &raw["derivations"]
            } else {
                &raw
            };
            let mut received = BTreeSet::new();
            for (name, entry) in graph.as_object().context("invalid Nix derivation JSON")? {
                let path = store_path(name)?;
                ensure!(
                    chunk.contains(&path) && received.insert(path.clone()),
                    "unexpected Nix derivation response"
                );
                let declared: BTreeSet<_> = entry["outputs"]
                    .as_object()
                    .context("missing derivation outputs")?
                    .values()
                    .filter_map(|output| output["path"].as_str())
                    .map(store_path)
                    .collect::<Result<_>>()?;
                if &path == derivation {
                    matched_result = declared.contains(result);
                }
                if entry["env"]["AIRLOCK_BUILD_ARTIFACT"] == "1"
                    || entry["structuredAttrs"]["AIRLOCK_BUILD_ARTIFACT"] == "1"
                {
                    selected.push(path.clone());
                }
                outputs.insert(path, declared);
            }
            ensure!(
                received.len() == chunk.len(),
                "incomplete Nix derivation response"
            );
        }
        ensure!(
            matched_result,
            "completed result differs from original derivation"
        );
        ensure!(
            !selected.is_empty(),
            "build has no reusable Airlock application recipes"
        );
        Ok(Recipes {
            metadata,
            selected,
            outputs,
        })
    }

    /// Read actual NAR sizes from Nix, accepting its supported array/map response forms.
    pub fn metadata(&self, paths: &BTreeSet<StorePath>) -> Result<BTreeMap<StorePath, u64>> {
        let ordered: Vec<_> = paths.iter().cloned().collect();
        let mut result = BTreeMap::new();
        for chunk in ordered.chunks(128) {
            let mut args = vec!["path-info", "--json"];
            args.extend(chunk.iter().map(StorePath::as_str));
            let raw: Value = serde_json::from_slice(&self.run(self.nix, &args)?)?;
            let entries: Vec<_> = match &raw {
                Value::Array(entries) => entries
                    .iter()
                    .map(|v| {
                        Ok((
                            v["path"]
                                .as_str()
                                .context("missing Nix path")?
                                .parse::<StorePath>()?,
                            v,
                        ))
                    })
                    .collect::<Result<_>>()?,
                Value::Object(entries) => entries
                    .iter()
                    .map(|(path, value)| Ok((path.parse::<StorePath>()?, value)))
                    .collect::<Result<_>>()?,
                _ => anyhow::bail!("invalid Nix path metadata"),
            };
            for (path, value) in entries {
                ensure!(chunk.contains(&path), "unexpected Nix metadata path");
                ensure!(
                    result
                        .insert(path, value["narSize"].as_u64().context("missing NAR size")?)
                        .is_none(),
                    "duplicate Nix metadata path"
                );
            }
        }
        ensure!(
            result.keys().cloned().collect::<BTreeSet<_>>() == *paths,
            "incomplete Nix metadata"
        );
        Ok(result)
    }

    /// Inventory registered objects of the completed build and its selected application recipes.
    pub fn inventory(&self, derivation: &StorePath, result: &StorePath) -> Result<Inventory> {
        let recipes = self.recipes(derivation, result)?;
        let metadata = self.metadata(&recipes.metadata)?;
        let mut paths = recipes.metadata;
        paths.extend(self.query(&recipes.selected, true)?);
        ensure!(
            paths.len() <= MAX_PATHS,
            "build closure exceeds object limit"
        );
        Ok(Inventory {
            paths: self.metadata(&paths)?,
            metadata,
        })
    }

    /// Verify the first transfer without requiring compiled objects in dom0's own Nix store.
    /// Allowed package identities come from the original recipes, including target/feature variants.
    pub fn prepare(&self, request: &Request) -> Result<()> {
        request.validate()?;
        let recipes = self.recipes(&request.derivation, &request.result)?;
        ensure!(
            self.metadata(&recipes.metadata)? == request.metadata,
            "imported build recipe metadata differs"
        );
        let inputs = self.query(&recipes.selected, false)?;
        let mut allowed = recipes.metadata;
        for (derivation, outputs) in recipes.outputs {
            if inputs.contains(&derivation) {
                allowed.extend(outputs);
            }
        }
        allowed.extend(inputs);
        ensure!(
            request.paths.keys().all(|path| allowed.contains(path)),
            "publication includes unrelated build objects"
        );
        Ok(())
    }

    /// Preserve Nix's own dump/load representation rather than inventing a registration encoder.
    pub fn registration(&self, paths: &BTreeMap<StorePath, u64>) -> Result<String> {
        let ordered: Vec<_> = paths.keys().collect();
        let mut registration = String::new();
        for chunk in ordered.chunks(128) {
            let mut args = vec!["--dump-db"];
            args.extend(chunk.iter().map(|path| path.as_str()));
            registration.push_str(std::str::from_utf8(&self.run(self.nix_store, &args)?)?);
            ensure!(
                registration.len() <= 64 * 1024 * 1024,
                "build registration exceeds limit"
            );
        }
        Ok(registration)
    }
}

/// Nix JSON v4 uses store basenames; earlier supported output uses absolute store paths.
fn store_path(value: &str) -> Result<StorePath> {
    Ok(if value.starts_with("/nix/store/") {
        value.to_owned()
    } else {
        format!("/nix/store/{value}")
    }
    .parse()?)
}

/// Hash the unchanged upstream registration representation with the existing digest library.
pub fn registration_hash(registration: &str) -> Result<LockHash> {
    Ok(format!(
        "{digest:x}",
        digest = Sha256::digest(registration.as_bytes())
    )
    .parse()?)
}

/// Recipe observations, not authority to publish their declared outputs.
struct Recipes {
    // Complete registered derivation/source closure returned by Nix.
    metadata: BTreeSet<StorePath>,
    // Actual marked application recipes inside that closure.
    selected: Vec<StorePath>,
    // Declared output identities, including outputs not yet present on the receiver.
    outputs: BTreeMap<StorePath, BTreeSet<StorePath>>,
}
