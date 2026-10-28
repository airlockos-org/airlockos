//! Keep authenticated image inputs alive through the actual upstream builder invocation.
//! Verus checks completeness and binding; filesystem observations and faithful builder execution
//! remain trusted. File stamps detect changes between verification and launch, not future health.

use super::{ValidatedHost, builder, fs::*, host, prepared, records};
use airlock_deployment_core::boot::artifacts::{CheckedImage, Identity, Profile};
use airlock_machine_core::boot::artifacts::SelectedBoot;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    process::Command,
};

#[derive(PartialEq, Eq)]
struct Stamp {
    // Filesystem and inode distinguish replaced objects with identical sizes.
    device: u64,
    // Identity within the original filesystem.
    inode: u64,
    // Length checked alongside the image fingerprint.
    bytes: u64,
    // Last content change, retaining subsecond precision.
    modified: (i64, i64),
    // Metadata changes catch renames, replacements and timestamp restoration.
    changed: (i64, i64),
    // File kind and permissions observed during verification.
    mode: u32,
}

/// Observe the same file identity before validation and immediately before execution.
fn stamp(path: &Path) -> Result<Stamp> {
    let m = fs::symlink_metadata(path)
        .with_context(|| format!("observe image input {path}", path = path.display()))?;
    Ok(Stamp {
        device: m.dev(),
        inode: m.ino(),
        bytes: m.len(),
        modified: (m.mtime(), m.mtime_nsec()),
        changed: (m.ctime(), m.ctime_nsec()),
        mode: m.mode(),
    })
}

/// Record all seed entries, including root disks deliberately excluded from duplicate byte hashing.
fn observations(seed: &Path, fingerprints: &Value) -> Result<BTreeMap<PathBuf, Stamp>> {
    let pool = seed.join("pool");
    let paths = fingerprints
        .as_object()
        .context("missing image integrity inventory")?;
    ensure!(!paths.is_empty(), "empty image integrity inventory");
    for relative in paths.keys() {
        let relative = Path::new(relative);
        ensure!(
            !relative.is_absolute() && !relative.components().any(|c| c == Component::ParentDir),
            "image integrity path escapes seed"
        );
        let path = pool.join(relative);
        ensure!(
            fs::canonicalize(&path)?.starts_with(seed),
            "image input symlink escapes seed"
        );
    }
    std::iter::once(seed.to_owned())
        .chain(descendants(seed)?)
        .map(|path| {
            let observed = stamp(&path)?;
            Ok((path, observed))
        })
        .collect()
}

/// Bind immutable wire inputs and authenticated host records without serializing evidence itself.
fn identity(
    seed: &Path,
    selection: &SelectedBoot,
    fingerprints: &Value,
    hosts: &[ValidatedHost],
) -> Result<Identity> {
    let records = hosts
        .iter()
        .map(|view| view.receipt().binding().map(|binding| binding.to_string()))
        .collect::<Result<Vec<_>>>()?;
    Ok(Identity {
        profile: selection.profile(),
        topology: crate::state::digest(selection.inputs().raw())?,
        seed: seed.to_str().context("non-UTF-8 image seed")?.into(),
        host: selection.system().to_string(),
        manifest: crate::state::digest(&json!({"fingerprints":fingerprints,"hosts":records}))?,
    })
}

/// An exact seed and selected boot profile whose complete packaged inventory passed validation.
/// This is compatibility evidence, not deployment approval or a proof of future boot success.
/// Assembly relies on Nix keeping the seed immutable while the upstream builder runs.
///
/// ```compile_fail
/// use airlock_dom0_service::VerifiedImageSeed;
/// /// A saved success receipt cannot authorize assembly in a later process.
/// fn bypass() {
///     fn deserialize<T: serde::de::DeserializeOwned>() {}
///     deserialize::<VerifiedImageSeed>();
/// }
/// ```
pub struct VerifiedImageSeed {
    // Canonical source whose file identities were checked before launch.
    seed: PathBuf,
    // Complete original topology, explicit profile and selected host generation.
    selection: SelectedBoot,
    // The executable Verus gate retains all declarations and their exact binding.
    evidence: CheckedImage,
    // Authenticated host observations remain owned until the builder exits.
    hosts: Vec<ValidatedHost>,
    // File observations prevent reusing evidence after changes before launch.
    observed: BTreeMap<PathBuf, Stamp>,
}

impl VerifiedImageSeed {
    /// Authenticate the packaged files, retained host view and every selected guest's host requirements.
    /// Missing records, mismatched inventories or changing inputs reject the seed before execution.
    pub fn verify(seed: &Path, selection: SelectedBoot) -> Result<Self> {
        let seed = fs::canonicalize(seed)?;
        let pool = seed.join("pool");
        let fingerprints: Value = read(&seed.join("pool-fingerprints.json"))?;
        let observed = observations(&seed, &fingerprints)?;
        let mut hosts = Vec::new();
        for path in children(&pool.join("host/boots"))? {
            let raw: Value = read(&path)?;
            let view = host::validate(&pool, Path::new(host::POOL), &text(&raw, "system")?, false)?;
            ensure!(
                view.pool() == pool,
                "validated host belongs to another image pool"
            );
            for record in [
                &path,
                &pool.join(view.receipt().manifest.strip_prefix(host::POOL)?),
                &pool.join(view.receipt().registration.strip_prefix(host::POOL)?),
                &pool.join(view.receipt().metadata_image.strip_prefix(host::POOL)?),
                &pool.join(view.receipt().blob_map.strip_prefix(host::POOL)?),
            ] {
                ensure!(
                    fingerprints
                        .get(
                            record
                                .strip_prefix(&pool)?
                                .to_str()
                                .context("non-UTF-8 host record")?
                        )
                        .is_some(),
                    "host evidence is absent from the image integrity inventory: {path}",
                    path = record.display()
                );
            }
            hosts.push(view);
        }
        let selected = hosts
            .iter()
            .find(|view| view.receipt().system == *selection.system())
            .context("selected host is absent from the image boot records")?;
        let requirements = selection.inputs().requirements()?;
        // Diagnostics retain the missing guest and path; the verified complete-set
        // decision below independently rejects an omitted requirement.
        for guest in requirements.guests() {
            if let Some(path) = guest.host_root() {
                ensure!(
                    selected.paths().contains(path),
                    "{name}: boot artifact absent from packaged host store: {path}",
                    name = guest.name()
                );
            }
        }
        let paths = selected.paths().iter().cloned().collect::<Vec<_>>();
        let evidence = requirements
            .check_image(identity(&seed, &selection, &fingerprints, &hosts)?, &paths)?;
        prepared::verify_files(&pool, &fingerprints, false)?;
        for path in records::manifests(&pool)? {
            records::root_image(&pool, &read(&path)?)?;
        }
        for role in ["usr-assistant", "sys-ctrl"] {
            if selection
                .inputs()
                .topology()
                .domains
                .keys()
                .any(|name| name.as_str() == role)
            {
                builder::volume_configs(&pool, Path::new(host::POOL), "airlock-closure", role)?;
            }
        }
        let verified = Self {
            seed,
            selection,
            evidence,
            hosts,
            observed,
        };
        verified.ensure_current()?;
        Ok(verified)
    }

    /// Report the checked coordinates; this JSON cannot be decoded back into evidence.
    pub fn report(&self) -> Value {
        let binding = self.evidence.identity();
        json!({"schema":"airlock.unified-seed-check.v2","status":"passed", "seed":binding.seed,
            "host":binding.host,"topology":binding.topology,"manifest":binding.manifest,
            "profile":profile(binding.profile),"guests":self.evidence.requirements().guests().len()})
    }

    /// Refuse evidence reuse after a seed file or binding changes.
    fn ensure_current(&self) -> Result<()> {
        let fingerprints: Value = read(&self.seed.join("pool-fingerprints.json"))?;
        let current_files = observations(&self.seed, &fingerprints)?;
        for (path, expected) in &self.observed {
            ensure!(
                current_files.get(path) == Some(expected),
                "verified image input changed: {path}",
                path = path.display()
            );
        }
        ensure!(
            current_files.len() == self.observed.len(),
            "verified image file set changed"
        );
        let current = identity(&self.seed, &self.selection, &fingerprints, &self.hosts)?;
        ensure!(
            self.evidence.matches(&current),
            "verified image binding changed"
        );
        Ok(())
    }

    /// Execute upstream assembly only while owning the checked seed and its unchanged binding.
    pub fn assemble(self, program: &OsStr, arguments: &[OsString]) -> Result<Value> {
        self.ensure_current()?;
        let binding = self.evidence.identity();
        let status = Command::new(program)
            .args(arguments)
            .env("AIRLOCK_VERIFIED_IMAGE_SEED", &self.seed)
            .env("AIRLOCK_VERIFIED_IMAGE_HOST", &binding.host)
            .env("AIRLOCK_VERIFIED_IMAGE_TOPOLOGY", &binding.topology)
            .env("AIRLOCK_VERIFIED_IMAGE_PROFILE", profile(binding.profile))
            .status()
            .context("run upstream image assembly")?;
        ensure!(status.success(), "upstream image assembly failed: {status}");
        Ok(self.report())
    }
}

/// Encode the explicit selection only at the process/report boundary.
fn profile(profile: Profile) -> &'static str {
    match profile {
        Profile::Normal => "normal",
        Profile::Recovery => "recovery",
    }
}
