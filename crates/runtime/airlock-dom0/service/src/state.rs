//! Read trusted release snapshots and publish bounded, durable dom0 records.

use crate::model::*;
use airlock_nix_core::state::read_json;
use anyhow::{Context, Result, ensure};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, Permissions},
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const LIMIT: u64 = 16 * 1024 * 1024;

struct RecordWriter<'a> {
    /// Temporary output file receiving the bounded serialized record.
    file: &'a mut File,
    /// Bytes still permitted before exceeding the record size limit.
    remaining: u64,
}

impl Write for RecordWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() as u64 > self.remaining {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "record exceeds size limit",
            ));
        }
        let n = self.file.write(bytes)?;
        self.remaining -= n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

/// Decode one bounded, duplicate-key-free regular-file record without repairing it.
pub fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
    read_json(path, LIMIT).with_context(|| format!("read {}", path.display()))
}

/// Decode configuration selected by the caller, resolving NixOS's generation symlinks.
///
/// This does not establish source trust or deployment authority. Use `read` for
/// mutable records, where a final-component symlink must remain an error.
pub(crate) fn configuration<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let resolved = fs::canonicalize(path)
        .with_context(|| format!("resolve configuration {}", path.display()))?;
    read_json(&resolved, LIMIT).with_context(|| format!("read configuration {}", path.display()))
}

/// Treat only an absent configuration entry as disabled; broken generation links remain errors.
pub(crate) fn optional_configuration<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match fs::symlink_metadata(path) {
        Ok(_) => configuration(path).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod configuration_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// NixOS-style generation links are configuration inputs, never mutable record aliases.
    #[test]
    fn generation_links_preserve_json_validation_and_record_symlink_rejection() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path();
        fs::create_dir(root.join("generation"))?;
        fs::create_dir(root.join("etc"))?;
        let data = root.join("generation/topology.json");
        fs::write(&data, br#"{"schema":"airlock.qubes-topology.v1"}"#)?;
        symlink("../generation", root.join("etc/static"))?;
        let configured = root.join("etc/topology.json");
        symlink("static/topology.json", &configured)?;

        let decoded: Value = configuration(&configured)?;
        assert_eq!(decoded["schema"], "airlock.qubes-topology.v1");
        assert_eq!(optional_configuration::<Value>(&configured)?, Some(decoded));
        assert!(optional_configuration::<Value>(&root.join("absent.json"))?.is_none());
        assert!(read::<Value>(&configured).is_err());
        assert!(optional::<Value>(&configured).is_err());

        let duplicate = br#"{"schema":"one","schema":"two"}"#;
        fs::write(&data, duplicate)?;
        assert!(configuration::<Value>(&configured).is_err());
        assert_eq!(fs::read(&data)?, duplicate);

        fs::remove_file(&data)?;
        assert!(configuration::<Value>(&configured).is_err());
        assert!(optional_configuration::<Value>(&configured).is_err());
        fs::create_dir(&data)?;
        assert!(configuration::<Value>(&configured).is_err());
        Ok(())
    }
}

/// Return `None` only for a missing path; propagate invalid or unreadable records.
pub fn optional<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match fs::symlink_metadata(path) {
        Ok(_) => read(path).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Reject symlinks, non-root ownership or group/other write permission along the path.
pub fn trusted(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "trusted path must be absolute");

    let mut p = PathBuf::from("/");
    for c in path.components().skip(1) {
        ensure!(
            matches!(c, std::path::Component::Normal(_)),
            "invalid trusted path"
        );
        p.push(c);
        let m = fs::symlink_metadata(&p).with_context(|| format!("inspect {}", p.display()))?;
        ensure!(
            !m.file_type().is_symlink() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "untrusted machine path: {}",
            p.display()
        );
    }

    Ok(())
}

/// Create and sync trusted state directories, rejecting unsafe existing ancestors.
pub fn directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match fs::symlink_metadata(path) {
        Ok(m) => {
            ensure!(m.is_dir(), "state path is not a directory");
            trusted(path)?;

            // Also cover retry after an earlier mkdir's sync failed. Merely
            // finding a directory does not prove its entry is durable yet.
            if let Some(parent) = path.parent() {
                File::open(parent)?.sync_all()?;
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().context("directory has no parent")?;
            directory(parent)?;

            fs::DirBuilder::new().mode(0o700).create(path)?;
            trusted(path)?;

            // A synced record inside a directory does not make the directory's
            // own entry durable. Publish every new ancestor before its contents.
            File::open(path)?.sync_all()?;
            File::open(parent)?.sync_all()?;
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Publish bounded JSON through a private temporary file and atomic rename.
///
/// Sync the file and destination directory; a post-rename sync error still reports failure.
pub fn save<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    save_with(path, value, |_| Ok(()))
}

/// Boundaries used to exercise interrupted publication without production fault controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicationPoint {
    // Serialized bytes exist only in the private temporary file.
    Written,
    // Temporary contents are durable, but the destination still names the old record.
    Synced,
    // Destination was replaced; durability of its directory entry is uncertain.
    Renamed,
}

fn save_with<T: Serialize>(
    path: &Path,
    value: &T,
    checkpoint: impl Fn(PublicationPoint) -> Result<()>,
) -> Result<()> {
    let parent = path.parent().context("record has no parent")?;
    directory(parent)?;
    if fs::symlink_metadata(path).is_ok() {
        trusted(path)?;
    }

    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file()
        .set_permissions(Permissions::from_mode(0o600))?;
    let mut writer = RecordWriter {
        file: file.as_file_mut(),
        remaining: LIMIT,
    };

    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;

    checkpoint(PublicationPoint::Written)?;
    file.as_file().sync_all()?;
    checkpoint(PublicationPoint::Synced)?;
    file.persist(path).map_err(|e| e.error)?;
    checkpoint(PublicationPoint::Renamed)?;
    File::open(parent)?
        .sync_all()
        .context("record replaced but directory sync failed")?;

    Ok(())
}

/// Exercise old-or-new visibility with the production writer in the caller's private namespace.
#[cfg(test)]
pub(crate) fn test_interrupted_publication(directory: &Path) -> Result<()> {
    let path = directory.join("interrupted.json");
    for boundary in [
        PublicationPoint::Written,
        PublicationPoint::Synced,
        PublicationPoint::Renamed,
    ] {
        save(&path, &json!({"generation": "old"}))?;
        let result = save_with(&path, &json!({"generation": "new"}), |point| {
            ensure!(point != boundary, "injected persistence failure");
            Ok(())
        });
        assert!(result.is_err());
        let visible: Value = read(&path)?;
        assert_eq!(
            visible["generation"],
            if boundary == PublicationPoint::Renamed {
                "new"
            } else {
                "old"
            }
        );
        // Retrying must sync and republish; a visible rename alone was not success.
        save(&path, &json!({"generation": "new"}))?;
        assert_eq!(read::<Value>(&path)?["generation"], "new");
    }
    Ok(())
}

/// Remove one state entry and sync its parent; a missing entry is already removed.
pub fn unlink(path: &Path) -> Result<()> {
    let parent = path.parent().context("entry has no parent")?;
    if !parent.try_exists()? {
        return Ok(());
    }
    trusted(parent)?;
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Single trusted manifest/topology snapshot and its canonical content fingerprint.
///
/// Recheck this snapshot before effects to reject release files changed since planning.
pub struct Release {
    /// Validated absolute location from which this release snapshot was read.
    pub path: PathBuf,
    /// Parsed build identities and system artifacts for this release.
    pub manifest: Manifest,
    /// Parsed intended Qubes configuration used for planning and activation.
    pub topology: Topology,
    /// Original topology value retained for canonical release fingerprinting.
    pub raw_topology: Value,
    /// Digest of the same manifest/topology snapshot used for planning.
    fingerprint: ReleaseFingerprint,
}

impl Release {
    /// Read and validate one release snapshot and fingerprint the same decoded source values.
    pub fn load(path: &Path) -> Result<Self> {
        let path = fs::canonicalize(path)
            .with_context(|| format!("resolve release {}", path.display()))?;
        let raw_manifest: Value = read(&path.join("release.json"))?;
        let raw_topology: Value = read(&path.join("topology.json"))?;

        let fingerprint =
            digest(&json!({"manifest":raw_manifest,"topology":raw_topology}))?.parse()?;

        let manifest: Manifest = serde_json::from_value(raw_manifest)?;
        let topology: Topology = serde_json::from_value(raw_topology.clone())?;
        topology.validate()?;
        manifest.validate(&topology)?;

        Ok(Self {
            path,
            manifest,
            topology,
            raw_topology,
            fingerprint,
        })
    }

    /// Borrow the canonical manifest/topology digest captured when this release was loaded.
    pub fn fingerprint(&self) -> &ReleaseFingerprint {
        &self.fingerprint
    }

    /// Reload trusted release metadata and reject any change from the captured fingerprint.
    pub fn recheck(&self) -> Result<()> {
        let observed = Self::load(&self.path)?;
        observed.trust()?;

        ensure!(
            observed.fingerprint == self.fingerprint,
            "release metadata changed during operation"
        );
        Ok(())
    }

    /// Require the release directory and both metadata files to satisfy dom0 ownership constraints.
    pub fn trust(&self) -> Result<()> {
        trusted(&self.path)?;
        trusted(&self.path.join("release.json"))?;
        trusted(&self.path.join("topology.json"))
    }
}

/// Return Unix time in fractional seconds, falling back to zero before the epoch.
pub fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Read and validate the current host boot UUID from procfs.
pub fn boot_id() -> Result<BootId> {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .parse()
}

/// Resolve the currently running dom0 system to its Nix store object.
pub fn host() -> Result<StorePath> {
    Ok(fs::canonicalize("/run/current-system")?
        .to_str()
        .context("non-UTF-8 host path")?
        .parse()?)
}

/// Read and validate the installed machine-profile token.
pub fn profile() -> Result<MachineProfile> {
    let p = fs::read_to_string("/etc/airlock/machine-profile")
        .context("this boot profile does not support machine deployment")?;
    p.trim().parse()
}

// Match Python json.dumps(sort_keys=True), including separators and ASCII escapes.
// Existing protected review fingerprints and generation history use that encoding.
fn python_json(value: &Value) -> Result<String> {
    fn string(s: &str) -> Result<String> {
        let encoded = serde_json::to_string(s)?;
        let mut out = String::new();
        for c in encoded.chars() {
            if c.is_ascii() {
                out.push(c)
            } else {
                let mut units = [0u16; 2];
                for u in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{u:04x}"));
                }
            }
        }
        Ok(out)
    }
    Ok(match value {
        Value::String(s) => string(s)?,
        Value::Array(a) => format!(
            "[{}]",
            a.iter()
                .map(python_json)
                .collect::<Result<Vec<_>>>()?
                .join(", ")
        ),
        Value::Object(o) => {
            let sorted: std::collections::BTreeMap<_, _> = o.iter().collect();
            format!(
                "{{{}}}",
                sorted
                    .into_iter()
                    .map(|(k, v)| Ok(format!("{}: {}", string(k)?, python_json(v)?)))
                    .collect::<Result<Vec<_>>>()?
                    .join(", ")
            )
        }
        _ => serde_json::to_string(value)?,
    })
}

/// Hash canonical JSON using the Python-compatible encoding shared with existing records.
pub fn digest(value: &Value) -> Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(python_json(value)?.as_bytes())
    ))
}

/// Hash the host system, setup program and topology to identify a retention-equivalent release.
pub fn release_key(r: &Release) -> Result<String> {
    digest(&json!({"host":r.manifest.host,"setup":r.manifest.setup,"topology":r.raw_topology}))
}
