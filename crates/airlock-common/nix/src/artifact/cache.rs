//! Nix caches each package's canonical tar bytes separately from VM identities and pool placement.
//! Index identities describe the concatenated fragments, so changing physical segments cannot invalidate them.

use super::util::*;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};

pub use airlock_store_packer::{Fragment, fragment, pack};

/// Common EROFS metadata before injecting a VM's private builder identity.
#[derive(Clone, Deserialize, Serialize)]
pub struct Index {
    /// Version of the build-time index representation.
    pub schema: String,
    /// Identity of all logical fragment offsets, lengths and digests.
    pub layout_sha256: String,
    /// SHA-256 of the EROFS metadata image.
    pub sha256: String,
}

/// Require the canonical hexadecimal digest representation used in cached metadata.
fn digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid cached digest"
    );
    Ok(())
}

// Preserve the original pool layout digest's sorted JSON and Python-compatible separators.
fn canonical_json(value: &Value) -> Result<String> {
    Ok(match value {
        Value::Array(items) => format!(
            "[{items}]",
            items = items
                .iter()
                .map(canonical_json)
                .collect::<Result<Vec<_>>>()?
                .join(", ")
        ),
        Value::Object(items) => format!(
            "{{{items}}}",
            items = items
                .iter()
                .map(|(key, value)| Ok(format!(
                    "{key}: {value}",
                    key = serde_json::to_string(key)?,
                    value = canonical_json(value)?
                )))
                .collect::<Result<Vec<_>>>()?
                .join(", ")
        ),
        _ => serde_json::to_string(value)?,
    })
}

/// Hash only logical tar layout, excluding physical pool paths, segment IDs and VM identities.
/// The input uses the pool blob-map's `logical_size` and `extents` fields.
pub fn layout_hash(map: &Value) -> Result<String> {
    let layout = json!({"logical_size":map["logical_size"],"extents":map["extents"].as_array().context("missing layout extents")?.iter().map(|item| json!({"object":item["object"],"object_sha256":item["object_sha256"],"logical_offset":item["logical_offset"],"length":item["length"]})).collect::<Vec<_>>()});
    Ok(hex(&Sha256::digest(canonical_json(&layout)?)))
}

/// Read the identity of a separately cached index; consumers must also check its file checksum.
pub fn index(directory: &Path) -> Result<Index> {
    let value: Index = serde_json::from_reader(File::open(directory.join("metadata.json"))?)?;
    ensure!(
        value.schema == "airlock.store-index.v1",
        "unsupported cached index"
    );
    digest(&value.layout_sha256)?;
    digest(&value.sha256)?;
    ensure!(
        fs::symlink_metadata(directory.join("store.erofs"))?.is_file(),
        "cached index is not a regular file"
    );
    Ok(value)
}

/// Build one reproducible EROFS index from an exact, sorted closure and its cached package fragments.
/// The manifest maps logical store roots to fragment directories.
/// Physical pool placement and builder registrations never enter this derivation.
pub fn build_index(manifest: &Path, output: &Path, mkfs: &OsStr) -> Result<Index> {
    let fragments: BTreeMap<String, PathBuf> = serde_json::from_reader(File::open(manifest)?)?;
    ensure!(!fragments.is_empty(), "cannot index an empty closure");

    fs::create_dir(output)?;
    let mut source = tempfile::NamedTempFile::new()?;
    let mut extents = Vec::new();
    let mut offset = 0u64;

    for (logical, directory) in fragments {
        let value = fragment(&directory, &logical)?;
        let mut input = File::open(directory.join("object.tar"))?;
        let mut actual = Sha256::new();
        let mut count = 0u64;
        let mut buffer = [0; 1024 * 1024];

        loop {
            let size = input.read(&mut buffer)?;
            if size == 0 {
                break;
            }
            source.write_all(&buffer[..size])?;
            actual.update(&buffer[..size]);
            count += size as u64;
        }

        ensure!(
            count == value.size && hex(&actual.finalize()) == value.sha256,
            "cached fragment checksum mismatch"
        );
        extents.push(json!({"object":entry(&logical)?,"object_sha256":value.sha256,"logical_offset":offset,"length":value.size}));
        offset = offset
            .checked_add(value.size)
            .context("cached layout overflow")?;
    }

    source.write_all(&[0; 1024])?;
    source.flush()?;
    extents.push(json!({"object":".tar-eof","object_sha256":hex(&Sha256::digest([0; 1024])),"logical_offset":offset,"length":1024}));
    let key = layout_hash(
        &json!({"logical_size":offset.checked_add(1024).context("cached layout overflow")?,"extents":extents}),
    )?;
    let uuid = format!(
        "{a}-{b}-{c}-{d}-{e}",
        a = &key[..8],
        b = &key[8..12],
        c = &key[12..16],
        d = &key[16..20],
        e = &key[20..32]
    );

    let result = crate::runtime::process::run(
        Command::new(mkfs)
            .args(["--quiet", "--tar=i", "-T", "1", "-U", &uuid])
            .arg(output.join("store.erofs"))
            .arg(source.path()),
        None,
        None,
    )?;
    result.checked("cached EROFS index")?;

    let value = Index {
        schema: "airlock.store-index.v1".into(),
        layout_sha256: key,
        sha256: hash(&output.join("store.erofs"))?,
    };
    fs::write(output.join("metadata.json"), serde_json::to_vec(&value)?)?;
    Ok(value)
}
