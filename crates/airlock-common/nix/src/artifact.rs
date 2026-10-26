//! Transfer a frozen Nix closure to dom0 without giving the sender pool authority.
//! Peers negotiate missing objects, then exchange checksummed tar fragments and a bound manifest.

mod root;

/// Reproducible package fragments and logical indexes cached by image builds.
pub mod cache;

/// Transport generated candidate source across the existing validation boundary.
pub mod prepared;

mod util;

pub use root::{RootDescriptor, decode as decode_root, encode as encode_root};

pub use airlock_store_packer::{create_tar_fragment, tree_hash, validate_store_path};

use crate::runtime::process::OwnedChild;
use crate::{admission::AdmissionReceipt, identity::SourceIdentity};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use util::*;

/// Full artifact encoding accepted without an initial negotiation message.
pub const FULL_SCHEMA: &str = "airlock.pool-artifact.full.v2";

/// Inventory and payload encoding used for missing-object negotiation.
pub const INCREMENTAL_SCHEMA: &str = "airlock.pool-artifact.v4";

/// Request asking whether an exact previously admitted generation can be reused.
pub const PROBE_SCHEMA: &str = "airlock.pool-generation-probe.v1";

/// Receiver response specifying the package fragments and root payload still needed.
pub const REQUEST_SCHEMA: &str = "airlock.pool-artifact-request.v2";

/// Failure response delivered over the same channel as negotiation and receipts.
pub const ERROR_SCHEMA: &str = "airlock.pool-artifact-error.v1";

/// Upper bound on one protocol JSON message, checked before allocating its contents.
pub const MAX_MESSAGE: usize = 64 * 1024 * 1024;

/// Frozen source and provenance for a configuration transferred to an admission receiver.
#[derive(Clone)]
pub struct Source {
    /// VM namespace named by the already authorized deployment.
    pub domain: String,
    /// Logical NixOS system root included in the frozen closure.
    pub system: String,
    /// Logical closureInfo source containing its complete store-path list.
    pub closure_source: String,
    /// Optional immutable guest boot-disk source.
    pub root_source: String,
    /// Qubes kernel selection attached to this configuration.
    pub kernel_name: String,
    /// Committed source revision submitted for human review.
    pub source_revision: String,
    /// Dependency lock digest submitted for human review.
    pub lock_hash: String,
    /// Local directory supplying the builder's package bytes.
    pub physical_store_root: PathBuf,
    /// Nix executable used only to query existing path metadata.
    pub nix: String,
    /// Optional Nix store URI containing the frozen configuration.
    pub nix_store: Option<String>,
    /// Optional cached metadata; may contain a union of several machine closures.
    pub path_info: Option<Value>,
}

/// Reject uncommitted or malformed source provenance before requesting package bytes.
pub fn validate_provenance(revision: &str, lock: &str) -> Result<()> {
    ensure!(
        [40, 64].contains(&revision.len())
            && revision
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "artifact requires a committed hexadecimal revision"
    );
    ensure!(
        lock.len() == 64
            && lock
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid artifact lock digest"
    );
    Ok(())
}

/// Read one bounded newline-delimited protocol message without consuming following payload bytes.
pub fn read_message(input: &mut dyn BufRead) -> Result<Value> {
    let mut data = Vec::new();
    let size = input
        .take(MAX_MESSAGE as u64 + 1)
        .read_until(b'\n', &mut data)?;
    ensure!(
        size <= MAX_MESSAGE && data.last() == Some(&b'\n'),
        "missing, truncated or oversized pool message"
    );
    Ok(serde_json::from_slice(&data)?)
}

/// Flush one bounded protocol message so a waiting peer can advance its state machine.
pub fn write_message(output: &mut dyn Write, value: &Value) -> Result<()> {
    let mut data = serde_json::to_vec(value)?;
    data.push(b'\n');
    ensure!(data.len() <= MAX_MESSAGE, "pool message exceeds size limit");
    output.write_all(&data)?;
    output.flush()?;
    Ok(())
}

fn append(archive: &mut tar::Builder<&mut dyn Write>, name: &str, path: &Path) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(fs::metadata(path)?.len());
    header.set_mode(0o400);
    header.set_mtime(1);
    header.set_uid(0);
    header.set_gid(0);
    header.set_cksum();
    archive.append_data(&mut header, name, File::open(path)?)?;
    Ok(())
}

fn receiver_message(input: &mut dyn BufRead) -> Result<Value> {
    let value = read_message(input)?;
    if value["schema"] == ERROR_SCHEMA {
        let error = value["error"]
            .as_str()
            .filter(|e| !e.is_empty() && e.len() <= 4096)
            .context("invalid pool receiver error")?;
        anyhow::bail!("pool receiver rejected admission: {error}");
    }
    Ok(value)
}

impl Source {
    fn physical(&self, path: &str) -> Result<PathBuf> {
        Ok(self.physical_store_root.join(entry(path)?))
    }

    fn paths(&self) -> Result<Vec<String>> {
        let source = if self.closure_source.starts_with("/nix/store/") {
            self.physical(&self.closure_source)?
        } else {
            PathBuf::from(&self.closure_source)
        };
        let path = if source.is_dir() {
            if source.join("store-paths").is_file() {
                source.join("store-paths")
            } else {
                source.join("closure/store-paths")
            }
        } else {
            source
        };
        let mut paths: Vec<_> = fs::read_to_string(path)?
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        paths.push(self.system.clone());
        paths.sort();
        paths.dedup();
        for path in &paths {
            validate_store_path(path)?;
        }
        Ok(paths)
    }

    fn root_path(&self) -> Result<Option<PathBuf>> {
        if self.root_source.is_empty() {
            return Ok(None);
        }
        let mut path = if self.root_source.starts_with("/nix/store/") {
            self.physical(&self.root_source)?
        } else {
            PathBuf::from(&self.root_source)
        };
        if path.is_dir() {
            path.push("root.img");
        }
        Ok(Some(path))
    }

    fn inventory(&self, incremental: bool) -> Result<Value> {
        component(&self.domain)?;
        validate_store_path(&self.system)?;
        validate_provenance(&self.source_revision, &self.lock_hash)?;
        let paths = self.paths()?;
        let info = if let Some(value) = &self.path_info {
            value.clone()
        } else {
            let mut command = Command::new(&self.nix);
            if let Some(store) = &self.nix_store {
                command.args(["--store", store]);
            }
            let output = command
                .args(["path-info", "--json"])
                .args(&paths)
                .stdin(Stdio::null())
                .output()?;
            ensure!(
                output.status.success(),
                "Nix path metadata query failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            serde_json::from_slice(&output.stdout)?
        };
        let info = if let Some(items) = info.as_array() {
            let mut mapped = serde_json::Map::new();
            for value in items {
                let path = value["path"]
                    .as_str()
                    .context("path-info record has no path")?;
                ensure!(
                    mapped.insert(path.to_owned(), value.clone()).is_none(),
                    "duplicate path-info record"
                );
            }
            Value::Object(mapped)
        } else {
            info
        };
        let mut objects = Vec::new();
        for path in paths {
            let info = info
                .get(&path)
                .context("closure path missing from path-info")?;
            let references = info["references"]
                .as_array()
                .context("missing Nix references")?;
            for reference in references {
                validate_store_path(reference.as_str().context("invalid Nix reference")?)?;
            }
            let hash = info["narHash"]
                .as_str()
                .filter(|s| !s.is_empty())
                .context("missing NAR hash")?;
            let size = info["narSize"].as_u64().context("invalid NAR size")?;
            let name = entry(&path)?;
            let mut object = json!({"path":path,"entry":name,"references":references,"nar_hash":hash,"nar_size":size,"fragment":format!("objects/{name}.tar")});
            if !incremental {
                object["tree_hash"] = json!(tree_hash(&self.physical(&path)?)?);
            }
            objects.push(object);
        }
        let paths: BTreeSet<_> = objects.iter().filter_map(|o| o["path"].as_str()).collect();
        for object in &objects {
            ensure!(
                object["references"]
                    .as_array()
                    .context("missing references")?
                    .iter()
                    .all(|r| r.as_str().is_some_and(|r| paths.contains(r))),
                "artifact closure is not reference complete"
            );
        }
        let root = self
            .root_path()?
            .map(|path| encode_root(&path, None))
            .transpose()?;
        Ok(json!({
            "schema": if incremental{INCREMENTAL_SCHEMA}else{FULL_SCHEMA},
            "domain": self.domain,
            "system": self.system,
            "closure_source": self.closure_source,
            "root_source": self.root_source,
            "root_artifact": root,
            "kernel_name": self.kernel_name,
            "source_revision": self.source_revision,
            "lock_hash": self.lock_hash,
            "object_count": objects.len(),
            "objects": objects,
        }))
    }

    fn payload(
        &self,
        output: &mut dyn Write,
        mut inventory: Value,
        request: Option<&Value>,
    ) -> Result<Value> {
        let paths: BTreeSet<String> = inventory["objects"]
            .as_array()
            .context("missing objects")?
            .iter()
            .map(|o| {
                o["path"]
                    .as_str()
                    .map(str::to_owned)
                    .context("missing object path")
            })
            .collect::<Result<_>>()?;
        let root_descriptor: Option<RootDescriptor> =
            serde_json::from_value(inventory["root_artifact"].clone())?;
        let (missing, missing_root, reused) = if let Some(request) = request {
            ensure!(
                request["schema"] == REQUEST_SCHEMA,
                "invalid missing-object request schema"
            );
            let raw: Vec<String> = serde_json::from_value(request["missing"].clone())?;
            let missing: BTreeSet<_> = raw.iter().cloned().collect();
            ensure!(
                missing.len() == raw.len() && missing.is_subset(&paths),
                "invalid missing-object request"
            );
            let missing_root = request["missing_root"]
                .as_bool()
                .context("missing root request flag")?;
            ensure!(
                !missing_root || root_descriptor.is_some(),
                "unexpected root request"
            );
            let reused: BTreeMap<String, String> =
                serde_json::from_value(request["reused_tree_hashes"].clone())?;
            ensure!(
                reused.keys().cloned().collect::<BTreeSet<_>>()
                    == paths.difference(&missing).cloned().collect(),
                "invalid reused-object identities"
            );
            for digest in reused.values() {
                ensure!(
                    digest.len() == 64
                        && digest
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                    "invalid reused object hash"
                );
            }
            (missing, missing_root, reused)
        } else {
            (paths, root_descriptor.is_some(), BTreeMap::new())
        };
        let temporary = tempfile::tempdir()?;
        let mut archive = tar::Builder::new(output);
        if missing_root {
            let path = temporary.path().join("root.sparse");
            let mut output = File::create(&path)?;
            ensure!(
                Some(encode_root(
                    &self.root_path()?.context("missing root source")?,
                    Some(&mut output)
                )?) == root_descriptor,
                "root image changed during transfer"
            );
            output.flush()?;
            append(&mut archive, "root.sparse", &path)?;
            fs::remove_file(path)?;
        }
        for object in inventory["objects"]
            .as_array_mut()
            .context("missing objects")?
        {
            let path = object["path"]
                .as_str()
                .context("missing object path")?
                .to_owned();
            if !missing.contains(&path) {
                object["tree_hash"] = json!(reused[&path]);
                continue;
            }
            let physical = self.physical(&path)?;
            if request.is_some() {
                object["tree_hash"] = json!(tree_hash(&physical)?);
            }
            let fragment = temporary.path().join(format!("{}.tar", entry(&path)?));
            create_tar_fragment(&physical, &fragment)?;
            object["fragment_size"] = json!(fs::metadata(&fragment)?.len());
            object["fragment_sha256"] = json!(hash(&fragment)?);
            append(
                &mut archive,
                object["fragment"]
                    .as_str()
                    .context("missing fragment name")?,
                &fragment,
            )?;
            fs::remove_file(fragment)?;
        }
        let bytes = serde_json::to_vec(&inventory)?;
        ensure!(bytes.len() <= MAX_MESSAGE, "artifact manifest too large");
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o400);
        header.set_mtime(1);
        header.set_uid(0);
        header.set_gid(0);
        header.set_cksum();
        archive.append_data(&mut header, "manifest.json", bytes.as_slice())?;
        archive.finish()?;
        Ok(inventory)
    }

    /// Write a complete streaming artifact without contacting dom0 or modifying a pool.
    pub fn write(&self, output: &mut dyn Write) -> Result<Value> {
        self.payload(output, self.inventory(false)?, None)
    }

    /// Negotiate and transfer missing objects over an existing duplex admission channel.
    /// The returned receipt confirms retained admission; it never implies activation.
    pub fn transfer(
        &self,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
        reuse_generation: bool,
    ) -> Result<AdmissionReceipt> {
        component(&self.domain)?;
        validate_store_path(&self.system)?;
        validate_provenance(&self.source_revision, &self.lock_hash)?;

        if reuse_generation {
            write_message(
                output,
                &json!({
                    "schema": PROBE_SCHEMA,
                    "domain": self.domain,
                    "system": self.system,
                    "closure_source": self.closure_source,
                    "root_source": self.root_source,
                    "kernel_name": self.kernel_name,
                    "source_revision": self.source_revision,
                    "lock_hash": self.lock_hash,
                }),
            )?;
            let probe = receiver_message(input)?;
            if probe["schema"] != PROBE_SCHEMA {
                let receipt = self.validate_receipt(probe)?;
                ensure!(
                    receipt.generation_reused == Some(true),
                    "invalid generation reuse response"
                );
                return Ok(receipt);
            }
            ensure!(probe["reuse"] == false, "invalid generation reuse response");
        }
        let inventory = self.inventory(true)?;
        write_message(output, &inventory)?;
        let request = receiver_message(input)?;
        let manifest = self.payload(output, inventory, Some(&request))?;
        output.flush()?;
        let receipt = self.validate_receipt(receiver_message(input)?)?;
        let root: Option<RootDescriptor> =
            serde_json::from_value(manifest["root_artifact"].clone())?;
        ensure!(
            root == receipt.root_artifact,
            "admission root identity differs from transferred artifact"
        );
        Ok(receipt)
    }

    fn validate_receipt(&self, value: Value) -> Result<AdmissionReceipt> {
        let receipt: AdmissionReceipt =
            serde_json::from_value(value).context("invalid pool admission receipt")?;
        let expected = SourceIdentity {
            revision: self.source_revision.parse()?,
            lock_hash: self.lock_hash.parse()?,
        };
        receipt
            .check_transfer(&self.domain.parse()?, &expected)
            .context("invalid pool admission receipt")?;
        ensure!(
            receipt.system.as_str() == self.system
                && receipt.root_source.to_str() == Some(self.root_source.as_str())
                && receipt.kernel_name == self.kernel_name,
            "invalid pool admission receipt"
        );
        Ok(receipt)
    }

    /// Send through policy-controlled qrexec and require both a valid receipt and successful exit.
    pub fn send(
        &self,
        qrexec: &str,
        admission: Option<&str>,
        reuse_generation: bool,
    ) -> Result<AdmissionReceipt> {
        component(&self.domain)?;
        if let Some(admission) = admission {
            component(admission)?;
        }
        let service = if let Some(id) = admission {
            format!("airlock.Pool.AdmitCandidate+{id}.{}", self.domain)
        } else {
            format!("airlock.Pool.AdmitIncremental+{}", self.domain)
        };
        let child = Command::new(qrexec)
            .args(["dom0", &service])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let mut child = OwnedChild(child);
        let mut input = BufReader::new(child.0.stdout.take().context("qrexec stdout unavailable")?);
        let mut output = child.0.stdin.take().context("qrexec stdin unavailable")?;
        let result = self.transfer(&mut input, &mut output, reuse_generation);
        drop(output);
        let receipt = result?;
        ensure!(child.0.wait()?.success(), "pool admission receiver failed");
        Ok(receipt)
    }
}
