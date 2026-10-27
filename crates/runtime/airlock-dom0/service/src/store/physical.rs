//! Resolve named logical requirements and complete consumer records before physical cleanup.
//! JSON reports are diagnostics; segment deletion consumes the checked protection capability.

use super::{fs::*, records, runtime, segments, tracing, views};
use airlock_deployment_core::retention::{
    physical::{Consumer, Inputs, PhysicalProtection, Resolution},
    tracing::{Extent, Resource, Trace},
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

/// Canonical current object locations used for compaction and checked physical resolution.
pub(super) type Locations = BTreeMap<String, (Value, segments::Extent)>;

/// Complete checked physical protection and separate diagnostic summaries of the same snapshot.
pub(super) struct References<'a> {
    /// The only protection authority accepted by segment deletion.
    pub(super) protection: PhysicalProtection<'a>,
    /// Human-readable pin descriptions; omissions cannot grant reclamation authority.
    pub(super) by_segment: BTreeMap<String, Vec<Value>>,
    /// Runtime records whose exact-name absence permits collection to omit their pins.
    pub(super) stale_runtime: Vec<PathBuf>,
}

/// Load canonical object locations directly from original requirements rather than a projected name set.
pub(super) fn locations(root: &Path, trace: &Trace) -> Result<Locations> {
    let mut output = Locations::new();
    for resource in trace.references() {
        let Resource::Object(name) = resource else {
            continue;
        };
        if output.contains_key(name) {
            continue;
        }
        let (value, extent) = object(root, name)?;
        output.insert(name.clone(), (value, extent));
    }
    Ok(output)
}

/// Authenticate one canonical object record and require an unambiguous current location.
pub(super) fn object(root: &Path, name: &str) -> Result<(Value, segments::Extent)> {
    let value: Value = read(&segments::object_metadata(root, name)?)?;
    if name == ".tar-eof" {
        ensure!(
            value["schema"] == "airlock.closure-store.tar-eof.v1",
            "invalid terminator location record"
        );
    } else {
        ensure!(
            value["schema"] == "airlock.closure-store.object-tar-fragment.v1"
                && value["entry"] == name,
            "object location identity mismatch"
        );
    }
    if let Some(locations) = value.get("locations") {
        let locations = locations
            .as_array()
            .context("invalid object location history")?;
        ensure!(
            locations
                .iter()
                .filter(|location| location["status"] == "current")
                .count()
                == 1,
            "ambiguous current object location"
        );
    }
    let extent = segments::extent(root, &value, true)?;
    Ok((value, extent))
}

/// Convert an already checked canonical range without truncating its coordinates.
fn object_extent(extent: &segments::Extent) -> Extent {
    Extent {
        segment: extent.segment_id.clone(),
        offset: extent.segment_offset,
        length: extent.size,
    }
}

/// Physical bounds are checked independently of logical source membership.
fn bounds(root: &Path, extents: &[Extent]) -> Result<()> {
    for extent in extents {
        segments::segment_id(&extent.segment)?;
        let path = segments::blob(root, &extent.segment)?;
        let metadata = fs::metadata(&path)?;
        ensure!(
            metadata.is_file()
                && extent.length > 0
                && extent
                    .offset
                    .checked_add(extent.length)
                    .is_some_and(|end| end <= metadata.len()),
            "physical pin exceeds segment"
        );
    }
    Ok(())
}

/// Encode diagnostics from typed pins; this map never supplies the protection trace.
fn report(output: &mut BTreeMap<String, Vec<Value>>, source: &str, extents: &[Extent]) {
    for extent in extents {
        output.entry(extent.segment.clone()).or_default().push(json!({
            "segment_id":extent.segment, "source":source, "offset":extent.offset, "length":extent.length,
        }));
    }
}

/// Resolve every original entry and supply every consumer before verified retention classification.
pub(super) fn resolve<'a>(
    root: &Path,
    logical: &'a Trace,
    locations: &Locations,
) -> Result<References<'a>> {
    let mut resolutions = Vec::new();
    let mut reports = BTreeMap::new();
    let mut cached_views = BTreeMap::<String, Vec<views::MapExtent>>::new();
    for (entry, (_, extent)) in locations {
        reports
            .entry(extent.segment_id.clone())
            .or_insert_with(Vec::new)
            .push(json!({
                "segment_id":extent.segment_id, "source":"canonical-current", "entry":entry,
                "offset":extent.segment_offset, "length":extent.size,
            }));
    }
    for resource in logical.references() {
        let (resource, extents) = match resource {
            Resource::Object(name) => {
                let (_, extent) = locations
                    .get(name)
                    .context("required object has no canonical location")?;
                (Resource::Object(name.clone()), vec![object_extent(extent)])
            }
            Resource::View(directory) => {
                if !cached_views.contains_key(directory) {
                    let path = Path::new(directory).join("store.blob-map.json");
                    pool_path(root, &path)?;
                    let extents = views::extents(&read(&path)?)?;
                    cached_views.insert(directory.clone(), extents);
                }
                let extents = cached_views[directory]
                    .iter()
                    .map(|extent| Extent {
                        segment: extent.segment_id.clone(),
                        offset: extent.segment_offset,
                        length: extent.length,
                    })
                    .collect();
                (Resource::View(directory.clone()), extents)
            }
            Resource::Root(digest) => (Resource::Root(digest.clone()), Vec::new()),
            Resource::Segment(_) => anyhow::bail!("physical segment supplied as a logical source"),
        };
        bounds(root, &extents)?;
        resolutions.push(Resolution { resource, extents });
    }
    for (directory, extents) in cached_views {
        for extent in extents {
            reports.entry(extent.segment_id.clone()).or_default().push(json!({
                "segment_id":extent.segment_id, "source":format!("view:{directory}"), "entry":extent.object,
                "offset":extent.segment_offset, "length":extent.length, "logical_offset":extent.logical_offset,
            }));
        }
    }

    let mut consumers = Vec::new();
    for (path, record) in records::running_refs(root)? {
        let extents = tracing::extents(
            record["physical_references"]
                .as_array()
                .context("running reference lacks physical pins")?,
        )?;
        bounds(root, &extents)?;
        let identity = path
            .to_str()
            .context("non-UTF-8 running reference identity")?
            .to_owned();
        report(&mut reports, &format!("running:{identity}"), &extents);
        consumers.push(Consumer::Running { identity, extents });
    }
    let mut stale_runtime = Vec::new();
    for path in children(&root.join("runtime"))? {
        if path.extension().is_none_or(|s| s != "json") {
            continue;
        }
        let reference = runtime::load(root, &path)?;
        let observation = runtime::observe(&reference.name);
        let consumer = Consumer::Runtime {
            identity: reference.name,
            phase: reference.phase,
            observation,
            extents: reference.pins,
        };
        if consumer
            .retains_pins()
            .context("runtime observation identity mismatch")?
        {
            let Consumer::Runtime {
                identity, extents, ..
            } = &consumer
            else {
                unreachable!()
            };
            bounds(root, extents)?;
            report(&mut reports, &format!("runtime:{identity}"), extents);
        } else {
            stale_runtime.push(path);
        }
        consumers.push(consumer);
    }
    let protection = PhysicalProtection::resolve(
        root.to_str().context("non-UTF-8 pool identity")?.to_owned(),
        logical,
        Inputs {
            resolutions,
            consumers,
        },
    )
    .context("incomplete or invalid physical protection inputs")?;
    Ok(References {
        protection,
        by_segment: reports,
        stale_runtime,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_or_wrongly_keyed_lookups_cannot_resolve_the_original_trace() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut logical = Trace::new();
        assert!(logical.include_object("required".into()));
        let mut locations = Locations::new();
        assert!(resolve(directory.path(), &logical, &locations).is_err());
        locations.insert(
            "other".into(),
            (
                Value::Null,
                segments::Extent {
                    segment_id: "000001".into(),
                    segment_blob: directory.path().join("unrelated"),
                    segment_offset: 0,
                    size: 512,
                    sha256: "0".repeat(64),
                },
            ),
        );
        assert!(resolve(directory.path(), &logical, &locations).is_err());
        Ok(())
    }
}
