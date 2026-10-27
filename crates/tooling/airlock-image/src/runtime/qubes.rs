//! Drive upstream offline objects while Rust owns image assembly and disk preparation.
//! One embedded Python session preserves Qubes' references until save and reload.

use super::plan::VmPlan;
use crate::support::run;
use anyhow::{Context, Result, ensure};
use pyo3::Python;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
};

mod bindings;

use bindings::Session;

/// Upstream label identity; existing numeric indices must survive image assembly.
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct Label {
    // Database identity allocated after all existing and reserved upstream indices.
    index: u32,
    // Human-readable label selected by the VM declaration.
    name: String,
    // Upstream color spelling, normalized only for equality checks.
    color: String,
}

/// Built-in labels and capacities provided by Qubes before applying image declarations.
struct Defaults {
    // Labels installed by the upstream empty-store constructor.
    labels: Vec<Label>,
    // Highest reserved built-in label index, including any unpopulated slots.
    maximum: u32,
    // Upstream private-image capacity used when Airlock leaves it unspecified.
    private_size: u64,
}

/// Filesystem location and default disks selected by the upstream VM constructor.
struct Created {
    // Qubes-selected directory where Rust prepares this VM's local disks.
    directory: PathBuf,
    // Default upstream disk configurations, retained when overriding their capacities.
    volumes: BTreeMap<String, Value>,
}

/// Plan custom label additions without changing existing indices or colors.
pub(crate) fn labels(domains: &[Value], existing: &[Label], maximum: u32) -> Result<Vec<Label>> {
    let mut known = existing.to_vec();
    let mut additions = Vec::new();
    for domain in domains {
        let Some(color) = domain["color"].as_str() else {
            continue;
        };
        let name = domain["label"]
            .as_str()
            .context("missing custom label name")?;
        if let Some(label) = known.iter().find(|label| label.name == name) {
            ensure!(
                label.color.to_lowercase().replace('#', "0x") == color.to_lowercase(),
                "existing custom label colour differs"
            );
            continue;
        }

        let index = known
            .iter()
            .map(|label| label.index)
            .chain([maximum])
            .max()
            .context("missing label index")?
            .checked_add(1)
            .context("label index overflow")?;
        let label = Label {
            index,
            name: name.into(),
            color: color.into(),
        };
        known.push(label.clone());
        additions.push(label);
    }

    Ok(additions)
}

/// Reject upstream filesystem paths that escape or redirect the fresh image tree.
fn image_path(root: &Path, path: &Path) -> Result<()> {
    ensure!(
        path.starts_with(root)
            && path != root
            && !path
                .components()
                .any(|part| part == std::path::Component::ParentDir),
        "Qubes disk path escapes image output"
    );

    for ancestor in path.ancestors().take_while(|ancestor| *ancestor != root) {
        ensure!(!ancestor.is_symlink(), "Qubes disk path contains a symlink");
    }
    Ok(())
}

/// Build disks and Qubes objects in dependency order, then inspect a freshly reopened store.
pub(super) fn assemble(
    root: &Path,
    plans: &[VmPlan],
    prefs: &BTreeMap<String, Value>,
) -> Result<Value> {
    // Qubes configuration and extension discovery are process-global Python state.
    // Serialize sessions before attaching so another caller cannot wait with the GIL held.
    static SESSION: Mutex<()> = Mutex::new(());

    let _guard = SESSION
        .lock()
        .map_err(|_| anyhow::anyhow!("offline Qubes session poisoned"))?;
    Python::attach(|py| {
        let mut session =
            Session::start(py, root).context("initialize embedded offline Qubes objects")?;
        assemble_objects(root, plans, prefs, &mut session)
    })
}

/// Populate upstream objects only after the session has installed its offline configuration.
fn assemble_objects(
    root: &Path,
    plans: &[VmPlan],
    prefs: &BTreeMap<String, Value>,
    session: &mut Session<'_>,
) -> Result<Value> {
    let defaults = session.defaults()?;

    let declarations = plans
        .iter()
        .map(|vm| json!({"label":vm.label,"color":vm.color}))
        .collect::<Vec<_>>();
    for label in labels(&declarations, &defaults.labels, defaults.maximum)? {
        session.add_label(&label)?;
    }

    session.add_pool(super::POOL)?;

    let mut created = BTreeMap::new();
    for vm in plans {
        let result = session.create_vm(vm)?;
        image_path(root, &result.directory)?;

        fs::create_dir_all(&result.directory)?;
        created.insert(&vm.name, result);
    }

    for vm in plans {
        let mut values = vm.prefs.clone();
        values.insert("kernel".into(), json!(vm.kernel));
        values.insert("kernelopts".into(), json!(vm.kernelopts));
        session.vm_properties(&vm.name, &values)?;
        session.features(vm)?;

        let Some(root_image) = &vm.root_image else {
            continue;
        };
        let source = crate::support::regular(root_image)?;
        let sizes = [
            ("root", source.metadata()?.len()),
            ("private", vm.private_size.unwrap_or(defaults.private_size)),
        ];
        for (name, size) in sizes {
            ensure!(size > 0, "image volume capacity must be positive");
            let mut config = created[&vm.name]
                .volumes
                .get(name)
                .context("missing upstream disk configuration")?
                .clone();
            config["size"] = json!(size);
            let path = session
                .volume(&vm.name, name, &config, true)?
                .context("created upstream volume has no disk path")?;
            image_path(root, &path)?;
            ensure!(
                fs::symlink_metadata(&path)?.is_file(),
                "Qubes disk is not a regular image file"
            );

            if name == "root" {
                run(Command::new("cp")
                    .args(["--sparse=always", "--reflink=auto", "--"])
                    .arg(root_image)
                    .arg(&path))?;
            } else {
                run(Command::new("mkfs.ext4").args(["-q", "-F"]).arg(&path))?;
            }
        }

        for config in &vm.volumes {
            let name = config["name"]
                .as_str()
                .context("missing image volume name")?;
            session.volume(&vm.name, name, config, false)?;
        }
    }

    // Resolve defaults only after all providers and their volumes exist. Omission
    // must retain inheritance, while explicit null must remain a disabled provider.
    session.app_properties(prefs)?;
    for vm in plans {
        let mut providers = BTreeMap::new();
        if vm.netvm.is_inherited() {
            session.inherit_netvm(&vm.name)?;
        } else {
            providers.insert("netvm".into(), json!(vm.netvm));
        }
        if let Some(guivm) = &vm.guivm {
            providers.insert("guivm".into(), guivm.clone());
        }
        session.vm_properties(&vm.name, &providers)?;
    }

    session.save()?;

    let snapshots = session.inspect(plans)?;
    session.finish()?;

    Ok(snapshots)
}
