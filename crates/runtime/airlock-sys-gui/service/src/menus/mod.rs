//! Coordinate complete Qubes inventories and per-VM menu refreshes without starting VMs.
//! Native validation and publication retain the existing Qubes transport and desktop identities.

use crate::qubes::{self, Vm};
use airlock_nix_core::identity::GuestName;
use airlock_vm_service::support;
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use serde::{Deserialize, Serialize};

use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

mod catalog;

mod icons;

mod store;

/// Local reconciliation and authenticated catalog receipt operations.
#[derive(Subcommand)]
pub(crate) enum Action {
    /// Reconcile the complete assigned-VM inventory and refresh running VMs.
    Reconcile,
    /// Refresh one running VM without autostarting it.
    Sync {
        // Validated Qubes VM name selected by the local launcher.
        name: GuestName,
        // Identity observed before scheduling this refresh worker.
        #[arg(long)]
        uuid: Option<Uuid>,
        // Explicit refresh bypassing the short icon-cache freshness window.
        #[arg(long)]
        force: bool,
    },
    /// Consume a catalog from the authenticated Qubes RPC caller.
    Receive,
}

impl Vm {
    /// Keep only ordinary application VMs assigned to this GUI session.
    pub(crate) fn assigned(&self, local: &str) -> bool {
        self.name.as_str() != "dom0"
            && self.name.as_str() != local
            && self.guivm == local
            && !self.tags.iter().any(|v| v == "airlock-retired")
            && !self.internal
            && !(self.class_name == "DispVM" && self.auto_cleanup)
    }

    /// Retain the trusted metadata that affects local publication and cache freshness.
    fn description(&self) -> Description {
        Description {
            name: self.name.clone(),
            uuid: self.uuid,
            running: self.running,
            label: self.label.clone(),
            menu_items: self.menu_items.clone(),
        }
    }
}

/// Inventory metadata persisted across renames and power-state changes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Description {
    // Current name presented in search and launcher menus.
    name: GuestName,
    // Persistent identity used for favorites and per-VM locks.
    uuid: Uuid,
    // Refresh eligibility; stopped VMs retain their cached applications.
    running: bool,
    // Trusted Qubes color rendered by the desktop extensions.
    label: String,
    // Upstream application selection included in cache invalidation.
    #[serde(rename = "menu-items")]
    menu_items: Option<String>,
}

/// Completed publication fingerprint; failures must not advance this receipt.
#[derive(Serialize, Deserialize)]
struct Receipt {
    // GUI kernel boot during which the catalog was successfully refreshed.
    #[serde(default)]
    boot_id: String,
    // Catalog and trusted metadata fingerprint used to skip unchanged icon fetches.
    digest: String,
    // Unix time at the last successful publication.
    updated: f64,
}

/// Read-only publication evidence used by the startup panel.
pub(crate) struct Publication {
    /// All selected launchers have been published for the current VM identity.
    pub(crate) available: bool,
    /// Latest failed refresh, retained only while applications remain unavailable.
    pub(crate) error: Option<String>,
}

/// Last failed refresh for a trusted inventory identity; successful publication supersedes it.
#[derive(Serialize, Deserialize)]
struct Failure {
    // GUI boot during which this failed refresh was observed.
    #[serde(default)]
    boot_id: String,
    // Name observed in the inventory before this refresh was scheduled.
    name: GuestName,
    // Persistent identity, preventing a reused name from inheriting old failures.
    uuid: Uuid,
    // Bounded plain text shown in the startup dropdown.
    detail: String,
}

/// Inspect existing inventory, receipts and launchers without creating directories or querying Qubes.
pub(crate) fn publication(name: &GuestName) -> Result<Publication> {
    let state = root()?;
    let inventory: BTreeMap<Uuid, Description> =
        support::read(&state.join("inventory.json"))?.unwrap_or_default();
    let Some(vm) = inventory.values().find(|vm| vm.name == *name) else {
        return Ok(Publication {
            available: false,
            error: None,
        });
    };
    let receipt: Option<Receipt> =
        support::read(&state.join(format!("{uuid}.json", uuid = vm.uuid)))?;
    let current_boot = boot_id()?;
    let available =
        receipt.is_some_and(|receipt| receipt.boot_id == current_boot) && store::available(vm)?;
    let failure: Option<Failure> =
        support::read(&state.join(format!("{uuid}.error.json", uuid = vm.uuid)))?;
    let error = failure
        .filter(|failure| {
            !available
                && failure.boot_id == current_boot
                && failure.name == *name
                && failure.uuid == vm.uuid
        })
        .map(|failure| failure.detail);
    Ok(Publication { available, error })
}

/// Locate the user-owned coordinator state and operation locks.
fn root() -> Result<PathBuf> {
    support::state_root("airlock-appmenus")
}

/// Measure successful publication time for the short icon-refresh cache.
fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Bind menu publication to this GUI boot so retained catalogs do not conceal first-refresh work.
fn boot_id() -> Result<String> {
    let path = std::env::var_os("AIRLOCK_GUI_BOOT_ID_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| "/proc/sys/kernel/random/boot_id".into());
    let value = fs::read_to_string(path)?;
    Ok(value.trim().parse::<Uuid>()?.to_string())
}

/// Locate one VM's upstream catalog while refusing redirected cache directories.
fn cached_directory(basedir: &Path, name: &GuestName) -> Result<PathBuf> {
    ensure!(
        basedir.is_absolute()
            && !basedir
                .components()
                .any(|part| part == std::path::Component::ParentDir),
        "menu cache must be an absolute path without traversal"
    );
    if basedir.try_exists()? {
        ensure!(
            fs::symlink_metadata(basedir)?.is_dir(),
            "menu cache root must be a real directory"
        );
    }
    let directory = basedir.join(name.as_str());
    ensure!(
        !directory.is_symlink(),
        "cached menu directory must not be a symlink"
    );
    Ok(directory)
}

/// Remove upstream launchers and then their local catalog under the existing VM lock.
fn remove_cached(basedir: &Path, name: &GuestName) -> Result<()> {
    let directory = cached_directory(basedir, name)?;
    store::remove(name)?;
    if directory.try_exists()? {
        fs::remove_dir_all(directory)?;
    }
    Ok(())
}

/// Move a stable UUID's catalog without overwriting another VM's cached applications.
fn rename_cached(basedir: &Path, old: &GuestName, new: &GuestName) -> Result<()> {
    let source = cached_directory(basedir, old)?;
    let destination = cached_directory(basedir, new)?;
    if source.try_exists()? {
        ensure!(
            !destination.try_exists()?,
            "renamed VM catalog already exists"
        );
        fs::rename(source, destination)?;
    }
    Ok(())
}

/// Reconcile complete membership under the inventory lock, then refresh running VMs independently.
fn reconcile() -> Result<()> {
    let state = root()?;
    // Acquire before querying: a snapshot taken while another reconciliation
    // runs can otherwise undo its newer membership decisions after waiting.
    let inventory_guard = support::lock(
        &state,
        "inventory",
        "reconcile the complete GUI VM application inventory",
    )?;
    let inventory = qubes::inventory()?;
    ensure!(
        inventory.basedir.is_absolute(),
        "menu cache must be an absolute path"
    );
    let mut current = BTreeMap::new();
    let mut names = BTreeSet::new();
    for vm in inventory
        .domains
        .iter()
        .filter(|v| v.assigned(inventory.local_name.as_str()))
    {
        ensure!(
            names.insert(vm.name.clone()),
            "duplicate VM name in inventory"
        );
        ensure!(
            current.insert(vm.uuid, vm.description()).is_none(),
            "duplicate VM identity in inventory"
        );
    }
    {
        let previous: BTreeMap<Uuid, Description> =
            support::read(&state.join("inventory.json"))?.unwrap_or_default();
        ensure!(
            previous.iter().all(|(id, vm)| *id == vm.uuid),
            "cached menu inventory identity mismatch"
        );
        let identities = previous
            .keys()
            .chain(current.keys())
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut guards = Vec::new();
        for id in identities {
            guards.push(support::lock(
                &state,
                &id.to_string(),
                "reconcile one VM's menu membership",
            )?);
        }
        let mut removed = previous
            .iter()
            .filter(|(id, _)| !current.contains_key(*id))
            .map(|(_, v)| v.name.clone())
            .collect::<BTreeSet<_>>();
        let renamed = current
            .iter()
            .filter_map(|(id, v)| {
                previous
                    .get(id)
                    .filter(|old| old.name != v.name)
                    .map(|old| (old.name.clone(), v.name.clone()))
            })
            .collect::<Vec<_>>();
        let wanted = current
            .values()
            .map(|v| v.name.clone())
            .collect::<BTreeSet<_>>();
        let old_names = renamed.iter().map(|(old, _)| old).collect::<BTreeSet<_>>();
        if inventory.basedir.try_exists()? {
            for entry in fs::read_dir(&inventory.basedir)? {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    continue;
                }
                if let Ok(name) = entry.file_name().to_string_lossy().parse::<GuestName>()
                    && !wanted.contains(&name)
                    && !old_names.contains(&name)
                {
                    removed.insert(name);
                }
            }
        }
        for name in removed {
            remove_cached(&inventory.basedir, &name)?;
        }
        for (old, new) in renamed {
            rename_cached(&inventory.basedir, &old, &new)?;
        }
        for (id, vm) in &current {
            if previous.get(id) != Some(vm)
                && cached_directory(&inventory.basedir, &vm.name)?
                    .join("catalog.json")
                    .is_file()
            {
                store::regenerate(vm)?;
            }
        }
        support::save(&state.join("inventory.json"), &current)?;
    }

    drop(inventory_guard);

    let running = current.values().filter(|v| v.running).collect::<Vec<_>>();
    // Each helper owns its Qubes client and deadline; refreshes hold separate VM locks.
    for batch in running.chunks(4) {
        std::thread::scope(|scope| {
            for vm in batch {
                let state = &state;
                scope.spawn(move || {
                    // Keep helper cleanup in this process. Killing an outer worker
                    // would orphan an adapter that owns its own process group.
                    let result = sync(vm.name.clone(), Some(vm.uuid), false, false);
                    if let Err(error) = result {
                        eprintln!("menu refresh for {name}: {error:#}", name = vm.name);
                        let failure = Failure {
                            boot_id: boot_id().unwrap_or_default(),
                            name: vm.name.clone(),
                            uuid: vm.uuid,
                            detail: format!("Application list unavailable; retrying: {error:#}")
                                .chars()
                                .filter(|c| !c.is_control())
                                .take(512)
                                .collect(),
                        };
                        if let Err(error) = support::save(
                            &state.join(format!("{uuid}.error.json", uuid = vm.uuid)),
                            &failure,
                        ) {
                            eprintln!("recording application-menu failure: {error:#}");
                        }
                    }
                });
            }
        });
    }
    Ok(())
}

/// Recheck identity around catalog collection and advance the receipt only after native publication.
fn sync(name: GuestName, expected: Option<Uuid>, incoming: bool, force: bool) -> Result<()> {
    let before = qubes::describe(&name)?;
    ensure!(
        before.name == name && expected.is_none_or(|id| id == before.uuid),
        "VM identity changed during application refresh"
    );
    let inventory = qubes::inventory()?;
    ensure!(
        before.assigned(inventory.local_name.as_str()) && before.running,
        "VM is not a running application VM for this GUI VM"
    );
    let state = root()?;
    let _guard = support::lock(
        &state,
        &before.uuid.to_string(),
        "refresh this VM's application menus",
    )?;

    let locked = qubes::describe(&name)?;
    ensure!(
        before == locked,
        "VM changed while waiting to refresh its menus"
    );

    let input = if incoming {
        let mut bytes = Vec::new();
        io::stdin()
            .lock()
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 16 * 1024 * 1024,
            "incoming application catalog exceeds limit"
        );
        Some(bytes)
    } else {
        None
    };
    let bytes = match input {
        Some(bytes) => bytes,
        None => qubes::service(&name, "qubes.GetAppmenus", None)?,
    };
    let menus = catalog::parse(&bytes)?;
    let after = qubes::describe(&name)?;
    ensure!(before == after, "VM changed during application refresh");
    let digest = format!(
        "{hash:x}",
        hash = Sha256::digest(serde_json::to_vec(&(before.description(), &menus))?)
    );
    let receipt_path = state.join(format!("{uuid}.json", uuid = before.uuid));
    let receipt: Option<Receipt> = support::read(&receipt_path)?;
    let timestamp = now();
    let current_boot = boot_id()?;
    let cache = cached_directory(&inventory.basedir, &name)?.join("catalog.json");
    if !force
        && cache.is_file()
        && receipt.is_some_and(|r| {
            r.boot_id == current_boot
                && r.digest == digest
                && r.updated <= timestamp
                && timestamp - r.updated < 300.0
        })
    {
        return Ok(());
    }

    store::publish(&before, &menus)?;
    support::save(
        &receipt_path,
        &Receipt {
            boot_id: current_boot,
            digest,
            updated: timestamp,
        },
    )
}

/// Dispatch local operations or consume a catalog from its authenticated Qubes RPC caller.
pub(crate) fn execute(action: Action) -> Result<()> {
    match action {
        Action::Reconcile => reconcile(),
        Action::Sync { name, uuid, force } => sync(name, uuid, false, force),
        Action::Receive => {
            ensure!(
                std::env::var("QREXEC_SERVICE_ARGUMENT")
                    .unwrap_or_default()
                    .is_empty(),
                "menu RPC does not accept arguments"
            );
            let name = std::env::var("QREXEC_REMOTE_DOMAIN")
                .context("missing authenticated menu caller")?
                .parse()?;
            sync(name, None, true, false)
        }
    }
}
