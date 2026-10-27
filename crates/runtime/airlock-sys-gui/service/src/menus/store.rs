//! Publish validated catalogs as local launchers and immutable, UUID-owned icon files.
//! Failed fetches retain cached applications; changed files are installed atomically and receipts follow publication.

use super::{
    Description,
    catalog::{self, Catalog},
    icons,
};
use crate::qubes::{self, Vm};
use airlock_nix_core::identity::GuestName;
use airlock_vm_service::appmenus::valid_id;
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use uuid::Uuid;

/// Icon filenames are local content hashes, not paths supplied by application VMs.
type IconCache = BTreeMap<String, String>;

/// Create a directory only through real directories, rejecting redirected cache or publication paths.
fn directory(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "desktop directory must be absolute");
    let mut current = PathBuf::new();

    for part in path.components() {
        ensure!(
            !matches!(part, std::path::Component::ParentDir),
            "desktop directory contains traversal"
        );
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => ensure!(
                metadata.is_dir(),
                "desktop path must be a real directory: {current:?}"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir(&current)?,
            Err(error) => return Err(error.into()),
        }
    }

    Ok(())
}

/// Read one regular local cache file with the same size ceiling as the wire catalog.
fn read(path: &Path) -> Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(metadata.is_file(), "desktop cache must be a regular file");

    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(catalog::MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= catalog::MAX_BYTES,
        "desktop cache exceeds limit"
    );
    Ok(Some(bytes))
}

/// Replace a changed file through a temporary sibling; unchanged content preserves its modification time.
fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    if read(path)?.as_deref() == Some(bytes) {
        return Ok(());
    }

    let parent = path.parent().context("desktop output parent")?;
    directory(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

/// Resolve one VM's cache below the locally selected root without following a redirected child.
fn cache(name: &GuestName) -> Result<PathBuf> {
    let path = qubes::cache_root()?.join(name.as_str());
    directory(&path)?;
    Ok(path)
}

/// Keep icons independent of mutable VM names, so renames preserve launcher and icon identity.
fn icon_directory(uuid: Uuid) -> Result<PathBuf> {
    let path = qubes::data_home()?
        .join("icons/airlock")
        .join(uuid.to_string());
    directory(&path)?;
    Ok(path)
}

/// Identify only launchers owned by one VM UUID, leaving local applications and other VMs untouched.
fn prefix(uuid: Uuid) -> String {
    format!("org.qubes-os.vm.{uuid}.")
}

/// Match the explicit Qubes selection; an absent selection publishes all available applications.
fn selected(description: &Description, id: &str) -> bool {
    description.menu_items.as_deref().is_none_or(|items| {
        items == "*"
            || items
                .split_whitespace()
                .any(|item| item == id || item == format!("{id}.desktop"))
    })
}

/// Require a matching cached VM identity and every selected launcher, including an intentionally empty catalog.
pub(super) fn available(description: &Description) -> Result<bool> {
    let path = super::cached_directory(&qubes::cache_root()?, &description.name)?;
    let Some(bytes) = read(&path.join("vm.json"))? else {
        return Ok(false);
    };
    let cached: Description = serde_json::from_slice(&bytes)?;
    if cached.name != description.name
        || cached.uuid != description.uuid
        || cached.menu_items != description.menu_items
    {
        return Ok(false);
    }
    if read(&path.join("catalog.json"))?.is_none() {
        return Ok(false);
    }
    let menus = cached_catalog(&path)?;
    let applications = qubes::data_home()?.join("applications");
    let prefix = prefix(description.uuid);
    for id in menus.keys().filter(|id| selected(description, id)) {
        if read(&applications.join(format!("{prefix}{id}.desktop")))?.is_none() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Read saved icon identities and require each filename to remain inside this UUID's icon directory.
fn cached_icons(path: &Path, uuid: Uuid) -> Result<IconCache> {
    let values: IconCache = match read(&path.join("icons.json"))? {
        Some(bytes) => serde_json::from_slice(&bytes)?,
        None => BTreeMap::new(),
    };
    let root = icon_directory(uuid)?;
    let mut result = IconCache::new();

    for (id, filename) in values {
        ensure!(
            valid_id(&id)
                && filename.starts_with(&format!("{id}-"))
                && filename.ends_with(".png")
                && filename
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
            "invalid cached icon identity"
        );
        if read(&root.join(&filename))?.is_some() {
            result.insert(id, filename);
        }
    }

    Ok(result)
}

/// Generate trusted launcher syntax; the VM's advertised Exec and source path are never interpolated.
fn launcher(
    description: &Description,
    id: &str,
    fields: &BTreeMap<String, String>,
    icon: Option<&Path>,
) -> String {
    let name = &description.name;
    let mut result = format!(
        r"[Desktop Entry]
Version=1.0
Type=Application
Terminal=false
X-Qubes-VmName={name}
X-Qubes-AppName={id}
Exec=airlock-launch-qube-app %c {name} qubes.StartApp+{id}
"
    );
    for (key, value) in fields {
        let base = key.split('[').next().unwrap();
        match base {
            "Name" | "GenericName" => result.push_str(&format!("{key}={name}: {value}\n")),
            "Comment" | "Keywords" | "OnlyShowIn" | "NotShowIn" => {
                result.push_str(&format!("{key}={value}\n"))
            }
            _ => (),
        }
    }

    let class = fields
        .get("StartupWMClass")
        .map(String::as_str)
        .unwrap_or(id);
    result.push_str(&format!("StartupWMClass={name}:{class}\n"));
    let categories = fields.get("Categories").map(String::as_str).unwrap_or("");
    result.push_str(&format!("Categories={categories}X-Qubes-VM;\n"));
    if let Some(icon) = icon {
        let escaped = icon
            .to_string_lossy()
            .replace('\\', "\\\\")
            .replace(' ', "\\s");
        result.push_str(&format!("Icon={escaped}\n"));
    } else {
        result.push_str("Icon=application-x-executable\n");
    }

    result
}

/// Install the selected launchers before withdrawing obsolete ones, using the UUID as the deletion boundary.
fn render(description: &Description, menus: &Catalog, icons: &IconCache) -> Result<()> {
    let applications = qubes::data_home()?.join("applications");
    directory(&applications)?;
    let icon_root = icon_directory(description.uuid)?;
    let prefix = prefix(description.uuid);
    let mut wanted = BTreeSet::new();

    for (id, fields) in menus.iter().filter(|(id, _)| selected(description, id)) {
        ensure!(valid_id(id), "invalid cached application identity");
        let filename = format!("{prefix}{id}.desktop");
        let icon = icons.get(id).map(|filename| icon_root.join(filename));
        write(
            &applications.join(&filename),
            launcher(description, id, fields, icon.as_deref()).as_bytes(),
        )?;
        wanted.insert(filename);
    }

    for entry in fs::read_dir(&applications)? {
        let entry = entry?;
        let filename = entry.file_name().to_string_lossy().into_owned();
        if filename.starts_with(&prefix)
            && filename.ends_with(".desktop")
            && !wanted.contains(&filename)
        {
            ensure!(
                entry.file_type()?.is_file(),
                "owned launcher must be a regular file"
            );
            fs::remove_file(entry.path())?;
        }
    }

    Ok(())
}

/// Load a saved validated catalog without allowing user cache corruption to introduce new command syntax.
fn cached_catalog(path: &Path) -> Result<Catalog> {
    let bytes = read(&path.join("catalog.json"))?.context("missing cached application catalog")?;
    let menus: Catalog = serde_json::from_slice(&bytes)?;
    let mut wire = String::new();

    for (id, fields) in &menus {
        ensure!(valid_id(id), "invalid cached application identity");
        for (key, value) in fields {
            ensure!(
                !key.contains(['\n', '\r', '=', ':']) && !value.chars().any(char::is_control),
                "invalid cached application field"
            );
            wire.push_str(&format!("{id}.desktop:{key}={value}\n"));
        }
    }

    let validated = catalog::parse(wire.as_bytes())?;
    ensure!(
        validated == menus,
        "cached application catalog failed validation"
    );
    Ok(validated)
}

/// Refresh icons under a total time/byte budget, recheck trusted identity, then publish files and cache metadata.
pub(super) fn publish(vm: &Vm, menus: &Catalog) -> Result<()> {
    let path = cache(&vm.name)?;
    let description = vm.description();
    let mut icons = cached_icons(&path, vm.uuid)?;
    let icon_root = icon_directory(vm.uuid)?;
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut pending = BTreeMap::new();
    let mut bytes = 0;

    for (id, fields) in menus.iter().filter(|(id, _)| selected(&description, id)) {
        let Some(icon) = fields.get("Icon") else {
            icons.remove(id);
            continue;
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match icons::fetch(&vm.name, icon, remaining.min(Duration::from_secs(3))) {
            Ok(image) => {
                bytes += image.len();
                ensure!(
                    bytes <= 32 * 1024 * 1024,
                    "application icons exceed total publication limit"
                );
                let filename = format!("{id}-{hash:x}.png", hash = Sha256::digest(&image));
                icons.insert(id.clone(), filename.clone());
                pending.insert(filename, image);
            }
            Err(error) => eprintln!("icon for {id} could not be refreshed: {error:#}"),
        }
    }

    ensure!(
        qubes::describe(&vm.name)? == *vm,
        "VM changed before menu publication"
    );

    for (filename, image) in pending {
        write(&icon_root.join(filename), &image)?;
    }
    icons.retain(|id, _| menus.contains_key(id));
    render(&description, menus, &icons)?;

    write(&path.join("catalog.json"), &serde_json::to_vec(menus)?)?;
    write(&path.join("icons.json"), &serde_json::to_vec(&icons)?)?;
    write(&path.join("vm.json"), &serde_json::to_vec(&description)?)?;
    prune_icons(&icon_root, &icons)?;
    Ok(())
}

/// Remove unused content-addressed icons only after all launchers refer to the completed publication.
fn prune_icons(root: &Path, icons: &IconCache) -> Result<()> {
    let wanted: BTreeSet<_> = icons.values().collect();

    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let filename = entry.file_name().to_string_lossy().into_owned();
        ensure!(
            entry.file_type()?.is_file(),
            "owned icon must be a regular file"
        );
        if !wanted.contains(&filename) {
            fs::remove_file(entry.path())?;
        }
    }

    Ok(())
}

/// Re-render cached applications for a rename or selection change, including when the VM is stopped.
pub(super) fn regenerate(description: &Description) -> Result<()> {
    let path = cache(&description.name)?;
    let menus = cached_catalog(&path)?;
    let icons = cached_icons(&path, description.uuid)?;
    ensure!(
        qubes::describe(&description.name)?.description() == *description,
        "VM changed before menu regeneration"
    );

    render(description, &menus, &icons)?;
    write(&path.join("vm.json"), &serde_json::to_vec(description)?)
}

/// Withdraw only the UUID recorded for this cache; another VM's files and local launchers remain untouched.
pub(super) fn remove(name: &GuestName) -> Result<()> {
    let path = cache(name)?;
    let Some(bytes) = read(&path.join("vm.json"))? else {
        return Ok(());
    };
    let description: Description = serde_json::from_slice(&bytes)?;
    let applications = qubes::data_home()?.join("applications");
    directory(&applications)?;
    let prefix = prefix(description.uuid);
    for entry in fs::read_dir(applications)? {
        let entry = entry?;
        let filename = entry.file_name().to_string_lossy().into_owned();
        if filename.starts_with(&prefix) && filename.ends_with(".desktop") {
            ensure!(
                entry.file_type()?.is_file(),
                "owned launcher must be a regular file"
            );
            fs::remove_file(entry.path())?;
        }
    }

    let root = icon_directory(description.uuid)?;
    prune_icons(&root, &IconCache::new())?;
    fs::remove_dir(root)?;
    Ok(())
}
