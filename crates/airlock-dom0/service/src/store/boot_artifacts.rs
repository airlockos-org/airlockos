//! Retained EFI payloads boot independently of the current immutable store view.
//! Checksummed descriptors authorize exact files; cleanup removes only authenticated duplicates.

use super::{fs::*, presentation};
use crate::model::{GenerationId, StorePath};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
};

/// Boot-file selection needs only these coordinates, including initial image records.
/// This projection does not authenticate storage bytes and cannot replace a HostReceipt.
#[derive(serde::Deserialize)]
pub(super) struct BootRecord {
    /// Exact host system whose retained EFI descriptor is addressed.
    pub(super) system: StorePath,
    /// Positive storage generation named by that descriptor.
    pub(super) generation: GenerationId,
    /// Retired systems are excluded from ordinary boot-file installation.
    #[serde(default)]
    pub(super) retired: Option<bool>,
}

pub(super) fn xen_config(binary: &Path) -> Result<BTreeMap<String, String>> {
    fn read_at<const N: usize>(file: &File, offset: u64) -> Result<[u8; N]> {
        let mut data = [0; N];
        file.read_exact_at(&mut data, offset)
            .context("truncated PE header")?;
        Ok(data)
    }

    ensure!(
        fs::symlink_metadata(binary)?.is_file(),
        "Xen EFI payload is not a regular file"
    );
    let file = File::open(binary)?;
    let length = file.metadata()?.len();
    let dos = read_at::<64>(&file, 0)?;
    ensure!(&dos[..2] == b"MZ", "invalid Xen EFI DOS header");
    let offset = u32::from_le_bytes(dos[60..64].try_into()?) as u64;
    let header = read_at::<24>(&file, offset)?;
    ensure!(&header[..4] == b"PE\0\0", "invalid Xen EFI PE header");
    let count = u16::from_le_bytes(header[6..8].try_into()?) as u64;
    let table = offset + 24 + u16::from_le_bytes(header[20..22].try_into()?) as u64;
    ensure!(
        count <= 96 && table + count * 40 <= length,
        "invalid EFI section table"
    );

    let mut config = None;
    for index in 0..count {
        let section = read_at::<40>(&file, table + index * 40)?;
        let name = &section[..8];
        if name.split(|b| *b == 0).next() != Some(b".config") {
            continue;
        }
        ensure!(
            config.is_none(),
            "Xen EFI requires exactly one configuration section"
        );
        let size = u32::from_le_bytes(section[16..20].try_into()?) as u64;
        let start = u32::from_le_bytes(section[20..24].try_into()?) as u64;
        ensure!(
            size > 0 && size <= 1024 * 1024 && start + size <= length,
            "invalid Xen configuration extent"
        );
        let mut bytes = vec![0; size as usize];
        file.read_exact_at(&mut bytes, start)?;
        let end = bytes.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
        config = Some(std::str::from_utf8(&bytes[..end])?.to_owned());
    }

    let config = config.context("Xen EFI requires exactly one configuration section")?;
    let mut fields = BTreeMap::new();
    for line in config.lines() {
        if let Some((key, value)) = line.split_once('=') {
            ensure!(
                fields.insert(key.to_owned(), value.to_owned()).is_none(),
                "ambiguous duplicate Xen configuration key"
            );
        }
    }
    Ok(fields)
}

fn fingerprint(path: &Path) -> Result<Value> {
    File::open(path)?.sync_all()?;
    Ok(json!({"size":fs::metadata(path)?.len(),"sha256":hash(path)?}))
}

pub(super) fn inventory(esp: &Path, system: &str) -> Result<Vec<Value>> {
    let mut entries = Vec::new();
    for path in children(&esp.join("loader/entries"))? {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .context("invalid boot entry name")?;
        if !name.starts_with("xen-") || !name.ends_with(".conf") {
            continue;
        }
        let fields = presentation::fields(&fs::read_to_string(&path)?);
        let Some(efi) = fields.get("efi").filter(|path| {
            path.starts_with("/EFI/nixos/")
                && !Path::new(path)
                    .components()
                    .any(|c| c == std::path::Component::ParentDir)
        }) else {
            continue;
        };
        let binary = esp.join(efi.trim_start_matches('/'));
        let config = xen_config(&binary)?;
        let kernel: Vec<_> = config
            .get("kernel")
            .context("missing Xen kernel")?
            .split_whitespace()
            .collect();
        if !kernel.contains(&format!("init={system}/init").as_str()) {
            continue;
        }
        let files = [
            kernel.first().copied().context("empty Xen kernel")?,
            config.get("ramdisk").context("missing Xen ramdisk")?,
        ];
        for name in &files {
            component(name)?;
        }
        let mut fingerprints = json!({});
        let parent = binary.parent().context("missing EFI parent")?;
        for file in [
            &path,
            &binary,
            &parent.join(files[0]),
            &parent.join(files[1]),
        ] {
            fingerprints[file
                .strip_prefix(esp)?
                .to_str()
                .context("invalid EFI path")?] = fingerprint(file)?;
        }
        entries.push(json!({"entry":name,"files":fingerprints}));
    }
    Ok(entries)
}

fn descriptor_path(root: &Path, system: &str) -> Result<PathBuf> {
    Ok(root
        .join("host/artifacts")
        .join(format!("{}.json", entry(system)?)))
}

pub(super) fn safe_artifact(esp: &Path, name: &str) -> Result<PathBuf> {
    let relative = Path::new(name);
    ensure!(
        !relative.is_absolute()
            && !relative.components().any(|c| matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )),
        "invalid boot artifact path"
    );
    let path = esp.join(relative);
    let mut ancestor = path.clone();
    loop {
        ensure!(!ancestor.is_symlink(), "boot artifact path is a symlink");
        if ancestor == esp {
            break;
        }
        ensure!(ancestor.pop(), "artifact has no ESP ancestor");
    }
    Ok(path)
}

pub(super) fn verify(
    root: &Path,
    esp: &Path,
    system: &StorePath,
    generation: GenerationId,
) -> Result<String> {
    let descriptor: Value = read(&descriptor_path(root, system.as_str())?)?;
    ensure!(
        descriptor["schema"] == "airlock.host-boot-artifacts.v1"
            && descriptor["system"] == system.as_str()
            && descriptor["generation"] == generation.get(),
        "host boot artifact binding mismatch"
    );
    let entries = descriptor["entries"]
        .as_array()
        .filter(|v| !v.is_empty())
        .context("missing retained boot entries")?;
    for entry in entries {
        let entry_name = text(entry, "entry")?;
        component(&entry_name)?;
        for (name, expected) in entry["files"]
            .as_object()
            .context("missing artifact checksums")?
        {
            let path = safe_artifact(esp, name)?;
            let actual = fingerprint(&path)?;
            let mut valid = &actual == expected;
            if name == &format!("loader/entries/{entry_name}") {
                valid |= descriptor["presentationMigration"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|change| change["path"] == *name && change["after"] == actual);
            }
            ensure!(valid, "missing or corrupt boot artifact: {name}");
        }
    }
    text(&entries[0], "entry")
}

pub(super) fn select_entry(esp: &Path, entry: &str, firmware: bool) -> Result<()> {
    component(entry)?;
    ensure!(
        esp.join("loader/entries").join(entry).is_file(),
        "selected loader entry missing"
    );
    let path = esp.join("loader/loader.conf");
    let previous = fs::read_to_string(&path)?;
    let lines: Vec<_> = previous
        .lines()
        .filter(|line| {
            !matches!(
                line.split_whitespace().next(),
                Some("default" | "preferred")
            )
        })
        .collect();
    if firmware {
        presentation::clear_saved_default()?;
    }
    atomic(
        &path,
        format!("default {entry}\n{}\n", lines.join("\n")).as_bytes(),
        0o644,
    )
}

fn remove_native_duplicates(esp: &Path, system: &str, selected: &str) -> Result<()> {
    let entries = inventory(esp, system)?;
    let names: BTreeSet<_> = entries
        .iter()
        .map(|v| text(v, "entry"))
        .collect::<Result<_>>()?;
    let loader = esp.join("loader/loader.conf");
    if !names.is_empty() && loader.try_exists()? {
        let text = fs::read_to_string(&loader)?;
        let lines: Vec<_> = text
            .lines()
            .map(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields.len() == 2
                    && ["default", "preferred"].contains(&fields[0])
                    && names.iter().any(|name| {
                        name.trim_end_matches(".conf") == fields[1].trim_end_matches(".conf")
                    })
                {
                    format!("{} {selected}", fields[0])
                } else {
                    line.to_owned()
                }
            })
            .collect();
        atomic(&loader, format!("{}\n", lines.join("\n")).as_bytes(), 0o644)?;
    }
    for name in names {
        remove(&esp.join("loader/entries").join(name))?;
    }
    sync_dir(&esp.join("loader/entries"))
}

fn remove_verified_native_files(esp: &Path, authenticated: &BTreeMap<String, Value>) -> Result<()> {
    let native = esp.join("EFI/nixos");
    ensure!(!native.is_symlink(), "native EFI directory is a symlink");
    let mut protected = BTreeSet::new();
    for path in children(&esp.join("loader/entries"))? {
        if path.extension().is_none_or(|s| s != "conf") {
            continue;
        }
        for (kind, name) in presentation::fields(&fs::read_to_string(path)?) {
            if !["efi", "linux", "initrd"].contains(&kind.as_str()) {
                continue;
            }
            let relative = Path::new(name.trim_start_matches('/'));
            if relative.parent() != Some(Path::new("EFI/nixos")) {
                continue;
            }
            let filename = relative
                .file_name()
                .context("missing EFI filename")?
                .to_string_lossy()
                .into_owned();
            protected.insert(filename);
            if kind == "efi" {
                let config = match xen_config(&esp.join(relative)) {
                    Ok(v) => v,
                    Err(_) => return Ok(()),
                };
                let Some(kernel) = config
                    .get("kernel")
                    .and_then(|s| s.split_whitespace().next())
                else {
                    return Ok(());
                };
                let Some(ramdisk) = config.get("ramdisk") else {
                    return Ok(());
                };
                for name in [kernel, ramdisk] {
                    if component(name).is_err() {
                        return Ok(());
                    }
                    protected.insert(name.to_owned());
                }
            }
        }
    }
    for (relative, expected) in authenticated {
        let path = Path::new(relative);
        if path.parent() != Some(Path::new("EFI/airlock")) {
            continue;
        }
        let name = path
            .file_name()
            .context("missing artifact filename")?
            .to_string_lossy()
            .into_owned();
        if protected.contains(&name) {
            continue;
        }
        let duplicate = native.join(name);
        if !duplicate.is_symlink() && duplicate.is_file() && fingerprint(&duplicate)? == *expected {
            remove(&duplicate)?;
            sync_dir(&native)?;
        }
    }
    Ok(())
}

fn refresh_presentation(path: &Path, esp: &Path) -> Result<()> {
    let mut descriptor: Value = read(path)?;
    let mut changes = descriptor["presentationMigration"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if descriptor.get("presentationMigration").is_none() {
        for entry in descriptor["entries"]
            .as_array()
            .context("missing boot entries")?
        {
            let filename = text(entry, "entry")?;
            component(&filename)?;
            let relative = format!("loader/entries/{filename}");
            let text = fs::read_to_string(safe_artifact(esp, &relative)?)?;
            let identity = presentation::identity(&text);
            let system = identity
                .get("airlock-system")
                .context("missing boot system")?;
            let source = presentation::source(Path::new(system))?;
            if source.is_none() && !identity.contains_key("airlock-revision") {
                continue;
            }
            let formatted = presentation::format(
                &text,
                presentation::generation(&text, false)?,
                identity.get("airlock-role").context("missing boot role")?,
                system,
                source.as_ref(),
            )?;
            if formatted != text {
                changes.push(json!({"path":relative,"text":formatted,"before":entry["files"][&relative],"after":{"size":formatted.len(),"sha256":hex(&Sha256::digest(formatted.as_bytes()))}}));
            }
        }
        if changes.is_empty() {
            return Ok(());
        }
        descriptor["presentationMigration"] = json!(changes);
        write(path, &descriptor, 0o644)?;
    }
    for change in changes {
        let relative = text(&change, "path")?;
        atomic(
            &safe_artifact(esp, &relative)?,
            text(&change, "text")?.as_bytes(),
            0o644,
        )?;
        for entry in descriptor["entries"]
            .as_array_mut()
            .context("missing boot entries")?
        {
            if entry["files"].get(&relative).is_some() {
                entry["files"][&relative] = change["after"].clone();
            }
        }
    }
    descriptor
        .as_object_mut()
        .context("invalid boot descriptor")?
        .remove("presentationMigration");
    write(path, &descriptor, 0o644)
}

pub(super) fn seal(root: &Path, esp: &Path, keep_default: bool, firmware: bool) -> Result<()> {
    let mut records = Vec::new();
    let mut authenticated = BTreeMap::new();
    for path in children(&root.join("host/boots"))? {
        let record: BootRecord = read(&path)?;
        if record.retired == Some(true) {
            continue;
        }
        let system = record.system.as_str();
        let descriptor = descriptor_path(root, system)?;
        if descriptor.try_exists()? {
            let selected = verify(root, esp, &record.system, record.generation)?;
            refresh_presentation(&descriptor, esp)?;
            remove_native_duplicates(esp, system, &selected)?;
            let value: Value = read(&descriptor)?;
            for entry in value["entries"]
                .as_array()
                .context("missing retained entries")?
            {
                authenticated.extend(
                    entry["files"]
                        .as_object()
                        .context("missing fingerprints")?
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone())),
                );
            }
        }
        records.push((record, descriptor));
    }
    remove_verified_native_files(esp, &authenticated)?;
    for (record, descriptor) in records {
        if descriptor.try_exists()? {
            continue;
        }
        let system = record.system.as_str();
        let mut retained = Vec::new();
        for entry in inventory(esp, system)? {
            let original = text(&entry, "entry")?;
            let name = format!("airlock-{original}");
            let source_entry = esp.join("loader/entries").join(&original);
            let mut files = json!({});
            for (relative, fingerprint) in
                entry["files"].as_object().context("missing fingerprints")?
            {
                let source = safe_artifact(esp, relative)?;
                if source == source_entry {
                    continue;
                }
                let filename = source.file_name().context("missing boot filename")?;
                let target = esp.join("EFI/airlock").join(filename);
                if target.try_exists()? {
                    ensure!(
                        hash(&target)? == text(fingerprint, "sha256")?,
                        "retained EFI filename collision"
                    );
                } else {
                    atomic(&target, &fs::read(source)?, 0o644)?;
                }
                files[target
                    .strip_prefix(esp)?
                    .to_str()
                    .context("invalid retained path")?] = fingerprint.clone();
            }
            let text = fs::read_to_string(source_entry)?.replace("/EFI/nixos/", "/EFI/airlock/");
            let metadata = presentation::identity(&text);
            let role = match metadata.get("airlock-role") {
                Some(role) => role.clone(),
                None => fs::read_to_string(Path::new(system).join("etc/airlock/boot-role"))?
                    .trim()
                    .to_owned(),
            };
            let formatted = presentation::format(
                &text,
                presentation::generation(&text, true)?,
                &role,
                system,
                presentation::source(Path::new(system))?.as_ref(),
            )?;
            let target = esp.join("loader/entries").join(&name);
            atomic(&target, formatted.as_bytes(), 0o644)?;
            files[target
                .strip_prefix(esp)?
                .to_str()
                .context("invalid entry path")?] = fingerprint(&target)?;
            retained.push(json!({"entry":name,"files":files}));
        }
        if !retained.is_empty() {
            write(
                &descriptor,
                &json!({"schema":"airlock.host-boot-artifacts.v1","system":system,"generation":record.generation,"entries":retained}),
                0o644,
            )?;
            let selected = verify(root, esp, &record.system, record.generation)?;
            remove_native_duplicates(esp, system, &selected)?;
            for entry in retained {
                authenticated.extend(
                    entry["files"]
                        .as_object()
                        .context("missing fingerprints")?
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone())),
                );
            }
            remove_verified_native_files(esp, &authenticated)?;
        }
    }
    if !keep_default
        && esp.join("loader/loader.conf").try_exists()?
        && let Ok(newest) = presentation::newest(&esp.join("loader/entries"))
    {
        select_entry(esp, &newest, firmware)?;
    }
    Ok(())
}

pub(super) fn forget(root: &Path, esp: &Path, system: &str) -> Result<()> {
    let descriptor = descriptor_path(root, system)?;
    if !descriptor.try_exists()? {
        return Ok(());
    }
    let mut retained = BTreeSet::new();
    for path in children(&root.join("host/artifacts"))? {
        if path == descriptor {
            continue;
        }
        let value: Value = read(&path)?;
        for entry in value["entries"]
            .as_array()
            .context("missing boot entries")?
        {
            retained.extend(
                entry["files"]
                    .as_object()
                    .context("missing fingerprints")?
                    .keys()
                    .cloned(),
            );
        }
    }
    let value: Value = read(&descriptor)?;
    for entry in value["entries"]
        .as_array()
        .context("missing boot entries")?
    {
        for name in entry["files"]
            .as_object()
            .context("missing fingerprints")?
            .keys()
        {
            ensure!(
                name.starts_with("EFI/airlock/") || name.starts_with("loader/entries/airlock-"),
                "invalid retained boot artifact path"
            );
            if !retained.contains(name) {
                let path = safe_artifact(esp, name)?;
                remove(&path)?;
                if let Some(parent) = path.parent().filter(|p| p.exists()) {
                    sync_dir(parent)?;
                }
            }
        }
    }
    remove(&descriptor)?;
    sync_dir(
        descriptor
            .parent()
            .context("missing boot artifact directory")?,
    )
}
