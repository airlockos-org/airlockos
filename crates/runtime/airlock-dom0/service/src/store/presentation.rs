//! Boot entries show the committed source identity and sort normal boots before recovery.
//! Formatting preserves loader directives while replacing only Airlock's presentation fields.

use super::fs::*;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::Path};

pub(super) fn fields(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.splitn(2, char::is_whitespace);
            Some((fields.next()?.to_owned(), fields.next()?.trim().to_owned()))
        })
        .collect()
}

pub(super) fn identity(text: &str) -> BTreeMap<String, String> {
    fields(
        &text
            .lines()
            .filter_map(|line| {
                line.strip_prefix("# airlock-")
                    .map(|line| format!("airlock-{line}"))
            })
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

pub(super) fn generation(text: &str, upstream: bool) -> Result<u64> {
    let identity = identity(text);
    let number = if let Some(value) = identity.get("airlock-generation") {
        value.parse()?
    } else {
        ensure!(upstream, "boot entry lacks explicit generation");
        fields(text)
            .get("version")
            .context("missing boot version")?
            .strip_prefix("Generation ")
            .context("invalid boot version")?
            .split_whitespace()
            .next()
            .context("missing boot generation")?
            .parse()?
    };
    ensure!(number > 0, "boot generation must be positive");
    Ok(number)
}

pub(super) fn source(system: &Path) -> Result<Option<Value>> {
    let path = system.join("etc/airlock/boot-source.json");
    if path.try_exists()? {
        Ok(Some(read(&path)?))
    } else {
        Ok(None)
    }
}

pub(super) fn format(
    text: &str,
    number: u64,
    role: &str,
    system: &str,
    source: Option<&Value>,
) -> Result<String> {
    ensure!(
        ["normal", "recovery"].contains(&role) && number > 0,
        "invalid boot identity"
    );
    let identity = identity(text);
    let saved=identity.get("airlock-revision").map(|revision|->Result<Value>{Ok(json!({"revision":revision,"timestamp":identity.get("airlock-timestamp").context("missing boot timestamp")?.parse::<u64>()?}))}).transpose()?;
    let source = source
        .or(saved.as_ref())
        .context("boot entry requires committed source provenance")?;
    // Source revisions in boot metadata are fixed SHA-1 Git identities.
    let revision_text = super::fs::text(source, "revision")?;
    ensure!(
        revision_text.len() == 40
            && revision_text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid boot revision"
    );
    let timestamp = super::fs::number(source, "timestamp")?;
    ensure!(timestamp > 0, "invalid boot timestamp");
    let date = command(
        "date",
        &["-u", "-d", &format!("@{timestamp}"), "+%Y-%m-%d_%H:%M"],
        None,
    )?;
    let label = format!("{}-{}", date.trim(), &revision_text[..7]);
    let mut lines = vec![
        format!(
            "title Airlock ({}{label})",
            if role == "recovery" { "recovery, " } else { "" }
        ),
        format!(
            "sort-key {}-{:020}",
            if role == "normal" {
                "00-airlock"
            } else {
                "01-airlock-recovery"
            },
            u64::MAX - number
        ),
    ];
    lines.extend(
        text.lines()
            .filter(|line| {
                ![
                    "title ",
                    "version ",
                    "sort-key ",
                    "machine-id ",
                    "# airlock-",
                ]
                .iter()
                .any(|prefix| line.starts_with(prefix))
            })
            .map(str::to_owned),
    );
    lines.extend([
        format!("# airlock-generation {number}"),
        format!("# airlock-role {role}"),
        format!("# airlock-system {system}"),
        format!("# airlock-revision {revision_text}"),
        format!("# airlock-timestamp {timestamp}"),
    ]);
    Ok(format!("{}\n", lines.join("\n")))
}

pub(super) fn newest(entries: &Path) -> Result<String> {
    let mut choices = Vec::new();
    for path in children(entries)? {
        if path.extension().is_none_or(|s| s != "conf") {
            continue;
        }
        let text = fs::read_to_string(&path)?;
        if identity(&text)
            .get("airlock-role")
            .is_some_and(|s| s == "normal")
        {
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .context("invalid entry filename")?
                .to_owned();
            choices.push((
                generation(&text, false)?,
                name.starts_with("airlock-"),
                name,
            ));
        }
    }
    choices.sort();
    choices
        .pop()
        .map(|(_, _, name)| name)
        .context("no normal Airlock boot entry")
}

pub(super) fn clear_saved_default() -> Result<()> {
    for (variable, operation) in [
        ("LoaderEntryDefault", "set-default"),
        ("LoaderEntryPreferred", "set-preferred"),
    ] {
        if Path::new("/sys/firmware/efi/efivars")
            .join(format!("{variable}-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"))
            .try_exists()?
        {
            command("bootctl", &[operation, ""], None)?;
        }
    }
    Ok(())
}

/// One menu choice with explicit VM-independent host boot identity.
struct MenuEntry {
    // Loader entry file selected for this generation and role.
    path: std::path::PathBuf,
    // NixOS profile generation, used independently of source dates for ordering.
    generation: u64,
    // Normal host boot or independent recovery.
    role: String,
    // Physical system path used to read installed source and role markers.
    system: std::path::PathBuf,
}

fn classified(entries: &Path, store: &Path) -> Result<Vec<MenuEntry>> {
    let mut output = Vec::new();
    for path in children(entries)? {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .context("invalid entry name")?;
        let retained = name.starts_with("airlock-xen-");
        if !name.ends_with(".conf") || (!retained && !name.starts_with("xen-")) {
            continue;
        }
        let text = fs::read_to_string(&path)?;
        let metadata = identity(&text);
        let number = match generation(&text, !retained) {
            Ok(value) => value,
            Err(error) => {
                if retained {
                    return Err(error);
                }
                continue;
            }
        };
        let system = if let Some(logical) = metadata
            .get("airlock-system")
            .filter(|s| s.starts_with("/nix/store/"))
        {
            Some(
                store.join(
                    Path::new(logical)
                        .file_name()
                        .context("missing host basename")?,
                ),
            )
        } else {
            let ordinary =
                path.with_file_name(format!("nixos-{}", name.trim_start_matches("xen-")));
            if ordinary.is_file() {
                fields(&fs::read_to_string(ordinary)?)
                    .get("options")
                    .and_then(|options| {
                        options.split_whitespace().find_map(|word| {
                            word.strip_prefix("init=")
                                .and_then(|p| p.strip_suffix("/init"))
                                .filter(|p| p.starts_with("/nix/store/"))
                                .and_then(|p| Path::new(p).file_name())
                                .map(|name| store.join(name))
                        })
                    })
            } else {
                None
            }
        };
        let Some(system) = system else {
            continue;
        };
        let marker = system.join("etc/airlock/boot-role");
        let role = metadata
            .get("airlock-role")
            .cloned()
            .or(if marker.is_file() {
                Some(fs::read_to_string(marker)?.trim().to_owned())
            } else {
                None
            });
        if let Some(role) = role.filter(|role| ["normal", "recovery"].contains(&role.as_str())) {
            output.push(MenuEntry {
                path,
                generation: number,
                role,
                system,
            });
        }
    }
    Ok(output)
}

pub(super) fn configure_menu(
    esp: &Path,
    store: &Path,
    recovery_profile: Option<&Path>,
    nix_env: &str,
    firmware: bool,
    dry_run: bool,
) -> Result<Value> {
    let entries = esp.join("loader/entries");
    let loader = esp.join("loader/loader.conf");
    ensure!(
        entries.is_dir() && loader.is_file(),
        "systemd-boot files missing from EFI partition"
    );
    let mut grouped: BTreeMap<(String, u64), Vec<MenuEntry>> = BTreeMap::new();
    for entry in classified(&entries, store)? {
        grouped
            .entry((entry.role.clone(), entry.generation))
            .or_default()
            .push(entry);
    }
    let mut selected = Vec::new();
    for choices in grouped.values_mut() {
        choices.sort_by_key(|entry| {
            (
                !entry
                    .path
                    .file_name()
                    .is_some_and(|s| s.to_string_lossy().starts_with("airlock-")),
                entry.path.clone(),
            )
        });
        selected.push(choices.remove(0));
    }
    selected.sort_by_key(|entry| std::cmp::Reverse(entry.generation));
    let current = selected
        .iter()
        .find(|e| e.role == "normal")
        .context("no Xen Airlock normal boot entry was generated")?;
    let recovery = selected
        .iter()
        .find(|e| e.role == "recovery")
        .context("no Xen Airlock recovery boot entry was generated")?;
    let mut formatted = Vec::new();
    for entry in &selected {
        if entry
            .path
            .file_name()
            .is_some_and(|s| s.to_string_lossy().starts_with("airlock-"))
        {
            continue;
        }
        let logical = format!(
            "/nix/store/{}",
            entry
                .system
                .file_name()
                .context("missing system basename")?
                .to_string_lossy()
        );
        let formatted_text = format(
            &fs::read_to_string(&entry.path)?,
            entry.generation,
            &entry.role,
            &logical,
            source(&entry.system)?.as_ref(),
        )?;
        formatted.push((&entry.path, formatted_text));
    }
    let receipt = json!({"default": current.path.file_name().context("invalid selected entry")?, "entries": selected.iter().map(|e|json!({"path":e.path,"generation":e.generation,"role":e.role,"system":e.system})).collect::<Vec<_>>()});
    if dry_run {
        return Ok(receipt);
    }
    if let Some(profile) = recovery_profile.filter(|_| {
        !recovery
            .path
            .file_name()
            .is_some_and(|s| s.to_string_lossy().starts_with("airlock-"))
    }) {
        mkdir_all(
            profile
                .parent()
                .context("missing recovery profile parent")?,
        )?;
        command(
            nix_env,
            &[
                "--profile",
                &profile.to_string_lossy(),
                "--set",
                &recovery.system.to_string_lossy(),
            ],
            None,
        )?;
    }
    for path in children(&entries)? {
        let name = path
            .file_name()
            .context("invalid entry path")?
            .to_string_lossy();
        if path.extension().is_some_and(|s| s == "conf")
            && (name.starts_with("nixos-") || name.starts_with("xen-"))
            && !selected.iter().any(|e| e.path == path)
        {
            remove(&path)?;
        }
    }
    for (path, text) in formatted {
        atomic(path, text.as_bytes(), 0o644)?;
    }
    let name = current
        .path
        .file_name()
        .and_then(|s| s.to_str())
        .context("invalid selected entry")?;
    let text = fs::read_to_string(&loader)?;
    let preferred = fields(&text).contains_key("preferred");
    if firmware {
        clear_saved_default()?;
    }
    let mut lines: Vec<_> = text
        .lines()
        .filter(|line| {
            !matches!(
                line.split_whitespace().next(),
                Some("default" | "preferred")
            )
        })
        .map(str::to_owned)
        .collect();
    lines.push(format!("default {name}"));
    if preferred {
        lines.push(format!("preferred {name}"));
    }
    atomic(&loader, format!("{}\n", lines.join("\n")).as_bytes(), 0o644)?;
    Ok(
        json!({"default":name,"entries":selected.iter().map(|e|json!({"path":e.path,"generation":e.generation,"role":e.role,"system":e.system})).collect::<Vec<_>>()}),
    )
}
