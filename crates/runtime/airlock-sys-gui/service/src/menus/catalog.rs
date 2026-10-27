//! Validate VM-supplied application metadata before it reaches local files or commands.

use airlock_vm_service::appmenus::{FIELDS, valid_id};
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};

/// Only validated display fields and an icon request are retained; remote Exec never becomes a local command.
pub(super) type Catalog = BTreeMap<String, BTreeMap<String, String>>;

/// Bound the complete response independently of the number of advertised applications.
pub(super) const MAX_BYTES: usize = 16 * 1024 * 1024;

/// Reject terminal controls and desktop substitutions in display text rather than interpreting escapes.
fn text(value: &str) -> bool {
    !value
        .chars()
        .any(|character| character.is_control() || matches!(character, '%' | '\\'))
}

/// Validate a field and its optional locale as one complete key, without accepting suffix junk.
fn field(key: &str) -> Option<&str> {
    let (base, locale) = match key.split_once('[') {
        Some((base, locale)) => (base, Some(locale.strip_suffix(']')?)),
        None => (key, None),
    };
    if let Some(locale) = locale
        && (!matches!(base, "Name" | "GenericName" | "Comment" | "Keywords")
            || locale.is_empty()
            || locale.len() > 64
            || !locale
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_@.-".contains(&byte)))
    {
        return None;
    }

    FIELDS.contains(&base).then_some(base)
}

/// Keep ordinary category identifiers while excluding reserved desktop shell roles.
fn categories(value: &str) -> String {
    value
        .split(';')
        .map(str::trim)
        .filter(|category| {
            !category.is_empty()
                && category.len() <= 64
                && category
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !matches!(*category, "Screensaver" | "TrayIcon" | "Applet" | "Shell")
        })
        .map(|category| format!("{category};"))
        .collect()
}

/// Parse Qubes' line protocol with bounded framing and a complete allowlist for local desktop fields.
/// Invalid individual records are omitted; malformed framing aborts the refresh and preserves its cache.
pub(super) fn parse(bytes: &[u8]) -> Result<Catalog> {
    ensure!(
        bytes.len() <= MAX_BYTES,
        "application catalog exceeds limit"
    );
    let source = std::str::from_utf8(bytes).context("application catalog is not UTF-8")?;
    ensure!(
        source.is_empty() || source.ends_with('\n'),
        "incomplete application catalog line"
    );
    let mut result = Catalog::new();
    let mut seen = BTreeSet::new();

    for (index, line) in source.lines().enumerate() {
        ensure!(
            index < 100_000 && line.len() <= 4096,
            "application catalog framing exceeds limit"
        );
        let Some((name, attribute)) = line.split_once(':') else {
            continue;
        };
        let id = name.strip_suffix(".desktop").unwrap_or(name);
        if !valid_id(id) || id == "qubes-start" {
            continue;
        }
        let Some((key, value)) = attribute.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        let Some(base) = field(key) else {
            continue;
        };
        // Commands are resolved inside the source VM by the fixed StartApp RPC.
        if base == "Exec" || !text(value) {
            continue;
        }
        if matches!(base, "StartupWMClass" | "OnlyShowIn" | "NotShowIn")
            && !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-;".contains(&byte))
        {
            continue;
        }
        if base == "StartupWMClass" && value.contains(';') {
            continue;
        }
        if base == "Icon" && (value.is_empty() || value.len() > 1024 || value.starts_with('-')) {
            continue;
        }
        ensure!(
            seen.insert((id.to_owned(), key.to_owned())),
            "duplicate application catalog field"
        );
        let value = if base == "Categories" {
            categories(value)
        } else {
            value.to_owned()
        };
        result
            .entry(id.to_owned())
            .or_default()
            .insert(key.to_owned(), value);
    }
    ensure!(result.len() <= 4096, "too many advertised applications");
    result.retain(|_, fields| fields.get("Name").is_some_and(|name| !name.is_empty()));
    Ok(result)
}
