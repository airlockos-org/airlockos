//! Discover applications from active XDG profiles, preserving higher-priority masks.
//! Retained Nix generations are not searched: the selected profiles define what is installed.

use anyhow::{Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use airlock_vm_service::appmenus::FIELDS;

type Entries = BTreeMap<String, BTreeMap<String, String>>;

fn token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn window_class(command: &str) -> Option<String> {
    let mut args = shlex::split(command)?;
    if args
        .first()
        .and_then(|a| Path::new(a).file_name())
        .is_some_and(|v| v == "env")
    {
        args.remove(0);
        while args.first().is_some_and(|a| {
            a.split_once('=').is_some_and(|(k, _)| {
                !k.is_empty()
                    && k.bytes().enumerate().all(|(i, b)| {
                        b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit())
                    })
            })
        }) {
            args.remove(0);
        }
        if args.first().is_some_and(|a| a == "--") {
            args.remove(0);
        }
    }
    let executable = args.first().filter(|a| !a.starts_with('-'))?;
    let basename = Path::new(executable).file_name()?.to_str()?;
    token(basename).then(|| basename.to_owned())
}

fn fields(text: &str) -> Option<BTreeMap<String, String>> {
    let mut active = false;
    let mut values = BTreeMap::new();
    for item in ini_core::Parser::new(text)
        .auto_trim(true)
        .comment_char(b'#')
    {
        match item {
            ini_core::Item::Section(name) => active = name == "Desktop Entry",
            ini_core::Item::Property(key, Some(value)) if active => {
                values.insert(key.to_owned(), value.to_owned());
            }
            ini_core::Item::Error(_) => return None,
            ini_core::Item::Property(key, None) if active && !key.starts_with(';') => return None,
            _ => (),
        }
    }
    Some(values)
}

fn walk(
    root: &Path,
    current: &Path,
    visited: &mut BTreeSet<(u64, u64)>,
    files: &mut Vec<(String, PathBuf)>,
    depth: usize,
) -> Result<()> {
    ensure!(depth < 256, "desktop directory nesting is too deep");
    let metadata = fs::metadata(current)?;
    if !visited.insert((metadata.dev(), metadata.ino())) {
        return Ok(());
    }
    let mut children = fs::read_dir(current)?
        .map(|e| e.map(|v| v.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    children.sort();
    for path in children {
        let metadata = fs::metadata(&path)?;
        if metadata.is_dir() {
            walk(root, &path, visited, files, depth + 1)?;
        } else if path.extension().is_some_and(|v| v == "desktop") {
            let relative = path.strip_prefix(root)?.to_string_lossy().replace('/', "-");
            files.push((relative, path));
            ensure!(files.len() <= 10000, "too many desktop entries");
        }
    }
    Ok(())
}

fn executable(value: &str) -> bool {
    let check = |p: &Path| fs::metadata(p).is_ok_and(|m| m.is_file() && m.mode() & 0o111 != 0);
    if value.contains('/') {
        return check(Path::new(value));
    }
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .any(|p| check(&p.join(value)))
}

fn catalog(directories: &[PathBuf]) -> Result<Entries> {
    let persistence = std::env::var("AIRLOCK_VM_PERSISTENCE").unwrap_or_else(|_| "full".into());
    let rw_device = fs::metadata("/rw").ok().map(|v| v.dev());
    let mut entries = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for directory in directories {
        let metadata = match fs::metadata(directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        ensure!(
            metadata.is_dir(),
            "application directory is not a directory"
        );
        if persistence != "full"
            && (persistence != "rw-only" || Some(fs::metadata(directory)?.dev()) != rw_device)
        {
            continue;
        }
        let mut files = Vec::new();
        walk(directory, directory, &mut BTreeSet::new(), &mut files, 0)?;
        for (id, path) in files {
            if !token(&id) || !seen.insert(id.clone()) {
                continue;
            }
            ensure!(seen.len() <= 10000, "too many desktop entries");
            // Nix profiles use symlinks, but a replaced FIFO must not block the scan.
            let file = File::from(rustix::fs::open(
                &path,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )?);
            let metadata = file.metadata()?;
            ensure!(
                metadata.is_file() && metadata.len() <= 1024 * 1024,
                "invalid or oversized desktop entry"
            );
            let mut bytes = Vec::new();
            file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() <= 1024 * 1024,
                "desktop entry changed beyond size limit"
            );
            let Ok(text) = String::from_utf8(bytes) else {
                continue;
            };
            let Some(mut values) = fields(&text) else {
                continue;
            };
            let truth = |key: &str| {
                values
                    .get(key)
                    .is_some_and(|v| v.eq_ignore_ascii_case("true"))
            };
            if values.get("Type").is_some_and(|v| v != "Application")
                || truth("Hidden")
                || truth("NoDisplay")
                || values.get("Name").is_none_or(|v| v.is_empty())
                || (values.get("Exec").is_none_or(|v| v.is_empty()) && !truth("DBusActivatable"))
                || values
                    .get("Categories")
                    .is_some_and(|v| v.split(';').any(|v| v == "Screensaver"))
                || values.get("TryExec").is_some_and(|v| !executable(v))
            {
                continue;
            }
            if values.get("StartupWMClass").is_none_or(|v| v.is_empty()) {
                values.remove("StartupWMClass");
                if let Some(class) = values.get("Exec").and_then(|v| window_class(v)) {
                    values.insert("StartupWMClass".into(), class);
                }
            }
            values.retain(|k, v| {
                FIELDS.contains(&k.split('[').next().unwrap_or_default())
                    && !v.contains(['\n', '\r'])
            });
            values.insert("Exec".into(), format!("qubes-desktop-run {id}"));
            values.insert(
                "X-Airlock-Source".into(),
                fs::canonicalize(path)?.to_string_lossy().into_owned(),
            );
            entries.insert(id, values);
        }
    }
    Ok(entries)
}

pub(crate) fn execute() -> Result<String> {
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow::anyhow!("HOME is not set"))?;
    let first = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(home).join(".local/share"));
    let mut directories = vec![first];
    directories.extend(std::env::split_paths(
        &std::env::var_os("XDG_DATA_DIRS").unwrap_or_else(|| "/usr/local/share:/usr/share".into()),
    ));
    let mut unique = BTreeSet::new();
    let directories = directories
        .into_iter()
        .filter(|v| v.is_absolute() && unique.insert(v.clone()))
        .map(|v| v.join("applications"))
        .collect::<Vec<_>>();
    let entries = catalog(&directories)?;
    let mut encoded = String::new();
    for (id, fields) in entries {
        for (key, value) in fields {
            encoded.push_str(&format!("{id}:{key}={value}\n"));
        }
    }
    Ok(encoded)
}
