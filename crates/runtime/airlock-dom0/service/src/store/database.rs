//! Offline Nix database replacement preserves validity metadata and realization references.
//! The previous complete database remains recoverable until the replacement rename is durable.

use super::{builder, fs::*};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OpenFlags, params, params_from_iter, types::Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    path::Path,
    time::Duration,
};

pub(super) fn recover(sysroot: &Path) -> Result<()> {
    let state = sysroot.join("nix/var/nix");
    let database = state.join("db");

    let previous = state.join("airlock-db-previous");
    if !database.try_exists()? && previous.try_exists()? {
        fs::rename(&previous, &database)?;
        sync_dir(&state)?;
    }
    if database.try_exists()? {
        remove(&previous)?;
    }
    remove(&state.join("airlock-db-pending"))
}

pub(super) fn dump(sysroot: &Path) -> Result<String> {
    recover(sysroot)?;
    ensure!(
        sysroot.join("nix/var/nix/db/db.sqlite").is_file(),
        "host upper registration database missing"
    );
    command(
        "nix-store",
        &[
            "--store",
            &format!("local?root={}", sysroot.display()),
            "--dump-db",
        ],
        None,
    )
}

pub(super) fn seed(source: &Path, destination: &Path) -> Result<()> {
    if destination.try_exists()? {
        return Ok(());
    }

    let parent = destination.parent().context("missing metadata parent")?;
    mkdir_all(parent)?;
    let temporary = tempfile::tempdir_in(parent)?;
    let path = temporary.path().join("db.sqlite");
    let source = Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut target = Connection::open(&path)?;
    {
        let backup = rusqlite::backup::Backup::new(&source, &mut target)?;
        backup.run_to_completion(128, Duration::from_millis(10), None)?;
    }

    target.close().map_err(|(_, error)| error)?;
    File::open(&path)?.sync_all()?;
    fs::rename(path, destination)?;
    sync_dir(parent)
}

fn columns(connection: &Connection, table: &str) -> Result<Vec<String>> {
    // All table names supplied here are fixed program constants.
    Ok(connection
        .prepare(&format!("PRAGMA table_info({table})"))?
        .query_map([], |row| row.get(1))?
        .collect::<rusqlite::Result<_>>()?)
}

fn copy_metadata(source: &Path, target: &Path) -> Result<()> {
    let source = Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut target = Connection::open(target)?;
    let transaction = target.transaction()?;
    let old_columns = columns(&source, "ValidPaths")?;
    let new_columns = columns(&transaction, "ValidPaths")?;
    let extras: Vec<_> = ["registrationTime", "ultimate", "sigs", "ca"]
        .into_iter()
        .filter(|c| old_columns.iter().any(|v| v == c) && new_columns.iter().any(|v| v == c))
        .collect();
    if !extras.is_empty() {
        let mut query =
            source.prepare(&format!("SELECT path,{} FROM ValidPaths", extras.join(",")))?;
        let rows = query.query_map([], |row| {
            (0..=extras.len())
                .map(|column| row.get::<_, Value>(column))
                .collect::<rusqlite::Result<Vec<_>>>()
        })?;
        let sql = format!(
            "UPDATE ValidPaths SET {} WHERE path=?",
            extras
                .iter()
                .map(|c| format!("{c}=?"))
                .collect::<Vec<_>>()
                .join(",")
        );
        for row in rows {
            let mut row = row?;
            let path = row.remove(0);
            row.push(path);
            transaction.execute(&sql, params_from_iter(row))?;
        }
    }

    let old_paths: BTreeMap<i64, String> = source
        .prepare("SELECT id,path FROM ValidPaths")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let new_paths: BTreeMap<String, i64> = transaction
        .prepare("SELECT path,id FROM ValidPaths")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let tables: BTreeSet<String> = source
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    if tables.contains("DerivationOutputs") {
        let mut query = source.prepare("SELECT drv,id,path FROM DerivationOutputs")?;
        for row in query.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })? {
            let (old, name, path) = row?;
            if let Some(id) = old_paths.get(&old).and_then(|path| new_paths.get(path)) {
                transaction.execute(
                    "INSERT OR REPLACE INTO DerivationOutputs (drv,id,path) VALUES (?,?,?)",
                    params![id, name, path],
                )?;
            }
        }
    }

    if tables.contains("Realisations") {
        let real_columns = columns(&source, "Realisations")?;
        ensure!(
            real_columns
                .iter()
                .all(|name| name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')),
            "unsupported realization columns"
        );
        let output_column = real_columns
            .iter()
            .position(|v| v == "outputPath")
            .context("unsupported realization schema")?;
        let id_column = real_columns
            .iter()
            .position(|v| v == "id")
            .context("realization lacks id")?;
        let sql = format!(
            "INSERT OR REPLACE INTO Realisations ({}) VALUES ({})",
            real_columns.join(","),
            vec!["?"; real_columns.len()].join(",")
        );
        let mut query = source.prepare("SELECT * FROM Realisations")?;
        let mut retained = BTreeSet::new();
        for row in query.query_map([], |row| {
            (0..real_columns.len())
                .map(|column| row.get::<_, Value>(column))
                .collect::<rusqlite::Result<Vec<_>>>()
        })? {
            let mut values = row?;
            let Value::Integer(old_id) = values[output_column] else {
                anyhow::bail!("invalid realization output identity")
            };
            if let Some(id) = old_paths.get(&old_id).and_then(|path| new_paths.get(path)) {
                values[output_column] = Value::Integer(*id);
                let Value::Integer(real_id) = values[id_column] else {
                    anyhow::bail!("invalid realization id")
                };
                retained.insert(real_id);
                transaction.execute(&sql, params_from_iter(values))?;
            }
        }
        if tables.contains("RealisationRefs") {
            let mut query =
                source.prepare("SELECT referrer,realisationReference FROM RealisationRefs")?;
            for row in
                query.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?
            {
                let (referrer, reference) = row?;
                if retained.contains(&referrer) && retained.contains(&reference) {
                    transaction.execute("INSERT OR IGNORE INTO RealisationRefs (referrer,realisationReference) VALUES (?,?)",params![referrer,reference])?;
                }
            }
        }
    }

    transaction.commit()?;
    target.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    Ok(())
}

pub(super) fn replace(
    sysroot: &Path,
    registration: &str,
    state_root: &Path,
    metadata_source: &Path,
) -> Result<()> {
    builder::registration(registration)?;
    let state = state_root.join("nix/var/nix");
    mkdir_all(&state)?;
    let staging = state.join("airlock-db-pending");
    mkdir(&staging)?;
    let store = staging.join("nix/store");
    mkdir_all(&store)?;
    command(
        "mount",
        &[
            "--bind",
            &sysroot.join("nix/store").to_string_lossy(),
            &store.to_string_lossy(),
        ],
        None,
    )?;
    let result = (|| -> Result<()> {
        command(
            "mount",
            &["-o", "remount,bind,ro", &store.to_string_lossy()],
            None,
        )?;
        command(
            "nix-store",
            &[
                "--store",
                &format!("local?root={}", staging.display()),
                "--load-db",
            ],
            Some(registration.as_bytes()),
        )?;
        Ok(())
    })();
    let unmount = command("umount", &[&store.to_string_lossy()], None);
    result?;
    unmount?;

    let old = state.join("db");
    let new = staging.join("nix/var/nix/db");
    if metadata_source.try_exists()? {
        copy_metadata(metadata_source, &new.join("db.sqlite"))?;
    }

    for file in children(&new)? {
        if file.is_file() {
            File::open(file)?.sync_all()?;
        }
    }
    sync_dir(&new)?;

    let previous = state.join("airlock-db-previous");
    failpoint("host-before-database-replace")?;
    if old.try_exists()? {
        fs::rename(&old, &previous)?;
        sync_dir(&state)?;
    }
    fs::rename(&new, &old)?;
    sync_dir(&state)?;
    failpoint("host-after-database-replace")?;
    remove(&previous)?;
    remove(&staging)
}
