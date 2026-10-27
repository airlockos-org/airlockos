//! Copy selected boot logs and capture fixed host commands without trusting file names as commands.

use super::{Supervisor, model::AttemptId};
use crate::{process::Runner, state};
use anyhow::{Context, Result, ensure};
use rustix::fs::{Mode, OFlags, open};
use serde_json::json;
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::Path,
    time::Duration,
};

const COPY_LIMIT: u64 = 64 * 1024 * 1024;

fn publish(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("diagnostic file has no parent")?;
    state::directory(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    if path.try_exists()? {
        state::trusted(path)?;
    }
    file.persist(path).map_err(|e| e.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

impl Supervisor {
    fn copy_diagnostics(&self, id: &AttemptId, destination: &Path) -> Result<()> {
        let mut copied = Vec::new();
        let mut errors = String::new();
        for (directory, airlock) in [
            ("var/log/airlock-xen-console", false),
            ("var/log/xen/console", false),
            ("var/log/xen", false),
            ("var/log/qubes", false),
            ("var/log/airlock", true),
        ] {
            let source_root = self.diagnostic.join(directory);
            let entries = match fs::read_dir(&source_root) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    errors.push_str(&format!("{}: {error}\n", source_root.display()));
                    continue;
                }
            };
            let mut paths = entries
                .map(|e| e.map(|e| e.path()))
                .collect::<std::io::Result<Vec<_>>>()?;
            paths.sort();
            for path in paths {
                let name = path
                    .file_name()
                    .context("log has no name")?
                    .to_string_lossy();
                if (airlock && !name.ends_with(".json") && !name.ends_with(".log"))
                    || (!airlock && !name.contains(".log"))
                    || name.starts_with('.')
                {
                    continue;
                }
                // Avoid devices, FIFOs and symlink-selected sources during privileged capture.
                if !fs::symlink_metadata(&path)?.is_file() {
                    continue;
                }
                let relative = path.strip_prefix(&self.diagnostic)?;
                let result = (|| -> Result<()> {
                    let input = File::from(open(
                        &path,
                        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                        Mode::empty(),
                    )?);
                    ensure!(
                        input.metadata()?.is_file(),
                        "diagnostic source is not regular"
                    );
                    let mut data = Vec::new();
                    input.take(COPY_LIMIT + 1).read_to_end(&mut data)?;
                    ensure!(
                        data.len() as u64 <= COPY_LIMIT,
                        "diagnostic source exceeds 64 MiB limit"
                    );
                    publish(&destination.join(relative), &data)
                })();
                match result {
                    Ok(()) => copied.push(relative.to_string_lossy().into_owned()),
                    Err(error) => errors.push_str(&format!("{}: {error:#}\n", path.display())),
                }
            }
        }
        if !errors.is_empty() {
            publish(&destination.join("copy-errors.log"), errors.as_bytes())?;
        }
        state::save(
            &destination.join("copied.json"),
            &json!({"boot_id":id,"files":copied}),
        )
    }

    pub(super) fn snapshot(
        &self,
        id: &AttemptId,
        label: &str,
        journal: Option<&AttemptId>,
    ) -> Result<()> {
        super::model::snapshot_label(label)?;
        let destination = self.logs.join(id.to_string()).join("snapshots").join(label);
        state::directory(&destination)?;
        self.copy_diagnostics(id, &destination)?;

        let mut commands = vec![
            ("xl-list.txt", "xl", vec!["list", "-l"]),
            ("xl-dmesg.txt", "xl", vec!["dmesg"]),
            (
                "qvm-ls.txt",
                "qvm-ls",
                vec!["--raw-data", "--fields", "NAME,STATE,XID"],
            ),
            (
                "failed-units.txt",
                "systemctl",
                vec!["--failed", "--no-pager"],
            ),
            ("memory.txt", "free", vec!["-h"]),
        ];
        let journal_id = journal.map(ToString::to_string);
        let mut journal_args = vec!["--boot"];
        if let Some(id) = journal_id.as_deref() {
            journal_args.push(id);
        }
        journal_args.push("--no-pager");
        commands.push(("journal.txt", "journalctl", journal_args));

        let runner = Runner::default();
        for (name, program, args) in commands {
            let arguments = args.iter().map(Into::into).collect::<Vec<_>>();
            let text = match runner.capture(program, &arguments, Duration::from_secs(30), &[]) {
                Ok(captured) => format!(
                    "exit={} limited={} command={program} {args:?}\n{}{}",
                    captured.status,
                    captured.limited,
                    String::from_utf8_lossy(&captured.stdout),
                    String::from_utf8_lossy(&captured.stderr)
                ),
                Err(error) => format!("command={program} {args:?} error={error:#}\n"),
            };
            publish(&destination.join(name), text.as_bytes())?;
        }
        Ok(())
    }
}
