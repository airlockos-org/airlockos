//! Maintenance requests select a fixed operation and its exact recorded target.
//! The installed or previously selected coordinator remains responsible for
//! reference checks, confirmation, locking and the resulting machine changes.

use super::*;
use crate::model::StorePath;
use serde::Deserialize;

pub(super) const SCHEMA: &str = "airlock.machine-control.v1";

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
enum Control {
    // Empty struct variants reject extra fields; serde unit variants discard them.
    Status {},
    Verify {},
    Resume {},
    Rollback {},
    TrashList {},
    ReleaseList {},
    TrashPurge {
        // Exact retired-VM record; traversal and option-like names are rejected.
        identity: String,
        // Must repeat the complete target before irreversible removal.
        confirm: String,
        // Explicit permission to waive the ordinary trash retention interval.
        #[serde(default)]
        before_expiry: bool,
    },
    ReleasePrunePlan {
        // Existing recorded release whose deletion blockers should be reported.
        release: ReleasePath,
        // Exact trash records exempted from the ordinary retention interval.
        #[serde(default)]
        allow_unexpired_trash: Vec<String>,
    },
    ReleasePrune {
        // Existing recorded release selected for irreversible removal.
        release: ReleasePath,
        // Must repeat the complete release path before deletion.
        confirm: ReleasePath,
        // Exact trash records exempted from the ordinary retention interval.
        #[serde(default)]
        allow_unexpired_trash: Vec<String>,
    },
    ReleaseRetain {
        // Existing recorded release whose manual retention marker changes.
        release: ReleasePath,
        // Wire values are strings, matching the public machine client protocol.
        retain: Retain,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Retain {
    True,
    False,
}

fn record_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 255
            && !matches!(name, "." | "..")
            && !name.starts_with('-')
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "invalid trash identity"
    );
    Ok(())
}

impl Receiver {
    fn recorded_release(&self, release: &ReleasePath) -> Result<()> {
        let path = release.as_path();
        ensure!(
            release.as_str().parse::<StorePath>().is_ok()
                || path.parent() == Some(self.state.join("candidates").as_path())
                || path == self.state.join("baseline"),
            "release must be an exact recorded release path"
        );
        ensure!(
            fs::canonicalize(path)?.as_os_str() == path.as_os_str(),
            "release path must not be an alias"
        );
        Ok(())
    }

    pub(super) fn control(&self, input: &mut impl BufRead) -> Result<Value> {
        let mut raw: Value = message(input, 65536)?;
        let object = raw.as_object_mut().context("invalid control request")?;
        ensure!(
            object.remove("schema") == Some(json!(SCHEMA)),
            "unsupported machine control schema"
        );
        let request: Control = serde_json::from_value(raw)?;
        let mut args = Vec::<String>::new();
        let (action, synchronous) = match request {
            Control::Status {} => ("status", true),
            Control::Verify {} => ("verify", true),
            Control::Resume {} => ("resume", false),
            Control::Rollback {} => ("rollback", false),
            Control::TrashList {} => ("trash-list", true),
            Control::ReleaseList {} => ("release-list", true),
            Control::TrashPurge {
                identity,
                confirm,
                before_expiry,
            } => {
                record_name(&identity)?;
                ensure!(
                    identity == confirm,
                    "confirmation must equal the exact target"
                );
                args.extend([identity, "--confirm".into(), confirm]);
                if before_expiry {
                    args.push("--before-expiry".into());
                }
                ("trash-purge", false)
            }
            Control::ReleasePrunePlan {
                release,
                allow_unexpired_trash,
            } => {
                self.recorded_release(&release)?;
                args.push(release.to_string());
                exceptions(&mut args, allow_unexpired_trash)?;
                ("release-prune-plan", true)
            }
            Control::ReleasePrune {
                release,
                confirm,
                allow_unexpired_trash,
            } => {
                self.recorded_release(&release)?;
                ensure!(
                    release == confirm,
                    "confirmation must equal the exact target"
                );
                args.extend([release.to_string(), "--confirm".into(), confirm.to_string()]);
                exceptions(&mut args, allow_unexpired_trash)?;
                ("release-prune", false)
            }
            Control::ReleaseRetain { release, retain } => {
                self.recorded_release(&release)?;
                args.extend([
                    release.to_string(),
                    "--retain".into(),
                    match retain {
                        Retain::True => "true",
                        Retain::False => "false",
                    }
                    .into(),
                ]);
                ("release-retain", true)
            }
        };
        args.insert(0, action.into());
        let args = args.iter().map(String::as_str).collect::<Vec<_>>();

        let selected = self.state.join("controller");
        let engine = match fs::symlink_metadata(&selected) {
            Ok(_) => selected,
            Err(error) if error.kind() == io::ErrorKind::NotFound => self.engine.clone(),
            Err(error) => return Err(error.into()),
        };
        if synchronous {
            self.engine(&engine, &args, None)
        } else {
            Ok(json!({"schema":SCHEMA,"unit":self.detach(&engine, &args)?,"action":action}))
        }
    }
}

fn exceptions(args: &mut Vec<String>, identities: Vec<String>) -> Result<()> {
    ensure!(identities.len() <= 100, "too many early purge identities");
    for identity in identities {
        record_name(&identity)?;
        args.extend(["--allow-unexpired-trash".into(), identity]);
    }
    Ok(())
}
