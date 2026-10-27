use crate::{
    Decision,
    effects::{self, PlannedEffects},
};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use similar::{ChangeTag, TextDiff};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_BLOB: usize = 1024 * 1024;

const MAX_PLAN: u64 = 16 * 1024 * 1024;

/// Source commit and display summary for one side of a review.
#[derive(Clone, Serialize)]
pub struct Revision {
    /// Git commit identity displayed for this side of the review.
    pub commit: String,
    /// First line of the commit message displayed beside its identity.
    pub subject: String,
}

/// One changed Git path with full source for expanding context and producing a faithful patch.
#[derive(Clone, Serialize)]
pub struct FileChange {
    /// Repository-relative file path displayed in the review tree.
    pub path: String,
    /// Git change kind, such as added, modified, deleted or renamed.
    pub status: String,
    /// Baseline Git file mode, absent when the path was added.
    pub old_mode: Option<String>,
    /// Candidate Git file mode, absent when the path was deleted.
    pub new_mode: Option<String>,
    /// Baseline blob identity, absent when no baseline file exists.
    pub old_oid: Option<String>,
    /// Candidate blob identity, absent when no candidate file exists.
    pub new_oid: Option<String>,
    /// Complete baseline source used for context expansion and copying.
    pub before: String,
    /// Complete candidate source used for context expansion and copying.
    pub after: String,
    /// Explanation when file contents cannot be rendered as a text diff.
    pub opaque: Option<String>,
    /// Number of added text lines reported for this file.
    pub additions: usize,
    /// Number of removed text lines reported for this file.
    pub deletions: usize,
}

/// Complete review material binding source changes and supplied deployment effects to a digest.
#[derive(Clone, Serialize)]
pub struct Review {
    /// Wire format identifier used to reject unsupported record versions.
    pub schema: &'static str,
    /// Input origin distinguishing synthetic demo data from repository review.
    pub mode: &'static str,
    /// Repository path used to load source, absent for standalone demo data.
    pub repository: Option<String>,
    /// Source commit currently deployed, displayed on the left.
    pub baseline: Revision,
    /// Proposed source commit displayed on the right.
    pub candidate: Revision,
    /// SHA-256 of flake.lock, binding the source to its dependency versions.
    pub lock_hash: Option<String>,
    /// Changed files with their complete source and Git metadata.
    pub files: Vec<FileChange>,
    /// Optional supplied deployment effects, retained in the copied review.
    pub deployment: Option<Value>,
    /// Digest binding the decision to the complete displayed review record.
    pub fingerprint: String,
}

#[derive(Clone)]
struct Entry {
    /// Git tree file mode used to detect metadata-only changes.
    mode: String,
    /// Git blob identity used to load the tree entry contents.
    oid: String,
}

fn git(repo: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("--no-pager")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .output()
        .context("running Git")?;
    ensure!(
        output.status.success(),
        "Git failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output.stdout)
}

fn revision(repo: &Path, reference: &str) -> Result<Revision> {
    let commit = String::from_utf8(git(
        repo,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{reference}^{{commit}}"),
        ],
    )?)?
    .trim()
    .to_owned();
    let subject = String::from_utf8(git(repo, &["show", "-s", "--format=%s", &commit])?)?
        .trim()
        .to_owned();
    Ok(Revision { commit, subject })
}

fn tree(repo: &Path, commit: &str) -> Result<BTreeMap<String, Entry>> {
    let raw = git(repo, &["ls-tree", "-r", "-z", "--full-tree", commit])?;
    let mut entries = BTreeMap::new();
    for record in raw.split(|byte| *byte == 0).filter(|item| !item.is_empty()) {
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .context("invalid Git tree record")?;
        let fields: Vec<_> = std::str::from_utf8(&record[..tab])?
            .split_whitespace()
            .collect();
        ensure!(fields.len() == 3, "invalid Git tree metadata");

        // Never turn tree paths into filesystem paths or follow candidate symlinks.
        let path = std::str::from_utf8(&record[tab + 1..])
            .context("non-UTF-8 Git paths cannot be reviewed")?;
        entries.insert(
            path.to_owned(),
            Entry {
                mode: fields[0].into(),
                oid: fields[2].into(),
            },
        );
    }

    Ok(entries)
}

fn content(repo: &Path, entry: Option<&Entry>) -> Result<(String, Option<String>)> {
    let Some(entry) = entry else {
        return Ok((String::new(), None));
    };
    if entry.mode == "160000" {
        return Ok((format!("Submodule commit: {}\n", entry.oid), None));
    }

    let size: usize = String::from_utf8(git(repo, &["cat-file", "-s", &entry.oid])?)?
        .trim()
        .parse()?;
    if size > MAX_BLOB {
        return Ok((
            String::new(),
            Some(format!(
                "File exceeds the 1 MiB display limit ({size} bytes)."
            )),
        ));
    }

    let bytes = git(repo, &["cat-file", "blob", &entry.oid])?;
    if bytes.contains(&0) {
        return Ok((
            String::new(),
            Some("Binary content cannot be displayed as text.".into()),
        ));
    }

    match String::from_utf8(bytes) {
        Ok(text) => Ok((text, None)),
        Err(_) => Ok((
            String::new(),
            Some("Non-UTF-8 content cannot be displayed as text.".into()),
        )),
    }
}

fn change(
    path: String,
    old: Option<&Entry>,
    new: Option<&Entry>,
    before: String,
    after: String,
    opaque: Option<String>,
) -> FileChange {
    let diff = TextDiff::configure()
        .timeout(std::time::Duration::from_millis(250))
        .diff_lines(&before, &after);
    let additions = diff
        .iter_all_changes()
        .filter(|line| line.tag() == ChangeTag::Insert)
        .count();
    let deletions = diff
        .iter_all_changes()
        .filter(|line| line.tag() == ChangeTag::Delete)
        .count();

    FileChange {
        path,
        status: match (old, new) {
            (None, _) => "Added",
            (_, None) => "Deleted",
            _ => "Modified",
        }
        .into(),
        old_mode: old.map(|entry| entry.mode.clone()),
        new_mode: new.map(|entry| entry.mode.clone()),
        old_oid: old.map(|entry| entry.oid.clone()),
        new_oid: new.map(|entry| entry.oid.clone()),
        before,
        after,
        opaque,
        additions,
        deletions,
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Longer fences preserve source/plan text containing Markdown code fences.
fn code_block(text: &str, language: &str) -> String {
    let longest = text
        .split(|character| character != '`')
        .map(str::len)
        .max()
        .unwrap_or(0);
    let fence = "`".repeat(3.max(longest + 1));
    let newline = if text.ends_with('\n') { "" } else { "\n" };
    format!("{fence}{language}\n{text}{newline}{fence}\n")
}

impl Review {
    /// Resolve committed baseline/candidate trees and load their changed files and optional plan.
    pub fn from_git(repo: &Path, base: &str, candidate: &str, plan: Option<&Path>) -> Result<Self> {
        let repo = repo.canonicalize().context("opening repository")?;
        let baseline = revision(&repo, base)?;
        let candidate = revision(&repo, candidate)?;

        let before_tree = tree(&repo, &baseline.commit)?;
        let after_tree = tree(&repo, &candidate.commit)?;

        let paths: BTreeSet<_> = before_tree.keys().chain(after_tree.keys()).collect();
        let mut files = Vec::new();
        for path in paths {
            let old = before_tree.get(path);
            let new = after_tree.get(path);
            if old.map(|entry| (&entry.oid, &entry.mode))
                == new.map(|entry| (&entry.oid, &entry.mode))
            {
                continue;
            }
            ensure!(
                files.len() < 4096,
                "candidate exceeds 4096 changed files; review cannot be truncated"
            );

            let (before, old_opaque) = content(&repo, old)?;
            let (after, new_opaque) = content(&repo, new)?;
            files.push(change(
                path.clone(),
                old,
                new,
                before,
                after,
                old_opaque.or(new_opaque),
            ));
        }

        let lock_hash = if let Some(entry) = after_tree.get("flake.lock") {
            ensure!(
                entry.mode == "100644" || entry.mode == "100755",
                "candidate flake.lock must be a regular file"
            );
            Some(digest(&git(&repo, &["cat-file", "blob", &entry.oid])?))
        } else {
            None
        };

        let deployment = if let Some(path) = plan {
            ensure!(fs::metadata(path)?.len() <= MAX_PLAN, "plan exceeds 16 MiB");
            let value: Value =
                serde_json::from_slice(&fs::read(path)?).context("reading plan JSON")?;
            ensure!(value.is_object(), "deployment plan must be a JSON object");
            let plan = value.get("plan").unwrap_or(&value);
            ensure!(plan.is_object(), "plan field must be a JSON object");
            for key in ["changed", "stop", "start"] {
                ensure!(
                    plan.get(key).and_then(Value::as_array).is_some(),
                    "plan must contain a {key} array"
                );
            }
            for key in [
                "changed", "stop", "start", "retire", "restore", "stage", "affected",
            ] {
                if let Some(names) = plan.get(key) {
                    ensure!(
                        names
                            .as_array()
                            .is_some_and(|names| names.iter().all(Value::is_string)),
                        "plan {key} must be an array of strings"
                    );
                }
            }

            for object in [&value, plan] {
                if let Some(revision) = object.get("revision") {
                    ensure!(
                        revision.as_str() == Some(candidate.commit.as_str()),
                        "plan revision differs from candidate commit"
                    );
                }
            }
            if let Some(hash) = value.get("lock_hash") {
                ensure!(
                    hash.as_str() == lock_hash.as_deref(),
                    "plan lock hash differs from candidate flake.lock"
                );
            }
            Some(value)
        } else {
            None
        };

        let mut review = Self {
            schema: "airlock.ctrl-local-review.v1",
            mode: "local",
            repository: Some(repo.to_string_lossy().into_owned()),
            baseline,
            candidate,
            lock_hash,
            files,
            deployment,
            fingerprint: String::new(),
        };
        review.fingerprint = review.calculate_fingerprint()?;
        Ok(review)
    }

    fn calculate_fingerprint(&self) -> Result<String> {
        // Bind all displayed source, blob identities, file modes and plan contents.
        let mut value = serde_json::to_value(self)?;
        value.as_object_mut().unwrap().remove("fingerprint");
        Ok(digest(&serde_json::to_vec(&value)?))
    }

    /// Return why the source review cannot be approved faithfully, if any file is opaque.
    pub fn approval_blocker(&self) -> Option<&str> {
        if self.files.is_empty() {
            return Some("The baseline and candidate have no source changes.");
        }
        if self.files.iter().any(|file| file.opaque.is_some()) {
            return Some("Some changed files cannot be displayed. Approval is disabled.");
        }
        if self.deployment.is_none() {
            return Some(
                "Source review only. Load a saved deployment plan to enable local approval.",
            );
        }
        None
    }

    /// Create a local decision record bound to the review fingerprint; grant no deployment authority.
    pub fn receipt(&self, decision: Decision) -> Result<Value> {
        if matches!(decision, Decision::Approve)
            && let Some(reason) = self.approval_blocker()
        {
            bail!("{reason}");
        }

        Ok(json!({
            "schema": "airlock.ctrl-local-decision.v1",
            "authority": "local-review-only",
            "decision": match decision { Decision::Approve => "approve", Decision::Reject => "reject" },
            "review_fingerprint": self.fingerprint,
            "baseline_revision": self.baseline.commit,
            "candidate_revision": self.candidate.commit,
            "lock_hash": self.lock_hash,
            "deployment": self.deployment,
            "recorded_at_unix": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        }))
    }

    /// Write a unique local decision receipt and return its path without overwriting an earlier decision.
    pub fn record_decision(
        &self,
        decision: Decision,
        directory: &Path,
    ) -> Result<std::path::PathBuf> {
        ensure!(self.mode != "demo", "demo decisions stay in memory");
        let receipt = self.receipt(decision)?;

        fs::create_dir_all(directory).context("creating local decision directory")?;
        let path = directory.join(format!("{}.json", self.fingerprint));

        // Publish a complete private receipt atomically; never replace a previous decision.
        let mut output = tempfile::NamedTempFile::new_in(directory)?;
        let mut data = serde_json::to_vec_pretty(&receipt)?;
        data.push(b'\n');
        output.write_all(&data)?;
        output.as_file().sync_all()?;

        output
            .persist_noclobber(&path)
            .context("creating decision receipt (an existing decision is never overwritten)")?;
        fs::File::open(directory)?.sync_all()?;

        Ok(path)
    }

    /// Borrow the supplied plan from either a plan envelope or bare deployment record.
    pub fn plan(&self) -> Option<&Value> {
        self.deployment
            .as_ref()
            .map(|value| value.get("plan").unwrap_or(value))
    }

    /// A self-contained clipboard report; the patch remains separately extractable.
    pub fn clipboard_report(&self) -> Result<String> {
        let patch = self.patch()?;
        let effects = self.plan().map(PlannedEffects::from_plan);
        let identities = json!({
            "schema": self.schema,
            "mode": self.mode,
            "repository": self.repository,
            "baseline": self.baseline,
            "candidate": self.candidate,
            "lock_hash": self.lock_hash,
            "fingerprint": self.fingerprint,
        });

        // Keep source text in the patch rather than cloning it into metadata.
        let files = self
            .files
            .iter()
            .map(|file| {
                json!({
                    "path": file.path,
                    "status": file.status,
                    "old_mode": file.old_mode,
                    "new_mode": file.new_mode,
                    "old_oid": file.old_oid,
                    "new_oid": file.new_oid,
                    "opaque": file.opaque,
                    "additions": file.additions,
                    "deletions": file.deletions,
                })
            })
            .collect::<Vec<_>>();

        let mut report = format!(
            "# Airlock review\n\n{}\n\n## Review identities\n\n{}\n## Deployment effects\n\n{}\n\n## Changed files\n\n{}\n## Deployment plan\n\n",
            self.candidate.subject,
            code_block(&serde_json::to_string_pretty(&identities)?, "json"),
            effects::summary(effects.as_ref()),
            code_block(&serde_json::to_string_pretty(&files)?, "json"),
        );
        if let Some(deployment) = &self.deployment {
            report.push_str("Supplied plan; machine state has not been verified.\n\n");
            report.push_str(&code_block(
                &serde_json::to_string_pretty(deployment)?,
                "json",
            ));
        } else {
            report.push_str("No deployment plan supplied.\n");
        }

        report.push_str("\n## Source patch\n\n");
        if patch.is_empty() {
            report.push_str("No source changes between these commits.\n");
        } else {
            report.push_str(&code_block(&patch, "diff"));
        }

        Ok(report)
    }

    /// A complete, applicable patch for the immutable commits being reviewed.
    /// Never includes the worktree, executes diff helpers or applies the patch.
    pub fn patch(&self) -> Result<String> {
        if self.mode == "demo" {
            let mut patch = String::new();
            for file in &self.files {
                let before = format!("a/{}", file.path);
                let after = format!("b/{}", file.path);
                patch.push_str(&format!("diff --git {before} {after}\n"));
                patch.push_str(
                    &TextDiff::from_lines(&file.before, &file.after)
                        .unified_diff()
                        .context_radius(3)
                        .header(&before, &after)
                        .to_string(),
                );
            }
            return Ok(patch);
        }

        let repo = Path::new(
            self.repository
                .as_deref()
                .context("review has no repository")?,
        );
        let bytes = git(
            repo,
            &[
                "-c",
                "core.quotePath=true",
                "diff",
                "--binary",
                "--full-index",
                "--no-ext-diff",
                "--no-textconv",
                "--no-color",
                "--no-renames",
                "--no-relative",
                "--src-prefix=a/",
                "--dst-prefix=b/",
                "--submodule=short",
                "--ignore-submodules=none",
                "--unified=3",
                &self.baseline.commit,
                &self.candidate.commit,
                "--",
            ],
        )?;

        String::from_utf8(bytes).context(
            "Git patch contains non-UTF-8 text and cannot be copied without changing its bytes",
        )
    }

    /// Return synthetic review data covering multiple files, separated hunks and deployment effects.
    pub fn demo() -> Self {
        let examples = [
            (
                "src/personal.rs",
                include_str!("../examples/diff-context/usr-home.before.rs"),
                include_str!("../examples/diff-context/usr-home.after.rs"),
            ),
            (
                "src/media.rs",
                "",
                r#"//! Declare an isolated media VM.

use airlock_config::model::{AuthoringError, GiB, Isolated, Vm, VmHandle};

/// Keep media playback separate from the networked personal workspace.
pub fn media() -> Result<VmHandle<Isolated>, AuthoringError> {
    Vm::isolated("usr-media", GiB(8))
}
"#,
            ),
            (
                "src/browser.rs",
                r#"//! Select the personal VM's browser package.

/// Return the target package attribute for browser installation.
pub fn browser_package() -> &'static str {
    "firefox"
}
"#,
                "",
            ),
            (
                "src/controller.rs",
                r#"//! Select controller memory for the machine declaration.

use airlock_config::model::{Memory, MiB};

/// Reserve fixed memory for controller builds.
pub fn memory() -> Memory {
    Memory::Fixed(MiB(8192))
}
"#,
                r#"//! Select controller memory for the machine declaration.

use airlock_config::model::{Memory, MiB};

/// Reserve fixed memory for controller builds.
pub fn memory() -> Memory {
    Memory::Fixed(MiB(12288))
}
"#,
            ),
            (
                "src/policy.rs",
                r#"//! Declare explicit Qubes permissions for controller operations.

/// Return the policy lines installed by the host component.
pub fn rules() -> &'static [&'static str] {
    &["airlock.Ctrl.MachineControl + sys-ctrl dom0 allow"]
}
"#,
                r#"//! Declare explicit Qubes permissions for controller operations.

/// Return the policy lines installed by the host component.
pub fn rules() -> &'static [&'static str] {
    &[
        "airlock.Ctrl.MachineControl + sys-ctrl dom0 allow",
        "qubes.OpenURL * usr-home @dispvm ask",
    ]
}
"#,
            ),
        ];
        let mut files: Vec<_> = examples
            .into_iter()
            .map(|(path, before, after)| {
                let old = Entry {
                    mode: "100644".into(),
                    oid: digest(before.as_bytes()),
                };
                let new = Entry {
                    mode: "100644".into(),
                    oid: digest(after.as_bytes()),
                };
                change(
                    path.into(),
                    (!before.is_empty()).then_some(&old),
                    (!after.is_empty()).then_some(&new),
                    before.into(),
                    after.into(),
                    None,
                )
            })
            .collect();
        files.sort_by(|left, right| left.path.cmp(&right.path));

        let mut review = Self {
            schema: "airlock.ctrl-local-review.v1",
            mode: "demo",
            repository: None,
            baseline: Revision {
                commit: "example-baseline".into(),
                subject: "Current configuration · example".into(),
            },
            candidate: Revision {
                commit: "example-candidate".into(),
                subject: "Update desktop applications, preferences and controller GUI · example"
                    .into(),
            },
            lock_hash: None,
            files,
            deployment: Some(
                json!({"plan": {"changed": ["sys-ctrl", "usr-home", "usr-media"], "stop": ["usr-home", "sys-ctrl"], "start": ["sys-ctrl", "usr-home", "usr-media"], "retire": [], "restore": [], "host_reboot_required": false}, "phase": "prepared", "example": true}),
            ),
            fingerprint: String::new(),
        };
        review.fingerprint = review.calculate_fingerprint().unwrap();
        review
    }
}
