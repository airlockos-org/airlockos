//! Controller review tests use committed Git objects and verify authority boundaries through the actual application CLI.

use crate::common;
use airlock_tests::{
    process::{binary, run},
    repository::git,
};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::Command,
};

/// A real source repository with a saved deployment plan and two committed revisions.
struct Review {
    // Owns source, plan inputs and local decision receipts.
    temporary: tempfile::TempDir,
    // Verified GUI artifact; tests refuse stale source or substituted executable bytes.
    binary: PathBuf,
    // Clean source history is separate from mutable plan and receipt fixtures.
    repo: PathBuf,
    // Original committed content shown on the left side of the review.
    base: String,
    // Committed candidate shown even if the working tree or replace refs change.
    candidate: String,
    // Saved deployment response supplied independently from source review.
    plan: PathBuf,
}

/// Resolve the explicitly prepared controller only after the workstation tool verifies its receipt.
fn controller() -> Result<PathBuf> {
    let mut command = Command::new(binary("AIRLOCK_DEV_BIN", "airlock-dev"));
    command
        .arg("--repository-root")
        .arg(common::root())
        .args(["ctrl-artifact", "verify"]);
    if let Some(path) = std::env::var_os("AIRLOCK_CTRL_BIN") {
        command.arg("--binary").arg(path);
    }
    let report: Value = serde_json::from_slice(&run(&mut command, None)?.checked()?)?;
    Ok(PathBuf::from(
        report["binary"].as_str().context("verified controller")?,
    ))
}

/// Commit fixture changes using fixed local author identity.
fn commit(repo: &Path, subject: &str) -> Result<String> {
    git(repo, &["add", "--all"])?;
    git(repo, &["commit", "-qm", subject])?;
    git(repo, &["rev-parse", "HEAD"])
}

impl Review {
    /// Include additions, deletions and unusual names in normal Rust source review.
    fn new() -> Result<Self> {
        let temporary = tempfile::tempdir()?;
        let repo = temporary.path().join("source");
        fs::create_dir(&repo)?;
        git(&repo, &["init", "-q", "-b", "main"])?;
        git(&repo, &["config", "user.name", "Fixture"])?;
        git(&repo, &["config", "user.email", "fixture@example.invalid"])?;
        git(&repo, &["config", "commit.gpgsign", "false"])?;
        for (name, contents) in [
            ("domain.rs", "packages: firefox\n"),
            ("flake.lock", "{\"nodes\": {}}\n"),
            ("remove.rs", "old declaration\n"),
            ("helper.rs", "before\n"),
            ("odd\tname\n.rs", "before\n"),
        ] {
            fs::write(repo.join(name), contents)?;
        }
        let base = commit(&repo, "Baseline")?;
        fs::write(repo.join("domain.rs"), "packages: firefox keepassxc\n")?;
        fs::remove_file(repo.join("remove.rs"))?;
        fs::write(repo.join("added.rs"), "new declaration\n")?;
        for name in ["helper.rs", "odd\tname\n.rs"] {
            fs::write(repo.join(name), "after\n")?;
        }
        let candidate = commit(&repo, "Candidate")?;
        let plan = temporary.path().join("plan.json");
        fs::write(
            &plan,
            serde_json::to_vec(
                &json!({"revision": candidate, "prepared": "a".repeat(64), "plan": {
                    "revision": candidate, "changed": ["usr-home"], "stop": ["usr-home"], "start": ["usr-home"],
                    "retire": [], "restore": [], "host_reboot_required": false
                }}),
            )?,
        )?;
        Ok(Self {
            temporary,
            binary: controller()?,
            repo,
            base,
            candidate,
            plan,
        })
    }

    /// Invoke source review with exact commit identities and optional saved-plan or decision arguments.
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(&self.binary);
        command
            .arg("--repo")
            .arg(&self.repo)
            .args(["--base", &self.base, "--candidate", &self.candidate])
            .args(args);
        command
    }

    /// Inspect the complete serialized review rather than inferring authority from rendered text.
    fn inspect(&self, plan: bool) -> Result<Value> {
        let mut command = self.command(&["--inspect"]);
        if plan {
            command.arg("--plan").arg(&self.plan);
        }
        Ok(serde_json::from_slice(
            &run(&mut command, None)?.checked()?,
        )?)
    }

    /// Preserve full printable output for patch reconstruction and report-fence assertions.
    fn text(&self, operation: &str, plan: bool) -> Result<String> {
        let mut command = self.command(&[operation]);
        if plan {
            command.arg("--plan").arg(&self.plan);
        }
        Ok(String::from_utf8(run(&mut command, None)?.checked()?)?)
    }

    /// Construct a typed controller approval request without granting authority to local review receipts.
    fn request(&self) -> Result<Value> {
        Ok(
            json!({"schema": "airlock.ctrl-approval-request.v1", "request_id": "a".repeat(64),
            "baseline": self.base, "revision": self.candidate, "lock_hash": self.inspect(false)?["lock_hash"],
            "family": "machine", "target": null, "scope": {"allowed_vms": ["usr-home", "sys-ctrl"], "allow_reboot": false}}),
        )
    }
}

/// Decode a fenced report section even when source or plan strings contain shorter Markdown fences.
fn block<'a>(report: &'a str, heading: &str) -> Result<&'a str> {
    let section = report
        .split_once(&format!("## {heading}\n\n"))
        .context("report heading")?
        .1;
    let start = section.find("```").context("report fence")?;
    let fence_line = section[start..].split_once('\n').context("fence line")?;
    let fence = fence_line
        .0
        .trim_end_matches("json")
        .trim_end_matches("diff");
    Ok(fence_line
        .1
        .split_once(&format!("\n{fence}\n"))
        .context("closing fence")?
        .0)
}

/// Explicit local examples show independent Rust changes, added/deleted files and no deployment authority.
#[test]
fn demo_review_is_complete_and_cannot_record_decisions() -> Result<()> {
    let binary = controller()?;
    let review: Value = serde_json::from_slice(
        &run(Command::new(&binary).args(["--demo", "--inspect"]), None)?.checked()?,
    )?;
    assert_eq!(review["mode"], "demo");
    assert!(review["repository"].is_null());
    assert_eq!(review["deployment"]["example"], true);
    let files = review["files"].as_array().unwrap();
    let desktop = files
        .iter()
        .find(|file| file["path"] == "src/personal.rs")
        .context("demo personal component")?;
    assert!(!desktop["before"].as_str().unwrap().contains("\"vlc\""));
    assert!(
        desktop["after"]
            .as_str()
            .unwrap()
            .contains("\"video/mp4\": desktop(\"vlc.desktop\")")
    );
    for status in ["Added", "Deleted", "Modified"] {
        assert!(files.iter().any(|file| file["status"] == status));
    }
    let temporary = tempfile::tempdir()?;
    let decisions = temporary.path().join("decisions");
    let result = run(
        Command::new(binary)
            .args(["--demo", "--record-decision", "approve", "--decisions-dir"])
            .arg(&decisions),
        None,
    )?;
    assert!(!result.status.success() && !decisions.exists());
    Ok(())
}

/// Review reads committed blobs, ignores working-tree edits and replacement refs, and lists every source path safely.
#[test]
fn review_uses_committed_objects_and_preserves_working_files() -> Result<()> {
    let review = Review::new()?;
    fs::write(
        review.repo.join("domain.rs"),
        "uncommitted and must not appear\n",
    )?;
    fs::write(review.repo.join("untracked.rs"), "untracked\n")?;
    git(&review.repo, &["replace", &review.candidate, &review.base])?;
    let value = review.inspect(true)?;
    assert_eq!(value["baseline"]["commit"], review.base);
    assert_eq!(value["candidate"]["commit"], review.candidate);
    assert_eq!(value["candidate"]["subject"], "Candidate");
    let files = value["files"].as_array().unwrap();
    assert_eq!(files.len(), 5);
    for (name, status) in [
        ("added.rs", "Added"),
        ("remove.rs", "Deleted"),
        ("odd\tname\n.rs", "Modified"),
    ] {
        assert_eq!(
            files.iter().find(|file| file["path"] == name).unwrap()["status"],
            status
        );
    }
    assert!(
        files
            .iter()
            .find(|file| file["path"] == "domain.rs")
            .unwrap()["after"]
            .as_str()
            .unwrap()
            .contains("keepassxc")
    );
    assert_eq!(
        fs::read_to_string(review.repo.join("domain.rs"))?,
        "uncommitted and must not appear\n"
    );
    Ok(())
}

/// A complete patch reconstructs the committed tree including binary bytes, links, executable bits, renamed paths and missing newlines.
#[test]
fn complete_patch_reconstructs_candidate_and_ignores_git_helpers() -> Result<()> {
    let mut review = Review::new()?;
    git(&review.repo, &["checkout", &review.base])?;
    fs::write(review.repo.join("binary.dat"), b"\0before\xff\n")?;
    symlink("old-target", review.repo.join("link"))?;
    review.base = commit(&review.repo, "Patch baseline")?;
    git(&review.repo, &["checkout", &review.candidate, "--", "."])?;
    fs::remove_file(review.repo.join("remove.rs"))?;
    fs::write(review.repo.join("binary.dat"), b"\0after\xfe\n")?;
    fs::remove_file(review.repo.join("link"))?;
    symlink("new-target", review.repo.join("link"))?;
    fs::set_permissions(
        review.repo.join("helper.rs"),
        fs::Permissions::from_mode(0o755),
    )?;
    fs::write(
        review.repo.join("added.rs"),
        "new declaration without a final newline",
    )?;
    git(&review.repo, &["mv", "domain.rs", "renamed domain.rs"])?;
    review.candidate = commit(&review.repo, "Complete patch candidate")?;
    fs::write(review.repo.join("renamed domain.rs"), "uncommitted text")?;
    for (key, value) in [
        ("diff.external", "false"),
        ("diff.custom.command", "false"),
        ("diff.custom.textconv", "false"),
        ("diff.noprefix", "true"),
        ("diff.relative", "true"),
        ("color.ui", "always"),
    ] {
        git(&review.repo, &["config", key, value])?;
    }
    fs::write(review.repo.join(".gitattributes"), "*.rs diff=custom\n")?;
    git(&review.repo, &["replace", &review.candidate, &review.base])?;
    let patch = review.text("--print-patch", false)?;
    assert!(patch.contains("GIT binary patch"));
    assert!(patch.contains("old mode 100644\nnew mode 100755"));
    assert!(patch.contains("\\ No newline at end of file"));
    assert!(!patch.contains("uncommitted text") && !patch.contains('\x1b'));
    let target = review.temporary.path().join("apply");
    git(
        review.temporary.path(),
        &[
            "clone",
            "--no-hardlinks",
            review.repo.to_str().unwrap(),
            target.to_str().unwrap(),
        ],
    )?;
    git(&target, &["checkout", &review.base])?;
    run(
        Command::new("git")
            .arg("-C")
            .arg(&target)
            .args(["apply", "--index", "--binary", "-"]),
        Some(patch.as_bytes().to_vec()),
    )?
    .checked()?;
    assert_eq!(
        git(&target, &["write-tree"])?,
        git(
            &review.repo,
            &[
                "--no-replace-objects",
                "rev-parse",
                &format!("{candidate}^{{tree}}", candidate = review.candidate)
            ]
        )?
    );
    assert_eq!(
        format!(
            "{body}\n",
            body = block(&review.text("--print-review", false)?, "Source patch")?
        ),
        patch
    );
    Ok(())
}

/// Printed review retains complete identities, file metadata, plans and patches even when their strings contain Markdown fences.
#[test]
fn copied_review_preserves_identity_plan_and_effects() -> Result<()> {
    let mut review = Review::new()?;
    fs::write(
        review.repo.join("fences.txt"),
        "```json\n{\"example\":true}\n```\n`````\n",
    )?;
    review.candidate = commit(&review.repo, "Add fenced examples")?;
    for (reboot, expected) in [
        (Some(true), "Required"),
        (Some(false), "Not required"),
        (None, "Unknown"),
    ] {
        let mut plan = json!({"plan": {"revision": review.candidate, "changed": [], "stop": ["usr-home", "sys-ctrl", "retiring", "usr-home"], "start": ["usr-home", "sys-ctrl", "new", "new"]}, "note": "``````\n## Source patch\n``````"});
        if let Some(reboot) = reboot {
            plan["plan"]["host_reboot_required"] = json!(reboot);
        }
        fs::write(&review.plan, serde_json::to_vec(&plan)?)?;
        let value = review.inspect(true)?;
        let text = review.text("--print-review", true)?;
        assert_eq!(
            serde_json::from_str::<Value>(block(&text, "Deployment plan")?)?,
            plan
        );
        let mut identities = value.clone();
        identities.as_object_mut().unwrap().remove("files");
        identities.as_object_mut().unwrap().remove("deployment");
        assert_eq!(
            serde_json::from_str::<Value>(block(&text, "Review identities")?)?,
            identities
        );
        let metadata: Vec<_> = value["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|file| {
                let mut file = file.clone();
                file.as_object_mut().unwrap().remove("before");
                file.as_object_mut().unwrap().remove("after");
                file
            })
            .collect();
        assert_eq!(
            serde_json::from_str::<Value>(block(&text, "Changed files")?)?,
            json!(metadata)
        );
        assert!(text.contains(&format!("VMs restarting: sys-ctrl, usr-home\nVMs starting: new\nVMs stopping: retiring\nSystem reboot: {expected}")));
        assert_eq!(
            format!("{body}\n", body = block(&text, "Source patch")?),
            review.text("--print-patch", true)?
        );
    }
    Ok(())
}

/// Typed prebuild approval must bind source and scope, and headless local decisions cannot authorize controller builds.
#[test]
fn prebuild_approval_binds_source_and_keeps_local_receipts_non_authoritative() -> Result<()> {
    let review = Review::new()?;
    let request_path = review.temporary.path().join("approval.json");
    let request = review.request()?;
    fs::write(&request_path, serde_json::to_vec(&request)?)?;
    let text = String::from_utf8(
        run(
            review
                .command(&["--print-review", "--approval-request"])
                .arg(&request_path),
            None,
        )?
        .checked()?,
    )?;
    let scope: Value = serde_json::from_str(
        text.split_once("## Approval scope\n\n")
            .context("approval scope")?
            .1,
    )?;
    assert_eq!(scope["scope"]["allow_reboot"], true);
    assert_eq!(
        scope["scope"]["allowed_vms"],
        json!(["sys-ctrl", "usr-home"])
    );
    assert_eq!(scope["request_id"], request["request_id"]);
    assert!(
        scope["purpose"]
            .as_str()
            .unwrap()
            .contains("final deployment plan is not yet known")
    );
    for change in [
        json!({"schema": "other"}),
        json!({"request_id": "bad"}),
        json!({"baseline": "b".repeat(40)}),
        json!({"revision": "b".repeat(40)}),
        json!({"lock_hash": "b".repeat(64)}),
        json!({"target": "usr-home"}),
        json!({"scope": {"allowed_vms": ["../usr-home"], "allow_reboot": false}}),
        json!({"family": "guest", "target": "dom0"}),
        json!({"approve": true}),
    ] {
        let mut value = request.clone();
        value
            .as_object_mut()
            .unwrap()
            .extend(change.as_object().unwrap().clone());
        fs::write(&request_path, serde_json::to_vec(&value)?)?;
        let output = run(
            review
                .command(&["--print-review", "--approval-request"])
                .arg(&request_path),
            None,
        )?;
        assert!(
            !output.status.success() && output.stdout.is_empty(),
            "{change}"
        );
    }
    fs::write(&request_path, serde_json::to_vec(&request)?)?;
    let decisions = review.temporary.path().join("decisions");
    let result = run(
        review
            .command(&["--record-decision", "approve", "--approval-request"])
            .arg(&request_path)
            .arg("--decisions-dir")
            .arg(&decisions),
        None,
    )?;
    assert!(!result.status.success() && !decisions.exists());
    Ok(())
}

/// Plans and local decisions bind the exact review fingerprint; receipts are private, exclusive and limited to local review.
#[test]
fn plans_and_local_receipts_are_bound_and_exclusive() -> Result<()> {
    let review = Review::new()?;
    let original: Value = serde_json::from_slice(&fs::read(&review.plan)?)?;
    let fingerprint = review.inspect(true)?["fingerprint"].clone();
    let mut changed = original.clone();
    changed["plan"]["host_reboot_required"] = json!(true);
    fs::write(&review.plan, serde_json::to_vec(&changed)?)?;
    assert_ne!(review.inspect(true)?["fingerprint"], fingerprint);
    for damage in ["revision", "lock", "shape", "names"] {
        let mut value = original.clone();
        match damage {
            "revision" => value["plan"]["revision"] = json!(review.base),
            "lock" => value["lock_hash"] = json!("0".repeat(64)),
            "shape" => value["plan"] = json!([]),
            _ => value["plan"]["stop"] = json!([123]),
        }
        fs::write(&review.plan, serde_json::to_vec(&value)?)?;
        assert!(
            !run(
                review.command(&["--inspect", "--plan"]).arg(&review.plan),
                None
            )?
            .status
            .success()
        );
    }
    fs::write(&review.plan, serde_json::to_vec(&original)?)?;
    let decisions = review.temporary.path().join("decisions");
    let decide = |decision: &str, plan: bool| -> Result<airlock_vm_service::support::Output> {
        let mut command = review.command(&["--record-decision", decision, "--decisions-dir"]);
        command.arg(&decisions);
        if plan {
            command.arg("--plan").arg(&review.plan);
        }
        run(&mut command, None)
    };
    assert!(!decide("approve", false)?.status.success());
    let path = PathBuf::from(String::from_utf8(decide("approve", true)?.checked()?)?.trim());
    let bytes = fs::read(&path)?;
    let receipt: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(receipt["authority"], "local-review-only");
    assert_eq!(receipt["schema"], "airlock.ctrl-local-decision.v1");
    assert_eq!(receipt["candidate_revision"], review.candidate);
    assert_eq!(receipt["review_fingerprint"], fingerprint);
    assert_eq!(path.metadata()?.permissions().mode() & 0o777, 0o600);
    assert!(!decide("reject", true)?.status.success());
    assert_eq!(fs::read(path)?, bytes);
    assert_eq!(fs::read_dir(decisions)?.count(), 1);
    Ok(())
}

/// Opaque content blocks approval; source links and mode-only changes are reviewed without following external files.
#[test]
fn opaque_and_linked_source_cannot_expand_review_authority() -> Result<()> {
    for bytes in [
        b"binary\0content".to_vec(),
        b"bad\xffutf8".to_vec(),
        vec![b'x'; 1024 * 1024 + 1],
    ] {
        let mut review = Review::new()?;
        fs::write(review.repo.join("opaque.rs"), bytes)?;
        review.candidate = commit(&review.repo, "Opaque change")?;
        let mut plan: Value = serde_json::from_slice(&fs::read(&review.plan)?)?;
        plan["revision"] = json!(review.candidate);
        plan["plan"]["revision"] = json!(review.candidate);
        fs::write(&review.plan, serde_json::to_vec(&plan)?)?;
        let value = review.inspect(true)?;
        let opaque = value["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|file| file["path"] == "opaque.rs")
            .unwrap();
        assert!(opaque["opaque"].is_string());
        assert!(opaque["new_oid"].is_string());
        let output = run(
            review
                .command(&["--record-decision", "approve", "--plan"])
                .arg(&review.plan)
                .arg("--decisions-dir")
                .arg(review.temporary.path().join("decisions")),
            None,
        )?;
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be displayed"));
    }
    let mut review = Review::new()?;
    let secret = review.temporary.path().join("outside");
    fs::write(&secret, "must never be read\n")?;
    symlink(&secret, review.repo.join("link.rs"))?;
    fs::set_permissions(
        review.repo.join("flake.lock"),
        fs::Permissions::from_mode(0o755),
    )?;
    review.candidate = commit(&review.repo, "Symlink and mode")?;
    let value = review.inspect(false)?;
    let files = value["files"].as_array().unwrap();
    let link = files.iter().find(|file| file["path"] == "link.rs").unwrap();
    assert_eq!(link["new_mode"], "120000");
    assert_eq!(link["after"], secret.to_str().unwrap());
    let mode = files
        .iter()
        .find(|file| file["path"] == "flake.lock")
        .unwrap();
    assert_eq!(mode["old_mode"], "100644");
    assert_eq!(mode["new_mode"], "100755");
    assert_eq!(mode["additions"], 0);
    Ok(())
}

/// Empty source reviews remain copyable, source-only rejection stays local and lossy clipboard text never masquerades as a valid patch.
#[test]
fn empty_and_lossy_reviews_preserve_copy_and_decision_boundaries() -> Result<()> {
    let mut review = Review::new()?;
    review.candidate = review.base.clone();
    assert_eq!(review.text("--print-patch", false)?, "");
    let text = review.text("--print-review", false)?;
    assert!(text.contains("Unknown (no plan)"));
    assert!(text.contains("No deployment plan supplied."));
    assert!(text.contains("No source changes between these commits."));
    let directory = review.temporary.path().join("source-decisions");
    run(
        review
            .command(&["--record-decision", "reject", "--decisions-dir"])
            .arg(directory),
        None,
    )?
    .checked()?;

    fs::write(review.repo.join("latin1.txt"), b"before \xff\n")?;
    review.base = commit(&review.repo, "Non-UTF-8 baseline")?;
    fs::write(review.repo.join("latin1.txt"), b"after \xff\n")?;
    review.candidate = commit(&review.repo, "Non-UTF-8 candidate")?;
    for operation in ["--print-patch", "--print-review"] {
        let output = run(&mut review.command(&[operation]), None)?;
        assert!(!output.status.success() && output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("non-UTF-8"));
    }
    Ok(())
}

/// Agent status includes live diagnostic counters while preserving the recorded job decision.
#[test]
fn review_status_exposes_progress_without_rewriting_the_job() -> Result<()> {
    use airlock_nix_core::{runtime::progress, state::StateStore};
    let temporary = tempfile::tempdir()?;
    let root = temporary
        .path()
        .join(".local/share/airlock/controller/rust-v1");
    fs::create_dir_all(&root)?;
    StateStore::initialize(&root)?;
    let id = "c".repeat(32);
    let directory = root.join("progress").join(&id);
    {
        let _recording = progress::record_to(&directory)?;
        let mut span = progress::Span::start("transferring_guest");
        span.update(json!({"objects_reused":12,"bytes_completed":1024,"bytes_total":2048}));
        span.complete();
    }
    let job = json!({"request_id":id,"status":"failed","error":"original failure"});
    let path = root.join("records").join(format!("job-{id}.json"));
    let bytes = serde_json::to_vec(&job)?;
    fs::create_dir_all(path.parent().unwrap())?;
    fs::write(&path, &bytes)?;
    let output = crate::common::json(
        Command::new(crate::common::binary(
            "AIRLOCK_SYS_CTRL_BIN",
            "airlock-sys-ctrl-service",
        ))
        .arg("review-status-serve")
        .env("HOME", temporary.path())
        .env("QREXEC_REMOTE_DOMAIN", "usr-assistant"),
        Some(format!("{request}\n", request = json!({"request_id":id})).into_bytes()),
    )?;
    assert_eq!(output["status"], "failed");
    assert_eq!(output["error"], "original failure");
    assert_eq!(
        output["progress"]["current"]["metrics"]["bytes_completed"],
        1024
    );
    assert_eq!(
        output["progress"]["current"]["metrics"]["objects_reused"],
        12
    );
    assert_eq!(fs::read(&path)?, bytes);
    Ok(())
}
