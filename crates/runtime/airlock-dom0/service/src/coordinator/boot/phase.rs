//! Admit execution phases from a checked plan and fresh GUI runtime observations.
//! Readiness evidence is process-local and rechecked around each deferred start.
//! Observations cannot reserve a live VM: Qubes still enforces authority during startup,
//! and a changed instance aborts the remaining phase instead of reusing old readiness.

use crate::process::Runner;
use airlock_deployment_core::boot::startup::Phase;
use airlock_machine_core::boot::startup::ForegroundPlan;
use airlock_nix_core::{
    identity::{GuestName, LockHash},
    store_path::StorePath,
};
use anyhow::{Context, Result, ensure};
use std::{ffi::OsString, time::Duration};

/// Evidence for one selected GUI generation on one live Xen instance.
struct GuiReady {
    // Full boot selection; another topology or staged selection cannot reuse this witness.
    selection: LockHash,
    // Expected immutable GUI generation observed through qrexec.
    system: StorePath,
    // Xen instance observed before and after the generation probe.
    instance: u32,
}

/// Only checked constructors choose the early phase or supply a fresh GUI witness.
enum Admission {
    /// Headless phase needs no running display provider.
    Early,
    /// Deferred phase retains an unforgeable observation of the selected GUI.
    Deferred(
        // Exact boot selection, generation and Xen instance admitted for this phase.
        GuiReady,
    ),
}

/// Execution access to exactly one checked phase; arbitrary guest lists cannot construct it.
pub(super) struct ReadyPhase<'plan, 'inputs> {
    // Complete plan whose canonical guests and dependency partition were verified.
    plan: &'plan ForegroundPlan<'inputs>,
    // Runtime evidence required for this execution phase.
    admission: Admission,
}

/// Query fixed Qubes tools with a bounded readiness budget; no topology text becomes a command.
fn query(runner: &Runner, program: &str, arguments: &[&str]) -> Result<String> {
    runner.run(
        program,
        &arguments.iter().map(OsString::from).collect::<Vec<_>>(),
        Duration::from_secs(airlock_machine_core::boot::GUI_PROBE_SECONDS),
        &[],
    )
}

/// Require the expected generation on the same running Xen instance throughout the observation.
fn observe(runner: &Runner, expected: &StorePath) -> Result<u32> {
    query(runner, "qvm-check", &["--running", "sys-gui"])?;
    let instance = || -> Result<u32> {
        let raw = query(
            runner,
            "qvm-ls",
            &["--raw-data", "--fields", "XID", "sys-gui"],
        )?;
        let xid = raw.parse::<u32>().context("invalid GUI Xen identity")?;
        ensure!(xid > 0, "invalid GUI Xen identity");
        Ok(xid)
    };
    let before = instance()?;
    let actual = query(
        runner,
        "qrexec-client",
        &["-d", "sys-gui", "user:readlink -f /run/current-system"],
    )?;
    ensure!(
        actual == expected.as_str(),
        "GUI running generation differs from selected startup plan"
    );
    ensure!(
        instance()? == before,
        "GUI restarted during startup readiness"
    );
    query(runner, "qvm-check", &["--running", "sys-gui"])?;
    Ok(before)
}

impl<'plan, 'inputs> ReadyPhase<'plan, 'inputs> {
    /// Admit only the plan's checked headless phase before GPU handoff.
    pub(super) fn early(plan: &'plan ForegroundPlan<'inputs>) -> Self {
        Self {
            plan,
            admission: Admission::Early,
        }
    }

    /// Admit the deferred phase only after checking the selected GUI generation and Xen instance.
    pub(super) fn deferred(
        plan: &'plan ForegroundPlan<'inputs>,
        runner: &Runner,
        selection: &LockHash,
    ) -> Result<Self> {
        let system = plan.inputs().topology().domains[&"sys-gui".parse()?]
            .backend
            .system
            .source
            .clone();
        let instance = observe(runner, &system)?;
        Ok(Self {
            plan,
            admission: Admission::Deferred(GuiReady {
                selection: selection.clone(),
                system,
                instance,
            }),
        })
    }

    /// Select the fixed phase associated with this admission, never a caller-provided phase tag.
    fn stage(&self) -> Phase {
        match self.admission {
            Admission::Early => Phase::BeforeGui,
            Admission::Deferred(_) => Phase::AfterGui,
        }
    }

    /// Borrow the plan's complete original inputs so execution can require its selected topology.
    pub(super) fn plan(&self) -> &ForegroundPlan<'inputs> {
        self.plan
    }

    /// Enumerate exactly this admitted phase in dependency order.
    pub(super) fn guests(&self) -> Vec<GuestName> {
        self.plan.phase(self.stage())
    }

    /// Require every hard provider of an optional overlapping guest to precede home in this phase.
    pub(super) fn can_overlap(&self, guest: &GuestName, home: &GuestName) -> Result<bool> {
        self.plan.can_overlap(self.stage(), guest, home)
    }

    /// Revalidate process-local evidence around every deferred start; a restarted GUI needs a new observation.
    pub(super) fn recheck(&self, runner: &Runner, selection: &LockHash) -> Result<()> {
        if let Admission::Deferred(ready) = &self.admission {
            ensure!(
                ready.selection == *selection,
                "GUI readiness belongs to another startup selection"
            );
            ensure!(
                observe(runner, &ready.system)? == ready.instance,
                "GUI restarted during foreground startup"
            );
        }
        Ok(())
    }
}
