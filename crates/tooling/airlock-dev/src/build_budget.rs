//! Reserve a physical CPU core for the workstation while image builders and their children run.

use crate::support;
use anyhow::{Context, Result, ensure};
use rustix::thread::{CpuSet, sched_getaffinity, sched_setaffinity};
use serde::Serialize;
use std::{
    collections::BTreeSet, ffi::OsString, fs, os::unix::process::CommandExt, path::Path,
    process::Command,
};

/// CPU identities are kernel logical CPU numbers, rather than positions in a dense list.
type Cpus = BTreeSet<usize>;

/// Resource selection recorded before replacing this process with the requested build command.
#[derive(Serialize)]
struct Budget {
    /// CPUs permitted by the caller, including any inherited taskset or cgroup restriction.
    inherited_cpus: Cpus,
    /// CPUs available to this build after excluding a whole physical core.
    build_cpus: Cpus,
    /// Online SMT siblings of the physical core excluded from the build.
    reserved_core_cpus: Cpus,
    /// Number of independent Nix derivations allowed to build concurrently.
    nix_jobs: usize,
    /// Logical CPUs offered to each Nix derivation within the shared CPU budget.
    nix_cores: usize,
}

/// Parse Linux's bounded CPU-list notation, rejecting incomplete topology instead of using every CPU.
fn cpu_list(value: &str) -> Result<Cpus> {
    let mut cpus = Cpus::new();
    for part in value.trim().split(',') {
        let (start, end) = part.split_once('-').unwrap_or((part, part));
        let start: usize = start.parse().context("invalid CPU-list start")?;
        let end: usize = end.parse().context("invalid CPU-list end")?;
        ensure!(
            start <= end && end < CpuSet::MAX_CPU,
            "CPU list exceeds affinity support"
        );
        cpus.extend(start..=end);
    }
    ensure!(!cpus.is_empty(), "CPU list is empty");
    Ok(cpus)
}

/// Inspect all online siblings so a pre-existing excluded core can satisfy the reservation too.
fn topology(root: &Path) -> Result<Vec<Cpus>> {
    let online = cpu_list(&fs::read_to_string(root.join("online"))?)?;
    let mut cores = BTreeSet::new();
    for cpu in &online {
        let siblings = cpu_list(&fs::read_to_string(
            root.join(format!("cpu{cpu}/topology/thread_siblings_list")),
        )?)?;
        ensure!(siblings.contains(cpu), "CPU topology omits its own CPU");
        cores.insert(siblings.intersection(&online).copied().collect());
    }
    Ok(cores.into_iter().collect())
}

/// Prefer an already excluded core; otherwise reserve the last core without widening caller affinity.
fn select(inherited_cpus: Cpus, cores: &[Cpus]) -> Result<Budget> {
    let mut online = Cpus::new();
    for core in cores {
        ensure!(
            !core.is_empty() && online.is_disjoint(core),
            "CPU topology has overlapping cores"
        );
        online.extend(core);
    }
    ensure!(
        !inherited_cpus.is_empty() && inherited_cpus.is_subset(&online),
        "caller CPU affinity differs from online CPU topology"
    );

    let reserved_core_cpus = cores
        .iter()
        .rev()
        .find(|core| core.is_disjoint(&inherited_cpus))
        .or_else(|| cores.last())
        .context("no physical CPU cores are available")?
        .clone();
    let build_cpus: Cpus = inherited_cpus
        .difference(&reserved_core_cpus)
        .copied()
        .collect();
    ensure!(
        !build_cpus.is_empty(),
        "cannot reserve a physical core while leaving CPUs for the build"
    );
    // Most image fragments use one CPU. Allow several to run together without
    // multiplying large compilers beyond the CPUs left after core reservation.
    let build_cores = cores
        .iter()
        .filter(|core| !core.is_disjoint(&build_cpus))
        .count();
    let nix_jobs = build_cores.min(4);
    let nix_cores = (build_cpus.len() / nix_jobs).max(1);
    Ok(Budget {
        inherited_cpus,
        build_cpus,
        reserved_core_cpus,
        nix_jobs,
        nix_cores,
    })
}

/// Respect smaller Cargo job limits, including its negative CPU-offset spelling.
fn cargo_jobs(cpus: usize, requested: Option<&str>) -> Result<usize> {
    let Some(requested) = requested else {
        return Ok(cpus);
    };
    let requested: i64 = requested.parse().context("invalid CARGO_BUILD_JOBS")?;
    ensure!(requested != 0, "CARGO_BUILD_JOBS must be nonzero");

    if requested > 0 {
        Ok(cpus.min(usize::try_from(requested)?))
    } else {
        Ok(cpus
            .saturating_sub(usize::try_from(requested.unsigned_abs())?)
            .max(1))
    }
}

/// Apply inherited affinity before exec so compilers, linkers, compression and build VMs share the limit.
pub(crate) fn run(root: &Path, arguments: &[OsString]) -> Result<u8> {
    let (program, arguments) = arguments
        .split_first()
        .context("build command is missing")?;
    let inherited = sched_getaffinity(None).context("cannot inspect build CPU affinity")?;
    let cpus = (0..CpuSet::MAX_CPU)
        .filter(|cpu| inherited.is_set(*cpu))
        .collect();
    let budget = select(cpus, &topology(Path::new("/sys/devices/system/cpu"))?)?;
    let mut affinity = CpuSet::new();
    for cpu in &budget.build_cpus {
        affinity.set(*cpu);
    }
    let jobs = cargo_jobs(
        budget.build_cpus.len(),
        std::env::var("CARGO_BUILD_JOBS").ok().as_deref(),
    )?;
    let inherited_config = std::env::var("NIX_CONFIG").unwrap_or_default();
    let config = format!(
        r#"{inherited_config}
max-jobs = {nix_jobs}
cores = {cores}
"#,
        nix_jobs = budget.nix_jobs,
        cores = budget.nix_cores
    );

    sched_setaffinity(None, &affinity).context("cannot restrict build CPU affinity")?;
    ensure!(
        sched_getaffinity(None)? == affinity,
        "build CPU affinity changed during setup"
    );

    support::record(&root.join(".airlock-logs/build-cpu-budget.json"), &budget)?;
    eprintln!(
        "Image build: reserving physical-core CPUs {reserved:?}; using CPUs {build:?} with {jobs} Cargo jobs and {nix_jobs} concurrent Nix jobs ({nix_cores} cores each).",
        reserved = budget.reserved_core_cpus,
        build = budget.build_cpus,
        nix_jobs = budget.nix_jobs,
        nix_cores = budget.nix_cores,
    );

    let error = Command::new(program)
        .args(arguments)
        .env("CARGO_BUILD_JOBS", jobs.to_string())
        .env("NIX_CONFIG", config)
        .env("AIRLOCK_IMAGE_BUILD_LIMITED", "1")
        .exec();
    Err(error).context("cannot execute CPU-limited build")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sparse SMT identities and inherited restrictions must never become dense CPU counts.
    #[test]
    fn physical_core_reservation_preserves_existing_cpu_restrictions() -> Result<()> {
        let cores = [cpu_list("2,10")?, cpu_list("4,12")?, cpu_list("7,15")?];
        let budget = select(cpu_list("2,4,7,10,12,15")?, &cores)?;
        assert_eq!(budget.build_cpus, cpu_list("2,4,10,12")?);
        assert_eq!(budget.reserved_core_cpus, cpu_list("7,15")?);
        assert_eq!((budget.nix_jobs, budget.nix_cores), (2, 2));

        let nested = select(budget.build_cpus.clone(), &cores)?;
        assert_eq!(nested.build_cpus, budget.build_cpus);
        assert_eq!(nested.reserved_core_cpus, budget.reserved_core_cpus);
        assert_eq!((nested.nix_jobs, nested.nix_cores), (2, 2));

        let partial = select(cpu_list("2,4,7")?, &cores)?;
        assert_eq!(partial.build_cpus, cpu_list("2,4")?);
        assert_eq!((partial.nix_jobs, partial.nix_cores), (2, 1));

        let one = select(cpu_list("2,10")?, &cores)?;
        assert_eq!((one.nix_jobs, one.nix_cores), (1, 2));

        assert!(select(cpu_list("2,10")?, &[cpu_list("2,10")?]).is_err());
        assert!(select(cpu_list("2,10")?, &[cpu_list("2,10")?, cpu_list("10,12")?]).is_err());
        assert!(select(cpu_list("1")?, &cores).is_err());
        Ok(())
    }

    /// Kernel topology records include offline siblings, but only online CPUs can be assigned.
    #[test]
    fn topology_groups_online_siblings_and_rejects_incomplete_records() -> Result<()> {
        let root = tempfile::tempdir()?;
        fs::write(root.path().join("online"), "0-1,8")?;
        for (cpu, siblings) in [(0, "0,8"), (1, "1,9"), (8, "0,8")] {
            let directory = root.path().join(format!("cpu{cpu}/topology"));
            fs::create_dir_all(&directory)?;
            fs::write(directory.join("thread_siblings_list"), siblings)?;
        }
        assert_eq!(topology(root.path())?, [cpu_list("0,8")?, cpu_list("1")?]);

        fs::write(root.path().join("cpu1/topology/thread_siblings_list"), "9")?;
        assert!(topology(root.path()).is_err());
        for malformed in ["", "1,", "2-1", "-1", "0-x", "1024"] {
            assert!(cpu_list(malformed).is_err(), "{malformed}");
        }
        Ok(())
    }

    /// Cargo's requested limit can reduce parallelism but cannot exceed the CPU budget.
    #[test]
    fn cargo_job_limits_fit_the_reserved_cpu_budget() -> Result<()> {
        assert_eq!(cargo_jobs(14, None)?, 14);
        assert_eq!(cargo_jobs(14, Some("2"))?, 2);
        assert_eq!(cargo_jobs(14, Some("64"))?, 14);
        assert_eq!(cargo_jobs(14, Some("-2"))?, 12);
        assert_eq!(cargo_jobs(14, Some("-64"))?, 1);
        assert!(cargo_jobs(14, Some("0")).is_err());
        assert!(cargo_jobs(14, Some("auto")).is_err());
        Ok(())
    }
}
