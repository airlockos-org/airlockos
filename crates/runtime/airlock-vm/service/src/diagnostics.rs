//! Best-effort local evidence collection when VM services fail.

use clap::{Args, ValueEnum};
use std::{fs, path::Path, process::Command};

#[derive(Args)]
pub(crate) struct Request {
    /// Service family whose failure is being reported.
    kind: Kind,
    /// Configured user whose workspace paths aid configuration diagnostics.
    #[arg(long, default_value = "user")]
    user: String,
}

#[derive(Clone, Copy, ValueEnum)]
enum Kind {
    Configuration,
    Storage,
    Database,
    Qrexec,
}

/// Report failed probes without suppressing the other evidence sources.
fn run(program: &str, args: &[&str]) {
    if let Err(error) = Command::new(program).args(args).status() {
        eprintln!("diagnostic probe {program}: {error}");
    }
}

/// List workspace paths without following symlinks into unrelated trees.
fn paths(root: &Path, depth: usize) {
    if depth == 0 {
        return;
    }
    match fs::read_dir(root) {
        Ok(entries) => {
            let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                println!("{path}", path = entry.path().display());
                if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    paths(&entry.path(), depth - 1);
                }
            }
        }
        Err(error) => eprintln!(
            "diagnostic directory {path}: {error}",
            path = root.display()
        ),
    }
}

pub(crate) fn execute(request: Request) {
    let service = match request.kind {
        Kind::Configuration => "airlock-config-guest-init.service",
        Kind::Storage => "airlock-qubes-rw-init.service",
        Kind::Database => "qubes-db.service",
        Kind::Qrexec => "qubes-qrexec-agent.service",
    };
    println!("airlock guest diagnostics: {service} failed");
    run("systemctl", &["--no-pager", "status", service]);
    run(
        "journalctl",
        &[
            "-b",
            "--no-pager",
            "-u",
            service,
            "-n",
            if matches!(request.kind, Kind::Configuration) {
                "160"
            } else {
                "120"
            },
        ],
    );
    match request.kind {
        Kind::Configuration => {
            println!("airlock guest diagnostics: Qubes identity");
            run("qubesdb-read", &["/name"]);
            run("qubesdb-read", &["/features/airlock-role"]);
            println!("airlock guest diagnostics: filesystem state");
            run("findmnt", &["/", "/rw", "/home", "/nix", "/nix/store"]);
            let home = format!("/home/{user}", user = request.user);
            run(
                "ls",
                &[
                    "-ld",
                    "/rw",
                    "/rw/home",
                    "/home",
                    &home,
                    "/nix",
                    "/nix/store",
                ],
            );
            println!("airlock guest diagnostics: config paths");
            paths(Path::new(&home), 3);
        }
        Kind::Storage => {
            println!("airlock guest diagnostics: filesystem state");
            run(
                "ls",
                &[
                    "-ld",
                    "/rw",
                    "/home",
                    "/usr/local",
                    "/var",
                    "/var/run",
                    "/run/qubes",
                    "/var/lib",
                    "/var/lib/qubes",
                ],
            );
            run("findmnt", &["/", "/rw", "/home", "/usr/local"]);
            println!("airlock guest diagnostics: block devices");
            run("lsblk", &["-o", "NAME,MAJ:MIN,SIZE,FSTYPE,MOUNTPOINTS"]);
            run("blkid", &["/dev/xvdb"]);
        }
        Kind::Database => {
            println!("airlock guest diagnostics: Xen device nodes");
            run("ls", &["-l", "/dev/xen", "/proc/xen"]);
            println!("airlock guest diagnostics: loaded Xen modules");
            match fs::read_to_string("/proc/modules") {
                Ok(text) => {
                    for line in text.lines().filter(|line| {
                        line.starts_with("xen")
                            || ["evtchn", "gnt", "privcmd"]
                                .iter()
                                .any(|word| line.contains(word))
                    }) {
                        println!("{line}");
                    }
                }
                Err(error) => eprintln!("diagnostic modules: {error}"),
            }
        }
        Kind::Qrexec => {
            println!("airlock guest diagnostics: QubesDB service state");
            run("systemctl", &["--no-pager", "status", "qubes-db.service"]);
        }
    }
}
