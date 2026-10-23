//! Establish and observe the persistent filesystem before guest sessions can use it.
//! Upstream Qubes owns filesystem initialization. Airlock checks live mount identities before
//! using its results; success is never reconstructed from a persisted readiness flag.
//! The kernel observation is not atomic with later I/O. Root-driven mount/device changes remain
//! outside this boundary, as do filesystem durability and the behavior of the upstream helpers.

use airlock_machine_planning::private_storage::{
    Device, Location, Mount, PrivateMount, check_mount, may_initialize,
};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::Path,
    process::Command,
    time::Duration,
};

/// Checked evidence of the private filesystem and its exact home/local bind roots.
pub use airlock_machine_planning::private_storage::ReadyStorage;

const DEVICE: &str = "/dev/xvdb";

const TABLE_LIMIT: u64 = 4 * 1024 * 1024;

/// Decode the four escapes emitted by procfs without accepting alternate path spellings.
fn unescape(value: &str) -> Result<String> {
    let mut bytes = Vec::new();
    let mut input = value.as_bytes().iter().copied();
    while let Some(byte) = input.next() {
        if byte != b'\\' {
            bytes.push(byte);
            continue;
        }
        let escape = [input.next(), input.next(), input.next()];
        bytes.push(match escape {
            [Some(b'0'), Some(b'4'), Some(b'0')] => b' ',
            [Some(b'0'), Some(b'1'), Some(b'1')] => b'\t',
            [Some(b'0'), Some(b'1'), Some(b'2')] => b'\n',
            [Some(b'1'), Some(b'3'), Some(b'4')] => b'\\',
            _ => bail!("invalid mountinfo path escape"),
        });
    }
    let path = String::from_utf8(bytes)?;
    ensure!(
        path.starts_with('/')
            && !path.contains('\0')
            && !path.contains("//")
            && !path.split('/').any(|part| part == "." || part == ".."),
        "noncanonical mountinfo path"
    );
    Ok(path)
}

/// Decode write permission without letting a contradictory ro/rw pair count as writable.
fn writable(options: &str) -> Result<bool> {
    let read_only = options.split(',').filter(|option| *option == "ro").count();
    let read_write = options.split(',').filter(|option| *option == "rw").count();
    ensure!(read_only + read_write == 1, "ambiguous mount write mode");
    Ok(read_write == 1)
}

/// Retain all kernel rows, including duplicate mountpoints, for the verified selector.
fn parse(table: &str) -> Result<Vec<Mount>> {
    let mut mounts = Vec::new();
    let mut ids = BTreeSet::new();
    for line in table.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        let separator = fields
            .iter()
            .position(|field| *field == "-")
            .context("mountinfo separator")?;
        ensure!(
            separator >= 6 && fields.len() == separator + 4,
            "invalid mountinfo row"
        );
        let id: u64 = fields[0].parse()?;
        let _parent: u64 = fields[1].parse()?;
        ensure!(
            id > 0 && ids.insert(id),
            "duplicate or invalid mount identity"
        );
        let (major, minor) = fields[2].split_once(':').context("mount device number")?;
        let target = unescape(fields[4])?;
        // A mount hiding an initialization source could redirect the upstream helpers even when
        // /rw itself is correct. Worker-store mounts elsewhere under /rw remain legitimate.
        ensure!(
            !["/rw/home", "/rw/usrlocal"].iter().any(|source| {
                target == *source
                    || target
                        .strip_prefix(source)
                        .is_some_and(|tail| tail.starts_with('/'))
            }),
            "private initialization source is overmounted: {target}"
        );
        mounts.push(Mount {
            device: Device {
                major: major.parse()?,
                minor: minor.parse()?,
            },
            root: unescape(fields[3])?,
            target,
            filesystem: fields[separator + 1].to_owned(),
            writable: writable(fields[5])? && writable(fields[separator + 3])?,
            nosuid: fields[5].split(',').any(|option| option == "nosuid"),
            nodev: fields[5].split(',').any(|option| option == "nodev"),
        });
    }
    ensure!(!mounts.is_empty(), "empty mount observation");
    Ok(mounts)
}

/// Fixed adapter actions; no remote caller supplies a target path or command.
#[derive(Clone, Copy)]
enum Effect {
    /// Let upstream Qubes inspect and initialize the unmounted private device.
    InitializeDevice,
    /// Mount the exact private block device at /rw.
    MountPrivate,
    /// Populate Qubes' persistent configuration and local software directories.
    SetupPrivate,
    /// Populate the persistent home using Qubes' ifneeded policy.
    InitializeHome,
    /// Bind the selected persistent directory at its fixed destination.
    Bind(Location),
    /// Explicitly retain private-mount restrictions on that bind mount.
    Restrict(Location),
    /// Create the configured user's directory only after /home passed the live check.
    HomeOwner,
}

/// Isolate kernel and subprocess observations from orchestration, including uncertain failures.
trait Backend {
    /// Read the private block-device identity and one complete current mount table.
    fn sample(&mut self) -> Result<(Device, Vec<Mount>)>;

    /// Perform one fixed adapter operation, propagating unsuccessful or uncertain completion.
    fn apply(&mut self, effect: Effect) -> Result<()>;
}

/// Recheck the original device on every snapshot; retries cannot silently substitute a device.
fn sample(backend: &mut impl Backend, expected: Device) -> Result<Vec<Mount>> {
    let (device, mounts) = backend.sample()?;
    ensure!(
        device == expected,
        "private block device changed during initialization"
    );
    Ok(mounts)
}

/// Require a valid private filesystem before any directory initialization or bind operation.
fn private(backend: &mut impl Backend, expected: Device) -> Result<PrivateMount> {
    PrivateMount::check(expected, sample(backend, expected)?)
        .context("incorrect private filesystem at /rw")
}

/// Map the supported bind roots; /rw is mounted as a block filesystem, never as a bind.
fn paths(location: Location) -> Result<(&'static str, &'static str)> {
    match location {
        Location::Home => Ok(("/rw/home", "/home")),
        Location::Local => Ok(("/rw/usrlocal", "/usr/local")),
        Location::Private => bail!("private filesystem is not a bind mount"),
    }
}

/// Reuse only an exact existing bind mount, otherwise create and immediately inspect it.
fn bind(backend: &mut impl Backend, expected: Device, location: Location) -> Result<()> {
    let (_, destination) = paths(location)?;
    let mounts = sample(backend, expected)?;
    ensure!(
        check_mount(expected, &mounts, Location::Private),
        "private filesystem changed before binding"
    );
    if !mounts.iter().any(|mount| mount.target == destination) {
        backend.apply(Effect::Bind(location))?;
        backend.apply(Effect::Restrict(location))?;
    }
    let mounts = sample(backend, expected)?;
    ensure!(
        check_mount(expected, &mounts, location),
        "incorrect persistent bind mount at {destination}"
    );
    Ok(())
}

/// Publish success only after a fresh complete observation passes the verified checks.
fn initialize_with(backend: &mut impl Backend) -> Result<ReadyStorage> {
    let (expected, mounts) = backend.sample()?;
    if !mounts.iter().any(|mount| mount.target == "/rw") {
        ensure!(
            may_initialize(expected, &mounts),
            "private device or destination is already mounted"
        );
        backend.apply(Effect::InitializeDevice)?;
        ensure!(
            may_initialize(expected, &sample(backend, expected)?),
            "private mounts changed during device initialization"
        );
        backend.apply(Effect::MountPrivate)?;
    }
    let _private = private(backend, expected)?;
    backend.apply(Effect::SetupPrivate)?;
    let _private = private(backend, expected)?;
    backend.apply(Effect::InitializeHome)?;
    bind(backend, expected, Location::Home)?;
    backend.apply(Effect::HomeOwner)?;
    bind(backend, expected, Location::Local)?;
    private(backend, expected)?
        .ready()
        .context("private storage is not ready")
}

/// Device descriptor retained throughout the operation, even when a path is replaced.
struct Observer {
    // Pins the original block device; path-using upstream helpers are separately rechecked.
    device: File,
}

impl Observer {
    /// Open only Qubes' installed private-device path and require a real block device.
    fn open() -> Result<Self> {
        let device = File::open(DEVICE).context("open private block device /dev/xvdb")?;
        ensure!(
            device.metadata()?.file_type().is_block_device(),
            "private device is not a block device"
        );
        Ok(Self { device })
    }

    /// Refuse a replaced path, then read the bounded mount table from the current namespace.
    fn sample(&self) -> Result<(Device, Vec<Mount>)> {
        let original = self.device.metadata()?;
        let current = fs::metadata(DEVICE)?;
        ensure!(
            current.file_type().is_block_device() && current.rdev() == original.rdev(),
            "private device path changed"
        );
        let mut table = String::new();
        File::open("/proc/self/mountinfo")?
            .take(TABLE_LIMIT + 1)
            .read_to_string(&mut table)?;
        ensure!(
            table.len() as u64 <= TABLE_LIMIT,
            "private mount observation exceeds limit"
        );
        Ok((
            Device {
                major: rustix::fs::major(original.rdev()),
                minor: rustix::fs::minor(original.rdev()),
            },
            parse(&table)?,
        ))
    }
}

/// Installed package paths and user selection, independent of incoming RPC data.
struct Kernel<'a> {
    // Pinned original private device and live mount-table reader.
    observer: Observer,
    // Immutable upstream Qubes agent containing its own initialization routines.
    agent: &'a Path,
    // Explicit Bash executable, independent of the caller's PATH.
    bash: &'a Path,
    // Installed unprivileged home owner.
    user: &'a str,
}

/// Require a real directory on the private filesystem, with no symlink substitution.
fn directory(path: &str, device: Device) -> Result<()> {
    let path = Path::new(path);
    ensure!(
        fs::canonicalize(path)? == path,
        "persistent directory is an alias: {path}",
        path = path.display()
    );
    let metadata = fs::metadata(path)?;
    ensure!(
        metadata.is_dir()
            && rustix::fs::major(metadata.dev()) == device.major
            && rustix::fs::minor(metadata.dev()) == device.minor,
        "directory is not on private storage: {path}",
        path = path.display()
    );
    Ok(())
}

/// Propagate command failures, including cancellation, instead of accepting a later successful step.
fn run(command: &mut Command) -> Result<()> {
    crate::support::run(command, None, Duration::from_secs(120))?.checked()?;
    Ok(())
}

/// Invoke Qubes' fixed initializer with literal arguments and its existing ifneeded policy.
pub(crate) fn home_initializer(bash: &Path, functions: &Path, home: &Path) -> Result<Command> {
    ensure!(
        bash.is_absolute(),
        "private storage Bash path must be absolute"
    );
    let mut command = Command::new(bash);
    command
        .args([
            "-eu",
            "-c",
            r#". "$1"; initialize_home "$2" ifneeded"#,
            "airlock-upstream-home",
        ])
        .arg(functions)
        .arg(home);
    Ok(command)
}

impl Backend for Kernel<'_> {
    fn sample(&mut self) -> Result<(Device, Vec<Mount>)> {
        self.observer.sample()
    }

    fn apply(&mut self, effect: Effect) -> Result<()> {
        let (device, mounts) = self.observer.sample()?;
        match effect {
            Effect::InitializeDevice | Effect::MountPrivate => {
                ensure!(
                    may_initialize(device, &mounts),
                    "private device initialization requires an unmounted device"
                );
            }
            _ => {
                let _private = PrivateMount::check(device, mounts)
                    .context("private filesystem changed before initialization")?;
                directory("/rw", device)?;
            }
        }

        match effect {
            Effect::InitializeDevice => run(&mut Command::new(
                self.agent.join("lib/qubes/init/setup-rwdev.sh"),
            )),
            Effect::MountPrivate => run(Command::new("mount").args([
                "-t",
                "ext4",
                "-o",
                "defaults,discard,nosuid,nodev",
                DEVICE,
                "/rw",
            ])),
            Effect::SetupPrivate => {
                for path in ["/rw/config", "/rw/home", "/rw/usrlocal"] {
                    if Path::new(path).try_exists()? {
                        directory(path, device)?;
                    }
                }
                run(&mut Command::new(
                    self.agent.join("lib/qubes/init/setup-rw.sh"),
                ))?;
                fs::create_dir_all("/rw/usrlocal")?;
                directory("/rw/usrlocal", device)
            }
            Effect::InitializeHome => {
                if Path::new("/rw/home").try_exists()? {
                    directory("/rw/home", device)?;
                }
                run(&mut home_initializer(
                    self.bash,
                    &self.agent.join("lib/qubes/init/functions"),
                    Path::new("/rw/home"),
                )?)?;
                directory("/rw/home", device)
            }
            Effect::Bind(location) => {
                let (source, target) = paths(location)?;
                directory(source, device)?;
                ensure!(
                    fs::canonicalize(target)? == Path::new(target),
                    "persistent bind destination is an alias"
                );
                run(Command::new("mount").args(["--bind", source, target]))
            }
            Effect::Restrict(location) => {
                let (_, target) = paths(location)?;
                run(Command::new("mount").args(["-o", "remount,bind,nosuid,nodev", target]))
            }
            Effect::HomeOwner => {
                let (_, mounts) = self.observer.sample()?;
                ensure!(
                    check_mount(device, &mounts, Location::Home),
                    "home changed before user directory setup"
                );
                directory("/home", device)?;
                let home = format!("/home/{user}", user = self.user);
                if Path::new(&home).try_exists()? {
                    directory(&home, device)?;
                }
                run(Command::new("install")
                    .args(["-d", "-m", "0700", "-o", self.user, "-g", "users", &home]))
            }
        }
    }
}

/// Establish private mounts using upstream Qubes helpers and verify their exact live identities.
/// Errors never yield readiness; retries reuse correct mounts and never fsck an already mounted device.
pub fn initialize(agent: &Path, bash: &Path, user: &str) -> Result<ReadyStorage> {
    ensure!(
        agent.is_absolute() && bash.is_absolute(),
        "private initialization needs installed absolute package paths"
    );
    ensure!(
        !user.is_empty() && !user.contains('/') && user != "." && user != "..",
        "invalid private home owner"
    );
    for directory in ["/rw", "/home", "/usr/local", "/var/lib/qubes"] {
        fs::create_dir_all(directory)?;
    }
    initialize_with(&mut Kernel {
        observer: Observer::open()?,
        agent,
        bash,
        user,
    })
}

/// Reobserve the actual private device and mount roots without starting services or changing mounts.
/// The returned evidence describes this observation only; it cannot promise future persistence.
pub fn observe() -> Result<ReadyStorage> {
    let (device, mounts) = Observer::open()?.sample()?;
    for path in ["/rw", "/rw/home", "/home", "/rw/usrlocal", "/usr/local"] {
        directory(path, device)?;
    }
    PrivateMount::check(device, mounts)
        .context("incorrect private mount")?
        .ready()
        .context("persistent home/local mounts are not ready")
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE: Device = Device {
        major: 202,
        minor: 16,
    };

    /// An unrelated root mount remains in every observation, including before private initialization.
    const ROOT: &str = "1 0 253:0 / / rw - ext4 /dev/mapper/dmroot rw\n";

    /// Realistic kernel spelling of one private mount; bind sources are intentionally not path names.
    fn row(location: Location) -> &'static str {
        match location {
            Location::Private => "2 1 202:16 / /rw rw,nosuid,nodev - ext4 /dev/xvdb rw\n",
            Location::Home => "3 1 202:16 /home /home rw,nosuid,nodev - ext4 /dev/xvdb rw\n",
            Location::Local => {
                "4 1 202:16 /usrlocal /usr/local rw,nosuid,nodev - ext4 /dev/xvdb rw\n"
            }
        }
    }

    /// Compose a full mount namespace without deduplicating or normalizing conflicting records.
    fn table() -> String {
        [
            ROOT,
            row(Location::Private),
            row(Location::Home),
            row(Location::Local),
        ]
        .concat()
    }

    /// Route fixture text through the same parser and opaque verified constructors as production.
    fn checked(text: &str) -> Result<ReadyStorage> {
        PrivateMount::check(PRIVATE, parse(text)?)
            .context("private")?
            .ready()
            .context("binds")
    }

    /// Wrong roots/devices/flags, omitted anchors and stacked targets cannot become readiness.
    #[test]
    fn readiness_requires_exact_private_mounts() -> Result<()> {
        let original = table();
        assert_eq!(checked(&original)?.device(), PRIVATE);
        let mut reordered: Vec<_> = original.lines().collect();
        reordered.reverse();
        assert!(checked(&reordered.join("\n")).is_ok());
        for changed in [
            original.replace("202:16 /home", "202:32 /home"),
            original.replace("/home /home", "/other /home"),
            original.replace("/ /rw", "/other /rw"),
            original.replace("/usrlocal /usr/local", "/home /usr/local"),
            original.replace("rw,nosuid,nodev", "ro,nosuid,nodev"),
            original.replace("rw,nosuid,nodev", "rw,nodev"),
            original.replace("rw,nosuid,nodev", "rw,nosuid"),
            original.replace("- ext4", "- tmpfs"),
            original.replace("/dev/xvdb rw", "/dev/xvdb ro"),
            original.replace(row(Location::Home), ""),
            original.replace(row(Location::Private), ""),
            original.replace(row(Location::Local), ""),
            format!("{original}5 1 202:16 /home /home rw,nosuid,nodev - ext4 /dev/xvdb rw\n"),
        ] {
            assert!(
                checked(&changed).is_err(),
                "accepted incorrect mount table: {changed}"
            );
        }
        // The source text is only informational; the kernel's device and filesystem root bind identity.
        assert!(checked(&original.replace("/dev/xvdb", "/dev/disk/by-uuid/private")).is_ok());
        Ok(())
    }

    /// Malformed observations never yield a partial table or hide a source-directory overmount.
    #[test]
    fn malformed_or_overlaid_mount_observations_fail_closed() {
        for text in [
            "".to_owned(),
            format!("{}malformed\n", table()),
            table().replace("3 1", "2 1"),
            table().replace("rw,nosuid,nodev", "rw,ro,nosuid,nodev"),
            table().replace("/home /home", "/home /ho\\057me"),
            table().replace("/home /home", "/home /x/../home"),
            format!("{}5 2 0:45 / /rw/home rw - tmpfs tmpfs rw\n", table()),
            format!("{}5 2 0:45 / /rw/home/user rw - tmpfs tmpfs rw\n", table()),
            format!("{}5 2 0:45 / /rw/usrlocal rw - tmpfs tmpfs rw\n", table()),
        ] {
            assert!(
                parse(&text).is_err(),
                "accepted malformed observation: {text}"
            );
        }
        let escaped = format!(
            "{}5 1 0:45 / /unrelated\\040name rw - tmpfs tmpfs rw\n",
            table()
        );
        assert!(checked(&escaped).is_ok());
    }

    /// A real directory must also belong to the expected private filesystem; symlinks are not evidence.
    #[test]
    fn directory_identity_rejects_aliases_and_other_filesystems() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let real = fs::canonicalize(temporary.path())?;
        let metadata = fs::metadata(&real)?;
        let device = Device {
            major: rustix::fs::major(metadata.dev()),
            minor: rustix::fs::minor(metadata.dev()),
        };
        directory(real.to_str().unwrap(), device)?;
        assert!(directory(real.to_str().unwrap(), PRIVATE).is_err());
        let alias = real.join("alias");
        std::os::unix::fs::symlink(&real, &alias)?;
        assert!(directory(alias.to_str().unwrap(), device).is_err());
        Ok(())
    }

    /// Inert mount namespace with deterministic failure before or after an external effect.
    struct Fixture {
        // Device identity returned by every observation, unless substitution is injected.
        device: Device,
        // Complete current mount observation, updated only by successful simulated mount effects.
        mounts: String,
        // Operations attempted by the production orchestrator.
        calls: Vec<&'static str>,
        // Failing operation and whether its effect happened before the failure was returned.
        failure: Option<(&'static str, bool)>,
        // Simulate replacement of the observed private device after directory setup.
        substitute_device: bool,
        // Simulate a mount helper reporting success after binding the wrong home root.
        misbind_home: bool,
    }

    impl Fixture {
        /// Begin before the first private mount; no real devices or mount operations are used.
        fn new() -> Self {
            Self {
                device: PRIVATE,
                mounts: ROOT.to_owned(),
                calls: Vec::new(),
                failure: None,
                substitute_device: false,
                misbind_home: false,
            }
        }
    }

    impl Backend for Fixture {
        fn sample(&mut self) -> Result<(Device, Vec<Mount>)> {
            Ok((self.device, parse(&self.mounts)?))
        }

        fn apply(&mut self, effect: Effect) -> Result<()> {
            let name = match effect {
                Effect::InitializeDevice => "device",
                Effect::MountPrivate => "mount",
                Effect::SetupPrivate => "setup",
                Effect::InitializeHome => "home",
                Effect::Bind(Location::Home) => "bind-home",
                Effect::Restrict(Location::Home) => "restrict-home",
                Effect::HomeOwner => "owner",
                Effect::Bind(Location::Local) => "bind-local",
                Effect::Restrict(Location::Local) => "restrict-local",
                _ => bail!("unexpected private bind"),
            };
            self.calls.push(name);
            if self.failure == Some((name, false)) {
                bail!("injected failure before {name}");
            }
            match effect {
                Effect::MountPrivate => self.mounts.push_str(row(Location::Private)),
                Effect::Bind(Location::Home) if self.misbind_home => {
                    self.mounts
                        .push_str(&row(Location::Home).replace("/home /home", "/other /home"));
                }
                Effect::Bind(location) => self.mounts.push_str(row(location)),
                Effect::SetupPrivate if self.substitute_device => self.device.minor = 32,
                _ => {}
            }
            if self.failure == Some((name, true)) {
                bail!("injected uncertain outcome after {name}");
            }
            Ok(())
        }
    }

    /// Retry every interruption point without accepting incomplete state or rechecking a mounted device.
    #[test]
    fn interrupted_initialization_requires_live_completion_and_recovers() -> Result<()> {
        for operation in [
            "device",
            "mount",
            "setup",
            "home",
            "bind-home",
            "restrict-home",
            "owner",
            "bind-local",
            "restrict-local",
        ] {
            for completed in [false, true] {
                let mut fixture = Fixture::new();
                fixture.failure = Some((operation, completed));
                assert!(
                    initialize_with(&mut fixture).is_err(),
                    "failure at {operation}"
                );
                assert_eq!(fixture.calls.last().copied(), Some(operation));
                fixture.failure = None;
                fixture.calls.clear();
                let mounted = fixture.mounts.contains(" /rw ");
                assert_eq!(initialize_with(&mut fixture)?.device(), PRIVATE);
                if mounted {
                    assert!(!fixture.calls.contains(&"device"));
                }
                fixture.calls.clear();
                initialize_with(&mut fixture)?;
                assert_eq!(fixture.calls, ["setup", "home", "owner"]);
            }
        }
        Ok(())
    }

    /// A wrong mounted private device blocks helpers; a wrong home blocks all user-directory writes.
    #[test]
    fn wrong_mounts_never_receive_initialization_writes() -> Result<()> {
        let mut fixture = Fixture::new();
        fixture.mounts = table().replace("202:16 / /rw", "202:32 / /rw");
        assert!(initialize_with(&mut fixture).is_err());
        assert!(fixture.calls.is_empty());
        fixture.mounts = table().replace("/home /home", "/other /home");
        assert!(initialize_with(&mut fixture).is_err());
        assert!(!fixture.calls.contains(&"owner"));
        fixture.calls.clear();
        fixture.mounts = format!("{ROOT}2 1 202:16 / /elsewhere rw - ext4 /dev/xvdb rw\n");
        assert!(initialize_with(&mut fixture).is_err());
        assert!(fixture.calls.is_empty());
        Ok(())
    }

    /// Reobservations catch a substituted device and a successful command with the wrong outcome.
    #[test]
    fn changed_device_or_incorrect_external_success_never_becomes_ready() {
        let mut fixture = Fixture::new();
        fixture.substitute_device = true;
        assert!(initialize_with(&mut fixture).is_err());
        assert!(!fixture.calls.contains(&"home"));

        let mut fixture = Fixture::new();
        fixture.misbind_home = true;
        assert!(initialize_with(&mut fixture).is_err());
        assert!(!fixture.calls.contains(&"owner"));
    }

    /// An explicit Bash works without PATH, preserves literal paths and propagates upstream failure.
    #[test]
    fn private_home_uses_declared_bash_without_path() -> Result<()> {
        let bash = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|directory| directory.join("bash"))
            .find(|path| path.is_file())
            .context("prepare Bash before running the home initialization regression")?;
        let bash = fs::canonicalize(bash)?;
        let temporary = tempfile::tempdir()?;
        let functions = temporary.path().join("functions ' literal");
        let home = temporary.path().join("home $(false) ' literal");
        fs::write(
            &functions,
            r#"
initialize_home() {
    printf '%s\n' "$1" "$2" > "$1"
}
"#,
        )?;
        run(home_initializer(&bash, &functions, &home)?
            .env_clear()
            .env("PATH", temporary.path()))?;
        assert_eq!(
            fs::read_to_string(&home)?,
            format!("{home}\nifneeded\n", home = home.display())
        );
        fs::write(&functions, "initialize_home() { return 23; }\n")?;
        assert!(
            run(home_initializer(&bash, &functions, &home)?
                .env_clear()
                .env("PATH", temporary.path()))
            .is_err()
        );
        assert!(home_initializer(Path::new("bash"), &functions, &home).is_err());
        Ok(())
    }
}
