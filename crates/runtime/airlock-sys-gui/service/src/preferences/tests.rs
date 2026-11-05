//! Exercise the real feed, bounded stream and namespace boundary with disposable local state.

use super::{admission, export, feed, sandbox, source};
use airlock_desktop_preferences::{ColorScheme, FrameDecoder, Setting, Snapshot};
use anyhow::Result;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, SystemTime};

/// Read one complete framed reply from a local simulated qrexec stream.
fn receive(peer: &mut UnixStream) -> Result<Snapshot> {
    peer.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut header = [0; 8];
    peer.read_exact(&mut header)?;
    let length = u16::from_be_bytes([header[6], header[7]]) as usize;
    let mut frame = header.to_vec();
    frame.resize(8 + length, 0);
    peer.read_exact(&mut frame[8..])?;
    Ok(FrameDecoder::default()
        .decode(&mut frame.as_slice())?
        .unwrap())
}

/// Start the same descriptor pump used inside the production sandbox.
fn subscriber(directory: &Path) -> Result<(UnixStream, std::thread::JoinHandle<Result<()>>)> {
    let (peer, mut output) = UnixStream::pair()?;
    let mut input = output.try_clone()?;
    let directory = directory.to_owned();
    let worker = std::thread::spawn(move || {
        export::pump(&directory, &mut input, &mut output, Duration::from_secs(5))
    });
    Ok((peer, worker))
}

/// Atomically replace state, enforce one publisher and reject stale, malformed or linked files.
#[test]
fn publication_ownership_and_liveness_are_enforced() -> Result<()> {
    let root = tempfile::tempdir()?;
    let publisher = feed::Publisher::new(root.path())?;
    assert!(feed::Publisher::new(root.path()).is_err());
    let snapshot = Snapshot::default();
    publisher.publish(&snapshot)?;
    let directory = root.path().join("feed");
    assert!(feed::read(&directory).is_ok());
    let file = fs::File::options()
        .write(true)
        .open(directory.join("snapshot"))?;
    file.set_times(fs::FileTimes::new().set_modified(SystemTime::now() - Duration::from_secs(6)))?;
    assert!(feed::read(&directory).is_err());
    publisher.publish(&snapshot)?;
    fs::write(directory.join("snapshot"), b"invalid")?;
    assert!(feed::read(&directory).is_err());
    fs::remove_file(directory.join("snapshot"))?;
    std::os::unix::fs::symlink("/dev/zero", directory.join("snapshot"))?;
    assert!(feed::read(&directory).is_err());
    drop(publisher);
    let restarted = feed::Publisher::new(root.path())?;
    restarted.publish(&snapshot)?;
    assert!(feed::read(&directory).is_ok());
    Ok(())
}

/// Admission bounds file count and concurrent callers, then reuses slots released by disconnects.
#[test]
fn admission_releases_per_caller_and_global_capacity() -> Result<()> {
    let root = tempfile::tempdir()?;
    let first = "usr-first".parse()?;
    let held = admission::acquire(root.path(), &first)?;
    assert!(admission::acquire(root.path(), &first).is_err());
    let mut others = Vec::new();
    for index in 1..64 {
        others.push(admission::acquire(
            root.path(),
            &format!("usr-{index}").parse()?,
        )?);
    }
    assert!(admission::acquire(root.path(), &"usr-overflow".parse()?).is_err());
    drop(held);
    let replacement = admission::acquire(root.path(), &first)?;
    assert_eq!(fs::read_dir(root.path().join("admission"))?.count(), 65);
    drop((replacement, others));
    assert!(admission::acquire(root.path(), &first).is_ok());
    Ok(())
}

/// Two readers follow replacements, tolerate half-close and recover from publisher restart.
#[test]
fn subscribers_receive_initial_changes_and_reconnect_state() -> Result<()> {
    let root = tempfile::tempdir()?;
    let publisher = feed::Publisher::new(root.path())?;
    let directory = root.path().join("feed");
    let (mut first, a) = subscriber(&directory)?;
    let (mut second, b) = subscriber(&directory)?;
    first.shutdown(std::net::Shutdown::Write)?;
    let initial = Snapshot::default();
    publisher.publish(&initial)?;
    assert_eq!(receive(&mut first)?, initial);
    assert_eq!(receive(&mut second)?, initial);
    let dark = Snapshot {
        color_scheme: Setting::Supported(ColorScheme::PreferDark),
        ..initial
    };
    publisher.publish(&dark)?;
    assert_eq!(receive(&mut first)?, dark);
    assert_eq!(receive(&mut second)?, dark);
    // An unchanged heartbeat produces no duplicate transport frame.
    publisher.publish(&dark)?;
    first.set_read_timeout(Some(Duration::from_millis(250)))?;
    assert!(first.read(&mut [0]).is_err());
    drop((first, second));
    assert!(a.join().unwrap().is_err());
    assert!(b.join().unwrap().is_err());
    drop(publisher);
    let restarted = feed::Publisher::new(root.path())?;
    restarted.publish(&Snapshot::default())?;
    let (mut fresh, worker) = subscriber(&directory)?;
    assert_eq!(receive(&mut fresh)?, Snapshot::default());
    drop(fresh);
    assert!(worker.join().unwrap().is_err());
    Ok(())
}

/// An idle connection expires even with a fresh feed, forcing the next caller through policy again.
#[test]
fn subscription_lease_requires_fresh_admission_without_losing_current_state() -> Result<()> {
    let root = tempfile::tempdir()?;
    let publisher = feed::Publisher::new(root.path())?;
    let directory = root.path().join("feed");
    for high_contrast in [false, true, false] {
        let snapshot = Snapshot {
            high_contrast: Setting::Supported(high_contrast),
            ..Snapshot::default()
        };
        publisher.publish(&snapshot)?;
        let (mut peer, mut output) = UnixStream::pair()?;
        let mut input = output.try_clone()?;
        let directory = directory.clone();
        let started = std::time::Instant::now();
        let worker = std::thread::spawn(move || {
            export::pump(
                &directory,
                &mut input,
                &mut output,
                Duration::from_millis(100),
            )
        });
        assert_eq!(receive(&mut peer)?, snapshot);
        worker.join().unwrap()?;
        assert!(started.elapsed() >= Duration::from_millis(100));
        assert_eq!(peer.read(&mut [0])?, 0);
    }
    Ok(())
}

/// Idle streams do no file reads; atomic replacement wakes them and watch loss closes them.
#[test]
fn exporter_waits_for_changes_without_periodic_snapshot_reads() -> Result<()> {
    use rustix::fs::inotify;
    let root = tempfile::tempdir()?;
    let publisher = feed::Publisher::new(root.path())?;
    publisher.publish(&Snapshot::default())?;
    let directory = root.path().join("feed");
    let (mut peer, worker) = subscriber(&directory)?;
    receive(&mut peer)?;
    let accesses = inotify::init(inotify::CreateFlags::NONBLOCK | inotify::CreateFlags::CLOEXEC)?;
    inotify::add_watch(
        &accesses,
        directory.join("snapshot"),
        inotify::WatchFlags::ACCESS,
    )?;
    std::thread::sleep(Duration::from_millis(350));
    let mut buffer = [std::mem::MaybeUninit::uninit(); 512];
    let mut events = inotify::Reader::new(&accesses, &mut buffer);
    assert!(matches!(events.next(), Err(rustix::io::Errno::WOULDBLOCK)));
    let changed = Snapshot {
        high_contrast: Setting::Supported(true),
        ..Snapshot::default()
    };
    publisher.publish(&changed)?;
    assert_eq!(receive(&mut peer)?, changed);
    fs::rename(&directory, root.path().join("moved-feed"))?;
    assert!(
        worker
            .join()
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("watch lost")
    );
    Ok(())
}

/// A full output pipe times out independently; unsolicited input cannot mutate the feed.
#[test]
fn slow_and_writing_guests_do_not_affect_other_subscribers() -> Result<()> {
    let root = tempfile::tempdir()?;
    let publisher = feed::Publisher::new(root.path())?;
    publisher.publish(&Snapshot::default())?;
    let directory = root.path().join("feed");
    let original = feed::read(&directory)?;
    let (slow_peer, mut slow_output) = UnixStream::pair()?;
    slow_output.set_nonblocking(true)?;
    while slow_output.write(&[0; 4096]).is_ok() {}
    let mut slow_input = slow_output.try_clone()?;
    let slow_directory = directory.clone();
    let slow = std::thread::spawn(move || {
        export::pump(
            &slow_directory,
            &mut slow_input,
            &mut slow_output,
            Duration::from_secs(4),
        )
    });
    let (mut attacker, rejected) = subscriber(&directory)?;
    attacker.write_all(b"set org.gnome.desktop.interface color-scheme prefer-light")?;
    assert!(rejected.join().unwrap().is_err());
    assert_eq!(feed::read(&directory)?, original);
    let (mut fast, active) = subscriber(&directory)?;
    assert_eq!(receive(&mut fast)?, Snapshot::default());
    let changed = Snapshot {
        high_contrast: Setting::Supported(true),
        ..Snapshot::default()
    };
    publisher.publish(&changed)?;
    assert_eq!(receive(&mut fast)?, changed);
    assert!(
        slow.join()
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("not reading")
    );
    drop((fast, slow_peer));
    assert!(active.join().unwrap().is_err());
    Ok(())
}

/// Compile disposable schemas using an explicitly prepared GLib development tool.
fn schemas() -> Result<(tempfile::TempDir, gio::SettingsSchemaSource)> {
    let directory = tempfile::tempdir()?;
    fs::write(
        directory.path().join("preferences.gschema.xml"),
        r#"
        <schemalist>
          <schema id="org.gnome.desktop.interface" path="/org/gnome/desktop/interface/">
            <key name="color-scheme" type="s"><default>'default'</default></key>
            <key name="font-name" type="s"><default>'Fixture Sans 11'</default></key>
            <key name="document-font-name" type="s"><default>'Fixture Sans 12'</default></key>
            <key name="monospace-font-name" type="s"><default>'Fixture Mono 11'</default></key>
            <key name="text-scaling-factor" type="d"><default>1.0</default></key>
            <key name="cursor-theme" type="s"><default>'Adwaita'</default></key>
            <key name="cursor-size" type="i"><default>24</default></key>
            <key name="enable-animations" type="b"><default>true</default></key>
            <key name="private-value" type="s"><default>'never export this'</default></key>
          </schema>
          <schema id="org.gnome.desktop.a11y.interface" path="/org/gnome/desktop/a11y/interface/">
            <key name="high-contrast" type="b"><default>false</default></key>
            <key name="reduced-motion" type="s"><default>'no-preference'</default></key>
          </schema>
        </schemalist>
    "#,
    )?;
    let compiler =
        std::env::var_os("GLIB_COMPILE_SCHEMAS").expect("prepare GLIB_COMPILE_SCHEMAS explicitly");
    assert!(
        std::process::Command::new(compiler)
            .arg(directory.path())
            .status()?
            .success()
    );
    let schemas = gio::SettingsSchemaSource::from_directory(directory.path(), None, false)?;
    Ok((directory, schemas))
}

/// Exercise actual GSettings notifications, effective resets and the fixed allowlist.
#[test]
#[ignore = "requires explicitly prepared GLIB_COMPILE_SCHEMAS"]
fn gsettings_changes_resets_and_initial_subscription() -> Result<()> {
    use gio::prelude::*;
    let (_directory, schemas) = schemas()?;
    let context = gio::glib::MainContext::new();
    context.with_thread_default(|| -> Result<()> {
        let backend = gio::memory_settings_backend_new();
        let source = source::Source::new(Some(&schemas), Some(&backend));
        let interface = gio::Settings::new_full(
            &schemas
                .lookup("org.gnome.desktop.interface", false)
                .unwrap(),
            Some(&backend),
            None,
        );
        let accessibility = gio::Settings::new_full(
            &schemas
                .lookup("org.gnome.desktop.a11y.interface", false)
                .unwrap(),
            Some(&backend),
            None,
        );
        // A change before initial capture is reflected in the initial complete state.
        interface.set_string("color-scheme", "prefer-dark")?;
        source.dirty.set(false);
        let initial = source.snapshot()?;
        assert_eq!(
            initial.color_scheme,
            Setting::Supported(ColorScheme::PreferDark)
        );
        interface.set_string("private-value", "private update")?;
        while context.pending() {
            context.iteration(false);
        }
        assert!(!source.dirty.get());
        interface.set_double("text-scaling-factor", 1.5)?;
        interface.set_string("font-name", "Changed Sans 14")?;
        accessibility.set_string("reduced-motion", "reduce")?;
        while context.pending() {
            context.iteration(false);
        }
        assert!(source.dirty.replace(false));
        let changed = source.snapshot()?;
        assert_ne!(changed, initial);
        assert_eq!(
            changed.reduced_motion,
            Setting::Supported(airlock_desktop_preferences::ReducedMotion::Reduce)
        );
        interface.reset("color-scheme");
        interface.reset("font-name");
        while context.pending() {
            context.iteration(false);
        }
        assert!(source.dirty.get());
        assert_eq!(
            source.snapshot()?.color_scheme,
            Setting::Supported(ColorScheme::NoPreference)
        );
        assert_eq!(source.snapshot()?.interface_font, initial.interface_font);
        interface.set_double("text-scaling-factor", f64::INFINITY)?;
        assert!(source.snapshot().is_err());
        assert_eq!(
            source::Source::new(None, None).snapshot()?,
            Snapshot::default()
        );
        Ok(())
    })??;
    Ok(())
}

/// Run inside the exact production sandbox and assert actual credentials/access, not argument text.
#[test]
#[ignore = "child of namespace_exporter_is_read_only_and_disconnected_from_the_session"]
fn sandbox_access_probe() -> Result<()> {
    assert_eq!(rustix::process::geteuid().as_raw(), 65534);
    let status = fs::read_to_string("/proc/self/status")?;
    assert!(
        status
            .lines()
            .any(|line| line == "CapEff:\t0000000000000000")
    );
    assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
    assert!(feed::read(Path::new("/feed")).is_ok());
    assert!(fs::write("/feed/snapshot", b"bad").is_err());
    assert!(fs::remove_file("/feed/snapshot").is_err());
    assert!(fs::write("/feed/new", b"bad").is_err());
    assert!(!Path::new("/home").exists());
    assert!(!Path::new("/run").exists());
    assert!(std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none());
    assert!(gio::bus_get_sync(gio::BusType::Session, gio::Cancellable::NONE).is_err());
    // Even knowing the real host bus address cannot bypass the mount boundary.
    let host_bus = std::env::var("PROBE_HOST_BUS")?;
    assert!(
        gio::DBusConnection::for_address_sync(
            &host_bus,
            gio::DBusConnectionFlags::AUTHENTICATION_CLIENT
                | gio::DBusConnectionFlags::MESSAGE_BUS_CONNECTION,
            None,
            gio::Cancellable::NONE
        )
        .is_err()
    );
    use std::os::linux::net::SocketAddrExt;
    let socket =
        std::os::unix::net::SocketAddr::from_abstract_name(b"airlock-preferences-sandbox-test")?;
    assert!(UnixStream::connect_addr(&socket).is_err());
    let publisher_pid = std::env::var("PROBE_HOST_PID")?;
    assert!(!Path::new(&format!("/proc/{publisher_pid}")).exists());
    Ok(())
}

/// A real bubblewrap namespace cannot modify the feed or reach path/abstract session sockets.
#[test]
#[ignore = "requires explicitly prepared AIRLOCK_PREFERENCES_BWRAP, DBUS_DAEMON and user namespaces"]
fn namespace_exporter_is_read_only_and_disconnected_from_the_session() -> Result<()> {
    use std::os::linux::net::SocketAddrExt;
    let root = tempfile::tempdir()?;
    let publisher = feed::Publisher::new(root.path())?;
    publisher.publish(&Snapshot::default())?;
    let directory = root.path().join("feed");
    let before = feed::read(&directory)?;
    let address =
        std::os::unix::net::SocketAddr::from_abstract_name(b"airlock-preferences-sandbox-test")?;
    let _listener = std::os::unix::net::UnixListener::bind_addr(&address)?;
    // This is a disposable real session bus, never the user's live desktop bus.
    let host_bus = format!("unix:path={path}", path = root.path().join("bus").display());
    let daemon = std::env::var_os("DBUS_DAEMON").expect("prepare DBUS_DAEMON explicitly");
    let mut bus = Bus(std::process::Command::new(daemon)
        .args([
            "--session",
            "--nofork",
            "--print-address=1",
            "--address",
            &host_bus,
        ])
        .stdout(std::process::Stdio::piped())
        .spawn()?);
    let mut ready = String::new();
    use std::io::BufRead;
    std::io::BufReader::new(bus.0.stdout.take().unwrap()).read_line(&mut ready)?;
    let _connection = gio::DBusConnection::for_address_sync(
        &host_bus,
        gio::DBusConnectionFlags::AUTHENTICATION_CLIENT
            | gio::DBusConnectionFlags::MESSAGE_BUS_CONNECTION,
        None,
        gio::Cancellable::NONE,
    )?;
    let bwrap = std::env::var_os("AIRLOCK_PREFERENCES_BWRAP")
        .expect("prepare AIRLOCK_PREFERENCES_BWRAP explicitly");
    let mut command = sandbox::command(Path::new(&bwrap), &std::env::current_exe()?, &directory);
    command.args([
        "--setenv",
        "PROBE_HOST_PID",
        &std::process::id().to_string(),
        "--setenv",
        "PROBE_HOST_BUS",
        &host_bus,
        "--",
        "/exporter",
        "--exact",
        "preferences::tests::sandbox_access_probe",
        "--ignored",
        "--nocapture",
    ]);
    let result = command.output()?;
    assert!(
        result.status.success(),
        "{stdout}\n{stderr}",
        stdout = String::from_utf8_lossy(&result.stdout),
        stderr = String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(feed::read(&directory)?, before);
    Ok(())
}

/// Reap the private D-Bus process even when an isolation assertion fails.
struct Bus(
    /// Disposable daemon whose only address is inside the temporary fixture.
    std::process::Child,
);

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
