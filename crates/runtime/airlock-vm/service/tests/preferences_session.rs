//! Exercise a real guest agent, dconf, XSettings and the Settings portal on a disposable display.
//! Explicitly prepared native tools and a guarded child keep these tests away from the live desktop.

#![cfg(feature = "desktop-preferences")]

use airlock_desktop_preferences::{
    ColorScheme, FontName, HEADER_LEN, MAX_FRAME_LEN, Setting, Snapshot, encode_frame,
};
use anyhow::{Context, Result, ensure};
use gio::{glib, prelude::*};
use std::cell::Cell;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::{fs::PermissionsExt, process::CommandExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::rc::Rc;
use std::time::{Duration, Instant};
use x11rb::{
    connection::Connection,
    protocol::xproto::{AtomEnum, ConnectionExt, CreateWindowAux, PropMode, WindowClass},
    wrapper::ConnectionExt as _,
};

/// A process group owned solely by this scenario, including daemon subprocesses.
struct Process {
    /// Unreaped leader retains its group identity until cleanup.
    child: Child,
    /// Prevent cleanup from signalling a process identity that has already been reaped.
    reaped: bool,
}

impl Process {
    /// Start a separate group so abrupt agent failure models systemd control-group cleanup.
    fn start(command: &mut Command) -> Result<Self> {
        Ok(Self {
            child: command.process_group(0).spawn()?,
            reaped: false,
        })
    }

    /// Stop the agent normally, allowing its baseline restoration to complete.
    fn stop(&mut self) -> Result<()> {
        rustix::process::kill_process(
            rustix::process::Pid::from_child(&self.child),
            rustix::process::Signal::TERM,
        )?;
        wait("graceful agent stop", || {
            self.reaped = self.child.try_wait()?.is_some();
            Ok(self.reaped)
        })
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        let _ = rustix::process::kill_process_group(
            rustix::process::Pid::from_child(&self.child),
            rustix::process::Signal::KILL,
        );
        let _ = self.child.wait();
    }
}

/// Pump local GIO callbacks while waiting for observable desktop behavior, with a finite deadline.
fn wait(label: &str, mut predicate: impl FnMut() -> Result<bool>) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        let context = glib::MainContext::default();
        while context.pending() {
            context.iteration(false);
        }
        if predicate()? {
            return Ok(());
        }
        ensure!(Instant::now() < deadline, "timed out: {label}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Require native tools to be prepared explicitly; tests never provision packages.
fn tool(name: &str) -> Result<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .with_context(|| format!("prepare {name} explicitly"))
}

/// Atomically publish complete records, matching the real feed and machine configuration behavior.
fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
    file.write_all(bytes)?;
    file.persist(path)?;
    Ok(())
}

/// Start a private bus without host service activation directories.
fn private_bus(root: &Path) -> Result<(Process, String)> {
    let address = format!("unix:path={path}/bus", path = root.display());
    let config = root.join("bus.conf");
    fs::write(
        &config,
        format!(
            r#"<busconfig>
      <type>session</type><listen>{address}</listen>
      <policy context="default"><allow send_destination="*"/><allow receive_sender="*"/><allow own="*"/></policy>
    </busconfig>"#
        ),
    )?;
    let mut bus = Process::start(
        Command::new("dbus-daemon")
            .args(["--nofork", "--print-address=1", "--config-file"])
            .arg(config)
            .stdout(Stdio::piped()),
    )?;
    let mut actual = String::new();
    BufReader::new(bus.child.stdout.take().unwrap()).read_line(&mut actual)?;
    ensure!(!actual.is_empty(), "private bus did not start");
    Ok((bus, actual.trim().to_owned()))
}

/// Launch disposable desktop services and a bounded child test with no live session environment.
#[test]
#[ignore = "requires prepared desktop shell, preferences_peer, publisher executable and bubblewrap"]
fn isolated_preferences_session() -> Result<()> {
    let root = tempfile::tempdir()?;
    for directory in [
        "runtime", "home", "config", "state", "cache", "data", "feed",
    ] {
        fs::create_dir(root.path().join(directory))?;
        fs::set_permissions(
            root.path().join(directory),
            fs::Permissions::from_mode(0o700),
        )?;
    }
    let mut display = Process::start(
        Command::new("Xvfb")
            .args([
                "-displayfd",
                "1",
                "-screen",
                "0",
                "800x600x24",
                "-nolisten",
                "tcp",
            ])
            .stdout(Stdio::piped()),
    )?;
    let mut screen = String::new();
    BufReader::new(display.child.stdout.take().unwrap()).read_line(&mut screen)?;
    let (_bus, actual) = private_bus(root.path())?;
    ensure!(!screen.is_empty(), "private display did not start");
    let profile = root.path().join("dconf-profile");
    fs::write(&profile, "user-db:user\n")?;
    let fonts = tool("AIRLOCK_TEST_FONTS")?;
    let fontconfig = root.path().join("fonts.conf");
    fs::write(
        &fontconfig,
        format!(
            r#"<?xml version="1.0"?>
        <!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd">
        <fontconfig><dir>{fonts}/share/fonts</dir><cachedir>{cache}</cachedir></fontconfig>
        "#,
            fonts = fonts.display(),
            cache = root.path().join("font-cache").display()
        ),
    )?;
    for family in ["Adwaita Sans", "Adwaita Mono"] {
        let output = Command::new("fc-match")
            .args(["--format=%{file}", family])
            .env("FONTCONFIG_FILE", &fontconfig)
            .output()?;
        ensure!(output.status.success(), "font lookup failed");
        let matched = PathBuf::from(String::from_utf8(output.stdout)?);
        ensure!(
            matched.starts_with(&fonts) && matched.is_file(),
            "baseline font unavailable: {family}"
        );
    }
    let icons = tool("AIRLOCK_TEST_ICONS")?.join("share");
    ensure!(
        icons.join("icons/Adwaita/cursors/left_ptr").is_file(),
        "baseline cursor unavailable"
    );
    let peer = tool("AIRLOCK_TEST_PREFERENCES_PEER")?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--exact", "session_probe", "--ignored", "--nocapture"])
        .env("AIRLOCK_TEST_SESSION_ROOT", root.path())
        .env("DISPLAY", format!(":{screen}", screen = screen.trim()))
        .env("DBUS_SESSION_BUS_ADDRESS", actual.trim())
        .env("HOME", root.path().join("home"))
        .env("XDG_RUNTIME_DIR", root.path().join("runtime"))
        .env("XDG_CONFIG_HOME", root.path().join("config"))
        .env("XDG_STATE_HOME", root.path().join("state"))
        .env("XDG_CACHE_HOME", root.path().join("cache"))
        .env("XDG_DATA_HOME", root.path().join("data"))
        .env("XDG_DATA_DIRS", icons)
        .env("FONTCONFIG_FILE", fontconfig)
        .env("XDG_CURRENT_DESKTOP", "GNOME")
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("GTK_THEME")
        .env(
            "GSETTINGS_SCHEMA_DIR",
            tool("AIRLOCK_TEST_GSETTINGS_SCHEMAS")?,
        )
        .env("GIO_EXTRA_MODULES", tool("AIRLOCK_TEST_DCONF_MODULES")?)
        .env("GSETTINGS_BACKEND", "dconf")
        .env("DCONF_PROFILE", profile)
        .env("AIRLOCK_XSETTINGSD", tool("AIRLOCK_TEST_XSETTINGSD")?)
        .env("AIRLOCK_QREXEC_CLIENT", peer)
        .env("AIRLOCK_TEST_PREFERENCES_FEED", root.path().join("feed"));
    let output = airlock_vm_service::support::run(&mut command, None, Duration::from_secs(150))?;
    eprintln!("{}", String::from_utf8_lossy(&output.stdout));
    output.checked()?;
    Ok(())
}

/// Read the actual standard Settings portal interface, rather than inferring it from dconf writes.
fn portal(bus: &gio::DBusConnection, namespace: &str, key: &str) -> Result<glib::Variant> {
    let result = bus.call_sync(
        Some("org.freedesktop.portal.Desktop"),
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.Settings",
        "ReadOne",
        Some(&(namespace, key).to_variant()),
        None,
        gio::DBusCallFlags::NO_AUTO_START,
        1000,
        gio::Cancellable::NONE,
    )?;
    result.child_value(0).as_variant().context("portal value")
}

/// Publish machine-owned association changes; wire payloads cannot select these values.
fn configure(root: &Path, source: &str, enabled: bool) -> Result<()> {
    replace(
        &root.join("binding.json"),
        &serde_json::to_vec(
            &serde_json::json!({"enabled":enabled,"gui_domain":source,"window_scale":2}),
        )?,
    )
}

/// Serve one complete pushed snapshot through the inert qrexec boundary.
fn publish(root: &Path, source: &str, snapshot: &Snapshot) -> Result<()> {
    replace(
        &root.join("feed").join(format!("{source}.frame")),
        &encode_frame(snapshot)?,
    )
}

/// Observe the agent's explicit outcome without treating a partially applied snapshot as success.
fn status(root: &Path) -> serde_json::Value {
    fs::read(root.join("runtime/airlock-desktop-preferences/status.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(serde_json::Value::Null)
}

/// Start the ordinary-user production command against this test's deployment binding.
fn agent(root: &Path) -> Result<Process> {
    Process::start(
        Command::new(env!("CARGO_BIN_EXE_airlock-vm-service"))
            .args(["preferences", "--config"])
            .arg(root.join("binding.json"))
            .arg("run")
            .env("NOTIFY_SOCKET", root.join("notify.sock")),
    )
}

/// Give the source its own bus, runtime and database, including dconf's invalidation files.
fn source_command(root: &Path, executable: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(executable);
    command
        .env("DCONF_PROFILE", root.join("publisher-profile"))
        .env("XDG_RUNTIME_DIR", root.join("publisher-runtime"))
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!(
                "unix:path={path}/bus",
                path = root.join("publisher-runtime").display()
            ),
        );
    command
}

/// Invoke GSettings against the source database, independent of guest convergence.
fn source_setting(root: &Path, arguments: &[&str]) -> Result<String> {
    let output = airlock_vm_service::support::run(
        source_command(root, "gsettings").args(arguments),
        None,
        Duration::from_secs(5),
    )?
    .checked()?;
    Ok(String::from_utf8(output)?.trim().to_owned())
}

/// Start the actual GNOME publisher with fixture-owned settings and runtime directories.
fn publisher(root: &Path) -> Result<Process> {
    Process::start(
        source_command(root, tool("AIRLOCK_TEST_PREFERENCES_PUBLISHER")?)
            .args(["preferences", "publish"]),
    )
}

/// Keep representative Qubes identity properties on a window across appearance updates.
/// This checks property integrity; recognizable host decorations require live acceptance.
fn security_marker() -> Result<impl Fn() -> Result<()>> {
    let (connection, screen) = x11rb::connect(None)?;
    let window = connection.generate_id()?;
    connection
        .create_window(
            x11rb::COPY_DEPTH_FROM_PARENT,
            window,
            connection.setup().roots[screen].root,
            0,
            0,
            100,
            100,
            0,
            WindowClass::INPUT_OUTPUT,
            0,
            &CreateWindowAux::new(),
        )?
        .check()?;
    let name = connection
        .intern_atom(false, b"_QUBES_VMNAME")?
        .reply()?
        .atom;
    let label = connection
        .intern_atom(false, b"_QUBES_LABEL")?
        .reply()?
        .atom;
    let color = connection
        .intern_atom(false, b"_QUBES_LABEL_COLOR")?
        .reply()?
        .atom;
    connection
        .change_property8(
            PropMode::REPLACE,
            window,
            name,
            AtomEnum::STRING,
            b"usr-fixture",
        )?
        .check()?;
    connection
        .change_property8(PropMode::REPLACE, window, label, AtomEnum::CARDINAL, &[1])?
        .check()?;
    connection
        .change_property32(
            PropMode::REPLACE,
            window,
            color,
            AtomEnum::CARDINAL,
            &[0xff0000],
        )?
        .check()?;
    Ok(move || {
        assert_eq!(
            connection
                .get_property(false, window, name, AtomEnum::STRING, 0, 32)?
                .reply()?
                .value,
            b"usr-fixture"
        );
        assert_eq!(
            connection
                .get_property(false, window, label, AtomEnum::CARDINAL, 0, 1)?
                .reply()?
                .value,
            [1]
        );
        assert_eq!(
            connection
                .get_property(false, window, color, AtomEnum::CARDINAL, 0, 1)?
                .reply()?
                .value32()
                .unwrap()
                .next(),
            Some(0xff0000)
        );
        Ok(())
    })
}

/// Join production publisher, sandbox and guest adapters; only qrexec establishment is substituted.
fn production_subscription(
    root: &Path,
    view: &gio::Settings,
    bus: &gio::DBusConnection,
    check_markings: &impl Fn() -> Result<()>,
) -> Result<()> {
    fs::write(root.join("publisher-profile"), "user-db:publisher\n")?;
    fs::create_dir(root.join("publisher-runtime"))?;
    fs::set_permissions(
        root.join("publisher-runtime"),
        fs::Permissions::from_mode(0o700),
    )?;
    let (_source_bus, address) = private_bus(&root.join("publisher-runtime"))?;
    let _source_dconf = Process::start(&mut source_command(
        root,
        tool("AIRLOCK_TEST_DCONF_SERVICE")?,
    ))?;
    let connection = gio::DBusConnection::for_address_sync(
        &address,
        gio::DBusConnectionFlags::AUTHENTICATION_CLIENT
            | gio::DBusConnectionFlags::MESSAGE_BUS_CONNECTION,
        None,
        gio::Cancellable::NONE,
    )?;
    wait("source dconf writer", || {
        let reply = connection.call_sync(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "NameHasOwner",
            Some(&("ca.desrt.dconf",).to_variant()),
            None,
            gio::DBusCallFlags::NONE,
            1000,
            gio::Cancellable::NONE,
        )?;
        Ok(reply.get::<(bool,)>() == Some((true,)))
    })?;
    let interface = "org.gnome.desktop.interface";
    let accessibility = "org.gnome.desktop.a11y.interface";
    source_setting(root, &["set", interface, "font-name", "Adwaita Sans 17"])?;
    source_setting(root, &["set", interface, "color-scheme", "prefer-dark"])?;
    source_setting(root, &["set", interface, "clock-show-seconds", "false"])?;
    let mut source = publisher(root)?;
    configure(root, "sys-gui", true)?;
    let start_guest = || -> Result<Process> {
        Process::start(
            Command::new(env!("CARGO_BIN_EXE_airlock-vm-service"))
                .args(["preferences", "--config"])
                .arg(root.join("binding.json"))
                .arg("run")
                .env(
                    "AIRLOCK_TEST_EXPORTER_RUNTIME",
                    root.join("publisher-runtime"),
                ),
        )
    };
    let mut guest = start_guest()?;
    wait("production initial snapshot", || {
        Ok(view.string("font-name") == "Adwaita Sans 17"
            && portal(bus, "org.freedesktop.appearance", "color-scheme")?.get::<u32>() == Some(1)
            && !status(root)["applied"].is_null())
    })?;
    check_markings()?;
    source_setting(root, &["set", interface, "text-scaling-factor", "1.5"])?;
    source_setting(root, &["set", accessibility, "high-contrast", "true"])?;
    wait("production accessibility notification", || {
        Ok(view.double("text-scaling-factor") == 1.5
            && portal(bus, "org.freedesktop.appearance", "contrast")?.get::<u32>() == Some(1)
            && status(root)["applied"]["high_contrast"]["supported"] == true)
    }).with_context(|| format!("source scale={scale}, contrast={contrast}; guest scale={guest_scale}, portal={portal:?}, status={status}",
        scale = source_setting(root, &["get", interface, "text-scaling-factor"]).unwrap_or_default(),
        contrast = source_setting(root, &["get", accessibility, "high-contrast"]).unwrap_or_default(),
        guest_scale = view.double("text-scaling-factor"),
        portal = portal(bus, "org.freedesktop.appearance", "contrast"),
        status = status(root)))?;
    check_markings()?;
    // Native convergence checks the actual XSettings property, including separate
    // text/window scale. User styles and unrelated dconf settings remain local.
    assert!(view.boolean("clock-show-seconds"));
    assert_eq!(
        source_setting(root, &["get", interface, "clock-show-seconds"])?,
        "false"
    );
    view.set_string("font-name", "Sans 29")?;
    wait("production drift repair", || {
        Ok(view.string("font-name") == "Adwaita Sans 17")
    })?;
    assert_eq!(
        source_setting(root, &["get", interface, "font-name"])?,
        "'Adwaita Sans 17'"
    );

    // A killed publisher stops refreshing its feed. The surviving agent retains
    // valid state, observes expiration, and recovers from a fresh source process.
    source.stop()?;
    wait("publisher expiration", || {
        Ok(!status(root)["error"].is_null())
    })?;
    assert_eq!(view.string("font-name"), "Adwaita Sans 17");
    source_setting(root, &["set", interface, "font-name", "Adwaita Sans 19"])?;
    source = publisher(root)?;
    wait("publisher restart", || {
        Ok(view.string("font-name") == "Adwaita Sans 19" && status(root)["error"].is_null())
    })?;

    guest.stop()?;
    assert_eq!(view.string("font-name"), "Sans 31");
    source_setting(root, &["set", interface, "color-scheme", "prefer-light"])?;
    source_setting(root, &["set", accessibility, "high-contrast", "false"])?;
    guest = start_guest()?;
    wait("late guest receives changes made offline", || {
        Ok(view.string("font-name") == "Adwaita Sans 19"
            && portal(bus, "org.freedesktop.appearance", "color-scheme")?.get::<u32>() == Some(2)
            && portal(bus, "org.freedesktop.appearance", "contrast")?.get::<u32>() == Some(0)
            && !status(root)["applied"].is_null())
    })?;
    check_markings()?;
    source_setting(root, &["reset", interface, "font-name"])?;
    let default_font = glib::Variant::parse(
        None,
        &source_setting(root, &["get", interface, "font-name"])?,
    )?
    .get::<String>()
    .context("source default font")?;
    wait("source reset sends effective default", || {
        Ok(view.string("font-name") == default_font)
    })?;
    configure(root, "sys-gui", false)?;
    wait("production subscription revoked", || {
        Ok(status(root)["phase"] == "disabled" && view.string("font-name") == "Sans 31")
    })?;
    source_setting(root, &["set", interface, "font-name", "Adwaita Sans 23"])?;
    guest.stop()?;
    source.stop()?;
    assert_eq!(view.string("font-name"), "Sans 31");
    assert!(view.boolean("clock-show-seconds"));
    Ok(())
}

/// Isolated child scenario: notification updates, portal signals, failures, reassignment and restoration.
#[test]
#[ignore = "child of isolated_preferences_session; never run against a live desktop"]
fn session_probe() -> Result<()> {
    let root = tool("AIRLOCK_TEST_SESSION_ROOT")?;
    ensure!(
        std::env::var("DBUS_SESSION_BUS_ADDRESS")?.contains(root.to_str().unwrap()),
        "test requires its private session bus"
    );
    let check_markings = security_marker()?;
    let stylesheet = root.join("config/gtk-4.0/gtk.css");
    fs::create_dir_all(stylesheet.parent().unwrap())?;
    let local_style = br#"/* local Qubes compatibility styles */
popover { box-shadow: none; }
"#;
    fs::write(&stylesheet, local_style)?;
    let notifications = std::os::unix::net::UnixDatagram::bind(root.join("notify.sock"))?;
    notifications.set_nonblocking(true)?;
    let _dconf = Process::start(&mut Command::new(tool("AIRLOCK_TEST_DCONF_SERVICE")?))?;
    let gtk = tool("AIRLOCK_TEST_GTK_PORTAL")?;
    let portals = root.join("data/xdg-desktop-portal/portals");
    fs::create_dir_all(&portals)?;
    fs::copy(
        gtk.parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("share/xdg-desktop-portal/portals/gtk.portal"),
        portals.join("gtk.portal"),
    )?;
    fs::create_dir_all(root.join("config/xdg-desktop-portal"))?;
    fs::write(
        root.join("config/xdg-desktop-portal/portals.conf"),
        "[preferred]\ndefault=gtk\norg.freedesktop.impl.portal.Settings=gtk\n",
    )?;
    let _gtk = Process::start(&mut Command::new(gtk))?;
    let bus = gio::bus_get_sync(gio::BusType::Session, gio::Cancellable::NONE)?;
    wait("GTK portal backend", || {
        let reply = bus.call_sync(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "NameHasOwner",
            Some(&("org.freedesktop.impl.portal.desktop.gtk",).to_variant()),
            None,
            gio::DBusCallFlags::NONE,
            1000,
            gio::Cancellable::NONE,
        )?;
        Ok(reply.get::<(bool,)>() == Some((true,)))
    })?;
    let _portal = Process::start(&mut Command::new(tool("AIRLOCK_TEST_PORTAL")?))?;
    let view = gio::Settings::new("org.gnome.desktop.interface");
    view.set_string("font-name", "Sans 13")?;
    view.set_string("document-font-name", "Serif 14")?;
    view.set_boolean("clock-show-seconds", true)?;
    gio::Settings::sync();
    wait("portal startup", || {
        Ok(portal(&bus, "org.freedesktop.appearance", "color-scheme").is_ok())
    })?;
    let signals = Rc::new(Cell::new(0));
    let count = signals.clone();
    let subscription = bus.subscribe_to_signal(
        Some("org.freedesktop.portal.Desktop"),
        Some("org.freedesktop.portal.Settings"),
        Some("SettingChanged"),
        Some("/org/freedesktop/portal/desktop"),
        Some("org.freedesktop.appearance"),
        gio::DBusSignalFlags::NONE,
        move |_| count.set(count.get() + 1),
    );
    let dark = Snapshot {
        color_scheme: Setting::Supported(ColorScheme::PreferDark),
        interface_font: Setting::Supported(FontName::new("Sans 14")?),
        enable_animations: Setting::Supported(false),
        ..Snapshot::default()
    };
    configure(&root, "sys-gui", true)?;
    publish(&root, "sys-gui", &dark)?;
    let competing_config = root.join("competing.conf");
    fs::write(&competing_config, "Gtk/FontName \"Sans 9\"\n")?;
    let mut competitor = Process::start(
        Command::new(tool("AIRLOCK_TEST_XSETTINGSD")?)
            .arg("-c")
            .arg(competing_config),
    )?;
    std::thread::sleep(Duration::from_millis(200));
    let mut running = agent(&root)?;
    wait("refuse existing XSettings owner", || {
        Ok(status(&root)["error"]
            .as_str()
            .is_some_and(|error| error.contains("another XSettings provider")))
    })?;
    assert!(status(&root)["applied"].is_null());
    // A competing owner must not stall the graphical target indefinitely.
    // Readiness reports the bounded fallback, then convergence can recover live.
    let mut notification = [0; 64];
    wait("systemd readiness notification", || {
        match notifications.recv(&mut notification) {
            Ok(length) => {
                assert_eq!(&notification[..length], b"READY=1");
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(error.into()),
        }
    })
    .with_context(|| format!("readiness status: {status}", status = status(&root)))?;
    assert!(status(&root)["ready"].as_bool().unwrap());
    assert!(status(&root)["applied"].is_null());
    competitor.stop()?;
    wait("partial failure recovery", || {
        Ok(!status(&root)["applied"].is_null())
    })?;
    wait("dconf font update", || {
        Ok(view.string("font-name") == "Sans 14")
    })?;
    wait("portal appearance and notification", || {
        Ok(
            portal(&bus, "org.freedesktop.appearance", "color-scheme")?.get::<u32>() == Some(1)
                && signals.get() > 0,
        )
    })?;
    wait("portal font update", || {
        Ok(portal(&bus, "org.gnome.desktop.interface", "font-name")?
            .get::<String>()
            .as_deref()
            == Some("Sans 14"))
    })?;
    wait("portal animation update", || {
        Ok(
            portal(&bus, "org.gnome.desktop.interface", "enable-animations")?.get::<bool>()
                == Some(false),
        )
    })?;
    let calls = fs::read(root.join("feed/calls"))?;
    view.set_string("font-name", "Sans 29")?;
    wait("repair local managed drift", || {
        Ok(view.string("font-name") == "Sans 14")
    })?;
    assert_eq!(calls, fs::read(root.join("feed/calls"))?);
    assert!(view.boolean("clock-show-seconds"));
    let before = signals.get();
    let light = Snapshot {
        color_scheme: Setting::Supported(ColorScheme::PreferLight),
        ..dark.clone()
    };
    publish(&root, "sys-gui", &light)?;
    wait("running portal light update", || {
        Ok(
            portal(&bus, "org.freedesktop.appearance", "color-scheme")?.get::<u32>() == Some(2)
                && signals.get() > before,
        )
    })?;
    publish(&root, "sys-gui", &Snapshot::default())?;
    wait("reset restores baseline", || {
        Ok(view.string("font-name") == "Sans 13")
    })?;
    view.set_string("document-font-name", "Serif 21")?;
    publish(&root, "sys-gui", &dark)?;
    wait("second supported value", || {
        Ok(view.string("font-name") == "Sans 14")
    })?;
    let mut version = encode_frame(&dark)?;
    version[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
    let mut oversized = version[..HEADER_LEN].to_vec();
    oversized[4..6].copy_from_slice(&1_u16.to_be_bytes());
    oversized[6..8].copy_from_slice(&(MAX_FRAME_LEN as u16).to_be_bytes());
    let mut invalid = serde_json::to_value(&dark)?;
    invalid["text_scale"] = serde_json::json!({"supported": 99.0});
    let payload = serde_json::to_vec(&invalid)?;
    let mut invalid = encode_frame(&dark)?[..HEADER_LEN].to_vec();
    invalid[6..8].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    invalid.extend(payload);
    for rejected in [b"malformed snapshot".to_vec(), version, oversized, invalid] {
        replace(&root.join("feed/sys-gui.frame"), &rejected)?;
        wait("invalid update rejected", || {
            Ok(!status(&root)["error"].is_null())
        })?;
        assert_eq!(view.string("font-name"), "Sans 14");
        publish(&root, "sys-gui", &light)?;
        wait("full snapshot after reconnect", || {
            Ok(status(&root)["error"].is_null()
                && portal(&bus, "org.freedesktop.appearance", "color-scheme")?.get::<u32>()
                    == Some(2))
        })?;
    }
    fs::write(root.join("feed/offline"), b"")?;
    wait("interrupted stream retained", || {
        Ok(!status(&root)["error"].is_null())
    })?;
    assert_eq!(view.string("font-name"), "Sans 14");
    configure(&root, "sys-gui-other", true)?;
    wait("reassignment revokes prior source", || {
        Ok(view.string("font-name") == "Sans 13" && status(&root)["desired"].is_null())
    })?;
    fs::remove_file(root.join("feed/offline"))?;
    let other = Snapshot {
        interface_font: Setting::Supported(FontName::new("Monospace 15")?),
        ..Snapshot::default()
    };
    publish(&root, "sys-gui-other", &other)?;
    wait("new association", || {
        Ok(view.string("font-name") == "Monospace 15" && !status(&root)["applied"].is_null())
    })?;
    assert_eq!(view.string("document-font-name"), "Serif 21");
    // A damaged recovery record must revoke remote authority immediately and
    // retain the error until the local record is repaired, then retry restoration.
    let journal = root.join("state/airlock-desktop-preferences/baseline.json");
    rustix::process::kill_process(
        rustix::process::Pid::from_child(&running.child),
        rustix::process::Signal::STOP,
    )?;
    let baseline = fs::read(&journal)?;
    fs::remove_file(&journal)?;
    fs::create_dir(&journal)?;
    configure(&root, "sys-gui-other", false)?;
    rustix::process::kill_process(
        rustix::process::Pid::from_child(&running.child),
        rustix::process::Signal::CONT,
    )?;
    wait("failed restoration revokes desired state", || {
        let status = status(&root);
        Ok(
            !status["error"].is_null()
                && status["desired"].is_null()
                && status["applied"].is_null(),
        )
    })?;
    fs::remove_dir(&journal)?;
    replace(&journal, &baseline)?;
    wait("disable restores", || {
        Ok(view.string("font-name") == "Sans 13" && status(&root)["phase"] == "disabled")
    })?;
    view.set_string("font-name", "Sans 31")?;
    configure(&root, "sys-gui-other", true)?;
    wait("reenable captures new baseline", || {
        Ok(view.string("font-name") == "Monospace 15" && !status(&root)["applied"].is_null())
    })?;
    running.stop()?;
    wait("graceful restoration", || {
        Ok(view.string("font-name") == "Sans 31")
    })?;
    drop(running);
    let crashed = agent(&root)?;
    wait("pre-crash state", || {
        Ok(view.string("font-name") == "Monospace 15" && !status(&root)["applied"].is_null())
    })?;
    drop(crashed);
    configure(&root, "sys-gui-other", false)?;
    let mut recovered = agent(&root)?;
    wait("durable crash recovery", || {
        Ok(view.string("font-name") == "Sans 31" && status(&root)["phase"] == "disabled")
    })?;
    assert_eq!(view.string("document-font-name"), "Serif 21");
    recovered.stop()?;
    production_subscription(&root, &view, &bus, &check_markings)?;
    check_markings()?;
    assert_eq!(fs::read(stylesheet)?, local_style);
    drop(subscription);
    Ok(())
}
