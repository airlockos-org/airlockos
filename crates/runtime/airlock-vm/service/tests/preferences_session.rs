//! Exercise a real guest agent, dconf, XSettings and the Settings portal on a disposable display.
//! Explicitly prepared native tools and a guarded child keep these tests away from the live desktop.

#![cfg(feature = "desktop-preferences")]

use airlock_desktop_preferences::{ColorScheme, FontName, Setting, Snapshot, encode_frame};
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

/// Launch disposable desktop services and a bounded child test with no live session environment.
#[test]
#[ignore = "requires explicitly prepared desktop shell and preferences_peer example"]
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
    let address = format!("unix:path={path}/bus", path = root.path().display());
    let bus_config = root.path().join("bus.conf");
    // No service directories: automatic activation must never inherit host-session paths.
    fs::write(
        &bus_config,
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
            .arg(bus_config)
            .stdout(Stdio::piped()),
    )?;
    let mut actual = String::new();
    BufReader::new(bus.child.stdout.take().unwrap()).read_line(&mut actual)?;
    ensure!(
        !actual.is_empty() && !screen.is_empty(),
        "private display/session did not start"
    );
    let profile = root.path().join("dconf-profile");
    fs::write(&profile, "user-db:user\n")?;
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
            .arg("run"),
    )
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
    replace(&root.join("feed/sys-gui.frame"), b"malformed snapshot")?;
    wait("malformed frame rejected", || {
        Ok(!status(&root)["error"].is_null())
    })?;
    assert_eq!(view.string("font-name"), "Sans 14");
    publish(&root, "sys-gui", &light)?;
    wait("full snapshot after reconnect", || {
        Ok(status(&root)["error"].is_null()
            && portal(&bus, "org.freedesktop.appearance", "color-scheme")?.get::<u32>() == Some(2))
    })?;
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
    drop(subscription);
    Ok(())
}
