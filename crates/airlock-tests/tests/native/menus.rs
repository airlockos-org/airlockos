//! Application discovery and Qubes menu publication retain active profiles and stable VM identities.

use crate::common;
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::{
    fs,
    os::{
        fd::AsFd,
        unix::fs::{PermissionsExt, symlink},
    },
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

const HOME: &str = "738a6af9-8e51-590d-afe4-790b26fbca79";

const WORK: &str = "728a6af9-8e51-590d-afe4-790b26fbca79";

/// Write a desktop entry in an active data directory with only the supplied metadata overrides.
fn desktop(directory: &Path, name: &str, overrides: Value) -> Result<PathBuf> {
    fs::create_dir_all(directory)?;
    let path = directory.join(name);
    let mut fields =
        json!({"Type": "Application", "Name": "Example", "Exec": "example %u", "Icon": "example"});
    fields
        .as_object_mut()
        .unwrap()
        .extend(overrides.as_object().unwrap().clone());
    let mut text = String::from("[Desktop Entry]\n");
    for (key, value) in fields.as_object().unwrap() {
        text.push_str(&format!("{key}={value}\n", value = value.as_str().unwrap()));
    }
    fs::write(&path, text)?;
    Ok(path)
}

/// Scan temporary profiles through the actual VM service without inheriting the workstation catalog.
fn scan(directory: &Path, roots: &[&Path]) -> Result<airlock_vm_service::support::Output> {
    common::run(
        Command::new(common::binary("AIRLOCK_VM_BIN", "airlock-vm-service"))
            .arg("catalog")
            .env("HOME", directory)
            .env("XDG_DATA_HOME", directory.join("empty"))
            .env("XDG_DATA_DIRS", std::env::join_paths(roots)?),
        None,
    )
}

/// Decode the upstream line protocol so assertions compare metadata rather than serialization order.
fn catalog(directory: &Path, roots: &[&Path]) -> Result<Value> {
    let mut entries = json!({});
    for line in String::from_utf8(scan(directory, roots)?.checked()?)?.lines() {
        let (identity, field) = line.split_once(':').context("catalog identity")?;
        let (key, value) = field.split_once('=').context("catalog field")?;
        if entries[identity].is_null() {
            entries[identity] = json!({});
        }
        entries[identity][key] = json!(value);
    }
    Ok(entries)
}

/// Changes in the selected profile and installed entries withdraw only the corresponding applications.
#[test]
fn catalog_follows_profile_switch_install_and_remove() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    for (profile, extra) in [("old", "old-only.desktop"), ("new", "new-only.desktop")] {
        let directory = root.join(profile).join("applications");
        desktop(&directory, "example.desktop", json!({}))?;
        desktop(&directory, extra, json!({}))?;
    }
    let active = root.join("active");
    symlink(root.join("old"), &active)?;
    let before = catalog(root, &[&active])?;
    fs::remove_file(&active)?;
    symlink(root.join("new"), &active)?;
    let after = catalog(root, &[&active])?;
    assert_eq!(after.as_object().unwrap().len(), 2);
    assert!(after.get("new-only.desktop").is_some());
    assert_ne!(
        before["example.desktop"]["X-Airlock-Source"],
        after["example.desktop"]["X-Airlock-Source"]
    );
    fs::remove_file(root.join("new/applications/new-only.desktop"))?;
    assert_eq!(catalog(root, &[&active])?.as_object().unwrap().len(), 1);
    assert!(root.join("old/applications/old-only.desktop").is_file());
    Ok(())
}

/// Priority masks, localized DBus applications and original commands retain upstream desktop semantics.
#[test]
fn catalog_preserves_metadata_and_masks_lower_priority_entries() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let user = root.join("user");
    let system = root.join("system");
    desktop(&system.join("applications"), "example.desktop", json!({}))?;
    for fields in [
        json!({"Hidden": "true"}),
        json!({"NoDisplay": "true"}),
        json!({"TryExec": "airlock-missing-executable"}),
    ] {
        desktop(&user.join("applications"), "example.desktop", fields)?;
        assert_eq!(catalog(root, &[&user, &system])?, json!({}));
    }

    for (command, expected) in [
        ("example", Some("example")),
        (r#""/nix/store/package/bin/new-app" %U"#, Some("new-app")),
        (
            r#"env MODE="some value" /run/current-system/sw/bin/new-app %f"#,
            Some("new-app"),
        ),
        ("env -- new-app", Some("new-app")),
        ("env MODE=value", None),
        ("env -u MODE new-app", None),
        ("\"unterminated", None),
        ("%k", None),
    ] {
        desktop(
            &user.join("applications"),
            "example.desktop",
            json!({"Exec": command}),
        )?;
        let entries = catalog(root, &[&user])?;
        assert_eq!(
            entries["example.desktop"]["StartupWMClass"],
            json!(expected)
        );
        assert_eq!(
            entries["example.desktop"]["Exec"],
            "qubes-desktop-run example.desktop"
        );
    }

    for command in ["nautilus --new-window %U", ""] {
        desktop(
            &user.join("applications"),
            "org.gnome.Nautilus.desktop",
            json!({
                "Exec": command, "DBusActivatable": "true", "Name[fr]": "Fichiers", "Keywords[fr]": "dossiers;", "OnlyShowIn": "GNOME;", "Icon": "org.gnome.Nautilus"
            }),
        )?;
        let entries = catalog(root, &[&user])?;
        let files = &entries["org.gnome.Nautilus.desktop"];
        assert_eq!(files["StartupWMClass"], "org.gnome.Nautilus");
        assert_eq!(files["Icon"], "org.gnome.Nautilus");
        assert_eq!(files["Name[fr]"], "Fichiers");
        assert_eq!(files["Keywords[fr]"], "dossiers;");
    }

    desktop(
        &user.join("applications"),
        "org.gnome.Nautilus.desktop",
        json!({"Exec": "different", "DBusActivatable": "true", "StartupWMClass": "Explicit"}),
    )?;
    assert_eq!(
        catalog(root, &[&user])?["org.gnome.Nautilus.desktop"]["StartupWMClass"],
        "Explicit"
    );
    Ok(())
}

/// Recursive links terminate, while unreadable or special entries never publish partial uninstall snapshots.
#[test]
fn catalog_scan_is_complete_or_fails_without_output() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let profile = root.join("profile");
    desktop(
        &root.join("package/wine/Programs"),
        "app.desktop",
        json!({}),
    )?;
    symlink(root.join("package/wine"), root.join("package/wine/loop"))?;
    fs::create_dir_all(profile.join("applications"))?;
    symlink(root.join("package/wine"), profile.join("applications/wine"))?;
    assert_eq!(
        catalog(root, &[&profile])?
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        ["wine-Programs-app.desktop"]
    );

    let broken = profile.join("applications/broken.desktop");
    symlink(root.join("missing"), &broken)?;
    let output = scan(root, &[&profile])?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    fs::remove_file(broken)?;
    rustix::fs::mknodat(
        rustix::fs::CWD,
        profile.join("applications/fifo.desktop"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )?;
    let output = scan(root, &[&profile])?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());

    let restricted = root.join("restricted");
    desktop(
        &restricted.join("profile/applications"),
        "other.desktop",
        json!({}),
    )?;
    fs::set_permissions(&restricted, fs::Permissions::from_mode(0o000))?;
    let output = scan(root, &[&profile, &restricted.join("profile")]);
    fs::set_permissions(&restricted, fs::Permissions::from_mode(0o700))?;
    let output = output?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    Ok(())
}

/// One explicitly supplied VM snapshot, independent of the test host's Qubes installation.
fn vm(name: &str, identity: &str, running: bool) -> Value {
    json!({
        "name": name, "uuid": identity, "guivm": "sys-gui", "tags": [], "internal": false,
        "class": "StandaloneVM", "auto_cleanup": false, "running": running,
        "label": "#3465a4", "menu-items": "*"
    })
}

/// Private Qubes reply data, cache and durable coordinator state used by one scenario.
struct Menus {
    // Owns all reply files and publication evidence until the scenario completes.
    temporary: tempfile::TempDir,
    // Mutable upstream inventory and menu data supplied before each operation.
    data: Value,
}

impl Menus {
    /// Start with one running application VM and one advertised application.
    fn new() -> Result<Self> {
        let temporary = tempfile::tempdir()?;
        let cache = temporary.path().join("data/qubes-appmenus");
        fs::create_dir_all(&cache)?;
        common::peer_link(temporary.path(), "menu-qrexec")?;
        common::peer_link(temporary.path(), "menu-qdb")?;
        Ok(Self {
            temporary,
            data: json!({
                "local_name": "sys-gui", "basedir": cache,
                "domains": [vm("usr-home", HOME, true)],
                "menus": {"example.desktop": {"Name": "Example"}}
            }),
        })
    }

    /// Locate the native coordinator's durable state independently of bridge cache contents.
    fn state(&self, name: &str) -> PathBuf {
        self.temporary
            .path()
            .join("state/airlock-appmenus")
            .join(name)
    }

    /// Locate upstream menu cache data without inferring it from the coordinator's inventory.
    fn cache(&self, name: &str) -> PathBuf {
        self.temporary.path().join("data/qubes-appmenus").join(name)
    }

    /// Persist upstream data before a new native invocation; concurrent tests may update it explicitly.
    fn persist(&self) -> Result<()> {
        fs::write(
            self.temporary.path().join("config.json"),
            serde_json::to_vec(&self.data)?,
        )?;
        Ok(())
    }

    /// Build a child-local environment using the inert bridge without changing the test process.
    fn command(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(common::binary(
            "AIRLOCK_SYS_GUI_BIN",
            "airlock-sys-gui-service",
        ));
        command
            .arg("menus")
            .args(arguments)
            .env("XDG_STATE_HOME", self.temporary.path().join("state"))
            .env(
                "AIRLOCK_QREXEC_CLIENT_VM",
                self.temporary.path().join("menu-qrexec"),
            )
            .env(
                "AIRLOCK_QUBESDB_READ",
                self.temporary.path().join("menu-qdb"),
            )
            .env("XDG_DATA_HOME", self.temporary.path().join("data"))
            .env(
                "AIRLOCK_TEST_MENUS",
                self.temporary.path().join("config.json"),
            );
        command
    }

    /// Run through the production CLI and keep intentional failures available to assertions.
    fn run(&self, arguments: &[&str], success: bool) -> Result<()> {
        self.persist()?;
        let result = common::run(&mut self.command(arguments), None)?;
        assert_eq!(
            result.status.success(),
            success,
            "{error}",
            error = String::from_utf8_lossy(&result.stderr)
        );
        Ok(())
    }

    /// Read recorded upstream calls, optionally selecting one process operation.
    fn calls(&self, operation: &str) -> Result<Vec<Value>> {
        let path = self.temporary.path().join("calls.jsonl");
        if !path.exists() {
            return Ok(Vec::new());
        }
        fs::read_to_string(path)?
            .lines()
            .map(|line| Ok(serde_json::from_str::<Value>(line)?))
            .filter(|row| match row {
                Ok(row) => row["operation"] == operation,
                Err(_) => true,
            })
            .collect()
    }

    /// Decode a state artifact only after the native operation has published it.
    fn read(&self, name: &str) -> Result<Value> {
        Ok(serde_json::from_slice(&fs::read(self.state(name))?)?)
    }

    /// Observe only the fixture's publication state behind a fixed read-only host reply.
    fn startup(&self) -> Result<Value> {
        let mut peers = crate::common::peers::Peers::new()?;
        peers.rules(
            "boot-rpc",
            json!([{"contains":"airlock.BootStatus", "stdout":json!({
            "boot_id":"host-boot", "status":"complete", "desktop_ready":true,
            "guests":[
                {"name":"usr-home","phase":"ready","applications":true},
                {"name":"sys-net","phase":"ready","applications":false}
            ]
        }).to_string()}]),
        )?;
        let mut command = peers.command(common::binary(
            "AIRLOCK_SYS_GUI_BIN",
            "airlock-sys-gui-service",
        ))?;
        command
            .arg("startup-status")
            .env("AIRLOCK_QVM_RUN", peers.path("bin/boot-rpc"))
            .env("XDG_STATE_HOME", self.temporary.path().join("state"))
            .env("XDG_DATA_HOME", self.temporary.path().join("data"));
        peers.json(&mut command)
    }
}

/// A running guest is not application-ready until this boot has a matching publication and every launcher exists.
#[test]
fn startup_panel_waits_for_current_menu_publication() -> Result<()> {
    let mut menus = Menus::new()?;
    let before = menus.startup()?;
    assert_eq!(before["complete"], false);
    assert_eq!(before["guests"][0]["phase"], "loading");
    assert_eq!(before["guests"][0]["detail"], "Loading applications");
    assert_eq!(before["guests"][1]["detail"], "Ready");
    assert!(
        !menus.state("inventory.json").exists(),
        "observation must not create menu state"
    );

    menus.data["fail"] = json!("fetch");
    menus.run(&["reconcile"], true)?;
    let failed = menus.startup()?;
    assert_eq!(failed["attention"], true);
    assert_eq!(failed["guests"][0]["phase"], "failed");
    menus.data.as_object_mut().unwrap().remove("fail");

    menus.run(&["reconcile"], true)?;
    let ready = menus.startup()?;
    assert_eq!(ready["complete"], true);
    assert_eq!(ready["detail"], "Ready");
    assert_eq!(ready["guests"][0]["detail"], "Ready");
    let receipt_path = menus.state(&format!("{HOME}.json"));
    let mut receipt = menus.read(&format!("{HOME}.json"))?;
    let current = receipt["boot_id"].clone();
    receipt["boot_id"] = json!(WORK);
    fs::write(&receipt_path, serde_json::to_vec(&receipt)?)?;
    assert_eq!(
        menus.startup()?["complete"],
        false,
        "a previous boot's cache is not fresh publication"
    );
    receipt["boot_id"] = current;
    fs::write(&receipt_path, serde_json::to_vec(&receipt)?)?;
    let launcher = menus.temporary.path().join(format!(
        "data/applications/org.qubes-os.vm.{HOME}.example.desktop"
    ));
    fs::remove_file(&launcher)?;
    assert_eq!(
        menus.startup()?["complete"],
        false,
        "missing launchers cannot count as available"
    );

    // A valid empty catalog is complete, rather than an endless spinner for a service-only VM.
    menus.data["menus"] = json!({});
    menus.run(&["reconcile"], true)?;
    assert_eq!(menus.startup()?["complete"], true);
    Ok(())
}

/// Stopped VMs stay searchable; renames preserve stable identities and remove only obsolete caches.
#[test]
fn menu_membership_uses_uuid_and_never_starts_stopped_vms() -> Result<()> {
    let mut menus = Menus::new()?;
    menus.data["domains"] = json!([vm("usr-home", HOME, false), vm("usr-work", WORK, true)]);
    menus.run(&["reconcile"], true)?;
    assert_eq!(menus.read("inventory.json")?.as_object().unwrap().len(), 2);
    assert_eq!(
        menus
            .calls("fetch")?
            .iter()
            .map(|row| &row["names"])
            .collect::<Vec<_>>(),
        [&json!(["usr-work"])]
    );

    let mut menus = Menus::new()?;
    menus.run(&["reconcile"], true)?;
    fs::create_dir(menus.cache("retired-vm"))?;
    menus.data["domains"] = json!([vm("usr-personal", HOME, false)]);
    menus.run(&["reconcile"], true)?;
    assert!(!menus.cache("usr-home").exists());
    assert!(!menus.cache("retired-vm").exists());
    assert!(menus.cache("usr-personal/catalog.json").is_file());
    let launcher = menus.temporary.path().join(format!(
        "data/applications/org.qubes-os.vm.{HOME}.example.desktop"
    ));
    assert!(fs::read_to_string(launcher)?.contains("Name=usr-personal: Example"));
    Ok(())
}

/// Failed or ambiguous inventory cannot withdraw membership, and excluded VMs cannot fetch applications.
#[test]
fn menu_inventory_rejects_ineligible_or_ambiguous_members() -> Result<()> {
    let mut menus = Menus::new()?;
    menus.run(&["reconcile"], true)?;
    let before = fs::read(menus.state("inventory.json"))?;
    menus.data["fail"] = json!("inventory");
    menus.run(&["reconcile"], false)?;
    assert_eq!(fs::read(menus.state("inventory.json"))?, before);
    menus.data.as_object_mut().unwrap().remove("fail");
    menus.data["domains"] = json!([vm("usr-home", HOME, true), vm("usr-home", WORK, true)]);
    menus.persist()?;
    let result = common::run(&mut menus.command(&["reconcile"]), None)?;
    assert!(String::from_utf8_lossy(&result.stderr).contains("duplicate VM name"));
    assert_eq!(fs::read(menus.state("inventory.json"))?, before);

    for change in [
        json!({"guivm": "other-gui"}),
        json!({"tags": ["airlock-retired"]}),
        json!({"internal": true}),
        json!({"class": "DispVM", "auto_cleanup": true}),
        json!({"name": "sys-gui"}),
    ] {
        let mut menus = Menus::new()?;
        let mut member = vm("usr-home", HOME, true);
        member
            .as_object_mut()
            .unwrap()
            .extend(change.as_object().unwrap().clone());
        menus.data["domains"] = json!([member]);
        menus.run(&["reconcile"], true)?;
        assert_eq!(menus.read("inventory.json")?, json!({}));
        assert!(menus.calls("fetch")?.is_empty());
    }
    Ok(())
}

/// Empty catalogs withdraw applications once; force and missing caches deliberately republish.
#[test]
fn menu_publication_caches_empty_catalogs_but_rechecks_identity() -> Result<()> {
    let mut menus = Menus::new()?;
    menus.data["menus"] = json!({});
    menus.run(&["sync", "usr-home"], true)?;
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(menus.cache("usr-home/catalog.json"))?)?,
        json!({})
    );
    let receipt_path = menus.state(&format!("{HOME}.json"));
    let first = fs::read(&receipt_path)?;
    menus.run(&["sync", "usr-home"], true)?;
    assert_eq!(fs::read(&receipt_path)?, first);
    menus.run(&["sync", "usr-home", "--force"], true)?;
    assert_ne!(fs::read(&receipt_path)?, first);
    fs::remove_file(menus.cache("usr-home/catalog.json"))?;
    menus.run(&["sync", "usr-home"], true)?;
    assert!(menus.cache("usr-home/catalog.json").is_file());
    let before = fs::read(&receipt_path)?;
    menus.data["fail"] = json!("fetch");
    menus.run(&["sync", "usr-home"], false)?;
    assert_eq!(fs::read(&receipt_path)?, before);

    let mut menus = Menus::new()?;
    menus.run(&["sync", "usr-home", "--uuid", WORK], false)?;
    assert!(menus.calls("fetch")?.is_empty());
    menus.data["stop_after_fetch"] = json!(true);
    menus.run(&["sync", "usr-home"], false)?;
    assert!(!menus.cache("usr-home/catalog.json").exists());
    Ok(())
}

/// Renaming refuses redirected or existing destinations without losing the original cache.
#[test]
fn menu_cache_rename_preserves_both_sides_on_conflict() -> Result<()> {
    let mut menus = Menus::new()?;
    menus.run(&["reconcile"], true)?;
    menus.data["domains"] = json!([vm("usr-personal", HOME, false)]);
    let destination = menus.cache("usr-personal");
    let outside = menus.temporary.path().join("outside");
    fs::create_dir(&outside)?;
    symlink(&outside, &destination)?;
    menus.run(&["reconcile"], false)?;
    assert!(menus.cache("usr-home/catalog.json").is_file());
    fs::remove_file(&destination)?;
    fs::create_dir(&destination)?;
    menus.run(&["reconcile"], false)?;
    assert!(destination.is_dir());
    assert!(menus.cache("usr-home/catalog.json").is_file());
    Ok(())
}

/// A waiting reconcile must take its inventory snapshot after acquiring the shared operation lock.
#[test]
fn menu_inventory_is_queried_only_after_lock_ownership() -> Result<()> {
    let mut menus = Menus::new()?;
    menus.data["domains"] = json!([vm("usr-home", HOME, false)]);
    menus.run(&["reconcile"], true)?;
    let queried = menus.calls("inventory")?.len();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(menus.state(".locks/operation-inventory.lock"))?;
    rustix::fs::flock(lock.as_fd(), rustix::fs::FlockOperation::LockExclusive)?;
    let logs = menus.temporary.path().join("lock-waiter");
    let mut child = airlock_tests::system::Job::spawn(&mut menus.command(&["reconcile"]), &logs)?;
    for _ in 0..10 {
        assert!(child.running()?);
        assert_eq!(menus.calls("inventory")?.len(), queried);
        std::thread::sleep(Duration::from_millis(20));
    }
    menus.data["domains"] = json!([vm("usr-work", WORK, false)]);
    menus.persist()?;
    rustix::fs::flock(lock.as_fd(), rustix::fs::FlockOperation::Unlock)?;
    assert!(child.wait(Duration::from_secs(5))?.success());

    assert_eq!(
        menus
            .read("inventory.json")?
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        [WORK]
    );
    Ok(())
}

/// Icon lookup respects the selected XDG theme without interpreting or decoding icon bytes itself.
#[test]
fn vm_icon_lookup_uses_the_active_theme() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let theme = root.join("icons/Adwaita");
    fs::create_dir_all(theme.join("48x48/apps"))?;
    fs::write(
        theme.join("index.theme"),
        r"[Icon Theme]
Name=Adwaita
Directories=48x48/apps

[48x48/apps]
Size=48
Context=Applications
Type=Fixed
",
    )?;
    let icon = theme.join("48x48/apps/airlock-test-icon.png");
    fs::write(
        &icon,
        b"icon lookup fixture; decoding belongs to upstream Qubes",
    )?;
    let output = common::run(
        Command::new(common::binary("AIRLOCK_VM_BIN", "airlock-vm-service"))
            .args(["icon", "airlock-test-icon", "48"])
            .env("HOME", root)
            .env("XDG_DATA_HOME", root)
            .env("XDG_DATA_DIRS", root),
        None,
    )?
    .checked()?;
    assert_eq!(
        fs::canonicalize(String::from_utf8(output)?.trim())?,
        fs::canonicalize(icon)?
    );
    Ok(())
}

/// Real publication validates metadata, preserves original icon pixels and refuses late identity changes or redirected outputs.
#[test]
fn menu_publication_preserves_safe_metadata_and_owns_only_its_files() -> Result<()> {
    let mut menus = Menus::new()?;
    menus.data["wire"] = json!(
        r"example.desktop:Name=Example
example.desktop:Name[fr]=Éditeur
example.desktop:Keywords=graphics;painting;
example.desktop:OnlyShowIn=GNOME;
example.desktop:Icon=example
example.desktop:Exec=touch /tmp/must-not-run
example.desktop:X-Airlock-Source=/nix/store/source/share/applications/example.desktop
example.desktop:StartupWMClass=class;command
bad;command.desktop:Name=Bad
"
    );
    menus.run(&["sync", "usr-home"], true)?;
    let path = menus.temporary.path().join(format!(
        "data/applications/org.qubes-os.vm.{HOME}.example.desktop"
    ));
    let desktop = fs::read_to_string(&path)?;
    for expected in [
        "Name=usr-home: Example",
        "Name[fr]=usr-home: Éditeur",
        "OnlyShowIn=GNOME;",
        "StartupWMClass=usr-home:example",
        "Exec=airlock-launch-qube-app %c usr-home qubes.StartApp+example",
    ] {
        assert!(desktop.contains(expected), "{desktop}");
    }
    assert!(
        !desktop.contains("touch /tmp")
            && !desktop.contains("X-Airlock-Source")
            && !desktop.contains("class;command")
    );
    let icon = desktop
        .lines()
        .find_map(|line| line.strip_prefix("Icon="))
        .unwrap();
    let mut decoder = png::Decoder::new(std::io::Cursor::new(fs::read(icon)?)).read_info()?;
    let mut pixels = vec![0; decoder.output_buffer_size().unwrap()];
    let frame = decoder.next_frame(&mut pixels)?;
    assert_eq!((frame.width, frame.height), (1, 1));
    assert_eq!(&pixels[..frame.buffer_size()], &[255, 32, 64, 255]);
    let modified = fs::metadata(icon)?.modified()?;
    menus.run(&["sync", "usr-home", "--force"], true)?;
    assert_eq!(fs::metadata(icon)?.modified()?, modified);

    let receipt = fs::read(menus.state(&format!("{HOME}.json")))?;
    menus.data["stop_after_icon"] = json!(true);
    menus.run(&["sync", "usr-home", "--force"], false)?;
    assert_eq!(fs::read(menus.state(&format!("{HOME}.json")))?, receipt);
    assert_eq!(fs::read_to_string(&path)?, desktop);
    menus
        .data
        .as_object_mut()
        .unwrap()
        .remove("stop_after_icon");
    menus.data["domains"][0]["running"] = json!(true);
    menus.data["wire"] = json!(format!("example.desktop:Name={}\n", "x".repeat(4096)));
    menus.run(&["sync", "usr-home"], false)?;
    assert_eq!(fs::read_to_string(&path)?, desktop);

    menus.data.as_object_mut().unwrap().remove("wire");
    let outside = menus.temporary.path().join("outside.desktop");
    fs::write(&outside, "local application")?;
    fs::remove_file(&path)?;
    symlink(&outside, &path)?;
    menus.run(&["sync", "usr-home", "--force"], false)?;
    assert_eq!(fs::read_to_string(outside)?, "local application");
    Ok(())
}
