//! Test native mappings, local ownership and restoration using disposable schemas/backends.

use super::{
    Config,
    assets::Assets,
    mapping::{self, XValue},
    settings::{self, Key, Settings},
    state::Paths,
};
use airlock_desktop_preferences::{
    ColorScheme, CursorSize, FontName, ReducedMotion, Setting, Snapshot, TextScale,
};
use anyhow::Result;
use gio::prelude::*;
use std::collections::BTreeMap;
use std::fs;
use std::time::{Duration, Instant};

/// A mixed snapshot exercises independent accessibility, color and scaling preferences.
fn snapshot() -> Snapshot {
    Snapshot {
        color_scheme: Setting::Supported(ColorScheme::PreferDark),
        interface_font: Setting::Supported(FontName::new("Sans 12").unwrap()),
        document_font: Setting::Supported(FontName::new("Serif 13").unwrap()),
        monospace_font: Setting::Supported(FontName::new("Monospace 11").unwrap()),
        text_scale: Setting::Supported(TextScale::new(1.5).unwrap()),
        cursor_size: Setting::Supported(CursorSize::new(32).unwrap()),
        high_contrast: Setting::Supported(false),
        enable_animations: Setting::Supported(true),
        reduced_motion: Setting::Supported(ReducedMotion::Reduce),
        ..Snapshot::default()
    }
}

/// Text-only scale and accessibility compose without changing the existing window scale.
#[test]
fn native_mapping_keeps_scale_color_and_motion_independent() -> Result<()> {
    let baseline = Settings::with_backend(None, None).capture("sys-gui".parse()?);
    let initial = snapshot();
    let plan = mapping::plan(&initial, &baseline, 2, &Assets::empty());
    assert_eq!(plan.xsettings["Xft/DPI"], XValue::Integer(294912));
    assert_eq!(plan.xsettings["Gdk/UnscaledDPI"], XValue::Integer(147456));
    assert_eq!(
        plan.xsettings["Gdk/WindowScalingFactor"],
        XValue::Integer(2)
    );
    assert_eq!(plan.xsettings["Gtk/CursorThemeSize"], XValue::Integer(64));
    assert_eq!(plan.xsettings["Gtk/EnableAnimations"], XValue::Integer(0));
    assert_eq!(
        plan.xsettings["Net/ThemeName"],
        XValue::Text("Adwaita-dark".into())
    );
    assert_eq!(
        Key::Animations
            .parse(plan.settings[&Key::Animations].as_ref().unwrap())?
            .get::<bool>(),
        Some(false)
    );
    let high_contrast = Snapshot {
        high_contrast: Setting::Supported(true),
        ..initial
    };
    assert_eq!(
        mapping::plan(&high_contrast, &baseline, 1, &Assets::empty()).xsettings["Net/ThemeName"],
        XValue::Text("HighContrast".into())
    );
    let mut limitations = Vec::new();
    assert_eq!(
        Assets::empty().font("Unavailable Example 15", true, &mut limitations),
        "Monospace 15"
    );
    assert!(!limitations.is_empty());
    let quoted = BTreeMap::from([("Gtk/FontName".into(), XValue::Text("A\"B\\C 12".into()))]);
    assert!(super::xsettings::render(&quoted)?.contains("A\\\"B\\\\C"));
    assert!(
        super::xsettings::render(&BTreeMap::from([(
            "Gtk/FontName".into(),
            XValue::Text("bad\ninjection".into())
        )]))
        .is_err()
    );
    Ok(())
}

/// Readiness belongs to the current binding and has a finite degraded fallback even with no agent.
#[test]
fn readiness_is_optional_bound_to_configuration_and_bounded() -> Result<()> {
    let root = tempfile::tempdir()?;
    let config_path = root.path().join("config.json");
    super::readiness_for(&config_path, root.path(), Duration::ZERO)?;
    let config = Config {
        enabled: true,
        gui_domain: "sys-gui".parse()?,
        window_scale: 1,
    };
    fs::write(&config_path, serde_json::to_vec(&config)?)?;
    let paths = Paths::at(root.path(), root.path())?;
    let mut status = super::state::Status {
        config: Some(Config {
            gui_domain: "sys-gui-old".parse()?,
            ..config.clone()
        }),
        ready: true,
        phase: "applied".into(),
        desired: None,
        applied: None,
        limitations: Vec::new(),
        error: None,
    };
    paths.status(&status)?;
    let started = Instant::now();
    super::readiness_for(&config_path, root.path(), Duration::from_millis(20))?;
    assert!(started.elapsed() >= Duration::from_millis(20));
    assert!(started.elapsed() < Duration::from_secs(1));
    status.config = Some(config.clone());
    paths.status(&status)?;
    let started = Instant::now();
    super::readiness_for(&config_path, root.path(), Duration::from_secs(2))?;
    assert!(started.elapsed() < Duration::from_secs(1));
    let invalid = Config {
        window_scale: 0,
        ..config
    };
    fs::write(&config_path, serde_json::to_vec(&invalid)?)?;
    assert!(Config::read(&config_path).is_err());
    Ok(())
}

/// Load the explicitly prepared desktop schemas with an isolated backend rather than a live dconf user.
fn native() -> Result<(Settings, gio::Settings)> {
    let directory = std::env::var_os("AIRLOCK_TEST_GSETTINGS_SCHEMAS")
        .expect("prepare AIRLOCK_TEST_GSETTINGS_SCHEMAS explicitly");
    let schemas = gio::SettingsSchemaSource::from_directory(directory, None, false)?;
    let backend = gio::memory_settings_backend_new();
    let view = gio::Settings::new_full(
        &schemas
            .lookup("org.gnome.desktop.interface", false)
            .unwrap(),
        Some(&backend),
        None,
    );
    Ok((Settings::with_backend(Some(&schemas), Some(&backend)), view))
}

/// Unsupported transitions restore once; unrelated/local changes survive and a crash journal recovers.
#[test]
#[ignore = "requires explicitly prepared AIRLOCK_TEST_GSETTINGS_SCHEMAS"]
fn managed_fields_restore_without_reverting_unmanaged_user_edits() -> Result<()> {
    let (mut settings, view) = native()?;
    view.set_string("font-name", "Original Local 13")?;
    let roots = tempfile::tempdir()?;
    let paths = Paths::at(roots.path(), roots.path())?;
    let mut baseline = settings.capture("sys-gui".parse()?);
    let desired = Snapshot {
        interface_font: snapshot().interface_font,
        ..Snapshot::default()
    };
    let plan = mapping::plan(&desired, &baseline, 1, &Assets::empty());
    baseline.managed.extend(plan.managed);
    paths.save(&baseline)?;
    settings.apply(&plan.settings)?;
    assert_eq!(view.string("font-name"), "Sans 12");
    view.set_string("document-font-name", "My Unmanaged Document 19")?;
    settings.refresh_unmanaged(&mut baseline);
    let reset = mapping::plan(&Snapshot::default(), &baseline, 1, &Assets::empty());
    assert_eq!(
        reset.xsettings["Gtk/FontName"],
        XValue::Text("Original Local 13".into())
    );
    settings.apply(&reset.settings)?;
    baseline.managed = reset.managed;
    paths.save(&baseline)?;
    assert_eq!(view.string("font-name"), "Original Local 13");
    assert_eq!(
        view.string("document-font-name"),
        "My Unmanaged Document 19"
    );
    view.set_string("font-name", "New Unmanaged Value 16")?;
    settings.refresh_unmanaged(&mut baseline);
    settings
        .apply(&mapping::plan(&Snapshot::default(), &baseline, 1, &Assets::empty()).settings)?;
    assert_eq!(view.string("font-name"), "New Unmanaged Value 16");
    let plan = mapping::plan(&desired, &baseline, 1, &Assets::empty());
    baseline.managed.extend(plan.managed);
    paths.save(&baseline)?;
    settings.apply(&plan.settings)?;
    settings.restore_saved(&paths)?;
    assert_eq!(view.string("font-name"), "New Unmanaged Value 16");
    assert!(paths.baseline()?.is_none());
    assert_eq!(
        view.string("document-font-name"),
        "My Unmanaged Document 19"
    );
    Ok(())
}

/// Native backend refusal is a retryable failure, not successful application or unsupported data.
#[test]
#[ignore = "requires explicitly prepared AIRLOCK_TEST_GSETTINGS_SCHEMAS"]
fn unwritable_backend_reports_failed_convergence() -> Result<()> {
    let directory = std::env::var_os("AIRLOCK_TEST_GSETTINGS_SCHEMAS").unwrap();
    let schemas = gio::SettingsSchemaSource::from_directory(directory, None, false)?;
    let backend = gio::null_settings_backend_new();
    let mut settings = Settings::with_backend(Some(&schemas), Some(&backend));
    assert!(
        settings
            .apply(&BTreeMap::from([(
                Key::Font,
                Some(settings::encoded(&"Different Font 17"))
            )]))
            .is_err()
    );
    Ok(())
}
