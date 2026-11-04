//! Observe effective allowlisted GSettings values; no settings-write API is used here.

use super::{HEARTBEAT, TICK, feed::Publisher};
use airlock_desktop_preferences::{
    ColorScheme, CursorSize, CursorTheme, FontName, ReducedMotion, Setting, Snapshot, TextScale,
};
use anyhow::{Result, bail};
use gio::{Settings, SettingsBackend, SettingsSchemaSource, glib, prelude::*};
use std::cell::Cell;
use std::path::Path;
use std::rc::Rc;
use std::time::Instant;

/// GNOME keys that have a corresponding field in the fixed shared contract.
const INTERFACE_KEYS: &[&str] = &[
    "color-scheme",
    "font-name",
    "document-font-name",
    "monospace-font-name",
    "text-scaling-factor",
    "cursor-theme",
    "cursor-size",
    "enable-animations",
];

/// Accessibility preferences kept distinct from color and animation values.
const ACCESSIBILITY_KEYS: &[&str] = &["high-contrast", "reduced-motion"];

/// Session-owned settings handles; construction subscribes before the first value read.
pub(super) struct Source {
    /// Effective interface values, including installed schema overrides and resets.
    interface: Option<Settings>,
    /// Optional accessibility schema; absent keys become explicit unsupported fields.
    accessibility: Option<Settings>,
    /// One coalescing bit, never a queue of change events.
    pub(super) dirty: Rc<Cell<bool>>,
}

impl Source {
    /// Connect notifications before reading values so updates during initial publication remain pending.
    pub(super) fn new(
        schemas: Option<&SettingsSchemaSource>,
        backend: Option<&SettingsBackend>,
    ) -> Self {
        let dirty = Rc::new(Cell::new(true));
        let observe = |schema, keys: &'static [&'static str]| {
            let schema = schemas?.lookup(schema, true)?;
            let settings = Settings::new_full(&schema, backend, None);
            let changed = dirty.clone();
            settings.connect_changed(None, move |_, key| {
                if keys.contains(&key) {
                    changed.set(true);
                }
            });
            Some(settings)
        };
        Self {
            interface: observe("org.gnome.desktop.interface", INTERFACE_KEYS),
            accessibility: observe("org.gnome.desktop.a11y.interface", ACCESSIBILITY_KEYS),
            dirty,
        }
    }

    /// Read every field before handing the complete validated replacement to publication.
    pub(super) fn snapshot(&self) -> Result<Snapshot> {
        let interface = &self.interface;
        let accessibility = &self.accessibility;
        Ok(Snapshot {
            color_scheme: value(interface, "color-scheme", |value: String| {
                Ok(match value.as_str() {
                    "default" => ColorScheme::NoPreference,
                    "prefer-dark" => ColorScheme::PreferDark,
                    "prefer-light" => ColorScheme::PreferLight,
                    _ => bail!("unsupported GNOME color-scheme value"),
                })
            })?,
            interface_font: value(interface, "font-name", |value: String| {
                Ok(FontName::new(value)?)
            })?,
            document_font: value(interface, "document-font-name", |value: String| {
                Ok(FontName::new(value)?)
            })?,
            monospace_font: value(interface, "monospace-font-name", |value: String| {
                Ok(FontName::new(value)?)
            })?,
            text_scale: value(interface, "text-scaling-factor", |value: f64| {
                Ok(TextScale::new(value)?)
            })?,
            cursor_theme: value(interface, "cursor-theme", |value: String| {
                Ok(CursorTheme::new(value)?)
            })?,
            cursor_size: value(interface, "cursor-size", |value: i32| {
                Ok(CursorSize::new(u16::try_from(value)?)?)
            })?,
            high_contrast: value(accessibility, "high-contrast", |value: bool| Ok(value))?,
            enable_animations: value(interface, "enable-animations", |value: bool| Ok(value))?,
            reduced_motion: value(accessibility, "reduced-motion", |value: String| {
                Ok(match value.as_str() {
                    "no-preference" => ReducedMotion::NoPreference,
                    "reduce" => ReducedMotion::Reduce,
                    _ => bail!("unsupported GNOME reduced-motion value"),
                })
            })?,
        })
    }
}

/// Missing schema/key means unsupported; an invalid present value rejects the whole update.
fn value<T: glib::variant::FromVariant, U>(
    settings: &Option<Settings>,
    key: &str,
    convert: impl FnOnce(T) -> Result<U>,
) -> Result<Setting<U>> {
    let Some(settings) = settings else {
        return Ok(Setting::Unsupported);
    };
    if !settings
        .settings_schema()
        .is_some_and(|schema| schema.has_key(key))
    {
        return Ok(Setting::Unsupported);
    }
    let Some(value) = settings.value(key).get::<T>() else {
        bail!("unexpected GNOME preference type for {key}");
    };
    Ok(Setting::Supported(convert(value)?))
}

/// Run on the graphical session's GLib context; a session unit stops this process on logout.
pub(super) fn run(root: &Path) -> Result<()> {
    let publisher = Publisher::new(root)?;
    let source = Source::new(SettingsSchemaSource::default().as_ref(), None);
    source.dirty.set(false);
    let mut latest = source.snapshot()?;
    publisher.publish(&latest)?;
    let mut refreshed = Instant::now();
    let main_loop = glib::MainLoop::new(None, false);
    let failure = Rc::new(std::cell::RefCell::new(None));
    let failed = failure.clone();
    let running = main_loop.clone();
    let timer = glib::timeout_add_local(TICK, move || {
        let mut changed = false;
        if source.dirty.replace(false) {
            match source.snapshot() {
                Ok(snapshot) if snapshot != latest => {
                    latest = snapshot;
                    changed = true;
                }
                Ok(_) => {}
                Err(error) => eprintln!("preferences: retaining last valid snapshot: {error}"),
            }
        }
        if changed || refreshed.elapsed() >= HEARTBEAT {
            if let Err(error) = publisher.publish(&latest) {
                *failed.borrow_mut() = Some(error);
                running.quit();
                // Leave the timer registered so the owner can always remove it below.
            }
            refreshed = Instant::now();
        }
        glib::ControlFlow::Continue
    });
    main_loop.run();
    timer.remove();
    match failure.take() {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
