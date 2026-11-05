//! Translate one validated desired snapshot into independent native adapter operations.

use super::{
    assets::Assets,
    settings::{Baseline, Key, encoded},
};
use airlock_desktop_preferences::{ColorScheme, ReducedMotion, Setting, Snapshot};
use std::collections::{BTreeMap, BTreeSet};

/// Values supported by xsettingsd's native configuration grammar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum XValue {
    /// Native signed XSettings number (including booleans and fixed-point DPI).
    Integer(#[doc = "The integer placed in the verified X property."] i32),
    /// A bounded, escaped native setting such as a font or cursor name.
    Text(#[doc = "The local value after asset fallback and validation."] String),
}

/// Desired local state plus explicit fallbacks; applying it is not a cross-toolkit transaction.
pub(super) struct Plan {
    /// Per-key native GVariant value, or reset to the original effective default.
    pub(super) settings: BTreeMap<Key, Option<String>>,
    /// Effective local values, combining managed preferences with the guest's current baseline.
    pub(super) xsettings: BTreeMap<String, XValue>,
    /// Asset/capability limitations, separate from adapter errors.
    pub(super) limitations: Vec<String>,
    /// Keys owned by this snapshot; fields leaving this set are restored once.
    pub(super) managed: BTreeSet<Key>,
}

/// Fill unsupported fields from the saved local baseline; override only supported preferences.
pub(super) fn plan(snapshot: &Snapshot, baseline: &Baseline, scale: u16, assets: &Assets) -> Plan {
    use Setting::Supported;
    let mut plan = Plan {
        settings: baseline
            .values
            .iter()
            .filter(|(key, _)| baseline.managed.contains(key))
            .map(|(key, saved)| (*key, saved.user.clone()))
            .collect(),
        xsettings: local_xsettings(baseline, scale),
        limitations: Vec::new(),
        managed: BTreeSet::new(),
    };

    if let Supported(value) = snapshot.color_scheme {
        plan.settings.insert(
            Key::Color,
            Some(encoded(&match value {
                ColorScheme::NoPreference => "default",
                ColorScheme::PreferDark => "prefer-dark",
                ColorScheme::PreferLight => "prefer-light",
            })),
        );
    }

    for (setting, key, monospace) in [
        (&snapshot.interface_font, Key::Font, false),
        (&snapshot.document_font, Key::Document, false),
        (&snapshot.monospace_font, Key::Monospace, true),
    ] {
        if let Supported(value) = setting {
            let font = assets.font(value.as_str(), monospace, &mut plan.limitations);
            plan.settings.insert(key, Some(encoded(&font)));
            if key == Key::Font {
                plan.xsettings
                    .insert("Gtk/FontName".into(), XValue::Text(font));
            }
        }
    }

    if let Supported(value) = snapshot.text_scale {
        plan.settings
            .insert(Key::Scale, Some(encoded(&value.get())));
        plan.xsettings.insert(
            "Gdk/UnscaledDPI".into(),
            XValue::Integer((96.0 * value.get() * 1024.0).round() as i32),
        );
        plan.xsettings.insert(
            "Xft/DPI".into(),
            XValue::Integer((96.0 * value.get() * 1024.0 * f64::from(scale)).round() as i32),
        );
    }

    if let Supported(value) = &snapshot.cursor_theme {
        let theme = assets.cursor(value.as_str(), &mut plan.limitations);
        plan.settings
            .insert(Key::CursorTheme, Some(encoded(&theme)));
        plan.xsettings
            .insert("Gtk/CursorThemeName".into(), XValue::Text(theme));
    }
    if let Supported(value) = snapshot.cursor_size {
        plan.settings
            .insert(Key::CursorSize, Some(encoded(&i32::from(value.get()))));
        plan.xsettings.insert(
            "Gtk/CursorThemeSize".into(),
            XValue::Integer(i32::from(value.get()) * i32::from(scale)),
        );
    }

    if let Supported(value) = snapshot.high_contrast {
        plan.settings.insert(Key::Contrast, Some(encoded(&value)));
    }
    if matches!(snapshot.color_scheme, Supported(_))
        || matches!(snapshot.high_contrast, Supported(_))
    {
        let contrast = match snapshot.high_contrast {
            Supported(value) => value,
            _ => baseline.effective(Key::Contrast, false),
        };
        let color = match snapshot.color_scheme {
            Supported(value) => value,
            _ => match baseline
                .effective(Key::Color, String::from("default"))
                .as_str()
            {
                "prefer-dark" => ColorScheme::PreferDark,
                _ => ColorScheme::NoPreference,
            },
        };
        let theme = if contrast {
            "HighContrast"
        } else if color == ColorScheme::PreferDark {
            "Adwaita-dark"
        } else {
            "Adwaita"
        };
        plan.settings.insert(Key::GtkTheme, Some(encoded(&theme)));
        plan.xsettings
            .insert("Net/ThemeName".into(), XValue::Text(theme.into()));
    }

    if let Supported(value) = snapshot.reduced_motion {
        plan.settings.insert(
            Key::Motion,
            Some(encoded(&match value {
                ReducedMotion::NoPreference => "no-preference",
                ReducedMotion::Reduce => "reduce",
            })),
        );
    }
    if matches!(snapshot.enable_animations, Supported(_))
        || matches!(snapshot.reduced_motion, Supported(_))
    {
        let enabled = match snapshot.enable_animations {
            Supported(value) => value,
            _ => baseline.effective(Key::Animations, true),
        };
        let reduced = match snapshot.reduced_motion {
            Supported(value) => value == ReducedMotion::Reduce,
            _ => baseline.effective(Key::Motion, String::from("no-preference")) == "reduce",
        };
        plan.settings
            .insert(Key::Animations, Some(encoded(&(enabled && !reduced))));
        plan.xsettings.insert(
            "Gtk/EnableAnimations".into(),
            XValue::Integer(i32::from(enabled && !reduced)),
        );
    }

    plan.xsettings.insert(
        "Gdk/WindowScalingFactor".into(),
        XValue::Integer(i32::from(scale)),
    );

    for (key, supported) in [
        (Key::Color, matches!(snapshot.color_scheme, Supported(_))),
        (Key::Font, matches!(snapshot.interface_font, Supported(_))),
        (
            Key::Document,
            matches!(snapshot.document_font, Supported(_)),
        ),
        (
            Key::Monospace,
            matches!(snapshot.monospace_font, Supported(_)),
        ),
        (Key::Scale, matches!(snapshot.text_scale, Supported(_))),
        (
            Key::CursorTheme,
            matches!(snapshot.cursor_theme, Supported(_)),
        ),
        (
            Key::CursorSize,
            matches!(snapshot.cursor_size, Supported(_)),
        ),
        (
            Key::Contrast,
            matches!(snapshot.high_contrast, Supported(_)),
        ),
        (Key::Motion, matches!(snapshot.reduced_motion, Supported(_))),
        (
            Key::Animations,
            matches!(snapshot.enable_animations, Supported(_))
                || matches!(snapshot.reduced_motion, Supported(_)),
        ),
        (
            Key::GtkTheme,
            matches!(snapshot.color_scheme, Supported(_))
                || matches!(snapshot.high_contrast, Supported(_)),
        ),
    ] {
        if supported {
            plan.managed.insert(key);
        }
    }

    plan
}

/// Keep unsupported fields consistent across GTK's XSettings and GSettings readers.
/// Unmanaged native changes refresh the baseline before this mapping is evaluated.
fn local_xsettings(baseline: &Baseline, scale: u16) -> BTreeMap<String, XValue> {
    let text_scale =
        airlock_desktop_preferences::TextScale::new(baseline.effective(Key::Scale, 1.0))
            .map(|value| value.get())
            .unwrap_or(1.0);
    let cursor_size = baseline.effective(Key::CursorSize, 24_i32).clamp(1, 256);
    BTreeMap::from([
        (
            "Gtk/FontName".into(),
            XValue::Text(baseline.effective(Key::Font, "Sans 11".into())),
        ),
        (
            "Net/ThemeName".into(),
            XValue::Text(baseline.effective(Key::GtkTheme, "Adwaita".into())),
        ),
        (
            "Gtk/CursorThemeName".into(),
            XValue::Text(baseline.effective(Key::CursorTheme, "Adwaita".into())),
        ),
        (
            "Gtk/CursorThemeSize".into(),
            XValue::Integer(cursor_size * i32::from(scale)),
        ),
        (
            "Gtk/EnableAnimations".into(),
            XValue::Integer(i32::from(baseline.effective(Key::Animations, true))),
        ),
        (
            "Gdk/UnscaledDPI".into(),
            XValue::Integer((96.0 * text_scale * 1024.0).round() as i32),
        ),
        (
            "Xft/DPI".into(),
            XValue::Integer((96.0 * text_scale * 1024.0 * f64::from(scale)).round() as i32),
        ),
    ])
}
