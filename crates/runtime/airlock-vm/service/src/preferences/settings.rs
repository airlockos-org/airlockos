//! Preserve only managed GSettings user values; unrelated dconf state is never copied.

use super::state::Paths;
use anyhow::{Result, anyhow, ensure};
use gio::{Settings as NativeSettings, SettingsSchemaSource, glib, prelude::*};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

/// Fixed local keys admitted by the adapter, including GTK's derived theme name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Key {
    Color,
    Font,
    Document,
    Monospace,
    Scale,
    CursorTheme,
    CursorSize,
    Contrast,
    Animations,
    Motion,
    GtkTheme,
}

impl Key {
    /// Complete allowlist used for capture, drift observation, application and restoration.
    pub(super) const ALL: [Self; 11] = [
        Self::Color,
        Self::Font,
        Self::Document,
        Self::Monospace,
        Self::Scale,
        Self::CursorTheme,
        Self::CursorSize,
        Self::Contrast,
        Self::Animations,
        Self::Motion,
        Self::GtkTheme,
    ];

    /// Native schema/key/type, with no remote-selected names.
    pub(super) fn native(self) -> (&'static str, &'static str, &'static str) {
        let (key, kind) = match self {
            Self::Color => ("color-scheme", "s"),
            Self::Font => ("font-name", "s"),
            Self::Document => ("document-font-name", "s"),
            Self::Monospace => ("monospace-font-name", "s"),
            Self::Scale => ("text-scaling-factor", "d"),
            Self::CursorTheme => ("cursor-theme", "s"),
            Self::CursorSize => ("cursor-size", "i"),
            Self::Contrast => ("high-contrast", "b"),
            Self::Animations => ("enable-animations", "b"),
            Self::Motion => ("reduced-motion", "s"),
            Self::GtkTheme => ("gtk-theme", "s"),
        };
        (
            if matches!(self, Self::Contrast | Self::Motion) {
                "org.gnome.desktop.a11y.interface"
            } else {
                "org.gnome.desktop.interface"
            },
            key,
            kind,
        )
    }

    /// Parse a locally stored value with the key's fixed GVariant type.
    pub(super) fn parse(self, text: &str) -> Result<glib::Variant> {
        Ok(glib::Variant::parse(
            Some(glib::VariantTy::new(self.native().2)?),
            text,
        )?)
    }
}

/// The original user override and effective value are separate: reset must preserve schema defaults.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Saved {
    /// None means reset the user key, preserving the system's effective default.
    pub(super) user: Option<String>,
    /// Effective baseline needed when combining supported and unsupported preferences.
    pub(super) effective: String,
}

/// Crash recovery contains local baselines only, never a cached remote desired snapshot.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Baseline {
    /// Journal schema; unknown versions must not drive local writes.
    version: u8,
    /// GUI association under which management began, for local diagnostics.
    pub(super) source: airlock_nix_core::identity::GuestName,
    /// Captured fields from the fixed allowlist, omitting unavailable local schema keys.
    pub(super) values: BTreeMap<Key, Saved>,
    /// Keys currently overridden or awaiting restoration; all others remain user-owned.
    pub(super) managed: BTreeSet<Key>,
}

impl Baseline {
    /// Read a typed effective baseline, with a toolkit default when this schema key is absent.
    pub(super) fn effective<T: glib::variant::FromVariant>(&self, key: Key, fallback: T) -> T {
        self.values
            .get(&key)
            .and_then(|saved| key.parse(&saved.effective).ok())
            .and_then(|value| value.get())
            .unwrap_or(fallback)
    }
}

/// Native handles confined to this guest's session; no host bus address is ever used.
pub(super) struct Settings {
    /// Each supported key points at its schema instance; map keys are the fixed allowlist.
    handles: BTreeMap<Key, NativeSettings>,
}

impl Settings {
    /// Open the guest's installed schemas and normal GSettings backend.
    pub(super) fn new() -> Result<Self> {
        Ok(Self::with_backend(
            SettingsSchemaSource::default().as_ref(),
            None,
        ))
    }

    /// Allow isolated schemas/backends in Cargo tests without modifying the developer's session.
    pub(super) fn with_backend(
        schemas: Option<&SettingsSchemaSource>,
        backend: Option<&gio::SettingsBackend>,
    ) -> Self {
        let mut handles = BTreeMap::new();
        for key in Key::ALL {
            let (schema_name, name, _) = key.native();
            if let Some(schema) = schemas.and_then(|schemas| schemas.lookup(schema_name, true))
                && schema.has_key(name)
            {
                handles.insert(key, NativeSettings::new_full(&schema, backend, None));
            }
        }
        Self { handles }
    }

    /// Connect drift notifications before capturing/reading values, so local edits are reconciled.
    pub(super) fn observe(&self, notify: Rc<dyn Fn()>) {
        for (key, settings) in &self.handles {
            let notify = notify.clone();
            settings.connect_changed(Some(key.native().1), move |_, _| notify());
        }
    }

    /// Save user overrides before the first managed write, and keep defaults separate.
    pub(super) fn capture(&self, source: airlock_nix_core::identity::GuestName) -> Baseline {
        Baseline {
            version: 1,
            source,
            managed: BTreeSet::new(),
            values: self
                .handles
                .iter()
                .map(|(key, settings)| {
                    (
                        *key,
                        Saved {
                            user: settings
                                .user_value(key.native().1)
                                .map(|value| value.print(true).to_string()),
                            effective: settings.value(key.native().1).print(true).to_string(),
                        },
                    )
                })
                .collect(),
        }
    }

    /// Capture a newly managed field at the moment of takeover, preserving intervening local edits.
    pub(super) fn refresh_unmanaged(&self, baseline: &mut Baseline) {
        let current = self.capture(baseline.source.clone());
        for (key, value) in current.values {
            if !baseline.managed.contains(&key) {
                baseline.values.insert(key, value);
            }
        }
    }

    /// Apply independent fields and report any partial failure for convergence retries.
    pub(super) fn apply(&mut self, values: &BTreeMap<Key, Option<String>>) -> Result<Vec<String>> {
        let mut unavailable = Vec::new();
        let mut failures = Vec::new();
        for (key, value) in values {
            let Some(settings) = self.handles.get(key) else {
                unavailable.push(format!("local schema key unavailable: {key:?}"));
                continue;
            };
            let name = key.native().1;
            let result = if let Some(value) = value {
                let value = key.parse(value)?;
                if settings.value(name) == value {
                    Ok(())
                } else {
                    settings
                        .set_value(name, &value)
                        .map_err(anyhow::Error::from)
                }
            } else if settings.user_value(name).is_some() {
                if !settings.is_writable(name) {
                    Err(anyhow!("local key is not writable"))
                } else {
                    settings.reset(name);
                    Ok(())
                }
            } else {
                Ok(())
            };
            if result.is_err() {
                failures.push(format!("cannot apply {key:?}"));
            }
        }
        ensure!(
            failures.is_empty(),
            "{failures}",
            failures = failures.join(", ")
        );
        Ok(unavailable)
    }

    /// Restore the still-managed keys before deleting their durable recovery record.
    pub(super) fn restore_saved(&mut self, paths: &Paths) -> Result<()> {
        if let Some(baseline) = paths.baseline()? {
            ensure!(
                baseline.version == 1,
                "unsupported preferences baseline version"
            );
            let values = baseline
                .values
                .into_iter()
                .filter(|(key, _)| baseline.managed.contains(key))
                .map(|(key, value)| (key, value.user))
                .collect();
            ensure!(
                self.apply(&values)?.is_empty(),
                "baseline schema keys are unavailable; recovery retained"
            );
            // dconf writes are asynchronous. Keep the journal on disk until the
            // backend confirms they are flushed, before any new baseline capture.
            NativeSettings::sync();
            paths.restored()?;
        }
        Ok(())
    }
}

/// Encode only a native typed value, never interpolate remote text into a command.
pub(super) fn encoded(value: &impl glib::variant::ToVariant) -> String {
    value.to_variant().print(true).to_string()
}
