//! Typed effective preferences, independent of their GNOME and toolkit adapters.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Whether the source can supply one preference, independently of its value.
///
/// Every field must be present on the wire. `Unsupported` tells the consumer to
/// remove its managed override and restore its local baseline. It does not mean
/// disconnected, unchanged, or the user's explicit no-preference choice.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Setting<T> {
    /// The source lacks this preference; restore only this managed field.
    #[default]
    Unsupported,
    /// The source's effective value, including a default obtained after a reset.
    Supported(
        /// Validated preference to apply through the local toolkit adapter.
        T,
    ),
}

/// Preferred application color scheme, without selecting arbitrary theme assets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ColorScheme {
    /// Follow the application's baseline appearance; this is a supported value.
    NoPreference,
    /// Prefer the application's dark appearance.
    PreferDark,
    /// Prefer the application's light appearance.
    PreferLight,
}

/// Motion preference separate from the user's animation enable switch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReducedMotion {
    /// No request to reduce motion; the animation preference still applies.
    NoPreference,
    /// Request reduced motion, even when animations are otherwise enabled.
    Reduce,
}

/// A complete replacement of the preferences managed by this subscription.
///
/// All fields are required when decoding, including unsupported ones. Equal
/// snapshots are duplicate desired state and can be skipped by consumers. The
/// default snapshot declares every field unsupported; it is not a disconnect
/// fallback and must not replace the last valid snapshot on transport failure.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    /// Application appearance preference, distinct from high contrast.
    pub color_scheme: Setting<ColorScheme>,
    /// Font description for ordinary application interface text.
    pub interface_font: Setting<FontName>,
    /// Font description for document surfaces that follow the desktop preference.
    pub document_font: Setting<FontName>,
    /// Font description for system-following fixed-width text surfaces.
    pub monospace_font: Setting<FontName>,
    /// Text-only scale multiplier; physical and integer window scaling remain local.
    pub text_scale: Setting<TextScale>,
    /// Installed cursor theme identifier; the protocol carries no theme files.
    pub cursor_theme: Setting<CursorTheme>,
    /// Logical cursor size before the VM's existing integer window scale.
    pub cursor_size: Setting<CursorSize>,
    /// Whether supporting applications should use their high contrast appearance.
    pub high_contrast: Setting<bool>,
    /// User animation preference, independently of reduced motion.
    pub enable_animations: Setting<bool>,
    /// Accessibility request that adapters combine with the animation preference.
    pub reduced_motion: Setting<ReducedMotion>,
}

/// A preference outside the contract's accepted representation or bounds.
///
/// Errors identify the setting category without copying untrusted input into logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueError {
    /// A font description is empty, too long, padded, or contains control characters.
    FontName,
    /// A cursor theme exceeds its identifier grammar or length limit.
    CursorTheme,
    /// Text scale is non-finite or outside the supported GNOME range.
    TextScale,
    /// Logical cursor size is outside the supported pixel range.
    CursorSize,
}

impl fmt::Display for ValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::FontName => "font must be 1–256 UTF-8 bytes without padding or control characters",
            Self::CursorTheme => "cursor theme must be 1–64 ASCII identifier bytes beginning with an alphanumeric character",
            Self::TextScale => "text scale must be finite and between 0.5 and 3.0",
            Self::CursorSize => "cursor size must be between 1 and 256 logical pixels",
        })
    }
}

impl std::error::Error for ValueError {}

/// A bounded font description consumed by the guest's native font APIs.
///
/// Accepts 1–256 UTF-8 bytes without leading/trailing whitespace or control
/// characters. This validates transport safety, not Pango syntax or installed
/// font availability. Adapters must escape configuration syntax themselves and
/// must never interpret a description as a shell command or filesystem path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct FontName {
    /// Validated description, preserved exactly for native font lookup.
    value: String,
}

impl FontName {
    /// Validate a font description, returning [`ValueError::FontName`] on failure.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        Self::try_from(value.into())
    }

    /// Borrow the original validated description.
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl TryFrom<String> for FontName {
    type Error = ValueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty()
            || value.len() > 256
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(ValueError::FontName);
        }

        Ok(Self { value })
    }
}

impl From<FontName> for String {
    fn from(font: FontName) -> Self {
        font.value
    }
}

/// An installed cursor theme identifier, never a path or transferred asset.
///
/// Accepts 1–64 ASCII bytes: an alphanumeric first character followed by
/// alphanumerics, dots, underscores or hyphens. Asset availability is local
/// policy and is not established by successful validation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CursorTheme {
    /// Validated name used to look up an already installed theme.
    value: String,
}

impl CursorTheme {
    /// Validate a theme identifier, returning [`ValueError::CursorTheme`] on failure.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        Self::try_from(value.into())
    }

    /// Borrow the validated theme identifier.
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl TryFrom<String> for CursorTheme {
    type Error = ValueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty()
            || value.len() > 64
            || !value.as_bytes()[0].is_ascii_alphanumeric()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return Err(ValueError::CursorTheme);
        }

        Ok(Self { value })
    }
}

impl From<CursorTheme> for String {
    fn from(theme: CursorTheme) -> Self {
        theme.value
    }
}

/// A finite text-only scale factor in GNOME's supported range, 0.5 through 3.0.
///
/// ```
/// use airlock_desktop_preferences::TextScale;
/// let scale = TextScale::new(1.25)?;
/// assert_eq!(scale.get(), 1.25);
/// assert!(TextScale::new(f64::NAN).is_err());
/// # Ok::<(), airlock_desktop_preferences::ValueError>(())
/// ```
///
/// Construction cannot bypass validation:
///
/// ```compile_fail
/// use airlock_desktop_preferences::TextScale;
/// let scale = TextScale { value: f64::NAN };
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "f64", into = "f64")]
pub struct TextScale {
    /// Finite multiplier, independent of physical monitor and integer window scale.
    value: f64,
}

impl TextScale {
    /// Validate the multiplier, rejecting non-finite and out-of-range values.
    pub fn new(value: f64) -> Result<Self, ValueError> {
        if !value.is_finite() || !(0.5..=3.0).contains(&value) {
            return Err(ValueError::TextScale);
        }

        Ok(Self { value })
    }

    /// Return the validated text-only multiplier.
    pub fn get(self) -> f64 {
        self.value
    }
}

impl TryFrom<f64> for TextScale {
    type Error = ValueError;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<TextScale> for f64 {
    fn from(scale: TextScale) -> Self {
        scale.value
    }
}

/// A logical cursor size from 1 through 256 pixels, before integer window scaling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct CursorSize {
    /// Nonzero logical size capped before multiplication by the local window scale.
    value: u16,
}

impl CursorSize {
    /// Validate a logical size, returning [`ValueError::CursorSize`] outside 1–256.
    pub fn new(value: u16) -> Result<Self, ValueError> {
        if !(1..=256).contains(&value) {
            return Err(ValueError::CursorSize);
        }

        Ok(Self { value })
    }

    /// Return the validated logical pixel size.
    pub fn get(self) -> u16 {
        self.value
    }
}

impl TryFrom<u16> for CursorSize {
    type Error = ValueError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<CursorSize> for u16 {
    fn from(size: CursorSize) -> Self {
        size.value
    }
}
