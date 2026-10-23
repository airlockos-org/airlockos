//! Share desktop identities and trusted icon artwork between applications and their packages.
//! These names connect installed desktop files, window classes and notification attribution.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

/// Desktop identity for Airlock's session notifications and background integration.
pub const DESKTOP_ID: &str = "org.airlockos.Desktop";

/// Existing application identity of the first-login setup window.
pub const SETUP_ID: &str = "org.airlockos.Setup";

/// Existing application identity of the controller's review window.
pub const CONTROL_ID: &str = "org.airlock.ctrl";

/// Window class advertised by the assistant's enrollment terminal and its desktop entry.
pub const TAILSCALE_ID: &str = "org.airlockos.Tailscale";

/// Shared full-color icon, resolved through the installed hicolor theme.
pub const ICON_NAME: &str = "org.airlockos.Airlock";

/// Full-color emblem with stronger outlines and arrows for desktop scaling.
pub const ICON_SVG: &str = include_str!("../assets/airlock.svg");

/// Monochrome, pixel-aligned emblem for small sizes and high-contrast themes.
pub const SYMBOLIC_SVG: &str = include_str!("../assets/airlock-symbolic.svg");

/// Transparent raster export used by window systems that accept icon pixels.
pub const ICON_PNG: &[u8] = include_bytes!("../assets/airlock.png");
