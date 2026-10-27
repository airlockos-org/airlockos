//! Describe the application metadata exchanged through Qubes' GetAppmenus service.
//! A receiver validates these fields before using them in its own desktop files.

/// Fields published by the application VM, including commands that receivers must never execute locally.
pub const FIELDS: &[&str] = &[
    "Name",
    "GenericName",
    "Comment",
    "Exec",
    "Icon",
    "StartupWMClass",
    "Categories",
    "Keywords",
    "OnlyShowIn",
    "NotShowIn",
];

/// Application identities are single filenames and fixed Qubes RPC arguments, never paths or shell syntax.
pub fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}
