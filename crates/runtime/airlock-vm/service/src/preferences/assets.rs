//! Resolve installed assets locally; the remote feed never supplies paths or font files.

use anyhow::Result;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

/// Session-local inventory; installation changes restart the agent through normal machine updates.
pub(super) struct Assets {
    /// Fontconfig family names, normalized for comparison with Pango descriptions.
    families: BTreeSet<String>,
    /// Ordinary local icon roots in which validated cursor identifiers may be looked up.
    icons: Vec<PathBuf>,
}

impl Assets {
    /// Ask native fontconfig for installed families with a finite helper deadline/output bound.
    pub(super) fn discover() -> Result<Self> {
        let output = crate::support::run(
            Command::new("fc-list").arg("--format=%{family}\n"),
            None,
            Duration::from_secs(2),
        )?
        .checked()?;
        let families = String::from_utf8(output)?
            .split([',', '\n'])
            .map(|name| name.trim().to_lowercase())
            .filter(|name| !name.is_empty())
            .collect();
        let mut icons: Vec<_> = std::env::split_paths(
            &std::env::var_os("XDG_DATA_DIRS")
                .unwrap_or_else(|| "/run/current-system/sw/share:/usr/share".into()),
        )
        .map(|path| path.join("icons"))
        .collect();
        if let Some(home) = std::env::var_os("HOME") {
            icons.push(PathBuf::from(&home).join(".icons"));
            icons.push(PathBuf::from(home).join(".local/share/icons"));
        }
        Ok(Self { families, icons })
    }

    /// Use toolkit generic families if font enumeration failed, and report it through fallbacks.
    pub(super) fn empty() -> Self {
        Self {
            families: BTreeSet::new(),
            icons: Vec::new(),
        }
    }

    /// Parse Pango syntax and substitute only unavailable or unsafe-sized font descriptions.
    pub(super) fn font(
        &self,
        requested: &str,
        monospace: bool,
        limitations: &mut Vec<String>,
    ) -> String {
        let mut description = pango::FontDescription::from_string(requested);
        let family = description
            .family()
            .map(|family| family.to_string())
            .unwrap_or_default();
        let generic = matches!(
            family.to_ascii_lowercase().as_str(),
            "sans" | "serif" | "monospace"
        );
        if !generic && !self.families.contains(&family.to_lowercase()) {
            description.set_family(if monospace { "Monospace" } else { "Sans" });
            limitations.push("requested font unavailable; using a local generic family".into());
        }
        if description.size() <= 0 || description.size() > 256 * pango::SCALE {
            description.set_size(11 * pango::SCALE);
            limitations.push("font size unavailable or outside local bounds; using 11pt".into());
        }
        description.to_string().to_string()
    }

    /// Cursor names have already passed the contract's identifier grammar.
    pub(super) fn cursor(&self, requested: &str, limitations: &mut Vec<String>) -> String {
        if self
            .icons
            .iter()
            .any(|root| root.join(requested).join("cursors").is_dir())
        {
            requested.into()
        } else {
            limitations.push(
                "requested cursor theme unavailable; using Adwaita (requires installed assets)"
                    .into(),
            );
            "Adwaita".into()
        }
    }
}
