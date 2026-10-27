//! Read the kernel's boot selection before any Nix store programs are available.

use std::{io, path::PathBuf};

/// Kernel-selected system and devices needed to locate its read-only store.
pub(super) struct BootConfig {
    /// NixOS system whose activation and init run after the store becomes available.
    pub system: PathBuf,
    /// Preferred metadata device, tried before the normal Qubes and virtio disk names.
    pub device: Option<String>,
    /// Separate EROFS data device, defaulting to the Qubes store-data disk.
    pub blob_device: String,
    /// Filesystem requested by the kernel arguments; only EROFS is supported.
    pub format: String,
}

impl BootConfig {
    /// Require a system inside the Nix store and preserve the first occurrence of each boot option.
    pub(super) fn parse(cmdline: &str) -> io::Result<Self> {
        let option = |key: &str| {
            cmdline.split_ascii_whitespace().find_map(|token| {
                let (name, value) = token.split_once('=')?;
                (name == key).then_some(value)
            })
        };
        let system = option("airlock.system")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                io::Error::other("missing required kernel option airlock.system=/nix/store/...")
            })?;
        if !system.starts_with("/nix/store/") {
            return Err(io::Error::other(format!(
                "airlock.system must point into /nix/store: {system}"
            )));
        }

        Ok(Self {
            system: system.into(),
            device: option("airlock.storedev")
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
            blob_device: option("airlock.storeblobdev").unwrap_or("/dev/xvdf").into(),
            format: option("airlock.storefmt").unwrap_or("erofs").into(),
        })
    }

    /// Try the explicit metadata device first, retaining the established discovery order otherwise.
    pub(super) fn devices(&self) -> impl Iterator<Item = &str> {
        const FALLBACK: &[&str] = &[
            "/dev/xvde",
            "/dev/xvdf",
            "/dev/xvdg",
            "/dev/xvdh",
            "/dev/xvdi",
            "/dev/xvdj",
            "/dev/xvdk",
            "/dev/xvdl",
            "/dev/vde",
            "/dev/vdf",
            "/dev/vdg",
            "/dev/vdh",
            "/dev/sde",
            "/dev/sdf",
            "/dev/sdg",
            "/dev/sdh",
        ];

        self.device.as_deref().into_iter().chain(
            FALLBACK
                .iter()
                .copied()
                .filter(|device| Some(*device) != self.device.as_deref()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::BootConfig;

    /// Defaults and overrides preserve the kernel interface, including first-match and empty-value behavior.
    #[test]
    fn kernel_options_preserve_device_selection() {
        let default = BootConfig::parse("quiet airlock.system=/nix/store/system").unwrap();
        assert_eq!(default.blob_device, "/dev/xvdf");
        assert_eq!(default.format, "erofs");
        assert_eq!(default.devices().next(), Some("/dev/xvde"));

        let explicit = BootConfig::parse(
            "airlock.system=/nix/store/first airlock.system=/nix/store/second \
             airlock.storedev=/dev/vdg airlock.storeblobdev=/dev/vdh airlock.storefmt=other",
        )
        .unwrap();
        assert_eq!(explicit.system.to_str(), Some("/nix/store/first"));
        assert_eq!(explicit.blob_device, "/dev/vdh");
        assert_eq!(explicit.format, "other");
        let devices: Vec<_> = explicit.devices().collect();
        assert_eq!(&devices[..3], &["/dev/vdg", "/dev/xvde", "/dev/xvdf"]);
        assert_eq!(
            devices
                .iter()
                .filter(|device| **device == "/dev/vdg")
                .count(),
            1
        );

        let empty = BootConfig::parse(
            "airlock.system=/nix/store/system airlock.storedev= airlock.storeblobdev=",
        )
        .unwrap();
        assert_eq!(empty.devices().next(), Some("/dev/xvde"));
        assert!(empty.blob_device.is_empty());
        for invalid in ["", "airlock.system=", "airlock.system=/other/system"] {
            assert!(BootConfig::parse(invalid).is_err());
        }
    }
}
