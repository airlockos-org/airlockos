//! Small typed configuration changes exercise the image's offline build inputs.

use anyhow::{Result, bail};
use rusix::{
    interop::NixPath,
    nix_record,
    nixos::{ModuleBody, NixosModule, compile_module},
};
use std::path::Path;

/// A bounded acceptance change applied to an archived personal VM configuration.
#[derive(Clone, Copy)]
pub(crate) enum TrialChange {
    /// Add an ordinary /etc file to require rebuilding the VM system closure.
    EtcMarker,
    /// Change qrexec's startup timeout without adding a package dependency.
    ServiceSetting,
}

impl TrialChange {
    /// Generate a module that imports the archived baseline from the trial's source tree.
    pub(super) fn module(self) -> Result<String> {
        let module = NixosModule::with_arguments(["airlockSupport"], |context| {
            let baseline = context
                .argument::<NixPath>("airlockSupport")
                .join_relative("generated/machine/usr-home-offline-baseline.nix")
                .expect("the baseline path is relative");
            let configuration = match self {
                Self::EtcMarker => nix_record! {
                    "environment": nix_record! { "etc": nix_record! {
                        "airlock-offline-gate": nix_record! { "text": "offline gate marker" },
                    } },
                },
                Self::ServiceSetting => nix_record! {
                    "systemd": nix_record! { "services": nix_record! {
                        "qubes-qrexec-agent": nix_record! { "serviceConfig": nix_record! {
                            "TimeoutStartSec": "90s",
                        } },
                    } },
                },
            };

            ModuleBody::new(configuration).import_value(baseline)
        });

        compile_module(&module)
            .map(|artifact| artifact.module.source)
            .map_err(|diagnostic| anyhow::anyhow!(diagnostic.render(Path::new("."))))
    }
}

impl TryFrom<&str> for TrialChange {
    type Error = anyhow::Error;

    /// Accept only named scenarios with known, bounded configuration changes.
    fn try_from(value: &str) -> Result<Self> {
        match value {
            "etc-marker" => Ok(Self::EtcMarker),
            "service-setting" => Ok(Self::ServiceSetting),
            _ => bail!("unknown offline acceptance scenario: {value}"),
        }
    }
}
