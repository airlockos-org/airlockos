//! Capture admitted host resources before publication and execute only typed host requests.
//! Store/Nix/Qubes boot adapters remain responsible for faithful execution and persistence.

use super::*;
use airlock_deployment_core::host::{Action, CheckedGeneration, Definition, HostRequest};

/// Retain the existing recovery/controller policy without consulting environment at effect dispatch.
pub(super) fn definition(release: &Release, recovery: bool) -> Result<Definition> {
    let service = std::env::var("AIRLOCK_DOM0_SERVICE")
        .map(PathBuf::from)
        .unwrap_or(std::env::current_exe()?);
    let controller = if !recovery && let Some(program) = &release.manifest.coordinator {
        let path = PathBuf::from(program.as_str());
        ensure!(
            path.file_name()
                .is_some_and(|n| n == "airlock-dom0-service"),
            "release does not select the native dom0 service"
        );
        path
    } else {
        service.clone()
    };
    let controller_root = if controller.starts_with("/nix/store") {
        controller
            .components()
            .take(4)
            .collect::<PathBuf>()
            .to_str()
            .context("invalid controller store root")?
            .to_owned()
    } else {
        String::new()
    };
    let expected = release
        .manifest
        .extra
        .get("hostPool")
        .map(|record| -> Result<_> {
            serde_json::from_value::<crate::store::HostReceipt>(record.clone())?.observation()
        })
        .transpose()?;
    Ok(Definition {
        expected,
        host: release.manifest.host.as_str().into(),
        transport: release
            .manifest
            .source_release
            .as_ref()
            .unwrap_or(&release.manifest.host)
            .as_str()
            .into(),
        controller: controller
            .to_str()
            .context("invalid native controller path")?
            .into(),
        controller_root,
        service: service
            .to_str()
            .context("invalid native storage adapter path")?
            .into(),
    })
}

impl Coordinator {
    /// Retain the typed publication/validation result under its exact authorised request.
    pub(super) fn host_generation(&self, request: HostRequest<'_>) -> Result<CheckedGeneration> {
        ensure!(
            matches!(request.action(), Action::Publish | Action::Validate),
            "host observation requires publication or validation"
        );

        let output = self.runner.host_deployment(&request, "")?;
        let receipt: crate::store::HostReceipt =
            airlock_nix_core::state::parse_json(output.as_bytes(), Path::new("<host-response>"))?;

        request
            .checked(receipt.observation()?)
            .context("host generation differs from the authorised candidate or prepared record")
    }

    /// The privileged boundary has no independently supplied host, operation or program argument.
    pub(super) fn host_effect(&self, request: HostRequest<'_>) -> Result<()> {
        let action = request.action();
        ensure!(
            !matches!(action, Action::Publish | Action::Validate),
            "host publication must retain its checked result"
        );

        if matches!(action, Action::InstallController) {
            let executable = Path::new(request.target());
            if executable.starts_with("/nix/store") {
                let link = self.state.join("controller.new");
                state::unlink(&link)?;
                std::os::unix::fs::symlink(executable, &link)?;
                fs::rename(&link, self.state.join("controller"))?;
                fs::File::open(&self.state)?.sync_all()?;
            }
            return Ok(());
        }
        if matches!(action, Action::PinController) && request.target().is_empty() {
            return Ok(());
        }

        let roots = self.state.join("roots");
        let root = match action {
            Action::PinHost => roots.join(format!("host-{attempt}", attempt = request.attempt())),
            Action::PinTransport => {
                roots.join(format!("transport-{attempt}", attempt = request.attempt()))
            }
            Action::PinController => roots.join("dom0-service"),
            _ => PathBuf::new(),
        };
        if !root.as_os_str().is_empty() {
            state::directory(&roots)?;
        }
        self.runner.host_deployment(
            &request,
            root.to_str().context("invalid retention root path")?,
        )?;
        Ok(())
    }
}
