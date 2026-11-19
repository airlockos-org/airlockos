//! Read selected and effective native firewall settings through existing status.
//! Missing or stale evidence remains explicit uncertainty; observation starts no VM.

use super::*;
use airlock_nix_core::runtime::protocol::{
    FIREWALL_SETTINGS_FILE, FIREWALL_SETTINGS_SOURCE, FirewallSettingsUpdate,
};

impl Coordinator {
    /// Read the selected topology and correlate settings with a stable running Xen identity.
    pub(super) fn firewall_parameters_status(&self) -> Result<Value> {
        let release = match self.selection()? {
            Some(selection) => Some(Release::load(selection.release.as_path())?),
            None => self.image_baseline()?.release,
        };
        let Some(release) = release else {
            return Ok(json!({}));
        };
        release.trust()?;
        let mut result = serde_json::Map::new();
        for (name, domain) in &release.topology.domains {
            let Some(parameters) = domain.firewall_parameters()? else {
                continue;
            };
            let selected = domain
                .features
                .contains_key(airlock_firewall_parameters::FEATURE)
                .then_some(parameters);
            let observation = (|| -> Result<Option<airlock_firewall_parameters::Document>> {
                let before = self.runner.text("qvm-prefs", &[name.as_str(), "xid"])?;
                let xid = u32::try_from(before.parse::<i64>()?)
                    .ok()
                    .filter(|xid| *xid > 0);
                let effective = crate::hermit::parameter_observation(name.as_str(), xid)?;
                let after = self.runner.text("qvm-prefs", &[name.as_str(), "xid"])?;
                ensure!(
                    before == after,
                    "firewall Xen identity changed during observation"
                );
                Ok(effective)
            })();
            let mut entry = json!({"selected": selected, "effective": null,
                "pending_restart": null, "activation": "next-vm-start"});
            if settings_source(&release, domain) {
                entry["settings_source"] = json!({
                    "revision": release.manifest.revision,
                    "lock_hash": release.manifest.lock_hash,
                });
            }
            match observation {
                Ok(effective) => {
                    entry["effective"] = serde_json::to_value(effective)?;
                    entry["pending_restart"] = serde_json::to_value(
                        effective
                            .zip(selected)
                            .map(|(effective, selected)| effective != selected),
                    )?;
                }
                Err(error) => entry["observation_error"] = json!(error.to_string()),
            }
            result.insert(name.to_string(), entry);
        }
        Ok(Value::Object(result))
    }

    /// Prepare a reviewed parameter update with the exact artifacts of the selected release.
    pub(crate) fn firewall_settings_candidate(
        &self,
        request: &FirewallSettingsUpdate,
    ) -> Result<ReleasePath> {
        let _guard = MachineLock::acquire(
            &self.state,
            "Firewall settings preparation",
            "Bind reviewed parameters to the selected firewall executable",
            MachineOperation::Candidate,
        )?;
        self.ensure_no_pruning()?;
        let approval = self.approved_review(
            &request.review_authorization,
            &request.candidate.revision,
            &request.candidate.lock_hash,
        )?;
        ensure!(
            matches!(approval.binding.target, ReviewTarget::Machine { .. }),
            "firewall parameter update requires machine source approval"
        );
        let baseline = self.baseline()?;
        baseline.trust()?;
        ensure!(
            baseline.manifest.revision == request.baseline.revision
                && baseline.manifest.lock_hash == request.baseline.lock_hash
                && request.candidate.lock_hash == request.baseline.lock_hash
                && request.candidate.revision != request.baseline.revision
                && baseline.manifest.host == state::host()?,
            "selected baseline differs from the reviewed firewall parameter update"
        );

        let name: GuestName = "sys-firewall".parse()?;
        let before = baseline
            .topology
            .domains
            .get(&name)
            .context("no selected sys-firewall")?;
        ensure!(
            settings_source(&baseline, before)
                && before.firewall_limits()? == Some(request.before)
                && request.before != request.after,
            "reviewed settings differ from the selected firewall document"
        );
        let settings = airlock_firewall_parameters::encode(*request.after.document())
            .map_err(|error| anyhow::anyhow!("invalid firewall settings: {error:?}"))?;
        let mut topology = baseline.raw_topology.clone();
        topology["domains"][name.as_str()]["features"][airlock_firewall_parameters::FEATURE] =
            json!(settings);
        let after = serde_json::from_value(topology.clone())?;
        let running = self.deployment_running()?;
        let plan = planning::plan(&baseline.topology, &after, &running, &[], false)?;
        ensure!(
            plan.changed == std::slice::from_ref(&name)
                && plan.stage.is_empty()
                && plan.retire.is_empty()
                && self
                    .active_trash()?
                    .keys()
                    .all(|name| !after.domains.contains_key(name))
                && plan
                    .firewall_parameters
                    .get(&name)
                    .is_some_and(|change| change.executable_unchanged),
            "firewall request would change more than the selected settings"
        );
        approval.scope.check(&plan)?;

        let mut manifest: Value = state::read(&baseline.path.join("release.json"))?;
        manifest["revision"] = json!(request.candidate.revision);
        manifest["retireDomains"] = json!([]);
        manifest["privateVolumeCopies"] = json!({});
        let path = self.publish_candidate(&manifest, &topology, BTreeMap::new())?;
        ReleasePath::from_path(&path)
    }
}

/// Only full physical releases with the compiler's explicit source declaration can be reused.
fn settings_source(release: &Release, domain: &Domain) -> bool {
    release.manifest.profile.as_str() == "usb-lab"
        && release.manifest.guest_admission.is_none()
        && !release.manifest.extra.contains_key("hostRepair")
        && domain
            .features
            .get(FIREWALL_SETTINGS_SOURCE)
            .and_then(Value::as_str)
            == Some(FIREWALL_SETTINGS_FILE)
        && domain
            .features
            .contains_key(airlock_firewall_parameters::FEATURE)
}
