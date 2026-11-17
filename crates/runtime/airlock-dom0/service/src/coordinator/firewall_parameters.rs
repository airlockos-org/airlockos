//! Read selected and effective native firewall settings through existing status.
//! Missing or stale evidence remains explicit uncertainty; observation starts no VM.

use super::*;

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
}
