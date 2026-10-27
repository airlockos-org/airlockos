use super::*;
use airlock_deployment_core::inventory::{DomainObservation, PowerState, ShutdownObservation};

impl Coordinator {
    /// Retain every Qubes inventory row and probe all active peers before shutdown.
    /// Verus-checked code classifies power states, selects probes and checks the full inventory.
    /// Hard references still come from the protected baseline under the machine lock.
    pub(super) fn shutdown_observation(
        &self,
        baseline: &Topology,
        name: &GuestName,
    ) -> Result<ShutdownObservation> {
        let inventory = self
            .runner
            .text("qvm-ls", &["--raw-data", "--fields", "NAME,STATE"])?;
        let hard = planning::dependencies(baseline, true)?;
        let mut domains = Vec::new();
        for line in inventory.lines() {
            let (live, status) = line
                .split_once('|')
                .context("invalid Qubes runtime inventory")?;
            let guest = if live == "dom0" {
                None
            } else {
                Some(live.parse::<GuestName>()?)
            };
            let mut row = DomainObservation {
                name: live.to_owned(),
                power: PowerState::classify(status),
                gui_provider: None,
                hard_dependent: guest
                    .as_ref()
                    .is_some_and(|live| hard.get(live).is_some_and(|deps| deps.contains(name))),
                declared: guest
                    .as_ref()
                    .is_some_and(|live| baseline.domains.contains_key(live)),
            };
            if row.needs_probe(name.as_str()) {
                row.gui_provider = Some(self.runner.text("qvm-prefs", &[live, "guivm"])?);
            }

            // No activity filter belongs here: the request gate must see every row,
            // including unknown states and peers for which observation is incomplete.
            domains.push(row);
        }

        Ok(ShutdownObservation::new(name.as_str().to_owned(), domains))
    }

    pub(super) fn gui_snapshot(
        &self,
        p: &Plan,
        previous: Option<&BTreeMap<GuestName, GuiSnapshot>>,
    ) -> Result<BTreeMap<GuestName, GuiSnapshot>> {
        let mut snapshots = BTreeMap::new();
        for (provider, clients) in &p.gui_reconnect {
            ensure!(
                provider.as_str() == "sys-gui",
                "GUI preservation only supports sys-gui"
            );

            for name in clients {
                ensure!(
                    self.runner.text("qvm-prefs", &[name.as_str(), "guivm"])? == provider.as_str()
                        && self
                            .runner
                            .text("qvm-features", &[name.as_str(), "airlock-gui-reconnect"])?
                            == "1",
                    "{name}: GUI preservation capability changed"
                );

                let boot_id: BootId = self
                    .runner
                    .text(
                        "qrexec-client",
                        &[
                            "-d",
                            name.as_str(),
                            "user:cat /proc/sys/kernel/random/boot_id",
                        ],
                    )?
                    .parse()?;
                if let Some(old) = previous.and_then(|v| v.get(name)) {
                    ensure!(
                        old.boot_id == boot_id && old.provider == *provider,
                        "{name}: guest restarted during GUI update"
                    );
                }

                snapshots.insert(
                    name.clone(),
                    GuiSnapshot {
                        provider: provider.clone(),
                        boot_id,
                    },
                );
            }
        }

        Ok(snapshots)
    }

    pub(super) fn gui_verify(&self, snapshots: &BTreeMap<GuestName, GuiSnapshot>) -> Result<Value> {
        let mut result = serde_json::Map::new();
        for (name, snapshot) in snapshots {
            let row = self.runner.text(
                "qvm-ls",
                &[
                    "--raw-data",
                    "--fields",
                    "NAME,XID",
                    snapshot.provider.as_str(),
                ],
            )?;
            let (provider, xid) = row.split_once('|').context("invalid GUI Xen identity")?;
            ensure!(
                provider == snapshot.provider.as_str()
                    && !xid.is_empty()
                    && xid.bytes().all(|b| b.is_ascii_digit()),
                "invalid GUI Xen identity"
            );

            let deadline = Instant::now() + Duration::from_secs(180);
            let mut connected = false;
            while Instant::now() < deadline {
                let args = [
                    "-d".into(),
                    name.as_str().into(),
                    "user:cat /proc/sys/kernel/random/boot_id".into(),
                ];
                let time = deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_secs(10));
                if let Ok(boot) = self.runner.run("qrexec-client", &args, time, &[]) {
                    ensure!(
                        boot.parse::<BootId>()? == snapshot.boot_id,
                        "{name}: guest restarted during GUI update"
                    );

                    let args = [
                        "-d".into(),
                        name.as_str().into(),
                        "user:cat /run/qubes/gui-reconnect-status".into(),
                    ];
                    if self
                        .runner
                        .run(
                            "qrexec-client",
                            &args,
                            deadline
                                .saturating_duration_since(Instant::now())
                                .min(Duration::from_secs(10)),
                            &[],
                        )
                        .is_ok_and(|s| s == format!("connected {xid}"))
                    {
                        connected = true;
                        break;
                    }
                }
                thread::sleep(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_secs(1)),
                );
            }

            ensure!(connected, "{name}: GUI reconnection timed out");
            result.insert(name.to_string(),json!({"provider":provider,"boot_id":snapshot.boot_id,"gui_xid":xid,"status":format!("connected {xid}")}));
        }

        Ok(Value::Object(result))
    }
}
