//! Keep preparation, generation changes, retention and rollback in one explicit scenario order.

use super::generations::{apply, contains, declaration, pool, restore, shutdown};
use super::probes::{Boot, guest, images, libvirt, ready, sharing, visibility};
use super::{Session, common, text};
use super::{report, settings::Scenario};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{fs, process::Command, thread, time::Duration};

/// First-generation observations remain available while the primary changes and the peer keeps running.
struct InitialGeneration {
    /// Primary identity that rollback must restore exactly.
    primary: Boot,
    /// Peer identity that must remain usable through publication and collection.
    peer: Boot,
    /// Initial object-sharing evidence needed to protect common bytes during collection.
    sharing: Value,
}

impl Scenario {
    /// Execute each phase in order; the caller retains diagnostics and the receipt on any error.
    pub(super) fn run(&self, session: &mut Session, record: &mut Value) -> Result<()> {
        self.prepare(session)?;
        let initial = self.first_generation(session)?;
        let marker = self.persist_marker(session)?;

        let second = self.second_generation(session, &initial)?;
        self.protect_running_generation(session, &second)?;

        let restored = self.rollback(session, &initial, &second)?;
        self.restart_probes(session, record, &restored, &marker)?;
        self.gui_probe(session, record)?;

        report::boot_identity(record, &restored);
        Ok(())
    }

    /// Check the control domain and prepare only the selected application mode.
    fn prepare(&self, session: &mut Session) -> Result<()> {
        let mode = self.mode.as_str();
        let staging = self.staging.as_str();
        let validator = self.validator.as_str();
        let vault = self.vault.as_str();

        session.control_domain()?;
        for target in [staging, validator, vault] {
            session.command("qvm-check", &[target], "nix-closure-domain-role-exists.log")?;
        }
        if mode == "config-flow" {
            for target in [staging, validator, vault] {
                shutdown(session, target, "nix-closure-domain-config-shutdown.log")?;
                let prefix = if target == validator {
                    "AIRLOCK_NIX_CLOSURE_VALIDATOR"
                } else {
                    "AIRLOCK_NIX_CLOSURE_CONFIG_VM"
                };
                let default = if target == validator { "1024" } else { "512" };
                for property in ["memory", "maxmem"] {
                    session.command(
                        "qvm-prefs",
                        &[
                            target,
                            property,
                            &common::setting(
                                &format!("{prefix}_{upper}", upper = property.to_ascii_uppercase()),
                                default,
                            ),
                        ],
                        "nix-closure-domain-config-memory.log",
                    )?;
                }
                session.start(target)?;
                ready(session, target, "nix-closure-domain-config-qrexec.log")?;
            }
            session.remote(
                staging,
                "airlock-config-staging-init",
                &[],
                None,
                "nix-closure-domain-staging-init.log",
            )?;
            session.remote(
                validator,
                "airlock-config-validator-init",
                &[],
                None,
                "nix-closure-domain-validator-init.log",
            )?;
        } else {
            for (key, default) in [
                (
                    "AIRLOCK_NIX_CLOSURE_DIRECT_PRIMARY_SOURCE_VM",
                    "sys-config-staging",
                ),
                (
                    "AIRLOCK_NIX_CLOSURE_DIRECT_PEER_SOURCE_VM",
                    "sys-config-validator",
                ),
                (
                    "AIRLOCK_NIX_CLOSURE_DIRECT_GEN2_SOURCE_VM",
                    "sys-config-vault",
                ),
            ] {
                declaration(session, &common::setting(key, default), "green")?;
            }
        }
        Ok(())
    }

    /// Apply and observe both initial guests before changing any generation.
    fn first_generation(&self, session: &mut Session) -> Result<InitialGeneration> {
        let domain = self.domain.as_str();
        let peer = self.peer.as_str();
        let mode = self.mode.as_str();
        let staging = self.staging.as_str();
        let message = self.message.as_str();
        let role = self.role.as_str();

        shutdown(
            session,
            domain,
            "nix-closure-domain-primary-pre-apply-shutdown.log",
        )?;
        shutdown(
            session,
            peer,
            "nix-closure-domain-peer-pre-apply-shutdown.log",
        )?;
        let applied = apply(session, domain, peer, false, mode, staging, message)?;
        ensure!(
            applied["schema"] == "airlock.config-apply.v1"
                && applied["status"] == "passed"
                && applied["setup"]["status"] == "passed",
            "closure apply failed"
        );
        self.validate_materialization(session, &applied)?;

        let initial = Boot::observe(session, domain)?;
        let peer_boot = Boot::observe(session, peer)?;
        let options = session.command(
            "qvm-prefs",
            &[domain, "kernelopts"],
            "nix-closure-domain-kernelopts.log",
        )?;
        let options = common::fields(&options.split_whitespace().collect::<Vec<_>>().join("\n"));
        for (key, expected) in [
            ("init", "/sbin/init"),
            ("airlock.system", initial.system.as_str()),
            ("airlock.storedev", initial.device.as_str()),
            ("airlock.storefmt", initial.filesystem.as_str()),
            ("airlock.storeblobdev", initial.blob.as_str()),
        ] {
            ensure!(
                options.get(key).map(String::as_str) == Some(expected),
                "kernelopts do not match {key}"
            );
        }

        let proof = sharing(session, domain, peer, (&initial, &peer_boot), false)?;
        images(session, domain, &initial)?;

        for (target, boot) in [(domain, &initial), (peer, &peer_boot)] {
            session.start(target)?;
            ready(session, target, "nix-closure-domain-qrexec.log")?;
            libvirt(
                session,
                target,
                if target == domain {
                    "nix-closure-domain-libvirt.xml"
                } else {
                    "nix-closure-domain-peer-libvirt.xml"
                },
            )?;
            boot.runtime(
                session,
                target,
                if target == domain {
                    "nix-closure-domain-runtime-service.log"
                } else {
                    "nix-closure-domain-peer-runtime-service.log"
                },
            )?;
        }
        guest(
            session,
            domain,
            &initial,
            role,
            (mode == "config-flow").then_some(message),
            "nix-closure-domain-guest-probe.log",
        )?;
        visibility(
            session,
            domain,
            text(&proof, "left_unique_object")?,
            text(&proof, "right_unique_object")?,
            text(&proof, "shared_object")?,
            "nix-closure-domain-visibility.log",
        )?;
        visibility(
            session,
            peer,
            text(&proof, "right_unique_object")?,
            text(&proof, "left_unique_object")?,
            text(&proof, "shared_object")?,
            "nix-closure-domain-peer-visibility.log",
        )?;

        Ok(InitialGeneration {
            primary: initial,
            peer: peer_boot,
            sharing: proof,
        })
    }

    /// Require both native VM materializations, store volumes and the exact runtime policy.
    fn validate_materialization(&self, session: &mut Session, applied: &Value) -> Result<()> {
        let domain = self.domain.as_str();
        let peer = self.peer.as_str();

        for target in [domain, peer] {
            ensure!(
                applied["nix_domain_materializations_result"]["domains"]
                    .as_array()
                    .is_some_and(|entries| entries.iter().any(|entry| entry["domain"] == target)),
                "apply omitted materialization for {target}"
            );
            let classes = session.command(
                "qvm-ls",
                &["--raw-data", "--fields", "NAME,CLASS"],
                "nix-closure-domain-classes.log",
            )?;
            ensure!(
                classes
                    .lines()
                    .any(|line| line == format!("{target}|StandaloneVM")),
                "{target} is not a StandaloneVM"
            );
            let volumes = session.command(
                "qvm-volume",
                &["list", target],
                "nix-closure-domain-volume-list.log",
            )?;
            for volume in ["store", "store-data"] {
                session.command(
                    "qvm-volume",
                    &["info", &format!("{target}:{volume}")],
                    "nix-closure-domain-store-volume.log",
                )?;
                ensure!(
                    common::has_volume(&volumes, volume),
                    "volume list omits {target}:{volume}"
                );
            }
        }
        let policy = fs::read_to_string(common::path(
            "AIRLOCK_POLICY_FILE",
            "/var/lib/airlock/qubes-policy.d/90-airlock.policy",
        ))?;
        for rule in [
            format!("airlock.NixStoreRuntimeCheck * dom0 {domain} allow"),
            format!("airlock.NixStoreRuntimeCheck * dom0 {peer} allow"),
            "airlock.NixStoreRuntimeCheck * @anyvm @anyvm deny".into(),
        ] {
            ensure!(
                policy.lines().any(|line| line == rule),
                "runtime policy omits {rule}"
            );
        }
        Ok(())
    }

    /// Write the initial message into private storage before changing the primary generation.
    fn persist_marker(&self, session: &mut Session) -> Result<String> {
        let domain = self.domain.as_str();
        let message = self.message.as_str();

        let user = common::setting("AIRLOCK_QUBE_USER", "user");
        let marker = format!("/home/{user}/airlock-closure-smoke-persistent");
        session.remote(
            domain,
            "tee",
            &[&marker],
            Some(message.as_bytes().to_vec()),
            "nix-closure-domain-persistence.log",
        )?;

        Ok(marker)
    }

    /// Publish a different primary generation, verify object reuse and keep the peer available.
    fn second_generation(
        &self,
        session: &mut Session,
        initial: &InitialGeneration,
    ) -> Result<Boot> {
        let domain = self.domain.as_str();
        let peer = self.peer.as_str();
        let mode = self.mode.as_str();
        let staging = self.staging.as_str();
        let second_message = self.second_message.as_str();
        let role = self.role.as_str();

        let peer_boot = &initial.peer;
        let initial = &initial.primary;

        let before = pool(
            session,
            &["status"],
            "nix-closure-domain-status-before.json",
        )?["segment_bytes_total"]
            .as_u64()
            .context("missing pool byte count")?;
        shutdown(session, domain, "nix-closure-domain-gen2-pre-shutdown.log")?;
        let applied = apply(session, domain, peer, true, mode, staging, second_message)?;
        ensure!(
            applied["status"] == "passed",
            "second generation apply failed"
        );
        let second = Boot::observe(session, domain)?;
        ensure!(
            second.generation != initial.generation,
            "second apply did not change generation"
        );
        let mut proof2 = sharing(session, domain, peer, (&second, peer_boot), true)?;
        let after = pool(
            session,
            &["status"],
            "nix-closure-domain-status-after.json",
        )?["segment_bytes_total"]
            .as_u64()
            .context("missing pool byte count")?;
        let added = after
            .checked_sub(before)
            .context("pool size decreased unexpectedly during second publication")?;
        ensure!(
            added
                < proof2["left_logical_size"]
                    .as_u64()
                    .context("missing logical size")?,
            "second generation rewrote too much object data"
        );
        for (key, value) in [
            ("initial_generation", json!(initial.generation)),
            ("new_generation", json!(second.generation)),
            ("segment_bytes_before", json!(before)),
            ("segment_bytes_after", json!(after)),
            ("physical_bytes_added_for_new_generation", json!(added)),
            ("existing_object_reuse_verified", json!(true)),
        ] {
            proof2[key] = value;
        }
        common::save(
            &session.file("nix-closure-domain-sharing-proof-gen2.json"),
            &proof2,
        )?;

        session.start(domain)?;
        ready(session, domain, "nix-closure-domain-qrexec-gen2.log")?;
        libvirt(session, domain, "nix-closure-domain-libvirt.xml")?;
        second.runtime(session, domain, "nix-closure-domain-runtime-service.log")?;
        guest(
            session,
            domain,
            &second,
            role,
            (mode == "config-flow").then_some(second_message),
            "nix-closure-domain-guest-probe.log",
        )?;
        ready(
            session,
            peer,
            "nix-closure-domain-peer-qrexec-after-gen2.log",
        )?;
        peer_boot.runtime(session, peer, "nix-closure-domain-peer-runtime-service.log")?;

        Ok(second)
    }

    /// Require both running volume references and prove collection retains their generation.
    fn protect_running_generation(&self, session: &mut Session, second: &Boot) -> Result<()> {
        let domain = self.domain.as_str();

        let running = pool(
            session,
            &["status"],
            "nix-closure-domain-running-status.json",
        )?;
        for volume in ["store", "store-data"] {
            ensure!(
                running["running"]
                    .as_array()
                    .is_some_and(|entries| entries
                        .iter()
                        .any(|entry| entry["domain"] == format!("{domain}-runtime-store")
                            && entry["generation"] == second.generation
                            && entry["volume"] == volume)),
                "running references omit {volume}"
            );
        }

        let gc = pool(
            session,
            &["gc", "--keep-generations", "0"],
            "nix-closure-domain-gc-running.json",
        )?;
        ensure!(
            contains(&gc, "running_generations", domain, second.generation)
                && contains(&gc, "retained_generations", domain, second.generation)
                && !contains(&gc, "removed_generations", domain, second.generation)
                && gc["stale_running_refs"]
                    .as_array()
                    .is_some_and(Vec::is_empty),
            "GC did not protect running generation"
        );
        Ok(())
    }

    /// Restore the initial generation before releasing and collecting the newer one.
    fn rollback(
        &self,
        session: &mut Session,
        initial: &InitialGeneration,
        second: &Boot,
    ) -> Result<Boot> {
        let domain = self.domain.as_str();
        let mode = self.mode.as_str();
        let message = self.message.as_str();
        let role = self.role.as_str();

        let proof = &initial.sharing;
        let initial = &initial.primary;

        shutdown(
            session,
            domain,
            "nix-closure-domain-rollback-pre-shutdown.log",
        )?;
        restore(session, domain, initial.generation)?;
        pool(
            session,
            &[
                "set-retention",
                "--domain",
                &format!("{domain}-runtime-store"),
                "--generation",
                &second.generation.to_string(),
                "--retain",
                "false",
            ],
            "nix-closure-domain-set-retention-gen2.json",
        )?;
        let gc = pool(
            session,
            &["gc", "--keep-generations", "0"],
            "nix-closure-domain-gc-after-rollback.json",
        )?;
        ensure!(
            contains(&gc, "removed_generations", domain, second.generation)
                && gc["removed_object_blobs"]
                    .as_array()
                    .is_some_and(|entries| !entries
                        .iter()
                        .any(|entry| entry == &proof["shared_object"])),
            "GC failed to collect unreferenced generation or removed shared data"
        );

        let restored = Boot::observe(session, domain)?;
        ensure!(
            restored.generation == initial.generation,
            "rollback selected wrong generation"
        );

        session.start(domain)?;
        ready(
            session,
            domain,
            "nix-closure-domain-qrexec-after-rollback.log",
        )?;
        libvirt(session, domain, "nix-closure-domain-libvirt.xml")?;
        restored.runtime(session, domain, "nix-closure-domain-runtime-service.log")?;
        guest(
            session,
            domain,
            &restored,
            role,
            (mode == "config-flow").then_some(message),
            "nix-closure-domain-guest-probe-after-rollback.log",
        )?;

        Ok(restored)
    }

    /// Verify optional reboot and mandatory restart preserve the restored identity and private marker.
    fn restart_probes(
        &self,
        session: &mut Session,
        record: &mut Value,
        restored: &Boot,
        marker: &str,
    ) -> Result<()> {
        let domain = self.domain.as_str();
        let mode = self.mode.as_str();
        let message = self.message.as_str();
        let role = self.role.as_str();

        if self.reboot {
            session.remote(
                domain,
                "systemctl",
                &["reboot"],
                None,
                "nix-closure-domain-reboot.log",
            )?;
            thread::sleep(Duration::from_secs(8));
            session.start(domain)?;
            guest(
                session,
                domain,
                restored,
                role,
                (mode == "config-flow").then_some(message),
                "nix-closure-domain-guest-probe-after-reboot.log",
            )?;
            restored.runtime(session, domain, "nix-closure-domain-runtime-service.log")?;
            record["reboot_status"] = json!("passed");
        } else {
            record["reboot_status"] = json!("skipped");
        }
        shutdown(session, domain, "nix-closure-domain-shutdown.log")?;
        session.start(domain)?;
        guest(
            session,
            domain,
            restored,
            role,
            (mode == "config-flow").then_some(message),
            "nix-closure-domain-guest-probe-after-restart.log",
        )?;
        ensure!(
            session.remote(
                domain,
                "cat",
                &[marker],
                None,
                "nix-closure-domain-persistence.log"
            )? == message,
            "private marker did not survive restart"
        );
        record["shutdown_start_status"] = json!("passed");
        Ok(())
    }

    /// Run the optional installed graphical helper after the restored guest passes restart checks.
    fn gui_probe(&self, session: &mut Session, record: &mut Value) -> Result<()> {
        let domain = self.domain.as_str();

        if self.gui {
            let helper = common::setting("AIRLOCK_GUI_SMOKE_COMMAND", "airlock-qube-gui-smoke");
            if std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                .any(|directory| directory.join(&helper).is_file())
            {
                session.run(
                    Command::new(helper).env("AIRLOCK_TEST_QUBE", domain),
                    None,
                    "nix-closure-domain-gui.log",
                )?;
                record["gui_status"] = json!("passed");
            }
        }
        Ok(())
    }
}
