//! Scheduled, bounded console observations from the native firewall loop.

use airlock_firewall_core::{Engine, parameters};
use airlock_qubes_network::status;

/// Keep each optional resource record well inside dom0's 64 KiB console tail.
const MAX_RESOURCE_REPORT_BYTES: usize = 16 * 1024;

/// Console publication state for one protected boot challenge.
pub(crate) struct Reports<'a> {
    /// Boot identity shared by readiness and resource observations.
    boot: &'a str,
    /// Deadline for the next optional resource sample.
    resources_at: u64,
    /// Deadline for the next unchanged lifecycle heartbeat.
    status_at: u64,
    /// Latest published lifecycle state, so transitions report immediately.
    previous_status: Option<status::Snapshot>,
}

impl<'a> Reports<'a> {
    /// Start with both reports due on the first completed service turn.
    pub(crate) fn new(boot: &'a str) -> Self {
        Self {
            boot,
            resources_at: 0,
            status_at: 0,
            previous_status: None,
        }
    }

    /// Publish a due resource sample followed by fresh lifecycle status.
    /// A dropped optional record still spends its interval. Readiness is the
    /// supplied lifecycle observation, independent of resource pressure.
    pub(crate) fn publish(
        &mut self,
        now: u64,
        engine: &Engine,
        status: status::Snapshot,
        heap_usage: impl FnOnce() -> (usize, usize),
        mut emit: impl FnMut(&str, &str),
    ) -> Result<(), serde_json::Error> {
        let resources_due = now >= self.resources_at;
        if resources_due {
            let interval = u64::from(engine.parameters().report_interval_seconds) * 1_000_000_000;
            self.resources_at = now.saturating_add(interval);
            let resources = engine.resource_snapshot();
            let (requested, peak_requested) = heap_usage();
            let report = airlock_firewall_core::diagnostics::Report {
                schema: "airlock.firewall.resources.v1",
                boot: self.boot,
                at_ns: now,
                settings: engine.parameters(),
                compiled_record_ceiling: parameters::MAX_RECORDS,
                compiled_client_record_ceiling: airlock_firewall_core::CLIENT_FLOWS,
                resources,
                heap_requested_bytes: requested,
                heap_peak_requested_bytes: peak_requested,
                heap_arena_bytes: parameters::APPLICATION_HEAP_BYTES,
            };
            publish_bounded::<MAX_RESOURCE_REPORT_BYTES>(
                "AIRLOCK_FIREWALL_RESOURCES",
                &report,
                &mut emit,
            );
        }

        // Follow resource output with a heartbeat even at the shortest interval.
        if self.previous_status != Some(status) || now >= self.status_at || resources_due {
            let parameters = parameters::BootReport {
                boot: self.boot.to_owned(),
                settings: *engine.parameters(),
            };
            publish_bounded::<{ parameters::MAX_BOOT_REPORT_BYTES }>(
                "AIRLOCK_FIREWALL_PARAMETERS",
                &parameters,
                &mut emit,
            );
            let report = status::Report {
                boot: self.boot.to_owned(),
                snapshot: status,
            };
            emit("AIRLOCK_FIREWALL_STATUS", &serde_json::to_string(&report)?);
            self.previous_status = Some(status);
            self.status_at = now.saturating_add(status::HEARTBEAT_NS);
        }
        Ok(())
    }
}

/// Serialize an optional record with serde and std's fixed slice writer.
/// A partially written record never reaches the console.
fn publish_bounded<const N: usize>(
    prefix: &str,
    report: &impl serde::Serialize,
    emit: &mut impl FnMut(&str, &str),
) {
    let mut storage = [0; N];
    let mut writer = std::io::Cursor::new(storage.as_mut_slice());
    if serde_json::to_writer(&mut writer, report).is_err() {
        log::warn!("operation=firewall-report.publish prefix={prefix} error=serialization_or_size");
        return;
    }
    let length = writer.position() as usize;
    if let Some(json) = storage
        .get(..length)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
    {
        emit(prefix, json);
    } else {
        log::warn!("operation=firewall-report.publish prefix={prefix} error=invalid_output");
    }
}
