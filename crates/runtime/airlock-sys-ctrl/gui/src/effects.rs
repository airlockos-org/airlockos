//! User-facing effects derived from the supplied plan, without changing its contents.
use serde_json::Value;
use std::collections::BTreeSet;

/// User-facing VM restart/start/stop and host reboot summary derived from a supplied plan.
pub struct PlannedEffects {
    /// VMs appearing in both stop and start sets.
    pub restarting: Vec<String>,
    /// VMs started without a matching stop in this plan.
    pub starting: Vec<String>,
    /// VMs stopped without a matching start in this plan.
    pub stopping: Vec<String>,
    /// Known host reboot requirement; absent when the plan cannot establish it.
    pub reboot: Option<bool>,
}

impl PlannedEffects {
    /// Summarize restart, start, stop and reboot effects from the supplied plan fields.
    pub fn from_plan(plan: &Value) -> Self {
        let names = |key| {
            plan.get(key)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
        };

        let stop = names("stop");
        let start = names("start");

        Self {
            restarting: stop.intersection(&start).cloned().collect(),
            starting: start.difference(&stop).cloned().collect(),
            stopping: stop.difference(&start).cloned().collect(),
            reboot: plan.get("host_reboot_required").and_then(Value::as_bool),
        }
    }
}

/// Return a readable VM-name summary, including an empty-set description.
pub fn names_text(names: &[String]) -> String {
    if names.is_empty() {
        return "None".to_owned();
    }

    names
        .iter()
        .map(|name| {
            name.chars()
                .flat_map(|character| {
                    if character.is_control() || character == '\\' {
                        character.escape_default().collect::<Vec<_>>()
                    } else {
                        vec![character]
                    }
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Describe VM lifecycle effects and known or unknown host reboot requirements.
pub fn summary(effects: Option<&PlannedEffects>) -> String {
    let Some(effects) = effects else {
        return "VMs restarting: Unknown (no plan)\nSystem reboot: Unknown (no plan)".to_owned();
    };

    let mut lines = vec![format!(
        "VMs restarting: {}",
        names_text(&effects.restarting)
    )];
    for (label, names) in [
        ("VMs starting", &effects.starting),
        ("VMs stopping", &effects.stopping),
    ] {
        if !names.is_empty() {
            lines.push(format!("{label}: {}", names_text(names)));
        }
    }

    let reboot = match effects.reboot {
        Some(true) => "Required",
        Some(false) => "Not required",
        None => "Unknown",
    };
    lines.push(format!("System reboot: {reboot}"));

    lines.join("\n")
}
