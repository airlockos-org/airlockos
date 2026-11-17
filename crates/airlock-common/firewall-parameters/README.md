# Firewall startup parameters

This contract lets the machine authoring tools, dom0 and Hermit validate the same
resource settings without pulling packet processing into the host tools. Serde
handles JSON; the typed validator owns the limits and their relationships.

Edit the firewall's `set_firewall_parameters` call in the machine's
[src/machine.rs](../../../airlock-machine/src/machine.rs), then use the existing
reviewed [machine deployment workflow](../../../docs/development-operations.md).
The plan shows old/new values, restart impact and executable reuse. Tuning these
values changes topology metadata independently of the projected Hermit sources;
normal machine planning and configuration work still applies.

Dom0 captures the reviewed document before spawn and publishes it before unpause.
The guest selects it once. Status shows selected and observed effective values;
missing boot evidence is unknown. The resource console record includes effective
settings and compiled ceilings. Normal recovery repeats publication on a fresh VM.

Keep `usr-assistant` on `sys-firewall-old` for recovery. If startup rejects settings,
correct them in the reviewed machine source and apply the resulting plan through
that retained route. A normal subsequent start selects the corrected document.
