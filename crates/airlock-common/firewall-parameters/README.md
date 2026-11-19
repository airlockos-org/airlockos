# Firewall startup parameters

This contract lets the machine authoring tools, dom0 and Hermit validate the same
resource settings without pulling packet processing into the host tools. Serde
handles JSON; the typed validator owns the limits and their relationships.

Edit the physical machine's committed
[`firewall-parameters.json`](../../../airlock-machine/firewall-parameters.json)
and submit it through the reviewed machine workflow. When the document is the
only change from the selected source, dom0 prepares a candidate using the
installed release's artifacts. The plan reports the old and new values, the
executable and the VM restart order. Changes to other source files continue
through whole-machine planning. [Deployment workflow](../../../docs/development-operations.md)

Dom0 captures the reviewed document before spawn and publishes it before unpause.
The guest selects it once. Status shows selected and observed effective values;
missing boot evidence is unknown. The resource console record includes effective
settings and compiled ceilings. Normal recovery repeats publication on a fresh VM.

Keep `usr-assistant` on `sys-firewall-old` for recovery. If startup rejects settings,
correct them in the reviewed machine source and apply the resulting plan through
that retained route. A normal subsequent start selects the corrected document.
