# Airlock Rust crates

`crates/` contains Airlock applications, services, shared libraries and configuration
authoring. Together, these turn changes to a machine into something a person can review, approve and follow
through to completion.

Airlock separates work across virtual machines to limit what each part of the
system can access. The applications follow those boundaries, so privileged
machine control, configuration building and user interaction can each have the
access they need. Shared libraries let applications reuse code while keeping
those boundaries explicit.

`runtime/` groups installed applications by their VM responsibilities.
`airlock-common/` holds shared libraries, while `tooling/` holds workstation and
image-build tools. Configuration authoring remains in `airlock-config/`.

Rust application and configuration development belongs here. The separate `airlock-machine` repository
defines how the software is installed and connected into a working machine.

Workstation tools also live here. They support development builds, installation
media and machine recovery, with a separate installation boundary from the
applications running inside VMs.

Runtime reconciliation and test orchestration belong in the Rust service for the
VM or workstation that owns them. Installed shell launchers bind package paths
and pass arguments; upstream Qubes helpers retain their protocol and device roles.
