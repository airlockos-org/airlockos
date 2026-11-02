# Firewall acceptance in the existing Xen lab

This opt-in fixture connects two ordinary Linux frontends through the production
Hermit firewall ELF to Linux DNS, TCP and UDP services. The upstream QubesDB daemon
supplies configuration and policy updates. Xen/QEMU lifecycle and final teardown
remain owned by hermit-xen's existing `xen-lab` controller. These executables are
never installed in production images.

Run the [Rust authoring example](../../../airlock-config/examples/firewall_lab.rs)
with a committed compatible hermit-xen checkout to emit an expression outside Git.
Its `lab`, `peer` and `kernel` attributes supply the immutable lab, Linux controller
and native Hermit archive. Link the production firewall with that archive, then use
`xen-lab test --guest external --no-build`, passing the lab, controller and ELF with
`--lab`, `--peer` and `--kernel`. Supply the upstream vif with
`--vif mac=00:16:3e:00:00:99,script=/etc/xen/scripts/true`, the boot argument
`--cmdline ' -- airlock.boot=12345678-1234-4234-8234-123456789abc'`, and
`--peer-expect AIRLOCK_FIREWALL_LAB_PASS`. The application `--expect` marker is
`AIRLOCK_FIREWALL_EXECUTING scope=dual-stack-experiment forwarding=per-client-gated`.
The fixture checks an explicit IPv4 scope; it does not establish full replacement
compatibility or migrate production clients. The existing lab retains console,
XenStore, toolstack, peer results and QEMU shutdown evidence in its run directory.
