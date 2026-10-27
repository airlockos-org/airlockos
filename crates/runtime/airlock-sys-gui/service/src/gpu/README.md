# Display-stall recovery

Use only during a confirmed display stall with remote access still working.
From dom0's administrative shell, capture evidence before recovery:

```sh
timeout 20 qrexec-client -d sys-gui 'root:airlock-sys-gui-service gpu capture' </dev/null
```

Request one in-driver recovery:

```sh
timeout 90 qrexec-client -d sys-gui 'root:airlock-sys-gui-service gpu recover --confirm-display-stall' </dev/null
```

If recovery completes but the desktop still does not respond, restart its
display manager once:

```sh
timeout 90 qrexec-client -d sys-gui 'root:airlock-sys-gui-service gpu restart-desktop --confirm-display-stall' </dev/null
```

The last command ends the desktop session. Sign in again and check the physical
screen, pointer, and application-window reconnection. A command returning
success does not establish physical recovery. If an operation fails or times
out, preserve its report and stop rather than escalate or repeat a reset.
Reports are in sys-gui's `/var/log/airlock/gpu-recovery/`.
