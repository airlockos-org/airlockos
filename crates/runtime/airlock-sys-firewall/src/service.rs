//! Single-task native scheduling. Each turn services a bounded number of control
//! events, four client owners and upstream frames, then returns to a timed wait.
//! No Linux processes, lab transport, qrexec service or deployment role is added.

use airlock_boot_core::Challenge;
use airlock_firewall_core::{Engine, MAX_CLIENTS, Output, Owner, Target};
use airlock_hermit_control::xen::{Certificate, Event, Pending, Session};
use xen_transport::hermit::{
    endpoint,
    netback::{Netback, Status},
    netfront::Netfront,
    poweroff::Poweroff,
    store,
};

/// Match the native network driver's bounded XenStore exchange budget. Watch
/// polling can issue an actual round trip to drain queued events; its deadline
/// must allow daemon scheduling independently of the maintenance wake interval.
const CONTROL_TIMEOUT_NS: u64 = 500_000_000;

/// Fatal errors preserve uncertain native resources until VM teardown. No
/// failure path fabricates a replacement connection or retries ambiguous closes.
#[derive(Debug)]
pub enum Error {
    /// Existing native control adapter rejected the original session.
    Control(
        /// Original error code, without policy data.
        airlock_hermit_control::xen::Error,
    ),
    /// Native networking or XenStore operation failed.
    Transport(
        /// Original error code, without packet contents.
        xen_transport::Error,
    ),
    /// Native directory/backend metadata was malformed or outside capacity.
    Discovery,
    /// The core rejected a clock/control transition or ownership reservation.
    State,
}

impl From<airlock_hermit_control::xen::Error> for Error {
    /// Preserve the control failure without treating it as a recoverable packet drop.
    fn from(error: airlock_hermit_control::xen::Error) -> Self {
        Self::Control(error)
    }
}

impl From<xen_transport::Error> for Error {
    /// Preserve native resource uncertainty; caller terminates the guest.
    fn from(error: xen_transport::Error) -> Self {
        Self::Transport(error)
    }
}

/// Admission cannot represent independent ready/pending flags.
enum Admission {
    /// Native interface exists but no current complete barrier has succeeded.
    Waiting,
    /// Exactly one native barrier is outstanding for this owner.
    Barrier(
        /// Original consuming request, not a copied serial.
        Pending,
    ),
    /// Exact completed barrier associated with this native interface.
    Ready(
        /// Non-cloneable original certificate.
        Certificate,
    ),
}

/// Actual owned backend and its inseparable admission state.
struct Client {
    /// Sole native handle for this original peer/interface incarnation.
    interface: Netback,
    /// Barrier state; packet processing requires Ready plus a current Permit.
    admission: Admission,
    /// Last admitted labels retained through re-admission for exact retirement.
    owner: Option<Owner>,
    /// Revision at which admission was last completed or reset.
    revision: u64,
}

/// Start the existing dom0 QubesDB session and the toolstack-owned upstream vif.
/// Progress requires cooperative native scheduling, reciprocal XenStore records,
/// grant revocation and a monotonic clock. No dynamic service authority is added.
pub fn run(challenge: Challenge, seed: [u8; 32]) -> Result<(), Error> {
    let boot = core::str::from_utf8(challenge.as_bytes())
        .map_err(|_| Error::State)?
        .to_owned();
    let mut control = Session::open(challenge)?;
    let mut poweroff = Poweroff::new(endpoint::now_ns().saturating_add(CONTROL_TIMEOUT_NS))?;
    let mut scratch = [0; 4096];
    let deadline = endpoint::now_ns().saturating_add(5_000_000_000);
    let length = store::value("device/vif/0/backend-id", &mut scratch, deadline)?;
    let upstream_peer = core::str::from_utf8(&scratch[..length])
        .ok()
        .and_then(|text| text.parse::<u16>().ok())
        // Xen permits dom0 as a network backend. This toolstack-owned upstream
        // identity is separate from admission of untrusted downstream clients.
        .filter(|peer| *peer < 0x7ff0)
        .ok_or(Error::Discovery)?;
    let mut upstream = Netfront::open(upstream_peer)?;
    let mut watch = store::Watch::new(
        "backend/vif",
        endpoint::now_ns().saturating_add(5_000_000_000),
    )?;
    let mut clients: Vec<Client> = Vec::new();
    let mut engine = Engine::new(seed);
    let mut discovery_at = 0;
    let mut announced = false;
    let mut status_at = 0;
    loop {
        // Capture the event generation before work to avoid a lost wakeup.
        let observed = endpoint::generation();
        if poweroff.requested(endpoint::now_ns().saturating_add(CONTROL_TIMEOUT_NS))? {
            // All firewall state is volatile. Stop admitting packets now; Xen
            // owns final grant/device teardown when the application exits.
            println!("AIRLOCK_FIREWALL_STOP reason=ToolstackPoweroff boot={boot}");
            return Ok(());
        }

        for _ in 0..16 {
            let event = control.poll()?;
            let now = endpoint::now_ns();
            if !engine.observe(control.projection(), now) {
                return Err(Error::State);
            }
            let idle = matches!(event, Event::Idle);
            if let Event::Barrier { serial } = event {
                for client in &mut clients {
                    if matches!(&client.admission, Admission::Barrier(pending) if pending.serial() == serial)
                    {
                        let admission =
                            core::mem::replace(&mut client.admission, Admission::Waiting);
                        if let Admission::Barrier(pending) = admission {
                            if let Some(certificate) =
                                control.admit(&mut client.interface, pending)?
                            {
                                if !engine.attach(certificate.binding()) {
                                    return Err(Error::State);
                                }
                                client.owner = Some(Owner::from_binding(certificate.binding()));
                                client.admission = Admission::Ready(certificate);
                                client.revision = control.projection().generation();
                            }
                        }
                    }
                }
            }
            if idle {
                break;
            }
        }
        let now = endpoint::now_ns();
        if let Some(answer) = engine.tick(control.projection(), now) {
            control.resolve(answer)?;
            if !engine.observe(control.projection(), endpoint::now_ns()) {
                return Err(Error::State);
            }
        }
        if !announced && control.projection().config().is_some() {
            println!(
                "AIRLOCK_FIREWALL_EXECUTING scope=ipv4-experiment forwarding=per-client-gated"
            );
            announced = true;
        }
        // Watch hints are not peer identities. Periodic rereads cover coalescing
        // and failed client startup without spinning on absent native records.
        let hint = watch.changed(endpoint::now_ns().saturating_add(CONTROL_TIMEOUT_NS))?;
        if hint || now >= discovery_at {
            discover(&mut clients, &mut engine, &mut scratch, now)?;
            discovery_at = now.saturating_add(1_000_000_000);
        }
        retire_closed(&mut clients, &mut engine, now)?;
        for client in &mut clients {
            let status = client.interface.progress()?;
            if status != Status::Ready {
                continue;
            }
            let revision = control.projection().generation();
            if client.revision != revision && matches!(client.admission, Admission::Ready(_)) {
                client.admission = Admission::Waiting;
                client.revision = revision;
            }
            if matches!(client.admission, Admission::Waiting) {
                if let Some(pending) = control.prepare(&mut client.interface)? {
                    client.admission = Admission::Barrier(pending);
                }
            }
            let Admission::Ready(certificate) = &client.admission else {
                continue;
            };
            for _ in 0..8 {
                let Some(permit) = control.permit(&mut client.interface, certificate)? else {
                    break;
                };
                let Some(received) = permit.receive(&mut scratch)? else {
                    break;
                };
                engine.client(
                    received.binding(),
                    received.projection(),
                    received.bytes(),
                    endpoint::now_ns(),
                );
            }
            // permit may have retained new control bytes; observe before polling
            // again so a tightening followed by relaxation still revokes flows.
            if !engine.observe(control.projection(), endpoint::now_ns()) {
                return Err(Error::State);
            }
            let owner = Owner::from_binding(certificate.binding());
            for _ in 0..8 {
                let Some(output) = engine.next_client(owner) else {
                    break;
                };
                let Some(permit) = control.permit(&mut client.interface, certificate)? else {
                    engine.retry(output);
                    break;
                };
                if output.authorized(
                    permit.projection(),
                    Some(permit.binding()),
                    endpoint::now_ns(),
                ) && !permit.send(output.bytes())?
                {
                    engine.retry(output);
                    break;
                }
            }
            if !engine.observe(control.projection(), endpoint::now_ns()) {
                return Err(Error::State);
            }
        }
        for _ in 0..16 {
            let Some(length) = upstream.poll(&mut scratch)? else {
                break;
            };
            let Some(observation) = control.observation()? else {
                break;
            };
            engine.upstream(
                observation.projection(),
                &scratch[..length],
                endpoint::now_ns(),
            );
        }
        if !engine.observe(control.projection(), endpoint::now_ns()) {
            return Err(Error::State);
        }
        for _ in 0..16 {
            let Some(output) = engine.next_upstream(control.projection(), endpoint::now_ns())
            else {
                break;
            };
            if !send_upstream(&mut control, &mut upstream, &mut clients, &output)? {
                engine.retry(output);
                break;
            }
            if !engine.observe(control.projection(), endpoint::now_ns()) {
                return Err(Error::State);
            }
        }
        let status = network_status(&mut control, &mut clients, &engine)?;
        if status.state == airlock_qubes_network::status::State::Fault {
            return Err(Error::State);
        }
        let now = endpoint::now_ns();
        // One bounded heartbeat per second, even when control updates arrive
        // continuously. Packet traffic cannot turn status logging into a flood.
        if now >= status_at {
            let report = airlock_qubes_network::status::Report {
                boot: boot.clone(),
                snapshot: status,
            };
            let report = serde_json::to_string(&report).map_err(|_| Error::State)?;
            println!("AIRLOCK_FIREWALL_STATUS {report}");
            status_at = now.saturating_add(1_000_000_000);
        }
        // Maintenance wakeups also drive grant revocation and deadlines when a
        // peer stops producing events. The event counter makes this race safe.
        match endpoint::wait(observed, endpoint::now_ns().saturating_add(1_000_000)) {
            Ok(()) | Err(xen_transport::Error::Timeout) => (),
            Err(error) => return Err(error.into()),
        }
    }
}

/// Observe exact native permits and a final drained control view. These facts
/// are diagnostics only; the packet path independently holds its consuming permit.
fn network_status(
    control: &mut Session,
    clients: &mut [Client],
    engine: &Engine,
) -> Result<airlock_qubes_network::status::Snapshot, Error> {
    use airlock_qubes_network::status::{Snapshot, classify};
    let revision = control.projection().generation();
    let mut admitted = 0;
    for client in clients.iter_mut() {
        if let Admission::Ready(certificate) = &client.admission {
            admitted += usize::from(
                control
                    .permit(&mut client.interface, certificate)?
                    .is_some(),
            );
        }
    }
    let Some(observation) = control.observation()? else {
        return Ok(Snapshot {
            state: classify(false, 0, clients.len(), admitted),
            revision,
            expected: 0,
            interfaces: clients.len(),
            admitted,
            gateway_reachable: false,
        });
    };
    let view = observation.projection();
    // A permit observed before another policy publication cannot count as a
    // current-view admission. The next fair service iteration will retry it.
    if view.generation() != revision {
        admitted = 0;
    }
    let now = endpoint::now_ns();
    let config = view.config();
    let expected = config
        .and_then(|config| config.clients(4))
        .map_or(0, |sources| sources.len());
    // A current Permit already requires complete policy for that exact live
    // interface's assigned sources. Halted VMs need no device or policy before
    // their provider can start; DNS reachability is not isolation authority.
    Ok(Snapshot {
        state: classify(config.is_some(), expected, clients.len(), admitted),
        revision: view.generation(),
        expected,
        interfaces: clients.len(),
        admitted,
        gateway_reachable: engine.gateway_reachable(view, now),
    })
}

/// Transmit only while holding either the exact client Permit or an upstream-only
/// live observation. True includes deliberate stale-owner/policy drops; false is
/// temporary native backpressure or pending control work and may be requeued.
fn send_upstream(
    control: &mut Session,
    upstream: &mut Netfront,
    clients: &mut [Client],
    output: &Output,
) -> Result<bool, Error> {
    if output.target() != Target::Upstream {
        return Err(Error::State);
    }
    if let Some(owner) = output.owner() {
        for client in clients {
            let Admission::Ready(certificate) = &client.admission else {
                continue;
            };
            if Owner::from_binding(certificate.binding()) != owner {
                continue;
            }
            let Some(permit) = control.permit(&mut client.interface, certificate)? else {
                return Ok(false);
            };
            if !output.authorized(
                permit.projection(),
                Some(permit.binding()),
                endpoint::now_ns(),
            ) {
                return Ok(true);
            }
            return Ok(upstream.try_send(output.bytes())?);
        }
        return Ok(true);
    }
    let Some(observation) = control.observation()? else {
        return Ok(false);
    };
    if !output.authorized(observation.projection(), None, endpoint::now_ns()) {
        return Ok(true);
    }
    Ok(upstream.try_send(output.bytes())?)
}

/// Retire completed native closures every turn, before selecting queued output.
/// Pending clients remain owned; an uncertain native failure terminates the VM.
fn retire_closed(clients: &mut Vec<Client>, engine: &mut Engine, now: u64) -> Result<(), Error> {
    let mut index = 0;
    while index < clients.len() {
        if clients[index].interface.progress()? == Status::Closed {
            let client = clients.remove(index);
            if let Some(owner) = client.owner {
                engine.retire(owner, now);
            }
            // progress consumed the successful native close; never replay it.
        } else {
            index += 1;
        }
    }
    Ok(())
}

/// Reconcile the whole bounded native directory. Removing a client retires its
/// queues/leases before consuming close; uncertain close is fatal, never retried.
fn discover(
    clients: &mut Vec<Client>,
    engine: &mut Engine,
    scratch: &mut [u8; 4096],
    now: u64,
) -> Result<(), Error> {
    let deadline = endpoint::now_ns().saturating_add(CONTROL_TIMEOUT_NS);
    let length = match store::directory("backend/vif", scratch, deadline) {
        Ok(length) => length,
        Err(xen_transport::Error::Platform(-2)) => 0,
        Err(error) => return Err(error.into()),
    };
    let mut peers =
        airlock_qubes_network::backend::peers(&scratch[..length]).ok_or(Error::Discovery)?;
    let mut index = 0;
    while index < clients.len() {
        let closed = clients[index].interface.progress()? == Status::Closed;
        if closed || !peers.contains(&clients[index].interface.peer()) {
            let client = clients.remove(index);
            if let Some(owner) = client.owner {
                engine.retire(owner, now);
            }
            let retired_peer = client.interface.peer();
            // A Closed native owner has already consumed its handle in progress.
            if !closed {
                client.interface.close()?;
            }
            // A native close can remove this backend node after the directory
            // read above. Do not immediately reopen it from that stale hint;
            // a later discovery can observe any replacement incarnation.
            peers.retain(|peer| *peer != retired_peer);
        } else {
            index += 1;
        }
    }
    for peer in peers {
        if clients.iter().any(|client| client.interface.peer() == peer) {
            continue;
        }
        // libxl may retain an empty peer parent after vif/0 is removed. This
        // hint prevents reserving a new native slot for an absent/offline vif;
        // attach still rechecks reciprocal links and establishes the real owner.
        let online = format!("backend/vif/{peer}/0/online");
        match store::value(
            &online,
            scratch,
            endpoint::now_ns().saturating_add(CONTROL_TIMEOUT_NS),
        ) {
            Ok(1) if scratch[0] == b'1' => (),
            Ok(_) | Err(xen_transport::Error::Platform(-2)) => continue,
            Err(error) => return Err(error.into()),
        }
        if clients.len() >= MAX_CLIENTS {
            return Err(Error::Discovery);
        }
        clients.push(Client {
            interface: Netback::attach(peer)?,
            admission: Admission::Waiting,
            owner: None,
            revision: 0,
        });
    }
    Ok(())
}
