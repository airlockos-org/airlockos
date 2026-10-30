//! X selection adapter for the existing Qubes graphical sessions and GUI Xwayland.
//! Ownership notifications publish local changes; owning our proxy selection never
//! republishes it. INCR transfers preserve large binary formats without file paths.

use super::{Client, Reply, Request};
use airlock_clipboard_core::shared::{
    self, DEFAULT_CAPACITY, Format, Generation, MAX_FORMATS, Offer,
};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};
use x11rb::{
    CURRENT_TIME, NONE,
    connection::Connection,
    protocol::{
        Event,
        xfixes::{ConnectionExt as _, SelectionEventMask},
        xproto::{
            self, Atom, AtomEnum, ConnectionExt as _, CreateWindowAux, EventMask, PropMode,
            Property, SelectionNotifyEvent, SelectionRequestEvent, Window, WindowClass,
        },
    },
    rust_connection::RustConnection,
    wrapper::ConnectionExt as _,
};

/// One outgoing X incremental transfer, bound to an immutable Hermit generation.
struct Sending {
    /// Receiving application window and property carrying the transfer.
    request: SelectionRequestEvent,
    /// Exact immutable source generation, invalidated on replacement.
    generation: Generation,
    /// Index of the selected representation.
    format: usize,
    /// Next unread byte in that representation.
    offset: usize,
    /// Total bytes advertised to the receiving application.
    size: usize,
    /// Fixed transaction deadline; application stalls do not retain unbounded work.
    deadline: Instant,
}

/// Desktop state owned by one graphical user and one authenticated Hermit connection.
struct Desktop {
    /// Qubes X server or GUI Xwayland connection, never a replacement display server.
    x: RustConnection,
    /// Hidden selection-owner window with no user interface.
    window: Window,
    /// Standard desktop CLIPBOARD selection.
    clipboard: Atom,
    /// Standard selection format-discovery target.
    targets: Atom,
    /// Standard selection ownership timestamp target.
    timestamp: Atom,
    /// Standard incremental transfer marker.
    incr: Atom,
    /// Private property used while reading a source's selection.
    property: Atom,
    /// Direct authenticated connection to Hermit.
    client: Client,
    /// Remote offer represented by our own selection, absent for a cleared clipboard.
    remote: Option<Offer>,
    /// Last generation and publication state observed, including pending replacements.
    observed: Option<(Generation, bool)>,
    /// Reservation currently belonging to the local application's clipboard owner.
    local_generation: Option<Generation>,
    /// Selection acquisition timestamp returned to ordinary X clients.
    acquired: u32,
    /// Events deferred during bounded source format conversion.
    deferred: VecDeque<Event>,
    /// Bounded outgoing incremental transfers, independently timed out.
    sending: Vec<Sending>,
}

impl Desktop {
    /// Intern one X target without interpreting clipboard content as an identifier.
    fn atom(&self, name: &str) -> Result<Atom> {
        Ok(self.x.intern_atom(false, name.as_bytes())?.reply()?.atom)
    }

    /// Check that asynchronous conversion still belongs to the same local owner.
    fn still_owner(&self, owner: Window) -> Result<bool> {
        Ok(self.x.get_selection_owner(self.clipboard)?.reply()?.owner == owner)
    }

    /// Read a property with a hard bound, optionally deleting it to advance INCR.
    fn property(&self, delete: bool) -> Result<xproto::GetPropertyReply> {
        let reply = self
            .x
            .get_property(
                delete,
                self.window,
                self.property,
                AtomEnum::ANY,
                0,
                (DEFAULT_CAPACITY / 4 + 1) as u32,
            )?
            .reply()?;
        ensure!(
            reply.bytes_after == 0 && reply.value.len() <= DEFAULT_CAPACITY,
            "clipboard representation exceeds capacity"
        );
        Ok(reply)
    }

    /// Wait for one source conversion while retaining unrelated desktop events.
    fn next_until(&mut self, deadline: Instant) -> Result<Event> {
        loop {
            if let Some(event) = self.x.poll_for_event()? {
                return Ok(event);
            }
            ensure!(
                Instant::now() < deadline,
                "clipboard source did not complete conversion"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// Convert one selection target, supporting exact binary INCR reconstruction.
    fn convert(&mut self, owner: Window, target: Atom) -> Result<Option<xproto::GetPropertyReply>> {
        self.x
            .delete_property(self.window, self.property)?
            .check()?;
        self.x
            .convert_selection(
                self.window,
                self.clipboard,
                target,
                self.property,
                CURRENT_TIME,
            )?
            .check()?;
        self.x.flush()?;
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let event = self.next_until(deadline)?;
            match event {
                Event::SelectionNotify(event)
                    if event.requestor == self.window
                        && event.selection == self.clipboard
                        && event.target == target =>
                {
                    if event.property == NONE {
                        return Ok(None);
                    }
                    ensure!(
                        event.property == self.property,
                        "unexpected clipboard property"
                    );
                    break;
                }
                Event::PropertyNotify(event)
                    if event.window == self.window && event.atom == self.property => {}
                event => {
                    ensure!(
                        self.deferred.len() < 4096,
                        "clipboard event backlog exceeded"
                    );
                    self.deferred.push_back(event);
                }
            }
        }
        ensure!(
            self.still_owner(owner)?,
            "clipboard source changed during conversion"
        );
        let mut reply = self.property(false)?;
        if reply.type_ != self.incr {
            self.x
                .delete_property(self.window, self.property)?
                .check()?;
            return Ok(Some(reply));
        }
        ensure!(
            reply.format == 32
                && reply.value32().is_some_and(|mut sizes| sizes
                    .next()
                    .is_some_and(|size| size as usize <= DEFAULT_CAPACITY)),
            "invalid incremental clipboard offer"
        );
        reply.value.clear();
        reply.format = 0;
        self.x
            .delete_property(self.window, self.property)?
            .check()?;
        self.x.flush()?;
        loop {
            let event = self.next_until(deadline)?;
            match event {
                Event::PropertyNotify(event)
                    if event.window == self.window
                        && event.atom == self.property
                        && event.state == Property::NEW_VALUE =>
                {
                    let chunk = self.property(true)?;
                    if reply.format == 0 {
                        reply.format = chunk.format;
                        reply.type_ = chunk.type_;
                    }
                    ensure!(
                        chunk.format == reply.format && chunk.type_ == reply.type_,
                        "incremental clipboard type changed"
                    );
                    ensure!(
                        reply.value.len() + chunk.value.len() <= DEFAULT_CAPACITY,
                        "clipboard representation exceeds capacity"
                    );
                    if chunk.value.is_empty() {
                        break;
                    }
                    reply.value.extend_from_slice(&chunk.value);
                    self.x.flush()?;
                }
                Event::PropertyNotify(event)
                    if event.window == self.window && event.atom == self.property => {}
                event => {
                    ensure!(
                        self.deferred.len() < 4096,
                        "clipboard event backlog exceeded"
                    );
                    self.deferred.push_back(event);
                }
            }
        }
        ensure!(
            self.still_owner(owner)?,
            "clipboard source changed during conversion"
        );
        Ok(Some(reply))
    }

    /// Publish one local selection; file offers stay local and clear shared availability.
    fn publish(&mut self, owner: Window) -> Result<()> {
        let Reply::Generation(generation) = self.client.request(Request::Reserve)? else {
            bail!("invalid clipboard reservation reply");
        };
        self.local_generation = Some(generation);
        self.remote = None;
        let targets = self
            .convert(owner, self.targets)?
            .context("clipboard source refused its target list")?;
        ensure!(
            targets.type_ == u32::from(AtomEnum::ATOM) && targets.format == 32,
            "invalid clipboard target list"
        );
        let atoms: Vec<_> = targets
            .value32()
            .context("invalid clipboard target encoding")?
            .collect();
        ensure!(atoms.len() <= 256, "too many clipboard targets");
        let mut names = Vec::new();
        for atom in atoms {
            let reply = self.x.get_atom_name(atom)?.reply()?;
            let Ok(name) = String::from_utf8(reply.name) else {
                continue;
            };
            if shared::is_file_format(&name) {
                ensure!(
                    matches!(
                        self.client.request(Request::Declare {
                            generation,
                            formats: Vec::new()
                        })?,
                        Reply::Ok
                    ),
                    "cannot clear shared file offer"
                );
                return Ok(());
            }
            if shared::is_data_format(&name) && !names.iter().any(|(_, previous)| previous == &name)
            {
                names.push((atom, name));
            }
        }
        ensure!(
            names.len() <= MAX_FORMATS,
            "too many clipboard representations"
        );
        let mut formats = Vec::new();
        let mut data = Vec::new();
        let mut total = 0;
        for (atom, name) in names {
            let Some(representation) = self.convert(owner, atom)? else {
                continue;
            };
            // X resource identifiers and native machine words are not transferable
            // representations. Desktop MIME encodings and text targets use octets.
            if representation.format != 8 {
                continue;
            }
            total += representation.value.len();
            ensure!(
                total <= DEFAULT_CAPACITY,
                "clipboard offer exceeds capacity"
            );
            formats.push(Format {
                name,
                size: representation.value.len(),
            });
            data.push(representation.value);
        }
        ensure!(
            self.still_owner(owner)?,
            "clipboard source changed before publication"
        );
        let empty = formats.is_empty();
        ensure!(
            matches!(
                self.client.request(Request::Declare {
                    generation,
                    formats
                })?,
                Reply::Ok
            ),
            "clipboard declaration failed"
        );
        for (format, bytes) in data.into_iter().enumerate() {
            for (index, chunk) in bytes
                .chunks(airlock_sys_clipboard::shared::DATA_CHUNK)
                .enumerate()
            {
                ensure!(
                    matches!(
                        self.client.request(Request::Write {
                            generation,
                            format,
                            offset: index * airlock_sys_clipboard::shared::DATA_CHUNK,
                            bytes: chunk.to_vec()
                        })?,
                        Reply::Ok
                    ),
                    "clipboard write failed"
                );
            }
        }
        if !empty {
            ensure!(
                matches!(
                    self.client.request(Request::Complete { generation })?,
                    Reply::Ok
                ),
                "clipboard publication failed"
            );
        }
        Ok(())
    }

    /// Reflect shared changes without publishing our proxy selection back to Hermit.
    fn synchronize(&mut self) -> Result<()> {
        let Reply::Offer(generation, offer) = self.client.request(Request::Offer)? else {
            bail!("invalid clipboard offer reply");
        };
        let state = (generation, offer.is_some());
        if self.local_generation == Some(generation) {
            self.observed = Some(state);
            return Ok(());
        }
        if self.observed == Some(state) {
            return Ok(());
        }
        if let Some(offer) = &offer {
            shared::validate_formats(&offer.formats, DEFAULT_CAPACITY)
                .map_err(|_| anyhow::anyhow!("invalid clipboard offer"))?;
        }
        self.remote = offer;
        self.local_generation = None;
        self.observed = Some(state);
        self.x
            .set_selection_owner(self.window, self.clipboard, CURRENT_TIME)?
            .check()?;
        self.x.flush()?;
        Ok(())
    }

    /// Complete the X selection handshake, reporting refusal with a null property.
    fn notify(&self, request: SelectionRequestEvent, property: Atom) -> Result<()> {
        let event = SelectionNotifyEvent {
            response_type: xproto::SELECTION_NOTIFY_EVENT,
            sequence: 0,
            time: request.time,
            requestor: request.requestor,
            selection: request.selection,
            target: request.target,
            property,
        };
        self.x
            .send_event(false, request.requestor, EventMask::NO_EVENT, event)?
            .check()?;
        self.x.flush()?;
        Ok(())
    }

    /// Advertise formats or begin a generation-bound incremental paste transaction.
    fn selection(&mut self, mut request: SelectionRequestEvent) -> Result<()> {
        if request.selection != self.clipboard {
            return self.notify(request, NONE);
        }
        if request.property == NONE {
            request.property = request.target;
        }
        let Some(offer) = &self.remote else {
            return self.notify(request, NONE);
        };
        let atoms = offer
            .formats
            .iter()
            .map(|format| self.atom(&format.name))
            .collect::<Result<Vec<_>>>()?;
        if request.target == self.targets {
            let mut targets = atoms;
            targets.extend([self.targets, self.timestamp]);
            self.x
                .change_property32(
                    PropMode::REPLACE,
                    request.requestor,
                    request.property,
                    AtomEnum::ATOM,
                    &targets,
                )?
                .check()?;
        } else if request.target == self.timestamp {
            self.x
                .change_property32(
                    PropMode::REPLACE,
                    request.requestor,
                    request.property,
                    AtomEnum::INTEGER,
                    &[self.acquired],
                )?
                .check()?;
        } else if let Some(format) = atoms.iter().position(|atom| *atom == request.target) {
            if self.sending.len() >= 16 {
                return self.notify(request, NONE);
            }
            let size = offer.formats[format].size;
            if size == 0 {
                self.x
                    .change_property8(
                        PropMode::REPLACE,
                        request.requestor,
                        request.property,
                        request.target,
                        &[],
                    )?
                    .check()?;
            } else {
                self.x
                    .change_window_attributes(
                        request.requestor,
                        &xproto::ChangeWindowAttributesAux::new()
                            .event_mask(EventMask::PROPERTY_CHANGE),
                    )?
                    .check()?;
                self.x
                    .change_property32(
                        PropMode::REPLACE,
                        request.requestor,
                        request.property,
                        self.incr,
                        &[size as u32],
                    )?
                    .check()?;
                self.sending.push(Sending {
                    request,
                    generation: offer.generation,
                    format,
                    offset: 0,
                    size,
                    deadline: Instant::now() + Duration::from_secs(120),
                });
            }
        } else {
            return self.notify(request, NONE);
        }
        self.notify(request, request.property)
    }

    /// Send the next incremental chunk only when the receiving client deletes its property.
    fn advance(&mut self, window: Window, property: Atom) -> Result<()> {
        let Some(index) = self
            .sending
            .iter()
            .position(|s| s.request.requestor == window && s.request.property == property)
        else {
            return Ok(());
        };
        let sending = &mut self.sending[index];
        if Instant::now() >= sending.deadline || sending.offset == sending.size {
            self.x
                .change_property8(
                    PropMode::REPLACE,
                    window,
                    property,
                    sending.request.target,
                    &[],
                )?
                .check()?;
            self.sending.remove(index);
        } else {
            let result = self.client.request(Request::Read {
                generation: sending.generation,
                format: sending.format,
                offset: sending.offset,
            });
            let bytes = match result {
                Ok(Reply::Data(bytes))
                    if !bytes.is_empty() && bytes.len() <= sending.size - sending.offset =>
                {
                    bytes
                }
                _ => {
                    // Abort an invalidated transfer; never splice replacement content
                    // into the old generation. A source change relinquishes ownership.
                    let target = sending.request.target;
                    self.sending.remove(index);
                    self.x
                        .change_property8(PropMode::REPLACE, window, property, target, &[])?
                        .check()?;
                    self.x.flush()?;
                    return Ok(());
                }
            };
            sending.offset += bytes.len();
            self.x
                .change_property8(
                    PropMode::REPLACE,
                    window,
                    property,
                    sending.request.target,
                    &bytes,
                )?
                .check()?;
        }
        self.x.flush()?;
        Ok(())
    }

    /// Process clipboard events without treating ordinary application reads as copies.
    fn event(&mut self, event: Event) -> Result<()> {
        match event {
            Event::XfixesSelectionNotify(event) if event.selection == self.clipboard => {
                if event.owner == self.window {
                    self.acquired = event.selection_timestamp;
                } else if event.owner == NONE && self.still_owner(NONE)? {
                    if event.subtype == x11rb::protocol::xfixes::SelectionEvent::SET_SELECTION_OWNER
                    {
                        let Reply::Generation(generation) =
                            self.client.request(Request::Reserve)?
                        else {
                            bail!("invalid clear reservation");
                        };
                        ensure!(
                            matches!(
                                self.client.request(Request::Declare {
                                    generation,
                                    formats: Vec::new()
                                })?,
                                Reply::Ok
                            ),
                            "clipboard clear failed"
                        );
                        self.local_generation = Some(generation);
                        self.remote = None;
                        return Ok(());
                    }
                    // A copied offer survives the source process exiting, like a
                    // desktop clipboard manager. Hermit already owns its bytes.
                    self.local_generation = None;
                    self.observed = None;
                } else if self.still_owner(event.owner)? && self.publish(event.owner).is_err() {
                    eprintln!("clipboard copy failed or was replaced");
                    // Keep the local selection intact, but never publish a partial copy.
                    if let Some(generation) = self.local_generation {
                        let _ = self.client.request(Request::Declare {
                            generation,
                            formats: Vec::new(),
                        });
                    }
                }
            }
            Event::SelectionRequest(request) => {
                if self.selection(request).is_err() {
                    let _ = self.notify(request, NONE);
                }
            }
            Event::PropertyNotify(event) if event.state == Property::DELETE => {
                let _ = self.advance(event.window, event.atom);
            }
            _ => (),
        }
        Ok(())
    }
}

/// Open the existing graphical session using its DISPLAY and XAUTHORITY.
fn connect(client: Client) -> Result<Desktop> {
    let (x, screen) = x11rb::connect(None)?;
    x.xfixes_query_version(5, 0)?.reply()?;
    let window = x.generate_id()?;
    x.create_window(
        x11rb::COPY_DEPTH_FROM_PARENT,
        window,
        x.setup().roots[screen].root,
        0,
        0,
        1,
        1,
        0,
        WindowClass::INPUT_OUTPUT,
        0,
        &CreateWindowAux::new().event_mask(EventMask::PROPERTY_CHANGE),
    )?
    .check()?;
    let atom = |name: &[u8]| -> Result<Atom> { Ok(x.intern_atom(false, name)?.reply()?.atom) };
    let clipboard = atom(b"CLIPBOARD")?;
    let targets = atom(b"TARGETS")?;
    let timestamp = atom(b"TIMESTAMP")?;
    let incr = atom(b"INCR")?;
    let property = atom(b"_AIRLOCK_CLIPBOARD_TRANSFER")?;
    x.xfixes_select_selection_input(
        window,
        clipboard,
        SelectionEventMask::SET_SELECTION_OWNER
            | SelectionEventMask::SELECTION_WINDOW_DESTROY
            | SelectionEventMask::SELECTION_CLIENT_CLOSE,
    )?
    .check()?;
    Ok(Desktop {
        x,
        window,
        clipboard,
        targets,
        timestamp,
        incr,
        property,
        client,
        remote: None,
        observed: None,
        local_generation: None,
        acquired: CURRENT_TIME,
        deferred: VecDeque::new(),
        sending: Vec::new(),
    })
}

/// Run inside the existing graphical session with its DISPLAY and XAUTHORITY.
pub(super) fn run(client: Client) -> Result<()> {
    let mut desktop = connect(client)?;
    let owner = desktop
        .x
        .get_selection_owner(desktop.clipboard)?
        .reply()?
        .owner;
    if owner != NONE {
        desktop.publish(owner)?;
    }
    let mut synchronize = Instant::now();
    loop {
        for _ in 0..64 {
            let event = match desktop.deferred.pop_front() {
                Some(event) => Some(event),
                None => desktop.x.poll_for_event()?,
            };
            let Some(event) = event else {
                break;
            };
            desktop.event(event)?;
        }
        if synchronize.elapsed() >= Duration::from_millis(200) {
            desktop.synchronize()?;
            desktop.sending.retain(|s| Instant::now() < s.deadline);
            synchronize = Instant::now();
        }
        desktop.x.flush()?;
        std::thread::sleep(Duration::from_millis(10));
    }
}
