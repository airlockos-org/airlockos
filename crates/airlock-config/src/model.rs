//! Validates connected Qubes VMs, with role-specific network and storage choices.
//! The authoring profile lives in `profiles::usb_lab`; conversion to Nix lives in `lowering`.

// Reuse the runtime identity that excludes dom0 from VM targets.
use airlock_machine_core::{
    model::VmReference as ReferenceSetting,
    relationships::{Relationships, VmRelationships},
    services::{CaptureConnection, ClipboardConnection},
};
use airlock_nix_core::identity::GuestName as VmName;
use rusix::{IntoRusixValue, nixos::NixosModule};
use std::collections::BTreeMap;

mod error;

#[cfg(doctest)]
mod type_constraints;

pub use error::AuthoringError;

use std::{
    cell::{Cell, OnceCell, RefCell},
    marker::PhantomData,
    rc::{Rc, Weak},
};

/// Memory and root-image sizes use MiB, unlike Qubes private-volume sizes in bytes.
#[derive(Clone, Copy, IntoRusixValue)]
pub struct MiB(
    /// Count of 2^20-byte units, emitted directly for the builder's MiB fields.
    pub u32,
);

/// Private-volume capacity, kept distinct from the builder's MiB arguments.
#[derive(Clone, Copy)]
pub struct GiB(
    /// Count of 2^30-byte units; lowering converts this to Qubes' byte count.
    pub u32,
);

impl GiB {
    /// Converts private-volume capacity to the byte count expected by Qubes.
    pub fn bytes(self) -> i64 {
        i64::from(self.0) * (1 << 30)
    }
}

/// A typed reference to a VM declaration, usable before and after registration.
/// Clones share module, resource and display edits. Identity, role, network and
/// launch-target connections stay fixed.
#[derive(Clone)]
pub struct VmHandle<R, B = Nixos> {
    /// Shared declaration whose membership is established by `Machine::add`.
    reference: VmReference,
    /// Retains the constructor's role so Rust can check connection compatibility.
    role: PhantomData<fn() -> (R, B)>,
}

impl<R, B> VmHandle<R, B> {
    /// Borrows the validated external identity for service records and diagnostics.
    /// Identity is immutable; machine membership still uses the declaration itself.
    pub fn name(&self) -> &VmName {
        &self.reference.definition.name
    }

    /// Advertise an additional Qubes feature without replacing role or relationship invariants.
    /// Reject invalid setting names and feature keys owned by the machine's role implementation.
    pub fn set_feature(&self, name: &str, value: impl Into<String>) -> Result<(), AuthoringError> {
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.:+-".contains(&byte))
            || [
                "airlock-role",
                "airlock-backend",
                "airlock-network-provider",
                "airlock-managed",
                "airlock-clipboard-authority",
                "airlock-clipboard-service",
                "gui",
                "servicevm",
            ]
            .contains(&name)
        {
            return Err(AuthoringError::InvalidFeature {
                vm: self.name().to_string(),
                name: name.to_owned(),
            });
        }

        self.reference
            .definition
            .features
            .borrow_mut()
            .insert(name.to_owned(), value.into());
        Ok(())
    }

    /// Sets boot and maximum memory; `finish` checks positivity and ordering.
    pub fn set_memory(&self, memory: Memory) {
        let mut settings = self.reference.definition.settings.get();
        settings.memory = memory;
        self.reference.definition.settings.set(settings);
    }

    /// Override the role's boot-start preference without changing its dependency relationships.
    pub fn set_autostart(&self, enabled: bool) {
        let mut settings = self.reference.definition.settings.get();
        settings.autostart = Some(enabled);
        self.reference.definition.settings.set(settings);
    }

    /// Sets the virtual CPU count; `finish` rejects zero CPUs.
    pub fn set_vcpus(&self, count: u16) {
        let mut settings = self.reference.definition.settings.get();
        settings.vcpus = count;
        self.reference.definition.settings.set(settings);
    }
}

impl<R> VmHandle<R, Nixos> {
    /// Register a component-owned evidence source; finalization checks duplicate and unsafe declarations.
    pub fn add_diagnostic_source(&self, source: airlock_diagnostics::Source) {
        self.reference
            .definition
            .diagnostic_sources
            .borrow_mut()
            .push(source);
    }

    /// Appends a NixOS contribution in authoring order, without changing VM membership.
    /// All handle clones and the registered machine observe the added module.
    pub fn add_module(&self, module: impl Into<VmModule>) {
        self.reference
            .definition
            .modules
            .borrow_mut()
            .push(module.into());
    }

    /// Set the capacity of the small VM boot filesystem; finalization rejects zero capacity.
    pub fn set_root_image(&self, size: MiB) {
        let mut settings = self.reference.definition.settings.get();
        settings.root_image = size;
        self.reference.definition.settings.set(settings);
    }
}

/// NixOS backend marker; only these handles accept Linux modules and root images.
#[derive(Clone)]
pub struct Nixos;

/// Hermit backend marker; these handles cannot acquire NixOS or qrexec services.
#[derive(Clone)]
pub struct Hermit;

/// A stateless system service, independent of its guest operating system.
#[derive(Clone)]
pub struct Service;

/// Guest implementation captured independently of identity and role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuestBackend {
    /// Existing NixOS system and shared immutable store.
    Nixos,
    /// Native Hermit PVH application, without Linux guest storage.
    Hermit {
        /// Application source selection interpreted by the Hermit builder.
        application: HermitApplication,
    },
}

/// Reviewed Hermit application selection; arbitrary build features cannot grant authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HermitApplication {
    /// Clipboard implementation, connected only through a typed GUI relationship.
    Clipboard,
}

/// A NixOS contribution that keeps desktop capabilities and diagnostic sources beside configuration.
/// Ordinary Rusix modules convert directly; the GNOME contribution also
/// informs connection validation. Implementation imports belong to each module.
#[derive(Clone)]
pub struct VmModule {
    /// Settings compiled by Rusix in the order they were attached to the VM.
    module: NixosModule,
    /// Whether this contribution installs GNOME, checked when connecting capture services.
    gnome: bool,
    /// Fixed evidence declarations installed whenever this component is attached to a VM.
    diagnostic_sources: Vec<airlock_diagnostics::Source>,
}

impl From<NixosModule> for VmModule {
    /// Wraps a plain contribution without introducing additional VM relationships.
    fn from(module: NixosModule) -> Self {
        Self {
            module,
            gnome: false,
            diagnostic_sources: Vec::new(),
        }
    }
}

impl VmModule {
    /// Attach a component-owned source; machine finalization validates and freezes its reader.
    pub fn with_diagnostic_source(mut self, source: airlock_diagnostics::Source) -> Self {
        self.diagnostic_sources.push(source);
        self
    }

    /// Records that this contribution installs GNOME and its capture completion adapter.
    pub(crate) fn with_gnome(mut self) -> Self {
        self.gnome = true;
        self
    }
}

/// Destination identity retained without creating GUI/application ownership cycles.
struct CaptureTarget {
    /// External identity retained for diagnostics if an unregistered handle expires.
    name: VmName,
    /// Exact declaration whose membership must be checked at finalization.
    definition: Weak<VmDefinition>,
}

impl VmHandle<Gui> {
    /// Connect this GUI session to one Hermit clipboard; finalization checks ownership.
    pub(crate) fn clipboard_service(&self, service: &VmHandle<Service, Hermit>) {
        *self.reference.definition.clipboard.borrow_mut() = Some(service.reference.clone());
    }

    /// Selects the personal VM receiving captures; finalization configures both endpoints.
    /// Reassignment replaces the previous connection for subsequent snapshots.
    pub(crate) fn capture_to(&self, target: &VmHandle<Personal>) {
        *self.reference.definition.capture.borrow_mut() = Some(CaptureTarget {
            name: target.name().clone(),
            definition: Rc::downgrade(&target.reference.definition),
        });
    }
}

/// Internal reference retaining the exact VM declaration used by a typed connection.
#[derive(Clone)]
pub(crate) struct VmReference {
    /// Keeps the referenced VM alive even before it is registered with a machine.
    definition: Rc<VmDefinition>,
}

impl VmReference {
    /// Returns the external Qubes identity for serialization or diagnostics.
    /// Membership checks use the declaration's owner, never a name lookup.
    pub fn name(&self) -> &str {
        self.definition.name.as_str()
    }

    /// Copies configuration with resolved identities and the validated display choice.
    /// The returned data contains no links to mutable declarations.
    fn snapshot(&self, guivm: ReferenceSetting) -> VmSnapshot {
        let mut diagnostic_sources = self.definition.diagnostic_sources.borrow().clone();
        diagnostic_sources.extend(
            self.definition
                .modules
                .borrow()
                .iter()
                .flat_map(|module| module.diagnostic_sources.iter().cloned()),
        );

        VmSnapshot {
            name: self.definition.name.clone(),
            backend: self.definition.backend.clone(),
            role: self
                .definition
                .role
                .map_references(|reference| reference.definition.name.clone()),
            settings: self.definition.settings.get(),
            features: self.definition.features.borrow().clone(),
            modules: self
                .definition
                .modules
                .borrow()
                .iter()
                .map(|part| part.module.clone())
                .collect(),
            guivm,
            diagnostic_sources,
        }
    }
}

/// Shared authoring state with fixed network edges and editable display assignments.
struct VmDefinition {
    /// Backend fixed at declaration; handle clones cannot change guest ABI.
    backend: GuestBackend,
    /// Validated external identity, fixed when the VM is declared.
    name: VmName,
    /// Role and references to earlier declarations; edges cannot be replaced.
    role: Role<VmReference>,
    /// Set once on successful registration and retained after the owning machine drops.
    owner: OnceCell<Rc<()>>,
    /// Copyable resources allow edits without exposing a mutable borrow of topology.
    settings: Cell<VmSettings>,
    /// Additional author-selected Qubes features, excluding role-owned invariants.
    features: RefCell<BTreeMap<String, String>>,
    /// Ordered contributions; only short internal appends and snapshot reads borrow them.
    modules: RefCell<Vec<VmModule>>,
    /// Optional explicit display assignment, resolved only when the machine finishes.
    gui: RefCell<Option<GuiReference>>,
    /// Optional capture destination resolved together with the machine configuration.
    capture: RefCell<Option<CaptureTarget>>,
    /// Hermit service selected by the GUI clipboard component.
    clipboard: RefCell<Option<VmReference>>,
    /// Evidence declarations supplied beside component configuration.
    diagnostic_sources: RefCell<Vec<airlock_diagnostics::Source>>,
}

/// A display assignment that cannot keep a GUI/application reference cycle alive.
struct GuiReference {
    /// Preserves a useful diagnostic even if the unregistered GUI was dropped.
    name: VmName,
    /// Display providers may point back to their default application, so this edge is weak.
    definition: Weak<VmDefinition>,
}

impl<R: UsesGui> VmHandle<R> {
    /// Selects an explicit GUI provider; `finish` checks its registration and ownership.
    /// Display links may be assigned after registration and do not affect network ordering.
    pub fn set_gui(&self, gui: &VmHandle<Gui>) {
        *self.reference.definition.gui.borrow_mut() = Some(GuiReference {
            name: gui.reference.definition.name.clone(),
            definition: Rc::downgrade(&gui.reference.definition),
        });
    }
}

/// PCI-owning network driver; may supply an uplink to another VM.
#[derive(Clone)]
pub struct NetworkDriver;

/// Firewall VM; may supply a filtered uplink to another VM.
#[derive(Clone)]
pub struct Firewall;

/// Personal application VM; may be the GUI's default application.
#[derive(Clone)]
pub struct Personal;

/// GUI session VM, connected to a personal application VM.
#[derive(Clone)]
pub struct Gui;

/// Build controller VM.
#[derive(Clone)]
pub struct Controller;

/// Interactive development VM.
#[derive(Clone)]
pub struct Assistant;

/// Command-line application VM.
#[derive(Clone)]
pub struct Command;

/// Application VM with no network connection and no implicit display provider.
#[derive(Clone)]
pub struct Isolated;

/// Keeps network-provider and GUI-client capabilities under the model's control.
mod sealed {
    /// Restricts network-capable roles to those provided by this model.
    pub trait NetworkRole {}

    impl NetworkRole for super::NetworkDriver {}

    impl NetworkRole for super::Firewall {}

    /// Limits display assignments to application roles, avoiding GUI startup cycles.
    pub trait GuiClient {}

    impl GuiClient for super::Personal {}

    impl GuiClient for super::Controller {}

    impl GuiClient for super::Assistant {}

    impl GuiClient for super::Command {}

    impl GuiClient for super::Isolated {}
}

/// Roles that may supply another VM's network connection.
pub trait ProvidesNetwork: sealed::NetworkRole {}

impl ProvidesNetwork for NetworkDriver {}

impl ProvidesNetwork for Firewall {}

/// Application roles that can use a GUI VM for display.
pub trait UsesGui: sealed::GuiClient {}

impl UsesGui for Personal {}

impl UsesGui for Controller {}

impl UsesGui for Assistant {}

impl UsesGui for Command {}

impl UsesGui for Isolated {}

/// Display transport selected when declaring a GUI VM.
#[derive(Clone, Copy)]
pub enum GuiDisplay {
    /// Forward the desktop to dom0 through Qubes GUI transport.
    Virtual,
    /// Render directly on the USB lab machine's assigned AMD GPU.
    PhysicalAmd,
}

/// Each role carries the settings it needs, rather than independent optional fields.
#[derive(Clone)]
pub enum Role<R> {
    /// A stateless service with no implicit network, GUI, or writable storage.
    Service,
    /// Runs a minimal application system without network or display access by default.
    Isolated {
        /// Persistent user state, separate from the immutable system closure.
        private_volume: GiB,
    },
    /// Owns network PCI devices and supplies connectivity to downstream VMs.
    NetworkDriver {
        /// Persistent NetworkManager state belongs to the PCI-owning network driver.
        private_volume: GiB,
    },
    /// Filters traffic received from its registered upstream provider.
    Firewall {
        /// Network provider from which this firewall receives its uplink.
        uplink: R,
    },
    /// Runs user applications with persistent files and a network connection.
    Personal {
        /// Network provider through which the user's applications connect.
        uplink: R,
        /// Persistent user files are stored independently of the immutable VM system.
        private_volume: GiB,
    },
    /// Hosts the GUI session and selects the personal VM opened at startup.
    Gui {
        /// Application VM opened when the GUI session starts.
        default_application: R,
        /// Determines virtualization, display services and physical hardware configuration.
        display: GuiDisplay,
    },
    /// Builds machine candidates using its persistent build store and history.
    Controller {
        /// Provider used to fetch sources and dependencies for machine builds.
        uplink: R,
        /// Candidate history and the writable build store.
        private_volume: GiB,
    },
    /// Provides a persistent interactive development workspace.
    Assistant {
        /// Provider used by the interactive development environment.
        uplink: R,
        /// Persistent workspace and build state.
        private_volume: GiB,
    },
    /// Runs command-line applications with their own persistent user files.
    Command {
        /// Provider used by command-line applications.
        uplink: R,
        /// Persistent user files.
        private_volume: GiB,
    },
}

impl<R> Role<R> {
    /// Replaces declaration references with resolved values when freezing configuration.
    fn map_references<T>(&self, map: impl Fn(&R) -> T) -> Role<T> {
        match self {
            Self::Service => Role::Service,
            Self::Isolated { private_volume } => Role::Isolated {
                private_volume: *private_volume,
            },
            Self::NetworkDriver { private_volume } => Role::NetworkDriver {
                private_volume: *private_volume,
            },
            Self::Firewall { uplink } => Role::Firewall {
                uplink: map(uplink),
            },
            Self::Personal {
                uplink,
                private_volume,
            } => Role::Personal {
                uplink: map(uplink),
                private_volume: *private_volume,
            },
            Self::Gui {
                default_application,
                display,
            } => Role::Gui {
                default_application: map(default_application),
                display: *display,
            },
            Self::Controller {
                uplink,
                private_volume,
            } => Role::Controller {
                uplink: map(uplink),
                private_volume: *private_volume,
            },
            Self::Assistant {
                uplink,
                private_volume,
            } => Role::Assistant {
                uplink: map(uplink),
                private_volume: *private_volume,
            },
            Self::Command {
                uplink,
                private_volume,
            } => Role::Command {
                uplink: map(uplink),
                private_volume: *private_volume,
            },
        }
    }

    /// Returns the declared provider for roles that consume another VM's network.
    /// The PCI-owning driver and the isolated GUI have no upstream VM.
    pub fn uplink(&self) -> Option<&R> {
        match self {
            Self::Service
            | Self::Isolated { .. }
            | Self::NetworkDriver { .. }
            | Self::Gui { .. } => None,
            Self::Firewall { uplink }
            | Self::Personal { uplink, .. }
            | Self::Controller { uplink, .. }
            | Self::Assistant { uplink, .. }
            | Self::Command { uplink, .. } => Some(uplink),
        }
    }

    /// Returns persistent capacity for roles that own writable state.
    /// Firewall and GUI roles omit this setting and retain their builder defaults.
    pub fn private_volume(&self) -> Option<GiB> {
        match self {
            Self::Isolated { private_volume }
            | Self::NetworkDriver { private_volume }
            | Self::Personal { private_volume, .. }
            | Self::Controller { private_volume, .. }
            | Self::Assistant { private_volume, .. }
            | Self::Command { private_volume, .. } => Some(*private_volume),
            Self::Service | Self::Firewall { .. } | Self::Gui { .. } => None,
        }
    }
}

/// Qubes labels used by the default machine.
#[derive(Clone, Copy, IntoRusixValue)]
pub enum Label {
    /// Default label for the network driver and build controller.
    Red,
    /// Default label for the firewall service VM.
    Green,
    /// Default label for personal application VMs.
    Khaki,
    /// Default label for the GUI infrastructure VM.
    Black,
    /// Default label for the interactive development VM.
    #[rusix(rename = "light-gray")]
    LightGray,
    /// Default label for the command-line VM.
    Yellow,
}

/// Xen VM modes used by this example; network PCI passthrough needs HVM here.
#[derive(Clone, Copy, IntoRusixValue)]
pub enum Virtualization {
    /// Hardware-assisted mode selected for the PCI-owning network driver.
    Hvm,
    /// PVH mode explicitly selected for the assistant VM in this profile.
    Pvh,
}

/// Boot memory and the largest amount Qubes may assign through memory balancing.
#[derive(Clone, Copy)]
pub enum Memory {
    /// Uses the same boot allocation and upper limit, with no balancing headroom.
    Fixed(
        /// Both the initial allocation and its upper limit, in MiB.
        MiB,
    ),
    /// Allows Qubes to increase memory from the initial allocation up to the maximum.
    Ballooned {
        /// Initial memory allocation at VM startup.
        initial: MiB,
        /// Maximum memory allocation after balancing.
        maximum: MiB,
    },
}

impl Memory {
    /// Returns initial and maximum memory in MiB, equal for a fixed allocation.
    pub fn bounds(self) -> (MiB, MiB) {
        match self {
            Self::Fixed(size) => (size, size),
            Self::Ballooned { initial, maximum } => (initial, maximum),
        }
    }
}

/// An owned view of VM configuration for inspection and Nix lowering.
/// Editing this value cannot mutate a declaration or its registered machine.
#[derive(Clone)]
pub struct VmSnapshot {
    /// Operating system and executable selection, independent of the service role.
    pub backend: GuestBackend,
    /// Validated Airlock identity, shared with the runtime's existing name type.
    pub name: VmName,
    /// Independent Rust-authored NixOS contributions composed for this VM.
    pub modules: Vec<NixosModule>,
    /// Carries the network/storage choices allowed for the VM role.
    pub role: Role<VmName>,
    /// Resource and presentation choices captured at finalization.
    pub settings: VmSettings,
    /// Additional Qubes features supplied through the validated VM handle.
    pub features: BTreeMap<String, String>,
    /// Resolved Qubes display preference: omit to inherit, null to disable, name to select.
    pub guivm: ReferenceSetting,
    /// Component-owned evidence inventory frozen with the VM configuration.
    pub diagnostic_sources: Vec<airlock_diagnostics::Source>,
}

/// Choices that can be edited without invalidating existing VM connections.
#[derive(Clone, Copy)]
pub struct VmSettings {
    /// Optional explicit boot-start preference; otherwise the role supplies it.
    pub autostart: Option<bool>,
    /// Qubes window and management label.
    pub label: Label,
    /// Capacity of the VM's small boot filesystem, excluding its shared Nix store.
    pub root_image: MiB,
    /// Initial and maximum VM memory allocations.
    pub memory: Memory,
    /// Number of virtual CPUs exposed to the VM.
    pub vcpus: u16,
}

impl VmSettings {
    /// Supplies personal-VM resource defaults that other application roles override.
    fn application() -> Self {
        Self {
            autostart: None,
            label: Label::Khaki,
            root_image: MiB(1024),
            memory: Memory::Ballooned {
                initial: MiB(2048),
                maximum: MiB(4096),
            },
            vcpus: 2,
        }
    }
}

/// Role constructors for independently declared VMs, configured through typed handles.
/// Declaration checks names and connection types; `Machine::add` establishes membership.
pub struct Vm;

impl Vm {
    /// Declare a stateless NixOS service using the existing Linux guest machinery.
    pub fn nixos(name: &str, memory: MiB) -> Result<VmHandle<Service>, AuthoringError> {
        Self::declare(
            name,
            Role::Service,
            VmSettings {
                memory: Memory::Fixed(memory),
                vcpus: 1,
                ..VmSettings::application()
            },
        )
    }

    /// Declare an isolated Hermit service with fixed memory and one virtual CPU.
    /// The application selection cannot enable the laboratory's dom0 authority.
    pub fn hermit(
        name: &str,
        memory: MiB,
        application: HermitApplication,
    ) -> Result<VmHandle<Service, Hermit>, AuthoringError> {
        let mut vm = Self::nixos(name, memory)?;
        let definition =
            Rc::get_mut(&mut vm.reference.definition).expect("new declaration has no clones");
        definition.backend = GuestBackend::Hermit { application };
        let mut settings = definition.settings.get();
        settings.root_image = MiB(0);
        definition.settings.set(settings);
        Ok(VmHandle {
            reference: vm.reference,
            role: PhantomData,
        })
    }

    /// Creates shared configuration without claiming membership in any machine.
    /// Only role constructors call this helper; they must pair `R` with the matching
    /// `Role` variant. Resource bounds are checked after configuration by the machine.
    fn declare<R>(
        name: &str,
        role: Role<VmReference>,
        settings: VmSettings,
    ) -> Result<VmHandle<R>, AuthoringError> {
        let name = name
            .parse::<VmName>()
            .map_err(|error| AuthoringError::InvalidName {
                name: name.to_owned(),
                reason: error.to_string(),
            })?;

        let definition = Rc::new(VmDefinition {
            name,
            backend: GuestBackend::Nixos,
            role,
            owner: OnceCell::new(),
            settings: Cell::new(settings),
            features: RefCell::new(BTreeMap::new()),
            modules: RefCell::new(Vec::new()),
            gui: RefCell::new(None),
            capture: RefCell::new(None),
            clipboard: RefCell::new(None),
            diagnostic_sources: RefCell::new(Vec::new()),
        });

        Ok(VmHandle {
            reference: VmReference { definition },
            role: PhantomData,
        })
    }

    /// Declares a GUI VM that opens the supplied personal VM.
    /// Rejects invalid names. Add the personal VM to the machine before adding this GUI.
    pub fn gui(
        name: &str,
        default_application: &VmHandle<Personal>,
    ) -> Result<VmHandle<Gui>, AuthoringError> {
        let default_application = default_application.reference.clone();
        Self::declare(
            name,
            Role::Gui {
                default_application,
                display: GuiDisplay::Virtual,
            },
            VmSettings {
                autostart: None,
                label: Label::Black,
                root_image: MiB(512),
                memory: Memory::Ballooned {
                    initial: MiB(1024),
                    maximum: MiB(2048),
                },
                vcpus: 2,
            },
        )
    }

    /// Declares the USB lab GUI with a physical AMD display and fixed resources.
    /// The host must assign its GPU; Qubes GUI forwarding to dom0 is disabled.
    /// Rejects invalid names and requires the personal VM to be registered first.
    pub fn physical_gui(
        name: &str,
        default_application: &VmHandle<Personal>,
    ) -> Result<VmHandle<Gui>, AuthoringError> {
        Self::declare(
            name,
            Role::Gui {
                default_application: default_application.reference.clone(),
                display: GuiDisplay::PhysicalAmd,
            },
            VmSettings {
                autostart: None,
                label: Label::Black,
                root_image: MiB(512),
                memory: Memory::Fixed(MiB(4096)),
                vcpus: 4,
            },
        )
    }

    /// Declares a build controller with persistent state and the supplied uplink.
    /// Starts on demand for system changes, with fixed memory and a larger boot filesystem.
    /// Rejects invalid names; registration checks the uplink's machine membership.
    pub fn controller<R: ProvidesNetwork>(
        name: &str,
        uplink: &VmHandle<R>,
        private_volume: GiB,
    ) -> Result<VmHandle<Controller>, AuthoringError> {
        let uplink = uplink.reference.clone();
        Self::declare(
            name,
            Role::Controller {
                uplink,
                private_volume,
            },
            VmSettings {
                autostart: None,
                label: Label::Red,
                root_image: MiB(2048),
                memory: Memory::Fixed(MiB(8192)),
                ..VmSettings::application()
            },
        )
    }

    /// Declares an interactive development VM with persistent workspace storage.
    /// Uses fixed memory for its development workload and the supplied provider.
    /// Rejects invalid names; registration checks the provider's machine membership.
    pub fn assistant<R: ProvidesNetwork>(
        name: &str,
        uplink: &VmHandle<R>,
        private_volume: GiB,
    ) -> Result<VmHandle<Assistant>, AuthoringError> {
        let uplink = uplink.reference.clone();
        Self::declare(
            name,
            Role::Assistant {
                uplink,
                private_volume,
            },
            VmSettings {
                label: Label::LightGray,
                memory: Memory::Fixed(MiB(8192)),
                ..VmSettings::application()
            },
        )
    }

    /// Declares a command-line VM with persistent files and the supplied uplink.
    /// Lowering preserves the bootstrap role's choice to leave this VM stopped at boot.
    /// Rejects invalid names; registration checks the uplink's machine membership.
    pub fn command<R: ProvidesNetwork>(
        name: &str,
        uplink: &VmHandle<R>,
        private_volume: GiB,
    ) -> Result<VmHandle<Command>, AuthoringError> {
        let uplink = uplink.reference.clone();
        Self::declare(
            name,
            Role::Command {
                uplink,
                private_volume,
            },
            VmSettings {
                label: Label::Yellow,
                ..VmSettings::application()
            },
        )
    }

    /// Declare an application VM with no uplink and no implicit GUI access.
    /// Additional Rust-authored modules select its applications and services.
    pub fn isolated(name: &str, private_volume: GiB) -> Result<VmHandle<Isolated>, AuthoringError> {
        Self::declare(
            name,
            Role::Isolated { private_volume },
            VmSettings {
                label: Label::Green,
                ..VmSettings::application()
            },
        )
    }

    /// Declares a PCI-owning network driver with persistent NetworkManager state.
    /// Rejects invalid names and returns an unregistered, network-capable handle.
    pub fn network(
        name: &str,
        private_volume: GiB,
    ) -> Result<VmHandle<NetworkDriver>, AuthoringError> {
        Self::declare(
            name,
            Role::NetworkDriver { private_volume },
            VmSettings {
                autostart: None,
                label: Label::Red,
                root_image: MiB(512),
                memory: Memory::Fixed(MiB(1024)),
                vcpus: 2,
            },
        )
    }

    /// Declares a firewall downstream of a network driver or another firewall.
    /// Rejects invalid names. The returned handle can supply other VMs; registration
    /// requires its provider to have been added to the same machine first.
    pub fn firewall<R: ProvidesNetwork>(
        name: &str,
        uplink: &VmHandle<R>,
    ) -> Result<VmHandle<Firewall>, AuthoringError> {
        let uplink = uplink.reference.clone();
        Self::declare(
            name,
            Role::Firewall { uplink },
            VmSettings {
                autostart: None,
                label: Label::Green,
                root_image: MiB(512),
                memory: Memory::Ballooned {
                    initial: MiB(512),
                    maximum: MiB(1024),
                },
                vcpus: 1,
            },
        )
    }

    /// Declares a personal VM with persistent files and the supplied uplink.
    /// Its handle can also select the GUI's default application. Rejects invalid
    /// names; registration checks the uplink's machine membership.
    pub fn personal<R: ProvidesNetwork>(
        name: &str,
        uplink: &VmHandle<R>,
        private_volume: GiB,
    ) -> Result<VmHandle<Personal>, AuthoringError> {
        let uplink = uplink.reference.clone();
        Self::declare(
            name,
            Role::Personal {
                uplink,
                private_volume,
            },
            VmSettings::application(),
        )
    }
}

/// Host relationships supplied through typed handles and checked at finalization.
struct HostBindings {
    /// Default display provider for applications without an explicit assignment.
    gui: VmReference,
    /// Default network provider for Qubes-created VMs.
    network: VmReference,
    /// Build controller authorized by the existing admission implementation.
    controller: VmReference,
}

/// Resolved host settings captured with the VM configurations.
#[derive(Clone)]
pub struct HostSnapshot {
    /// Selects physical boot composition or the nested bootstrap environment.
    pub platform: HostPlatform,
    /// Validated default GUI identity.
    pub gui: VmName,
    /// Validated default network identity.
    pub network: VmName,
    /// Validated pool-admission caller identity.
    pub controller: VmName,
}

/// Host environment whose boot and deployment configuration accompanies the VMs.
#[derive(Clone, Copy, Default)]
pub enum HostPlatform {
    /// Nested QEMU environment used for bootstrap and network validation.
    #[default]
    Bootstrap,
    /// Physical USB installation with normal, graphics-validation and recovery boots.
    UsbLab,
}

/// A validated machine configuration detached from all editable handles.
/// Only `Machine::finish` can construct it; consumers receive shared read-only views.
pub struct MachineSnapshot {
    /// Identity of the builder that registered the captured declarations.
    owner: Rc<()>,
    /// Complete VM configurations captured in registration order.
    vms: Vec<VmSnapshot>,
    /// Host relationships, absent for partial models without configured host bindings.
    host: Option<HostSnapshot>,
    /// Immutable capture relationships used by endpoint lowering and host policy.
    captures: Vec<CaptureConnection>,
    /// Frozen clipboard membership shared by installed endpoints and policy.
    clipboards: Vec<ClipboardConnection>,
    /// Validated diagnostic client and the exact installed endpoint inventory.
    diagnostics: Option<crate::components::diagnostics::Access>,
}

impl MachineSnapshot {
    /// Borrow configured GUI clipboards with their exact admitted participants.
    pub fn clipboard_connections(&self) -> &[ClipboardConnection] {
        &self.clipboards
    }

    /// Borrow the frozen diagnostic relationship used by endpoint installation and Qubes policy.
    pub fn diagnostic_access(&self) -> Option<&crate::components::diagnostics::Access> {
        self.diagnostics.as_ref()
    }

    /// Check that a handle belongs to this snapshot, including snapshots made before later registrations.
    pub(crate) fn contains<R, B>(&self, handle: &VmHandle<R, B>) -> bool {
        handle
            .reference
            .definition
            .owner
            .get()
            .is_some_and(|owner| Rc::ptr_eq(owner, &self.owner))
            && self.vms.iter().any(|vm| &vm.name == handle.name())
    }

    /// Returns resolved capture connections, including the exact source and destination identities.
    pub fn capture_connections(&self) -> &[CaptureConnection] {
        &self.captures
    }

    /// Project frozen references into the same dependency semantics used by dom0.
    /// The returned view is independently owned; it cannot mutate this snapshot.
    pub fn relationships(&self) -> Relationships {
        let domains = self
            .vms
            .iter()
            .map(|vm| {
                let mut prefs = BTreeMap::new();
                if !vm.guivm.is_inherited() {
                    prefs.insert(
                        "guivm".to_owned(),
                        serde_json::to_value(&vm.guivm)
                            .expect("reference settings serialize to strings or null"),
                    );
                }

                let netvm = vm.role.uplink().map_or(ReferenceSetting::Disabled, |name| {
                    ReferenceSetting::Named(name.as_vm_name().clone())
                });

                (
                    vm.name.clone(),
                    VmRelationships {
                        netvm,
                        template: ReferenceSetting::Disabled,
                        prefs,
                        service_providers: [
                            "airlock-clipboard-authority",
                            "airlock-clipboard-service",
                        ]
                        .iter()
                        .filter_map(|key| {
                            vm.features
                                .get(*key)
                                .map(|value| serde_json::Value::String(value.clone()))
                        })
                        .collect(),
                        ..VmRelationships::default()
                    },
                )
            })
            .collect();

        let mut prefs = BTreeMap::new();
        if let Some(host) = &self.host {
            prefs.insert("default_guivm".to_owned(), host.gui.to_string().into());
            prefs.insert("default_netvm".to_owned(), host.network.to_string().into());
        }

        Relationships { domains, prefs }
    }

    /// Visits the frozen VM definitions without allowing mutation of the snapshot.
    pub fn vms(&self) -> impl Iterator<Item = &VmSnapshot> {
        self.vms.iter()
    }

    /// Returns the frozen host defaults and admission relationship when configured.
    pub fn host(&self) -> Option<&HostSnapshot> {
        self.host.as_ref()
    }
}

/// Editable machine assembly; network dependencies must be registered first.
/// GUI defaults resolve at finalization, allowing a display provider to launch its
/// own application without confusing that reference with a network startup cycle.
#[derive(Default)]
pub struct Machine {
    /// Unique identity retained by registered declarations, even after this builder drops.
    owner: Rc<()>,
    /// Registered declarations, never exposed for mutation or unchecked export.
    vms: Vec<VmReference>,
    /// Typed host relationships resolved in the same snapshot as the VM settings.
    host: Option<HostBindings>,
    /// Boot environment captured alongside the resolved host relationships.
    platform: HostPlatform,
    /// Diagnostic source declaration, checked for exact machine membership at finalization.
    diagnostic_observer: Option<VmReference>,
}

impl Machine {
    /// Designate the diagnostic client without granting permissions until finalization and deployment.
    pub(crate) fn set_diagnostic_observer<R>(&mut self, observer: &VmHandle<R>) {
        self.diagnostic_observer = Some(observer.reference.clone());
    }

    /// Selects the host boot environment for subsequent snapshots.
    pub fn set_host_platform(&mut self, platform: HostPlatform) {
        self.platform = platform;
    }

    /// Registers a VM after its network or launch-target dependencies.
    /// Failure preserves existing membership and permits retry after adding a dependency.
    /// Display assignments are checked later by `finish`, because they can point back
    /// to the GUI that launches an application.
    pub fn add<R, B>(&mut self, vm: &VmHandle<R, B>) -> Result<(), AuthoringError> {
        let definition = &vm.reference.definition;
        if let Some(owner) = definition.owner.get() {
            return Err(if Rc::ptr_eq(owner, &self.owner) {
                AuthoringError::AlreadyRegistered {
                    name: definition.name.to_string(),
                }
            } else {
                AuthoringError::ForeignMachine {
                    vm: definition.name.to_string(),
                    relation: "registration",
                    target: definition.name.to_string(),
                }
            });
        }

        if self
            .vms
            .iter()
            .any(|existing| existing.name() == vm.reference.name())
        {
            return Err(AuthoringError::DuplicateName {
                name: definition.name.to_string(),
            });
        }

        if let Role::Gui {
            default_application,
            ..
        } = &definition.role
        {
            self.check_reference(
                vm.reference.name(),
                "launch target",
                &default_application.definition,
            )?;
        } else if let Some(uplink) = definition.role.uplink() {
            self.check_reference(vm.reference.name(), "network", &uplink.definition)?;
        }

        definition
            .owner
            .set(Rc::clone(&self.owner))
            .expect("checked unregistered VM");
        self.vms.push(vm.reference.clone());

        Ok(())
    }

    /// Selects the host's GUI, network default and admission caller using role-checked handles.
    /// References may be assigned before registration; `finish` checks the actual declarations.
    pub fn set_host(
        &mut self,
        gui: &VmHandle<Gui>,
        network: &VmHandle<Firewall>,
        controller: &VmHandle<Controller>,
    ) {
        self.host = Some(HostBindings {
            gui: gui.reference.clone(),
            network: network.reference.clone(),
            controller: controller.reference.clone(),
        });
    }

    /// Rejects missing and foreign declarations with the relationship's full context.
    fn check_reference(
        &self,
        vm: &str,
        relation: &'static str,
        target: &VmDefinition,
    ) -> Result<(), AuthoringError> {
        match target.owner.get() {
            Some(owner) if Rc::ptr_eq(owner, &self.owner) => Ok(()),
            Some(_) => Err(AuthoringError::ForeignMachine {
                vm: vm.to_owned(),
                relation,
                target: target.name.to_string(),
            }),
            None => Err(AuthoringError::MissingDependency {
                vm: vm.to_owned(),
                relation,
                target: target.name.to_string(),
            }),
        }
    }

    /// Validates the complete current assembly and captures it without mutable references.
    /// Resource errors, missing defaults and foreign links are reported structurally.
    /// The builder and handles remain editable for a later snapshot or a corrected retry;
    /// earlier snapshots are immutable and are the sole inputs to Nix generation.
    pub fn finish(&self) -> Result<MachineSnapshot, AuthoringError> {
        let host = self
            .host
            .as_ref()
            .map(|bindings| self.freeze_host(bindings))
            .transpose()?;
        let mut vms = Vec::with_capacity(self.vms.len());
        let mut captures = Vec::new();
        let mut clipboards = Vec::new();

        for vm in &self.vms {
            let definition = &vm.definition;
            let settings = definition.settings.get();
            let (initial, maximum) = settings.memory.bounds();
            if initial.0 == 0
                || initial.0 > maximum.0
                || settings.vcpus == 0
                || (matches!(definition.backend, GuestBackend::Nixos) && settings.root_image.0 == 0)
                || definition
                    .role
                    .private_volume()
                    .is_some_and(|size| size.0 == 0)
            {
                return Err(AuthoringError::InvalidResources {
                    vm: vm.name().to_owned(),
                    reason: "resources must be positive and initial memory must not exceed maximum",
                });
            }

            if matches!(definition.backend, GuestBackend::Hermit { .. })
                && (initial.0 != maximum.0
                    || !(16..=256).contains(&initial.0)
                    || settings.vcpus != 1
                    || settings.root_image.0 != 0
                    || !definition.modules.borrow().is_empty()
                    || !definition.features.borrow().is_empty()
                    || !matches!(definition.role, Role::Service)
                    || definition.gui.borrow().is_some())
            {
                return Err(AuthoringError::InvalidResources {
                    vm: vm.name().to_owned(),
                    reason: "Hermit requires one CPU, fixed 16–256 MiB memory, and no Linux, GUI or storage configuration",
                });
            }

            if let Some(target) = definition.capture.borrow().as_ref() {
                let declaration = target.definition.upgrade().ok_or_else(|| {
                    AuthoringError::MissingDependency {
                        vm: vm.name().to_owned(),
                        relation: "capture destination",
                        target: target.name.to_string(),
                    }
                })?;
                self.check_reference(vm.name(), "capture destination", &declaration)?;

                let gnome_components = definition
                    .modules
                    .borrow()
                    .iter()
                    .filter(|module| module.gnome)
                    .count();
                if gnome_components != 1 {
                    return Err(AuthoringError::InvalidCapture {
                        vm: vm.name().to_owned(),
                        reason: "screen capture requires exactly one GNOME component",
                    });
                }

                captures.push(CaptureConnection {
                    source: definition.name.clone(),
                    target: target.name.clone(),
                });
            }

            if let Some(service) = definition.clipboard.borrow().as_ref() {
                self.check_reference(vm.name(), "clipboard service", &service.definition)?;
                if clipboards.iter().any(|connection: &ClipboardConnection| {
                    connection.service == service.definition.name
                }) {
                    return Err(AuthoringError::InvalidClipboard {
                        reason: "a clipboard service must belong to exactly one GUI session".into(),
                    });
                }
                clipboards.push(ClipboardConnection {
                    gui: definition.name.clone(),
                    service: service.definition.name.clone(),
                    participants: Vec::new(),
                });
            }
            let guivm = self.resolve_gui(vm, host.as_ref())?;
            vms.push(vm.snapshot(guivm));
        }

        crate::components::screen_capture::configure(&mut vms, &captures);
        crate::components::clipboard::configure(&mut vms, &mut clipboards, host.as_ref())?;
        if let Some(observer) = &self.diagnostic_observer {
            self.check_reference("diagnostics", "observer", &observer.definition)?;
        }
        let diagnostics = crate::components::diagnostics::configure(
            &mut vms,
            self.diagnostic_observer.as_ref().map(VmReference::name),
            host.is_some(),
        )?;

        let snapshot = MachineSnapshot {
            owner: Rc::clone(&self.owner),
            vms,
            host,
            captures,
            clipboards,
            diagnostics,
        };
        snapshot.relationships().ordered().map_err(|error| {
            AuthoringError::InvalidDependencies {
                reason: error.to_string(),
            }
        })?;

        Ok(snapshot)
    }

    /// Resolves typed host references and enforces identities required by upstream policy.
    fn freeze_host(&self, bindings: &HostBindings) -> Result<HostSnapshot, AuthoringError> {
        for (relation, reference) in [
            ("default GUI", &bindings.gui),
            ("default network", &bindings.network),
            ("admission controller", &bindings.controller),
        ] {
            self.check_reference("host", relation, &reference.definition)?;
        }

        // Existing machine-deployment scripts/policy name the controller and GUI.
        // Network defaults are configurable; no fixed firewall name is imposed here.
        for (role, expected, reference) in [
            ("bootstrap GUI", "sys-gui", &bindings.gui),
            ("admission controller", "sys-ctrl", &bindings.controller),
        ] {
            if reference.name() != expected {
                return Err(AuthoringError::RequiredIdentity {
                    role,
                    expected,
                    actual: reference.name().to_owned(),
                });
            }
        }

        Ok(HostSnapshot {
            platform: self.platform,
            gui: bindings.gui.definition.name.clone(),
            network: bindings.network.definition.name.clone(),
            controller: bindings.controller.definition.name.clone(),
        })
    }

    /// Resolves display dependencies separately from network/launch-target ordering.
    /// Explicit links override host defaults; command VMs otherwise preserve Qubes inheritance.
    fn resolve_gui(
        &self,
        vm: &VmReference,
        host: Option<&HostSnapshot>,
    ) -> Result<ReferenceSetting, AuthoringError> {
        if let Some(gui) = vm.definition.gui.borrow().as_ref() {
            let definition =
                gui.definition
                    .upgrade()
                    .ok_or_else(|| AuthoringError::MissingDependency {
                        vm: vm.name().to_owned(),
                        relation: "GUI",
                        target: gui.name.to_string(),
                    })?;
            self.check_reference(vm.name(), "GUI", &definition)?;

            return Ok(ReferenceSetting::Named(gui.name.as_vm_name().clone()));
        }

        match &vm.definition.role {
            Role::Gui {
                display: GuiDisplay::PhysicalAmd,
                ..
            } => Ok(ReferenceSetting::Disabled),
            Role::Gui { .. } => Ok(ReferenceSetting::Named(
                "dom0".parse().expect("fixed host identity"),
            )),
            Role::Service
            | Role::Isolated { .. }
            | Role::NetworkDriver { .. }
            | Role::Firewall { .. } => Ok(ReferenceSetting::Disabled),
            role => {
                let host = host.ok_or_else(|| AuthoringError::MissingHostReference {
                    vm: vm.name().to_owned(),
                    relation: "default GUI",
                })?;
                if matches!(role, Role::Command { .. }) {
                    Ok(ReferenceSetting::Inherit)
                } else {
                    Ok(ReferenceSetting::Named(host.gui.as_vm_name().clone()))
                }
            }
        }
    }
}
