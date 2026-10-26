//! Select native VM storage requests from the checked configuration and executing durable intent.
//! Filesystem resolution and the storage service remain explicit external adapters.
//!
//! ## Native VM storage requests
//!
//! The [storage boundary](crate::storage) retains each native backend in the exact checked
//! configuration order before intent publication. Selecting a backend requires the complete
//! executing operation context. Root import requests require a named halted observation and
//! a resolution naming that VM and its original root source. The import argv fixes the root
//! volume and resolved image. Private-volume growth requires the same named halted evidence,
//! an original declared capacity, and an observed capacity below it. Missing or unknown power
//! and capacity observations fail closed. Kernel requests retain the original effective kernel
//! name and source. Store requests retain the native executable, VM, system, root, closure,
//! descriptor and supported immutable layout; dispatch accepts no independent overrides.
//! A store request retains the selected generation explicitly, rejecting a different or
//! missing selection when the original release names one. The storage adapter passes that
//! number to the native service; decimal rendering is trusted. The service rejects a
//! conflicting staged ledger and does not reuse a different generation merely because its
//! boot sources match. The verified argv also requires retained/prepared data: the service
//! refuses fresh package admission during deployment reconciliation, including repair of
//! an unchanged VM whose runtime storage has drifted. Boot/manual admission retains its
//! separate policy.
//!
//! Native deployment calls the shared Rust backend reconciliation directly. Boot/manual setup
//! retains its separate compatibility policy. Immutable root import may repeat after a lost
//! reply; private growth reconciles current capacity. These are reconciliation guarantees,
//! not exactly-once execution. Qubes administrators can still change registration or state
//! between observation and dispatch.
//!
//! Derived kernel and boot settings have fixed typed keys and original backend values.
//! Mutation requires fresh named halted evidence; already matching values need no mutation.
//! Generation-dependent features and daemon restoration require a storage outcome matching
//! the VM, system, root, closure, kernel and the request's selected generation. A receipt
//! cannot select arbitrary feature keys or a different system service. Root-artifact features
//! must attest the original VM/root source. Boot-option interpolation, scalar decoding and
//! truthfulness of generation metadata remain trusted; the verified boundary confines the
//! retained values and rejects unclassified setting requests.
//!
//! [`staging`] derives generation obligations from the original checked stage/configure fields.
//! A complete `StagedGenerations` preserves pinned generations and complete boot identities;
//! required dependency work cannot become an omitted-map fallback. Only unpinned native VMs
//! without planned staging retain the explicit existing/prepared compatibility policy.
//! Native deployment consumes the opaque staging result in memory. Backend selection rechecks
//! attempt, stable operation, authority, plan and the executing durable gate. The final typed
//! argv retains the exact selected number and retained-only flag; adapters only render decimals.
//! `staged.json` is a derived compatibility projection and grants no native execution authority.
//! Each newly authorised recovery attempt resolves/revalidates its original requirements again;
//! an old token cannot migrate to it. Originally unpinned generations can be selected anew
//! under that fresh authorization, rather than acquiring an across-attempt numeric pin.
//!
//! Source decoding, physical Nix-path translation and source-to-root-image authentication
//! remain trusted. The storage service's admission, pool locking, offline snapshot updates,
//! restart journal and faithful Qubes/filesystem execution remain adapter duties. Its separate
//! verified attachment kernel retains its existing guarantees. In particular, the store request theorem confines its source and boot
//! parameters; it does not prove the inner storage algorithm or that a running VM experiences
//! no implicit effect. The independent observation-to-dispatch race remains outside the
//! theorem. Legacy full-batch
//! helpers and global setup retain their separately documented trusted boundaries.

pub mod staging;

use crate::{
    effects::{self, Targets},
    inventory::PowerState,
    operation::{DurableOperation, ExecutionContext, PlanBinding},
};
use vstd::prelude::*;

verus! {

/// Native backend parameters captured from the admitted candidate before publication.
pub struct Native {
    /// Approved NixOS guest system.
    pub system: String,
    /// Approved immutable boot disk source.
    pub root: String,
    /// Approved shared closure source.
    pub source: String,
    /// Physical closure descriptor selected by the trusted source-path adapter.
    pub artifact: String,
    /// Approved effective Qubes kernel name.
    pub kernel: String,
    /// Approved kernel files, or empty when no installation was declared.
    pub kernel_source: String,
    /// Effective boot options frozen before publication, including mandatory native-store options.
    pub kernelopts: String,
    /// Declared minimum private-state capacity; absence grants no resizing authority.
    pub private_size: Option<u64>,
    /// Original staged generation, when explicitly named by the release.
    pub generation: Option<u64>,
}

/// Immutable executable identity for a diskless Hermit guest.
pub struct Executable {
    /// System store object containing the executable.
    pub system: String,
    /// Canonical full artifact descriptor, including digest and source revisions.
    pub descriptor: String,
}

/// One checked configuration coordinate, including VMs without native storage.
pub struct Definition {
    /// Same name and index as the complete checked configure field.
    pub name: String,
    /// Native storage authority exists only for a declared native backend.
    pub native: Option<Native>,
    /// Diskless executable, mutually exclusive with native Linux storage.
    pub executable: Option<Executable>,
    /// Native storage executable selected before intent publication.
    pub service: String,
}

/// A power observation remains associated with the VM actually queried.
pub struct Power {
    /// Name in the observed Qubes inventory row.
    pub name: String,
    /// Verified interpretation of that row's state field.
    pub state: PowerState,
}

/// Root resolution must attest the source and VM of its returned file.
pub struct RootArtifact {
    /// VM whose retained root was resolved.
    pub name: String,
    /// Immutable root source used by resolution.
    pub source: String,
    /// Existing admitted artifact image; resolution authenticates its contents.
    pub image: String,
    /// Admitted artifact digest, used by boot-feature reconciliation.
    pub hash: String,
}

/// Every retained backend definition has the corresponding checked configuration identity.
pub open spec fn valid(s: (effects::Scope, Seq<Definition>, Seq<char>, effects::Scope)) -> bool {
    effects::valid(s.0) && s.1.len() == s.0.targets.len()
        && (forall|i: int| 0 <= i < s.1.len() ==> #[trigger] s.1[i].name@ == s.0.targets[i]@)
        && (forall|i: int| 0 <= i < s.3.targets.len() ==> effects::planned(s.0, #[trigger] s.3.targets[i]@))
}

/// Immutable backend authority, available only through the complete checked deployment plan.
pub struct StoragePlan {
    // Original reviewed configuration namespace.
    targets: Targets,
    // Exact admitted backend definitions in configuration order.
    definitions: Vec<Definition>,
    // Complete candidate, baseline, revision and plan binding.
    binding: PlanBinding,
    // Original checked VM namespace requiring generation staging.
    stage: Targets,
}

impl View for StoragePlan {
    type V = (effects::Scope, Seq<Definition>, Seq<char>, effects::Scope);

    closed spec fn view(&self) -> Self::V { (self.targets@, self.definitions@, self.binding@, self.stage@) }
}

impl StoragePlan {
    /// Bind backend definitions to the complete ordered configuration namespace.
    pub(crate) fn new(targets: Targets, definitions: Vec<Definition>, binding: PlanBinding, stage: Targets) -> (out: Option<Self>)
        ensures out.is_some() ==> out.unwrap()@ == (targets@, definitions@, binding@, stage@),
            out.is_some() && effects::valid(targets@) ==> valid(out.unwrap()@),
    {
        let names = targets.names();
        if definitions.len() != names.len() { return None; }
        let mut i = 0;
        while i < definitions.len()
            invariant 0 <= i <= definitions.len(), definitions.len() == names.len(),
                forall|j: int| 0 <= j < i ==> #[trigger] definitions[j].name@ == names[j]@,
            decreases definitions.len() - i,
        {
            if definitions[i].name.as_str() != names[i].as_str() { return None; }
            assert(definitions[i as int].name@ == names[i as int]@);
            i += 1;
        }

        let staged_names = stage.names();
        let mut k = 0;
        while k < staged_names.len()
            invariant 0 <= k <= staged_names.len(),
                forall|j: int| 0 <= j < k ==> effects::planned(targets@, #[trigger] staged_names[j]@),
                definitions.len() == names.len(),
                forall|j: int| 0 <= j < definitions.len() ==> #[trigger] definitions[j].name@ == names[j]@,
            decreases staged_names.len() - k,
        {
            if !targets.contains(staged_names[k].as_str()) { return None; }
            k += 1;
        }
        Some(Self { targets, definitions, binding, stage })
    }

    /// Observe retained definitions without permitting effects.
    pub fn definitions(&self) -> (out: &[Definition]) ensures out@ == self@.1,
    { self.definitions.as_slice() }

    /// Every native request family starts with this exact checked execution context.
    pub fn select<'a>(&'a self, durable: &'a DurableOperation, context: &ExecutionContext, index: usize)
        -> (out: Option<Backend<'a>>)
        ensures out.is_some() ==> crate::operation::executing(durable, context) && context.plan@ == self@.2,
            out.is_some() ==> index < self@.1.len() && self@.1[index as int].native.is_some(),
            out.is_some() ==> out.unwrap()@ == self@.1[index as int],
            out.is_some() && valid(self@) && self@.0.reviewed ==> self@.0.allowed.contains(out.unwrap()@.name@),
    {
        if !durable.allows_effect(context) || context.plan.as_str() != self.binding.as_str() || index >= self.definitions.len() { return None; }
        let d = &self.definitions[index];
        if !self.targets.contains(d.name.as_str()) || d.native.is_none() { return None; }
        Some(Backend { definition: d, _durable: durable })
    }
}

/// A retained backend is not itself an upstream command or independently supplied parameter set.
/// Store dispatch additionally requires the complete staging result.
///
/// ```compile_fail,E0624
/// use airlock_deployment_core::storage::Backend;
/// /// A raw backend cannot choose its own generation or omit required staging.
/// fn bypass(backend: &Backend<'_>) { let _ = backend.store(Some(7)); }
/// ```
pub struct Backend<'a> {
    // Complete immutable backend selected from the checked namespace.
    definition: &'a Definition,
    // Prevents invalidation of the executing gate while requests borrow it.
    _durable: &'a DurableOperation,
}

impl<'a> View for Backend<'a> {
    type V = Definition;

    closed spec fn view(&self) -> Definition { *self.definition }
}

/// Power evidence is both named and explicitly halted, never an unknown-is-stopped convention.
pub open spec fn halted(d: Definition, o: Power) -> bool { o.name@ == d.name@ && o.state@ is Halted }

impl<'a> Backend<'a> {
    /// Observe the exact original parameters used by read-only reconciliation.
    pub fn definition(&self) -> (out: &Definition) ensures *out == self@,
    { self.definition }

    /// Import only an admitted image resolved for this VM's original root source.
    pub fn root<'b>(&'b self, artifact: &'b RootArtifact, observed: &Power) -> (out: Option<RootRequest<'b>>)
        ensures out.is_some() ==> self@.native.is_some() && halted(self@, *observed),
            out.is_some() ==> artifact.name@ == self@.name@ && artifact.source@ == self@.native.unwrap().root@,
            out.is_some() ==> out.unwrap()@ == (self@, *artifact),
    {
        let native = self.definition.native.as_ref()?;
        if observed.name.as_str() != self.definition.name.as_str() || !observed.state.is_halted()
            || artifact.name.as_str() != self.definition.name.as_str() || artifact.source.as_str() != native.root.as_str()
            || artifact.image.is_empty() { return None; }
        Some(RootRequest { definition: self.definition, artifact, _durable: self._durable })
    }

    /// Resizing is limited to the declared minimum and never shrinks observed private state.
    pub fn resize<'b>(&'b self, observed: &Power, current: u64) -> (out: Option<ResizeRequest<'b>>)
        ensures out.is_some() ==> self@.native.is_some() && halted(self@, *observed),
            out.is_some() ==> self@.native.unwrap().private_size.is_some()
                && out.unwrap()@ == (self@.name@, self@.native.unwrap().private_size.unwrap()) && current < out.unwrap()@.1,
    {
        let n = self.definition.native.as_ref()?;
        let size = n.private_size?;
        if observed.name.as_str() != self.definition.name.as_str() || !observed.state.is_halted() || current >= size { return None; }
        Some(ResizeRequest { name: self.definition.name.as_str(), size, _durable: self._durable })
    }

    /// Install only the original nonempty kernel source under its effective approved name.
    pub fn kernel<'b>(&'b self) -> (out: Option<KernelRequest<'b>>)
        ensures out.is_some() ==> self@.native.is_some() && self@.native.unwrap().kernel_source@.len() > 0,
            out.is_some() ==> out.unwrap()@ == self@,
    {
        let n = self.definition.native.as_ref()?;
        if n.kernel_source.is_empty() { return None; }
        Some(KernelRequest { definition: self.definition, _durable: self._durable })
    }

    /// Delegate store installation using only retained source, layout and boot parameters.
    /// The storage adapter separately authenticates admission and serializes offline attachment.
    fn store<'b>(&'b self, generation: Option<u64>) -> (out: Option<StoreRequest<'b>>)
        ensures out.is_some() ==> self@.native.is_some() && out.unwrap()@ == (self@, generation),
            out.is_some() ==> match self@.native.unwrap().generation { Some(g) => generation == Some(g), None => true },
            out.is_some() ==> match generation { Some(g) => g > 0, None => true },
    {
        let n = self.definition.native.as_ref()?;
        if match n.generation { Some(g) => generation != Some(g), None => false } { return None; }
        if match generation { Some(g) => g == 0, None => false } { return None; }
        Some(StoreRequest { definition: self.definition, generation, _durable: self._durable })
    }
}

/// Kernel installation receives no independently supplied name or source.
pub struct KernelRequest<'a> {
    // Original VM and immutable kernel source definition.
    definition: &'a Definition,
    // Keep the executing gate borrowed through filesystem installation.
    _durable: &'a DurableOperation,
}

impl<'a> View for KernelRequest<'a> {
    type V = Definition;

    closed spec fn view(&self) -> Definition { *self.definition }
}

impl<'a> KernelRequest<'a> {
    /// Exact VM, effective kernel name and source consumed by the filesystem adapter.
    pub fn parameters(&self) -> (out: (&str, &str, &str))
        ensures self@.native.is_some() ==> out.0@ == self@.name@
            && out.1@ == self@.native.unwrap().kernel@ && out.2@ == self@.native.unwrap().kernel_source@,
    {
        match &self.definition.native {
            Some(n) => (self.definition.name.as_str(), n.kernel.as_str(), n.kernel_source.as_str()),
            None => (self.definition.name.as_str(), "", ""),
        }
    }
}

/// Exact admitted root image and target, accepted without independent adapter parameters.
pub struct RootRequest<'a> {
    // Immutable approved VM and root source.
    definition: &'a Definition,
    // Authenticated source-to-image resolution; never an arbitrary path selector.
    artifact: &'a RootArtifact,
    // Keep execution authority borrowed until dispatch finishes.
    _durable: &'a DurableOperation,
}

impl<'a> View for RootRequest<'a> {
    type V = (Definition, RootArtifact);

    closed spec fn view(&self) -> Self::V { (*self.definition, *self.artifact) }
}

impl<'a> RootRequest<'a> {
    /// Root import cannot substitute another VM or another volume kind.
    pub fn arguments(&self) -> (out: Vec<String>)
        ensures out.len() == 3 && out[0]@ == "import"@ && out[1]@ == self@.0.name@ + ":root"@ && out[2]@ == self@.1.image@,
    {
        let mut volume = self.definition.name.as_str().to_string();
        volume.push_str(":root");
        vec!["import".to_string(), volume, self.artifact.image.as_str().to_string()]
    }
}

/// Private state may only grow to this original declared capacity.
pub struct ResizeRequest<'a> {
    // Same VM selected by Backend::resize.
    name: &'a str,
    // Original minimum size, numerically checked before rendering by the adapter.
    size: u64,
    // Keep the checked durable state borrowed.
    _durable: &'a DurableOperation,
}

impl<'a> View for ResizeRequest<'a> {
    type V = (Seq<char>, u64);

    closed spec fn view(&self) -> Self::V { (self.name@, self.size) }
}

impl<'a> ResizeRequest<'a> {
    /// Fixed private-volume target; callers cannot supply another disk name.
    pub fn volume(&self) -> (out: String) ensures out@ == self@.0 + ":private"@,
    { let mut out = self.name.to_string(); out.push_str(":private"); out }

    /// Exact original numeric capacity; decimal rendering is a trusted adapter duty.
    pub fn size(&self) -> (out: u64) ensures out == self@.1,
    { self.size }
}

/// Store attachment preserves every authorised source and supported layout parameter.
pub struct StoreRequest<'a> {
    // Complete backend retained before durable publication.
    definition: &'a Definition,
    // Exact staged generation selected for this request, never inferred by the adapter.
    generation: Option<u64>,
    // Borrowed publication/execution authority.
    _durable: &'a DurableOperation,
}

impl<'a> View for StoreRequest<'a> {
    type V = (Definition, Option<u64>);

    closed spec fn view(&self) -> Self::V { (*self.definition, self.generation) }
}

impl<'a> StoreRequest<'a> {
    /// No dispatch-time override of the native storage executable is accepted.
    pub fn program(&self) -> (out: &str) ensures out@ == self@.0.service@,
    { self.definition.service.as_str() }

    /// Exact generation passed to the storage adapter; absence retains its admission policy.
    pub fn generation(&self) -> (out: Option<u64>) ensures out == self@.1,
    { self.generation }

    /// The adapter receives a fixed operation and exact approved boot/storage identities.
    pub fn arguments(&self) -> (out: Vec<String>)
        ensures self@.0.native.is_some() ==> out.len() == 23
            && out[0]@ == "storage"@ && out[1]@ == "domain"@ && out[2]@ == "ensure-store"@
            && out[3]@ == self@.0.name@ && out[4]@ == (if self@.1.is_some() { self@.0.native.unwrap().source@ } else { self@.0.native.unwrap().artifact@ }) && out[5]@ == self@.0.native.unwrap().source@
            && out[6]@ == "--mode"@ && out[7]@ == "shared-closure"@
            && out[8]@ == "--system"@ && out[9]@ == self@.0.native.unwrap().system@
            && out[10]@ == "--root"@ && out[11]@ == self@.0.native.unwrap().root@
            && out[12]@ == "--kernel"@ && out[13]@ == self@.0.native.unwrap().kernel@
            && out[14]@ == "--device"@ && out[15]@ == "/dev/xvde"@
            && out[16]@ == "--blob-device"@ && out[17]@ == "/dev/xvdf"@
            && out[18]@ == "--mountpoint"@ && out[19]@ == "/nix/store"@
            && out[20]@ == "--view-backend"@ && out[21]@ == "erofs-objectmap"@ && out[22]@ == "--require-retained"@,
    {
        let n = match &self.definition.native { Some(n) => n, None => return Vec::new() };
        vec!["storage".to_string(), "domain".to_string(), "ensure-store".to_string(), self.definition.name.as_str().to_string(),
            if self.generation.is_some() { n.source.as_str().to_string() } else { n.artifact.as_str().to_string() }, n.source.as_str().to_string(), "--mode".to_string(), "shared-closure".to_string(),
            "--system".to_string(), n.system.as_str().to_string(), "--root".to_string(), n.root.as_str().to_string(),
            "--kernel".to_string(), n.kernel.as_str().to_string(), "--device".to_string(), "/dev/xvde".to_string(),
            "--blob-device".to_string(), "/dev/xvdf".to_string(), "--mountpoint".to_string(), "/nix/store".to_string(),
            "--view-backend".to_string(), "erofs-objectmap".to_string(), "--require-retained".to_string()]
    }
}

/// Literal argument equality at the final executable storage boundary.
pub open spec fn argument_text(arg: crate::boot::Argument, value: Seq<char>) -> bool {
    arg is Text && arg->Text_0@ == value
}

/// Independent fixed storage prefix: all approved fields and the retained-only policy.
pub open spec fn store_prefix(d: Definition, generation: Option<u64>) -> Seq<Seq<char>> {
    let n = d.native.unwrap();
    seq!["storage"@, "domain"@, "ensure-store"@, d.name@,
        if generation.is_some() { n.source@ } else { n.artifact@ }, n.source@,
        "--mode"@, "shared-closure"@, "--system"@, n.system@, "--root"@, n.root@,
        "--kernel"@, n.kernel@, "--device"@, "/dev/xvde"@, "--blob-device"@, "/dev/xvdf"@,
        "--mountpoint"@, "/nix/store"@, "--view-backend"@, "erofs-objectmap"@, "--require-retained"@]
}

impl<'a> StoreRequest<'a> {
    /// Include the exact selected generation in the privileged invocation; only decimal rendering remains external.
    pub fn dispatch_arguments(&self) -> (out: Vec<crate::boot::Argument>)
        ensures self@.0.native.is_some() ==> {
            &&& out.len() == (if self@.1.is_some() { 25usize } else { 23usize })
            &&& forall|i: int| 0 <= i < 23 ==> argument_text(#[trigger] out[i], store_prefix(self@.0, self@.1)[i])
            &&& self@.1.is_some() ==> argument_text(out[23], "--generation"@)
                && out[24] is Generation && out[24]->Generation_0 == self@.1.unwrap()
        },
    {
        let base = self.arguments();
        let mut args = Vec::new();
        let mut i = 0;
        while i < base.len()
            invariant 0 <= i <= base.len(), args.len() == i,
                forall|j: int| 0 <= j < i ==> argument_text(#[trigger] args[j], base[j]@),
            decreases base.len() - i,
        {
            args.push(crate::boot::Argument::Text(base[i].clone()));
            i += 1;
        }

        if let Some(generation) = self.generation {
            args.push(crate::boot::Argument::Text("--generation".to_string()));
            args.push(crate::boot::Argument::Generation(generation));
        }

        args
    }
}

/// Boot settings derived only from the original checked backend.
#[derive(Clone, Copy)]
pub enum BootField {
    /// Qubes kernel name.
    Kernel,
    /// Effective boot command line.
    Kernelopts,
    /// Native backend marker.
    Backend,
    /// Guest NixOS system.
    System,
    /// Immutable root source.
    Root,
    /// Shared closure source.
    Source,
    /// Immutable shared-closure mode.
    Mode,
    /// Supported metadata layout.
    ViewBackend,
    /// Metadata filesystem format.
    Filesystem,
    /// Canonical guest store mount.
    Mountpoint,
    /// Metadata frontend.
    Device,
    /// External-data frontend.
    BlobDevice,
    /// Read-only store policy.
    ReadOnly,
}

/// Independent fixed mapping from backend fields to upstream boot-setting keys.
pub open spec fn boot_key(field: BootField) -> Seq<char> {
    match field {
        BootField::Kernel => "kernel"@, BootField::Kernelopts => "kernelopts"@,
        BootField::Backend => "airlock-backend"@, BootField::System => "airlock-system-source"@,
        BootField::Root => "airlock-root-source"@, BootField::Source => "airlock-store-source"@,
        BootField::Mode => "airlock-store-mode"@, BootField::ViewBackend => "airlock-store-view-backend"@,
        BootField::Filesystem => "airlock-store-filesystem"@, BootField::Mountpoint => "airlock-store-mountpoint"@,
        BootField::Device => "airlock-store-device"@, BootField::BlobDevice => "airlock-store-blob-device"@,
        BootField::ReadOnly => "airlock-store-read-only"@,
    }
}

/// Values are fixed by original sources and the single supported storage layout.
pub open spec fn boot_value(n: Native, field: BootField) -> Seq<char> {
    match field {
        BootField::Kernel => n.kernel@, BootField::Kernelopts => n.kernelopts@,
        BootField::Backend => "nix-closure"@, BootField::System => n.system@,
        BootField::Root => n.root@, BootField::Source => n.source@,
        BootField::Mode => "shared-closure"@, BootField::ViewBackend => "erofs-objectmap"@,
        BootField::Filesystem => "erofs"@, BootField::Mountpoint => "/nix/store"@,
        BootField::Device => "/dev/xvde"@, BootField::BlobDevice => "/dev/xvdf"@,
        BootField::ReadOnly => "True"@,
    }
}

/// Kernel settings are properties; all other boot identity fields are features.
pub open spec fn boot_property(field: BootField) -> bool { field is Kernel || field is Kernelopts }

/// Upstream setting request whose target, family, key and value have all been selected.
pub struct BootRequest<'a> {
    // VM borrowed from the checked backend.
    name: &'a str,
    // Fixed setting key chosen by its typed field.
    key: &'static str,
    // Original backend value or authenticated generation evidence.
    value: &'a str,
    // Selects qvm-prefs instead of qvm-features for kernel properties.
    property: bool,
    // Prevents completing/interruption of the gate during dispatch.
    _durable: &'a DurableOperation,
}

impl<'a> View for BootRequest<'a> {
    type V = (Seq<char>, Seq<char>, Seq<char>, bool);

    closed spec fn view(&self) -> Self::V { (self.name@, self.key@, self.value@, self.property) }
}

impl<'a> BootRequest<'a> {
    /// No dispatch-time tool override is accepted.
    pub fn program(&self) -> (out: &str)
        ensures out@ == if self@.3 { "qvm-prefs"@ } else { "qvm-features"@ },
    { if self.property { "qvm-prefs" } else { "qvm-features" } }

    /// Only this original VM and selected boot identity reach Qubes.
    pub fn arguments(&self) -> (out: Vec<String>)
        ensures out.len() == 3 && out[0]@ == self@.0 && out[1]@ == self@.1 && out[2]@ == self@.2,
    { vec![self.name.to_string(), self.key.to_string(), self.value.to_string()] }
}

impl<'a> Backend<'a> {
    /// Boot identity mutation requires the original field and a freshly named halted VM.
    pub fn setting<'b>(&'b self, field: BootField, observed: &Power) -> (out: Option<BootRequest<'b>>)
        ensures out.is_some() ==> self@.native.is_some() && halted(self@, *observed),
            out.is_some() ==> out.unwrap()@ == (self@.name@, boot_key(field), boot_value(self@.native.unwrap(), field), boot_property(field)),
    {
        let n = self.definition.native.as_ref()?;
        if observed.name.as_str() != self.definition.name.as_str() || !observed.state.is_halted() { return None; }
        let key = match field {
            BootField::Kernel => "kernel", BootField::Kernelopts => "kernelopts",
            BootField::Backend => "airlock-backend", BootField::System => "airlock-system-source",
            BootField::Root => "airlock-root-source", BootField::Source => "airlock-store-source",
            BootField::Mode => "airlock-store-mode", BootField::ViewBackend => "airlock-store-view-backend",
            BootField::Filesystem => "airlock-store-filesystem", BootField::Mountpoint => "airlock-store-mountpoint",
            BootField::Device => "airlock-store-device", BootField::BlobDevice => "airlock-store-blob-device",
            BootField::ReadOnly => "airlock-store-read-only",
        };
        let value = match field {
            BootField::Kernel => n.kernel.as_str(), BootField::Kernelopts => n.kernelopts.as_str(),
            BootField::Backend => "nix-closure", BootField::System => n.system.as_str(),
            BootField::Root => n.root.as_str(), BootField::Source => n.source.as_str(),
            BootField::Mode => "shared-closure", BootField::ViewBackend => "erofs-objectmap",
            BootField::Filesystem => "erofs", BootField::Mountpoint => "/nix/store",
            BootField::Device => "/dev/xvde", BootField::BlobDevice => "/dev/xvdf",
            BootField::ReadOnly => "True",
        };
        Some(BootRequest { name: self.definition.name.as_str(), key, value,
            property: matches!(field, BootField::Kernel | BootField::Kernelopts), _durable: self._durable })
    }

    /// The root-artifact feature must attest the original root source and target.
    pub fn root_setting<'b>(&'b self, artifact: &'b RootArtifact, observed: &Power) -> (out: Option<BootRequest<'b>>)
        ensures out.is_some() ==> self@.native.is_some() && halted(self@, *observed),
            out.is_some() ==> artifact.source@ == self@.native.unwrap().root@ && artifact.name@ == self@.name@,
            out.is_some() ==> out.unwrap()@ == (self@.name@, "airlock-root-artifact"@, artifact.hash@, false),
    {
        let n = self.definition.native.as_ref()?;
        if artifact.source.as_str() != n.root.as_str() || artifact.name.as_str() != self.definition.name.as_str()
            || observed.name.as_str() != self.definition.name.as_str() || !observed.state.is_halted() { return None; }
        Some(BootRequest { name: self.definition.name.as_str(), key: "airlock-root-artifact", value: artifact.hash.as_str(), property: false, _durable: self._durable })
    }
}

/// Decoded storage outcome; no field independently grants permission to mutate a VM.
pub struct StoreEvidence {
    /// VM whose installation returned this receipt.
    pub name: String,
    /// Selected guest system.
    pub system: String,
    /// Selected root source.
    pub root: String,
    /// Selected closure source.
    pub source: String,
    /// Selected Qubes kernel.
    pub kernel: String,
    /// Positive admitted storage generation.
    pub generation: u64,
    /// Decimal rendering of generation; rendering fidelity is a decoder contract.
    pub generation_text: String,
    /// Closure digest reported for this generation.
    pub closure_hash: String,
    /// Metadata image selected for this generation.
    pub view_image: String,
    /// External-data map selected for this generation.
    pub blob_map: String,
    /// External-data volume selected for this generation.
    pub blob_volume: String,
    /// Whether an offline update still requires qubesd restoration.
    pub restart_required: bool,
    /// Whether the storage service already restored qubesd.
    pub restarted: bool,
}

/// A receipt is acceptable only for this backend's full boot identity and named generation.
pub open spec fn receipt_matches(d: Definition, selected: Option<u64>, e: StoreEvidence) -> bool {
    d.native.is_some() && e.name@ == d.name@ && e.system@ == d.native.unwrap().system@
        && e.root@ == d.native.unwrap().root@ && e.source@ == d.native.unwrap().source@
        && e.kernel@ == d.native.unwrap().kernel@ && e.generation > 0
        && (match d.native.unwrap().generation { Some(g) => e.generation == g, None => true })
        && (match selected { Some(g) => e.generation == g, None => true })
}

/// Authenticated selection evidence borrows the same backend and durable gate.
pub struct StoreOutcome<'a> {
    // Original backend identity; the receipt cannot replace it.
    definition: &'a Definition,
    // Fully checked source/boot binding returned by the storage adapter.
    evidence: &'a StoreEvidence,
    // Keep the approved operation executing while derived requests are dispatched.
    _durable: &'a DurableOperation,
}

impl<'a> View for StoreOutcome<'a> {
    type V = (Definition, StoreEvidence);

    closed spec fn view(&self) -> Self::V { (*self.definition, *self.evidence) }
}

impl<'a> StoreRequest<'a> {
    /// Wrong VM, source, boot identity or explicitly staged generation yields no derived authority.
    pub fn outcome<'b>(&'b self, e: &'b StoreEvidence) -> (out: Option<StoreOutcome<'b>>)
        ensures out.is_some() == receipt_matches(self@.0, self@.1, *e), out.is_some() ==> out.unwrap()@ == (self@.0, *e),
    {
        let n = self.definition.native.as_ref()?;
        if e.name.as_str() != self.definition.name.as_str() || e.system.as_str() != n.system.as_str()
            || e.root.as_str() != n.root.as_str() || e.source.as_str() != n.source.as_str()
            || e.kernel.as_str() != n.kernel.as_str() || e.generation == 0 { return None; }
        if match n.generation { Some(g) => g != e.generation, None => false } { return None; }
        if match self.generation { Some(g) => g != e.generation, None => false } { return None; }
        Some(StoreOutcome { definition: self.definition, evidence: e, _durable: self._durable })
    }
}

/// Only these generation-dependent features can be selected from an accepted receipt.
#[derive(Clone, Copy)]
pub enum ReceiptField {
    /// Decimal generation identity.
    Generation,
    /// Immutable closure digest.
    ClosureHash,
    /// Metadata image identity.
    ViewImage,
    /// External-data map identity.
    BlobMap,
    /// External-data volume identity.
    BlobVolume,
}

/// Fixed keys cannot be supplied by an external storage response.
pub open spec fn receipt_key(field: ReceiptField) -> Seq<char> {
    match field { ReceiptField::Generation => "airlock-store-generation"@, ReceiptField::ClosureHash => "airlock-store-closure-hash"@,
        ReceiptField::ViewImage => "airlock-store-view-image"@, ReceiptField::BlobMap => "airlock-store-blob-map"@,
        ReceiptField::BlobVolume => "airlock-store-blob-volume"@ }
}

/// Values are selected only from their corresponding fields of the validated receipt.
pub open spec fn receipt_value(e: StoreEvidence, field: ReceiptField) -> Seq<char> {
    match field { ReceiptField::Generation => e.generation_text@, ReceiptField::ClosureHash => e.closure_hash@,
        ReceiptField::ViewImage => e.view_image@, ReceiptField::BlobMap => e.blob_map@, ReceiptField::BlobVolume => e.blob_volume@ }
}

impl<'a> StoreOutcome<'a> {
    /// Generation features cannot acquire authority over another VM or a different feature key.
    pub fn setting<'b>(&'b self, field: ReceiptField, observed: &Power) -> (out: Option<BootRequest<'b>>)
        ensures out.is_some() ==> halted(self@.0, *observed),
            out.is_some() ==> out.unwrap()@ == (self@.0.name@, receipt_key(field), receipt_value(self@.1, field), false),
    {
        if observed.name.as_str() != self.definition.name.as_str() || !observed.state.is_halted() { return None; }
        let key = match field { ReceiptField::Generation => "airlock-store-generation", ReceiptField::ClosureHash => "airlock-store-closure-hash",
            ReceiptField::ViewImage => "airlock-store-view-image", ReceiptField::BlobMap => "airlock-store-blob-map", ReceiptField::BlobVolume => "airlock-store-blob-volume" };
        let e = self.evidence;
        let value = match field { ReceiptField::Generation => e.generation_text.as_str(), ReceiptField::ClosureHash => e.closure_hash.as_str(),
            ReceiptField::ViewImage => e.view_image.as_str(), ReceiptField::BlobMap => e.blob_map.as_str(), ReceiptField::BlobVolume => e.blob_volume.as_str() };
        Some(BootRequest { name: self.definition.name.as_str(), key, value, property: false, _durable: self._durable })
    }

    /// Only an accepted storage outcome needing restoration permits this fixed daemon request.
    pub fn restart<'b>(&'b self) -> (out: Option<RestartRequest<'b>>)
        ensures out.is_some() == (self@.1.restart_required && !self@.1.restarted),
    {
        if !self.evidence.restart_required || self.evidence.restarted { return None; }
        Some(RestartRequest { _durable: self._durable })
    }
}

/// Fixed qubesd restoration; cannot select a different system service or operation.
pub struct RestartRequest<'a> {
    // Keep the original durable execution gate borrowed through restoration.
    _durable: &'a DurableOperation,
}

impl<'a> RestartRequest<'a> {
    /// The adapter supplies no independent daemon name or systemctl action.
    pub fn arguments(&self) -> (out: Vec<String>)
        ensures out.len() == 2 && out[0]@ == "try-restart"@ && out[1]@ == "qubesd.service"@,
    { vec!["try-restart".to_string(), "qubesd.service".to_string()] }
}

}
