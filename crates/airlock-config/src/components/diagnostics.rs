//! A frozen observer relationship supplies endpoint contracts and exact Qubes permissions.
//! Automatic approval deliberately permits raw evidence; sources are not secret-free.

use crate::model::{AuthoringError, Machine, VmHandle, VmSnapshot};
use airlock_build::{Application, Workspace};
use airlock_diagnostics::{
    ApprovalMode, CONFIG_SCHEMA, CallerId, OUTPUT_LIMIT, Probe, ServerConfig, TargetId,
};
use rusix::{
    interop::raw::{NixRepresentation, NixValue},
    nix_record, nix_text,
    nixos::{ContextualModule, ModuleBody, ModuleContext, NixosModule},
};

pub use airlock_diagnostics::{Reader, Source, SourceId};

/// Exact observer and endpoints captured by machine finalization.
#[derive(Clone)]
pub struct Access {
    /// Authenticated VM granted diagnostic access, independent of deployment rights.
    observer: CallerId,
    /// Complete immutable endpoint inventories, including dom0 when a host exists.
    endpoints: Vec<ServerConfig>,
}

impl Access {
    /// Borrow endpoint contracts used for both lowering and permission generation.
    pub fn endpoints(&self) -> &[ServerConfig] {
        &self.endpoints
    }

    /// Exact Qubes caller selected by the authored relationship.
    pub fn observer(&self) -> &CallerId {
        &self.observer
    }
}

/// Designate one registered VM to inspect every registered VM and the configured host.
/// This initial policy automatically approves diagnostic requests, including raw logs.
/// Finalization checks declaration ownership; no permissions change before deployment.
pub fn enable<R>(machine: &mut Machine, observer: &VmHandle<R>) {
    machine.set_diagnostic_observer(observer);
}

/// Declare a stable source with an implementation-owned reader.
fn source(id: &str, description: &str, reader: Reader) -> Source {
    Source {
        id: id.parse().expect("static source identity"),
        description: description.into(),
        reader,
    }
}

/// Common readers work for upstream applications without requiring an Airlock wrapper per app.
fn sources() -> Vec<Source> {
    vec![
        source(
            "journal",
            "System service logs for the current boot; may contain sensitive data",
            Reader::Journal {},
        ),
        source(
            "user-journal",
            "User service logs for UID 1000; may contain personal data",
            Reader::UserJournal { uid: 1000 },
        ),
        source(
            "kernel",
            "Kernel messages for the current boot",
            Reader::Kernel {},
        ),
        source(
            "services",
            "System service inventory and current state",
            Reader::Probe {
                probe: Probe::Services,
            },
        ),
        source(
            "pci",
            "PCI hardware and driver bindings",
            Reader::Probe { probe: Probe::Pci },
        ),
        source(
            "addresses",
            "Network interfaces and assigned addresses",
            Reader::Probe {
                probe: Probe::Addresses,
            },
        ),
        source(
            "routes",
            "Routing tables",
            Reader::Probe {
                probe: Probe::Routes,
            },
        ),
        source(
            "mounts",
            "Mounted filesystem state",
            Reader::Probe {
                probe: Probe::Mounts,
            },
        ),
        source(
            "os-release",
            "Installed operating-system identity",
            Reader::StoreFile {
                path: "/etc/os-release".into(),
            },
        ),
    ]
}

/// Construct and validate one immutable server contract before creating any module.
fn contract(
    target: &str,
    observer: &str,
    sources: Vec<Source>,
) -> Result<ServerConfig, AuthoringError> {
    let make = || -> anyhow::Result<ServerConfig> {
        let config = ServerConfig {
            schema: CONFIG_SCHEMA.into(),
            target: target.parse()?,
            callers: vec![observer.parse()?],
            approval: ApprovalMode::Automatic,
            max_bytes: OUTPUT_LIMIT,
            sources,
        };
        config.validate()?;
        Ok(config)
    };
    make().map_err(|error| AuthoringError::InvalidDiagnostics {
        reason: format!("{target}: {error}"),
    })
}

/// Freeze component sources and derive both sides of the observer connection.
pub(crate) fn configure(
    vms: &mut [VmSnapshot],
    observer: Option<&str>,
    host: bool,
) -> Result<Option<Access>, AuthoringError> {
    // Validate declarations even when diagnostic access has not been enabled.
    let mut endpoints = Vec::new();
    for vm in vms.iter_mut() {
        // Hermit has no qrexec endpoint; its retained console is observed through dom0.
        if matches!(vm.backend, crate::model::GuestBackend::Hermit { .. }) {
            continue;
        }
        let mut inventory = sources();
        inventory.extend(vm.diagnostic_sources.clone());
        let mut config = contract(vm.name.as_str(), observer.unwrap_or("disabled"), inventory)?;
        if observer == Some(vm.name.as_str()) {
            config
                .callers
                .push("dom0".parse().expect("static identity"));
        }
        if observer.is_some() {
            vm.modules.push(endpoint(config.clone(), None));
            endpoints.push(config);
        }
    }
    let Some(observer) = observer else {
        return Ok(None);
    };
    if host {
        let mut inventory = sources();
        for (id, description, probe) in [
            ("xen-info", "Xen host information", Probe::XenInfo),
            ("xen-log", "Xen retained messages", Probe::XenLog),
            (
                "qubes",
                "VM state without starting stopped VMs",
                Probe::Qubes,
            ),
        ] {
            inventory.push(source(id, description, Reader::Probe { probe }));
        }
        for vm in vms.iter() {
            inventory.push(source(
                &format!("console-{name}", name = vm.name),
                &format!(
                    "Retained {name} console; may include earlier guest boots and sensitive data",
                    name = vm.name
                ),
                Reader::File {
                    path: format!("/var/log/xen/console/guest-{name}.log", name = vm.name),
                    tail: true,
                    owner: 0,
                },
            ));
        }
        endpoints.push(contract("dom0", observer, inventory)?);
    }
    let access = Access {
        observer: observer.parse().expect("registered VM name"),
        endpoints,
    };
    if let Some(vm) = vms.iter_mut().find(|vm| vm.name.as_str() == observer) {
        vm.modules.push(client(&access));
    }
    Ok(Some(access))
}

/// Exact target rules prevent observation from starting a halted VM or gaining Qubes administration.
pub fn policy(access: &Access) -> String {
    let mut policy = String::new();
    for endpoint in &access.endpoints {
        if endpoint.target.as_str() == access.observer.as_str() {
            continue;
        }
        policy.push_str(&format!(
            "airlock.Diagnostics + {caller} {target} allow user=root autostart=no\n",
            caller = access.observer,
            target = endpoint.target
        ));
    }
    policy.push_str(&format!(
        "airlock.Diagnostics.Self + {caller} dom0 allow user=root autostart=no\n",
        caller = access.observer
    ));
    for service in ["airlock.Diagnostics", "airlock.Diagnostics.Self"] {
        policy.push_str(&format!(
            "{service} * @anyvm dom0 deny\n{service} * @anyvm @anyvm deny\n"
        ));
    }
    policy
}

/// Install the endpoint with explicit reader tools and an immutable contract assertion.
fn endpoint(config: ServerConfig, workspace: Option<Workspace>) -> NixosModule {
    NixosModule::with_context(move |inputs| endpoint_body(inputs, &config, workspace))
}

/// Share endpoint construction between standalone VM modules and host module closures.
fn endpoint_body(
    inputs: ModuleContext,
    config: &ServerConfig,
    workspace: Option<Workspace>,
) -> ModuleBody {
    let workspace = workspace
        .clone()
        .unwrap_or_else(|| airlock_build::native::workspace(&inputs.pkgs));
    let executable = Application::Diagnostics.build(&inputs.pkgs, &workspace);
    let text = serde_json::to_string(&config).expect("validated contract serializes");
    let tools = ["systemd", "pciutils", "iproute2", "util-linux"]
        .map(|name| inputs.pkgs.clone().select(name));
    ModuleBody::new(nix_record! {
        "environment": nix_record! {
            "systemPackages": NixValue::list(tools),
            "etc": nix_record! {
                "airlock/diagnostics.json": nix_record! { "text": text.clone() },
                "qubes-rpc/airlock.Diagnostics": nix_record! {
                    "source": nix_text!("{executable}/bin/airlock-diagnostics", executable = executable),
                    "mode": "0555",
                },
                "qubes/rpc-config/airlock.Diagnostics": nix_record! { "text": "force-user=root\n" },
            },
        },
        "systemd": nix_record! {
            "tmpfiles": nix_record! { "rules": NixValue::list(["d /run/airlock-diagnostics 0700 root root -".into()]) },
        },
        "assertions": NixValue::list([nix_record! {
            "assertion": inputs.config.clone().select("environment.etc").select_segments(["airlock/diagnostics.json"]).select("text").equals(text),
            "message": "Diagnostic contracts and Qubes permissions derive from the same Rust relationship.",
        }]),
    })
}

/// Publish a trusted endpoint inventory in the observer VM without collecting evidence.
fn client(access: &Access) -> NixosModule {
    let targets: Vec<TargetId> = access
        .endpoints
        .iter()
        .map(|endpoint| endpoint.target.clone())
        .collect();
    let text = serde_json::to_string(&targets).expect("validated identities serialize");
    NixosModule::with_context(move |inputs| {
        ModuleBody::new(nix_record! {
            "environment": nix_record! {
                "systemPackages": NixValue::list([Application::Cli.build(&inputs.pkgs, &airlock_build::native::workspace(&inputs.pkgs)).as_expression()]),
                "etc": nix_record! { "airlock/diagnostic-targets.json": nix_record! { "text": text.clone() } },
            },
        })
    })
}

/// Install host readers and policy without depending on the deployment controller's process.
pub(crate) fn host_module(access: &Access, workspace: Workspace) -> NixValue {
    let host = access
        .endpoints
        .iter()
        .find(|endpoint| endpoint.target.as_str() == "dom0")
        .expect("configured host endpoint");
    let policy = policy(access);
    let host = host.clone();
    let relay =
        serde_json::json!({"schema":"airlock.diagnostics-relay.v1", "observer":access.observer})
            .to_string();
    let executable = Application::Diagnostics;
    ContextualModule::new(move |inputs| {
        let package = executable.build(&inputs.pkgs, &workspace);
        // Qubes joins policy packages into one immutable directory; /etc entries cannot extend it.
        let policy_package = inputs
            .pkgs
            .clone()
            .select("writeTextDir")
            .call("etc/qubes/policy.d/44-airlock-diagnostics.policy")
            .call(policy);

        endpoint_body(inputs, &host, Some(workspace)).module(ModuleBody::new(nix_record! {
            "virtualisation": nix_record! {
                "qubes": nix_record! { "packages": NixValue::list([policy_package]) },
            },
            "environment": nix_record! {
                "etc": nix_record! {
                    "airlock/diagnostics-relay.json": nix_record! { "text": relay },
                    "qubes-rpc/airlock.Diagnostics.Self": nix_record! {
                        "source": nix_text!("{package}/bin/airlock-diagnostics-relay", package = package),
                        "mode": "0555",
                    },
                },
            },
        }))
    }).into_expression()
}
