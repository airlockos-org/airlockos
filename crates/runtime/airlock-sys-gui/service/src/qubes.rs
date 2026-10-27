//! Read trusted VM identities through the existing Qubes Admin API and qrexec client.
//! VM payloads use separate RPCs; their policy rules explicitly prohibit autostart.

use airlock_nix_core::identity::GuestName;
use airlock_vm_service::support;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf, process::Command, time::Duration};
use uuid::Uuid;

/// Trusted metadata used to decide GUI membership and detect concurrent VM changes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Vm {
    /// Current Qubes name used for API routing.
    pub(crate) name: GuestName,
    /// Persistent identity retained when a VM is renamed.
    pub(crate) uuid: Uuid,
    /// GUI assignment resolved by qubesd.
    pub(crate) guivm: String,
    /// Permitted tag listing; no tag.Get request is needed.
    pub(crate) tags: Vec<String>,
    /// Internal infrastructure VMs do not publish application menus.
    pub(crate) internal: bool,
    /// Qubes class distinguishing disposable instances and ordinary VMs.
    #[serde(rename = "class")]
    pub(crate) class_name: String,
    /// Automatically cleaned disposable instances must not acquire persistent menus.
    pub(crate) auto_cleanup: bool,
    /// Current running state; reading catalogs must never start a VM.
    pub(crate) running: bool,
    /// Trusted label color reported by the label API.
    pub(crate) label: String,
    /// Explicit application selection, with `*` meaning all advertised entries.
    #[serde(rename = "menu-items")]
    pub(crate) menu_items: Option<String>,
}

/// Complete assigned-VM observation; failure to collect it must preserve cached membership.
pub(crate) struct Inventory {
    /// QubesDB identity of the GUI VM running this service.
    pub(crate) local_name: GuestName,
    /// Local cache root chosen by this user, never by a remote VM.
    pub(crate) basedir: PathBuf,
    /// Observed VM metadata after filtering foreign GUI assignments.
    pub(crate) domains: Vec<Vm>,
}

/// Protocol rejection whose exact class distinguishes absent features from denied or failed queries.
#[derive(Debug)]
struct Rejection {
    // Qubes exception class supplied in the framed Admin API response.
    class: String,
}

impl std::fmt::Display for Rejection {
    /// Report the remote exception class without interpreting its untrusted formatting string.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Qubes API rejected the request: {class}",
            class = self.class
        )
    }
}

impl std::error::Error for Rejection {}

/// Decode Qubes' success/error framing without accepting malformed or ambiguous responses.
fn response(bytes: Vec<u8>) -> Result<String> {
    if let Some(payload) = bytes.strip_prefix(b"0\0") {
        return Ok(String::from_utf8(payload.to_vec())?);
    }
    if let Some(error) = bytes.strip_prefix(b"2\0") {
        let fields: Vec<_> = error.split(|byte| *byte == 0).collect();
        ensure!(
            fields.len() >= 4 && fields.last() == Some(&b"".as_slice()),
            "invalid Qubes error framing"
        );
        let class = std::str::from_utf8(fields[0])?;
        ensure!(
            !class.is_empty()
                && class
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
            "invalid Qubes error class"
        );
        return Err(Rejection {
            class: class.to_owned(),
        }
        .into());
    }

    bail!("invalid Qubes API response framing")
}

/// Invoke a fixed read-only Admin API method through its existing policy-authorized destination.
fn admin(name: &str, method: &str, argument: Option<&str>) -> Result<String> {
    admin_with_timeout(name, method, argument, Duration::from_secs(15))
}

/// Limit a feature lookup to the caller's remaining session-start budget.
fn admin_with_timeout(
    name: &str,
    method: &str,
    argument: Option<&str>,
    timeout: Duration,
) -> Result<String> {
    let service = match argument {
        Some(argument) => {
            ensure!(
                !argument.is_empty()
                    && argument
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
                "invalid Qubes API argument"
            );
            format!("{method}+{argument}")
        }
        None => method.to_owned(),
    };

    let output = support::run(
        Command::new(support::tool(
            "AIRLOCK_QREXEC_CLIENT_VM",
            "qrexec-client-vm",
        ))
        .args(["--", name, &service]),
        None,
        timeout,
    )?
    .checked()?;
    response(output).with_context(|| format!("{method} for {name}"))
}

/// Read a typed Qubes property, refusing malformed headers or a different protocol type.
fn property(name: &GuestName, key: &str, kind: &str) -> Result<String> {
    let data = admin(name.as_str(), "admin.vm.property.Get", Some(key))?;
    let mut fields = data.splitn(3, ' ');
    ensure!(
        matches!(fields.next(), Some("default=True" | "default=False")),
        "invalid Qubes property default flag"
    );
    ensure!(
        fields.next() == Some(format!("type={kind}").as_str()),
        "invalid Qubes property type for {key}"
    );
    let value = fields.next().context("missing Qubes property value")?;
    ensure!(
        !value.chars().any(char::is_control),
        "control character in Qubes property"
    );
    ensure!(
        kind != "bool" || matches!(value, "True" | "False"),
        "invalid Qubes boolean property"
    );
    Ok(value.to_owned())
}

/// Only the documented absent-feature exception means absence; permission and transport failures propagate.
fn feature(name: &GuestName, key: &str) -> Result<Option<String>> {
    feature_with_timeout(name, key, Duration::from_secs(15))
}

/// Preserve absent-feature semantics while bounding discovery by an outer operation deadline.
fn feature_with_timeout(name: &GuestName, key: &str, timeout: Duration) -> Result<Option<String>> {
    match admin_with_timeout(name.as_str(), "admin.vm.feature.Get", Some(key), timeout) {
        Ok(value) => Ok(Some(value)),
        Err(error)
            if error
                .downcast_ref::<Rejection>()
                .is_some_and(|error| error.class == "QubesFeatureNotFoundError") =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// Resolve the local Qubes identity from QubesDB rather than accepting a remote or hostname assertion.
pub(crate) fn local_name() -> Result<GuestName> {
    support::text(
        Command::new(support::tool("AIRLOCK_QUBESDB_READ", "qubesdb-read")).arg("/name"),
        Duration::from_secs(5),
    )?
    .parse()
    .context("invalid GUI VM identity in QubesDB")
}

/// Select a local XDG data directory for launchers, icons and the admitted catalog cache.
pub(crate) fn data_home() -> Result<PathBuf> {
    let path = match std::env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(std::env::var_os("HOME").context("missing user home")?)
            .join(".local/share"),
    };
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|part| part == std::path::Component::ParentDir),
        "XDG data home must be absolute without traversal"
    );
    ensure!(
        path.to_str()
            .is_some_and(|path| !path.chars().any(char::is_control)),
        "XDG data home must be UTF-8 without controls"
    );
    Ok(path)
}

/// Keep cached catalogs in the user's established Qubes application-menu directory.
pub(crate) fn cache_root() -> Result<PathBuf> {
    Ok(data_home()?.join("qubes-appmenus"))
}

/// Parse a complete VM listing while rejecting duplicate identities and missing class data.
fn list() -> Result<BTreeMap<GuestName, String>> {
    let text = admin("dom0", "admin.vm.List", None)?;
    let mut result = BTreeMap::new();

    for line in text.lines() {
        let (name, properties) = line.split_once(' ').context("invalid Qubes VM listing")?;
        let class = properties
            .split(' ')
            .find_map(|field| field.strip_prefix("class="))
            .context("missing Qubes VM class")?;
        ensure!(
            !class.is_empty() && class.bytes().all(|byte| byte.is_ascii_alphanumeric()),
            "invalid Qubes VM class"
        );
        // The global listing includes the AdminVM. GuestName intentionally
        // excludes dom0, so discard that row before decoding guest identities.
        if name == "dom0" {
            continue;
        }
        ensure!(
            result.insert(name.parse()?, class.to_owned()).is_none(),
            "duplicate VM name in inventory"
        );
    }

    Ok(result)
}

/// Read a VM snapshot only after its identity and class have been listed by qubesd.
fn snapshot(name: &GuestName, class: &str, guivm: String) -> Result<Vm> {
    let label_name = property(name, "label", "label")?;
    let label = admin("dom0", "admin.label.Get", Some(&label_name))?;
    let color = label
        .strip_prefix('#')
        .or_else(|| label.strip_prefix("0x"))
        .context("invalid Qubes label color")?;
    ensure!(
        color.len() == 6 && color.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid Qubes label color"
    );

    let tags = admin(name.as_str(), "admin.vm.tag.List", None)?
        .lines()
        .map(str::to_owned)
        .collect();
    let state = admin(name.as_str(), "admin.vm.CurrentState", None)?;
    let running = state
        .split_whitespace()
        .find_map(|field| field.strip_prefix("power_state="))
        .context("missing Qubes power state")?
        == "Running";

    Ok(Vm {
        name: name.clone(),
        uuid: Uuid::parse_str(&property(name, "uuid", "str")?)?,
        guivm,
        tags,
        internal: feature(name, "internal")?.is_some_and(|value| !value.is_empty()),
        class_name: class.to_owned(),
        auto_cleanup: class == "DispVM" && property(name, "auto_cleanup", "bool")? == "True",
        running,
        label,
        menu_items: feature(name, "menu-items")?,
    })
}

/// Gather only assigned-VM details; foreign assignments never trigger feature or tag reads.
pub(crate) fn inventory() -> Result<Inventory> {
    let local_name = local_name()?;
    let mut domains = Vec::new();

    for (name, class) in list()? {
        if name == local_name || name.as_str() == "dom0" {
            continue;
        }
        let guivm = property(&name, "guivm", "vm")?;
        if guivm == local_name.as_str() {
            domains.push(snapshot(&name, &class, guivm)?);
        }
    }

    Ok(Inventory {
        local_name,
        basedir: cache_root()?,
        domains,
    })
}

/// Re-read the whole trusted snapshot for identity and publication checks.
pub(crate) fn describe(name: &GuestName) -> Result<Vm> {
    let listed = list()?;
    let class = listed
        .get(name)
        .context("VM is no longer listed by Qubes")?;
    snapshot(name, class, property(name, "guivm", "vm")?)
}

/// Resolve just the stable identity needed by the session's workspace reservation API.
pub(crate) fn identity(name: &GuestName) -> Result<Uuid> {
    Ok(Uuid::parse_str(&property(name, "uuid", "str")?)?)
}

/// Retain the advertised readiness RPC without invoking it or starting a VM.
pub(crate) fn readiness(name: &GuestName, timeout: Duration) -> Result<bool> {
    Ok(
        feature_with_timeout(name, "supported-rpc.airlock.AppSessionReady", timeout)?
            .is_some_and(|value| !value.is_empty()),
    )
}

/// Fetch VM bytes after checking running state; Qubes policy also prohibits autostart at dispatch.
pub(crate) fn service(name: &GuestName, service: &str, input: Option<Vec<u8>>) -> Result<Vec<u8>> {
    let state = admin(name.as_str(), "admin.vm.CurrentState", None)?;
    ensure!(
        state
            .split_whitespace()
            .any(|field| field == "power_state=Running"),
        "VM is not running"
    );
    rpc(name, service, input, Duration::from_secs(30))
}

/// Read icon pixels under the refresh budget; the image RPC policy forbids autostart even if a VM stops concurrently.
pub(crate) fn image(name: &GuestName, input: Vec<u8>, timeout: Duration) -> Result<Vec<u8>> {
    rpc(name, "qubes.GetImageRGBA", Some(input), timeout)
}

/// Keep all qrexec children bounded and reap their process groups on failure or timeout.
fn rpc(
    name: &GuestName,
    service: &str,
    input: Option<Vec<u8>>,
    timeout: Duration,
) -> Result<Vec<u8>> {
    support::run(
        Command::new(support::tool(
            "AIRLOCK_QREXEC_CLIENT_VM",
            "qrexec-client-vm",
        ))
        .args(["--", name.as_str(), service]),
        input.map(support::Input::bytes),
        timeout,
    )?
    .checked()
}
