//! Compare saved Qubes XML and disk metadata before reusing an applied boot receipt.

use super::*;
use quick_xml::{Reader, events::Event};
use std::io::Read;

#[derive(Clone)]
struct Node {
    // XML element name from Qubes' saved configuration.
    tag: String,
    // Unescaped attribute values, sorted independently of XML formatting.
    attrs: BTreeMap<String, String>,
    // Trimmed element text; formatting whitespace carries no configuration meaning.
    text: String,
    // Ordered XML children before canonicalization and runtime-field filtering.
    children: Vec<Node>,
}

impl Node {
    /// Exclude representational noise and keyboard state not owned by the declaration.
    fn normalize(&mut self, prefs: &BTreeMap<String, Value>) {
        // Qubes creates device collections lazily. An empty collection grants no
        // assignments, regardless of when a loaded extension first serializes it.
        self.children.retain(|node| {
            !(node.tag == "devices"
                && node.attrs.len() == 1
                && node.attrs.contains_key("class")
                && node.text.trim().is_empty()
                && node.children.is_empty())
        });

        // The GUI reports the session's layout after login. Explicit settings,
        // including an explicit reset, remain part of the startup comparison.
        if !prefs.contains_key("keyboard_layout")
            && let Some(properties) = self.children.iter_mut().find(|n| n.tag == "properties")
        {
            properties.children.retain(|property| {
                property
                    .attrs
                    .get("name")
                    .is_none_or(|name| name != "keyboard_layout")
            });
        }
    }

    fn child(&self, tag: &str) -> Result<&Node> {
        self.children
            .iter()
            .find(|n| n.tag == tag)
            .context("incomplete Qubes configuration; use recovery")
    }

    fn attr(&self, key: &str) -> Result<&str> {
        self.attrs
            .get(key)
            .map(String::as_str)
            .context("missing Qubes XML attribute")
    }

    /// Resolve Qubes' fixed dom0 identity without inventing names for guest records.
    fn domain_name(&self) -> Result<&str> {
        let name = self
            .child("properties")?
            .children
            .iter()
            .find(|property| property.attrs.get("name").is_some_and(|key| key == "name"))
            .map(|property| property.text.as_str());

        // Upstream AdminVM defaults to dom0 and does not serialize that fixed name.
        // A conflicting explicit property must not become an alias for a guest.
        if self
            .attrs
            .get("class")
            .is_some_and(|class| class == "AdminVM")
        {
            ensure!(
                name.is_none_or(|name| name == "dom0"),
                "AdminVM must be named dom0"
            );
            return Ok("dom0");
        }

        name.context("missing VM name")
    }

    fn value(&self) -> Value {
        let mut children: Vec<_> = self.children.iter().map(Node::value).collect();
        children.sort_by_cached_key(Value::to_string);
        json!([
            self.tag,
            self.attrs.iter().collect::<Vec<_>>(),
            self.text.trim(),
            children
        ])
    }
}

fn xml(path: &Path) -> Result<Node> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(state::LIMIT + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= state::LIMIT,
        "Qubes XML exceeds size limit"
    );
    let mut reader = Reader::from_reader(bytes.as_slice());
    let mut stack: Vec<Node> = Vec::new();
    let mut root = None;
    let mut count = 0;
    loop {
        let event = reader.read_event()?;
        let empty = matches!(event, Event::Empty(_));
        match event {
            Event::Start(e) | Event::Empty(e) => {
                count += 1;
                ensure!(
                    count <= 100000 && stack.len() < 128,
                    "Qubes XML complexity exceeds limit"
                );
                let mut attrs = BTreeMap::new();
                for attr in e.attributes() {
                    let attr = attr?;
                    ensure!(
                        attrs
                            .insert(
                                String::from_utf8(attr.key.as_ref().to_vec())?,
                                attr.decoded_and_normalized_value(
                                    quick_xml::XmlVersion::Implicit1_0,
                                    reader.decoder()
                                )?
                                .into_owned()
                            )
                            .is_none(),
                        "duplicate XML attribute"
                    );
                }
                let node = Node {
                    tag: String::from_utf8(e.name().as_ref().to_vec())?,
                    attrs,
                    text: String::new(),
                    children: Vec::new(),
                };
                if empty {
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(node);
                    } else {
                        ensure!(root.replace(node).is_none(), "multiple XML roots");
                    }
                } else {
                    stack.push(node);
                }
            }
            Event::Text(e) => {
                if let Some(node) = stack.last_mut() {
                    node.text
                        .push_str(&quick_xml::escape::unescape(&e.decode()?)?);
                } else {
                    ensure!(e.decode()?.trim().is_empty(), "unexpected XML text");
                }
            }
            Event::GeneralRef(e) => {
                let node = stack.last_mut().context("unexpected XML entity")?;
                if let Some(c) = e.resolve_char_ref()? {
                    node.text.push(c);
                } else {
                    let name = e.decode()?;
                    node.text.push_str(
                        quick_xml::escape::resolve_predefined_entity(&name)
                            .context("unsupported XML entity")?,
                    );
                }
            }
            Event::CData(e) => {
                stack
                    .last_mut()
                    .context("unexpected XML data")?
                    .text
                    .push_str(&e.decode()?);
            }
            Event::End(_) => {
                let node = stack.pop().context("unbalanced Qubes XML")?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else {
                    ensure!(root.replace(node).is_none(), "multiple XML roots");
                }
            }
            Event::Decl(_) | Event::Comment(_) | Event::PI(_) => {}
            Event::Eof => break,
            _ => bail!("unsupported Qubes XML content"),
        }
    }
    ensure!(stack.is_empty(), "truncated Qubes XML");
    root.context("missing Qubes XML root")
}

fn metadata(path: &Path) -> Result<Value> {
    let m = fs::metadata(path)
        .with_context(|| format!("read required boot artifact {path}", path = path.display()))?;
    ensure!(
        m.is_file(),
        "artifact is not a regular file: {}",
        path.display()
    );
    Ok(json!([
        m.dev(),
        m.ino(),
        m.size(),
        m.mtime() as i128 * 1000000000 + m.mtime_nsec() as i128,
        m.ctime() as i128 * 1000000000 + m.ctime_nsec() as i128,
        m.mode()
    ]))
}

/// Index all saved domains while retaining duplicate checks across explicit and implicit names.
fn domains(root: &Node) -> Result<BTreeMap<&str, &Node>> {
    let mut domains = BTreeMap::new();
    for domain in &root.child("domains")?.children {
        ensure!(
            domains.insert(domain.domain_name()?, domain).is_none(),
            "duplicate VM name"
        );
    }
    Ok(domains)
}

/// Category hashes explain a rejection; the complete hashes still decide reuse.
#[derive(Serialize, Deserialize)]
pub(super) struct Details {
    // Pools, global settings, persistent ownership and managed policy fingerprints.
    shared: BTreeMap<String, LockHash>,
    // Configuration, immutable artifact metadata and persistent disk sizes per VM.
    domains: BTreeMap<GuestName, BTreeMap<String, LockHash>>,
}

impl Details {
    /// Retain diagnostics for disjoint scopes only when their aggregate receipt is retained too.
    pub(super) fn inherit(&mut self, previous: Self) {
        for (name, categories) in previous.domains {
            self.domains.entry(name).or_insert(categories);
        }
    }
}

/// Fresh aggregate fingerprints accompanied by bounded diagnostic categories.
pub(super) struct Snapshot {
    /// Complete global Qubes configuration and managed policy fingerprint.
    pub(super) shared: LockHash,
    /// Complete checked state of each requested VM.
    pub(super) domains: BTreeMap<GuestName, LockHash>,
    /// Additional fingerprints used only to explain aggregate mismatches.
    pub(super) details: Details,
}

/// Hash object members independently without retaining configuration contents.
fn categories(value: &Value) -> Result<BTreeMap<String, LockHash>> {
    value
        .as_object()
        .context("snapshot categories must be an object")?
        .iter()
        .map(|(name, value)| Ok((name.clone(), state::digest(value)?.parse()?)))
        .collect()
}

/// Describe changed categories, including receipts written before details existed.
fn changed(
    current: &BTreeMap<String, LockHash>,
    saved: Option<&BTreeMap<String, LockHash>>,
) -> String {
    let Some(saved) = saved else {
        return "comparison details unavailable in saved receipt".into();
    };

    let names = current.keys().chain(saved.keys()).collect::<BTreeSet<_>>();
    let changes = names
        .into_iter()
        .filter(|name| current.get(*name) != saved.get(*name))
        .map(String::as_str)
        .collect::<Vec<_>>();
    if changes.is_empty() {
        "aggregate fingerprint".into()
    } else {
        changes.join(", ")
    }
}

impl Snapshot {
    /// Identify every rejected scope without exposing XML or artifact paths.
    pub(super) fn mismatch(&self, saved: &BootReceipt) -> String {
        let mut changes = Vec::new();
        if self.shared != saved.shared {
            changes.push(format!(
                "shared Qubes state: {categories}",
                categories = changed(
                    &self.details.shared,
                    saved.details.as_ref().map(|d| &d.shared)
                )
            ));
        }
        for (name, fingerprint) in &self.domains {
            if saved.domains.get(name) != Some(fingerprint) {
                changes.push(format!(
                    "{name}: {categories}",
                    categories = changed(
                        &self.details.domains[name],
                        saved.details.as_ref().and_then(|d| d.domains.get(name))
                    )
                ));
            }
        }
        changes.join("; ")
    }
}

impl Coordinator {
    pub(super) fn boot_snapshot(
        &self,
        requirements: &airlock_machine_core::boot::artifacts::BootRequirements<'_>,
        names: &[GuestName],
    ) -> Result<Snapshot> {
        let topology = requirements.inputs().topology();
        let root = xml(&configured_path(
            "AIRLOCK_QUBES_XML",
            "/var/lib/qubes/qubes.xml",
        )?)?;
        let pools: BTreeMap<_, _> = root
            .child("pools")?
            .children
            .iter()
            .map(|p| Ok((p.attr("name")?.to_owned(), p.attrs.clone())))
            .collect::<Result<_>>()?;
        let domains = domains(&root)?;
        let managed: BTreeSet<_> = names.iter().map(GuestName::as_str).collect();
        let mut owners = BTreeMap::new();
        for (name, d) in &domains {
            if let Ok(volumes) = d.child("volume-config") {
                for v in &volumes.children {
                    if !["root", "private"].contains(&v.attr("name")?) {
                        continue;
                    }
                    ensure!(
                        !managed.contains(name)
                            || v.attrs.get("source").is_none_or(String::is_empty),
                        "{name}: persistent volume has a foreign source"
                    );
                    let key = (v.attr("pool")?.to_owned(), v.attr("vid")?.to_owned());
                    if let Some(previous) = owners.insert(key, name.to_string()) {
                        ensure!(
                            !managed.contains(name) && !managed.contains(previous.as_str()),
                            "{name}: persistent disk shared with {previous}"
                        );
                    }
                }
            }
        }
        for (name, d) in &domains {
            if let Ok(volumes) = d.child("volume-config") {
                for v in &volumes.children {
                    for field in ["vid", "source"] {
                        if let (Some(pool), Some(id)) = (v.attrs.get("pool"), v.attrs.get(field))
                            && let Some(owner) = owners.get(&(pool.clone(), id.clone()))
                        {
                            ensure!(
                                !managed.contains(owner.as_str()) || owner == name,
                                "{name}: volume references {owner}'s persistent disk"
                            );
                        }
                    }
                }
            }
        }
        let policy = configured_path(
            "AIRLOCK_QUBES_POLICY_DIR",
            airlock_machine_core::services::policy_directory(),
        )?
        .join(
            std::env::var("AIRLOCK_QUBES_MANAGED_POLICY_FILE")
                .unwrap_or_else(|_| airlock_machine_core::services::policy_filename().into()),
        );
        let mut policy_bytes = Vec::new();
        fs::File::open(policy)?
            .take(state::LIMIT + 1)
            .read_to_end(&mut policy_bytes)?;
        ensure!(
            policy_bytes.len() as u64 <= state::LIMIT,
            "policy exceeds size limit"
        );
        let owners: Vec<_> = owners.iter().map(|((p, v), n)| json!([p, v, n])).collect();
        let shared_value = json!({"pools":pools,"labels":root.child("labels")?.value(),"prefs":root.child("properties")?.value(),"owners":owners,"policy":format!("{:x}",Sha256::digest(policy_bytes))});
        let shared = state::digest(&shared_value)?.parse()?;
        let mut details = Details {
            shared: categories(&shared_value)?,
            domains: BTreeMap::new(),
        };
        let mut snapshots = BTreeMap::new();
        for name in names {
            let mut node = (*domains
                .get(name.as_str())
                .context("startup VM missing; use recovery")?)
            .clone();
            if let Ok(tags) = node.child("tags") {
                ensure!(
                    !tags
                        .children
                        .iter()
                        .any(|n| n.attrs.get("name").is_some_and(|s| s == "airlock-retired")),
                    "startup VM is retired: {name}"
                );
            }
            node.children.retain(|n| n.tag != "tags");
            node.normalize(&topology.domains[name].prefs);
            if let Some(features) = node.children.iter_mut().find(|n| n.tag == "features") {
                features.children.retain(|n| {
                    n.attrs.get("name").is_some_and(|key| {
                        topology.domains[name].features.contains_key(key)
                            || key.starts_with("airlock-")
                            || key.starts_with("service.")
                    })
                });
            }
            let contract = requirements.guest(name)?;
            if let airlock_deployment_core::boot::artifacts::Guest::Hermit { .. } = contract {
                ensure!(
                    node.attr("class")? == "HermitVM",
                    "{name}: Hermit backend requires HermitVM class"
                );
            }

            let volumes = node
                .children
                .iter_mut()
                .find(|n| n.tag == "volume-config")
                .context("missing persistent volumes; use recovery")?;
            let mut artifacts = BTreeMap::new();
            match contract {
                airlock_deployment_core::boot::artifacts::Guest::Hermit { executable, .. } => {
                    // Hermit boots one authenticated executable and deliberately has no disks.
                    // Track that file so cache reuse still detects missing or replaced artifacts.
                    ensure!(
                        volumes.children.is_empty(),
                        "{name}: Hermit volumes must be empty"
                    );
                    let path = PathBuf::from(executable);
                    artifacts.insert(path.clone(), metadata(&path)?);
                }
                airlock_deployment_core::boot::artifacts::Guest::Nixos { .. } => {
                    let kinds: BTreeSet<_> = volumes
                        .children
                        .iter()
                        .map(|v| v.attr("name"))
                        .collect::<Result<_>>()?;
                    ensure!(
                        contract
                            .volumes()
                            .iter()
                            .all(|volume| kinds.contains(volume.name())),
                        "{name}: persistent or closure volumes missing"
                    );
                }
            }

            let mut disks = BTreeMap::new();
            volumes
                .children
                .retain(|v| v.attrs.get("name").is_none_or(|n| n != "volatile"));
            for volume in &volumes.children {
                let pool = pools.get(volume.attr("pool")?).context("missing pool")?;
                let kind = volume.attr("name")?;
                if ["root", "private"].contains(&kind)
                    && pool.get("driver").is_some_and(|s| s == "file")
                {
                    let path = Path::new(pool.get("dir_path").context("missing pool directory")?)
                        .join(format!("{}.img", volume.attr("vid")?));
                    let m = fs::metadata(&path)?;
                    ensure!(
                        m.is_file() && m.len() >= volume.attr("size")?.parse::<u64>()?,
                        "{name}: {kind} disk missing or truncated; use recovery"
                    );
                    disks.insert(path, m.len());
                }
                for field in ["view_path", "blob_map_path", "manifest_path"] {
                    if let Some(path) = volume.attrs.get(field).filter(|s| !s.is_empty()) {
                        let path = PathBuf::from(path);
                        artifacts.insert(path.clone(), metadata(&path)?);
                        if field == "manifest_path" {
                            for p in self.store().retained_root_files(
                                &path,
                                pool.get("root_dir").map(String::as_str),
                            )? {
                                artifacts.insert(p.clone(), metadata(&p)?);
                            }
                        }
                    }
                }
                if kind == "kernel"
                    && let Some(id) = volume.attrs.get("vid").filter(|s| !s.is_empty())
                {
                    let directory = Path::new(
                        pool.get("dir_path")
                            .map_or("/var/lib/qubes/vm-kernels", String::as_str),
                    )
                    .join(id);
                    ensure!(
                        directory.join("vmlinuz").is_file(),
                        "{name}: VM kernel missing; use recovery"
                    );
                    for entry in fs::read_dir(directory)? {
                        let p = entry?.path();
                        if p.is_file() {
                            artifacts.insert(p.clone(), metadata(&p)?);
                        }
                    }
                }
            }
            let configuration = node.value();
            details.domains.insert(name.clone(), categories(&json!({
                "configuration":configuration, "artifact metadata":artifacts, "persistent disks":disks
            }))?);
            snapshots.insert(
                name.clone(),
                state::digest(&json!({"xml":configuration,"artifacts":artifacts,"disks":disks}))?
                    .parse()?,
            );
        }
        Ok(Snapshot {
            shared,
            domains: snapshots,
            details,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse domain fragments through the same bounded XML reader used at boot.
    fn configuration(domains: &str) -> Result<Node> {
        let file = tempfile::NamedTempFile::new()?;
        fs::write(
            file.path(),
            format!("<qubes><domains>{domains}</domains></qubes>"),
        )?;
        xml(file.path())
    }

    /// Runtime layout and empty collections are equivalent; declared layouts and assignments remain checked.
    #[test]
    fn normalization_preserves_owned_settings_and_device_assignments() -> Result<()> {
        let before = configuration(
            r#"
            <domain><properties/><devices class="pci"/></domain>
        "#,
        )?;
        let after = configuration(
            r#"
            <domain><properties><property name="keyboard_layout">us++</property></properties>
                <devices class="pci"/><devices class="block"/><devices class="usb"/>
            </domain>
        "#,
        )?;
        let normalized = |root: &Node, prefs: &BTreeMap<String, Value>| -> Result<Value> {
            let mut node = root.child("domains")?.child("domain")?.clone();
            node.normalize(prefs);
            Ok(node.value())
        };
        let empty = BTreeMap::new();
        assert_eq!(normalized(&before, &empty)?, normalized(&after, &empty)?);

        // An explicit reset is owned just like a concrete layout selection.
        for setting in [json!("us++"), Value::Null] {
            let prefs = BTreeMap::from([("keyboard_layout".into(), setting)]);
            assert_ne!(normalized(&before, &prefs)?, normalized(&after, &prefs)?);
        }

        let assigned = configuration(
            r#"
            <domain><properties/><devices class="usb">
                <device backend-domain="sys-usb" id="1-1"/>
            </devices></domain>
        "#,
        )?;
        assert_ne!(normalized(&before, &empty)?, normalized(&assigned, &empty)?);
        Ok(())
    }

    /// Both upstream's default representation and an explicit fixed name identify dom0.
    #[test]
    fn adminvm_default_name_coexists_with_explicit_guest_names() -> Result<()> {
        let root = configuration(
            r#"
            <domain id="domain-0" class="AdminVM">
                <properties><property name="label">black</property></properties>
            </domain>
            <domain class="StandaloneVM">
                <properties><property name="name">sys-gui</property></properties>
            </domain>
        "#,
        )?;
        let indexed = domains(&root)?;
        assert_eq!(
            indexed.keys().copied().collect::<Vec<_>>(),
            ["dom0", "sys-gui"]
        );
        assert_eq!(indexed["dom0"].attr("class")?, "AdminVM");

        let explicit = configuration(
            r#"
            <domain class="AdminVM">
                <properties><property name="name">dom0</property></properties>
            </domain>
        "#,
        )?;
        assert!(domains(&explicit)?.contains_key("dom0"));
        Ok(())
    }

    /// Defaulting dom0 cannot excuse an unnamed guest, an alias or duplicate domain records.
    #[test]
    fn invalid_guest_and_adminvm_identities_remain_rejected() -> Result<()> {
        for (input, expected) in [
            (
                r#"<domain class="StandaloneVM"><properties/></domain>"#,
                "missing VM name",
            ),
            (
                r#"<domain class="AdminVM"><properties><property name="name">sys-gui</property></properties></domain>"#,
                "AdminVM must be named dom0",
            ),
            (
                r#"<domain class="AdminVM"><properties/></domain><domain class="AdminVM"><properties/></domain>"#,
                "duplicate VM name",
            ),
            (
                r#"<domain class="AdminVM"><properties/></domain><domain><properties><property name="name">dom0</property></properties></domain>"#,
                "duplicate VM name",
            ),
        ] {
            let root = configuration(input)?;
            let error = domains(&root)
                .err()
                .context("invalid identities were accepted")?;
            assert!(error.to_string().contains(expected), "{error}");
        }
        Ok(())
    }
}
