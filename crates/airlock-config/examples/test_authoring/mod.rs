//! Select Rust test authoring scenarios without accepting Nix source from callers.

use super::*;

mod desktop;

mod authoring_boundary;

mod physical;

mod host;

mod machine;

mod equivalence;

mod prepared_store;

mod workspace;

mod usr_assistant_machine_source;

mod usb_dev;

mod usb_lab;

mod usr_home_gnome;

mod gui_minimal;

mod vm_search;

mod network_reliability;

mod live_vm_interfaces;

mod memory_accounting_nix;

mod dev_dom0_terminal;

mod usr_assistant_workspace;

mod gpu_probe;

mod qubes_gui_window_state;

mod network_uplink_vm;

mod pool_admission_module;

mod gui_gpu_assignment;

mod system_schema;

mod guest_roles;

mod native_etc;

/// Select a fixture by its stable scenario name and supply JSON-derived caller values.
pub(super) fn fixture(
    name: &str,
    inputs: NixValue,
    settings: &serde_json::Value,
) -> Result<NixValue, String> {
    {
        let argument_1 = match name {
            "model/export" => authoring_boundary::export(settings)?,
            "candidate/evaluate" => candidate_value(inputs),
            "gui/render-command" => authoring_boundary::commands(settings)?,
            "source/forbidden-root" => source::forbidden_root(),
            "source/empty" => source::empty(),
            "export/bootstrap" => export::expression(inputs),
            "usr_assistant_machine_build/build_script" => {
                usr_assistant_machine_build::build_script(inputs)
            }
            "schema/evaluate" => schema(inputs),
            "schema/scenario" => schema_scenario(inputs, settings)?,
            "topology_schema/valid" => topology_schema::expression(),
            "topology_schema/invalid" => topology_schema::invalid_expression(
                settings["case"].as_str().ok_or("expected topology case")?,
            )?,
            "desktop" => desktop::expression().call(inputs),
            "physical" => physical::expression().call(inputs),
            "host" => host::expression().call(inputs),
            "machine" => machine::expression().call(inputs),
            "equivalence" => equivalence::expression().call(inputs),
            "prepared_store/sealed_store" => prepared_store::sealed_store(inputs),
            "prepared_store/cache" => prepared_store::cache(inputs),
            "prepared_store/raw_disk_hooks" => prepared_store::raw_disk_hooks(inputs),
            "workspace/sources" => workspace::sources(inputs, settings)?,
            "usr_assistant_machine_source/seed_archive" => {
                usr_assistant_machine_source::seed_archive(inputs)
            }
            "usb_dev/independent_display_startup" => usb_dev::independent_display_startup(inputs),
            "usb_lab/source_metadata" => usb_lab::source_metadata(inputs),
            "usb_lab/startup_contract" => usb_lab::startup_contract(inputs),
            "native_etc/installation" => native_etc::installation(inputs),
            "native_etc/host_rpcs" => native_etc::host_rpcs(inputs),
            "native_etc/icon_receiver" => native_etc::icon_receiver(inputs),
            "usb_lab/network_and_development_access" => {
                usb_lab::network_and_development_access(inputs)
            }
            "usb_lab/boot_source_metadata" => usb_lab::boot_source_metadata(inputs),
            "usr_home_gnome/personal_integrations" => usr_home_gnome::personal_integrations(inputs),
            "usr_home_gnome/personal_gui_selection" => {
                usr_home_gnome::personal_gui_selection(inputs)
            }
            "usr_home_gnome/application_routing" => usr_home_gnome::application_routing(inputs),
            "gui_minimal/minimal_desktop" => gui_minimal::minimal_desktop(inputs),
            "vm_search/search_extension" => vm_search::search_extension(inputs),
            "network_reliability/network_recovery" => network_reliability::network_recovery(inputs),
            "live_vm_interfaces/bitmap_icons" => live_vm_interfaces::bitmap_icons(inputs),
            "live_vm_interfaces/svg_icons" => live_vm_interfaces::svg_icons(inputs),
            "live_vm_interfaces/interfaces" => live_vm_interfaces::interfaces(inputs),
            "memory_accounting_nix/patched_reporter" => {
                memory_accounting_nix::patched_reporter(inputs)
            }
            "dev_dom0_terminal/terminal_configuration" => {
                dev_dom0_terminal::terminal_configuration(inputs)
            }
            "dev_dom0_terminal/terminal_client" => dev_dom0_terminal::terminal_client(inputs),
            "usr_assistant_workspace/assistant_workspace" => {
                usr_assistant_workspace::assistant_workspace(inputs)
            }
            "gpu_probe/gpu_lab" => gpu_probe::gpu_lab(inputs),
            "qubes_gui_window_state/window_state" => qubes_gui_window_state::window_state(inputs),
            "network_uplink_vm/uplink_hotplug" => network_uplink_vm::uplink_hotplug(inputs),
            "network_uplink_vm/input_receiver" => network_uplink_vm::input_receiver(inputs),
            "pool_admission_module/admission_receiver" => {
                pool_admission_module::admission_receiver(inputs)
            }
            "gui_gpu_assignment/gpu_selection" => gui_gpu_assignment::gpu_selection(inputs),
            "gui_gpu_assignment/private_storage" => gui_gpu_assignment::private_storage(inputs),
            "gui_gpu_assignment/hardware_override" => gui_gpu_assignment::hardware_override(inputs),
            "gui_gpu_assignment/preflight_selection" => {
                gui_gpu_assignment::preflight_selection(inputs)
            }
            "gui_gpu_assignment/live_preflight" => gui_gpu_assignment::live_preflight(inputs),
            "system_schema/live_activation" => system_schema::live_activation(inputs),
            "system_schema/reboot_activation" => system_schema::reboot_activation(inputs),
            "system_schema/boot_activation" => system_schema::boot_activation(inputs),
            "guest_roles/command_role" => guest_roles::command_role(inputs),
            "guest_roles/minimal_vm" => guest_roles::minimal_vm(inputs),
            _ => return Err(format!("unknown test fixture {name}")),
        };

        Ok(argument_1)
    }
}

mod topology_schema;

mod usr_assistant_machine_build;

/// Apply the real schema to JSON test data and select the normalized fields under inspection.
fn schema(inputs: NixValue) -> NixValue {
    let source = inputs.clone().select("source");
    let library = inputs.clone().select("library");
    let schemas = NixValue::builtin("import").call(add(
        inputs.clone().select("machine"),
        "/generated/schemas.nix".into(),
    ));
    let lib = NixValue::builtin("import").call(add(source, "/lib".into()));
    let selected = NixValue::builtin("getAttr")
        .call(library.clone())
        .call(schemas)
        .call(lib);
    let function = NixValue::if_else(library.equals("system"), "mkSystem", "mkTopology");
    let config = NixValue::builtin("getAttr")
        .call(function)
        .call(selected)
        .call(inputs.clone().select("config"));

    NixValue::builtin("foldl'")
        .call(NixValue::function(|value| {
            NixValue::function(|key| NixValue::builtin("getAttr").call(key).call(value))
        }))
        .call(config)
        .call(inputs.select("selector"))
}

/// Apply a schema example directly with admitted inputs, without creating another flake lock.
fn schema_scenario(inputs: NixValue, settings: &serde_json::Value) -> Result<NixValue, String> {
    let scenario = settings["scenario"]
        .as_str()
        .ok_or("expected schema scenario")?;
    let (example, library) = match scenario {
        "valid" => (topology_schema::expression(), "topology"),
        "invalid" => (
            topology_schema::invalid_expression(
                settings["case"].as_str().ok_or("expected topology case")?,
            )?,
            "topology",
        ),
        "live" => (system_schema::live_activation(inputs.clone()), "system"),
        "reboot" => (system_schema::reboot_activation(inputs.clone()), "system"),
        "boot" => (system_schema::boot_activation(inputs.clone()), "system"),
        _ => return Err(format!("unknown schema scenario {scenario}")),
    };

    let lib = NixValue::builtin("import").call(add(inputs.clone().select("source"), "/lib".into()));
    let caller = field(
        ["self"],
        NixValue::record([
            ("outPath", inputs.select("fixtureRoot")),
            ("inputs", field(["nixpkgs", "lib"], lib)),
        ]),
    );

    Ok(example
        .select("outputs")
        .call(caller)
        .select_segments(["airlock", library]))
}

mod export;

mod source;

/// Select an explicit attribute path from an emitted candidate without constructing executable text from caller data.
fn candidate_value(inputs: NixValue) -> NixValue {
    NixValue::builtin("foldl'")
        .call(NixValue::function(|value| {
            NixValue::function(|segment| {
                NixValue::builtin("getAttr")
                    .call(segment)
                    .call(value.clone())
            })
        }))
        .call(NixValue::builtin("getFlake").call(inputs.clone().select("candidate")))
        .call(inputs.select("segments"))
}

/// Inspect the fixed arguments and environment installed beside a native executable.
/// Nix realizes the immutable sidecar rather than interpreting ELF bytes as text.
fn native_contract(path: NixValue) -> NixValue {
    let bytes =
        NixValue::builtin("readFile").call(NixValue::concat_text([path.to_text(), ".json".into()]));

    // Realize the sidecar first, then treat its store references as fixture data.
    // fromJSON rejects a string carrying dependency context from those references.
    NixValue::builtin("fromJSON").call(NixValue::builtin("unsafeDiscardStringContext").call(bytes))
}
