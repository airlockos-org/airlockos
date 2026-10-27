//! Rust owns temporary modules and subprocesses; JavaScript checks its own Shell models without a desktop.

use crate::common;
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{fs, process::Command};

const HOME: &str = "738a6af9-8e51-590d-afe4-790b26fbca79";

const AGENT: &str = "a8c14e6d-05c6-412a-952d-28f41c910aca";

/// Load actual extension modules, replacing only desktop imports with inert Shell objects.
fn javascript(kind: &str, scenario: &str, arguments: Value, shell: bool) -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let gnome = common::root().join("crates/runtime/airlock-sys-gui/gnome");
    let extension = match kind {
        "workspace" => "vm-workspaces-extension",
        "search" => "vm-search-extension",
        "focus" => "focused-vm-extension",
        "startup" => "startup-progress-extension",
        _ => anyhow::bail!("unknown extension {kind}"),
    };
    for (name, source) in [
        ("model", format!("{extension}/model.js")),
        ("state", "focused-vm-extension/state.js".into()),
        ("identity", "focused-vm-extension/state.js".into()),
        ("inventory", "vm-search-extension/model.js".into()),
    ] {
        let path = gnome.join(source);
        if path.exists() {
            fs::copy(path, root.join(format!("{name}.mjs")))?;
        }
    }
    let imports = match kind {
        "workspace" => {
            r#"import {MAX_SLOTS,describeWorkspace,groupOccupiedWorkspaces,groupOwnedWorkspaces} from './model.mjs';
import {WindowIdentityCache,LOCAL,UNKNOWN,validateIdentity} from './identity.mjs';
import {parseInventory} from './inventory.mjs';
"#
        }
        "search" => "import {describeResult,groupResults,parseInventory} from './model.mjs';\n",
        "focus" => "import {FocusState,WindowIdentityCache,LOCAL,UNKNOWN} from './state.mjs';\n",
        "startup" => "import {elapsedText,parseSnapshot} from './model.mjs';\n",
        _ => unreachable!(),
    };
    let mocks = match kind {
        "workspace" => {
            "const {Clutter,Gio,GLib,Meta,St,Main,PanelMenu,DND,Workspace,WorkspaceThumbnail,Extension,InjectionManager}=globalThis.shellMocks;\n"
        }
        "search" => {
            "const {Clutter,Gio,GLib,GObject,Pango,Shell,St,Main,Search,Extension,InjectionManager}=globalThis.shellMocks;\n"
        }
        "focus" => "const {Gio,GLib,Meta,Main,Extension}=globalThis.shellMocks;\n",
        "startup" => {
            "const {Clutter,Gio,GLib,Pango,St,Animation,Main,PanelMenu,PopupMenu,Extension}=globalThis.shellMocks;\n"
        }
        _ => unreachable!(),
    };
    let source = fs::read_to_string(gnome.join(extension).join("extension.js"))?;
    let source = source
        .lines()
        .filter(|line| !line.starts_with("import "))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(
        root.join("extension.mjs"),
        format!("{imports}{mocks}{source}"),
    )?;
    let mut program = String::from("import assert from 'node:assert/strict';\n");
    if kind == "startup" {
        program.push_str(imports);
    }
    if !matches!(kind, "focus" | "startup") {
        program.push_str(imports);
        program.push_str(&format!(
            "const HOME={home},AGENT={agent};\n",
            home = json!(HOME),
            agent = json!(AGENT)
        ));
        program.push_str(if kind == "workspace" {
            r#"const inventory=new Map([[HOME,{name:'usr-home',color:'#3465a4',running:true}],
[AGENT,{name:'usr-assistant',color:'#cc0000',running:false}]]);
"#
        } else {
            r#"const app=(vm,name='org.gnome.Console')=>`org.qubes-os.vm.${vm}.${name}.desktop`;
const snapshot=()=>({[HOME]:{uuid:HOME,name:'usr-home',label:'0x3465a4',running:true},
[AGENT]:{uuid:AGENT,name:'usr-assistant',label:'0xcc0000',running:false}});
"#
        });
    }
    if shell {
        program.push_str(match kind {
            "workspace" => include_str!("../../fixtures/gnome/workspace_shell.mjs"),
            "search" => include_str!("../../fixtures/gnome/search_shell.mjs"),
            "startup" => include_str!("../../fixtures/gnome/startup_shell.mjs"),
            _ => unreachable!(),
        });
        program.push_str(match kind {
            "workspace" => "\nconst {default:Controller}=await import('./extension.mjs');\n",
            "startup" => "\nconst {default:StartupProgressExtension}=await import('./extension.mjs');\n",
            _ => "\nconst {VMSearchResults,default:VMSearchExtension}=await import('./extension.mjs');\n",
        });
    }
    program.push_str(match kind {
        "workspace" => include_str!("../../fixtures/gnome/workspace_scenarios.mjs"),
        "search" => include_str!("../../fixtures/gnome/search_scenarios.mjs"),
        "focus" => include_str!("../../fixtures/gnome/focus_scenarios.mjs"),
        "startup" => include_str!("../../fixtures/gnome/startup_scenarios.mjs"),
        _ => unreachable!(),
    });
    let output = common::run(
        Command::new(common::tool("node")?)
            .args(["--input-type=module", "-e", &program])
            .current_dir(root)
            .env("AIRLOCK_JS_SCENARIO", scenario)
            .env("AIRLOCK_JS_ARGUMENTS", serde_json::to_string(&arguments)?),
        None,
    )?;
    ensure!(
        output.status.success(),
        "{kind}/{scenario}: {error}",
        error = String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

/// The real panel controller survives delayed menus, unavailable transport and GNOME extension teardown.
#[test]
#[ignore = "requires explicitly prepared Node.js"]
fn javascript_startup_panel_tracks_publication_and_cleans_up() -> Result<()> {
    for (scenario, shell) in [
        ("snapshot_validation", false),
        ("wait_for_application_publication", true),
        ("lost_status_retains_guests", true),
        ("failures_remain_visible", true),
        ("disable_rejects_stale_callbacks", true),
        ("already_complete_stops_polling", true),
    ] {
        javascript("startup", scenario, json!({}), shell)?;
    }
    Ok(())
}

/// Search keeps VM identity, grouping and GNOME actions through result changes and extension cleanup.
#[test]
#[ignore = "requires explicitly prepared Node.js"]
fn javascript_search_preserves_identity_order_and_shell_lifetimes() -> Result<()> {
    for (scenario, shell) in [
        ("groups_follow_best_match_and_preserve_gnome_order", false),
        ("many_matches_do_not_hide_another_vm", false),
        ("names_colours_and_renames_use_inventory_uuid", false),
        ("guest_names_cannot_supply_vm_identity_or_css", false),
        ("rows_reuse_original_controls_and_wrap_full_names", true),
        ("late_queries_and_destroyed_displays_cannot_publish", true),
        (
            "inventory_refresh_preserves_snapshot_and_ignores_stale_reads",
            true,
        ),
        (
            "enable_disable_restores_search_and_leaves_other_providers",
            true,
        ),
    ] {
        javascript("search", scenario, json!({}), shell)?;
    }
    Ok(())
}

/// Workspace ownership and review attention follow trusted VM identities and the current unlocked Shell instance.
#[test]
#[ignore = "requires explicitly prepared Node.js"]
fn javascript_workspaces_preserve_ownership_and_review_attention() -> Result<()> {
    for (scenario, shell) in [
        ("only_occupied_application_workspaces_form_groups", false),
        ("groups_keep_order_and_drop_closed_workspaces", false),
        ("mixed_and_unknown_windows_use_neutral_identity", false),
        (
            "controller_keeps_native_activities_and_removes_empty_slots",
            true,
        ),
        (
            "multiple_slots_stay_contiguous_and_foreign_moves_are_blocked",
            true,
        ),
        ("overview_decoration_tints_hover_labels_and_cleanup", true),
        ("extension_reload_does_not_refocus_existing_review", true),
    ] {
        javascript("workspace", scenario, json!({}), shell)?;
    }
    for wm_class in [
        "sys-ctrl:airlock-sys-ctrl-gui",
        "sys-ctrl:airlock-ctrl",
        "sys-ctrl:org.airlock.ctrl",
    ] {
        javascript(
            "workspace",
            "new_control_review_switches_workspace_and_focuses_once",
            json!({"wm_class": wm_class}),
            true,
        )?;
    }
    for options in [
        json!({"origin": {"kind": "vm", "name": "usr-home"}, "wmClass": "sys-ctrl:airlock-sys-ctrl-gui"}),
        json!({"origin": {"kind": "unknown"}, "wmClass": "sys-ctrl:airlock-sys-ctrl-gui"}),
        json!({"origin": {"kind": "local", "name": "sys-gui"}, "wmClass": "sys-ctrl:airlock-sys-ctrl-gui"}),
        json!({"wmClass": "sys-ctrl:org.gnome.Console"}),
        json!({"wmClass": "sys-ctrl:airlock-sys-ctrl-gui-spoof"}),
        json!({"wmClass": "airlock-sys-ctrl-gui"}),
        json!({"kind": 1}),
        json!({"transient": true}),
    ] {
        javascript(
            "workspace",
            "other_windows_cannot_request_review_focus",
            json!({"options": options}),
            true,
        )?;
    }
    for order in [
        "identity-before-map",
        "map-before-identity",
        "class-after-map",
    ] {
        javascript(
            "workspace",
            "review_focus_waits_for_identity_mapping_and_class",
            json!({"order": order}),
            true,
        )?;
    }
    for mode in ["isLocked", "isGreeter"] {
        javascript(
            "workspace",
            "review_waits_for_unlocked_desktop",
            json!({"mode": mode}),
            true,
        )?;
    }
    for cleanup in ["closed", "disabled"] {
        javascript(
            "workspace",
            "pending_review_focus_is_cancelled_on_cleanup",
            json!({"cleanup": cleanup}),
            true,
        )?;
    }
    Ok(())
}

/// Focus and identity cache results cannot outlive a window or the extension instance that requested them.
#[test]
#[ignore = "requires explicitly prepared Node.js"]
fn javascript_focused_vm_rejects_stale_and_untrusted_results() -> Result<()> {
    for scenario in [
        "focus_changes_suppression_and_late_results",
        "shell_update_cannot_publish_into_a_reenabled_instance",
        "application_actors_and_settled_shell_focus",
        "cached_switches_retry_unknowns_and_window_lifetime",
    ] {
        javascript("focus", scenario, json!({}), false)?;
    }
    Ok(())
}
