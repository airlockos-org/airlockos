//! Exercise Airlock's real command and protocol boundaries using inert temporary state.

mod common;

#[path = "native/process.rs"]
mod process;

#[path = "native/smoke.rs"]
mod smoke;

#[path = "native/launchers.rs"]
mod launchers;

#[path = "native/preflight.rs"]
mod preflight;

#[path = "native/journal.rs"]
mod journal;

#[path = "native/storage.rs"]
mod storage;

#[path = "native/input.rs"]
mod input;

#[path = "nix/mod.rs"]
mod nix;

#[path = "native/adapters.rs"]
mod adapters;

#[path = "native/setup.rs"]
mod setup;

#[path = "native/gpu.rs"]
mod gpu;

#[path = "native/recovery.rs"]
mod recovery;

#[path = "native/desktop.rs"]
mod desktop;

#[path = "native/libvirt.rs"]
mod libvirt;

#[path = "native/keyboard.rs"]
mod keyboard;

#[path = "native/events.rs"]
mod events;

#[path = "native/rpc.rs"]
mod rpc;

#[path = "native/boot_menu.rs"]
mod boot_menu;

#[path = "native/boot.rs"]
mod boot;

#[path = "native/memory.rs"]
mod memory;

#[path = "native/gpu_artifacts.rs"]
mod gpu_artifacts;

#[path = "native/gpu_assignment.rs"]
mod gpu_assignment;

#[path = "native/menus.rs"]
mod menus;

#[path = "native/capture.rs"]
mod capture;

#[path = "native/coordinator/mod.rs"]
mod coordinator;

#[path = "native/javascript.rs"]
mod javascript;

#[path = "native/window_identity.rs"]
mod window_identity;

#[path = "native/workspace.rs"]
mod workspace;

#[path = "native/storage_integrity.rs"]
mod storage_integrity;

#[path = "native/host_store.rs"]
mod host_store;

#[path = "native/cli.rs"]
mod cli;

#[path = "native/prepared_source.rs"]
mod prepared_source;

#[path = "native/attachment.rs"]
mod attachment;

#[path = "native/gui_protocol.rs"]
mod gui_protocol;

#[path = "native/setup_window.rs"]
mod setup_window;

#[path = "native/configuration/mod.rs"]
mod configuration;

#[path = "native/workstation.rs"]
mod workstation;

#[path = "native/source_archives.rs"]
mod source_archives;

#[path = "native/image_seed.rs"]
mod image_seed;

#[path = "native/controller.rs"]
mod controller;

#[path = "native/boot_cache.rs"]
mod boot_cache;

#[path = "native/activation_flow.rs"]
mod activation_flow;

#[path = "native/network.rs"]
mod network;

#[path = "native/systemd_order.rs"]
mod systemd_order;

#[path = "native/system_vm.rs"]
mod system_vm;

#[path = "native/builder.rs"]
mod builder;

#[path = "native/assistant_build.rs"]
mod assistant_build;

#[path = "native/observation.rs"]
mod observation;

#[path = "native/packaged.rs"]
mod packaged;

#[path = "native/storage_objects.rs"]
mod storage_objects;

#[path = "native/storage_linux.rs"]
mod storage_linux;

#[path = "native/policy_path.rs"]
mod policy_path;
