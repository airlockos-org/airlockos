//! Build and install the GUI service using the caller's packages and explicit source trees.
//! These functions construct lazy Nix expressions; they never build or run the service in Rust.

mod capture;

mod package;

use crate::command::{DesktopCommand, EXECUTABLE, RUNTIME_COMMAND_NAMES, WINDOW_IDENTITY};
use clap::Subcommand;
use rusix::{
    installation::Application,
    interop::{
        NixPath, Package,
        raw::{NixRepresentation, NixValue},
    },
    nix_text,
};

/// Admitted application workspace supplying the native build and integration patches.
#[derive(Clone)]
pub struct Sources {
    /// Cargo workspace containing service sources, integration patches and the shared lockfile.
    apps: NixPath,
}

impl Sources {
    /// Uses caller-supplied symbolic paths without resolving a developer checkout.
    pub fn new(apps: NixPath) -> Self {
        Self {
            apps: airlock_build::Workspace::new(apps).root(),
        }
    }

    /// Snapshot one shared integration asset without depending on unrelated application contents.
    fn file(&self, relative: &str) -> NixValue {
        self.apps
            .join_relative(relative)
            .expect("service asset paths are static and relative")
            .snapshot()
            .as_expression()
    }
}

/// The packaged GUI service and its installation helpers for one package set.
/// Machine authors retain ownership of VM placement and Qubes permissions.
pub struct Deployment {
    /// Final caller package set, including its platform and overlays.
    pkgs: NixValue,
    /// Source paths retained for patches and completion adapters.
    sources: Sources,
    /// Native service with its Qubes RPC tools and runtime environment.
    package: Package,
}

/// Build the standalone native executable before adding its runtime Qubes tools.
pub fn native(pkgs: &NixValue, apps: &NixPath) -> Package {
    package::native(pkgs, apps)
}

/// Describes the complete GUI service package in the caller's dependency scope.
pub fn deployment(pkgs: &NixValue, sources: &Sources) -> Deployment {
    Deployment {
        package: package::wrapped(pkgs, sources),
        pkgs: pkgs.clone(),
        sources: sources.clone(),
    }
}

impl Deployment {
    /// Declares this package's executable export and shared desktop command schema.
    /// The machine must compose all participating apps for a VM together before
    /// emitting their modules. Other runtime-only nested commands are not registered.
    pub fn installation(&self) -> Application {
        let mut paths = RUNTIME_COMMAND_NAMES
            .iter()
            .map(|name| vec![(*name).into()])
            .collect::<Vec<_>>();
        let parser = DesktopCommand::augment_subcommands(clap::Command::new(EXECUTABLE));
        desktop_command_paths(&parser, &[], &mut paths);

        Application::new(EXECUTABLE).executable(self.package(), EXECUTABLE, paths)
    }

    /// Returns the package to install in this VM's system environment.
    pub fn package(&self) -> Package {
        self.package.clone()
    }

    /// Returns the executable with its Nix store dependency context intact.
    pub fn executable(&self) -> NixValue {
        nix_text!(
            "{package}/bin/{name}",
            package = self.package.clone(),
            name = EXECUTABLE
        )
        .into()
    }

    /// Installs the extension adapter that forwards its X11 window ID to the trusted reader.
    /// The daemon package supplies the executable used to verify the window's provenance.
    pub fn window_identity_reader(&self, gui_daemon: Package) -> NixValue {
        let arguments = NixValue::list([
            self.executable(),
            WINDOW_IDENTITY.into(),
            "--guid".into(),
            nix_text!("{daemon}/bin/qubes-guid", daemon = gui_daemon).into(),
        ]);
        let command = self
            .pkgs
            .clone()
            .select("lib.escapeShellArgs")
            .call(arguments);

        self.pkgs
            .clone()
            .select("writeShellScript")
            .call("airlock-focused-vm-identity")
            .call(nix_text!(
                r#"
                    exec {command} "$@"
                "#,
                command = command,
            ))
    }

    /// Constructs a shell-safe invocation of a command understood by the runtime parser.
    /// This is shell syntax; desktop entries must use the separate desktop renderer.
    ///
    /// # Panics
    /// Panics if a path argument cannot be represented as UTF-8 Nix text.
    pub fn shell_command(&self, command: &DesktopCommand) -> NixValue {
        let arguments = command.arguments().into_iter().map(|argument| {
            argument
                .into_string()
                .expect("authored command arguments must be UTF-8")
                .into()
        });
        let arguments = NixValue::list(std::iter::once(self.executable()).chain(arguments));

        self.pkgs
            .clone()
            .select("lib.escapeShellArgs")
            .call(arguments)
    }

    /// Constructs a desktop-entry Exec value with desktop-specific escaping.
    /// Shell quoting is insufficient here: percent signs are desktop field-code markers.
    ///
    /// # Panics
    /// Panics if a path argument cannot be represented as UTF-8 desktop-entry text.
    pub fn desktop_command(&self, command: &DesktopCommand) -> NixValue {
        let arguments = command
            .arguments()
            .into_iter()
            .map(|argument| {
                let argument = argument
                    .into_string()
                    .expect("authored arguments must be UTF-8");
                desktop_argument(&argument)
            })
            .collect::<Vec<_>>()
            .join(" ");

        nix_text!(
            "{executable} {arguments}",
            executable = self.executable(),
            arguments = arguments
        )
        .into()
    }
}

/// Collects the parser's desktop commands and aliases in their literal parent scopes.
fn desktop_command_paths(parser: &clap::Command, parent: &[String], paths: &mut Vec<Vec<String>>) {
    for child in parser.get_subcommands() {
        for name in std::iter::once(child.get_name()).chain(child.get_all_aliases()) {
            let path = parent
                .iter()
                .cloned()
                .chain([name.into()])
                .collect::<Vec<_>>();
            paths.push(path.clone());
            desktop_command_paths(child, &path, paths);
        }
    }
}

/// Quotes literal desktop arguments according to the Exec grammar, without shell evaluation.
fn desktop_argument(argument: &str) -> String {
    if !argument.is_empty()
        && argument
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_/.:".contains(&byte))
    {
        return argument.into();
    }

    let escaped = argument
        .replace('\\', "\\\\\\\\")
        .replace('"', "\\\\\"")
        .replace('`', "\\\\`")
        .replace('$', "\\\\$")
        .replace('%', "%%")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    format!("\"{escaped}\"")
}

/// Exports native and Qubes-integrated package constructors for Nix consumers.
/// Both functions use the same recipes as Rust callers; generated Nix is an artifact.
pub fn packages() -> impl rusix::IntoConfig {
    /// Package entry points emitted together from the service-owned recipes.
    #[derive(rusix::IntoConfig)]
    struct Packages {
        /// Native Cargo build for standalone application consumers.
        native: NixValue,
        /// Complete Qubes desktop service for machine consumers.
        deployment: NixValue,
    }

    let native = NixValue::function_attrs_open(["pkgs", "apps"], |args| {
        let apps = NixPath::from_expression(args.clone().select("apps"));
        let package = package::native(&args.select("pkgs"), &apps);

        (Vec::<(&str, NixValue)>::new(), package.as_expression())
    });
    let wrapped = NixValue::function_attrs_open(["pkgs", "apps"], |args| {
        let sources = Sources::new(NixPath::from_expression(args.clone().select("apps")));
        let service = deployment(&args.select("pkgs"), &sources);

        (
            Vec::<(&str, NixValue)>::new(),
            service.package().as_expression(),
        )
    });

    Packages {
        native,
        deployment: wrapped,
    }
}

#[cfg(test)]
mod installation_tests {
    use super::*;
    use airlock_machine_core::services::CaptureSenderConfig;
    use rusix::installation::{self, CollisionChecks, InstallationError};

    /// A real sender contract owns the same path used by its login command and JSON reader.
    #[test]
    fn sender_contract_checks_its_declared_files() {
        let source = NixPath::from_expression("/unneeded-source".into());
        let service = deployment(
            &NixValue::record([] as [(&str, NixValue); 0]),
            &Sources::new(source),
        );
        let sender = service.capture_sender(&CaptureSenderConfig::default());
        installation::compose("sys-gui", CollisionChecks::Enabled, [sender.clone()]).unwrap();

        let conflicting =
            Application::new("other-app").etc_text("airlock/capture-sender.json", "{}");
        let error =
            installation::compose("sys-gui", CollisionChecks::Enabled, [sender, conflicting])
                .unwrap_err();
        assert!(matches!(error, InstallationError::Collision { .. }));
        assert!(
            error
                .to_string()
                .contains("/etc/airlock/capture-sender.json")
        );
    }

    /// Desktop aliases share the executable's namespace with runtime-only root commands.
    #[test]
    fn desktop_aliases_cannot_shadow_runtime_roots() {
        let mut paths = RUNTIME_COMMAND_NAMES
            .iter()
            .map(|name| vec![(*name).into()])
            .collect::<Vec<_>>();
        let parser = clap::Command::new(EXECUTABLE)
            .subcommand(clap::Command::new("capture-example").alias(crate::command::LAUNCH));
        desktop_command_paths(&parser, &[], &mut paths);
        let app = Application::new(EXECUTABLE).executable(
            Package::from_expression("/unneeded-package".into()),
            EXECUTABLE,
            paths,
        );

        assert!(matches!(
            installation::compose("sys-gui", CollisionChecks::Enabled, [app]),
            Err(InstallationError::Collision { .. })
        ));
    }
}
