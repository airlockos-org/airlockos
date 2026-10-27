//! Dom0 command entry point; Qubes plugins share the same native implementation.

fn main() -> std::process::ExitCode {
    airlock_dom0_service::main()
}
