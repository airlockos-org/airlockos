//! Local development transport peers run real shell framing and record finite Nix or SSH operations.

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, PermissionsExt, symlink},
        process::CommandExt,
    },
    path::Path,
    process::Command,
};

/// Record one child-tool invocation before returning its finite response or executing a local fixture shell.
pub(crate) fn execute(root: &Path, name: &str, args: &[String]) -> Result<()> {
    let config: Value = serde_json::from_slice(&fs::read(root.join("peer.json"))?)?;
    let name = if config["usb_flow"].is_object()
        && name == "airlock-test-peer"
        && args
            .first()
            .is_some_and(|arg| arg == "provision-after-build")
    {
        "airlock-usb"
    } else {
        name
    };
    writeln!(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join(format!("{name}.jsonl")))?,
        "{}",
        json!(args)
    )?;
    let bash = config["bash"].as_str().context("fixture shell")?;
    match name {
        "cargo" => {}
        "ssh" if config["shell"].as_bool() == Some(true) => {
            let mut command = Command::new(bash);
            if args == ["-tt", "--", "fixture", "airlock-dom0-shell"] {
                println!("DEVELOPMENT: dom0 shell.");
                std::io::stdout().flush()?;
                command.args(["--noprofile", "--norc"]);
            } else {
                command.arg("-c").arg(args.last().context("SSH command")?);
            }
            return Err(command.exec().into());
        }
        "ssh" => {
            if args.last().is_some_and(|arg| arg.contains("import")) {
                let mut bytes = Vec::new();
                std::io::stdin().read_to_end(&mut bytes)?;
                fs::write(root.join("received.tar.gz"), bytes)?;
            } else {
                println!("{}", json!({"status": "fixture"}));
            }
        }
        "sudo" if config["usb_flow"].is_object() => {
            ensure!(
                args.first().is_some_and(|arg| arg == "--"),
                "unexpected USB sudo arguments"
            );
            return Err(Command::new(&args[1]).args(&args[2..]).exec().into());
        }
        "airlock-usb" if config["usb_flow"].is_object() => {
            ensure!(
                args.first()
                    .is_some_and(|arg| arg == "provision-after-build"),
                "unexpected USB action"
            );
            let index = args
                .iter()
                .position(|arg| arg == "--result-link")
                .context("USB result link")?;
            let result = Path::new(&args[index + 1]);
            ensure!(
                fs::symlink_metadata(result).is_err(),
                "existing image was offered before build"
            );
            let argument = |name: &str| -> Result<&str> {
                let index = args
                    .iter()
                    .position(|a| a == name)
                    .context("missing USB run argument")?;
                Ok(args[index + 1].as_str())
            };
            let source = Path::new(argument("--repo")?);
            ensure!(
                source != root.join("parent with spaces"),
                "USB helper uses the active checkout"
            );
            ensure!(
                airlock_tests::repository::git(source, &["rev-parse", "HEAD"])?
                    == argument("--application-revision")?
                    && airlock_tests::repository::git(
                        &source.join("airlock-machine"),
                        &["rev-parse", "HEAD"]
                    )? == argument("--machine-revision")?,
                "USB helper received different committed sources"
            );
            fs::write(
                root.join("usb-source.json"),
                serde_json::to_vec(&json!({
                    "path":source, "revision":argument("--application-revision")?,
                    "machine_revision":argument("--machine-revision")?,
                }))?,
            )?;
            if config["usb_flow"]["prepare_fail"].as_bool() == Some(true) {
                std::process::exit(19);
            }
            fs::write(root.join("usb-prepared"), b"credentials collected")?;
            println!("airlock-usb-prepared-v2");
            std::io::stdout().flush()?;
            let mut completion = Vec::new();
            std::io::stdin().read_to_end(&mut completion)?;
            if completion.is_empty() {
                fs::write(root.join("usb-cancelled"), b"no write")?;
                std::process::exit(1);
            }
            let completion: Value = serde_json::from_slice(&completion)?;
            ensure!(
                completion["schema"] == "airlock.usb-build-complete.v2"
                    && completion["status"] == "passed"
                    && completion["result_link"] == result.to_str().context("result path")?
                    && completion["revision"] == argument("--application-revision")?
                    && completion["machine_revision"] == argument("--machine-revision")?
                    && completion["output"]
                        == "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-usb-image",
                "USB completion did not preserve this run's source and image"
            );
            ensure!(
                fs::read_link(result)?
                    == Path::new("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-usb-image"),
                "wrong image selected"
            );
            if config["usb_flow"]["provision_fail"].as_bool() == Some(true) {
                std::process::exit(23);
            }
            fs::write(
                root.join("usb-provisioned"),
                result.as_os_str().as_encoded_bytes(),
            )?;
        }
        "make" if config["usb_flow"].is_object() => {
            ensure!(
                root.join("usb-prepared").is_file(),
                "build started before credentials"
            );
            let result = args
                .iter()
                .find_map(|arg| arg.strip_prefix("AIRLOCK_RESULT_LINK_DIR="))
                .context("private image result directory")?;
            let directory = Path::new(result);
            let info = fs::metadata(directory)?;
            ensure!(
                info.uid() == rustix::process::geteuid().as_raw(),
                "build ran as a different user"
            );
            ensure!(
                info.permissions().mode() & 0o777 == 0o700,
                "result directory is not private"
            );
            if config["usb_flow"]["build_fail"].as_bool() == Some(true) {
                std::process::exit(42);
            }
            if config["usb_flow"]["source_change"].as_bool() == Some(true) {
                let repo = root.join("parent with spaces");
                fs::write(repo.join("README"), "new source commit")?;
                let machine = repo.join("airlock-machine");
                fs::write(machine.join("README"), "new machine commit")?;
                airlock_tests::repository::git(
                    &machine,
                    &["commit", "-qam", "Concurrent machine change"],
                )?;
                ensure!(
                    Command::new("git")
                        .arg("-C")
                        .arg(&repo)
                        .args(["commit", "-qam", "Concurrent source change"])
                        .status()?
                        .success(),
                    "source change failed"
                );
                fs::write(
                    repo.join("crates/application.rs"),
                    "active uncommitted edit",
                )?;
            }
            let source: Value = serde_json::from_slice(&fs::read(root.join("usb-source.json"))?)?;
            let checkout = Path::new(source["path"].as_str().context("captured source path")?);
            ensure!(
                std::env::current_dir()? == checkout,
                "build did not use the captured checkout"
            );
            ensure!(
                airlock_tests::repository::git(checkout, &["rev-parse", "HEAD"])?
                    == source["revision"]
                    && airlock_tests::repository::git(
                        &checkout.join("airlock-machine"),
                        &["rev-parse", "HEAD"]
                    )? == source["machine_revision"]
                    && fs::read_to_string(checkout.join("crates/application.rs"))? == "application",
                "active development changed the captured build inputs"
            );
            if config["usb_flow"]["snapshot_change"].as_bool() == Some(true) {
                fs::write(checkout.join("README"), "mutated isolated source")?;
            }
            if config["usb_flow"]["missing_result"].as_bool() != Some(true) {
                symlink(
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-usb-image",
                    directory.join("usb-dev-image"),
                )?;
            }
        }
        "nix-store" if config["usb_flow"].is_object() => {
            if config["usb_flow"]["publish_fail"].as_bool() == Some(true) {
                std::process::exit(33);
            }
            let index = args
                .iter()
                .position(|arg| arg == "--add-root")
                .context("image root")?;
            let link = Path::new(&args[index + 1]);
            fs::remove_file(link)?;
            symlink(args.last().context("built image")?, link)?;
        }
        "sudo" => {
            ensure!(
                args.starts_with(&["-S".into(), "-p".into()]),
                "unexpected sudo boundary"
            );
            return Err(Command::new(&args[3]).args(&args[4..]).exec().into());
        }
        "bash" => {
            if !args.is_empty() {
                return Err(Command::new(bash).args(args).exec().into());
            }
            let mut script = String::new();
            std::io::stdin().read_to_string(&mut script)?;
            script = script.replace(
                "/var/lib/airlock/machine/receipts",
                root.join("receipts").to_str().unwrap(),
            );
            if config["snapshot"].is_object() {
                let tool = root.join("tools/native-dom0");
                script = script.replace(
                    "/run/current-system/sw/bin/airlock-dom0-service",
                    tool.to_str().unwrap(),
                );
                if let Some(release) = config["release"].as_str() {
                    script = script.replace(
                        &format!("{release}/bin/airlock-dom0-service"),
                        tool.to_str().unwrap(),
                    );
                }
            }
            return Err(Command::new(bash).args(["-c", &script]).exec().into());
        }
        "nix" => {
            if let Some(diagnostics) = config["nix_stderr"].as_str() {
                eprint!("{diagnostics}");
            }
            if config["nix_wait_stdin"].as_bool() == Some(true) {
                std::io::stdin().read_exact(&mut [0])?;
            }
            if let Some(remote) = config["fetch_remote"].as_str() {
                let target = root.join("apps-fetch");
                for mut command in [
                    {
                        let mut command = Command::new("git");
                        command.args(["init", "--quiet", "--bare"]).arg(&target);
                        command
                    },
                    {
                        let mut command = Command::new("git");
                        command.arg("-C").arg(&target).args([
                            "fetch",
                            "--quiet",
                            remote,
                            "refs/heads/main",
                        ]);
                        command
                    },
                ] {
                    ensure!(
                        command.status()?.success(),
                        "local application fetch failed"
                    );
                }
                let output = Command::new("git")
                    .arg("-C")
                    .arg(target)
                    .args(["rev-parse", "FETCH_HEAD"])
                    .output()?;
                ensure!(output.status.success(), "fetched revision unavailable");
                fs::write(root.join("fetched"), output.stdout)?;
            }
            if config["prune"].as_bool() == Some(true) {
                let mut command = Command::new(
                    std::env::var_os("AIRLOCK_TEST_DEV_EXECUTABLE").context("development CLI")?,
                );
                command
                    .arg("--repository-root")
                    .arg(root.join("parent with spaces"));
                command.args(["source", "prune", "--keep", "0", "--apply"]);
                let output = command.output()?;
                ensure!(
                    output.status.success(),
                    "prune failed: {errors}",
                    errors = String::from_utf8_lossy(&output.stderr)
                );
                fs::write(root.join("pruning.json"), output.stdout)?;
            }
            let release = config["release"]
                .as_str()
                .unwrap_or("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-built");
            if args.iter().any(|arg| arg == "build") && config["release"].is_string() {
                if let Some(index) = args.iter().position(|arg| arg == "--out-link") {
                    let path = Path::new(&args[index + 1]);
                    fs::create_dir_all(path.parent().context("output parent")?)?;
                    if path.is_symlink() {
                        fs::remove_file(path)?;
                    }
                    symlink(release, path)?;
                }
                println!("{}", json!([{"outputs": {"out": release}}]));
            } else if args.iter().any(|arg| arg == "--all") {
                println!(
                    "{inventory}",
                    inventory = config["inventory"].as_str().unwrap_or("")
                );
            } else if args.iter().any(|arg| arg == "path-info") {
                println!("{}", json!({release: {"narSize": 1024 * 1024 * 1024}}));
            }
            std::process::exit(config["nix_exit"].as_i64().unwrap_or(0) as i32);
        }
        "nix-store" => bail!("unexpected export"),
        "stat" => {
            let key = if args.last().is_some_and(|arg| arg == "/nix/store") {
                "dom0_space"
            } else {
                "bridge_space"
            };
            println!(
                "{report}",
                report = config[key].as_str().unwrap_or("10000000 4096")
            );
        }
        "systemd-run" => println!("started fixture worker"),
        "native-dom0" => {
            let reply = if args
                .first()
                .is_some_and(|arg| arg == "development-snapshot")
            {
                config["snapshot"].clone()
            } else {
                json!({})
            };
            println!("{reply}");
        }
        "cat" if config["boot"].is_object() => println!("{boot}", boot = config["boot"]),
        "cat" => {
            let status = Command::new(config["cat"].as_str().context("fixture cat")?)
                .args(args)
                .status()?;
            ensure!(status.success(), "fixture cat failed");
        }
        _ => bail!("unexpected workstation peer: {name} {args:?}"),
    }
    Ok(())
}
