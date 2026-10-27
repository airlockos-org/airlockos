//! Drive input discovery and sender ownership with inert devices and child processes.

#[path = "../src/input/model.rs"]
mod model;

#[path = "../src/input/forwarder.rs"]
mod forwarder;

use std::{
    io::{BufRead, Read, Write},
    path::{Path, PathBuf},
};

/// Dispatch one descriptor query or interactive sender-lifecycle scenario.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args[1] == "describe" {
        let mut bytes = String::new();
        std::io::stdin().read_to_string(&mut bytes)?;
        let value: serde_json::Value = serde_json::from_str(&bytes)?;
        let properties = serde_json::from_value(value["properties"].clone())?;
        let descriptor = model::describe(
            Path::new(value["node"].as_str().unwrap()),
            Path::new(value["sys_path"].as_str().unwrap()),
            value["name"].as_str().map(std::ffi::OsStr::new),
            &properties,
        );
        let rendered = descriptor
            .map(|descriptor| {
                assert_eq!(
                    descriptor.node.path(),
                    Path::new(value["node"].as_str().unwrap())
                );
                serde_json::to_value(descriptor.hardware).unwrap()
            })
            .unwrap_or(serde_json::Value::Null);
        println!("{rendered}");
        return Ok(());
    }

    let mut forwarder = forwarder::Forwarder::new(
        "sys-gui".parse()?,
        PathBuf::from(&args[2]),
        PathBuf::from(&args[3]),
    )?;
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        let (action, path) = line.split_once(' ').unwrap();
        let node = model::Node::parse(Path::new(path)).unwrap();
        match action {
            "add" => {
                if let Err(error) = forwarder.add(node) {
                    eprintln!("{error}");
                }
            }
            "remove" => forwarder.remove(&node),
            "reap" => forwarder.reap(),
            _ => unreachable!(),
        }
        println!("ok");
        std::io::stdout().flush()?;
    }
    Ok(())
}
