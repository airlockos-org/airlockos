mod approval;

mod branding;

mod diff_context;

mod effects;

mod file_tree;

mod icons;

mod model;

mod selection;

mod syntax;

mod theme;

mod ui;

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use std::path::PathBuf;

/// Human choice stored by local review tooling or returned to the launch controller.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Decision {
    Approve,
    Reject,
}

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Show the built-in example (also the default when no repository is supplied).
    #[arg(long, conflicts_with = "repo")]
    demo: bool,
    /// Repository containing the committed baseline and candidate.
    #[arg(long, requires = "base")]
    repo: Option<PathBuf>,
    /// Explicit comparison baseline. Local Git history is not a deployed baseline.
    #[arg(long, requires = "repo")]
    base: Option<String>,
    /// Candidate commit or ref, resolved once to an immutable commit.
    #[arg(long, default_value = "HEAD")]
    candidate: String,
    /// Optional saved dom0 plan/response JSON. Displayed as supplied, not authenticated.
    #[arg(long, requires = "repo")]
    plan: Option<PathBuf>,
    /// Write local decision receipts here. Receipts grant no deployment authority.
    #[arg(long)]
    decisions_dir: Option<PathBuf>,
    /// Print the review and its content fingerprint as JSON without opening a window.
    #[arg(long, conflicts_with_all = ["print_patch", "print_review"])]
    inspect: bool,
    /// Print the entire reviewed Git patch to stdout without opening a window.
    #[arg(long, conflicts_with_all = ["screenshot", "record_decision", "print_review"])]
    print_patch: bool,
    /// Print the complete clipboard review, including the supplied plan and patch.
    #[arg(long, conflicts_with_all = ["screenshot", "record_decision"])]
    print_review: bool,
    /// Controller-owned pre-build approval request. Decisions return on stdout.
    #[arg(long, requires = "repo", conflicts_with_all = ["plan", "decisions_dir", "record_decision", "print_patch", "screenshot"])]
    approval_request: Option<PathBuf>,
    /// Record a local decision without a window; intended for offline review tooling.
    #[arg(long, requires = "decisions_dir", conflicts_with = "screenshot")]
    record_decision: Option<Decision>,
    /// Render a PNG of the window and exit, for local visual checks.
    #[arg(long, conflicts_with = "inspect")]
    screenshot: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let review = if let Some(repo) = &args.repo {
        model::Review::from_git(
            repo,
            args.base.as_deref().unwrap(),
            &args.candidate,
            args.plan.as_deref(),
        )?
    } else {
        if args.record_decision.is_some() {
            bail!("demo decisions stay in memory; use --repo to write a local receipt");
        }
        model::Review::demo()
    };

    let approval = args
        .approval_request
        .as_deref()
        .map(|path| approval::load_request(path, &review))
        .transpose()?;

    if let Some(decision) = args.record_decision {
        let path = review.record_decision(decision, args.decisions_dir.as_deref().unwrap())?;
        println!("{}", path.display());
        return Ok(());
    }

    if args.inspect {
        println!("{}", serde_json::to_string_pretty(&review)?);
        return Ok(());
    }

    if args.print_patch {
        print!("{}", review.patch()?);
        return Ok(());
    }

    if args.print_review {
        if let Some(request) = approval {
            let session = approval::Session {
                allowed_vms: request
                    .scope()
                    .allowed_vms()
                    .iter()
                    .map(|name| name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                request,
                reply: Default::default(),
            };
            print!("{}", session.copy_text(&review.clipboard_report()?)?);
        } else {
            print!("{}", review.clipboard_report()?);
        }
        return Ok(());
    }

    let reply: approval::Reply = Default::default();
    let cancelled = approval
        .as_ref()
        .map(|request| {
            approval::response(
                request,
                &review,
                approval::ApprovalDecision::Cancelled,
                request.scope().clone(),
            )
        })
        .transpose()?;
    let session = approval.map(|request| approval::Session {
        allowed_vms: request
            .scope()
            .allowed_vms()
            .iter()
            .map(|name| name.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        request,
        reply: reply.clone(),
    });

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("Airlock Control")
            .with_decorations(true)
            .with_app_id(airlock_desktop::CONTROL_ID)
            .with_icon(branding::logo().context("loading the embedded Airlock logo")?)
            .with_inner_size([1600.0, 820.0])
            .with_min_inner_size([880.0, 600.0]),
        renderer: eframe::Renderer::Glow,
        hardware_acceleration: eframe::HardwareAcceleration::Preferred,
        ..Default::default()
    };
    eframe::run_native(
        "Airlock Control",
        options,
        Box::new(move |cc| {
            Ok(Box::new(ui::Controller::new(
                cc,
                review,
                args.decisions_dir,
                args.screenshot,
                session,
            )))
        }),
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))
    .context("opening Airlock Control")?;

    if let Some(response) = reply.lock().unwrap().take().or(cancelled) {
        println!("{}", serde_json::to_string(&response)?);
    }

    Ok(())
}
