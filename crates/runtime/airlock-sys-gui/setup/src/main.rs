//! First-run GTK welcome window; dom0 owns completion and authorizes its two Qubes RPCs.

#![forbid(unsafe_code)]
use airlock_vm_service::support;
use anyhow::{Result, ensure};
use libadwaita::{
    self as adw,
    gtk::{self, gio, glib},
    prelude::*,
};
use std::{
    cell::{Cell, RefCell},
    process::{Command, ExitCode},
    rc::Rc,
    time::Duration,
};

#[derive(Clone, Copy, PartialEq)]
enum Status {
    Incomplete,
    Complete,
}

struct Session {
    // Keep automatic dismissal local to this graphical session, as GApplication owns the process.
    dismissed: Cell<bool>,
    // Local completion used only by explicit preview mode.
    preview_complete: Cell<bool>,
    // Explicit preview mode never contacts dom0 or changes persistent setup state.
    preview: bool,
    // Current window, cleared when the user dismisses it.
    window: RefCell<Option<adw::ApplicationWindow>>,
    // Application hold preserves dismissal memory until the desktop session ends.
    hold: RefCell<Option<gio::ApplicationHoldGuard>>,
}

impl Session {
    fn request(&self, complete: bool) -> Result<Status> {
        if self.preview {
            if complete {
                self.preview_complete.set(true);
            }
            return Ok(if self.preview_complete.get() {
                Status::Complete
            } else {
                Status::Incomplete
            });
        }
        let service = if complete {
            "airlock.SetupComplete"
        } else {
            "airlock.SetupStatus"
        };
        let response = support::text(
            Command::new(support::tool("AIRLOCK_QVM_RUN", "qvm-run")).args([
                "--pass-io",
                "--no-gui",
                "--service",
                "dom0",
                service,
            ]),
            Duration::from_secs(15),
        )?;
        match response.as_str() {
            "complete" => Ok(Status::Complete),
            "incomplete" => Ok(Status::Incomplete),
            _ => anyhow::bail!("unexpected setup-state response"),
        }
    }

    fn show(self: &Rc<Self>, app: &adw::Application, automatic: bool) {
        if automatic && self.dismissed.get() {
            return;
        }
        if let Some(window) = self.window.borrow().as_ref() {
            window.present();
            return;
        }
        let result = self.request(false);
        if automatic && matches!(result, Ok(Status::Complete)) {
            return;
        }
        if self.hold.borrow().is_none() {
            self.hold.replace(Some(app.hold()));
        }

        let window = adw::ApplicationWindow::builder()
            .icon_name(airlock_desktop::ICON_NAME)
            .application(app)
            .title(if self.preview {
                "AirlockOS Setup Preview"
            } else {
                "AirlockOS Setup"
            })
            .default_width(620)
            .default_height(440)
            .build();
        let toolbar = adw::ToolbarView::new();
        toolbar.add_top_bar(&adw::HeaderBar::new());
        let page = adw::StatusPage::builder()
            .icon_name(airlock_desktop::ICON_NAME)
            .build();
        toolbar.set_content(Some(&page));
        let actions = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        actions.set_margin_top(12);
        actions.set_margin_bottom(12);
        actions.set_margin_start(18);
        actions.set_margin_end(18);
        actions.set_halign(gtk::Align::End);
        let message = gtk::Label::builder()
            .wrap(true)
            .selectable(true)
            .hexpand(true)
            .halign(gtk::Align::Start)
            .build();
        let retry = gtk::Button::with_label("Retry");
        let finish = gtk::Button::with_label("Finish setup");
        finish.add_css_class("suggested-action");
        let tour = gtk::Button::with_label("Take a desktop tour");
        tour.add_css_class("suggested-action");
        actions.append(&message);
        actions.append(&retry);
        actions.append(&finish);
        actions.append(&tour);
        toolbar.add_bottom_bar(&actions);
        window.set_content(Some(&toolbar));

        let retry_button = retry.clone();
        let finish_button = finish.clone();
        let tour_button = tour.clone();
        let tour_message = message.clone();
        let update = {
            let page = page.downgrade();
            let message = message.downgrade();
            let retry = retry.downgrade();
            let finish = finish.downgrade();
            let tour = tour.downgrade();
            Rc::new(move |result: Result<Status>| {
                let (Some(page), Some(message), Some(retry), Some(finish), Some(tour)) = (
                    page.upgrade(),
                    message.upgrade(),
                    retry.upgrade(),
                    finish.upgrade(),
                    tour.upgrade(),
                ) else {
                    return;
                };
                let complete = matches!(result, Ok(Status::Complete));
                page.set_title(if complete {
                    "Setup complete"
                } else {
                    "Welcome to AirlockOS"
                });
                page.set_description(Some(if complete { "AirlockOS is ready. You can explore the GNOME desktop now or close this window. Setup remains available from the applications menu." } else { "Your desktop is ready. Finish setup to stop showing this welcome screen when you sign in. You can reopen Setup from the applications menu." }));
                message.set_text(
                    &result
                        .as_ref()
                        .err()
                        .map(|e| format!("{e:#}"))
                        .unwrap_or_default(),
                );
                retry.set_visible(result.is_err());
                finish.set_sensitive(matches!(result, Ok(Status::Incomplete)));
                finish.set_visible(!complete);
                tour.set_visible(complete);
            })
        };
        for (button, complete) in [(retry_button, false), (finish_button, true)] {
            let session = Rc::downgrade(self);
            let update = update.clone();
            button.connect_clicked(move |_| {
                if let Some(session) = session.upgrade() {
                    update(session.request(complete));
                }
            });
        }
        let weak_window = window.downgrade();
        tour_button.connect_clicked(move |_| {
            let result = (|| -> Result<()> {
                let program = std::env::var_os("AIRLOCK_GNOME_TOUR_EXEC")
                    .ok_or_else(|| anyhow::anyhow!("GNOME Tour is not packaged"))?;
                ensure!(!program.is_empty(), "GNOME Tour is not packaged");
                Command::new(program).spawn()?;
                Ok(())
            })();
            match result {
                Ok(()) => {
                    if let Some(window) = weak_window.upgrade() {
                        window.close();
                    }
                }
                Err(error) => tour_message.set_text(&format!(
                    "Could not open GNOME Tour. Setup is still complete. {error}"
                )),
            }
        });
        let session = Rc::downgrade(self);
        window.connect_close_request(move |_| {
            if let Some(session) = session.upgrade() {
                session.dismissed.set(true);
                session.window.replace(None);
            }
            glib::Propagation::Proceed
        });
        update(result);
        self.window.replace(Some(window.clone()));
        window.present();
    }
}

fn main() -> ExitCode {
    let preview = std::env::var("AIRLOCK_SETUP_PREVIEW").as_deref() == Ok("1");
    let session = Rc::new(Session {
        dismissed: Cell::new(false),
        preview_complete: Cell::new(false),
        preview,
        window: RefCell::new(None),
        hold: RefCell::new(None),
    });
    let app = adw::Application::builder()
        .application_id(if preview {
            "org.airlockos.SetupPreview"
        } else {
            airlock_desktop::SETUP_ID
        })
        .flags(gio::ApplicationFlags::HANDLES_COMMAND_LINE)
        .build();
    app.add_main_option(
        "auto",
        glib::Char::from(0),
        glib::OptionFlags::NONE,
        glib::OptionArg::None,
        "Show the welcome window only when setup is incomplete",
        None,
    );
    let state = session.clone();
    app.connect_command_line(move |app, line| {
        let automatic = line.options_dict().contains("auto");
        state.show(app, automatic);
        glib::ExitCode::SUCCESS
    });
    let code = app.run();
    drop(session);
    code.into()
}
