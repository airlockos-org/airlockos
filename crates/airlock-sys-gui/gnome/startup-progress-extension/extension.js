import Clutter from 'gi://Clutter';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import Pango from 'gi://Pango';
import St from 'gi://St';

import * as Animation from 'resource:///org/gnome/shell/ui/animation.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import * as PopupMenu from 'resource:///org/gnome/shell/ui/popupMenu.js';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';
import {elapsedText, parseSnapshot} from './model.js';

const STATUS_READER = '@statusReader@';

export default class StartupProgressExtension extends Extension {
    enable() {
        this._generation = (this._generation ?? 0) + 1;
        this._active = true;
        this._started = GLib.get_monotonic_time();
        this._snapshot = null;
        this._observedWorking = false;
        this._lastError = null;
        this._button = new PanelMenu.Button(0.0, 'Airlock startup');
        const box = new St.BoxLayout({style_class: 'airlock-startup-panel'});
        this._spinner = new Animation.Spinner(16, {hideOnStop: true});
        this._warning = new St.Icon({icon_name: 'dialog-warning-symbolic',
            style_class: 'system-status-icon', visible: false});
        this._label = new St.Label({text: 'Starting Airlock',
            y_align: Clutter.ActorAlign.CENTER});
        box.add_child(this._spinner);
        box.add_child(this._warning);
        box.add_child(this._label);
        this._button.add_child(box);
        this._summary = new PopupMenu.PopupMenuItem('Preparing applications and services',
            {reactive: false, can_focus: false});
        this._summary.label.add_style_class_name('airlock-startup-summary');
        this._summary.label.clutter_text.set({line_wrap: true,
            line_wrap_mode: Pango.WrapMode.WORD_CHAR});
        this._elapsed = new PopupMenu.PopupMenuItem('', {reactive: false, can_focus: false});
        this._button.menu.addMenuItem(this._summary);
        this._button.menu.addMenuItem(this._elapsed);
        this._button.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());
        this._rows = new PopupMenu.PopupMenuSection();
        this._button.menu.addMenuItem(this._rows);
        Main.panel.addToStatusArea('airlock-startup-progress', this._button, 0, 'right');
        this._spinner.play();
        this._poll();
    }

    _schedule() {
        this._timer = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 5, () => {
            this._timer = 0;
            this._poll();
            return GLib.SOURCE_REMOVE;
        });
    }

    _poll() {
        if (!this._active)
            return;
        const generation = this._generation;
        const cancellable = new Gio.Cancellable();
        this._cancellable = cancellable;
        try {
            const process = Gio.Subprocess.new([STATUS_READER],
                Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_PIPE);
            process.communicate_utf8_async(null, cancellable, (source, result) => {
                try {
                    const [, stdout, stderr] = source.communicate_utf8_finish(result);
                    if (!this._active || generation !== this._generation)
                        return;
                    if (!source.get_successful()) {
                        const status = source.get_if_exited()
                            ? `exit ${source.get_exit_status()}`
                            : `signal ${source.get_term_sig()}`;
                        throw new Error(`Startup reader ${status}: ${stderr.slice(0, 1024)}`);
                    }
                    if (stdout.length > 128 * 1024)
                        throw new Error('Startup reader response exceeds 128 KiB');
                    const snapshot = parseSnapshot(JSON.parse(stdout));
                    if (this._snapshot && this._snapshot.bootId !== snapshot.bootId)
                        this._started = GLib.get_monotonic_time();
                    this._snapshot = snapshot;
                    this._lastError = null;
                    this._render(snapshot);
                    if (!snapshot.complete)
                        this._schedule();
                } catch (error) {
                    if (this._active && generation === this._generation)
                        this._unavailable(error);
                }
            });
        } catch (error) {
            this._unavailable(error);
        }
    }

    _unavailable(error) {
        // Keep journal evidence without flooding it on every identical five-second retry.
        const detail = String(error).replace(/[\u0000-\u001f\u007f-\u009f]/gu, ' ').slice(0, 1024);
        if (detail !== this._lastError) {
            console.warn(`Airlock startup observer: ${detail}`);
            this._lastError = detail;
        }
        // Keep the last per-VM observations visible; lost transport cannot mean completion.
        this._button.show();
        this._label.text = 'Startup status unavailable';
        this._warning.show();
        this._spinner.play();
        this._summary.label.text = 'Startup status unavailable; retrying. Showing the last known VM status.';
        this._button.accessible_name = this._summary.label.text;
        this._updateElapsed();
        this._schedule();
    }

    _updateElapsed() {
        this._elapsed.label.text = elapsedText((GLib.get_monotonic_time() - this._started) / 1_000_000);
    }

    _render(snapshot) {
        this._summary.label.text = snapshot.detail;
        this._updateElapsed();
        this._rows.removeAll();
        for (const guest of snapshot.guests) {
            const row = new PopupMenu.PopupBaseMenuItem({reactive: false, can_focus: false});
            const column = new St.BoxLayout({orientation: Clutter.Orientation.VERTICAL,
                x_expand: true, style_class: 'airlock-startup-guest'});
            column.add_child(new St.Label({text: guest.name,
                style_class: 'airlock-startup-guest-name'}));
            const detail = new St.Label({text: guest.detail,
                style_class: guest.phase === 'failed' ? 'airlock-startup-error' : 'airlock-startup-detail'});
            detail.clutter_text.set({line_wrap: true, line_wrap_mode: Pango.WrapMode.WORD_CHAR});
            column.add_child(detail);
            row.add_child(column);
            this._rows.addMenuItem(row);
        }
        this._button.accessible_name = `${snapshot.detail}. ${snapshot.guests.map(guest =>
            `${guest.name}: ${guest.detail}`).join('. ')}`;
        this._warning.visible = snapshot.attention;
        if (snapshot.complete || snapshot.attention)
            this._spinner.stop();
        else
            this._spinner.play();
        if (!snapshot.complete) {
            this._observedWorking = true;
            this._button.show();
            this._label.text = snapshot.attention ? 'Startup needs attention' : 'Starting Airlock';
            return;
        }

        // Once publication is complete, stop polling. Keep a brief, quiet completion indication.
        if (!this._observedWorking) {
            this._button.hide();
            return;
        }
        this._label.text = 'Ready';
        this._timer = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 5, () => {
            this._timer = 0;
            this._button.menu.close();
            this._button.hide();
            return GLib.SOURCE_REMOVE;
        });
    }

    disable() {
        this._active = false;
        this._generation++;
        if (this._timer)
            GLib.Source.remove(this._timer);
        this._timer = 0;
        // The native observer owns a bounded helper process group. Let its deadline
        // clean up Qubes transport rather than force-killing it and orphaning a child.
        this._cancellable?.cancel();
        this._cancellable = null;
        this._spinner.stop();
        this._button.destroy();
        this._button = null;
        this._snapshot = null;
    }
}
