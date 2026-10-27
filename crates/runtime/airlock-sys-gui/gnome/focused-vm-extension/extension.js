import Clutter from 'gi://Clutter';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import Meta from 'gi://Meta';
import Pango from 'gi://Pango';
import St from 'gi://St';

import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';
import {FocusState, WindowIdentityCache, LOCAL, UNKNOWN} from './state.js';

const READER = '@identityReader@';

export default class FocusedVMExtension extends Extension {
    enable() {
        this._signals = [];
        this._windowSignals = [];
        this._cache = new WindowIdentityCache();
        this._indicator = new PanelMenu.Button(0.0, 'Focused VM', true);
        this._indicator.reactive = false;
        this._indicator.can_focus = false;
        const box = new St.BoxLayout({style_class: 'airlock-focused-vm-box'});
        this._dot = new St.Widget({style_class: 'airlock-focused-vm-dot',
            y_align: Clutter.ActorAlign.CENTER});
        this._label = new St.Label({style_class: 'airlock-focused-vm-name',
            y_align: Clutter.ActorAlign.CENTER});
        this._label.clutter_text.ellipsize = Pango.EllipsizeMode.END;
        box.add_child(this._dot);
        box.add_child(this._label);
        this._indicator.add_child(box);
        this._state = new FocusState(identity => this._render(identity));
        Main.panel.addToStatusArea('airlock-focused-vm', this._indicator, 1, 'left');
        this._connect(global.display, 'notify::focus-window', () => this._focusChanged());
        this._connect(global.stage, 'notify::key-focus', () => this._queueUpdate());
        this._connect(global.stage, 'notify::is-grabbed', () => this._queueUpdate());
        this._connect(Main.overview, 'showing', () => this._update());
        this._connect(Main.overview, 'hidden', () => this._update());
        this._connect(Main.sessionMode, 'updated', () => this._update());
        this._focusChanged();
    }

    _connect(object, signal, callback, list = this._signals) {
        list.push([object, object.connect(signal, callback)]);
    }

    _disconnect(list) {
        for (const [object, id] of list)
            object.disconnect(id);
        list.length = 0;
    }

    _focusChanged() {
        this._disconnect(this._windowSignals);
        this._focused = global.display.focus_window;
        const seen = new Set();
        for (let window = this._focused; window && !seen.has(window); window = window.get_transient_for()) {
            seen.add(window);
            this._connect(window, 'unmanaged', () => {
                this._focused = null;
                this._queueUpdate();
            }, this._windowSignals);
        }
        this._update();
    }

    _suppressed() {
        // Shell menus, modal dialogs, overview, switchers and lock screens own input.
        const keyFocus = global.stage.get_key_focus();
        const applicationFocus = keyFocus && (
            global.window_group.contains(keyFocus) ||
            global.top_window_group.contains(keyFocus));
        return Main.overview.visible || Main.sessionMode.isLocked ||
            Main.sessionMode.isGreeter || Main.modalCount > 0 ||
            Boolean(keyFocus && !applicationFocus);
    }

    _queueUpdate() {
        // Signals can arrive while Shell is still unwinding a modal grab.
        // Invalidate pending results immediately, then read the settled state.
        this._cancelRead();
        this._state.begin(null, true);
        if (this._updateSource)
            return;
        this._updateSource = GLib.idle_add(GLib.PRIORITY_DEFAULT_IDLE, () => {
            this._updateSource = 0;
            this._focusChanged();
            return GLib.SOURCE_REMOVE;
        });
    }

    _update() {
        this._cancelRead();
        const window = this._focused;
        const suppressed = this._suppressed();
        const state = this._state;
        // Native Wayland windows are local in this GUI path; no reader is needed.
        const cached = this._cache.get(window) ??
            (window?.get_client_type() === Meta.WindowClientType.WAYLAND ? LOCAL : null);
        const revision = state.begin(window, suppressed, cached ?? UNKNOWN);
        if (!window || suppressed || [Meta.WindowType.DESKTOP, Meta.WindowType.DOCK].includes(window.get_window_type())) {
            this._render(null);
            return;
        }
        if (cached)
            return;
        const cancellable = new Gio.Cancellable();
        this._cancellable = cancellable;
        this._resolve(window, cancellable, new Set()).then(identity => {
            state.complete(revision, identity);
        }).catch(() => state.complete(revision, UNKNOWN));
    }

    async _resolve(window, cancellable, seen) {
        if (cancellable.is_cancelled() || seen.has(window))
            return UNKNOWN;
        seen.add(window);
        const cache = this._cache;
        const cached = cache.get(window);
        if (cached)
            return cached;
        if (window.get_client_type() === Meta.WindowClientType.WAYLAND)
            return LOCAL;
        // Mutter's description starts with the X client XID; its title is ignored.
        const xid = /^(0x[0-9a-fA-F]+)\s/.exec(window.get_description())?.[1];
        if (!xid)
            return UNKNOWN;
        cache.watch(window);
        const identity = await this._read(xid, cancellable);
        if (cancellable.is_cancelled())
            return UNKNOWN;
        if (identity.kind === 'absent') {
            const parent = window.get_transient_for();
            return parent ? this._resolve(parent, cancellable, seen) : UNKNOWN;
        }
        cache.remember(window, identity);
        return identity;
    }

    _read(xid, cancellable) {
        return new Promise(resolve => {
            if (cancellable.is_cancelled()) {
                resolve(UNKNOWN);
                return;
            }
            const process = Gio.Subprocess.new([READER, xid],
                Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_SILENCE);
            this._process = process;
            process.communicate_utf8_async(null, cancellable, (source, result) => {
                if (this._process === process)
                    this._process = null;
                try {
                    const [, stdout] = source.communicate_utf8_finish(result);
                    resolve(source.get_successful() ? JSON.parse(stdout) : UNKNOWN);
                } catch (_error) {
                    resolve(UNKNOWN);
                }
            });
        });
    }

    _cancelRead() {
        this._cancellable?.cancel();
        this._cancellable = null;
        this._process?.force_exit();
        this._process = null;
    }

    _render(identity) {
        this._identity = identity;
        this._indicator.visible = identity !== null;
        this._label.set_text(identity?.name ?? '');
        this._dot.visible = Boolean(identity?.color);
        this._dot.set_style(identity?.color ? `background-color: ${identity.color};` : null);
        this._indicator.accessible_name = identity?.name ?? 'Focused VM';
    }

    disable() {
        if (this._updateSource) {
            GLib.Source.remove(this._updateSource);
            this._updateSource = 0;
        }
        this._cancelRead();
        this._disconnect(this._signals);
        this._disconnect(this._windowSignals);
        this._cache.clear();
        this._cache = null;
        this._state.disable();
        this._state = null;
        this._focused = null;
        this._indicator.destroy();
        this._indicator = null;
        this._label = null;
        this._dot = null;
    }
}
