import Clutter from 'gi://Clutter';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import GObject from 'gi://GObject';
import Pango from 'gi://Pango';
import Shell from 'gi://Shell';
import St from 'gi://St';

import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as Search from 'resource:///org/gnome/shell/ui/search.js';
import {Extension, InjectionManager} from 'resource:///org/gnome/shell/extensions/extension.js';
import {describeResult, groupResults, parseInventory} from './model.js';

// Keep GNOME's AppIcon/SystemActionIcon: activation, context menus, favorites,
// running indicators and dragging continue to use their original identities.
function makeRow(display) {
    const original = display.get_child();
    display.set_child(null);
    original.set({x_expand: false, y_expand: false,
        x_align: Clutter.ActorAlign.CENTER, y_align: Clutter.ActorAlign.CENTER});
    display.icon.label?.hide();
    display.icon.style_class = 'airlock-vm-search-icon';
    // System action icons normally take their size from the grid theme.
    display.icon._setSizeManually = true;
    display.icon.setIconSize(32);
    display.icon.set({x_expand: false, y_expand: false});
    original.set_size(32, 32);
    const content = new St.BoxLayout({style_class: 'airlock-vm-search-content',
        x_expand: true, orientation: Clutter.Orientation.HORIZONTAL});
    content.add_child(original);
    display._airlockTitle = new St.Label({style_class: 'airlock-vm-search-title',
        x_expand: true, y_align: Clutter.ActorAlign.CENTER});
    display._airlockTitle.clutter_text.set({line_wrap: true,
        line_wrap_mode: Pango.WrapMode.WORD_CHAR, ellipsize: Pango.EllipsizeMode.NONE});
    content.add_child(display._airlockTitle);
    display.set_child(content);
    display.style_class = 'airlock-vm-search-row';
    display.x_expand = true;
    display.label_actor = display._airlockTitle;
    return display;
}

export const VMSearchResults = GObject.registerClass(
class VMSearchResults extends Search.GridSearchResults {
    _init(provider, view, inventory) {
        super._init(provider, view);
        this._inventory = inventory;
        this._alive = true;
        this._revision = 0;
        this._groups = [];
        this._first = null;
        // Reuse the upstream result cache/cancellation/focus machinery. Its
        // square grid is replaced by a vertical presentation inside the same
        // search section and the existing overview scroll view.
        this._resultDisplayBin.child.destroy();
        this._rows = new St.BoxLayout({style_class: 'airlock-vm-search',
            orientation: Clutter.Orientation.VERTICAL, x_expand: true});
        this._resultDisplayBin.child = this._rows;
    }

    _onDestroy() {
        this._alive = false;
        this._revision++;
        this._cancellable.cancel();
        super._onDestroy();
    }

    clear() {
        this._revision++;
        super.clear();
    }

    _clearResultDisplay() {
        // Cached row actors survive searches; only headings/containers are
        // disposable. Detach rows before destroying their former group.
        for (const display of Object.values(this._resultDisplays))
            display.get_parent()?.remove_child(display);
        for (const group of this._groups)
            group.destroy();
        this._groups = [];
        this._first = null;
        this._focusChild = null;
    }

    _createResultDisplay(meta) {
        return makeRow(this.provider.createResultObject(meta));
    }

    async updateSearch(results, terms) {
        const revision = ++this._revision;
        const inventory = this._inventory();
        const groups = groupResults(results, inventory);
        const ordered = groups.flatMap(group => group.ids);
        this._terms = terms;
        await this._ensureResultActors(ordered);
        if (!this._alive || revision !== this._revision)
            return;
        this.hide();
        this._clearResultDisplay();
        for (const group of groups) {
            const box = new St.BoxLayout({style_class: 'airlock-vm-search-group',
                orientation: Clutter.Orientation.VERTICAL, x_expand: true});
            const heading = new St.BoxLayout({style_class: 'airlock-vm-search-heading',
                can_focus: false, reactive: false});
            if (group.color) {
                const dot = new St.Widget({style_class: 'airlock-vm-search-color',
                    y_align: Clutter.ActorAlign.CENTER});
                dot.set_style(`background-color: ${group.color};`);
                heading.add_child(dot);
            }
            const name = new St.Label({text: group.heading,
                style_class: 'airlock-vm-search-name', x_expand: true});
            name.clutter_text.set({line_wrap: true,
                line_wrap_mode: Pango.WrapMode.WORD_CHAR, ellipsize: Pango.EllipsizeMode.NONE});
            heading.add_child(name);
            if (group.stopped)
                heading.add_child(new St.Label({text: 'Stopped',
                    style_class: 'airlock-vm-search-status'}));
            box.add_child(heading);
            for (const id of group.ids) {
                const row = this._resultDisplays[id];
                const fullName = row.app?.get_name() ?? row.metaInfo.name;
                row._airlockTitle.text = describeResult(id, fullName, inventory).title;
                row.accessible_name = fullName;
                box.add_child(row);
                this._first ??= row;
            }
            this._rows.add_child(box);
            this._groups.push(box);
        }
        this.visible = ordered.length > 0;
    }

    getFirstResult() {
        return this._first;
    }
});

export default class VMSearchExtension extends Extension {
    enable() {
        this._active = true;
        this._inventory = new Map();
        this._inventoryRead = 0;
        this._views = new Set();
        this._cancellable = new Gio.Cancellable();
        this._injections = new InjectionManager();
        const extension = this;
        this._injections.overrideMethod(Search.SearchResultsView.prototype,
            '_ensureProviderDisplay', original => function (provider) {
                if (provider.id !== 'applications')
                    return original.call(this, provider);
                if (provider.display)
                    return;
                const display = new VMSearchResults(provider, this, () => extension._inventory);
                display.connect('notify::focus-child', this._focusChildChanged.bind(this));
                display.hide();
                this._content.add_child(display);
                provider.display = display;
                extension._views.add(this);
            });
        const view = Main.overview._overview.controls._searchController._searchResults;
        this._replaceDisplay(view);
        this._apps = Shell.AppSystem.get_default();
        this._appsSignal = this._apps.connect('installed-changed', () => this._refreshViews());
        const directory = GLib.build_filenamev([GLib.get_user_state_dir(), 'airlock-appmenus']);
        GLib.mkdir_with_parents(directory, 0o700);
        this._file = Gio.File.new_for_path(`${directory}/inventory.json`);
        this._monitor = Gio.File.new_for_path(directory).monitor_directory(
            Gio.FileMonitorFlags.WATCH_MOVES, this._cancellable);
        this._monitor.connect('changed', (_monitor, file, other) => {
            if (file.get_basename() === 'inventory.json' || other?.get_basename() === 'inventory.json')
                this._queueInventory();
        });
        this._loadInventory();
    }

    _replaceDisplay(view) {
        const provider = view._providers.find(item => item.id === 'applications');
        if (!provider)
            return;
        const old = provider.display;
        const position = view._content.get_children().indexOf(old);
        view._setSelected(view._defaultResult, false);
        view._defaultResult = null;
        old?.clear();
        old?.destroy();
        provider.display = null;
        view._ensureProviderDisplay(provider);
        view._content.set_child_at_index(provider.display, Math.max(position, 0));
        if (view.terms.length)
            view._doProviderSearch(provider).catch(logError);
    }

    _refreshViews() {
        if (!this._active)
            return;
        for (const view of this._views) {
            const provider = view._providers.find(item => item.id === 'applications');
            if (provider && view.terms.length && !provider.searchInProgress)
                view._doProviderSearch(provider).catch(logError);
        }
    }

    _queueInventory() {
        if (this._inventoryLater)
            GLib.source_remove(this._inventoryLater);
        this._inventoryLater = GLib.timeout_add(GLib.PRIORITY_DEFAULT, 100, () => {
            this._inventoryLater = 0;
            this._loadInventory();
            return GLib.SOURCE_REMOVE;
        });
    }

    _loadInventory() {
        const cancellable = this._cancellable;
        const revision = ++this._inventoryRead;
        this._file.load_contents_async(cancellable, (file, result) => {
            try {
                const [, bytes] = file.load_contents_finish(result);
                if (!this._active || cancellable.is_cancelled() ||
                    revision !== this._inventoryRead || bytes.length > 1024 * 1024)
                    return;
                const text = new TextDecoder().decode(bytes);
                if (text === this._inventoryText)
                    return;
                const inventory = parseInventory(text);
                this._inventoryText = text;
                this._inventory = inventory;
                this._refreshViews();
            } catch (error) {
                // Missing/transient cache snapshots preserve the last complete
                // inventory. Search itself never asks Qubes to start a VM.
                if (!error.matches?.(Gio.io_error_quark(), Gio.IOErrorEnum.NOT_FOUND) &&
                    !error.matches?.(Gio.io_error_quark(), Gio.IOErrorEnum.CANCELLED))
                    logError(error, 'Airlock VM search inventory');
            }
        });
    }

    disable() {
        this._active = false;
        this._cancellable?.cancel();
        this._monitor?.cancel();
        if (this._inventoryLater)
            GLib.source_remove(this._inventoryLater);
        this._inventoryLater = 0;
        if (this._appsSignal)
            this._apps.disconnect(this._appsSignal);
        this._injections?.clear();
        for (const view of this._views ?? [])
            this._replaceDisplay(view);
        this._views?.clear();
        this._inventory = new Map();
        this._inventoryText = null;
    }
}
