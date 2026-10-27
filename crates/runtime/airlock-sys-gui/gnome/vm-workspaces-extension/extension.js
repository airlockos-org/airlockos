import Clutter from 'gi://Clutter';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import Meta from 'gi://Meta';
import St from 'gi://St';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import * as DND from 'resource:///org/gnome/shell/ui/dnd.js';
import * as Workspace from 'resource:///org/gnome/shell/ui/workspace.js';
import * as WorkspaceThumbnail from 'resource:///org/gnome/shell/ui/workspaceThumbnail.js';
import {Extension, InjectionManager} from 'resource:///org/gnome/shell/extensions/extension.js';
import {WindowIdentityCache, LOCAL, UNKNOWN, validateIdentity} from './identity.js';
import {parseInventory} from './inventory.js';
import {MAX_SLOTS, describeWorkspace, groupOwnedWorkspaces} from './model.js';

const READER = '@identityReader@';
const WORKSPACE_BUS = 'org.airlock.Workspaces';
const WORKSPACE_PATH = '/org/airlock/Workspaces';
const WORKSPACE_XML = `<node><interface name="org.airlock.Workspaces">
<method name="Prepare"><arg type="s" direction="in"/><arg type="s" direction="out"/></method>
<method name="Cancel"><arg type="s" direction="in"/></method>
<method name="State"><arg type="s" direction="out"/></method>
</interface></node>`;

const TYPES = [Meta.WindowType.NORMAL, Meta.WindowType.DIALOG, Meta.WindowType.MODAL_DIALOG];
// Qubes prefixes both WM_CLASS fields with the originating VM name. The X11
// backend uses the executable name; app-id based backends use org.airlock.ctrl.
const REVIEW_CLASSES = new Set(['sys-ctrl:airlock-sys-ctrl-gui', 'sys-ctrl:airlock-ctrl-gui',
    'sys-ctrl:airlock-ctrl', 'sys-ctrl:org.airlock.ctrl']);

export default class VMWorkspacesExtension extends Extension {
    enable() {
        this._active = true;
        this._scanning = false;
        this._dirty = false;
        this._signals = [];
        this._windows = new Map();
        this._identities = new Map();
        this._pendingPlacement = new Set();
        this._pendingReviewFocus = new Set();
        this._mappedWindows = new WeakSet();
        this._owners = new Map();
        this._launches = new Map();
        this._heldActors = new Map();
        this._lastWorkspace = new Map();
        this._internalMoves = new Set();
        this._cache = new WindowIdentityCache();
        this._inventory = new Map();
        this._inventoryFingerprint = null;
        this._inventoryRevision = 0;
        this._cancellable = new Gio.Cancellable();
        this._wm = global.workspace_manager;
        this._mutter = new Gio.Settings({schema_id: 'org.gnome.mutter'});
        this._preferences = new Gio.Settings({schema_id: 'org.gnome.desktop.wm.preferences'});
        this._originalDynamic = this._mutter.get_boolean('dynamic-workspaces');
        this._originalCount = this._preferences.get_int('num-workspaces');
        this._preferences.set_int('num-workspaces', this._wm.n_workspaces);
        this._mutter.set_boolean('dynamic-workspaces', false);
        this._groups = [];
        this._overviewActors = new Map();
        this._thumbnailBoxes = new Map();
        this._dragging = false;
        this._indicator = new PanelMenu.Button(0.0, 'VM workspaces', true);
        this._indicator.reactive = false;
        this._indicator.can_focus = false;
        this._indicator.track_hover = false;
        this._indicator.add_style_class_name('airlock-workspace-bar');
        this._box = new St.BoxLayout({style_class: 'airlock-workspaces',
            reactive: false, clip_to_allocation: true, style: 'max-width: 480px;'});
        this._indicator.add_child(this._box);
        // GNOME owns the original left-hand Activities/workspace dots unchanged.
        Main.panel.addToStatusArea('airlock-vm-workspaces', this._indicator, 0, 'right');
        this._tooltip = new St.Label({style_class: 'dash-label', visible: false, reactive: false});
        Main.layoutManager.addChrome(this._tooltip);
        this._installOverview();
        this._installMovePolicy();
        this._installLaunchService();
        const extension = this;
        this._injections.overrideMethod(Main.wm, '_shouldAnimateActor', original => function (actor, ...args) {
            if (extension._pendingPlacement.has(actor.meta_window)) {
                extension._prepareWindow(actor.meta_window);
                if (extension._pendingPlacement.has(actor.meta_window)) {
                    extension._holdActor(actor);
                    return false;
                }
            }
            return original.call(this, actor, ...args);
        });
        this._connect(Main.overview, 'hidden', () => this._hideTooltip());
        for (const kind of ['window', 'item']) {
            this._connect(Main.overview, `${kind}-drag-begin`, () => {
                this._dragging = true;
                this._hideTooltip();
                this._refreshDragTargets();
            });
            for (const end of ['end', 'cancelled'])
                this._connect(Main.overview, `${kind}-drag-${end}`, () => {
                    this._dragging = false;
                    this._refreshDragTargets();
                });
        }
        this._connect(this._wm, 'workspace-switched', () => this._refresh());
        this._connect(this._wm, 'workspace-added', () => this._queue());
        this._connect(this._wm, 'workspace-removed', () => this._queue());
        this._connect(this._wm, 'workspaces-reordered', () => this._queue());
        this._connect(Main.sessionMode, 'updated', () => this._sessionChanged());
        this._sessionChanged();
        this._connect(global.display, 'window-created', (_display, window) => {
            this._watch(window);
            if (TYPES.includes(window.get_window_type())) {
                this._pendingPlacement.add(window);
                if (window.get_window_type() === Meta.WindowType.NORMAL && !window.get_transient_for())
                    this._pendingReviewFocus.add(window);
                this._prepareWindow(window);
            }
            this._queue();
        });
        this._connect(global.window_manager, 'map', (_manager, actor) => {
            const window = actor.meta_window;
            if (this._windows.has(window)) {
                this._mappedWindows.add(window);
                this._presentReview(window);
            }
        });
        for (const actor of global.get_window_actors())
            this._watch(actor.meta_window);
        const menus = GLib.build_filenamev([GLib.get_user_state_dir(), 'airlock-appmenus']);
        GLib.mkdir_with_parents(menus, 0o700);
        this._inventoryFile = Gio.File.new_for_path(GLib.build_filenamev([menus, 'inventory.json']));
        this._monitor = Gio.File.new_for_path(menus).monitor_directory(Gio.FileMonitorFlags.WATCH_MOVES, null);
        this._connect(this._monitor, 'changed', (_monitor, file, other) => {
            if ([file, other].some(f => f?.get_basename() === 'inventory.json'))
                this._loadInventory();
        });
        this._loadInventory();
        this._queue();
    }

    _connect(object, signal, callback) {
        this._signals.push([object, object.connect(signal, callback)]);
    }

    _watch(window) {
        if (!window || this._windows.has(window) || !TYPES.includes(window.get_window_type()))
            return;
        this._cache.watch(window);
        const changed = window.connect('workspace-changed', () => {
            this._enforceWorkspace(window);
            this._queue();
        });
        const sticky = window.connect('notify::on-all-workspaces', () => this._enforceWorkspace(window));
        // Mutter notifies wm-class when either class or instance changes.
        const wmClass = window.connect('notify::wm-class', () => this._presentReview(window));
        const unmanaged = window.connect('unmanaged', () => {
            window.disconnect(changed);
            window.disconnect(unmanaged);
            window.disconnect(sticky);
            window.disconnect(wmClass);
            this._windows.delete(window);
            this._identities.delete(window);
            this._pendingPlacement.delete(window);
            this._pendingReviewFocus.delete(window);
            this._lastWorkspace.delete(window);
            this._queue();
        });
        this._windows.set(window, [changed, unmanaged, sticky, wmClass]);
        this._lastWorkspace.set(window, window.get_workspace());
    }

    _workspaceWindows(workspace) {
        // Count sticky windows once, rather than creating an entry on every slot.
        return [...this._windows.keys()].filter(window => window.get_workspace() === workspace);
    }

    _sync() {
        const workspaces = Array.from({length: this._wm.n_workspaces},
            (_, index) => this._wm.get_workspace_by_index(index));
        const identities = new Map(workspaces.map(workspace => [workspace,
            this._workspaceWindows(workspace).map(window => this._identities.get(window) ?? UNKNOWN)]));
        // Adopt existing homogeneous workspaces only once. Later moves never change ownership.
        for (const workspace of workspaces) {
            if (!this._owners.has(workspace)) {
                const description = describeWorkspace(identities.get(workspace), this._inventory);
                if (description?.kind === 'vm')
                    this._owners.set(workspace, description);
            }
        }
        const reserved = new Set([...this._launches.values()].map(launch => launch.workspace));
        // A local system prompt may occupy a workspace, but gets no sys-gui tab.
        const occupied = workspaces.filter(workspace => this._workspaceWindows(workspace).length || reserved.has(workspace));
        const active = this._wm.get_active_workspace();
        if (occupied.length && !occupied.includes(active)) {
            const nearest = occupied.reduce((best, workspace) =>
                Math.abs(workspace.index() - active.index()) < Math.abs(best.index() - active.index())
                    ? workspace : best);
            nearest.activate(global.get_current_time());
        }
        for (const workspace of workspaces) {
            if (!occupied.includes(workspace) && (occupied.length || workspace !== active) && this._wm.n_workspaces > 1)
                this._wm.remove_workspace(workspace, global.get_current_time());
        }
        for (const workspace of this._owners.keys()) {
            if (workspace.index() < 0 || (!occupied.includes(workspace) && !reserved.has(workspace)))
                this._owners.delete(workspace);
        }
        this._groups = groupOwnedWorkspaces(this._groups, workspaces.filter(workspace => workspace.index() >= 0),
            this._owners, identities, this._inventory);
        // Reorder workspace objects; existing windows stay attached to them.
        this._groups.flatMap(group => group.slots).forEach((workspace, index) => {
            if (workspace.index() !== index)
                this._wm.reorder_workspace(workspace, index);
        });
        this._ownedCount = this._wm.n_workspaces;
        this._preferences.set_int('num-workspaces', this._ownedCount);
        this._render();
    }

    _sessionChanged() {
        this._indicator.visible = this._groups.length > 0 &&
            !Main.sessionMode.isLocked && !Main.sessionMode.isGreeter;
        this._hideTooltip();
        for (const window of this._pendingReviewFocus)
            this._presentReview(window);
    }

    _presentReview(window) {
        if (!this._active || !this._pendingReviewFocus.has(window) ||
            this._pendingPlacement.has(window) || !this._mappedWindows.has(window))
            return;
        const identity = this._identities.get(window);
        if (!identity || identity.kind === 'unknown')
            return;
        // Application metadata is not proof of VM origin. Only the existing
        // qubes-guid provenance reader can qualify a window for this exception.
        if (identity.kind !== 'vm' || identity.name !== 'sys-ctrl') {
            this._pendingReviewFocus.delete(window);
            return;
        }
        if (window.get_window_type() !== Meta.WindowType.NORMAL || window.get_transient_for() ||
            ![window.get_wm_class(), window.get_wm_class_instance()].some(value => REVIEW_CLASSES.has(value)) ||
            Main.sessionMode.isLocked || Main.sessionMode.isGreeter)
            return;
        const workspace = window.get_workspace();
        if (!workspace || workspace.index() < 0)
            return;
        // Remove before activation, which emits workspace/focus notifications.
        // Refreshes and extension reloads must not repeatedly steal focus.
        this._pendingReviewFocus.delete(window);
        Main.activateWindow(window, global.get_current_time());
    }

    _loadInventory() {
        const revision = ++this._inventoryRevision;
        const cancellable = this._cancellable;
        this._inventoryFile.load_contents_async(cancellable, (file, result) => {
            let inventory;
            try {
                const [, bytes] = file.load_contents_finish(result);
                if (!this._active || cancellable.is_cancelled() || revision !== this._inventoryRevision || bytes.length > 1048576)
                    return;
                inventory = parseInventory(new TextDecoder().decode(bytes));
            } catch (_error) {
                return; // Retain the previous valid snapshot.
            }
            const fingerprint = JSON.stringify([...inventory].sort(([a], [b]) => a.localeCompare(b)));
            if (fingerprint === this._inventoryFingerprint) {
                this._queue();
                return;
            }
            this._inventory = inventory;
            this._inventoryFingerprint = fingerprint;
            for (const owner of this._owners.values()) {
                const entry = owner.key.startsWith('vm:')
                    ? [...inventory].find(([, vm]) => vm.name === owner.name)
                    : inventory.has(owner.key) ? [owner.key, inventory.get(owner.key)] : null;
                if (entry) {
                    const [key, vm] = entry;
                    for (const group of this._groups) {
                        if (group.key === owner.key)
                            group.key = key;
                    }
                    Object.assign(owner, {key, name: vm.name, names: [vm.name], color: vm.color ?? '#888888'});
                }
            }
            this._queue();
        });
    }

    _render() {
        const entries = this._groups.flatMap(group => group.slots.map(workspace => ({group, workspace})));
        // Preserve hovered/focused actors when only the active workspace changes.
        const unchanged = this._tabs?.length === entries.length && entries.every(({group, workspace}, index) => {
            const old = this._tabs[index];
            return old.workspace === workspace && old.group.key === group.key &&
                old.group.color === group.color && old.group.name === group.name;
        });
        if (unchanged) {
            this._tabs.forEach((tab, index) => { tab.group = entries[index].group; });
        } else {
            this._hideTooltip();
            this._box.destroy_all_children();
            this._tabs = [];
            for (const group of this._groups) {
                const box = new St.BoxLayout({style_class: 'airlock-workspace-group',
                    reactive: false, style: `border-bottom-color: ${group.color};`});
                if (this._box.get_first_child())
                    box.add_style_class_name('vm-divider');
                for (const workspace of group.slots) {
                    const button = new St.Button({style_class: 'airlock-workspace-tab',
                        reactive: true, can_focus: true, track_hover: true});
                    if (workspace !== group.slots[0])
                        button.add_style_class_name('slot-divider');
                    const label = new St.Label({reactive: false, can_focus: false,
                        y_align: Clutter.ActorAlign.CENTER});
                    button.set_child(label);
                    const tab = {group, workspace, button, label, focused: false};
                    this._tabs.push(tab);
                    button.connect('clicked', () => {
                        this._hideTooltip();
                        const focused = global.display.focus_window;
                        if ((global.get_pointer()[2] & Clutter.ModifierType.SHIFT_MASK) &&
                            focused && this._identities.get(focused)?.name === tab.group.name)
                            this._splitWindow(focused);
                        else
                            workspace.activate(global.get_current_time());
                    });
                    button.connect('notify::hover', () => {
                        this._styleTab(tab);
                        if (button.hover)
                            this._showTooltip(tab);
                        else
                            this._hideTooltip();
                    });
                    button.connect('key-focus-in', () => {
                        tab.focused = true;
                        this._styleTab(tab);
                        this._showTooltip(tab);
                    });
                    button.connect('key-focus-out', () => {
                        tab.focused = false;
                        this._styleTab(tab);
                        this._hideTooltip();
                    });
                    button._delegate = {
                        handleDragOver: source => !source.metaWindow ? DND.DragMotionResult.CONTINUE
                            : this._canMove(source.metaWindow, workspace) ? DND.DragMotionResult.MOVE_DROP
                                : DND.DragMotionResult.NO_DROP,
                        acceptDrop: source => {
                            if (!source.metaWindow || !this._canMove(source.metaWindow, workspace, true))
                                return false;
                            source.metaWindow.change_workspace(workspace);
                            this._queue();
                            return true;
                        },
                    };
                    box.add_child(button);
                }
                this._box.add_child(box);
            }
        }
        this._refresh();
        this._sessionChanged();
    }

    _description(tab) {
        const description = describeWorkspace(this._workspaceWindows(tab.workspace)
            .map(window => this._identities.get(window) ?? UNKNOWN), this._inventory);
        const owner = description?.kind === 'mixed' ? `Mixed: ${description.names.join(', ')}`
            : description?.name ?? tab.group?.name;
        return `${owner} · workspace ${tab.workspace.index() + 1}`;
    }

    _refresh() {
        const active = this._wm.get_active_workspace();
        for (const tab of this._tabs ?? []) {
            tab.label.text = String(tab.workspace.index() + 1);
            tab.button.accessible_name = this._description(tab);
            this._styleTab(tab);
            if (tab.workspace === active) {
                tab.button.add_style_class_name('active');
                tab.group.lastUsed = tab.workspace;
            } else {
                tab.button.remove_style_class_name('active');
            }
        }
        this._refreshOverview();
    }

    _styleTab(tab) {
        const alpha = tab.workspace === this._wm.get_active_workspace() ? 0.55
            : tab.button.hover || tab.focused ? 0.45 : 0.35;
        const actual = describeWorkspace(this._workspaceWindows(tab.workspace)
            .map(window => this._identities.get(window) ?? UNKNOWN), this._inventory);
        const candidate = actual && actual.kind !== 'vm' ? '#888888' : tab.group.color;
        const color = /^#[0-9a-f]{6}$/i.test(candidate) ? candidate : '#888888';
        const rgb = [1, 3, 5].map(index => parseInt(color.slice(index, index + 2), 16));
        tab.button.style = `background-color: rgba(${rgb.join(',')},${alpha});`;
    }

    _installOverview() {
        this._injections = new InjectionManager();
        const extension = this;
        for (const [prototype, small] of [[Workspace.Workspace.prototype, false],
            [WorkspaceThumbnail.WorkspaceThumbnail.prototype, true]]) {
            this._injections.overrideMethod(prototype, '_init', original => function (...args) {
                original.apply(this, args);
                extension._decorateOverview(this, small);
            });
        }
        this._injections.overrideMethod(Workspace.WorkspaceBackground.prototype,
            '_updateBorderRadius', original => function (...args) {
                original.apply(this, args);
                const record = extension._overviewActors.get(this.get_parent());
                if (record)
                    extension._paintOverview(record);
            });
        this._installWorkspaceInsertion();
        // Keep GNOME's moving selector, but give it the selected VM's colour.
        for (const method of ['_init', '_updateIndicator', 'addThumbnails']) {
            this._injections.overrideMethod(WorkspaceThumbnail.ThumbnailsBox.prototype,
                method, original => function (...args) {
                    const result = original.apply(this, args);
                    extension._decorateThumbnailBox(this);
                    return result;
                });
        }
        // Also cover previews created before this extension was enabled.
        const controls = Main.overview._overview.controls;
        this._decorateThumbnailBox(controls._thumbnailsBox);
        for (const actor of controls._thumbnailsBox?._thumbnails ?? [])
            this._decorateOverview(actor, true);
        for (const view of controls._workspacesDisplay?._workspacesViews ?? []) {
            this._decorateThumbnailBox(view._thumbnails);
            for (const actor of view._workspaces ?? view._workspacesView?._workspaces ?? [])
                this._decorateOverview(actor, false);
            for (const actor of view._thumbnails?._thumbnails ?? [])
                this._decorateOverview(actor, true);
        }
    }

    _decorateThumbnailBox(box) {
        if (!this._active || !box?._indicator || !box._scrollAdjustment)
            return;
        if (!this._thumbnailBoxes.has(box)) {
            const record = {style: box._indicator.get_style()};
            record.destroySignal = box.connect('destroy', () => this._thumbnailBoxes.delete(box));
            this._thumbnailBoxes.set(box, record);
            box.add_style_class_name('airlock-workspace-thumbnails');
        }
        this._paintSelector(box);
    }

    _paintSelector(box) {
        // Follow the nearest thumbnail as the native selector animates/swipes.
        const index = Math.round(box._scrollAdjustment.value);
        const workspace = this._wm.get_workspace_by_index(index) ?? this._wm.get_active_workspace();
        const description = describeWorkspace(this._workspaceWindows(workspace)
            .map(window => this._identities.get(window) ?? UNKNOWN), this._inventory) ?? this._owners.get(workspace);
        const previous = this._thumbnailBoxes.get(box).style;
        const style = previous ? `${previous}; ` : '';
        box._indicator.style = `${style}border-color: ${description?.color ?? '#888888'}; border-radius: 0;`;
    }

    _decorateOverview(actor, small) {
        if (!this._active || !actor.metaWorkspace || this._overviewActors.has(actor))
            return;
        // Large outlines sit above the wallpaper and below every window preview.
        const border = new St.Widget({reactive: false, can_focus: false,
            style_class: small ? 'airlock-overview-thumbnail-border' : 'airlock-overview-workspace-border'});
        border.add_constraint(new Clutter.BindConstraint({
            source: small ? actor : actor._background,
            coordinate: small ? Clutter.BindCoordinate.SIZE : Clutter.BindCoordinate.ALL,
        }));
        if (small)
            actor.add_child(border);
        else
            actor.insert_child_above(border, actor._background);
        const record = {actor, border, small, workspace: actor.metaWorkspace, button: actor,
            tooltipAbove: !small, reactive: actor.reactive, trackHover: actor.track_hover};
        if (!small) {
            record.backgroundStyle = actor._background.get_style();
            record.geometrySource = actor._background._bin;
            // Allocation completes after the radius update during the zoom animation.
            record.geometrySource?.connectObject('notify::allocation',
                () => this._paintOverview(record), border);
        }
        actor.reactive = true;
        actor.track_hover = true;
        record.hoverSignal = actor.connect('notify::hover', () => {
            if (actor.hover && record.group && Main.overview.visible)
                this._showTooltip(record);
            else
                this._hideTooltip();
        });
        record.destroySignal = actor.connect('destroy', () => {
            this._hideTooltip();
            this._overviewActors.delete(actor);
        });
        this._overviewActors.set(actor, record);
        this._paintOverview(record);
    }

    _paintOverview(record) {
        const {workspace, border} = record;
        record.group = describeWorkspace(this._workspaceWindows(workspace)
            .map(window => this._identities.get(window) ?? UNKNOWN), this._inventory) ?? this._owners.get(workspace);
        const active = workspace === this._wm.get_active_workspace();
        // GNOME's selector alone outlines the active small thumbnail.
        const color = record.small && active ? 'transparent' : record.group?.color ?? 'transparent';
        let radius = 0;
        if (!record.small) {
            const background = record.actor._background;
            const scale = St.ThemeContext.get_for_stage(global.stage).scaleFactor;
            const wallpaperScale = background._bin?.width > 0 && background._workarea?.width > 0
                ? background._bin.width / background._workarea.width : 1;
            radius = (background._bgManager?.backgroundActor?.content?.rounded_clip_radius ?? 0)
                * wallpaperScale / scale;
            const original = record.backgroundStyle ? `${record.backgroundStyle}; ` : '';
            const backgroundStyle = `${original}border-radius: ${radius}px;`;
            if (background.get_style() !== backgroundStyle)
                background.style = backgroundStyle;
            border.opacity = Math.round(255 * (background._stateAdjustment?.value ?? 1) * (active ? 1 : 0.7));
        }
        // Selected and unselected outlines share exactly the same outer and inner contours.
        border.style = `border-color: ${color}; border-width: 2px; border-radius: ${radius}px;`;
    }

    _refreshDragTargets() {
        for (const box of this._thumbnailBoxes.keys()) {
            box._updateShouldShow();
            if (!this._dragging)
                box._clearDragPlaceholder();
        }
    }

    _canInsert(box, position, owner) {
        if (!owner || this._wm.n_workspaces >= MAX_SLOTS ||
            !(box._thumbnails[position]?.metaWorkspace.index() >= 0))
            return false;
        return [box._thumbnails[position - 1], box._thumbnails[position]]
            .some(thumbnail => this._owners.get(thumbnail?.metaWorkspace)?.key === owner.key);
    }

    _installWorkspaceInsertion() {
        const extension = this;
        const prototype = WorkspaceThumbnail.ThumbnailsBox.prototype;
        this._injections.overrideMethod(prototype, '_updateShouldShow', original => function (...args) {
            // A single occupied workspace still needs a thumbnail during a window drag.
            if (extension._dragging && extension._groups.length) {
                if (!this._shouldShow) {
                    this._shouldShow = true;
                    this.notify('should-show');
                }
            } else {
                original.apply(this, args);
            }
        });
        this._injections.overrideMethod(prototype, 'handleDragOver', original => function (source, actor, x, y, time) {
            if (!source.metaWindow)
                return original.call(this, source, actor, x, y, time);
            const owner = extension._owner(extension._moveIdentity(source.metaWindow));
            const rtl = Clutter.get_default_text_direction() === Clutter.TextDirection.RTL;
            const spacing = this.get_theme_node().get_length('spacing');
            // Reuse GNOME's native cut regions, expanding insertion placeholder and cursor.
            for (let index = 0; index < this._thumbnails.length; index++) {
                const [start, end] = this._getPlaceholderTarget(index, spacing, rtl);
                if (x <= start || x > end)
                    continue;
                if (!extension._canInsert(this, index, owner)) {
                    this._dropWorkspace = -1;
                    this._clearDragPlaceholder();
                    return DND.DragMotionResult.NO_DROP;
                }
                this._dropWorkspace = -1;
                if (this._dropPlaceholderPos !== index) {
                    this._dropPlaceholderPos = index;
                    this.queue_relayout();
                }
                return DND.DragMotionResult.MOVE_DROP;
            }
            return original.call(this, source, actor, x, y, time);
        });
        this._injections.overrideMethod(prototype, 'acceptDrop', original => function (source, ...args) {
            if (!source.metaWindow || this._dropWorkspace !== -1 || this._dropPlaceholderPos === -1)
                return original.call(this, source, ...args);
            const position = this._dropPlaceholderPos;
            const owner = extension._owner(extension._moveIdentity(source.metaWindow));
            if (!extension._canInsert(this, position, owner))
                return false;
            const index = this._thumbnails[position].metaWorkspace.index();
            this._clearDragPlaceholder();
            // Move workspace objects, never shuffle foreign windows between owned slots.
            const workspace = extension._wm.append_new_workspace(false, global.get_current_time());
            extension._owners.set(workspace, owner);
            extension._wm.reorder_workspace(workspace, index);
            Main.moveWindowToMonitorAndWorkspace(source.metaWindow, this._monitorIndex, workspace.index());
            workspace.activate(global.get_current_time());
            extension._sync();
            return true;
        });
    }

    _refreshOverview() {
        for (const record of this._overviewActors.values())
            this._paintOverview(record);
        for (const box of this._thumbnailBoxes.keys())
            this._paintSelector(box);
    }

    _showTooltip(tab) {
        this._hideTooltip();
        if (this._dragging)
            return;
        this._tooltipSource = GLib.timeout_add(GLib.PRIORITY_DEFAULT, 200, () => {
            this._tooltipSource = 0;
            if (!this._active || !this._indicator.visible || this._dragging ||
                (tab.tooltipAbove !== undefined && !Main.overview.visible))
                return GLib.SOURCE_REMOVE;
            this._tooltip.text = this._description(tab);
            const [x, y] = tab.button.get_transformed_position();
            const [width, height] = tab.button.get_transformed_size();
            const [, naturalWidth] = this._tooltip.get_preferred_width(-1);
            const monitor = Main.layoutManager.findMonitorForActor(tab.button) ?? Main.layoutManager.primaryMonitor;
            const [, naturalHeight] = this._tooltip.get_preferred_height(-1);
            const tooltipY = tab.tooltipAbove ? y - naturalHeight - 8 : y + height + 8;
            this._tooltip.set_position(Math.max(monitor.x, Math.min(x + width / 2 - naturalWidth / 2,
                monitor.x + monitor.width - naturalWidth)), Math.max(monitor.y + 8,
                Math.min(tooltipY, monitor.y + monitor.height - naturalHeight - 8)));
            this._tooltip.show();
            return GLib.SOURCE_REMOVE;
        });
    }

    _hideTooltip() {
        if (this._tooltipSource)
            GLib.Source.remove(this._tooltipSource);
        this._tooltipSource = 0;
        this._tooltip?.hide();
    }

    _splitWindow(window) {
        if (this._wm.n_workspaces >= MAX_SLOTS || window.is_on_all_workspaces())
            return;
        const workspace = this._wm.append_new_workspace(false, global.get_current_time());
        const owner = this._owners.get(window.get_workspace());
        if (owner)
            this._owners.set(workspace, owner);
        window.change_workspace(workspace);
        workspace.activate(global.get_current_time());
        this._queue();
    }

    _moveIdentity(window) {
        let identity = this._identities.get(window) ?? this._cache.get(window);
        // Failed reads are retried by the asynchronous scanner, not every move guard.
        if (!identity) {
            identity = this._resolveSync(window, new Set());
            this._identities.set(window, validateIdentity(identity));
        }
        return identity;
    }

    _canMove(window, workspace, claim = false) {
        if (!this._active || this._internalMoves.has(window) || !TYPES.includes(window.get_window_type()))
            return true;
        if (!workspace || workspace.index() < 0)
            return false;
        const identity = this._moveIdentity(window);
        if (identity.kind === 'local')
            return true;
        const owner = this._owner(identity);
        const destinationOwner = this._owners.get(workspace);
        if (!owner)
            return !destinationOwner && workspace === window.get_workspace();
        if (destinationOwner)
            return destinationOwner.key === owner.key;
        // A new, unowned slot can join this VM, but cannot contain foreign or unknown windows.
        const compatible = this._workspaceWindows(workspace).filter(other => other !== window)
            .every(other => {
                const otherIdentity = this._identities.get(other) ?? this._cache.get(other);
                return otherIdentity?.kind === 'local' || this._owner(otherIdentity)?.key === owner.key;
            });
        if (compatible && claim)
            this._owners.set(workspace, owner);
        return compatible;
    }

    _moveInternally(window, workspace) {
        this._internalMoves.add(window);
        try {
            if (window.is_on_all_workspaces())
                window.unstick();
            if (workspace !== window.get_workspace())
                window.change_workspace(workspace);
            this._lastWorkspace.set(window, workspace);
        } finally {
            this._internalMoves.delete(window);
        }
    }

    _enforceWorkspace(window) {
        if (!this._active || this._internalMoves.has(window) || this._pendingPlacement.has(window))
            return;
        const identity = this._identities.get(window) ?? this._cache.get(window);
        if (!identity || identity.kind === 'local')
            return;
        const current = window.get_workspace();
        if (!window.is_on_all_workspaces() && this._canMove(window, current, true)) {
            this._lastWorkspace.set(window, current);
            return;
        }
        const previous = this._lastWorkspace.get(window);
        const owner = this._owner(identity);
        const destination = previous && this._canMove(window, previous, true) ? previous
            : owner ? this._destination(owner, null, window)
                : this._wm.append_new_workspace(false, global.get_current_time());
        this._moveInternally(window, destination);
        this._queue();
    }

    _installMovePolicy() {
        const extension = this;
        this._injections.overrideMethod(Meta.Window.prototype, 'change_workspace', original => function (workspace) {
            if (extension._canMove(this, workspace, true))
                return original.call(this, workspace);
            return undefined;
        });
        this._injections.overrideMethod(Meta.Window.prototype, 'change_workspace_by_index', original => function (index, append) {
            if (extension._internalMoves.has(this) || !TYPES.includes(this.get_window_type()))
                return original.call(this, index, append);
            if (index === -1)
                return this.stick();
            let workspace = extension._wm.get_workspace_by_index(index);
            if (!workspace && append && index >= 0)
                workspace = extension._wm.append_new_workspace(false, global.get_current_time());
            if (workspace && extension._canMove(this, workspace, true))
                return this.change_workspace(workspace);
            return undefined;
        });
        this._injections.overrideMethod(Meta.Window.prototype, 'stick', original => function (...args) {
            if (extension._internalMoves.has(this) || !TYPES.includes(this.get_window_type()) ||
                extension._moveIdentity(this).kind === 'local')
                return original.apply(this, args);
            return undefined;
        });
        this._injections.overrideMethod(Main.wm, 'actionMoveWindow', original => function (window, workspace) {
            if (extension._canMove(window, workspace, true))
                return original.call(this, window, workspace);
            return undefined;
        });
        for (const [prototype, over, drop] of [
            [Workspace.Workspace.prototype, 'handleDragOver', 'acceptDrop'],
            [WorkspaceThumbnail.WorkspaceThumbnail.prototype, 'handleDragOverInternal', 'acceptDropInternal'],
        ]) {
            this._injections.overrideMethod(prototype, over, original => function (source, ...args) {
                const workspace = this.metaWorkspace ?? extension._wm.get_active_workspace();
                if (source.metaWindow && !extension._canMove(source.metaWindow, workspace))
                    return DND.DragMotionResult.NO_DROP;
                return original.call(this, source, ...args);
            });
            this._injections.overrideMethod(prototype, drop, original => function (source, ...args) {
                const workspace = this.metaWorkspace ?? extension._wm.get_active_workspace();
                if (source.metaWindow && !extension._canMove(source.metaWindow, workspace, true))
                    return false;
                return original.call(this, source, ...args);
            });
        }
    }

    _owner(identity) {
        const description = describeWorkspace([identity], this._inventory);
        return description?.kind === 'vm' ? description : null;
    }

    _destination(owner, current = null, window = null) {
        const belongs = workspace => this._owners.get(workspace)?.key === owner.key;
        const usable = workspace => belongs(workspace) && this._workspaceWindows(workspace)
            .filter(other => other !== window).every(other => {
                const identity = this._identities.get(other);
                return identity?.kind === 'local' || this._owner(identity)?.key === owner.key;
            });
        const pending = [...this._launches.values()].reverse().find(launch => launch.owner.key === owner.key);
        if (pending && usable(pending.workspace))
            return pending.workspace;
        if (current && usable(current))
            return current;
        const group = this._groups.find(group => group.key === owner.key);
        if (group?.lastUsed && usable(group.lastUsed))
            return group.lastUsed;
        for (const workspace of this._owners.keys()) {
            if (usable(workspace))
                return workspace;
        }
        const blank = Array.from({length: this._wm.n_workspaces}, (_, index) => this._wm.get_workspace_by_index(index))
            .find(workspace => !this._owners.has(workspace) && !this._workspaceWindows(workspace).some(other => other !== window));
        const workspace = blank ?? this._wm.append_new_workspace(false, global.get_current_time());
        this._owners.set(workspace, owner);
        return workspace;
    }

    _placeNewWindow(window, identity) {
        if (identity.kind === 'unknown')
            return;
        const owner = this._owner(identity);
        const parent = window.get_transient_for();
        let destination;
        if (owner) {
            const parentWorkspace = parent?.get_workspace();
            destination = parentWorkspace && this._owners.get(parentWorkspace)?.key === owner.key
                ? parentWorkspace : this._destination(owner, window.get_workspace(), window);
        }
        this._pendingPlacement.delete(window);
        if (destination && destination !== window.get_workspace()) {
            const focused = global.display.focus_window === window;
            this._moveInternally(window, destination);
            if (focused && !Main.sessionMode.isLocked && !Main.sessionMode.isGreeter)
                destination.activate(global.get_current_time());
        }
        if (destination)
            this._lastWorkspace.set(window, destination);
        if (destination) {
            for (const [token, launch] of this._launches) {
                if (launch.workspace === destination && launch.owner.key === owner.key)
                    this._releaseLaunch(token);
            }
        }
        this._releaseActor(window);
        this._enforceWorkspace(window);
        this._presentReview(window);
    }

    _prepareWindow(window) {
        if (!this._active || !this._windows.has(window))
            return;
        // The existing trusted reader has its own two-second process deadline.
        // For this POC, a synchronous first lookup runs before Shell can paint.
        const identity = this._resolveSync(window, new Set());
        this._identities.set(window, validateIdentity(identity));
        if (identity.kind !== 'unknown')
            this._placeNewWindow(window, identity);
    }

    _resolveSync(window, seen) {
        if (!window || seen.has(window))
            return UNKNOWN;
        seen.add(window);
        const cached = this._cache.get(window);
        if (cached)
            return cached;
        if (window.get_client_type() === Meta.WindowClientType.WAYLAND)
            return LOCAL;
        const xid = /^(0x[0-9a-fA-F]+)\s/.exec(window.get_description())?.[1];
        if (!xid)
            return UNKNOWN;
        try {
            const process = Gio.Subprocess.new([READER, xid],
                Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_SILENCE);
            const [, stdout] = process.communicate_utf8(null, null);
            const identity = process.get_successful() ? JSON.parse(stdout) : UNKNOWN;
            if (identity.kind === 'absent')
                return this._resolveSync(window.get_transient_for(), seen);
            this._cache.remember(window, identity);
            return validateIdentity(identity);
        } catch (_error) {
            return UNKNOWN;
        }
    }

    _holdActor(actor) {
        if (!this._heldActors.has(actor.meta_window))
            this._heldActors.set(actor.meta_window, {actor, opacity: actor.opacity, since: GLib.get_monotonic_time()});
        actor.opacity = 0;
        this._queue();
    }

    _releaseActor(window) {
        const held = this._heldActors.get(window);
        if (held) {
            held.actor.opacity = held.opacity;
            this._heldActors.delete(window);
        }
    }

    _installLaunchService() {
        this._dbus = Gio.DBusExportedObject.wrapJSObject(WORKSPACE_XML, {
            Prepare: uuid => this._prepareLaunch(uuid),
            Cancel: token => { this._releaseLaunch(token); this._queue(); },
            State: () => JSON.stringify([...this._owners].map(([workspace, owner]) => ({
                workspace: workspace.index() + 1, uuid: owner.key, name: owner.name,
                pending: [...this._launches.values()].filter(launch => launch.workspace === workspace).length,
            }))),
        });
        this._dbus.export(Gio.DBus.session, WORKSPACE_PATH);
        this._busName = Gio.bus_own_name_on_connection(Gio.DBus.session, WORKSPACE_BUS,
            Gio.BusNameOwnerFlags.NONE, null, null);
    }

    _prepareLaunch(uuid) {
        if (!this._active || Main.sessionMode.isLocked || Main.sessionMode.isGreeter)
            throw new Error('The desktop is not ready to launch an application');
        const vm = this._inventory.get(uuid);
        if (!vm || vm.name === 'sys-gui')
            throw new Error('The VM is missing from the desktop inventory');
        const owner = {key: uuid, name: vm.name, color: vm.color ?? '#888888', kind: 'vm', names: [vm.name]};
        const workspace = this._destination(owner, this._wm.get_active_workspace());
        const token = GLib.uuid_string_random();
        const timeout = GLib.timeout_add(GLib.PRIORITY_DEFAULT, 90000, () => {
            const launch = this._launches.get(token);
            if (launch)
                launch.timeout = 0;
            this._releaseLaunch(token);
            this._queue();
            return GLib.SOURCE_REMOVE;
        });
        this._launches.set(token, {owner, workspace, timeout});
        this._sync();
        workspace.activate(global.get_current_time());
        Main.overview.hide();
        return token;
    }

    _releaseLaunch(token) {
        const launch = this._launches.get(token);
        if (!launch)
            return;
        if (launch.timeout)
            GLib.Source.remove(launch.timeout);
        this._launches.delete(token);
    }

    _queue() {
        if (!this._active)
            return;
        this._dirty = true;
        if (this._source || this._scanning)
            return;
        this._source = GLib.timeout_add(GLib.PRIORITY_DEFAULT, 400, () => {
            this._source = 0;
            this._scan();
            return GLib.SOURCE_REMOVE;
        });
    }

    async _scan() {
        this._scanning = true;
        this._dirty = false;
        const cache = this._cache;
        const cancellable = this._cancellable;
        try {
            // A single bounded identity reader at a time, with the same trusted
            // provenance checks as the existing focused-VM panel.
            for (const window of [...this._windows.keys()]) {
                if (!this._active || cancellable.is_cancelled())
                    break;
                const identity = await this._resolve(window, cache, cancellable, new Set());
                if (!this._active || cancellable.is_cancelled() || !this._windows.has(window))
                    continue;
                this._identities.set(window, validateIdentity(identity));
                if (this._pendingPlacement.has(window) && identity.kind !== 'unknown')
                    this._placeNewWindow(window, identity);
            }
            if (this._active) {
                for (const window of this._windows.keys())
                    this._enforceWorkspace(window);
                for (const [window, held] of this._heldActors) {
                    if (!this._windows.has(window)) {
                        this._heldActors.delete(window);
                    } else if (GLib.get_monotonic_time() - held.since > 5000000) {
                        // Failed identity is never guessed into another VM's workspace.
                        const workspace = this._wm.append_new_workspace(false, global.get_current_time());
                        this._moveInternally(window, workspace);
                        this._pendingPlacement.delete(window);
                        this._releaseActor(window);
                        Main.notify('Airlock', 'A window with unverified VM origin was placed in an isolated, neutral workspace.');
                    }
                }
                this._sync();
                if (this._heldActors.size)
                    this._queue();
            }
        } catch (error) {
            if (this._active)
                console.error(`Airlock workspace identity: ${error.message}`);
        } finally {
            if (this._cancellable === cancellable) {
                this._scanning = false;
                if (this._active && this._dirty)
                    this._queue();
            }
        }
    }

    async _resolve(window, cache, cancellable, seen) {
        if (seen.has(window) || cancellable.is_cancelled())
            return UNKNOWN;
        seen.add(window);
        const cached = cache.get(window);
        if (cached)
            return cached;
        if (window.get_client_type() === Meta.WindowClientType.WAYLAND)
            return LOCAL;
        const xid = /^(0x[0-9a-fA-F]+)\s/.exec(window.get_description())?.[1];
        if (!xid)
            return UNKNOWN;
        cache.watch(window);
        const identity = await this._read(xid, cancellable);
        if (identity.kind === 'absent') {
            const parent = window.get_transient_for();
            return parent ? this._resolve(parent, cache, cancellable, seen) : UNKNOWN;
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

    disable() {
        this._active = false;
        this._dbus?.unexport();
        if (this._busName)
            Gio.bus_unown_name(this._busName);
        for (const token of this._launches.keys())
            this._releaseLaunch(token);
        for (const window of this._heldActors.keys())
            this._releaseActor(window);
        this._owners.clear();
        ++this._inventoryRevision;
        if (this._source)
            GLib.Source.remove(this._source);
        this._source = 0;
        this._cancellable?.cancel();
        this._process?.force_exit();
        this._monitor?.cancel();
        for (const [object, id] of this._signals)
            object.disconnect(id);
        for (const [window, signals] of this._windows) {
            for (const id of signals)
                window.disconnect(id);
        }
        this._windows.clear();
        this._pendingReviewFocus.clear();
        this._lastWorkspace.clear();
        this._internalMoves.clear();
        this._cache.clear();
        this._injections?.clear();
        for (const [box, record] of this._thumbnailBoxes) {
            box.disconnect(record.destroySignal);
            box._indicator.style = record.style;
            box.remove_style_class_name('airlock-workspace-thumbnails');
        }
        this._thumbnailBoxes.clear();
        for (const record of this._overviewActors.values()) {
            record.actor.disconnect(record.hoverSignal);
            record.actor.disconnect(record.destroySignal);
            record.actor.reactive = record.reactive;
            record.actor.track_hover = record.trackHover;
            if (!record.small) {
                record.geometrySource?.disconnectObject(record.border);
                record.actor._background.style = record.backgroundStyle;
            }
            record.border.destroy();
        }
        this._overviewActors.clear();
        this._hideTooltip();
        Main.layoutManager.removeChrome(this._tooltip);
        this._tooltip.destroy();
        this._indicator.destroy();
        // Restore preferences only when they still match our last settings.
        // Keep occupied workspace objects until GNOME handles its normal cleanup.
        if (this._preferences.get_int('num-workspaces') === this._ownedCount)
            this._preferences.set_int('num-workspaces', this._originalCount);
        if (!this._mutter.get_boolean('dynamic-workspaces'))
            this._mutter.set_boolean('dynamic-workspaces', this._originalDynamic);
    }
}
