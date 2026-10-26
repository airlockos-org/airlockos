// Only GNOME objects and transport scheduling are mocked; scenarios execute the real extension.
let monotonic = 0;
let nextTimer = 0;
const timers = new Map();
const reads = [];
const indicators = [];
const warnings = [];
console.warn = message => warnings.push(message);

class Actor {
    constructor(properties = {}) {
        Object.assign(this, {visible: true, children: [], text: ''}, properties);
        this.clutter_text = {set() {}};
    }
    add_child(child) { this.children.push(child); }
    show() { this.visible = true; }
    hide() { this.visible = false; }
    destroy() { this.destroyed = true; }
    add_style_class_name() {}
}

class Section extends Actor {
    constructor() { super(); this.items = []; }
    addMenuItem(item) { this.items.push(item); }
    removeAll() { this.items = []; }
    close() { this.closed = true; }
}

class Button extends Actor {
    constructor() { super(); this.menu = new Section(); }
}

class Item extends Actor {
    constructor(text, properties) { super(properties); this.label = new Actor({text}); }
}

class Spinner extends Actor {
    play() { this.playing = true; this.show(); }
    stop() { this.playing = false; this.hide(); }
}

globalThis.shellMocks = {
    Clutter: {ActorAlign: {CENTER: 0}, Orientation: {VERTICAL: 1}},
    Pango: {WrapMode: {WORD_CHAR: 1}},
    St: {BoxLayout: Actor, Icon: Actor, Label: Actor},
    Animation: {Spinner}, PanelMenu: {Button}, Extension: class {},
    PopupMenu: {PopupMenuItem: Item, PopupBaseMenuItem: Actor,
        PopupSeparatorMenuItem: Actor, PopupMenuSection: Section},
    Main: {panel: {addToStatusArea(_name, button) { indicators.push(button); }}},
    GLib: {
        PRIORITY_DEFAULT: 0, SOURCE_REMOVE: false,
        get_monotonic_time: () => monotonic,
        timeout_add_seconds(_priority, _seconds, callback) {
            const identifier = ++nextTimer;
            timers.set(identifier, callback);
            return identifier;
        },
        Source: {remove(identifier) { timers.delete(identifier); }},
    },
    Gio: {
        Cancellable: class { cancel() { this.cancelled = true; } },
        SubprocessFlags: {STDOUT_PIPE: 1, STDERR_PIPE: 2},
        Subprocess: {new() {
            const process = {
                successful: true,
                communicate_utf8_async(_input, cancellable, callback) {
                    reads.push({process, cancellable, callback});
                },
                communicate_utf8_finish(result) {
                    if (result.error)
                        throw new Error('Status transport failed');
                    return [true, JSON.stringify(result.snapshot), result.stderr ?? ''];
                },
                get_successful() { return this.successful; },
                get_if_exited() { return true; },
                get_exit_status() { return 1; },
            };
            return process;
        }},
    },
};

function reply(index, snapshot, error = false, stderr = '') {
    const {process, callback} = reads[index];
    process.successful = !stderr;
    callback(process, {snapshot, error, stderr});
}

function tick() {
    assert.equal(timers.size, 1, 'only one scheduled read or completion timer');
    const [identifier, callback] = timers.entries().next().value;
    timers.delete(identifier);
    monotonic += 5_000_000;
    callback();
}
