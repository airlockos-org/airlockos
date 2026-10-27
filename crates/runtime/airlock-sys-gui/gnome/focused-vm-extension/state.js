// Independent of GJS so native tests can exercise focus races with an installed JS runtime.
export const UNKNOWN = {kind: 'unknown', name: 'Unknown VM', color: null};
export const LOCAL = {kind: 'local', name: 'sys-gui', color: null};

export function validateIdentity(value) {
    if (value?.kind === 'local' && value.name === 'sys-gui')
        return {...LOCAL};
    if (value?.kind === 'vm' && typeof value.name === 'string' &&
        value.name.length >= 1 && value.name.length <= 31 &&
        /^[A-Za-z]/.test(value.name) && !/[^A-Za-z0-9_-]/.test(value.name)) {
        return {kind: 'vm', name: value.name,
            color: typeof value.color === 'string' && value.color.length === 7 &&
                /^#[0-9a-f]{6}$/.test(value.color) ? value.color : null};
    }
    return {...UNKNOWN};
}

// Keys are live Meta.Window objects, never reusable XIDs or application names.
// Only direct, verified identities are retained. Transient-parent fallback and
// failed reads are resolved again so a changed parent cannot inherit stale data.
export class WindowIdentityCache {
    constructor() {
        this._entries = new Map();
        this._active = true;
    }

    watch(window) {
        if (!this._active || this._entries.has(window))
            return;
        const signal = window.connect('unmanaged', () => {
            window.disconnect(signal);
            this._entries.delete(window);
        });
        this._entries.set(window, {signal, identity: null});
    }

    get(window) {
        return this._entries.get(window)?.identity ?? null;
    }

    remember(window, value) {
        const entry = this._entries.get(window);
        const identity = validateIdentity(value);
        // A late lookup cannot resurrect a destroyed window or a cleared cache.
        if (this._active && entry && identity.kind !== 'unknown')
            entry.identity = identity;
    }

    clear() {
        this._active = false;
        for (const [window, {signal}] of this._entries)
            window.disconnect(signal);
        this._entries.clear();
    }
}

export class FocusState {
    constructor(render) {
        this._render = render;
        this._revision = 0;
        this._active = true;
    }

    begin(window, suppressed, identity = UNKNOWN) {
        const revision = ++this._revision;
        this._render(window && !suppressed ? validateIdentity(identity) : null);
        return revision;
    }

    complete(revision, value) {
        if (this._active && revision === this._revision)
            this._render(validateIdentity(value));
    }

    disable() {
        this._active = false;
        ++this._revision;
        this._render(null);
    }
}
