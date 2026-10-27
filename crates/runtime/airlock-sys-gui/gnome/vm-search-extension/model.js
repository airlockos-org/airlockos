// Pure presentation model. Identity comes from the Qubes inventory, never
// from an application's display name or icon.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const VM_NAME = /^[A-Za-z][A-Za-z0-9_.-]{0,30}$/;
const COLOR = /^(?:#|0x)([0-9a-fA-F]{6})$/;
const LAUNCHER = /^org\.qubes-os\.(vm|dispvm)\.([0-9a-f-]{36})\..+\.desktop$/;

export function parseInventory(text) {
    const data = JSON.parse(text);
    if (!data || typeof data !== 'object' || Array.isArray(data))
        throw new Error('Invalid VM inventory');
    const inventory = new Map();
    for (const [identity, item] of Object.entries(data)) {
        if (!UUID.test(identity) || !item || item.uuid !== identity ||
            typeof item.name !== 'string' || !VM_NAME.test(item.name) ||
            typeof item.running !== 'boolean')
            continue;
        const color = typeof item.label === 'string' ? COLOR.exec(item.label) : null;
        inventory.set(identity, {
            name: item.name,
            color: color ? `#${color[1].toLowerCase()}` : null,
            running: item.running,
        });
    }
    return inventory;
}

export function describeResult(id, name, inventory) {
    const match = LAUNCHER.exec(id);
    const vm = match ? inventory.get(match[2]) : null;
    if (vm) {
        const disposable = match[1] === 'dispvm';
        const prefix = `${vm.name}: `;
        return {
            key: `${match[1]}:${match[2]}`,
            heading: disposable ? `${vm.name} (Disposable)` : vm.name,
            color: vm.color,
            stopped: !vm.running,
            title: name.startsWith(prefix) ? name.slice(prefix.length) : name,
        };
    }
    return {
        key: match ? 'unknown' : id.endsWith('.desktop') ? 'local' : 'system',
        heading: match ? 'Other applications' : id.endsWith('.desktop') ? 'sys-gui' : 'System',
        color: null,
        stopped: false,
        title: name,
    };
}

export function groupResults(ids, inventory) {
    // Map insertion order puts the group containing the best GNOME match
    // first, and preserves GNOME's ordering within each group. No global
    // tile limit is applied before other VMs have had a chance to appear.
    const groups = new Map();
    for (const id of ids) {
        const description = describeResult(id, '', inventory);
        if (!groups.has(description.key))
            groups.set(description.key, {...description, ids: []});
        groups.get(description.key).ids.push(id);
    }
    return [...groups.values()];
}
