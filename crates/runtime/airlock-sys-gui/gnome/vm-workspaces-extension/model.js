// The inventory supplies presentation metadata, never reservations for empty VMs.
export const MAX_SLOTS = 36;

export function describeWorkspace(identities, inventory) {
    const applications = identities.filter(identity => identity?.kind !== 'local' && identity?.name !== 'sys-gui');
    if (!applications.length)
        return null;
    const names = [...new Set(applications.map(identity => identity?.kind === 'vm'
        ? identity.name : 'Unidentified'))].sort();
    if (names.length !== 1 || names[0] === 'Unidentified') {
        return {key: names.length > 1 ? 'mixed' : 'unknown',
            name: names.length > 1 ? 'Mixed VMs' : 'Unidentified',
            kind: names.length > 1 ? 'mixed' : 'unknown', color: '#888888', names};
    }
    const name = names[0];
    const entry = [...inventory].find(([, vm]) => vm.name === name);
    return {key: entry?.[0] ?? `vm:${name}`, name, kind: 'vm', names,
        color: entry?.[1].color ?? applications.find(identity => identity.color)?.color ?? '#888888'};
}

export function groupOccupiedWorkspaces(previous, workspaces, identities, inventory) {
    const groups = new Map();
    for (const workspace of workspaces) {
        const description = describeWorkspace(identities.get(workspace) ?? [], inventory);
        if (!description)
            continue;
        if (!groups.has(description.key))
            groups.set(description.key, {...description, slots: []});
        groups.get(description.key).slots.push(workspace);
    }
    const result = [];
    // Retain the order of surviving groups; a new group joins the end.
    for (const old of previous) {
        const group = groups.get(old.key);
        if (!group)
            continue;
        group.lastUsed = group.slots.includes(old.lastUsed) ? old.lastUsed : null;
        result.push(group);
        groups.delete(old.key);
    }
    return result.concat([...groups.values()]);
}

// Ownership is assigned once, rather than inferred again after a manual move.
export function groupOwnedWorkspaces(previous, workspaces, owners, identities, inventory) {
    const groups = new Map();
    for (const workspace of workspaces) {
        const owner = owners.get(workspace);
        const description = owner ?? describeWorkspace(identities.get(workspace) ?? [], inventory);
        if (!description)
            continue;
        if (!groups.has(description.key))
            groups.set(description.key, {...description, slots: []});
        groups.get(description.key).slots.push(workspace);
    }
    const result = [];
    for (const old of previous) {
        const group = groups.get(old.key);
        if (group) {
            group.lastUsed = group.slots.includes(old.lastUsed) ? old.lastUsed : null;
            result.push(group);
            groups.delete(old.key);
        }
    }
    return result.concat([...groups.values()]);
}
