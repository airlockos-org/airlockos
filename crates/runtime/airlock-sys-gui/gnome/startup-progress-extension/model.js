// Validate the native observer's snapshot before it can hide pending work.
export function parseSnapshot(value) {
    const text = (item, limit) => typeof item === 'string' && item.length <= limit &&
        !/[\u0000-\u001f\u007f]/u.test(item);
    if (value?.schema !== 'airlock.startup-panel.v1' ||
        !text(value.boot_id, 255) || typeof value.complete !== 'boolean' ||
        typeof value.attention !== 'boolean' || !text(value.detail, 512) ||
        !Array.isArray(value.guests) || value.guests.length > 128)
        throw new Error('Invalid startup status');

    const names = new Set();
    const guests = value.guests.map(guest => {
        if (!text(guest.name, 63) || !/^[a-zA-Z][a-zA-Z0-9_.-]*$/u.test(guest.name) ||
            names.has(guest.name) || !text(guest.detail, 512) ||
            !['waiting', 'starting', 'loading', 'ready', 'failed'].includes(guest.phase))
            throw new Error('Invalid guest startup status');
        names.add(guest.name);
        return {name: guest.name, phase: guest.phase, detail: guest.detail};
    });
    if (value.complete && (value.attention || guests.some(guest => guest.phase !== 'ready')))
        throw new Error('Startup completed with unavailable guests');

    return {bootId: value.boot_id, complete: value.complete, attention: value.attention,
        detail: value.detail, guests};
}

// Elapsed time explains a long wait without presenting an invented percentage or estimate.
export function elapsedText(seconds) {
    seconds = Math.max(0, Math.floor(seconds));
    const minutes = Math.floor(seconds / 60);
    return minutes ? `${minutes}m ${seconds % 60}s elapsed` : `${seconds}s elapsed`;
}
