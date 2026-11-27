// The only hand-written JS on the dashboard: dialogs, clipboard, iframe
// refresh, and the session terminal client.
document.addEventListener('click', (e) => {
    const t = e.target.closest('[data-open-dialog],[data-close-dialog],[data-copy],[data-refresh]');
    if (t?.dataset.openDialog) document.getElementById(t.dataset.openDialog).showModal();
    if (t?.hasAttribute('data-close-dialog')) t.closest('dialog').close();
    if (t?.dataset.refresh) { const f = document.getElementById(t.dataset.refresh); f.src = f.src; }
    if (t?.dataset.copy) {
        navigator.clipboard.writeText(document.getElementById(t.dataset.copy).value);
        t.textContent = 'copied';
        setTimeout(() => t.textContent = 'copy', 1500);
    }
    if (e.target.tagName === 'DIALOG') e.target.close(); // backdrop click
});
document.addEventListener('focusin', (e) => e.target.matches('[data-select-on-focus]') && e.target.select());
document.addEventListener('input', (e) => {
    const i = e.target;
    // Force online: the button is enabled once the session name is typed.
    if (i.dataset.confirmName !== undefined) {
        i.form.querySelector('[data-confirm-submit]').disabled = i.value !== i.dataset.confirmName;
        return;
    }
    if (i.id !== 'session-name') return;
    const pos = i.selectionStart, v = i.value.replace(/ /g, '-').toLowerCase();
    if (v !== i.value) { i.value = v; i.setSelectionRange(pos, pos); }
});
// Open a dialog when htmx swaps content into it (session info, and the
// force online dialog, whose HX-Retarget leaves the target a selector).
document.addEventListener('htmx:after:swap', (e) => {
    let t = e.detail?.ctx?.target;
    if (typeof t === 'string') t = document.querySelector(t);
    const d = t?.closest?.('dialog');
    if (d && !d.open) d.showModal();
});
document.addEventListener('close-dialog', () => document.querySelectorAll('dialog[open]').forEach((d) => d.close()));
document.addEventListener('session-created', (e) => {
    if (e.detail.openTab && e.detail.url) window.open(e.detail.url, '_blank');
    document.getElementById('new-session-modal').close();
});
document.getElementById('new-session-modal')?.addEventListener('close', (e) => {
    e.target.querySelector('form').reset();
    document.getElementById('create-error').textContent = '';
    htmx.ajax('GET', '/sessions/validate', {target: '#session-name-hint', swap: 'outerHTML'});
});

// Session terminal: xterm.js speaking ttyd's protocol over the dashboard's
// WebSocket proxy, which adds ttyd's credential. Client messages start with
// '0' (input) or '1' (resize); server messages with '0' (output), '1'
// (title), or '2' (preferences), and only output is used.
const termEl = document.querySelector('[data-terminal]');
if (termEl) {
    const enc = new TextEncoder();
    const term = new Terminal({
        fontSize: 13,
        scrollback: 10000,
        // Links open in a new tab, but never on the dashboard's own host:
        // that is where its cookie is sent.
        linkHandler: {
            allowNonHttpProtocols: false,
            activate: (_e, text) => {
                let u;
                try { u = new URL(text); } catch { return; }
                if (!/^https?:$/.test(u.protocol) || u.hostname === location.hostname) return;
                window.open(u.href, '_blank', 'noopener,noreferrer');
            },
        },
    });
    const fit = new FitAddon.FitAddon();
    term.loadAddon(fit);
    term.open(termEl);
    fit.fit();
    const url = new URL(termEl.dataset.terminal, location.href);
    url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(url, ['tty']);
    ws.binaryType = 'arraybuffer';
    const send = (s) => ws.readyState === WebSocket.OPEN && ws.send(enc.encode(s));
    ws.onopen = () => {
        ws.send(enc.encode(JSON.stringify({columns: term.cols, rows: term.rows})));
        // Only in its own tab: a framed terminal's iframe is sandboxed,
        // which refuses focus without a click, so it can't take focus
        // from the dashboard.
        if (window === window.top) term.focus();
    };
    ws.onmessage = (e) => {
        const d = new Uint8Array(e.data);
        if (d[0] === 0x30) term.write(d.subarray(1));
    };
    ws.onclose = () => term.write('\r\n\x1b[2m[disconnected: click refresh to reconnect]\x1b[0m\r\n');
    term.onData((d) => send('0' + d));
    term.onBinary((d) => {
        if (ws.readyState !== WebSocket.OPEN) return;
        const b = new Uint8Array(d.length + 1);
        b[0] = 0x30;
        for (let i = 0; i < d.length; i++) b[i + 1] = d.charCodeAt(i) & 0xff;
        ws.send(b);
    });
    term.onResize(({cols, rows}) => send('1' + JSON.stringify({columns: cols, rows})));
    new ResizeObserver(() => fit.fit()).observe(termEl);
}
