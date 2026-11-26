// The only hand-written JS on the dashboard: dialogs, clipboard, and iframe refresh.
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
    if (i.id !== 'session-name') return;
    const pos = i.selectionStart, v = i.value.replace(/ /g, '-').toLowerCase();
    if (v !== i.value) { i.value = v; i.setSelectionRange(pos, pos); }
});
// Open a dialog when htmx swaps content into it (session info).
document.addEventListener('htmx:after:swap', (e) => {
    const d = e.detail?.ctx?.target?.closest?.('dialog');
    if (d && !d.open) d.showModal();
});
document.addEventListener('session-created', (e) => {
    if (e.detail.openTab && e.detail.url) window.open(e.detail.url, '_blank');
    document.getElementById('new-session-modal').close();
});
document.getElementById('new-session-modal').addEventListener('close', (e) => {
    e.target.querySelector('form').reset();
    document.getElementById('create-error').textContent = '';
    htmx.ajax('GET', '/sessions/validate', {target: '#session-name-hint', swap: 'outerHTML'});
});
