// Optional portal theme; standalone PairDrop keeps its native theme controls.
const porthubTheme = new URLSearchParams(location.search).get('theme');
if (['dark','light'].includes(porthubTheme)) localStorage.setItem('theme',porthubTheme);
window.addEventListener('message', event => {
    if (event.origin !== location.origin || event.source !== window.parent || event.data?.type !== 'porthub-theme') return;
    const theme = event.data.theme;
    if (!['dark','light'].includes(theme) || typeof pairDrop === 'undefined') return;
    if (theme === 'dark') pairDrop.themeUI.setModeToDark(); else pairDrop.themeUI.setModeToLight();
});
// User-chosen peer names must remain text in upstream HTML templates.
window.porthubEscapeText = value => String(value ?? '').replace(/[&<>"']/g, character => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
