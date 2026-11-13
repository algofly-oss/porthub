// File objects and publisher keys stay in this window. Neither is persisted.
const actors = new Map();
const listeners = new Set();
const empty = [];
let snapshot = empty;
let installed = false;
const emit = () => {
  snapshot = [...actors.values()].map(({ file, controller, key, ...publicState }) => publicState);
  for (const listener of listeners) listener();
};
export const subscribe = listener => { listeners.add(listener); return () => listeners.delete(listener); };
export const getSnapshot = () => snapshot;
export const getServerSnapshot = () => empty;
const requestId = () => Array.from(crypto.getRandomValues(new Uint8Array(12)), byte => byte.toString(16).padStart(2, '0')).join('');
const active = actor => actors.get(actor.localId) === actor && !actor.controller.signal.aborted;
function update(actor, values) { if (actors.get(actor.localId) !== actor) return; Object.assign(actor, values); emit(); }
async function pause(signal) {
  if (signal.aborted) return;
  await new Promise(resolve => {
    const done = () => { clearTimeout(timer); signal.removeEventListener('abort', done); resolve(); };
    const timer = setTimeout(done, 1500); signal.addEventListener('abort', done, { once: true });
  });
}
function closeRemote(actor) {
  if (!actor.id || !actor.key) return;
  void fetch(`${actor.base}/api/transfers/${actor.id}`, { method: 'DELETE', credentials: 'omit', keepalive: true, headers: { 'X-Transfer-Key': actor.key } }).catch(() => {});
}
export function stopShare(localId) {
  const actor = actors.get(localId); if (!actor) return;
  actors.delete(localId); actor.controller.abort(); closeRemote(actor); actor.file = null; emit();
}
export function retryShare(localId) {
  const actor = actors.get(localId); if (!actor?.file) return;
  const file = actor.file; stopShare(localId); return shareFile(file);
}
async function worker(actor) {
  const signal = actor.controller.signal;
  const headers = { 'X-Transfer-Key': actor.key };
  while (active(actor)) {
    try {
      const response = await fetch(`${actor.base}/api/transfers/${actor.id}/next`, { headers, signal, credentials: 'omit', cache: 'no-store' });
      if ([403, 404, 410].includes(response.status)) {
        update(actor, { status: 'error', error: 'This link has expired. Share the file again for a new link.' }); actor.controller.abort(); return;
      }
      if (!response.ok) throw new Error('Reconnect to keep sharing.');
      if (actor.status !== 'sharing') update(actor, { status: 'sharing', error: '' });
      if (response.status === 204) continue;
      const [job, offsetText, lengthText] = (await response.text()).trim().split(/\s+/);
      const offset = Number(offsetText), length = Number(lengthText);
      if (!/^[A-Za-z0-9_-]{1,64}$/.test(job) || !Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length <= 0 || length > 4 * 1024 * 1024 || offset + length > actor.size) throw new Error('Invalid download request.');
      const uploaded = await fetch(`${actor.base}/api/transfers/${actor.id}/chunks/${job}`, { method: 'PUT', headers, body: actor.file.slice(offset, offset + length), signal, credentials: 'omit' });
      // A canceled receiver can invalidate its chunk without stopping the share.
      if (uploaded.status === 404) continue;
      if (!uploaded.ok) throw new Error('Reconnect to keep sharing.');
      update(actor, { sent: actor.sent + length, status: 'sharing', error: '' });
    } catch (error) {
      if (!active(actor)) return;
      if (error.name === 'NotReadableError') { update(actor, { status: 'error', error: 'The file can no longer be read. Choose it again.' }); actor.controller.abort(); return; }
      update(actor, { status: 'reconnecting', error: 'Reconnecting… Keep this tab open.' }); await pause(signal);
    }
  }
}
export async function shareFile(file) {
  if (actors.size >= 8) throw new Error('Stop a share before adding another file.');
  if (!installed) {
    installed = true;
    window.addEventListener('pagehide', () => { for (const id of [...actors.keys()]) stopShare(id); });
  }
  const actor = { localId: requestId(), id: '', key: '', file, name: file.name, size: file.size, sent: 0, url: '', status: 'starting', error: '', base: window.location.origin, controller: new AbortController() };
  actors.set(actor.localId, actor); emit();
  try {
    const response = await fetch(`${actor.base}/api/transfers`, { method: 'POST', credentials: 'omit', signal: actor.controller.signal, headers: { 'X-Transfer-Name-Encoded': encodeURIComponent(file.name), 'X-Transfer-Size': String(file.size) } });
    if (!response.ok) throw new Error(response.status === 429 ? 'Sharing capacity is full. Try again shortly.' : 'Could not start sharing. Try again.');
    const [id, key] = (await response.text()).trim().split(/\s+/);
    if (!/^[A-Za-z0-9_-]{32}$/.test(id) || !/^[A-Za-z0-9_-]{32}$/.test(key)) throw new Error('Could not start sharing. Try again.');
    actor.id = id; actor.key = key;
    if (!active(actor)) { closeRemote(actor); return; }
    update(actor, { url: `${actor.base}/api/transfers/${id}`, status: 'sharing' });
    for (let i = 0; i < 4; i++) void worker(actor);
    return actor.url;
  } catch (error) {
    if (active(actor)) { update(actor, { status: 'error', error: error.message }); actor.controller.abort(); }
  }
}
