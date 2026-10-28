# PortHub patch to notify 8.2.1

This is the upstream 8.2.1 crate with its CC0 license retained. Two conditional
exports in `src/lib.rs` make the existing FSEvents backend available whenever
`macos_fsevent` is enabled, including when `macos_kqueue` is also enabled.
`RecommendedWatcher` keeps its upstream selection and behavior.

Arti enables `macos_kqueue` transitively. That feature otherwise hides FSEvents
and silently changes every application's recommended watcher to kqueue. Its
directory-write handling adds newly discovered children recursively, including
for a non-recursive parent watch. Populated Tor caches and upgrade backups can
then exhaust the agent's descriptor limit.

PortHub explicitly selects FSEvents for general macOS application watches.
Preference notifications use a separate, bounded directory-vnode watcher for
prompt atomic replacements. Linux and Windows backend implementations are
unchanged. Registry-generated metadata and the upstream crate's standalone
lockfile are omitted from this vendored copy.
