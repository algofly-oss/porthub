//! Integration test entry point.
//!
//! This file serves as the entry point for integration tests.
//! The actual tests are organized in the `integration/` directory.
//!
//! # Running Tests
//!
//! Integration tests require root privileges. Build as yourself and run
//! only the test binary under sudo, with the CI lane's features:
//!
//! ```bash
//! export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -E'
//! F=lab,sockdiag,namespace_watcher
//!
//! # Run all integration tests
//! cargo test -p nlink --test integration --features $F -- --test-threads=1
//!
//! # Run one module, or one test
//! cargo test -p nlink --test integration --features $F -- --test-threads=1 events::
//! cargo test -p nlink --test integration --features $F -- test_create_veth_pair
//! ```
//!
//! Shared helpers (traffic, counters, topologies, convergence checks,
//! strict event waits) are in `common/`; see `integration/harness.rs`.
//!
//! # Test Organization
//!
//! - `link.rs` - Link creation, modification, and deletion
//! - `address.rs` - IP address management
//! - `route.rs` - Route management
//! - `tc.rs` - Traffic control (qdisc, class, filter)
//! - `events.rs` - Event monitoring

#[macro_use]
#[path = "common/mod.rs"]
mod common;

#[path = "integration/link.rs"]
mod link;

#[path = "integration/address.rs"]
mod address;

#[path = "integration/route.rs"]
mod route;

#[path = "integration/tc.rs"]
mod tc;

#[path = "integration/events.rs"]
mod events;

#[path = "integration/config.rs"]
mod config;

// Plan 186 — VLAN parent ifindex race repro + topo-sort
// regression coverage. Lives in its own module so the focused
// scenarios stay out of the broader `config` integration
// surface.
#[path = "integration/network_config_apply.rs"]
mod network_config_apply;

#[path = "integration/config_undo.rs"]
mod config_undo;

#[path = "integration/ratelimit.rs"]
mod ratelimit;

#[path = "integration/impair.rs"]
mod impair;

#[path = "integration/diagnostics.rs"]
mod diagnostics;

#[path = "integration/timeout.rs"]
mod timeout;

#[path = "integration/sysctl.rs"]
mod sysctl;

#[path = "integration/namespace_spawn.rs"]
mod namespace_spawn;

#[path = "integration/namespace_path.rs"]
mod namespace_path;

// The owned namespace handle (#520).
#[path = "integration/netns.rs"]
mod netns;

// Feature-gated: the privileged integration workflow builds with
// `lab,sockdiag,namespace_watcher` so the inotify round-trip (#183)
// runs there.
#[cfg(feature = "namespace_watcher")]
#[path = "integration/namespace_watcher.rs"]
mod namespace_watcher;

#[path = "integration/conntrack.rs"]
mod conntrack;

// Feature-gated: only compiles when `sockdiag` is enabled. The
// privileged integration workflow builds with `lab,sockdiag` so the
// on-kernel bytecode validation runs there.
#[cfg(feature = "sockdiag")]
#[path = "integration/sockdiag_bytecode.rs"]
mod sockdiag_bytecode;

// Unprivileged by design — sock_diag dumps your own sockets without any
// capability, so these run for the non-root maintainer too.
#[cfg(feature = "sockdiag")]
#[path = "integration/sockdiag_correctness.rs"]
mod sockdiag_correctness;

#[path = "integration/neigh.rs"]
mod neigh;

#[path = "integration/fdb.rs"]
mod fdb;

#[path = "integration/rule.rs"]
mod rule;

#[path = "integration/blocking.rs"]
mod blocking;

// Plan 166 backfill — root-gated tests for the headline 0.16 features.
// Each module gates on `require_root!()` so this all early-returns
// when run as a regular user.

#[path = "integration/ergonomics.rs"]
mod ergonomics;

#[path = "integration/streaming.rs"]
mod streaming;

#[path = "integration/flowtable.rs"]
mod flowtable;

#[path = "integration/nftables_diag.rs"]
mod nftables_diag;

#[path = "integration/nftables_reconcile.rs"]
mod nftables_reconcile;

#[path = "integration/syscall_batch.rs"]
mod syscall_batch;

#[path = "integration/pool.rs"]
mod pool;

// Plan 194 — concurrent stress + seq-routing regression.
// Spawns 16 concurrent dumps on a shared Arc<Connection>
// and 16 concurrent LabNamespace::new calls. Both root-gated.
#[path = "integration/concurrent_stress.rs"]
mod concurrent_stress;

// 0.19 cycle backfill — Plan 188/196/199/200/202 round-trips
// surfaced by the post-cycle audit as kernel-touching surfaces
// with only unit-test coverage. All root-gated; WG/nft tests
// also gated by require_module!().
#[path = "integration/cycle_0_19_backfill.rs"]
mod cycle_0_19_backfill;

// Plan 221 — 0.19.1 XFRM hotfix regression tests. Root-gated +
// `xfrm_user` module-gated. Lock the corrected constant + dispatch
// values so a future commit can't re-introduce the bug class.
#[path = "integration/xfrm_hotfix.rs"]
mod xfrm_hotfix;

// Plan 197 — OVPN GENL family integration tests. Root-gated +
// `ovpn` module-gated (kernel 6.16+). Exercises peer + key ops
// + the declarative OvpnConfig diff + apply cycle.
#[path = "integration/ovpn.rs"]
mod ovpn;

// #190, #195, #199 — nftables safety. A foreign table must survive an
// apply that doesn't declare it; rules must install in declaration
// order; a mid-batch kernel rejection must surface as that error
// rather than an opaque 30s timeout.
#[path = "integration/nftables_safety.rs"]
mod nftables_safety;

// nftables write statements: `meta mark set`, `tcp option maxseg size set`
// (exthdr) and the set size. Pins that the kernel accepts the bytes the
// unit tests pin, and echoes back the same expressions.
#[path = "integration/nftables_statements.rs"]
mod nftables_statements;

// #708: a rule read back as `nft list` prints it, with nft as the oracle,
// for what nft installs and for what nlink builds.
#[path = "integration/nftables_lift.rs"]
mod nftables_lift;

// #708 (e): every chain type and hook in every family, through nft and
// through `BaseChain`; the kernel decides which exist.
#[path = "integration/nftables_chain_kinds.rs"]
mod nftables_chain_kinds;

// #708 (c): a rule built as a `RuleSpec` is the rule nft writes for its
// text, and rules declared as data converge.
#[path = "integration/nftables_spec.rs"]
mod nftables_spec;

// #708 (b): what the kernel holds reads back as the typed diff's values,
// the same as what a config says it holds.
#[path = "integration/nftables_readback.rs"]
mod nftables_readback;

// #708 (b): what the diff cannot do is one `blocked` list, refused before
// the apply writes anything: a recreate a foreign rule's binding blocks.
#[path = "integration/nftables_blocked.rs"]
mod nftables_blocked;

// Every rule shape nlink writes must reconcile to an empty diff: the kernel
// echoes some attributes whether or not they were sent, and drops others.
#[path = "integration/nftables_echo.rs"]
mod nftables_echo;

// Declarative rule identity and order: declared order is enforced with
// minimal moves, unchanged rules (and their counters) are left alone.
#[path = "integration/nftables_rules.rs"]
mod nftables_rules;

// Set lookups by packet field (IPv6, ports, `!= @set`), the raw escape
// hatch, and set-element / generation events — on real traffic.
#[path = "integration/nftables_lookups.rs"]
mod nftables_lookups;

// Interval sets (ranges, prefixes) on traffic: a range matches its ends and
// nothing past them; declared ranges converge and change one at a time.
#[path = "integration/nftables_intervals.rs"]
mod nftables_intervals;

// `reject` on traffic: refused, not left to time out, in every family (#480).
#[path = "integration/nftables_reject.rs"]
mod nftables_reject;

// Sets of concatenated keys (ipset hash:ip,port / hash:net,port) on traffic.
#[path = "integration/nftables_concat.rs"]
mod nftables_concat;

// Set timeouts and dynset (add/update/delete @set from a rule) on traffic;
// declared dynamic sets keep what the packet path put in them.
#[path = "integration/nftables_timeouts.rs"]
mod nftables_timeouts;

// Maps and verdict maps on traffic; declared maps converge and replace an
// element whose data changed.
#[path = "integration/nftables_maps.rs"]
mod nftables_maps;

// Named counters, quotas and limits, object maps; declared objects keep
// their live state across applies.
#[path = "integration/nftables_objects.rs"]
mod nftables_objects;

// #191-#194, #218 — psched tick conversion. The unit tests pin the
// bytes nlink emits; these pin that the *kernel* accepts them and
// reads back what we wrote. Needed because the pre-fix writer and
// reader were wrong in the same direction and agreed with each other.
#[path = "integration/psched_ticks.rs"]
mod psched_ticks;

// Plan 234 (0.21) — Dispatcher foundation: ENOBUFS routing to
// ResyncMarker::ResyncStart, per-family wiring smoke checks,
// concurrent-request coexistence with dispatcher subscribers.
#[path = "integration/dispatcher.rs"]
mod dispatcher;

// #253 — the rtnetlink + uevent netdev lifecycle join. Root-gated +
// `veth` module-gated. The unit tests pin the join's logic with
// hand-fed streams; this pins the kernel facts underneath it — that a
// net uevent inside a namespace reaches a socket opened in that
// namespace, and that its IFINDEX= agrees with rtnetlink's.
#[path = "integration/netdev_lifecycle.rs"]
mod netdev_lifecycle;

// #251 — uevent socket hardening. Unprivileged by design: attaching a
// classic-BPF socket filter and reading uevents both need no
// capability, and it is the kernel's BPF verifier — not the privilege
// — that these check.
#[path = "integration/uevent_filter.rs"]
mod uevent_filter;

// #292 — extended-ack parsing, end to end. The unit tests synthesise the
// capped payload; only the kernel sends the shape that was actually
// arriving.
#[path = "integration/ext_ack.rs"]
mod ext_ack;

// #275 — MPTCP endpoint wiring. `dev(name)` was stored and never
// resolved, so endpoints had no interface binding; and the port's byte
// order is only checkable against an independent reader, because nlink
// writes and reads it symmetrically.
#[path = "integration/mptcp_pm.rs"]
mod mptcp_pm;

// #275 — declared values that the writers never read. Each test asserts
// the *value* landed, not that the call returned Ok; asserting Ok is
// what let these ship.
#[path = "integration/declared_input.rs"]
mod declared_input;
// #258/#268/#269/#270 — the TC shaping recipes. The HTB `default` and
// the class it names must agree (three bugs shipped because nothing
// checked), reconcile must notice an edited match criterion, and
// declaring a clsact must not delete the root qdisc.
#[path = "integration/tc_shaping.rs"]
mod tc_shaping;
// #515 — qdisc options print in tc(8) syntax, and the text reinstalls the
// qdisc through tc, `parse_params` and `NetemConfig::from`.
#[path = "integration/tc_display.rs"]
mod tc_display;
// #267 — NLMSG_DONE's result code. Unprivileged: sock_diag dumps your
// own sockets without any capability, and a protocol with no diag
// handler answers DONE-with-ENOENT, which used to read as an empty list.
#[cfg(feature = "sockdiag")]
#[path = "integration/dump_termination.rs"]
mod dump_termination;

// #276, #280 — public API reachability. The integration target is a
// separate crate, so it sees what a downstream user sees.
#[path = "integration/api_surface.rs"]
mod api_surface;

// Every shape the declarative layers can declare must converge: apply,
// diff empty, apply again with no changes, diff empty again. Each file
// covers one layer; the cases are tables so a run lists every red shape.
#[path = "integration/network_config_echo.rs"]
mod network_config_echo;

// Every declared field changed A→B in one apply, and the boundary values
// of the inputs that take numbers or names (#534, Wave 7).
#[path = "integration/transitions.rs"]
mod transitions;

#[path = "integration/wireguard_echo.rs"]
mod wireguard_echo;

#[path = "integration/recipes_echo.rs"]
mod recipes_echo;

// Declared TC trees: classes, leaves, filters and the IFB redirect (#514).
#[path = "integration/tc_tree.rs"]
mod tc_tree;

// `Stack::plan_in` → `StackPlan::apply`: one diff of every layer (#519).
#[path = "integration/stack_plan.rs"]
mod stack_plan;

// The netdev GENL family: features, queues, NAPI, queue statistics (#166).
#[path = "integration/genl_netdev.rs"]
mod genl_netdev;

// Record a connection's traffic in a namespace, replay it without one (#168).
#[cfg(feature = "replay")]
#[path = "integration/replay.rs"]
mod replay;

// The helpers in `common/` checked against themselves, including where
// each must fail: a helper that cannot fail turns every test built on it
// into a pass.
#[path = "integration/harness.rs"]
mod harness;
