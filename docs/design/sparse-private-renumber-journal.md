# Standalone-Mongo private address migration (local prototype design)

Status: implementation contract, not deployed or advertised. Base f64ba2e. Sparse remains default-off. This supersedes the earlier design's prohibition on automatic address changes: enrolled identity and DNS are stable; literal old IP addresses are not stable identity.

## Actual gap

private_networks::allocate_locked expands pools but does not move existing conflicting assignments. save changes preferences while retaining old peer addresses. The process-local private_network_lock covers allocation/enrollment/save, not sync publication or every credential/member/ACL writer. Consequently a journal plus sequential peer writes alone would expose mixed generations and could republish obsolete authority. A mutex is not crash durability. No replica set, transaction, change stream, or atomic multi-document operation is assumed.

## Durable authority fence

One workspace head document owns monotonically increasing generation and optional migration ID. An atomic journaled head transition Stable(g) -> Preparing(g+1,job) is the linearization point. Reads/publications and all address/namespace writers must participate in a per-workspace in-process publication mutex and read the head fresh; an active job refuses new private authorization with explicit retry/migrating response (not auth denial and not old-snapshot fallback). Restart loads and recovers pending heads before accepting private control. Cross-process workers require database fencing, not this single-core mutex. Horizontal API support remains out of scope.

Already published authorities must be revoked: every incident Hub/base/pair ticket, signaling queue and existing carrier must bind workspace generation. Retiring the generation cancels all old transports, including authorized stream optimization and relay fallback. Wait for acknowledgements or maximum independent lease lifetime before editing addresses; acknowledgement alone cannot extend an old lease. Existing clients lacking migration/rebind support receive actionable update-required before migration starts. Legacy clients below4096 retain their existing contract absent migration. Never truncate peers or restore oversized legacy snapshots.

## Durable journal layout and ordering

Head contains schema, workspace, generation, state, job ID, old/new pool digest, assignment count/digest, preparation cursor and applied cursor. Separate immutable assignment rows keyed job+peer contain old/new canonical IPv4 plus stable machine/workspace identity and credential-generation pin. Do not store credentials. Chunk rows and bounded cursor scans avoid16MiB BSON and RAM exhaustion; upper bounds65536 peers and32 pools remain explicit. Create unique job+peer and job+new-IP indexes; ordinary private_peers workspace+IP unique index remains unchanged.

1. Select disjoint new pools avoiding all foreign reserved pools/assigned addresses and fresh own advertised LAN/VPN/WSL prefixes. Do not route over an ambiguous LAN. Persist head Preparing first, thereby fencing publication and allocation. Reserve target pools through the same gateway-wide allocator lock and durable reservation records; other allocators must include Preparing reservations after restart.
2. Build immutable assignment rows using keyset pagination. Record generation/credential-generation, not full mutable peer blobs. Finalize count and canonical digest only after all rows durably exist. Crash during preparation resumes or aborts before address writes; never infer completeness from cursor alone.
3. Transition head to Applying only after revalidating all target reservations, relevant local networks and client readiness. Each peer CAS changes ONLY ip and address_generation with filters for stable workspace/machine/peer, expected old address and credential-generation. A row already at exact new address+job generation is idempotent success. Any other address/generation or missing/replaced identity blocks recovery; never overwrite foreign changes. Concurrent revocation remains allowed: disabled credentials stay disabled; migrating must never recreate credential fields or resurrect deleted peers.
4. Crash between peer CAS and row progress acknowledgement is safe: read exact assignment, detect AlreadyApplied, then acknowledge. Advance durable cursor only after assignment ACK. No write rollback to old IPs once Applying: recovery rolls forward because old pools may conflict and clients may have observed a new generation.
5. Verify every surviving expected peer's exact assignment and all reservation digests using bounded scans. Atomically publish new pool head Stable(g+1) only when complete; invalidate/rebuild DNS directory. New sync rebinds own IP and creates new independent pair epochs. DNS names/custom aliases and rules/groups/selectors are untouched. No old-IP aliases or synthetic peers.
6. Retain audit/tombstone and retire old reservations only after stable head commit plus old authority drain. Reservation GC cannot remove active/Preparing job reservations. Unknown job/head mismatch stays fenced with actionable repair, never guesses a prefix.

Every durable transition uses explicit acknowledged journaled writes (j:true); validate deployment journaling support and fail closed on unsupported writes. Do not assume majority replication on standalone. Crash recovery must reconcile uncertain write results by fresh exact reads. Process death is the fault model; disk loss is not recoverable by this journal alone.

## Required wiring before enabling

- private_networks allocator/ensure/save and routes/private_enrollment: head/reservation-aware allocation.
- routes/private_sync and private_sparse directory/pair publication: fresh head generation and publication fence before/after awaited reads; cached names never authorize.
- private_relay tickets/base/pair/carrier: workspace generation revocation and no late publication across head transition.
- credential/bootstrap/revoke, workspace/member/group/rule and machine name/domain mutations: audit each writer; preserve concurrent authoritative denial and reject address-affecting writers during migration.
- agent protocol: bounded conflict report containing validated prefixes, generation acknowledgement, own-IP clean rebind; all3OS owned aggregate routes/resolvers revalidated and old routes retired.
- startup recovery blocks affected workspace before normal serving; global allocator loads pending reservations before enrollment.

## Named tests

Pure recovery core: crashBeforePeerWrite, crashAfterPeerBeforeAck, wrongIdentity, wrongCredentialGeneration, foreignSameIpDifferentGeneration, missingPeerNoResurrection, duplicateTarget, generationOverflow, preserveUnrelatedFields.
Actual isolated standalone Mongo: fail after each durable step; recreate App; resume; assert exact IDs/credentials/groups/books/names unchanged and no mixed generation publication. Concurrent enrollment/enable/revoke/domain edit/group removal; pending reservation respected by second tenant; stale head/job rejected; two jobs CAS one winner;4097 assignment keyset scan bounded;65k journal split never one BSON array; journal-write failure keeps fence; abandoned Preparing recovery safe.
Publication/carrier: in-flight request paused before final publish, migrate, release -> no old authority; old active stream/relay/QUIC revoked independently; DNS cached old address cannot authorize; fresh DNS answer new address only after commit.
Native opt-in later: all3OS own-address rebind and exact old-route/resolver cleanup, collision with LAN/VPN/WSL refuses unsafe capture, new nonconflicting pool restores stable-name connectivity. No native proof exists yet.

## Implementation boundary

A pure recovery decision core can be implemented/tested independently now. Real Mongo journal orchestration must not be presented as complete until durable head/reservation gates and publication/drain are wired together. Current f64 has none of these durable migration gates. No migration route or auto-trigger is enabled by adding the core. Exit/Tor/fairness and existing native disposable-host proof remain separate open requirements.

Primary references: [MongoDB single-document atomicity](https://www.mongodb.com/docs/manual/core/write-operations-atomicity/), [write concern](https://www.mongodb.com/docs/manual/reference/write-concern/), and [WiredTiger journaling](https://www.mongodb.com/docs/manual/core/journaling/). Multi-document update operations are not a transaction; this design deliberately uses a fenced roll-forward protocol.
