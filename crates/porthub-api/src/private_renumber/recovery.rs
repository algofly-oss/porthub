//! Pure recovery decisions for a future fenced standalone-Mongo migration.
//! Not exported or wired to an API: no address writes are authorized by this module.
use std::{collections::BTreeSet, net::Ipv4Addr};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assignment {
    pub peer: String,
    pub machine: String,
    pub workspace: String,
    pub credential_generation: String,
    pub old: Ipv4Addr,
    pub new: Ipv4Addr,
    pub previous_generation: u64,
    pub generation: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Current {
    pub peer: String,
    pub machine: String,
    pub workspace: String,
    pub credential_generation: String,
    pub address: Ipv4Addr,
    pub generation: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// Caller must perform an exact old-identity/address/generation CAS, changing
    /// only address and generation; then read back before acknowledging progress.
    CompareAndSet,
    /// Peer write succeeded before a crash, but journal progress may not have.
    AlreadyApplied,
    /// Deletion must remain deletion. The orchestrator must account for a durable
    /// revocation/deletion record; absence alone does not finalize the journal.
    Missing,
    Conflict,
}
pub fn decide(expected: &Assignment, current: Option<&Current>) -> Decision {
    let Some(current) = current else {
        return Decision::Missing;
    };
    if expected.previous_generation.checked_add(1) != Some(expected.generation)
        || expected.old == expected.new
        || current.peer != expected.peer
        || current.machine != expected.machine
        || current.workspace != expected.workspace
        || current.credential_generation != expected.credential_generation
    {
        return Decision::Conflict;
    }
    if current.address == expected.new && current.generation == expected.generation {
        Decision::AlreadyApplied
    } else if current.address == expected.old && current.generation == expected.previous_generation
    {
        Decision::CompareAndSet
    } else {
        Decision::Conflict
    }
}
/// Validate a bounded chunk before persistence. Global uniqueness still requires
/// unique journal indexes; chunk validation never substitutes for them.
pub fn validate_chunk(rows: &[Assignment]) -> bool {
    if rows.is_empty() || rows.len() > 256 {
        return false;
    }
    let first = &rows[0];
    let mut peers = BTreeSet::new();
    let mut targets = BTreeSet::new();
    rows.iter().all(|a| {
        !a.peer.is_empty()
            && !a.machine.is_empty()
            && !a.workspace.is_empty()
            && !a.credential_generation.is_empty()
            && a.workspace == first.workspace
            && a.generation == first.generation
            && a.previous_generation == first.previous_generation
            && a.previous_generation.checked_add(1) == Some(a.generation)
            && a.old != a.new
            && a.old.is_private()
            && a.new.is_private()
            && peers.insert(&a.peer)
            && targets.insert(a.new)
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn row() -> Assignment {
        Assignment {
            peer: "w:p".into(),
            machine: "m".into(),
            workspace: "w".into(),
            credential_generation: "credential-1".into(),
            old: "10.203.0.2".parse().unwrap(),
            new: "10.204.0.2".parse().unwrap(),
            previous_generation: 4,
            generation: 5,
        }
    }
    fn current(a: &Assignment) -> Current {
        Current {
            peer: a.peer.clone(),
            machine: a.machine.clone(),
            workspace: a.workspace.clone(),
            credential_generation: a.credential_generation.clone(),
            address: a.old,
            generation: a.previous_generation,
        }
    }
    #[test]
    fn crash_before_write_resumes_exact_cas() {
        let a = row();
        assert_eq!(decide(&a, Some(&current(&a))), Decision::CompareAndSet);
    }
    #[test]
    fn crash_after_write_before_ack_is_idempotent() {
        let a = row();
        let mut c = current(&a);
        c.address = a.new;
        c.generation = a.generation;
        assert_eq!(decide(&a, Some(&c)), Decision::AlreadyApplied);
    }
    #[test]
    fn foreign_same_address_is_not_applied() {
        let a = row();
        let mut c = current(&a);
        c.address = a.new;
        assert_eq!(decide(&a, Some(&c)), Decision::Conflict);
    }
    #[test]
    fn identity_or_credential_replacement_blocks() {
        let a = row();
        for field in 0..4 {
            let mut c = current(&a);
            match field {
                0 => c.peer.push('x'),
                1 => c.machine.push('x'),
                2 => c.workspace.push('x'),
                _ => c.credential_generation.push('x'),
            };
            assert_eq!(decide(&a, Some(&c)), Decision::Conflict);
        }
    }
    #[test]
    fn deletion_is_never_upserted() {
        assert_eq!(decide(&row(), None), Decision::Missing);
    }
    #[test]
    fn overflow_or_skipped_generation_blocks() {
        let mut a = row();
        a.previous_generation = u64::MAX;
        a.generation = 0;
        assert_eq!(decide(&a, Some(&current(&a))), Decision::Conflict);
        a = row();
        a.generation += 1;
        assert!(!validate_chunk(&[a]));
    }
    #[test]
    fn duplicate_target_or_peer_rejects() {
        let a = row();
        let mut b = a.clone();
        b.peer.push('2');
        assert!(!validate_chunk(&[a.clone(), b.clone()]));
        b.new = "10.204.0.3".parse().unwrap();
        assert!(validate_chunk(&[a.clone(), b.clone()]));
        b.peer = a.peer.clone();
        assert!(!validate_chunk(&[a, b]));
    }
    #[test]
    fn chunk_bound_does_not_truncate() {
        let rows = vec![row(); 257];
        assert!(!validate_chunk(&rows));
        assert!(!validate_chunk(&[]));
    }
}
