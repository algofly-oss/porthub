//! Kernel UAPI struct sizes — verified against `include/uapi/linux/*.h`
//! on the kernel versions noted per module. Each constant is paired with
//! a regression test asserting `std::mem::size_of::<NlinkType>() ==
//! KERNEL_SIZE`.
//!
//! Plan 213 (0.19) introduced this module as the byte-level regression
//! gate that prevents the wire-format defect class Plan 204 fixed
//! (silent EINVAL on `add_sp`, silent strict-checking rejection on
//! `del_sp`, etc.) from recurring.
//!
//! ## Why this approach?
//!
//! The simpler alternative — a `build.rs` that compiles a C program
//! emitting `sizeof(struct ...)` — was considered and deferred. It
//! adds a build-time C-toolchain dependency that complicates
//! cross-compile and sandboxed CI environments. Kernel UAPI struct
//! ABIs are treated as immutable per netlink semantics
//! (struct sizes never decrease; new fields are added via attributes,
//! not in-struct), so a one-time human verification of the canonical
//! sizes plus runtime test-time assertion is sufficient.
//!
//! ## When this fails
//!
//! - **A maintainer changes a `#[repr(C)]` / `#[repr(C, packed)]`
//!   struct layout** (adds/removes a field, changes packing). The
//!   relevant `*_size_matches_kernel` test fails immediately, surfacing
//!   the regression at `cargo test` time.
//! - **The kernel UAPI changes** (rare; struct ABIs are stable). The
//!   constant here would need to be updated alongside any new field
//!   additions on the nlink side.
//!
//! ## Attribute ids live elsewhere
//!
//! This module used to carry hand-copied tables of attribute ids and
//! message types (IFLA, RTA, CTA, XFRM, flower, HTB, DPLL, devlink,
//! ethtool), each tested against literals or against nlink's own
//! constants. A copy checks one transcription against another; #265
//! found `TCA_HTB_OFFLOAD` wrong in both. They were removed in 0.32
//! (#167): `scripts/audit-uapi-constants.sh` checks nlink's constants
//! against the kernel's headers and YNL specs directly, private ones
//! included. What stays here is what that audit cannot read: struct
//! sizes, signed verdict codes, a multicast group name and the hook
//! numbering per family.

// Sizes below are verified for the LP64 ABI (every 64-bit Linux
// target). 32-bit cross-compile is not currently supported.
#![cfg(target_pointer_width = "64")]

/// XFRM struct sizes — `include/uapi/linux/xfrm.h` (kernel 6.X).
pub mod xfrm {
    /// `sizeof(struct xfrm_userpolicy_info)`.
    ///
    /// Natural alignment; the trailing four `__u8` fields
    /// (`dir`, `action`, `flags`, `share`) pad to the next u64
    /// boundary because of the u64s in `xfrm_lifetime_*`. Plan 204 C2
    /// fix added the explicit 4-byte trailing pad to match.
    pub const USERPOLICY_INFO: usize = 168;

    /// `sizeof(struct xfrm_userpolicy_id)`.
    ///
    /// Selector (56) plus `index` (4) plus `dir` (1) plus 3 pad
    /// bytes to next u32 boundary. Plan 204 C3 fix trimmed the
    /// trailing pad from 7 to 3 bytes.
    pub const USERPOLICY_ID: usize = 64;

    /// `sizeof(struct xfrm_usersa_info)`. Trailing pad is 7 bytes
    /// (the kernel struct ends with `__u8 flags` then pads to next
    /// u64 align).
    pub const USERSA_INFO: usize = 224;

    /// `sizeof(struct xfrm_selector)`. Two addresses (16+16) + two
    /// port pairs (8) + family (2) + 2 prefix lens + proto + 3 pad
    /// + ifindex (4) + user (4) = 56.
    pub const SELECTOR: usize = 56;

    /// `sizeof(struct xfrm_lifetime_cfg)`. 8 × u64 = 64.
    pub const LIFETIME_CFG: usize = 64;

    /// `sizeof(struct xfrm_lifetime_cur)`. 4 × u64 = 32.
    pub const LIFETIME_CUR: usize = 32;

    /// `sizeof(struct xfrm_user_tmpl)`.
    pub const USER_TMPL: usize = 64;
}

/// nftables verdict constants — `include/uapi/linux/netfilter/nf_tables.h`
/// `enum nft_verdicts` (kernel 6.X).
///
/// Plan 204 C1 corrected `NFT_JUMP` and `NFT_GOTO`, which previously
/// shipped as `-2` and `-3`. The kernel defines them as `-3` and `-4`
/// — pre-0.19 nlink wrote `-2` for `Verdict::Jump`, which the kernel
/// interpreted as `NFT_BREAK` (terminate rule eval), silently breaking
/// every subroutine rule.
pub mod nft_verdict {
    pub const NF_DROP: i32 = 0;
    pub const NF_ACCEPT: i32 = 1;
    pub const NFT_CONTINUE: i32 = -1;
    pub const NFT_BREAK: i32 = -2;
    pub const NFT_JUMP: i32 = -3;
    pub const NFT_GOTO: i32 = -4;
    pub const NFT_RETURN: i32 = -5;
}

/// Devlink multicast group name — `include/uapi/linux/devlink.h`
/// `DEVLINK_GENL_MCGRP_CONFIG_NAME`.
///
/// Plan 204 C4 corrected the constant value from `"devlink"` (which
/// the kernel doesn't register) to `"config"`.
pub const DEVLINK_MCGRP_CONFIG_NAME: &str = "config";

/// Netfilter hook numbers — `include/uapi/linux/netfilter.h` enum
/// `nf_inet_hooks` and `include/uapi/linux/netfilter_netdev.h` enum
/// `nf_dev_hooks`. Plan 211 M1 made `Hook::Ingress` distinguish
/// between the two families.
pub mod nf_hook {
    /// `NF_INET_PRE_ROUTING`.
    pub const PRE_ROUTING: u32 = 0;
    /// `NF_INET_LOCAL_IN`.
    pub const LOCAL_IN: u32 = 1;
    /// `NF_INET_FORWARD`.
    pub const FORWARD: u32 = 2;
    /// `NF_INET_LOCAL_OUT`.
    pub const LOCAL_OUT: u32 = 3;
    /// `NF_INET_POST_ROUTING`.
    pub const POST_ROUTING: u32 = 4;
    /// `NF_INET_INGRESS` (kernel 5.10+).
    pub const INET_INGRESS: u32 = 5;
    /// `NF_NETDEV_INGRESS`.
    pub const NETDEV_INGRESS: u32 = 0;
    /// `NF_NETDEV_EGRESS` (kernel 5.16+).
    pub const NETDEV_EGRESS: u32 = 1;
    /// `NF_ARP_IN` (`netfilter_arp.h`).
    pub const ARP_IN: u32 = 0;
    /// `NF_ARP_OUT`.
    pub const ARP_OUT: u32 = 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    // ----- XFRM struct sizes -----

    /// Plan 204 C2 regression guard. Pre-fix this was 164 and
    /// `add_sp` failed with EINVAL on every kernel version.
    #[test]
    fn xfrm_userpolicy_info_size_matches_kernel() {
        assert_eq!(
            size_of::<crate::netlink::xfrm::XfrmUserpolicyInfo>(),
            xfrm::USERPOLICY_INFO,
            "XfrmUserpolicyInfo: kernel expects {} bytes (Plan 204 C2)",
            xfrm::USERPOLICY_INFO,
        );
    }

    /// Plan 204 C3 regression guard. Pre-fix this was 68 and
    /// strict-checking kernels rejected `del_sp`/`get_sp` with
    /// EINVAL.
    #[test]
    fn xfrm_userpolicy_id_size_matches_kernel() {
        assert_eq!(
            size_of::<crate::netlink::xfrm::XfrmUserpolicyId>(),
            xfrm::USERPOLICY_ID,
            "XfrmUserpolicyId: kernel expects {} bytes (Plan 204 C3)",
            xfrm::USERPOLICY_ID,
        );
    }

    #[test]
    fn xfrm_usersa_info_size_matches_kernel() {
        assert_eq!(
            size_of::<crate::netlink::xfrm::XfrmUsersaInfo>(),
            xfrm::USERSA_INFO,
        );
    }

    #[test]
    fn xfrm_selector_size_matches_kernel() {
        assert_eq!(
            size_of::<crate::netlink::xfrm::XfrmSelector>(),
            xfrm::SELECTOR,
        );
    }

    #[test]
    fn xfrm_lifetime_cfg_size_matches_kernel() {
        assert_eq!(
            size_of::<crate::netlink::xfrm::XfrmLifetimeCfg>(),
            xfrm::LIFETIME_CFG,
        );
    }

    #[test]
    fn xfrm_lifetime_cur_size_matches_kernel() {
        assert_eq!(
            size_of::<crate::netlink::xfrm::XfrmLifetimeCur>(),
            xfrm::LIFETIME_CUR,
        );
    }

    #[test]
    fn xfrm_user_tmpl_size_matches_kernel() {
        assert_eq!(
            size_of::<crate::netlink::xfrm::XfrmUserTmpl>(),
            xfrm::USER_TMPL,
        );
    }

    // ----- nftables verdict constants -----

    /// Plan 204 C1 regression guard. Pre-fix `NFT_JUMP` was `-2`
    /// (= `NFT_BREAK`) and `NFT_GOTO` was `-3` (= `NFT_JUMP`).
    /// Every `Verdict::Jump`/`Verdict::Goto` shipped wrong on the
    /// wire.
    #[test]
    fn nft_verdict_constants_match_kernel_uapi() {
        use crate::netlink::nftables::{
            NF_ACCEPT, NF_DROP, NFT_BREAK, NFT_CONTINUE, NFT_GOTO, NFT_JUMP, NFT_RETURN,
        };

        assert_eq!(NF_DROP, nft_verdict::NF_DROP);
        assert_eq!(NF_ACCEPT, nft_verdict::NF_ACCEPT);
        assert_eq!(NFT_CONTINUE, nft_verdict::NFT_CONTINUE);
        assert_eq!(
            NFT_BREAK,
            nft_verdict::NFT_BREAK,
            "NFT_BREAK was missing in nlink pre-0.19 (Plan 204 C1)"
        );
        assert_eq!(
            NFT_JUMP,
            nft_verdict::NFT_JUMP,
            "NFT_JUMP was -2 (= NFT_BREAK) pre-0.19 (Plan 204 C1)"
        );
        assert_eq!(
            NFT_GOTO,
            nft_verdict::NFT_GOTO,
            "NFT_GOTO was -3 (= NFT_JUMP) pre-0.19 (Plan 204 C1)"
        );
        assert_eq!(NFT_RETURN, nft_verdict::NFT_RETURN);
    }

    // ----- Devlink mcast group name -----

    /// Plan 204 C4 regression guard. Pre-fix value was `"devlink"`
    /// which the kernel doesn't register; every devlink event
    /// subscriber returned `FamilyNotFound`.
    #[test]
    fn devlink_mcast_group_name_matches_kernel_uapi() {
        use crate::netlink::genl::devlink::DEVLINK_MCGRP_NAME;
        assert_eq!(
            DEVLINK_MCGRP_NAME, DEVLINK_MCGRP_CONFIG_NAME,
            "DEVLINK_MCGRP_NAME was \"devlink\" pre-0.19 (Plan 204 C4); \
             kernel registers it as \"config\"."
        );
    }

    // ----- Plan 211 M1 — Hook variant kernel hook numbers -----

    /// Plan 211 M1 regression guard. Pre-fix `Hook::Ingress`
    /// always encoded `0`, which silently installed `Family::Inet`
    /// ingress chains on `Prerouting` instead of the real
    /// `NF_INET_INGRESS = 5` hook. It is numbered by the family now
    /// (#708).
    #[test]
    fn nft_hook_variants_match_kernel_uapi() {
        use crate::netlink::nftables::{Family, Hook};

        let inet = |h: Hook| h.number(Family::Inet);
        assert_eq!(inet(Hook::Prerouting), nf_hook::PRE_ROUTING);
        assert_eq!(inet(Hook::Input), nf_hook::LOCAL_IN);
        assert_eq!(inet(Hook::Forward), nf_hook::FORWARD);
        assert_eq!(inet(Hook::Output), nf_hook::LOCAL_OUT);
        assert_eq!(inet(Hook::Postrouting), nf_hook::POST_ROUTING);
        assert_eq!(
            inet(Hook::Ingress),
            nf_hook::INET_INGRESS,
            "Hook::Ingress encoded 0 pre-0.19 (Plan 211 M1); \
             kernel expects NF_INET_INGRESS=5"
        );
        let netdev = |h: Hook| h.number(Family::Netdev);
        assert_eq!(netdev(Hook::Ingress), nf_hook::NETDEV_INGRESS);
        assert_eq!(netdev(Hook::Egress), nf_hook::NETDEV_EGRESS);
        // ARP numbers its two hooks on its own (#484).
        assert_eq!(Hook::Input.number(Family::Arp), nf_hook::ARP_IN);
        assert_eq!(Hook::Output.number(Family::Arp), nf_hook::ARP_OUT);
        // The deprecated per-family spellings keep their numbers.
        #[allow(deprecated)]
        {
            assert_eq!(inet(Hook::InetIngress), nf_hook::INET_INGRESS);
            assert_eq!(netdev(Hook::NetdevIngress), nf_hook::NETDEV_INGRESS);
            assert_eq!(netdev(Hook::NetdevEgress), nf_hook::NETDEV_EGRESS);
        }
        // A chain read back names the hook it was given.
        let hooks = [
            Hook::Prerouting,
            Hook::Input,
            Hook::Forward,
            Hook::Output,
            Hook::Postrouting,
            Hook::Ingress,
            Hook::Egress,
        ];
        let families = [
            Family::Ip,
            Family::Ip6,
            Family::Inet,
            Family::Arp,
            Family::Bridge,
            Family::Netdev,
        ];
        for family in families {
            for hook in hooks.into_iter().filter(|h| h.is_valid_for_family(family)) {
                assert_eq!(
                    Hook::from_number(family, hook.number(family)),
                    Some(hook),
                    "{family} {hook}"
                );
            }
        }
    }

    /// Plan 211 M1 — `is_valid_for_family` correctly disambiguates
    /// hook + family combinations the kernel would reject.
    #[test]
    fn nft_hook_is_valid_for_family_disambiguates_correctly() {
        use crate::netlink::nftables::{Family, Hook};

        // Ingress: inet's and netdev's; the ip and ip6 filter chain types
        // have none, and nft refuses it there (#708).
        assert!(Hook::Ingress.is_valid_for_family(Family::Netdev));
        assert!(Hook::Ingress.is_valid_for_family(Family::Inet));
        assert!(!Hook::Ingress.is_valid_for_family(Family::Ip));
        assert!(!Hook::Ingress.is_valid_for_family(Family::Ip6));
        // Egress: netdev's only.
        assert!(Hook::Egress.is_valid_for_family(Family::Netdev));
        assert!(!Hook::Egress.is_valid_for_family(Family::Inet));
        // Standard L3 hooks on Inet/Ip/Ip6: OK
        assert!(Hook::Prerouting.is_valid_for_family(Family::Inet));
        assert!(Hook::Forward.is_valid_for_family(Family::Ip6));
        // Standard L3 hooks on Netdev: NOT OK
        assert!(!Hook::Prerouting.is_valid_for_family(Family::Netdev));
        // Neither ingress nor egress on Bridge: the bridge family has no
        // ingress hook, and `NetdevIngress` there encoded as its
        // prerouting (#484).
        assert!(!Hook::Egress.is_valid_for_family(Family::Bridge));
        assert!(!Hook::Ingress.is_valid_for_family(Family::Bridge));
        // ARP: input and output only.
        assert!(Hook::Input.is_valid_for_family(Family::Arp));
        assert!(Hook::Output.is_valid_for_family(Family::Arp));
        assert!(!Hook::Forward.is_valid_for_family(Family::Arp));
        assert!(!Hook::Prerouting.is_valid_for_family(Family::Arp));
        // The deprecated spellings stay tied to their family.
        #[allow(deprecated)]
        {
            assert!(Hook::NetdevIngress.is_valid_for_family(Family::Netdev));
            assert!(!Hook::NetdevIngress.is_valid_for_family(Family::Inet));
            assert!(Hook::InetIngress.is_valid_for_family(Family::Inet));
            assert!(!Hook::InetIngress.is_valid_for_family(Family::Ip));
        }
    }
}
