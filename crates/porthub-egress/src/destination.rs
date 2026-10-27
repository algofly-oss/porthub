//! Target-side checks shared by gateway and peer connectors. Names are resolved
//! once, checked, then connected by the resulting address (no second DNS lookup).
use std::net::IpAddr;

pub fn permitted(address: IpAddr, allow_lan: bool, overlay: &[IpAddr]) -> bool {
    let address = match address {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(address),
        _ => address,
    };
    if overlay.contains(&address) {
        return false;
    }
    match address {
        IpAddr::V4(ip) => {
            let [a, b, _, _] = ip.octets();
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_broadcast()
                && a != 0
                && a < 224
                && !(a == 100 && (64..=127).contains(&b))
                && (allow_lan || !ip.is_private())
        }
        IpAddr::V6(ip) => {
            // Global unicast or explicitly allowed ULA. No local, multicast,
            // mapped metadata, or NAT64 escape from the IPv4 checks above.
            // AWS IMDS also has a ULA endpoint; LAN permission must not
            // expose instance credentials. See the EC2 metadata-access guide:
            // https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
            ip != std::net::Ipv6Addr::new(0xfd00,0xec2,0,0,0,0,0,0x254)
                && ((ip.segments()[0] & 0xe000 == 0x2000) || (allow_lan && ip.is_unique_local()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lan_permission_never_grants_metadata_loopback_or_overlay_access() {
        let overlay = ["10.203.0.2".parse().unwrap()];
        for target in [
            "127.0.0.1",
            "169.254.169.254",
            "100.100.100.200",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "fd00:ec2::254",
            "ff02::1",
            "::ffff:169.254.169.254",
            "10.203.0.2",
        ] {
            assert!(
                !permitted(target.parse().unwrap(), true, &overlay),
                "{target}"
            );
        }
        for target in [
            "10.1.2.3",
            "192.168.80.3",
            "172.16.0.3",
            "fd00::3",
            "::ffff:10.1.2.3",
        ] {
            let target = target.parse().unwrap();
            assert!(!permitted(target, false, &overlay));
            assert!(permitted(target, true, &overlay));
        }
        assert!(permitted("1.1.1.1".parse().unwrap(), false, &overlay));
        assert!(permitted(
            "2606:4700:4700::1111".parse().unwrap(),
            false,
            &overlay
        ));
    }
}
