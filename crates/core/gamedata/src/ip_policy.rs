//! Which addresses january may connect to on behalf of a user-supplied URL
//!
//! Written out by hand (std's `is_global` is unstable). IPv4 is judged
//! against a list of special-purpose ranges. IPv6 is allowed only inside
//! global unicast (2000::/3) minus the tunnelling and documentation ranges
//! in it, so loopback, unspecified, link-local, unique-local, multicast,
//! IPv4-compatible and NAT64 addresses are all forbidden by construction.
//! IPv4-mapped IPv6 addresses are judged as the IPv4 address they carry.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IPv4 ranges january must never connect to
const FORBIDDEN_V4: [(Ipv4Addr, u8); 15] = [
    (Ipv4Addr::new(0, 0, 0, 0), 8),       // "this network"
    (Ipv4Addr::new(10, 0, 0, 0), 8),      // private
    (Ipv4Addr::new(100, 64, 0, 0), 10),   // shared address space (CGNAT)
    (Ipv4Addr::new(127, 0, 0, 0), 8),     // loopback
    (Ipv4Addr::new(169, 254, 0, 0), 16),  // link-local (cloud metadata)
    (Ipv4Addr::new(172, 16, 0, 0), 12),   // private
    (Ipv4Addr::new(192, 0, 0, 0), 24),    // IETF protocol assignments
    (Ipv4Addr::new(192, 0, 2, 0), 24),    // documentation
    (Ipv4Addr::new(192, 88, 99, 0), 24),  // 6to4 relay anycast
    (Ipv4Addr::new(192, 168, 0, 0), 16),  // private
    (Ipv4Addr::new(198, 18, 0, 0), 15),   // benchmarking
    (Ipv4Addr::new(198, 51, 100, 0), 24), // documentation
    (Ipv4Addr::new(203, 0, 113, 0), 24),  // documentation
    (Ipv4Addr::new(224, 0, 0, 0), 4),     // multicast
    (Ipv4Addr::new(240, 0, 0, 0), 4),     // reserved + broadcast
];

/// The only IPv6 range january may connect to (global unicast)
const ALLOWED_V6: (Ipv6Addr, u8) = (Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3);

/// IPv6 ranges inside `ALLOWED_V6` that are still forbidden
const FORBIDDEN_V6: [(Ipv6Addr, u8); 4] = [
    // IETF protocol assignments (incl. Teredo)
    (Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23),
    // documentation
    (Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32),
    // 6to4
    (Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16),
    // documentation
    (Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20),
];

/// Whether january must refuse to connect to `ip`
pub fn is_forbidden(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_forbidden_v4(ip),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_forbidden_v4(mapped);
            }

            let bits = u128::from(ip);
            let (allowed, len) = ALLOWED_V6;
            !in_v6(bits, allowed, len)
                || FORBIDDEN_V6.iter().any(|&(net, len)| in_v6(bits, net, len))
        }
    }
}

fn is_forbidden_v4(ip: Ipv4Addr) -> bool {
    let bits = u32::from(ip);
    FORBIDDEN_V4.iter().any(|&(net, len)| {
        let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
        bits & mask == u32::from(net) & mask
    })
}

fn in_v6(bits: u128, net: Ipv6Addr, len: u8) -> bool {
    let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
    bits & mask == u128::from(net) & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("valid address")
    }

    #[test]
    fn sec002_ipv4_ranges_and_their_edges() {
        // (address, forbidden): first and last address of every range, and
        // the neighbours just outside it
        for (value, forbidden) in [
            ("0.0.0.0", true),
            ("0.255.255.255", true),
            ("1.0.0.0", false),
            ("9.255.255.255", false),
            ("10.0.0.0", true),
            ("10.255.255.255", true),
            ("11.0.0.0", false),
            ("100.63.255.255", false),
            ("100.64.0.0", true),
            ("100.127.255.255", true),
            ("100.128.0.0", false),
            ("126.255.255.255", false),
            ("127.0.0.0", true),
            ("127.0.0.1", true),
            ("127.255.255.255", true),
            ("128.0.0.0", false),
            ("169.253.255.255", false),
            ("169.254.0.0", true),
            ("169.254.169.254", true),
            ("169.254.255.255", true),
            ("169.255.0.0", false),
            ("172.15.255.255", false),
            ("172.16.0.0", true),
            ("172.31.255.255", true),
            ("172.32.0.0", false),
            ("191.255.255.255", false),
            ("192.0.0.0", true),
            ("192.0.0.255", true),
            ("192.0.1.0", false),
            ("192.0.1.255", false),
            ("192.0.2.0", true),
            ("192.0.2.255", true),
            ("192.0.3.0", false),
            ("192.88.98.255", false),
            ("192.88.99.0", true),
            ("192.88.99.255", true),
            ("192.88.100.0", false),
            ("192.167.255.255", false),
            ("192.168.0.0", true),
            ("192.168.255.255", true),
            ("192.169.0.0", false),
            ("198.17.255.255", false),
            ("198.18.0.0", true),
            ("198.19.255.255", true),
            ("198.20.0.0", false),
            ("198.51.99.255", false),
            ("198.51.100.0", true),
            ("198.51.100.255", true),
            ("198.51.101.0", false),
            ("203.0.112.255", false),
            ("203.0.113.0", true),
            ("203.0.113.255", true),
            ("203.0.114.0", false),
            ("223.255.255.255", false),
            ("224.0.0.0", true),
            ("239.255.255.255", true),
            ("240.0.0.0", true),
            ("255.255.255.255", true),
            // public controls
            ("8.8.8.8", false),
            ("1.1.1.1", false),
        ] {
            assert_eq!(is_forbidden(ip(value)), forbidden, "{value}");
        }
    }

    #[test]
    fn sec002_ipv6_ranges_and_their_edges() {
        for (value, forbidden) in [
            // outside 2000::/3
            ("::", true),
            ("::1", true),
            ("::7f00:1", true),
            ("::808:808", true),
            ("64:ff9b::7f00:1", true),
            ("64:ff9b::808:808", true),
            ("64:ff9b:1::1", true),
            ("100::1", true),
            ("fc00::", true),
            ("fd12:3456::1", true),
            ("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("fe80::", true),
            ("fe80::1", true),
            ("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("fec0::1", true),
            ("feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("ff00::", true),
            ("ff02::1", true),
            ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            // edges of 2000::/3
            ("1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2000::", false),
            ("3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("4000::", true),
            // 2001::/23 (incl. Teredo)
            ("2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2001::", true),
            ("2001:0:4136:e378:8000:63bf:3fff:fdd2", true),
            ("2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2001:200::", false),
            // 2001:db8::/32
            ("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2001:db8::", true),
            ("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2001:db9::", false),
            // 2002::/16 (6to4, incl. 6to4 of 127.0.0.1)
            ("2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2002::", true),
            ("2002:7f00:1::", true),
            ("2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2003::", false),
            // 3fff::/20
            ("3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("3fff::", true),
            ("3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("3fff:1000::", false),
            // public controls
            ("2606:4700::1111", false),
            ("2a00:1450::1", false),
            ("2001:4860:4860::8888", false),
        ] {
            assert_eq!(is_forbidden(ip(value)), forbidden, "{value}");
        }
    }

    #[test]
    fn sec002_ipv4_mapped_addresses_are_judged_as_ipv4() {
        for (value, forbidden) in [
            ("::ffff:0.0.0.0", true),
            ("::ffff:127.0.0.1", true),
            ("::ffff:10.0.0.1", true),
            ("::ffff:100.64.0.1", true),
            ("::ffff:169.254.169.254", true),
            ("::ffff:192.168.1.1", true),
            ("::ffff:255.255.255.255", true),
            ("::ffff:8.8.8.8", false),
            ("::ffff:1.1.1.1", false),
        ] {
            assert_eq!(is_forbidden(ip(value)), forbidden, "{value}");
        }
    }
}
