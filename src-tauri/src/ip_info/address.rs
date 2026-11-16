// Reads an IP address and works out what kind it is. Everything here happens on this PC, with
// no network, so it can be tested with plain addresses.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use url::Url;

// A longer paste than this is not an IP address.
const MAX_INPUT: usize = 2048;

// Where an address can be reached from. It decides which optional lookups make sense.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Internet,
    Private,
    Shared,
    LinkLocal,
    Loopback,
    Unspecified,
    Multicast,
    Broadcast,
    Documentation,
    Benchmarking,
    Special,
    Reserved,
}

impl Scope {
    // A private or shared address can have a name on the local network, so this PC's DNS
    // server is worth asking. The others have no meaningful name to find.
    pub fn reverse_dns(self) -> bool {
        matches!(self, Scope::Internet | Scope::Private | Scope::Shared)
    }

    // Only a public address means anything to an outside service. Private ones would tell it
    // about a network it cannot see.
    pub fn external(self) -> bool {
        self == Scope::Internet
    }
}

pub struct Class {
    pub kind: &'static str,
    pub scope: Scope,
    pub note: &'static str,
    // The block of addresses this one belongs to, such as "192.168.0.0/16".
    pub range: String,
}

// =========================
// Reading the input
// =========================

// Turns what was typed into an address. A port, brackets or a pasted web address are accepted.
// An IPv4-mapped IPv6 address is turned into the IPv4 address it carries. The bool says so.
pub fn parse(input: &str) -> Result<(IpAddr, bool), String> {
    let text = input.trim();
    if text.is_empty() {
        return Err("Enter an IP address to look up.".to_string());
    }
    if text.len() > MAX_INPUT {
        return Err("That is too long to be an IP address.".to_string());
    }
    if text.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("An IP address has no spaces. Enter one address at a time.".to_string());
    }

    let host = if text.contains("://") {
        Url::parse(text)
            .ok()
            .and_then(|url| url.host_str().map(str::to_string))
            .ok_or_else(|| "That is not a web address Tenax can read.".to_string())?
    } else if let Some(rest) = text.strip_prefix('[') {
        // "[2001:db8::1]" or "[2001:db8::1]:443"
        rest.split_once(']')
            .map_or("", |(inside, _)| inside)
            .to_string()
    } else {
        match text.split_once(':') {
            // "203.0.113.5:443" has one colon. An IPv6 address has several.
            Some((address, port))
                if !port.contains(':') && port.chars().all(|c| c.is_ascii_digit()) =>
            {
                address.to_string()
            }
            _ => text.to_string(),
        }
    };

    let host = host.trim_matches(['[', ']']);
    // A zone, such as "%12" on a link-local address, says which connection it is on.
    let host = host.split('%').next().unwrap_or("");

    match host.parse::<IpAddr>() {
        Ok(ip) => {
            let canonical = ip.to_canonical();
            Ok((canonical, canonical != ip))
        }
        Err(_) if looks_like_name(host) => {
            Err("That looks like a domain name. Use DNS Lookup for domain names.".to_string())
        }
        Err(_) => Err(
            "That is not a valid IP address. Enter IPv4 such as 203.0.113.5, or IPv6 such as 2001:db8::1."
                .to_string(),
        ),
    }
}

fn looks_like_name(host: &str) -> bool {
    // A name ends in a part with letters, such as "com". "0x8.8.8.8" ends in a number.
    host.rsplit('.')
        .next()
        .is_some_and(|last| last.chars().any(|c| c.is_ascii_alphabetic()))
        && host.contains('.')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

// =========================
// Classifying
// =========================

struct V4 {
    prefix: [u8; 4],
    length: u32,
    kind: &'static str,
    scope: Scope,
    note: &'static str,
}

const PRIVATE_NOTE: &str = "Reserved for private networks (RFC 1918). Homes and workplaces reuse it, so it identifies nothing on its own.";
const UNSPECIFIED_NOTE: &str =
    "It means \"no address\". A device uses it before it has been given one.";
const LOOPBACK_NOTE: &str =
    "It always points back to the device using it, so it never leaves this PC.";
const MULTICAST_NOTE: &str = "It addresses a group of devices at once, not a single one.";
const DOCUMENTATION_NOTE: &str =
    "Set aside for examples. It should never appear on a real network.";

// The most specific block comes first, so the first match is the right one.
const V4_BLOCKS: &[V4] = &[
    V4 {
        prefix: [0, 0, 0, 0],
        length: 32,
        kind: "Unspecified address",
        scope: Scope::Unspecified,
        note: UNSPECIFIED_NOTE,
    },
    V4 {
        prefix: [255, 255, 255, 255],
        length: 32,
        kind: "Broadcast address",
        scope: Scope::Broadcast,
        note: "It addresses every device on the local network at once.",
    },
    V4 {
        prefix: [0, 0, 0, 0],
        length: 8,
        kind: "\"This network\" address",
        scope: Scope::Reserved,
        note: "This range is reserved for use on the local network and is never a destination on the internet.",
    },
    V4 {
        prefix: [10, 0, 0, 0],
        length: 8,
        kind: "Private address",
        scope: Scope::Private,
        note: PRIVATE_NOTE,
    },
    V4 {
        prefix: [100, 64, 0, 0],
        length: 10,
        kind: "Shared address (carrier-grade NAT)",
        scope: Scope::Shared,
        note: "Internet providers use this range (RFC 6598) to share public addresses between many customers.",
    },
    V4 {
        prefix: [127, 0, 0, 0],
        length: 8,
        kind: "Loopback address",
        scope: Scope::Loopback,
        note: LOOPBACK_NOTE,
    },
    V4 {
        prefix: [169, 254, 0, 0],
        length: 16,
        kind: "Link-local address",
        scope: Scope::LinkLocal,
        note: "A device gives itself one of these when it cannot get an address from a network. It works only on the same connection.",
    },
    V4 {
        prefix: [172, 16, 0, 0],
        length: 12,
        kind: "Private address",
        scope: Scope::Private,
        note: PRIVATE_NOTE,
    },
    V4 {
        prefix: [192, 0, 0, 0],
        length: 24,
        kind: "Protocol assignment address",
        scope: Scope::Special,
        note: "Set aside for internet protocol work (RFC 6890). It is not given to ordinary devices.",
    },
    V4 {
        prefix: [192, 0, 2, 0],
        length: 24,
        kind: "Documentation address",
        scope: Scope::Documentation,
        note: DOCUMENTATION_NOTE,
    },
    V4 {
        prefix: [192, 88, 99, 0],
        length: 24,
        kind: "6to4 relay address (retired)",
        scope: Scope::Special,
        note: "Once used to carry IPv6 over IPv4. It was retired in 2015 (RFC 7526).",
    },
    V4 {
        prefix: [192, 168, 0, 0],
        length: 16,
        kind: "Private address",
        scope: Scope::Private,
        note: PRIVATE_NOTE,
    },
    V4 {
        prefix: [198, 18, 0, 0],
        length: 15,
        kind: "Benchmarking address",
        scope: Scope::Benchmarking,
        note: "Set aside for testing network equipment (RFC 2544). It should not appear on the internet.",
    },
    V4 {
        prefix: [198, 51, 100, 0],
        length: 24,
        kind: "Documentation address",
        scope: Scope::Documentation,
        note: DOCUMENTATION_NOTE,
    },
    V4 {
        prefix: [203, 0, 113, 0],
        length: 24,
        kind: "Documentation address",
        scope: Scope::Documentation,
        note: DOCUMENTATION_NOTE,
    },
    V4 {
        prefix: [224, 0, 0, 0],
        length: 4,
        kind: "Multicast address",
        scope: Scope::Multicast,
        note: MULTICAST_NOTE,
    },
    V4 {
        prefix: [240, 0, 0, 0],
        length: 4,
        kind: "Reserved address",
        scope: Scope::Reserved,
        note: "Held back for future use. It is not given to ordinary devices.",
    },
];

struct V6 {
    prefix: [u16; 8],
    length: u32,
    kind: &'static str,
    scope: Scope,
    note: &'static str,
}

// The most specific block comes first, as above. Anything outside these and 2000::/3 is reserved.
const V6_BLOCKS: &[V6] = &[
    V6 {
        prefix: [0, 0, 0, 0, 0, 0, 0, 0],
        length: 128,
        kind: "Unspecified address",
        scope: Scope::Unspecified,
        note: UNSPECIFIED_NOTE,
    },
    V6 {
        prefix: [0, 0, 0, 0, 0, 0, 0, 1],
        length: 128,
        kind: "Loopback address",
        scope: Scope::Loopback,
        note: LOOPBACK_NOTE,
    },
    V6 {
        prefix: [0x64, 0xff9b, 0, 0, 0, 0, 0, 0],
        length: 96,
        kind: "NAT64 address",
        scope: Scope::Special,
        note: "Carries an IPv4 address inside an IPv6 one, so IPv6-only networks can reach IPv4 sites (RFC 6052).",
    },
    V6 {
        prefix: [0x100, 0, 0, 0, 0, 0, 0, 0],
        length: 64,
        kind: "Discard-only address",
        scope: Scope::Special,
        note: "Traffic sent here is meant to be dropped (RFC 6666).",
    },
    V6 {
        prefix: [0x2001, 0xdb8, 0, 0, 0, 0, 0, 0],
        length: 32,
        kind: "Documentation address",
        scope: Scope::Documentation,
        note: DOCUMENTATION_NOTE,
    },
    V6 {
        prefix: [0x2001, 0, 0, 0, 0, 0, 0, 0],
        length: 32,
        kind: "Teredo tunnel address",
        scope: Scope::Internet,
        note: "Used by Teredo to carry IPv6 through IPv4 networks. It is an older way of tunnelling and is now rare.",
    },
    V6 {
        prefix: [0x2002, 0, 0, 0, 0, 0, 0, 0],
        length: 16,
        kind: "6to4 tunnel address",
        scope: Scope::Internet,
        note: "Carries an IPv4 address inside an IPv6 one. It is an older tunnelling method and is rarely used now.",
    },
    V6 {
        prefix: [0x2000, 0, 0, 0, 0, 0, 0, 0],
        length: 3,
        kind: "Global unicast address",
        scope: Scope::Internet,
        note: "An ordinary public IPv6 address. It can be reached from the internet.",
    },
    V6 {
        prefix: [0xfc00, 0, 0, 0, 0, 0, 0, 0],
        length: 7,
        kind: "Unique local address",
        scope: Scope::Private,
        note: "The IPv6 version of a private address (RFC 4193). It is used inside one network and is not reachable from the internet.",
    },
    V6 {
        prefix: [0xfe80, 0, 0, 0, 0, 0, 0, 0],
        length: 10,
        kind: "Link-local address",
        scope: Scope::LinkLocal,
        note: "Every IPv6 device has one. It works only on the same connection.",
    },
    V6 {
        prefix: [0xff00, 0, 0, 0, 0, 0, 0, 0],
        length: 8,
        kind: "Multicast address",
        scope: Scope::Multicast,
        note: MULTICAST_NOTE,
    },
];

fn matches_v4(ip: Ipv4Addr, block: &V4) -> bool {
    let mask = u32::MAX.checked_shl(32 - block.length).unwrap_or(0);
    u32::from(ip) & mask == u32::from(Ipv4Addr::from(block.prefix)) & mask
}

fn matches_v6(ip: Ipv6Addr, block: &V6) -> bool {
    let mask = u128::MAX.checked_shl(128 - block.length).unwrap_or(0);
    u128::from(ip) & mask == u128::from(Ipv6Addr::from(block.prefix)) & mask
}

pub fn classify(ip: IpAddr) -> Class {
    match ip {
        IpAddr::V4(ip) => match V4_BLOCKS.iter().find(|block| matches_v4(ip, block)) {
            Some(block) => Class {
                kind: block.kind,
                scope: block.scope,
                note: block.note,
                range: format!("{}/{}", Ipv4Addr::from(block.prefix), block.length),
            },
            None => Class {
                kind: "Public address",
                scope: Scope::Internet,
                note: "An ordinary public IPv4 address. It can be reached from the internet.",
                range: "Outside every reserved range".to_string(),
            },
        },
        IpAddr::V6(ip) => match V6_BLOCKS.iter().find(|block| matches_v6(ip, block)) {
            Some(block) => Class {
                kind: block.kind,
                scope: block.scope,
                note: block.note,
                range: format!("{}/{}", Ipv6Addr::from(block.prefix), block.length),
            },
            None => Class {
                kind: "Reserved address",
                scope: Scope::Reserved,
                note: "This part of the IPv6 space is not in use yet, so a real device should not have one of these.",
                range: "Outside 2000::/3".to_string(),
            },
        },
    }
}

// =========================
// Names
// =========================

// The name DNS uses to look up what an address points back to. 203.0.113.5 becomes
// 5.113.0.203.in-addr.arpa, and an IPv6 address is written one hex digit at a time.
pub fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, d] = ip.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(ip) => {
            let digits: Vec<String> = ip
                .octets()
                .iter()
                .flat_map(|byte| [byte >> 4, byte & 0xf])
                .rev()
                .map(|digit| format!("{digit:x}"))
                .collect();
            format!("{}.ip6.arpa", digits.join("."))
        }
    }
}

// IPv6 written in full, such as 2001:0db8:0000:0000:0000:0000:0000:0001, for reading and comparing.
pub fn full_form(ip: Ipv6Addr) -> String {
    ip.segments()
        .iter()
        .map(|part| format!("{part:04x}"))
        .collect::<Vec<_>>()
        .join(":")
}
