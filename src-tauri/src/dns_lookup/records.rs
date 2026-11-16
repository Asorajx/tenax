// What a DNS lookup returns, in plain Rust types, and the one thing that does the asking.
// There is no Windows or network code here, so everything built on it can be tested with
// made-up answers.

use std::net::{Ipv4Addr, Ipv6Addr};

// The kinds of record Tenax asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    A,
    Aaaa,
    Mx,
    Ns,
    Txt,
    Soa,
    // The name an address points back to. Used by IP Information.
    Ptr,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Data {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Mx {
        preference: u16,
        host: String,
    },
    Ns(String),
    Cname(String),
    Ptr(String),
    // A text record can be sent in several pieces. They are joined into one string.
    Txt(String),
    Soa {
        primary: String,
        admin: String,
        serial: u32,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    pub name: String,
    // How long, in seconds, a DNS server may keep this answer.
    pub ttl: u32,
    pub data: Data,
}

// Why an answer was not given. "No records" and "no such domain" are real answers. The rest
// mean the question could not be answered, which is not the same as the answer being "none".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    NoSuchDomain,
    NoRecords,
    ServerFailed,
    Refused,
    Timeout,
    NoServers,
    Other(u32),
}

impl Failure {
    // Whether the DNS server gave an answer at all. If not, asking more questions is pointless.
    pub fn is_unreachable(&self) -> bool {
        matches!(
            self,
            Failure::Timeout | Failure::NoServers | Failure::ServerFailed
        )
    }
}

pub type Answer = Result<Vec<Record>, Failure>;

// Whatever asks DNS. Windows' DNS client is one. The tests use a fake one.
pub trait Resolver {
    fn query(&self, name: &str, kind: Kind) -> Answer;
}
