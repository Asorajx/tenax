// Turns what was found about an address into cards. There is no network or Windows code here,
// so every case can be tested with made-up answers.
//
// Each card says where its information came from, because Tenax keeps three sources apart:
//   this PC       the kind of address, worked out locally
//   DNS server    the name the address points back to, from the server this PC already uses
//   external      the owner and location, from ipinfo.io, only when the user asked for it
// None of them says whether an address is good or bad. IP Information describes an address.

use std::net::IpAddr;
use std::time::Instant;

use super::address::{Class, Scope, classify, full_form};
use super::countries;
use super::external::{self, Owner};
use crate::dns_lookup::records::{Answer, Data, Failure};
use crate::finding::{Detail, Finding, Status, Step, Verdict, count_of, detail};

// The longest a name is shown.
const MAX_NAME: usize = 253;

fn scope_label(scope: Scope) -> &'static str {
    match scope {
        Scope::Internet => "Public internet",
        Scope::Private => "Private network",
        Scope::Shared => "Provider-shared network",
        Scope::LinkLocal => "Same connection only",
        Scope::Loopback => "This device only",
        Scope::Unspecified => "No address",
        Scope::Multicast => "A group of devices",
        Scope::Broadcast => "Every device on the network",
        Scope::Documentation => "Examples only",
        Scope::Benchmarking => "Equipment testing only",
        Scope::Special => "Special purpose",
        Scope::Reserved => "Not in use",
    }
}

// =========================
// This PC: the kind of address
// =========================

pub fn address(ip: IpAddr, mapped: bool, started: Instant) -> (Verdict, Finding) {
    let class = classify(ip);
    let (status, headline, explanation) = describe(&class);

    let mut details = vec![detail("Address", ip.to_string())];
    match ip {
        IpAddr::V4(_) => details.push(detail("Version", "IPv4")),
        IpAddr::V6(ip) => {
            details.push(detail("Version", "IPv6"));
            details.push(detail("Full form", full_form(ip)));
        }
    }
    details.push(detail("Type", class.kind).because(class.note));
    details.push(detail("Range", class.range.clone()));
    details.push(detail("Reached from", scope_label(class.scope)));

    let note = mapped.then(|| {
        format!(
            "You entered an IPv4-mapped IPv6 address, which carries the IPv4 address {ip}. Tenax read it as that address."
        )
    });

    let finding = Finding {
        id: "ip-address".to_string(),
        status,
        title: "Address type".to_string(),
        summary: class.kind.to_string(),
        checked: "I read the address and matched it against the ranges that internet standards set aside.".to_string(),
        why: "The range an address falls in says where it can be reached from, and so what is worth looking up about it.".to_string(),
        action: None,
        details,
        note,
        urls: Vec::new(),
        steps: vec![Step::new(
            "Worked out the kind of address",
            "Read the address on this PC and worked out what kind it is",
            "Parsed with the Rust standard library and matched against the reserved IPv4 and IPv6 ranges (RFC 6890)",
            format!("{} · {}", class.kind, scope_label(class.scope)),
            started,
        )],
    };

    (
        Verdict {
            status,
            headline: headline.to_string(),
            detail: explanation.to_string(),
        },
        finding,
    )
}

fn describe(class: &Class) -> (Status, &'static str, &'static str) {
    match class.scope {
        Scope::Internet => (
            Status::Ok,
            "This is a public internet address.",
            "It can be reached from the internet. The address alone does not say who runs it or where it is.",
        ),
        Scope::Private => (
            Status::Ok,
            "This is a private network address.",
            "It is used inside homes and workplaces and cannot be reached directly from the internet. Many networks use the same ones.",
        ),
        Scope::Shared => (
            Status::Ok,
            "This is a provider-shared address.",
            "Internet providers use this range to share public addresses between many customers. It cannot be reached directly from the internet.",
        ),
        Scope::LinkLocal => (
            Status::Ok,
            "This is a link-local address.",
            "A device uses it to talk to others on the same connection. It is not routed anywhere else.",
        ),
        Scope::Loopback => (
            Status::Ok,
            "This address points back to the device using it.",
            "Traffic sent to it never leaves this PC.",
        ),
        _ => (
            Status::Info,
            "This address is set aside for a special purpose.",
            "It is not given to ordinary devices on the internet.",
        ),
    }
}

// =========================
// This PC's DNS server: the name
// =========================

// What a failed question means, in words.
fn failure_text(failure: &Failure) -> &'static str {
    match failure {
        Failure::Timeout => "This PC's DNS server did not answer in time.",
        Failure::NoServers => "This PC has no DNS server it can reach.",
        Failure::ServerFailed => "The DNS server reported an error.",
        Failure::Refused => "The DNS server refused the question.",
        _ => "Windows could not get an answer.",
    }
}

fn clean(name: &str) -> String {
    external::printable(name.trim_end_matches('.'), MAX_NAME)
}

// Whether a returned name is a real host name. A name that is just the address again, or the
// question that was asked, tells the user nothing, so it is never shown as a result.
fn is_name(name: &str, question: &str) -> bool {
    let name = clean(name);
    !name.is_empty() && name.parse::<IpAddr>().is_err() && !name.eq_ignore_ascii_case(question)
}

pub fn reverse(question: &str, answer: &Answer, started: Instant) -> Finding {
    let method = format!("Windows DNS client (DnsQuery), PTR record at {question}");
    // Only real names count. If none are left, the address has no name.
    let answer: Answer = match answer {
        Ok(records) => {
            let kept: Vec<_> = records
                .iter()
                .filter(|record| matches!(&record.data, Data::Ptr(name) if is_name(name, question)))
                .cloned()
                .collect();
            if kept.is_empty() {
                Err(Failure::NoRecords)
            } else {
                Ok(kept)
            }
        }
        Err(failure) => Err(failure.clone()),
    };
    let answer = &answer;
    let (status, summary, details, note, step_result, step_ok): (
        Status,
        String,
        Vec<Detail>,
        String,
        String,
        bool,
    ) = match answer {
        Ok(records) => {
            let names: Vec<String> = records
                .iter()
                .filter_map(|record| match &record.data {
                    Data::Ptr(name) => Some(clean(name)),
                    _ => None,
                })
                .collect();
            (
                Status::Ok,
                count_of(names.len(), "name"),
                names.iter().map(|name| detail("Name", name)).collect(),
                "Whoever controls the address chooses this name, so it is a clue about the network and not proof of who is behind it.".to_string(),
                format!("{} found", count_of(names.len(), "name")),
                true,
            )
        }
        Err(Failure::NoRecords | Failure::NoSuchDomain) => (
            Status::Info,
            "No name".to_string(),
            Vec::new(),
            "The DNS server answered that this address has no name. That is common, and says nothing about the address by itself.".to_string(),
            "No name".to_string(),
            true,
        ),
        Err(failure) => (
            Status::Limited,
            "Could not be checked".to_string(),
            Vec::new(),
            format!("{} Without an answer, Tenax cannot say whether the address has a name.", failure_text(failure)),
            failure_text(failure).to_string(),
            false,
        ),
    };

    Finding {
        id: "reverse-dns".to_string(),
        status,
        title: "Reverse DNS".to_string(),
        summary,
        checked: "I asked this PC's DNS server which name the address points back to.".to_string(),
        why: "A name can hint at who runs a network or what a device is, though anyone who controls an address can choose it.".to_string(),
        action: None,
        details,
        note: Some(note),
        urls: Vec::new(),
        steps: vec![Step {
            ok: step_ok,
            ..Step::new(
                "Asked this PC's DNS server for the address's name",
                "Asked the DNS server this PC already uses which name this address has",
                &method,
                step_result,
                started,
            )
        }],
    }
}

// =========================
// External: owner and location
// =========================

fn location(owner: &Owner) -> Option<String> {
    // The country code is written with its name, such as "United States (US)".
    let country = owner.country.as_deref().map(countries::with_name);
    let parts: Vec<&str> = [
        owner.city.as_deref(),
        owner.region.as_deref(),
        country.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect();
    (!parts.is_empty()).then(|| parts.join(", "))
}

pub fn owner(ip: IpAddr, outcome: &Result<Owner, String>, started: Instant) -> Finding {
    let method = format!(
        "HTTPS GET {}, redirects not followed",
        external::url_for(ip)
    );
    let source = detail(
        "Source",
        format!("{} (external service)", external::SERVICE),
    );

    let (status, summary, details, note, step_result, step_ok) = match outcome {
        Ok(found) if found.not_public => (
            Status::Info,
            "No details".to_string(),
            vec![source],
            format!(
                "{} says this is not a public address, so it has no owner or location to report.",
                external::SERVICE
            ),
            "Not a public address".to_string(),
            true,
        ),
        Ok(found) => {
            let mut details = vec![source];
            if let Some(name) = &found.organisation {
                details.push(detail("Organisation", name));
            }
            if let Some(asn) = &found.asn {
                details.push(detail("Network (ASN)", asn));
            }
            if let Some(place) = location(found) {
                details.push(detail("Approximate location", place).because(
                    "This is an estimate for the area the network is registered or routed in. It does not show where a device or person physically is.",
                ));
            }
            if let Some(zone) = &found.timezone {
                details.push(detail("Time zone", zone));
            }
            let summary = match (&found.organisation, &found.asn) {
                (Some(name), Some(asn)) => format!("{name} · {asn}"),
                (Some(name), None) => name.clone(),
                (None, Some(asn)) => asn.clone(),
                (None, None) => "No details".to_string(),
            };
            let shown = details.len() - 1;
            (
                if shown == 0 { Status::Info } else { Status::Ok },
                summary,
                details,
                "These details come from the service, not from this PC. The location is approximate: it points to an area, often a city or just a country, and never to a device's exact physical location or to who is using the address. It can also be wrong, especially for VPNs, mobile networks and companies that use one address in many places. Neither ownership nor location says whether an address is good or bad.".to_string(),
                format!("{} returned", count_of(shown, "detail")),
                true,
            )
        }
        Err(message) => (
            Status::Unknown,
            "Could not be checked".to_string(),
            vec![source],
            message.clone(),
            message.clone(),
            false,
        ),
    };

    Finding {
        id: "owner".to_string(),
        status,
        title: "Owner and location".to_string(),
        summary,
        checked: format!(
            "I sent the IP address to {} and read the owner, network and approximate location it reported.",
            external::SERVICE
        ),
        why: "Knowing which organisation runs a network, and roughly where, helps you judge whether traffic or an email from it fits what you expected.".to_string(),
        action: None,
        details,
        note: Some(note),
        urls: Vec::new(),
        steps: vec![Step {
            ok: step_ok,
            ..Step::new(
                &format!("Asked {} about the address", external::SERVICE),
                &format!("Sent the IP address to {}, which reported the owner and location it has on record", external::SERVICE),
                &method,
                step_result,
                started,
            )
        }],
    }
}
