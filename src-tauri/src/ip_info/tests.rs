// IP Information run against made-up addresses, answers and replies, so no network is needed.

use std::cell::RefCell;
use std::net::IpAddr;
use std::time::Instant;

use super::address::{Scope, classify, parse, reverse_name};
use super::external::{self, Owner};
use super::*;
use crate::dns_lookup::records::{Answer, Data, Failure, Kind, Record, Resolver};
use crate::finding::Status;

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

// A DNS that gives one answer, and remembers what it was asked.
struct Fake {
    answer: Answer,
    asked: RefCell<Vec<(String, Kind)>>,
}

impl Fake {
    fn new(answer: Answer) -> Self {
        Fake {
            answer,
            asked: RefCell::new(Vec::new()),
        }
    }
}

impl Resolver for Fake {
    fn query(&self, name: &str, kind: Kind) -> Answer {
        self.asked.borrow_mut().push((name.to_string(), kind));
        self.answer.clone()
    }
}

fn ptr(name: &str) -> Record {
    Record {
        name: "ignored".to_string(),
        ttl: 300,
        data: Data::Ptr(name.to_string()),
    }
}

// =========================
// What kind of address it is
// =========================

#[test]
fn addresses_are_sorted_into_the_right_kind() {
    for (address, kind, scope) in [
        ("8.8.8.8", "Public address", Scope::Internet),
        ("1.1.1.1", "Public address", Scope::Internet),
        ("10.1.2.3", "Private address", Scope::Private),
        ("172.16.0.1", "Private address", Scope::Private),
        ("172.31.255.255", "Private address", Scope::Private),
        ("172.32.0.1", "Public address", Scope::Internet),
        ("192.168.1.1", "Private address", Scope::Private),
        (
            "100.64.0.1",
            "Shared address (carrier-grade NAT)",
            Scope::Shared,
        ),
        (
            "100.127.255.255",
            "Shared address (carrier-grade NAT)",
            Scope::Shared,
        ),
        ("100.128.0.1", "Public address", Scope::Internet),
        ("127.0.0.1", "Loopback address", Scope::Loopback),
        ("169.254.10.10", "Link-local address", Scope::LinkLocal),
        ("0.0.0.0", "Unspecified address", Scope::Unspecified),
        ("0.1.2.3", "\"This network\" address", Scope::Reserved),
        ("255.255.255.255", "Broadcast address", Scope::Broadcast),
        ("224.0.0.1", "Multicast address", Scope::Multicast),
        ("240.0.0.1", "Reserved address", Scope::Reserved),
        ("192.0.2.1", "Documentation address", Scope::Documentation),
        (
            "198.51.100.7",
            "Documentation address",
            Scope::Documentation,
        ),
        ("203.0.113.5", "Documentation address", Scope::Documentation),
        ("198.18.0.1", "Benchmarking address", Scope::Benchmarking),
        (
            "198.19.255.255",
            "Benchmarking address",
            Scope::Benchmarking,
        ),
        ("192.0.0.8", "Protocol assignment address", Scope::Special),
        ("::", "Unspecified address", Scope::Unspecified),
        ("::1", "Loopback address", Scope::Loopback),
        (
            "2606:4700:4700::1111",
            "Global unicast address",
            Scope::Internet,
        ),
        ("2001:db8::1", "Documentation address", Scope::Documentation),
        ("2001:0::1", "Teredo tunnel address", Scope::Internet),
        ("2002:c000:204::1", "6to4 tunnel address", Scope::Internet),
        ("fd12:3456::1", "Unique local address", Scope::Private),
        ("fc00::1", "Unique local address", Scope::Private),
        ("fe80::1", "Link-local address", Scope::LinkLocal),
        ("ff02::1", "Multicast address", Scope::Multicast),
        ("64:ff9b::808:808", "NAT64 address", Scope::Special),
        ("100::1", "Discard-only address", Scope::Special),
        ("4000::1", "Reserved address", Scope::Reserved),
        ("::2", "Reserved address", Scope::Reserved),
    ] {
        let class = classify(ip(address));
        assert_eq!((class.kind, class.scope), (kind, scope), "{address}");
    }
}

#[test]
fn the_range_shown_is_the_block_the_address_belongs_to() {
    assert_eq!(classify(ip("192.168.4.4")).range, "192.168.0.0/16");
    assert_eq!(classify(ip("172.20.1.1")).range, "172.16.0.0/12");
    assert_eq!(classify(ip("fd00::1")).range, "fc00::/7");
}

#[test]
fn only_the_right_addresses_are_offered_each_lookup() {
    for (address, reverse, external) in [
        ("8.8.8.8", true, true),
        ("2606:4700:4700::1111", true, true),
        ("192.168.1.1", true, false),
        ("100.64.0.1", true, false),
        ("fd00::1", true, false),
        ("127.0.0.1", false, false),
        ("169.254.1.1", false, false),
        ("0.0.0.0", false, false),
        ("224.0.0.1", false, false),
        ("203.0.113.5", false, false),
        ("240.0.0.1", false, false),
    ] {
        let scope = classify(ip(address)).scope;
        assert_eq!(scope.reverse_dns(), reverse, "reverse {address}");
        assert_eq!(scope.external(), external, "external {address}");
        let report = inspect(address).unwrap();
        assert_eq!(report.can_reverse, reverse, "{address}");
        assert_eq!(report.can_external, external, "{address}");
    }
}

#[test]
fn a_private_address_is_refused_by_the_external_lookup_itself() {
    // The interface hides the button, but the command does not trust that.
    for address in [
        "192.168.1.1",
        "10.0.0.1",
        "127.0.0.1",
        "fd00::1",
        "100.64.0.1",
    ] {
        assert!(
            checked(address, Scope::external, "no").is_err(),
            "{address}"
        );
    }
    assert!(checked("8.8.8.8", Scope::external, "no").is_ok());
    // And the reverse lookup refuses an address with no name to find.
    assert!(checked("127.0.0.1", Scope::reverse_dns, "no").is_err());
    assert!(checked("192.168.1.1", Scope::reverse_dns, "no").is_ok());
}

// =========================
// Reading what was typed
// =========================

#[test]
fn addresses_are_read_however_they_are_pasted() {
    for (typed, expected) in [
        ("8.8.8.8", "8.8.8.8"),
        ("  8.8.8.8  ", "8.8.8.8"),
        ("8.8.8.8:443", "8.8.8.8"),
        ("https://8.8.8.8/path?x=1", "8.8.8.8"),
        ("http://8.8.8.8:8080/", "8.8.8.8"),
        ("2001:4860:4860::8888", "2001:4860:4860::8888"),
        ("[2001:4860:4860::8888]", "2001:4860:4860::8888"),
        ("[2001:4860:4860::8888]:443", "2001:4860:4860::8888"),
        ("http://[2001:4860:4860::8888]:80/", "2001:4860:4860::8888"),
        ("fe80::1%12", "fe80::1"),
        ("2001:4860:4860:0:0:0:0:8888", "2001:4860:4860::8888"),
    ] {
        let (address, mapped) = parse(typed).unwrap();
        assert_eq!(address.to_string(), expected, "{typed}");
        assert!(!mapped, "{typed}");
    }
}

#[test]
fn an_ipv4_mapped_address_is_read_as_the_ipv4_address_it_carries() {
    let (address, mapped) = parse("::ffff:8.8.8.8").unwrap();
    assert_eq!(address, ip("8.8.8.8"));
    assert!(mapped);
    let report = inspect("::ffff:192.168.1.1").unwrap();
    assert_eq!(report.address, "192.168.1.1");
    assert!(
        report.findings[0]
            .note
            .as_deref()
            .unwrap()
            .contains("IPv4-mapped")
    );
}

#[test]
fn what_is_not_an_address_is_refused_with_a_reason() {
    for (typed, wanted) in [
        ("", "Enter an IP address"),
        ("   ", "Enter an IP address"),
        ("example.com", "domain name"),
        ("www.example.co.uk", "domain name"),
        ("8.8.8", "not a valid IP address"),
        ("8.8.8.8.8", "not a valid IP address"),
        ("256.1.1.1", "not a valid IP address"),
        ("08.8.8.8", "not a valid IP address"),
        ("0x8.8.8.8", "not a valid IP address"),
        ("2130706433", "not a valid IP address"),
        ("8.8.8.8 1.1.1.1", "no spaces"),
        ("8.8.8.8\n1.1.1.1", "no spaces"),
        ("gggg::1", "not a valid IP address"),
        ("[::1", "not a valid IP address"),
        ("1:2:3:4:5:6:7:8:9", "not a valid IP address"),
        ("https://example.com/", "domain name"),
    ] {
        let error = parse(typed).unwrap_err();
        assert!(error.contains(wanted), "{typed}: {error}");
    }
    assert!(parse(&"1".repeat(3000)).unwrap_err().contains("too long"));
}

#[test]
fn odd_text_never_crashes_the_reader() {
    // A fixed spread of awkward input. The point is that none of it panics.
    let pieces = [
        "",
        ":",
        "::",
        "[",
        "]",
        "[]",
        "%",
        "/",
        "//",
        "://",
        "@",
        ".",
        "..",
        "0",
        "255",
        "1.2.3.4",
        "::1",
        "ffff",
        "é",
        "\u{202e}",
        "\u{0}",
        "http",
        "[::1]:",
        "%%",
        "1.2.3.4:99999999999",
    ];
    for a in pieces {
        for b in pieces {
            for c in pieces {
                let _ = parse(&format!("{a}{b}{c}"));
            }
        }
    }
}

// =========================
// Reverse names
// =========================

#[test]
fn the_name_that_is_asked_about_is_the_address_written_backwards() {
    assert_eq!(reverse_name(ip("203.0.113.5")), "5.113.0.203.in-addr.arpa");
    assert_eq!(
        reverse_name(ip("2001:db8::567:89ab")),
        "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    );
}

// =========================
// Reverse DNS
// =========================

#[test]
fn a_reverse_lookup_asks_one_question_about_the_address_only() {
    let fake = Fake::new(Ok(vec![ptr("dns.google.")]));
    let finding = reverse(&fake, ip("8.8.8.8"));
    assert_eq!(
        *fake.asked.borrow(),
        vec![("8.8.8.8.in-addr.arpa".to_string(), Kind::Ptr)]
    );
    assert_eq!(finding.status, Status::Ok);
    assert_eq!(finding.summary, "1 name");
    // The closing dot is dropped.
    assert_eq!(finding.details[0].value, "dns.google");
    assert_eq!(finding.id, "reverse-dns");
    assert!(finding.steps[0].ok);
}

#[test]
fn several_names_are_all_listed() {
    let fake = Fake::new(Ok(vec![ptr("a.example."), ptr("b.example.")]));
    let finding = reverse(&fake, ip("8.8.8.8"));
    assert_eq!(finding.summary, "2 names");
    assert_eq!(finding.details.len(), 2);
}

#[test]
fn no_name_is_an_answer_and_a_failed_question_is_not() {
    for failure in [Failure::NoRecords, Failure::NoSuchDomain] {
        let finding = reverse(&Fake::new(Err(failure)), ip("8.8.8.8"));
        assert_eq!(finding.status, Status::Info);
        assert_eq!(finding.summary, "No name");
        assert!(finding.steps[0].ok);
    }
    for failure in [
        Failure::Timeout,
        Failure::NoServers,
        Failure::ServerFailed,
        Failure::Refused,
        Failure::Other(5),
    ] {
        let finding = reverse(&Fake::new(Err(failure)), ip("8.8.8.8"));
        // It cannot say either way, so it is never shown as "no name".
        assert_eq!(finding.status, Status::Limited);
        assert_eq!(finding.summary, "Could not be checked");
        assert!(!finding.steps[0].ok);
    }
}

#[test]
fn an_address_returned_as_its_own_name_is_not_a_name() {
    // Whatever way the address or the question comes back, there is no name.
    for echoed in [
        "8.8.8.8",
        "8.8.8.8.",
        "8.8.8.8.in-addr.arpa",
        "8.8.8.8.IN-ADDR.ARPA.",
        "1.1.1.1",
        "2001:db8::1",
        "",
        ".",
    ] {
        let finding = reverse(&Fake::new(Ok(vec![ptr(echoed)])), ip("8.8.8.8"));
        assert_eq!(finding.status, Status::Info, "{echoed:?}");
        assert_eq!(finding.summary, "No name", "{echoed:?}");
        assert!(finding.details.is_empty(), "{echoed:?}");
        assert!(finding.steps[0].ok);
    }
    // A real name next to a useless one still shows only the real one.
    let mixed = Fake::new(Ok(vec![ptr("8.8.8.8"), ptr("dns.google.")]));
    let finding = reverse(&mixed, ip("8.8.8.8"));
    assert_eq!(finding.summary, "1 name");
    assert_eq!(finding.details[0].value, "dns.google");
    // An answer that is not a name record at all is not a name either.
    let wrong = Fake::new(Ok(vec![Record {
        name: "x".to_string(),
        ttl: 1,
        data: Data::A("8.8.8.8".parse().unwrap()),
    }]));
    assert_eq!(reverse(&wrong, ip("8.8.8.8")).summary, "No name");
}

#[test]
fn control_characters_in_a_returned_name_are_removed() {
    let fake = Fake::new(Ok(vec![ptr("evil\u{202e}\u{0}.example.")]));
    let finding = reverse(&fake, ip("8.8.8.8"));
    assert_eq!(finding.details[0].value, "evil.example");
    let long = Fake::new(Ok(vec![ptr(&"a".repeat(1000))]));
    assert_eq!(reverse(&long, ip("8.8.8.8")).details[0].value.len(), 253);
}

// =========================
// The external lookup
// =========================

const GOOGLE: &str = r#"{
  "ip": "8.8.8.8",
  "hostname": "dns.google",
  "city": "Mountain View",
  "region": "California",
  "country": "US",
  "loc": "38.0088,-122.1175",
  "org": "AS15169 Google LLC",
  "postal": "94043",
  "timezone": "America/Los_Angeles"
}"#;

#[test]
fn a_normal_reply_is_read_into_its_parts() {
    let owner = external::parse(ip("8.8.8.8"), GOOGLE).unwrap();
    assert_eq!(owner.asn.as_deref(), Some("AS15169"));
    assert_eq!(owner.organisation.as_deref(), Some("Google LLC"));
    assert_eq!(owner.city.as_deref(), Some("Mountain View"));
    assert_eq!(owner.region.as_deref(), Some("California"));
    assert_eq!(owner.country.as_deref(), Some("US"));
    assert_eq!(owner.timezone.as_deref(), Some("America/Los_Angeles"));
    assert!(!owner.not_public);
}

#[test]
fn a_reply_with_gaps_is_still_read() {
    let owner = external::parse(ip("8.8.8.8"), r#"{"ip":"8.8.8.8","org":"Some Network"}"#).unwrap();
    assert_eq!(owner.asn, None);
    assert_eq!(owner.organisation.as_deref(), Some("Some Network"));
    assert_eq!(owner.city, None);

    let only_number =
        external::parse(ip("8.8.8.8"), r#"{"ip":"8.8.8.8","org":"AS64500"}"#).unwrap();
    assert_eq!(only_number.asn, None);
    assert_eq!(only_number.organisation.as_deref(), Some("AS64500"));

    let empty = external::parse(ip("8.8.8.8"), r#"{"ip":"8.8.8.8"}"#).unwrap();
    assert_eq!(empty, Owner::default());
}

#[test]
fn a_reply_about_another_address_or_no_address_is_refused() {
    assert!(
        external::parse(ip("1.1.1.1"), GOOGLE)
            .unwrap_err()
            .contains("different address")
    );
    // The same address written another way is the same address.
    let owner = external::parse(
        ip("2001:4860:4860::8888"),
        r#"{"ip":"2001:4860:4860:0:0:0:0:8888"}"#,
    );
    assert!(owner.is_ok());
    for body in [
        "",
        "not json",
        "[]",
        "null",
        "42",
        r#"{"org":"AS1 X"}"#,
        r#"{"ip":42}"#,
        r#"{"ip":"not an address"}"#,
        r#"{"error":{"title":"Rate limit exceeded"}}"#,
    ] {
        let error = external::parse(ip("8.8.8.8"), body).unwrap_err();
        assert!(error.contains("could not read"), "{body}: {error}");
    }
}

#[test]
fn a_bogon_reply_says_the_address_is_not_public() {
    let owner = external::parse(ip("8.8.8.8"), r#"{"ip":"8.8.8.8","bogon":true}"#).unwrap();
    assert!(owner.not_public);
    let finding = findings::owner(ip("8.8.8.8"), &Ok(owner), Instant::now());
    assert_eq!(finding.status, Status::Info);
    assert_eq!(finding.summary, "No details");
}

#[test]
fn text_in_a_reply_is_cleaned_and_capped() {
    let body = serde_json::json!({
        "ip": "8.8.8.8",
        "org": format!("AS1 {}", "x".repeat(500)),
        "city": "Bad\u{0}City\u{202e}",
        "region": "   ",
        "country": 42,
    })
    .to_string();
    let owner = external::parse(ip("8.8.8.8"), &body).unwrap();
    assert_eq!(
        owner.organisation.as_ref().unwrap().len(),
        100 - "AS1 ".len()
    );
    assert_eq!(owner.city.as_deref(), Some("BadCity"));
    assert_eq!(owner.region, None);
    assert_eq!(owner.country, None);
}

#[test]
fn the_request_goes_to_one_named_service_and_carries_only_the_address() {
    assert_eq!(
        external::url_for(ip("8.8.8.8")),
        "https://ipinfo.io/8.8.8.8/json"
    );
    assert_eq!(
        external::url_for(ip("2001:4860:4860::8888")),
        "https://ipinfo.io/2001:4860:4860::8888/json"
    );
}

#[test]
fn the_owner_card_names_the_service_and_keeps_the_details_apart() {
    let owner = external::parse(ip("8.8.8.8"), GOOGLE).unwrap();
    let finding = findings::owner(ip("8.8.8.8"), &Ok(owner), Instant::now());
    assert_eq!(finding.id, "owner");
    assert_eq!(finding.status, Status::Ok);
    assert_eq!(finding.summary, "Google LLC · AS15169");
    let value = |label: &str| {
        finding
            .details
            .iter()
            .find(|detail| detail.label == label)
            .map(|detail| detail.value.as_str())
    };
    assert_eq!(value("Source"), Some("ipinfo.io (external service)"));
    assert_eq!(value("Organisation"), Some("Google LLC"));
    assert_eq!(value("Network (ASN)"), Some("AS15169"));
    assert_eq!(
        value("Approximate location"),
        Some("Mountain View, California, United States (US)")
    );
    assert_eq!(value("Time zone"), Some("America/Los_Angeles"));
    assert!(finding.checked.contains("ipinfo.io"));
    let note = finding.note.as_deref().unwrap();
    assert!(note.contains("approximate"));
    assert!(note.contains("exact physical location"));
    // The location row carries its own reason, folded away in the interface.
    let place = finding
        .details
        .iter()
        .find(|d| d.label == "Approximate location")
        .unwrap();
    assert!(
        place
            .reason
            .as_deref()
            .unwrap()
            .contains("does not show where a device or person physically is")
    );
    assert!(
        finding.steps[0]
            .method
            .contains("https://ipinfo.io/8.8.8.8/json")
    );
}

#[test]
fn a_failed_external_lookup_is_never_shown_as_a_result() {
    let failed: Result<Owner, String> = Err("ipinfo.io did not answer in time.".to_string());
    let finding = findings::owner(ip("8.8.8.8"), &failed, Instant::now());
    assert_eq!(finding.status, Status::Unknown);
    assert_eq!(finding.summary, "Could not be checked");
    assert_eq!(finding.details.len(), 1);
    assert!(!finding.steps[0].ok);
    assert_eq!(
        finding.note.as_deref(),
        Some("ipinfo.io did not answer in time.")
    );
}

// =========================
// Wording and shape
// =========================

#[test]
fn inspecting_an_address_sends_nothing_and_says_where_it_came_from() {
    let report = inspect("8.8.8.8").unwrap();
    assert_eq!(report.address, "8.8.8.8");
    assert_eq!(report.findings.len(), 1);
    let step = &report.findings[0].steps[0];
    assert!(step.method.contains("matched against the reserved"));
    assert!(!step.method.contains("HTTP"));
    assert_eq!(
        report.verdict.headline,
        "This is a public internet address."
    );
    assert_eq!(report.verdict.status, Status::Ok);
}

#[test]
fn nothing_is_called_safe_or_dangerous() {
    let mut all = Vec::new();
    for address in [
        "8.8.8.8",
        "192.168.1.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "0.0.0.0",
        "224.0.0.1",
        "203.0.113.5",
        "fd00::1",
        "4000::1",
        "64:ff9b::1",
    ] {
        let report = inspect(address).unwrap();
        all.push(report.verdict.headline.clone());
        all.push(report.verdict.detail.clone());
        let finding = &report.findings[0];
        all.push(finding.summary.clone());
        all.push(finding.checked.clone());
        all.push(finding.why.clone());
        all.extend(finding.note.clone());
        for detail in &finding.details {
            all.push(detail.value.clone());
            all.extend(detail.reason.clone());
        }
    }
    let owner = external::parse(ip("8.8.8.8"), GOOGLE).unwrap();
    for finding in [
        findings::owner(ip("8.8.8.8"), &Ok(owner), Instant::now()),
        reverse(&Fake::new(Ok(vec![ptr("dns.google.")])), ip("8.8.8.8")),
        reverse(&Fake::new(Err(Failure::NoRecords)), ip("8.8.8.8")),
    ] {
        all.push(finding.summary.clone());
        all.push(finding.why.clone());
        all.extend(finding.note.clone());
    }
    for text in all {
        let lower = text.to_lowercase();
        for banned in [
            "safe",
            "legitimate",
            "trustworthy",
            "malicious",
            "dangerous",
            "scam",
            "reputation",
        ] {
            assert!(!lower.contains(banned), "{banned}: {text}");
        }
    }
}

#[test]
fn the_report_has_the_shape_the_interface_reads() {
    let json = serde_json::to_value(inspect("8.8.8.8").unwrap()).unwrap();
    assert_eq!(json["address"], "8.8.8.8");
    assert_eq!(json["canReverse"], true);
    assert_eq!(json["canExternal"], true);
    assert_eq!(json["verdict"]["status"], "ok");
    assert_eq!(json["findings"][0]["id"], "ip-address");
}

// =========================
// Real lookups
// =========================

// Asks this PC's real DNS about 8.8.8.8, which is a well-known public address, not anything of
// the user's. Run with: cargo test -- --ignored --nocapture
#[cfg(windows)]
#[test]
#[ignore]
fn asks_windows_for_a_reverse_name() {
    // These steps only run while network access is on.
    crate::network::set_network_access(true);
    let finding = reverse(&crate::dns_lookup::resolver::WindowsDns, ip("8.8.8.8"));
    println!("{} | {:?}", finding.summary, finding.details);
    assert_eq!(finding.status, Status::Ok);
}

// Sends the well-known public address 8.8.8.8 to ipinfo.io, and nothing else.
// Run with: cargo test -- --ignored --nocapture
#[test]
#[ignore]
fn asks_the_real_service() {
    let outcome = tauri::async_runtime::block_on(external::fetch(ip("8.8.8.8")));
    println!("{outcome:?}");
    let owner = outcome.unwrap();
    assert!(owner.organisation.is_some());
}
