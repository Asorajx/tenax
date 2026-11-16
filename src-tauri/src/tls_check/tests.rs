// TLS Certificate run against a fake network, so every kind of certificate and every kind of
// failure can be tried without connecting to anything. The certificates are the test ones in
// fixtures.rs, and the Windows error codes are the real ones Windows gives.

use std::cell::RefCell;
use std::net::{IpAddr, SocketAddr};

use x509_parser::pem::parse_x509_pem;

use super::cert::{self, CertInfo, name_covers};
use super::fixtures::{LEAF, SELF_SIGNED, WEAK};
use super::session::{Der, Failure, Stage};
use super::*;
use crate::finding::{Detail, Status};

// Windows error codes.
const EXPIRED: u32 = 0x800B_0101;
const UNTRUSTED_ROOT: u32 = 0x800B_0109;
const NAME_MISMATCH: u32 = 0x800B_010F;
const REVOKED: u32 = 0x800B_010C;
const UNKNOWN: u32 = 0x8009_0300;

// Moments to judge a certificate at. The test certificates are valid from 2026 to 2126.
const IN_DATE: i64 = 1_893_456_000; // 2030-01-01
const AFTER_EXPIRY: i64 = 7_258_118_400; // 2200-01-01
const BEFORE_START: i64 = 1_577_836_800; // 2020-01-01

fn der(pem: &str) -> Der {
    parse_x509_pem(pem.as_bytes()).unwrap().1.contents
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn handshake_failure(code: u32, text: &str) -> Failure {
    Failure {
        stage: Stage::Handshake,
        code: Some(code),
        text: text.to_string(),
    }
}

fn connect_failure(text: &str) -> Failure {
    Failure {
        stage: Stage::Connect,
        code: Some(10060),
        text: text.to_string(),
    }
}

// A network with set answers. It remembers every handshake it was asked for.
struct Fake {
    addresses: Result<Vec<IpAddr>, String>,
    strict: Result<Der, Failure>,
    lenient: Result<Der, Failure>,
    handshakes: RefCell<Vec<(IpAddr, bool)>>,
    resolved: RefCell<Vec<String>>,
}

impl Fake {
    fn new(strict: Result<Der, Failure>, lenient: Result<Der, Failure>) -> Self {
        Fake {
            addresses: Ok(vec![ip("93.184.216.34")]),
            strict,
            lenient,
            handshakes: RefCell::new(Vec::new()),
            resolved: RefCell::new(Vec::new()),
        }
    }

    // A server whose certificate Windows trusts.
    fn trusted(pem: &str) -> Self {
        Fake::new(Ok(der(pem)), Ok(der(pem)))
    }

    // A server whose certificate Windows refuses, with the code Windows gave.
    fn refused(pem: &str, code: u32) -> Self {
        Fake::new(
            Err(handshake_failure(code, "Windows said no.")),
            Ok(der(pem)),
        )
    }

    fn resolving_to(mut self, addresses: &[&str]) -> Self {
        self.addresses = Ok(addresses.iter().map(|text| ip(text)).collect());
        self
    }

    fn calls(&self) -> Vec<(IpAddr, bool)> {
        self.handshakes.borrow().clone()
    }
}

impl Transport for Fake {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        self.resolved.borrow_mut().push(host.to_string());
        self.addresses.clone()
    }

    fn handshake(&self, addr: SocketAddr, _host: &str, verify: bool) -> Result<Der, Failure> {
        assert_eq!(addr.port(), 443, "only port 443 may be used");
        self.handshakes.borrow_mut().push((addr.ip(), verify));
        if verify {
            self.strict.clone()
        } else {
            self.lenient.clone()
        }
    }
}

fn check(fake: &Fake, host: &str, now: i64) -> TlsReport {
    run(fake, host, now).unwrap()
}

fn card<'a>(report: &'a TlsReport, id: &str) -> &'a Finding {
    report
        .findings
        .iter()
        .find(|finding| finding.id == id)
        .unwrap_or_else(|| panic!("no {id} card"))
}

fn row<'a>(finding: &'a Finding, label: &str) -> &'a Detail {
    finding
        .details
        .iter()
        .find(|detail| detail.label == label)
        .unwrap_or_else(|| panic!("no {label} row in {}", finding.id))
}

fn has_row(finding: &Finding, label: &str) -> bool {
    finding.details.iter().any(|detail| detail.label == label)
}

fn leaf() -> CertInfo {
    cert::read(&der(LEAF)).unwrap()
}

// =========================
// Reading certificates
// =========================

#[test]
fn a_certificate_is_read_into_plain_values() {
    let info = leaf();
    assert_eq!(info.subject, "O=Example Pty Ltd, CN=example.test");
    assert_eq!(info.issuer, "C=AU, O=Tenax Tests, CN=Tenax Test CA");
    assert_eq!(info.valid_from, "2026-11-16");
    assert_eq!(info.valid_until, "2126-10-23");
    assert_eq!(info.names, ["example.test", "*.example.test"]);
    assert_eq!(info.addresses, [ip("93.184.216.34")]);
    assert!(!info.self_signed);
    assert_eq!(info.key, "RSA, 2048 bits");
    assert_eq!(info.signature, "SHA-256 with RSA");
    assert!(info.key_weakness.is_none() && info.signature_weakness.is_none());
    assert!(!info.serial.is_empty());

    let own = cert::read(&der(SELF_SIGNED)).unwrap();
    assert!(own.self_signed);
    assert_eq!(own.key, "Elliptic curve, P-256");
    assert_eq!(own.signature, "SHA-256 with ECDSA");

    let weak = cert::read(&der(WEAK)).unwrap();
    assert_eq!(weak.key, "RSA, 1024 bits");
    assert_eq!(weak.signature, "SHA-1 with RSA");
    assert!(weak.key_weakness.is_some() && weak.signature_weakness.is_some());
}

#[test]
fn bytes_that_are_not_a_certificate_are_refused_without_a_crash() {
    for bytes in [
        &b""[..],
        b"x",
        b"not a certificate",
        &[0x30, 0x82, 0xff, 0xff],
        &[0; 64],
    ] {
        assert!(cert::read(bytes).is_err());
    }
    // A real certificate cut short, and with its end changed.
    let whole = der(LEAF);
    for length in [10, 100, whole.len() - 1] {
        assert!(cert::read(&whole[..length]).is_err(), "{length}");
    }
}

#[test]
fn wildcards_cover_one_part_and_nothing_more() {
    for (pattern, host, expected) in [
        ("example.test", "example.test", true),
        ("example.test", "www.example.test", false),
        ("*.example.test", "www.example.test", true),
        ("*.example.test", "example.test", false),
        ("*.example.test", "a.b.example.test", false),
        ("*.example.test", ".example.test", false),
        ("*.com", "example.com", false),
        ("*", "example.com", false),
        ("www.*.test", "www.a.test", false),
        ("example.test.", "example.test", true),
    ] {
        assert_eq!(name_covers(pattern, host), expected, "{pattern} for {host}");
    }
    let info = leaf();
    assert!(info.covers("example.test"));
    assert!(info.covers("www.example.test"));
    assert!(info.covers("93.184.216.34"));
    assert!(!info.covers("other.test"));
    assert!(!info.covers("93.184.216.35"));
}

// =========================
// A valid certificate
// =========================

#[test]
fn a_certificate_windows_trusts_is_reported_as_valid() {
    let fake = Fake::trusted(LEAF);
    let report = check(&fake, "example.test", IN_DATE);

    assert_eq!(report.verdict.status, Status::Ok);
    assert_eq!(report.verdict.headline, "Certificate accepted by Windows.");
    let trust = card(&report, "trust");
    assert_eq!(trust.status, Status::Ok);
    assert_eq!(trust.summary, "Accepted by Windows");
    assert_eq!(row(trust, "Connected to").value, "93.184.216.34");
    assert!(trust.note.as_deref().unwrap().contains("revoked"));

    assert_eq!(card(&report, "names").summary, "Covers example.test");
    assert_eq!(card(&report, "validity").status, Status::Ok);
    assert_eq!(card(&report, "issuer").summary, "Issued by Tenax Test CA");
    assert_eq!(card(&report, "key").status, Status::Ok);
    assert_eq!(
        row(card(&report, "issuer"), "Subject").value,
        "O=Example Pty Ltd, CN=example.test"
    );

    // Only one handshake was needed, and it was the one that checks the certificate.
    assert_eq!(fake.calls(), [(ip("93.184.216.34"), true)]);
}

#[test]
fn a_wildcard_name_and_an_ip_address_can_be_checked() {
    let report = check(&Fake::trusted(LEAF), "www.example.test", IN_DATE);
    assert_eq!(card(&report, "names").summary, "Covers www.example.test");
    assert_eq!(row(card(&report, "names"), "Name").value, "example.test");
    assert!(
        card(&report, "names")
            .details
            .iter()
            .any(|d| d.value == "*.example.test · matches")
    );

    let fake = Fake::trusted(LEAF);
    let report = check(&fake, "93.184.216.34", IN_DATE);
    // An address that was typed is not looked up, and is still judged against the certificate.
    assert!(fake.resolved.borrow().is_empty());
    assert_eq!(card(&report, "names").summary, "Covers 93.184.216.34");
}

#[test]
fn a_certificate_ending_soon_is_pointed_out_even_when_trusted() {
    let end = leaf().not_after;
    let report = check(&Fake::trusted(LEAF), "example.test", end - 10 * 86_400);
    let validity = card(&report, "validity");
    assert_eq!(validity.status, Status::Warning);
    assert_eq!(validity.summary, "Expires in 10 days");
    assert!(validity.action.as_deref().unwrap().contains("renew"));
    // The certificate is still trusted, and the verdict says there is something to note.
    assert_eq!(card(&report, "trust").status, Status::Ok);
    assert_eq!(report.verdict.status, Status::Warning);
    assert_eq!(
        report.verdict.headline,
        "Certificate accepted by Windows, with points worth noting."
    );

    let today = check(&Fake::trusted(LEAF), "example.test", end - 3_600);
    assert_eq!(
        card(&today, "validity").summary,
        "Expires in less than a day"
    );
}

#[test]
fn a_weak_key_and_signature_are_pointed_out() {
    let report = check(&Fake::trusted(WEAK), "weak.test", IN_DATE);
    let key = card(&report, "key");
    assert_eq!(key.status, Status::Warning);
    assert!(row(key, "Public key").reason.is_some());
    assert!(row(key, "Signature algorithm").reason.is_some());
    assert!(key.action.is_some());
}

// =========================
// Certificate problems
// =========================

#[test]
fn an_expired_certificate_is_explained_and_never_trusted() {
    let fake = Fake::refused(LEAF, EXPIRED);
    let report = check(&fake, "example.test", AFTER_EXPIRY);

    assert_eq!(report.verdict.headline, "This certificate has problems.");
    assert_eq!(report.verdict.status, Status::Warning);
    let trust = card(&report, "trust");
    assert_eq!(trust.summary, "Not trusted: expired");
    assert_eq!(trust.status, Status::Warning);
    let expired = row(trust, "Expired");
    assert!(expired.value.contains("2126-10-23"));
    // The reason mentions the PC's clock, since a wrong clock looks like an expired certificate.
    assert!(
        expired
            .reason
            .as_deref()
            .unwrap()
            .contains("date or time on this PC")
    );
    assert!(row(trust, "Windows said").value.starts_with("0x800B0101"));
    assert!(
        card(&report, "validity")
            .summary
            .starts_with("Expired about")
    );
    assert!(trust.note.as_deref().unwrap().contains("still not trusted"));
    assert!(
        trust
            .action
            .as_deref()
            .unwrap()
            .contains("Avoid signing in")
    );

    // The checking handshake came first, and the reading-only one only after it failed.
    assert_eq!(
        fake.calls(),
        [(ip("93.184.216.34"), true), (ip("93.184.216.34"), false)]
    );
}

#[test]
fn a_certificate_that_has_not_started_is_explained() {
    let report = check(&Fake::refused(LEAF, EXPIRED), "example.test", BEFORE_START);
    let trust = card(&report, "trust");
    assert!(has_row(trust, "Not valid yet"));
    assert!(!has_row(trust, "Expired"));
    assert_eq!(card(&report, "validity").summary, "Starts in about 7 years");
}

#[test]
fn an_expired_certificate_above_an_in_date_one_is_told_apart() {
    // Windows says expired, but this certificate's own dates are fine.
    let report = check(&Fake::refused(LEAF, EXPIRED), "example.test", IN_DATE);
    let trust = card(&report, "trust");
    assert!(has_row(trust, "A certificate above it has expired"));
    assert!(!has_row(trust, "Expired"));
}

#[test]
fn a_self_signed_certificate_is_explained() {
    let report = check(
        &Fake::refused(SELF_SIGNED, UNTRUSTED_ROOT),
        "selfsigned.test",
        IN_DATE,
    );
    assert_eq!(report.verdict.status, Status::Risk);
    let trust = card(&report, "trust");
    assert_eq!(trust.summary, "Not trusted: signed by itself");
    assert_eq!(trust.status, Status::Risk);
    assert!(has_row(trust, "Signed by itself"));
    // It is reported as signed by itself, and not also as an unknown issuer.
    assert!(!has_row(trust, "Issuer not trusted"));
    assert_eq!(card(&report, "issuer").summary, "Signed by itself");
    assert_eq!(card(&report, "issuer").status, Status::Warning);
}

#[test]
fn a_certificate_from_an_untrusted_authority_is_explained() {
    let report = check(
        &Fake::refused(LEAF, UNTRUSTED_ROOT),
        "example.test",
        IN_DATE,
    );
    let trust = card(&report, "trust");
    assert_eq!(trust.summary, "Not trusted: issuer not trusted");
    assert_eq!(trust.status, Status::Risk);
    let row = row(trust, "Issuer not trusted");
    assert!(row.reason.as_deref().unwrap().contains("workplace"));
    assert!(!has_row(trust, "Signed by itself"));
}

#[test]
fn a_certificate_for_another_name_is_explained() {
    let fake = Fake::refused(LEAF, NAME_MISMATCH);
    let report = check(&fake, "other.test", IN_DATE);
    let trust = card(&report, "trust");
    assert_eq!(trust.summary, "Not trusted: issued for other names");
    assert_eq!(trust.status, Status::Risk);
    assert!(
        row(trust, "Issued for other names")
            .value
            .contains("other.test")
    );
    let names = card(&report, "names");
    assert_eq!(names.summary, "Does not cover other.test");
    assert_eq!(names.status, Status::Risk);
    assert!(names.details.iter().any(|d| d.value == "example.test"));
}

#[test]
fn several_problems_are_all_listed_with_the_serious_ones_first() {
    // Windows reports only the first problem. The certificate shows the others.
    let report = check(&Fake::refused(LEAF, EXPIRED), "other.test", AFTER_EXPIRY);
    let trust = card(&report, "trust");
    assert_eq!(trust.summary, "Not trusted: 2 problems");
    let labels: Vec<&str> = trust.details.iter().map(|d| d.label.as_str()).collect();
    let mismatch = labels
        .iter()
        .position(|l| *l == "Issued for other names")
        .unwrap();
    let expired = labels.iter().position(|l| *l == "Expired").unwrap();
    assert!(mismatch < expired);
    assert_eq!(trust.status, Status::Risk);
    assert!(report.verdict.detail.contains("issued for other names"));
    assert!(report.verdict.detail.contains("expired"));
}

#[test]
fn a_revoked_or_unrecognised_refusal_is_still_never_trusted() {
    let revoked = check(&Fake::refused(LEAF, REVOKED), "example.test", IN_DATE);
    assert_eq!(card(&revoked, "trust").summary, "Not trusted: revoked");

    let unknown = check(&Fake::refused(LEAF, UNKNOWN), "example.test", IN_DATE);
    let trust = card(&unknown, "trust");
    assert_eq!(trust.summary, "Not trusted: rejected by Windows");
    assert!(row(trust, "Windows said").value.starts_with("0x80090300"));
    assert_ne!(unknown.verdict.status, Status::Ok);
}

#[test]
fn a_problem_certificate_is_never_ok_whatever_the_certificate_says() {
    // Even a fine-looking certificate, if Windows refused it, is not trusted.
    for code in [EXPIRED, UNTRUSTED_ROOT, NAME_MISMATCH, REVOKED, UNKNOWN] {
        let report = check(&Fake::refused(LEAF, code), "example.test", IN_DATE);
        assert_ne!(card(&report, "trust").status, Status::Ok, "{code:#x}");
        assert_ne!(report.verdict.status, Status::Ok, "{code:#x}");
        assert!(card(&report, "trust").summary.starts_with("Not trusted"));
    }
}

#[test]
fn a_refused_certificate_that_cannot_be_read_is_still_reported_as_not_trusted() {
    let fake = Fake::new(
        Err(handshake_failure(UNTRUSTED_ROOT, "Untrusted.")),
        Ok(b"not a certificate".to_vec()),
    );
    let report = check(&fake, "example.test", IN_DATE);
    assert_eq!(
        card(&report, "trust").summary,
        "Not trusted: rejected by Windows"
    );
    assert_eq!(card(&report, "issuer").summary, "Could not be read");
}

// =========================
// Connection failures
// =========================

#[test]
fn a_name_that_cannot_be_found_is_a_connection_failure_and_not_a_certificate_problem() {
    let mut fake = Fake::trusted(LEAF);
    fake.addresses = Err("No such host is known. (os error 11001)".to_string());
    let report = check(&fake, "nothing.example.test", IN_DATE);
    assert_eq!(report.verdict.status, Status::Unknown);
    assert_eq!(report.verdict.headline, "The server could not be found.");
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].id, "connection");
    assert_eq!(report.findings[0].summary, "Server not found");
    assert!(fake.calls().is_empty());
}

#[test]
fn a_server_that_cannot_be_reached_is_a_connection_failure() {
    let fake = Fake::new(
        Err(connect_failure("Timed out.")),
        Err(connect_failure("Timed out.")),
    )
    .resolving_to(&["93.184.216.34", "93.184.216.35", "93.184.216.36"]);
    let report = check(&fake, "example.test", IN_DATE);
    assert_eq!(report.verdict.status, Status::Unknown);
    assert_eq!(report.verdict.headline, "Could not connect to the server.");
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].summary, "Could not connect");
    // A server that cannot be reached is never asked to skip its checks, and only two
    // addresses are tried.
    assert_eq!(
        fake.calls(),
        [(ip("93.184.216.34"), true), (ip("93.184.216.35"), true)]
    );
    assert!(!report.findings[0].steps.last().unwrap().ok);
}

#[test]
fn the_next_address_is_tried_when_the_first_cannot_be_reached() {
    struct SecondWorks(Fake);
    impl Transport for SecondWorks {
        fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
            self.0.resolve(host)
        }
        fn handshake(&self, addr: SocketAddr, host: &str, verify: bool) -> Result<Der, Failure> {
            if addr.ip() == ip("93.184.216.34") {
                self.0.handshakes.borrow_mut().push((addr.ip(), verify));
                return Err(connect_failure("Refused."));
            }
            self.0.handshake(addr, host, verify)
        }
    }
    let fake = SecondWorks(Fake::trusted(LEAF).resolving_to(&["93.184.216.34", "93.184.216.35"]));
    let report = run(&fake, "example.test", IN_DATE).unwrap();
    assert_eq!(report.verdict.status, Status::Ok);
    assert_eq!(
        row(card(&report, "trust"), "Connected to").value,
        "93.184.216.35"
    );
}

#[test]
fn a_failed_handshake_with_nothing_to_read_is_a_connection_failure() {
    let failure = handshake_failure(0x8009_0331, "The client and server cannot communicate.");
    let fake = Fake::new(Err(failure.clone()), Err(failure));
    let report = check(&fake, "example.test", IN_DATE);
    assert_eq!(report.verdict.status, Status::Unknown);
    assert_eq!(
        report.verdict.headline,
        "Could not complete a secure connection."
    );
    assert_eq!(report.findings.len(), 1);
    let connection = &report.findings[0];
    assert_eq!(connection.summary, "Secure connection failed");
    assert!(
        row(connection, "Windows said")
            .value
            .starts_with("0x80090331")
    );
    assert!(
        connection
            .note
            .as_deref()
            .unwrap()
            .contains("not a finding about the site")
    );
    // Nothing is said about a certificate, because none was read.
    assert!(
        report
            .findings
            .iter()
            .all(|f| f.id != "names" && f.id != "key")
    );
}

// =========================
// What may be connected to
// =========================

#[test]
fn private_and_other_non_public_addresses_are_refused_before_connecting() {
    for address in [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "192.0.2.1",
        "198.18.0.1",
        "240.0.0.1",
        "::1",
        "::",
        "fe80::1",
        "fd00::1",
        "ff02::1",
        "2001:db8::1",
        "64:ff9b::808:808",
        "2002:c0a8:101::1",
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        "[::1]",
        "https://127.0.0.1/",
        "::ffff:10.0.0.1",
        "::ffff:127.0.0.1",
    ] {
        let fake = Fake::trusted(LEAF);
        let error = run(&fake, address, IN_DATE)
            .err()
            .unwrap_or_else(|| panic!("{address} was allowed"));
        assert!(error.contains("not a public address"), "{address}: {error}");
        assert!(fake.calls().is_empty(), "{address} was connected to");
    }
}

#[test]
fn a_name_that_leads_to_a_private_address_is_refused_after_it_is_looked_up() {
    for addresses in [
        &["127.0.0.1"][..],
        &["10.1.2.3"],
        &["192.168.0.10"],
        &["::1"],
        &["fd00::5"],
        &["169.254.169.254"],
        // A mix is refused too, so a name cannot be pointed at both.
        &["93.184.216.34", "127.0.0.1"],
        &["127.0.0.1", "93.184.216.34"],
        &["8.8.8.8", "fe80::1"],
    ] {
        let fake = Fake::trusted(LEAF).resolving_to(addresses);
        let error = run(&fake, "sneaky.example.test", IN_DATE)
            .err()
            .unwrap_or_else(|| panic!("{addresses:?} was allowed"));
        assert!(error.contains("sneaky.example.test points to"), "{error}");
        assert!(error.contains("not a public address"), "{error}");
        assert!(fake.calls().is_empty(), "{addresses:?} was connected to");
        // The name was looked up, which is how the refusal was reached.
        assert_eq!(*fake.resolved.borrow(), ["sneaky.example.test"]);
    }
}

#[test]
fn a_name_with_no_addresses_is_refused() {
    let fake = Fake::trusted(LEAF).resolving_to(&[]);
    assert!(run(&fake, "example.test", IN_DATE).is_err());
    assert!(fake.calls().is_empty());
}

#[test]
fn only_ordinary_public_addresses_pass() {
    for address in [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "2606:4700:4700::1111",
        "2a00:1450:4001::1",
    ] {
        assert!(target::is_public(ip(address)), "{address}");
    }
}

#[test]
fn only_port_443_is_accepted_and_the_input_is_cleaned() {
    for (typed, host) in [
        ("example.com", "example.com"),
        ("  Example.COM  ", "example.com"),
        ("example.com:443", "example.com"),
        ("https://example.com/path?x=1", "example.com"),
        ("https://user@example.com:443/", "example.com"),
        ("http://example.com", "example.com"),
        ("example.com.", "example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("8.8.8.8", "8.8.8.8"),
        ("8.8.8.8:443", "8.8.8.8"),
        ("[2606:4700:4700::1111]:443", "2606:4700:4700::1111"),
        ("2606:4700:4700::1111", "2606:4700:4700::1111"),
    ] {
        assert_eq!(target::parse(typed).unwrap().host, host, "{typed}");
    }
    for typed in [
        "example.com:80",
        "example.com:8443",
        "https://example.com:8443/",
        "8.8.8.8:22",
        "[2606:4700:4700::1111]:25",
        "example.com:99999",
    ] {
        let error = target::parse(typed).unwrap_err();
        assert!(
            error.contains("port 443") || error.contains("not valid"),
            "{typed}: {error}"
        );
    }
    for typed in [
        "",
        "   ",
        "example",
        "exa mple.com",
        "http://",
        "a..b",
        "[::1",
    ] {
        assert!(target::parse(typed).is_err(), "{typed:?}");
    }
    assert!(
        target::parse(&"a".repeat(3000))
            .unwrap_err()
            .contains("too long")
    );
}

#[test]
fn odd_text_never_crashes_the_reader() {
    let pieces = [
        "", ":", "::", "[", "]", "/", "//", "://", "@", ".", "..", "443", ":443", "99999",
        "example", ".com", "é", "\u{202e}", "\u{0}", "http", "%", "1.2.3.4", "::1", "ffff", " ",
    ];
    for a in pieces {
        for b in pieces {
            for c in pieces {
                let _ = target::parse(&format!("{a}{b}{c}"));
            }
        }
    }
}

// =========================
// Wording and shape
// =========================

#[test]
fn nothing_is_called_safe_or_dangerous_and_revocation_is_not_claimed() {
    let mut reports = vec![
        check(&Fake::trusted(LEAF), "example.test", IN_DATE),
        check(&Fake::trusted(WEAK), "weak.test", IN_DATE),
        check(&Fake::refused(LEAF, EXPIRED), "other.test", AFTER_EXPIRY),
        check(
            &Fake::refused(SELF_SIGNED, UNTRUSTED_ROOT),
            "selfsigned.test",
            IN_DATE,
        ),
        check(&Fake::refused(LEAF, REVOKED), "example.test", IN_DATE),
        check(&Fake::refused(LEAF, UNKNOWN), "example.test", BEFORE_START),
    ];
    let failure = handshake_failure(0x8009_0331, "Failed.");
    reports.push(check(
        &Fake::new(Err(failure.clone()), Err(failure)),
        "example.test",
        IN_DATE,
    ));

    for report in reports {
        let mut all = vec![
            report.verdict.headline.clone(),
            report.verdict.detail.clone(),
        ];
        for finding in &report.findings {
            all.push(finding.summary.clone());
            all.push(finding.checked.clone());
            all.push(finding.why.clone());
            all.extend(finding.action.clone());
            all.extend(finding.note.clone());
            for detail in &finding.details {
                all.push(detail.value.clone());
                all.extend(detail.reason.clone());
            }
        }
        for text in all {
            // The one allowed use of the word is to say acceptance does not mean the site is safe.
            let lower = text
                .to_lowercase()
                .replace("does not mean the website itself is safe", "");
            for banned in [
                "safe",
                "legitimate",
                "trustworthy",
                "malicious",
                "dangerous",
                "scam",
                "secure site",
            ] {
                assert!(!lower.contains(banned), "{banned}: {text}");
            }
        }
    }
}

#[test]
fn the_steps_say_what_was_done_and_that_no_web_request_was_made() {
    let report = check(&Fake::refused(LEAF, EXPIRED), "example.test", AFTER_EXPIRY);
    let steps = &report.findings[0].steps;
    assert!(steps.len() >= 5);
    assert!(
        steps
            .iter()
            .any(|s| s.action.contains("Checked the addresses are public"))
    );
    let methods: Vec<&str> = steps.iter().map(|s| s.method.as_str()).collect();
    assert!(
        methods
            .iter()
            .any(|m| m.contains("certificate checked against the Windows trust store"))
    );
    assert!(
        methods
            .iter()
            .any(|m| m.contains("certificate checks switched off")
                && m.contains("Used only to read"))
    );
    assert!(methods.iter().all(|m| !m.contains("HTTP GET")));
    // Only the first card carries the steps.
    assert!(report.findings[1..].iter().all(|f| f.steps.is_empty()));
    // The checking handshake failed, and the reading one worked.
    let failed: Vec<bool> = steps.iter().map(|s| s.ok).collect();
    assert!(failed.contains(&false) && failed.contains(&true));
}

#[test]
fn the_report_has_the_shape_the_interface_reads() {
    let json = serde_json::to_value(check(&Fake::trusted(LEAF), "example.test", IN_DATE)).unwrap();
    assert_eq!(json["verdict"]["status"], "ok");
    let ids: Vec<&str> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["trust", "names", "validity", "issuer", "key"]);
}

#[test]
fn long_name_lists_are_capped() {
    let mut info = leaf();
    info.names = (0..40).map(|n| format!("n{n}.example.test")).collect();
    let card = findings::build(
        "other.test",
        None,
        &Outcome::Reached {
            trust: Trust::Trusted,
            cert: Ok(info),
        },
        IN_DATE,
    )
    .1
    .into_iter()
    .find(|f| f.id == "names")
    .unwrap();
    assert!(card.details.len() <= 13);
    assert_eq!(card.details.last().unwrap().label, "More");
}

// =========================
// Real handshakes
// =========================

// Connects to public test servers that have a known certificate problem, to check the whole
// path with Windows. Only a handshake is made. Run with: cargo test -- --ignored --nocapture
#[cfg(windows)]
#[test]
#[ignore]
fn checks_real_servers() {
    for (host, expect) in [
        ("example.com", "Certificate accepted by Windows."),
        ("expired.badssl.com", "This certificate has problems."),
        ("self-signed.badssl.com", "This certificate has problems."),
        (
            "untrusted-root.badssl.com",
            "This certificate has problems.",
        ),
        ("wrong.host.badssl.com", "This certificate has problems."),
        ("nothing.invalid", "The server could not be found."),
    ] {
        let report = run(&Windows, host, unix_now()).unwrap();
        println!(
            "{host}: {} | {}",
            report.verdict.headline,
            report
                .findings
                .iter()
                .map(|f| format!("{}={}", f.id, f.summary))
                .collect::<Vec<_>>()
                .join(" | ")
        );
        if std::env::var("TENAX_PRINT_JSON").is_ok() {
            println!("JSON:{host}:{}", serde_json::to_string(&report).unwrap());
        }
        assert_eq!(report.verdict.headline, expect, "{host}");
    }
    // A private address is refused with no connection.
    assert!(run(&Windows, "127.0.0.1", unix_now()).is_err());
    assert!(run(&Windows, "localhost", unix_now()).is_err());
}

#[test]
fn every_result_says_what_tenax_did_not_check() {
    // Acceptance is not a guarantee, revocation is not checked and only one certificate is shown.
    let accepted = check(&Fake::trusted(LEAF), "example.test", IN_DATE);
    let note = card(&accepted, "trust").note.clone().unwrap();
    assert!(note.contains("does not mean the website itself is safe"));
    assert!(note.contains("does not check whether a certificate has been revoked"));
    assert!(note.contains("only the server's own certificate"));
    assert!(
        accepted
            .verdict
            .detail
            .contains("does not mean the website itself is safe")
    );
    assert!(accepted.verdict.detail.contains("revoked"));
    assert!(
        card(&accepted, "issuer")
            .note
            .as_deref()
            .unwrap()
            .contains("only the server's own certificate")
    );

    let refused = check(&Fake::refused(LEAF, EXPIRED), "example.test", AFTER_EXPIRY);
    let note = card(&refused, "trust").note.clone().unwrap();
    assert!(note.contains("does not check whether a certificate has been revoked"));
    assert!(note.contains("only the server's own certificate"));
}
