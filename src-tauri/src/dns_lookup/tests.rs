// The lookup run against a fake DNS, so every kind of answer can be tried without a network.

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::records::{Answer, Data, Failure, Kind, Record, Resolver};
use super::*;
use crate::finding::{Detail, Status};

// A DNS with set answers. It remembers every question it was asked.
struct Fake {
    answers: HashMap<(String, Kind), Answer>,
    asked: RefCell<Vec<(String, Kind)>>,
}

impl Fake {
    fn new() -> Self {
        Fake {
            answers: HashMap::new(),
            asked: RefCell::new(Vec::new()),
        }
    }

    fn with(mut self, name: &str, kind: Kind, answer: Answer) -> Self {
        self.answers.insert((name.to_string(), kind), answer);
        self
    }

    fn questions(&self) -> Vec<(String, Kind)> {
        self.asked.borrow().clone()
    }
}

impl Resolver for Fake {
    fn query(&self, name: &str, kind: Kind) -> Answer {
        self.asked.borrow_mut().push((name.to_string(), kind));
        self.answers
            .get(&(name.to_string(), kind))
            .cloned()
            .unwrap_or(Err(Failure::NoRecords))
    }
}

fn rec(name: &str, ttl: u32, data: Data) -> Record {
    Record {
        name: name.to_string(),
        ttl,
        data,
    }
}

fn txt(name: &str, text: &str) -> Record {
    rec(name, 300, Data::Txt(text.to_string()))
}

fn mx(name: &str, preference: u16, host: &str) -> Record {
    rec(
        name,
        300,
        Data::Mx {
            preference,
            host: host.to_string(),
        },
    )
}

const NAME: &str = "example.org";

// A domain that is set up well.
fn healthy() -> Fake {
    Fake::new()
        .with(
            NAME,
            Kind::A,
            Ok(vec![rec(
                NAME,
                300,
                Data::A(Ipv4Addr::new(93, 184, 216, 34)),
            )]),
        )
        .with(
            NAME,
            Kind::Aaaa,
            Ok(vec![rec(NAME, 300, Data::Aaaa(Ipv6Addr::LOCALHOST))]),
        )
        .with(
            NAME,
            Kind::Mx,
            Ok(vec![
                mx(NAME, 20, "mail2.example.org."),
                mx(NAME, 10, "mail1.example.org."),
            ]),
        )
        .with(
            NAME,
            Kind::Ns,
            Ok(vec![
                rec(NAME, 3600, Data::Ns("ns1.example.org.".into())),
                rec(NAME, 3600, Data::Ns("ns2.example.org.".into())),
            ]),
        )
        .with(
            NAME,
            Kind::Soa,
            Ok(vec![rec(
                NAME,
                3600,
                Data::Soa {
                    primary: "ns1.example.org.".into(),
                    admin: "hostmaster.example.org.".into(),
                    serial: 2030010101,
                },
            )]),
        )
        .with(
            NAME,
            Kind::Txt,
            Ok(vec![
                txt(NAME, "v=spf1 include:_spf.mailer.example -all"),
                txt(NAME, "google-site-verification=abc123"),
            ]),
        )
        .with(
            "_dmarc.example.org",
            Kind::Txt,
            Ok(vec![txt(
                "_dmarc.example.org",
                "v=DMARC1; p=reject; rua=mailto:reports@example.org",
            )]),
        )
}

fn look_up(fake: &Fake) -> DnsReport {
    run(fake, NAME).expect("the lookup ran")
}

fn card<'a>(report: &'a DnsReport, id: &str) -> &'a Finding {
    report
        .findings
        .iter()
        .find(|f| f.id == id)
        .expect("card exists")
}

fn status(report: &DnsReport, id: &str) -> Status {
    card(report, id).status
}

fn row<'a>(report: &'a DnsReport, id: &str, label: &str) -> &'a Detail {
    card(report, id)
        .details
        .iter()
        .find(|d| d.label == label)
        .expect("row exists")
}

// =========================
// A domain that is set up well
// =========================

#[test]
fn a_well_set_up_domain_reads_clearly() {
    let report = look_up(&healthy());
    assert_eq!(report.verdict.status, Status::Ok);
    assert_eq!(report.verdict.headline, "DNS records found.");

    let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(
        ids,
        ["addresses", "mail", "names", "text", "email-security"]
    );
    assert!(
        report.findings.iter().all(|f| f.status == Status::Ok),
        "{:?}",
        report.findings.iter().map(|f| f.status).collect::<Vec<_>>()
    );

    assert_eq!(
        row(&report, "addresses", "IPv4").value,
        "93.184.216.34 · TTL 5 min"
    );
    assert_eq!(row(&report, "addresses", "IPv6").value, "::1 · TTL 5 min");
    // Mail servers are listed by priority, without the dot that ends a name.
    let mail: Vec<&str> = card(&report, "mail")
        .details
        .iter()
        .map(|d| d.value.as_str())
        .collect();
    assert_eq!(
        mail,
        [
            "mail1.example.org · TTL 5 min",
            "mail2.example.org · TTL 5 min"
        ]
    );
    assert_eq!(card(&report, "mail").details[0].label, "Priority 10");
    assert_eq!(
        row(&report, "names", "Primary server").value,
        "ns1.example.org"
    );
    assert_eq!(
        row(&report, "names", "Contact").value,
        "hostmaster@example.org"
    );
    assert_eq!(row(&report, "names", "Serial").value, "2030010101");
    assert_eq!(
        row(&report, "text", "SPF").value,
        "v=spf1 include:_spf.mailer.example -all"
    );
    assert_eq!(
        row(&report, "text", "Verification").value,
        "google-site-verification=abc123"
    );
    assert_eq!(
        row(&report, "email-security", "SPF").value,
        "Strict: only the listed servers may send · 1 included service"
    );
    assert!(
        row(&report, "email-security", "DMARC")
            .value
            .starts_with("Reject")
    );
    assert_eq!(
        row(&report, "email-security", "Reports sent to").value,
        "mailto:reports@example.org"
    );
}

#[test]
fn only_this_domain_is_ever_asked_about_and_only_the_seven_questions() {
    let fake = healthy();
    look_up(&fake);
    let mut asked = fake.questions();
    asked.sort_by_key(|(name, kind)| (name.clone(), format!("{kind:?}")));

    let mut expected: Vec<(String, Kind)> = [
        Kind::A,
        Kind::Aaaa,
        Kind::Mx,
        Kind::Ns,
        Kind::Txt,
        Kind::Soa,
    ]
    .into_iter()
    .map(|kind| (NAME.to_string(), kind))
    .collect();
    expected.push(("_dmarc.example.org".to_string(), Kind::Txt));
    expected.sort_by_key(|(name, kind)| (name.clone(), format!("{kind:?}")));
    assert_eq!(asked, expected);
}

#[test]
fn an_alias_chain_is_shown_once_and_the_address_is_counted_once() {
    let fake = Fake::new()
        .with(
            NAME,
            Kind::A,
            Ok(vec![
                rec(NAME, 60, Data::Cname("edge.cdn.example.net.".into())),
                rec(
                    "edge.cdn.example.net",
                    60,
                    Data::A(Ipv4Addr::new(203, 0, 113, 7)),
                ),
            ]),
        )
        .with(
            NAME,
            Kind::Aaaa,
            Ok(vec![rec(
                NAME,
                60,
                Data::Cname("edge.cdn.example.net.".into()),
            )]),
        );
    let report = look_up(&fake);
    let aliases = card(&report, "addresses")
        .details
        .iter()
        .filter(|d| d.label == "Alias")
        .count();
    assert_eq!(aliases, 1);
    assert_eq!(card(&report, "addresses").summary, "1 address");
    assert_eq!(
        row(&report, "addresses", "Alias").value,
        "example.org → edge.cdn.example.net"
    );
}

#[test]
fn counts_read_naturally_and_a_long_list_of_text_records_is_capped() {
    let two = Fake::new().with(
        NAME,
        Kind::A,
        Ok(vec![
            rec(NAME, 60, Data::A(Ipv4Addr::new(1, 1, 1, 1))),
            rec(NAME, 60, Data::A(Ipv4Addr::new(2, 2, 2, 2))),
        ]),
    );
    let report = look_up(&two);
    assert_eq!(card(&report, "addresses").summary, "2 addresses");
    // The log says the same, and never says "addresss".
    assert_eq!(
        card(&report, "addresses").steps[1].result,
        "2 addresses read"
    );

    let many: Vec<Record> = (0..30)
        .map(|i| txt(NAME, &format!("site-verification={i}")))
        .collect();
    let report = look_up(&healthy().with(NAME, Kind::Txt, Ok(many)));
    let text = card(&report, "text");
    // Every record is counted, and only some are listed.
    assert_eq!(text.summary, "30 text records");
    assert_eq!(text.details.len(), 13);
    assert_eq!(text.details[12].label, "More");
    assert_eq!(text.details[12].value, "18 more");
}

#[test]
fn times_to_live_are_shown_in_a_readable_unit() {
    let fake = Fake::new().with(
        NAME,
        Kind::A,
        Ok(vec![
            rec(NAME, 59, Data::A(Ipv4Addr::new(1, 1, 1, 1))),
            rec(NAME, 7200, Data::A(Ipv4Addr::new(2, 2, 2, 2))),
            rec(NAME, 172_800, Data::A(Ipv4Addr::new(3, 3, 3, 3))),
        ]),
    );
    let values: Vec<String> = card(&look_up(&fake), "addresses")
        .details
        .iter()
        .map(|d| d.value.clone())
        .collect();
    assert_eq!(
        values,
        [
            "1.1.1.1 · TTL 59 s",
            "2.2.2.2 · TTL 2 h",
            "3.3.3.3 · TTL 2 d"
        ]
    );
}

#[test]
fn long_text_is_cut_and_each_record_is_named_by_what_it_is_for() {
    let long = format!("some very long note {}", "x".repeat(300));
    let fake = healthy().with(
        NAME,
        Kind::Txt,
        Ok(vec![
            txt(NAME, &long),
            txt(NAME, "v=DKIM1; k=rsa; p=abc"),
            txt(NAME, "MS=ms12345"),
            txt(NAME, "hello"),
        ]),
    );
    let report = look_up(&fake);
    let labels: Vec<&str> = card(&report, "text")
        .details
        .iter()
        .map(|d| d.label.as_str())
        .collect();
    assert_eq!(labels, ["Text", "DKIM", "Verification", "Text"]);
    assert!(card(&report, "text").details[0].value.ends_with('…'));
    assert!(card(&report, "text").details[0].value.chars().count() <= 160);
}

// =========================
// Email security
// =========================

// The email security card for a domain that receives mail, with these text records.
fn with_texts(texts: &[&str], dmarc: Option<&str>) -> DnsReport {
    let records: Vec<Record> = texts.iter().map(|text| txt(NAME, text)).collect();
    let mut fake = healthy().with(NAME, Kind::Txt, Ok(records));
    fake = match dmarc {
        Some(policy) => fake.with(
            "_dmarc.example.org",
            Kind::Txt,
            Ok(vec![txt("_dmarc.example.org", policy)]),
        ),
        None => fake.with("_dmarc.example.org", Kind::Txt, Err(Failure::NoRecords)),
    };
    look_up(&fake)
}

#[test]
fn a_mail_domain_with_no_spf_and_no_dmarc_is_a_point_worth_noting() {
    let report = with_texts(&[], None);
    assert_eq!(status(&report, "email-security"), Status::Warning);
    assert_eq!(card(&report, "email-security").summary, "Points to note");
    assert!(
        card(&report, "email-security")
            .action
            .as_deref()
            .unwrap()
            .contains("If you manage this domain")
    );
    assert_eq!(report.verdict.status, Status::Warning);
    assert_eq!(
        report.verdict.headline,
        "Records found, with points worth noting."
    );
    // The reasons are kept apart from what was found, for the interface to fold away.
    assert!(row(&report, "email-security", "SPF").reason.is_some());
}

#[test]
fn how_an_spf_record_ends_decides_what_is_said_about_it() {
    for (record, expected, headline) in [
        (
            "v=spf1 -all",
            Status::Ok,
            "Strict: no servers may send email",
        ),
        (
            "v=spf1 mx -all",
            Status::Ok,
            "Strict: only the listed servers",
        ),
        ("v=spf1 ip4:203.0.113.5 ~all", Status::Ok, "Soft"),
        ("v=spf1 ip4:203.0.113.5 ?all", Status::Info, "Neutral"),
        ("v=spf1 +all", Status::Warning, "Open"),
        ("v=spf1 all", Status::Warning, "Open"),
        ("v=spf1 mx a", Status::Info, "No rule"),
        (
            "v=spf1 redirect=_spf.example.net",
            Status::Ok,
            "Uses another domain's rules",
        ),
    ] {
        let report = with_texts(&[record], Some("v=DMARC1; p=reject"));
        assert_eq!(status(&report, "email-security"), expected, "{record}");
        assert!(
            row(&report, "email-security", "SPF")
                .value
                .starts_with(headline),
            "{record}: {}",
            row(&report, "email-security", "SPF").value
        );
    }
    // The services an SPF record includes are counted, not looked up.
    let report = with_texts(
        &["v=spf1 include:a.example include:b.example -all"],
        Some("v=DMARC1; p=reject"),
    );
    assert!(
        row(&report, "email-security", "SPF")
            .value
            .ends_with("2 included services")
    );
}

#[test]
fn more_than_one_spf_record_is_an_error_worth_noting() {
    let report = with_texts(&["v=spf1 -all", "v=spf1 +all"], Some("v=DMARC1; p=reject"));
    assert_eq!(status(&report, "email-security"), Status::Warning);
    assert_eq!(
        row(&report, "email-security", "SPF").value,
        "More than one SPF record"
    );
}

#[test]
fn the_dmarc_policy_is_read_and_explained() {
    for (record, expected, headline) in [
        ("v=DMARC1; p=reject", Status::Ok, "Reject"),
        ("v=DMARC1; p=quarantine; pct=50", Status::Ok, "Quarantine"),
        (
            "v=DMARC1; p=none; rua=mailto:a@example.org",
            Status::Info,
            "Monitor only",
        ),
        (
            "v=DMARC1; p=bogus",
            Status::Warning,
            "The policy could not be read",
        ),
        ("v=DMARC1", Status::Warning, "The policy could not be read"),
    ] {
        let report = with_texts(&["v=spf1 -all"], Some(record));
        assert_eq!(status(&report, "email-security"), expected, "{record}");
        assert!(
            row(&report, "email-security", "DMARC")
                .value
                .starts_with(headline),
            "{record}"
        );
    }
    let report = with_texts(
        &["v=spf1 -all"],
        Some("v=DMARC1; p=reject; rua=mailto:a@example.org"),
    );
    assert_eq!(
        row(&report, "email-security", "Reports sent to").value,
        "mailto:a@example.org"
    );
}

#[test]
fn a_missing_dmarc_record_is_only_a_note_when_spf_is_there() {
    let report = with_texts(&["v=spf1 -all"], None);
    assert_eq!(status(&report, "email-security"), Status::Info);
    assert_eq!(card(&report, "email-security").summary, "Not fully set up");
    assert!(card(&report, "email-security").action.is_none());
    assert_eq!(report.verdict.status, Status::Ok);
}

#[test]
fn a_domain_that_says_it_has_no_mail_is_not_blamed_for_having_no_email_records() {
    let fake = healthy()
        .with(NAME, Kind::Mx, Ok(vec![mx(NAME, 0, ".")]))
        .with(NAME, Kind::Txt, Err(Failure::NoRecords));
    let report = look_up(&fake);
    assert_eq!(card(&report, "mail").summary, "Does not accept email");
    assert!(card(&report, "mail").details.is_empty());
    assert_ne!(status(&report, "email-security"), Status::Warning);
}

// =========================
// What cannot be seen, and what is not there
// =========================

#[test]
fn a_domain_that_does_not_exist_gets_one_card_and_no_further_questions() {
    let fake = Fake::new().with(NAME, Kind::A, Err(Failure::NoSuchDomain));
    let report = look_up(&fake);
    assert_eq!(report.verdict.status, Status::Info);
    assert_eq!(report.verdict.headline, "This domain name does not exist.");
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].summary, "Does not exist");
    assert_eq!(fake.questions().len(), 1);
}

#[test]
fn a_dns_server_that_does_not_answer_is_limited_never_empty() {
    for failure in [Failure::Timeout, Failure::NoServers, Failure::ServerFailed] {
        let fake = Fake::new().with(NAME, Kind::A, Err(failure.clone()));
        let report = look_up(&fake);
        assert_eq!(report.verdict.status, Status::Limited, "{failure:?}");
        assert!(report.verdict.headline.starts_with("Lookup limited"));
        assert!(
            report.findings.iter().all(|f| f.status == Status::Limited),
            "{failure:?}"
        );
        // One question was enough to know, so the others were not sent.
        assert_eq!(fake.questions().len(), 1, "{failure:?}");
    }
}

#[test]
fn one_unanswered_question_is_kept_next_to_what_was_found() {
    let fake = healthy().with(NAME, Kind::Aaaa, Err(Failure::Timeout));
    let report = look_up(&fake);
    // The address card still shows what it found, and says what it could not.
    assert_eq!(status(&report, "addresses"), Status::Ok);
    assert!(
        card(&report, "addresses")
            .note
            .as_deref()
            .unwrap()
            .contains("IPv6: The DNS server did not answer in time.")
    );
    assert_eq!(report.verdict.status, Status::Limited);
    assert_eq!(
        report.verdict.headline,
        "Records found, but some lookups went unanswered."
    );
}

#[test]
fn an_empty_answer_is_an_answer_and_not_a_limit() {
    let fake = healthy()
        .with(NAME, Kind::Aaaa, Err(Failure::NoRecords))
        .with(NAME, Kind::Mx, Err(Failure::NoRecords));
    let report = look_up(&fake);
    assert_eq!(status(&report, "mail"), Status::Info);
    assert_eq!(card(&report, "mail").summary, "No mail servers");
    assert!(
        card(&report, "mail")
            .note
            .as_deref()
            .unwrap()
            .contains("usually fails")
    );
    assert_ne!(report.verdict.status, Status::Limited);
    // A domain with no address records says so plainly.
    let nothing = Fake::new().with(NAME, Kind::A, Err(Failure::NoRecords));
    assert_eq!(
        card(&look_up(&nothing), "addresses").summary,
        "No addresses"
    );
}

#[test]
fn a_refusal_is_named_as_one() {
    let fake = healthy().with(NAME, Kind::Mx, Err(Failure::Refused));
    let report = look_up(&fake);
    assert_eq!(status(&report, "mail"), Status::Limited);
    assert!(
        card(&report, "mail")
            .note
            .as_deref()
            .unwrap()
            .contains("refused")
    );
}

// =========================
// The name that is sent
// =========================

#[test]
fn what_is_typed_becomes_the_name_that_is_asked_about() {
    for (input, expected) in [
        ("example.com", "example.com"),
        ("  Example.COM  ", "example.com"),
        ("example.com.", "example.com"),
        ("https://www.Example.com/a/b?c=1#d", "www.example.com"),
        ("http://user:pass@example.com:8080/x", "example.com"),
        ("example.com:8443/path", "example.com"),
        ("sam@example.com", "example.com"),
        ("_dmarc.example.com", "_dmarc.example.com"),
        ("a.b.c.example.co.uk", "a.b.c.example.co.uk"),
        ("m\u{fc}nchen.example", "xn--mnchen-3ya.example"),
    ] {
        assert_eq!(normalise(input).as_deref(), Ok(expected), "{input}");
    }
}

#[test]
fn input_that_is_not_a_domain_name_is_refused_before_anything_is_asked() {
    for (input, reason) in [
        ("", "Enter a domain name"),
        ("   ", "Enter a domain name"),
        ("example", "full domain name"),
        ("1.2.3.4", "IP address"),
        ("[::1]", "IP address"),
        ("http://192.168.0.1/login", "IP address"),
        ("http://[::1]/x", "IP address"),
        ("two words.com", "no spaces"),
        ("a..example.com", "not a valid"),
        ("exa$mple.com", "not a valid"),
        ("https://", "not a web address"),
    ] {
        let error = normalise(input).expect_err(input);
        assert!(error.contains(reason), "{input:?}: {error}");
    }
    assert!(normalise(&format!("{}.com", "a".repeat(64))).is_err());
    assert!(normalise(&format!("{}.com", ["abcdefghi"; 30].join("."))).is_err());
    assert!(normalise(&"a".repeat(3000)).is_err());
    // Nothing was asked for any of them.
    let fake = Fake::new();
    assert!(run(&fake, "1.2.3.4").is_err() && run(&fake, "").is_err());
    assert!(fake.questions().is_empty());
}

#[test]
fn an_international_name_is_asked_about_in_its_ascii_form() {
    let fake = Fake::new();
    let _ = run(&fake, "m\u{fc}nchen.example");
    let names: Vec<String> = fake.questions().into_iter().map(|(name, _)| name).collect();
    assert!(names.contains(&"xn--mnchen-3ya.example".to_string()));
    assert!(names.contains(&"_dmarc.xn--mnchen-3ya.example".to_string()));
    assert!(names.iter().all(|name| name.is_ascii()));
}

// =========================
// Privacy, wording and shape
// =========================

#[test]
fn the_domain_is_never_part_of_the_log() {
    let report = look_up(&healthy());
    for step in report.findings.iter().flat_map(|f| f.steps.iter()) {
        for text in [&step.action, &step.plain, &step.method, &step.result] {
            assert!(!text.contains("example.org"), "{text}");
        }
    }
}

#[test]
fn nothing_claims_a_domain_is_safe_or_dangerous() {
    let reports = [
        look_up(&healthy()),
        with_texts(&[], None),
        with_texts(&["v=spf1 +all"], Some("v=DMARC1; p=none")),
        run(
            &Fake::new().with(NAME, Kind::A, Err(Failure::NoSuchDomain)),
            NAME,
        )
        .unwrap(),
        run(
            &Fake::new().with(NAME, Kind::A, Err(Failure::Timeout)),
            NAME,
        )
        .unwrap(),
    ];
    for report in reports {
        let mut words = format!("{} {}", report.verdict.headline, report.verdict.detail);
        for finding in &report.findings {
            words.push(' ');
            words.push_str(&finding.summary);
            for part in [&finding.note, &finding.action].into_iter().flatten() {
                words.push(' ');
                words.push_str(part);
            }
            for detail in &finding.details {
                words.push(' ');
                words.push_str(&detail.value);
                words.push(' ');
                words.push_str(detail.reason.as_deref().unwrap_or(""));
            }
        }
        let words = words.to_lowercase().replace("not whether it is safe", "");
        for banned in [
            "safe",
            "legitimate",
            "trustworthy",
            "malicious",
            "dangerous",
            "scam",
        ] {
            assert!(!words.contains(banned), "{banned} in {words}");
        }
    }
}

#[test]
fn the_report_is_sent_in_the_shape_the_interface_reads() {
    let json = serde_json::to_value(with_texts(&["v=spf1 -all"], None)).expect("it serialises");
    assert_eq!(json["verdict"]["status"], "ok");
    let ids: Vec<&str> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        ["addresses", "mail", "names", "text", "email-security"]
    );
    assert_eq!(json["findings"][4]["status"], "info");
    assert!(json["findings"][4]["details"][0]["reason"].is_string());
    assert!(json["findings"][0]["steps"][0]["action"] == "Prepared the domain name");
    assert!(json["findings"][0].get("urls").is_none());
}

#[test]
fn odd_input_never_panics() {
    let pieces = [
        "http://",
        "https://",
        "%",
        "&",
        "=",
        "\u{202e}",
        "\u{430}",
        "\u{1f600}",
        "\u{0}",
        "xn--",
        "..",
        "@",
        ":",
        "/",
        "?",
        "#",
        "[",
        "]",
        "example",
        "com",
        ".",
        "-",
        "_",
        "\u{e9}\u{301}",
        "1",
        "::1",
        "8080",
    ];
    let mut seed: u64 = 0xC0FF_EE12_3456_789A;
    for _ in 0..3_000 {
        let mut text = String::new();
        for _ in 0..10 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            text.push_str(pieces[(seed >> 33) as usize % pieces.len()]);
        }
        let outcome = std::panic::catch_unwind(|| run(&Fake::new(), &text));
        assert!(outcome.is_ok(), "panicked on {text:?}");
    }
}

#[test]
fn a_domain_that_does_not_receive_email_gets_a_neutral_email_security_summary() {
    let fake = healthy()
        .with(NAME, Kind::Mx, Ok(vec![mx(NAME, 0, ".")]))
        .with(NAME, Kind::Txt, Ok(vec![txt(NAME, "v=spf1 -all")]))
        .with(
            "_dmarc.example.org",
            Kind::Txt,
            Ok(vec![txt("_dmarc.example.org", "v=DMARC1; p=reject")]),
        );
    let report = look_up(&fake);
    assert_eq!(card(&report, "email-security").summary, "Records found");
    assert!(
        row(&report, "email-security", "SPF")
            .reason
            .as_deref()
            .unwrap()
            .contains("No servers are authorised")
    );
}

#[test]
fn only_a_valid_null_mx_is_reported_as_not_accepting_email() {
    // Priority 10 with "." is not a valid null MX, and no MX at all is not one either.
    let odd = healthy().with(NAME, Kind::Mx, Ok(vec![mx(NAME, 10, ".")]));
    assert_ne!(
        card(&look_up(&odd), "mail").summary,
        "Does not accept email"
    );
    let none = healthy().with(NAME, Kind::Mx, Err(Failure::NoRecords));
    assert_eq!(card(&look_up(&none), "mail").summary, "No mail servers");
}
