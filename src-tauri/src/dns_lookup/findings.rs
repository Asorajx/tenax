// Turns DNS answers into cards and an overall result.
// There is no Windows or network code here, so every case can be tested with made-up answers.
//
// Each card is one of three things, as in the other tools:
//   checked   the DNS server answered, and what it said is shown (an empty answer is an answer)
//   limited   the DNS server did not answer, so the card cannot say what is there
//   a point   something worth noting, with the reason
// DNS Lookup describes how a domain is set up. It does not say whether a domain is safe.

use std::time::Instant;

use super::records::{Answer, Data, Failure, Record};
use crate::finding::{Detail, Finding, Status, Step, Verdict, count_of, detail, shorten};

// The longest a piece of text is shown before it is cut.
const MAX_TEXT_SHOWN: usize = 160;
// How many text records are listed before the rest are counted. Some domains have dozens.
const MAX_TEXT_ROWS: usize = 12;

// Every answer a lookup got.
pub struct Lookup {
    pub a: Answer,
    pub aaaa: Answer,
    pub mx: Answer,
    pub ns: Answer,
    pub txt: Answer,
    pub soa: Answer,
    // The text records at _dmarc, where a domain publishes its DMARC policy.
    pub dmarc: Answer,
}

struct Check {
    id: &'static str,
    title: &'static str,
    checked: &'static str,
    why: &'static str,
}

const ADDRESSES: Check = Check {
    id: "addresses",
    title: "Addresses",
    checked: "I asked for the domain's IPv4 and IPv6 addresses and any aliases.",
    why: "These say which servers the domain's name leads to.",
};

const MAIL: Check = Check {
    id: "mail",
    title: "Mail servers",
    checked: "I asked which servers receive email for the domain.",
    why: "Without a mail server, email sent to the domain usually cannot be delivered.",
};

const NAMES: Check = Check {
    id: "names",
    title: "Name servers",
    checked: "I asked which servers hold the domain's DNS records.",
    why: "These are the servers that answer for the domain, so whoever controls them controls the domain's records.",
};

const TEXT: Check = Check {
    id: "text",
    title: "Text records",
    checked: "I asked for the domain's text records.",
    why: "Text records carry settings and proofs of ownership that other services read.",
};

const EMAIL_SECURITY: Check = Check {
    id: "email-security",
    title: "Email security",
    checked: "I read the domain's SPF and DMARC records.",
    why: "SPF and DMARC tell receivers which servers may send email as the domain, and what to do with forgeries.",
};

fn finding(
    check: &Check,
    status: Status,
    summary: String,
    action: Option<&str>,
    details: Vec<Detail>,
    note: Vec<String>,
    step: Step,
) -> Finding {
    Finding {
        id: check.id.to_string(),
        status,
        title: check.title.to_string(),
        summary,
        checked: check.checked.to_string(),
        why: check.why.to_string(),
        action: action.map(str::to_string),
        details,
        steps: vec![step],
        note: (!note.is_empty()).then(|| note.join(" ")),
        urls: Vec::new(),
    }
}

// =========================
// Reading answers
// =========================

// "1 address" or "2 addresses". count_of only adds an "s", which is wrong for this word.
fn addresses_of(count: usize) -> String {
    if count == 1 {
        "1 address".to_string()
    } else {
        format!("{count} addresses")
    }
}

// How a time to live is shown, such as "5 min".
fn ttl(seconds: u32) -> String {
    match seconds {
        0..=59 => format!("{seconds} s"),
        60..=3599 => format!("{} min", seconds / 60),
        3600..=86399 => format!("{} h", seconds / 3600),
        _ => format!("{} d", seconds / 86400),
    }
}

// Without the dot that ends a name, which is how names usually appear in DNS.
fn plain(name: &str) -> &str {
    name.trim_end_matches('.')
}

fn records(answer: &Answer) -> &[Record] {
    answer.as_deref().unwrap_or(&[])
}

// Why a question got no answer, in words.
fn unanswered(failure: &Failure) -> &'static str {
    match failure {
        Failure::Timeout => "The DNS server did not answer in time.",
        Failure::NoServers => "No DNS server could be reached. Check the network connection.",
        Failure::ServerFailed => "The DNS server could not look this up.",
        Failure::Refused => "The DNS server refused to answer.",
        _ => "The DNS server did not give an answer.",
    }
}

// The reasons some answers are missing, for a card's note. Only real failures count: "no such
// record" is an answer.
fn missing(answers: &[(&str, &Answer)]) -> Vec<String> {
    answers
        .iter()
        .filter_map(|(what, answer)| match answer {
            Err(failure) if !matches!(failure, Failure::NoRecords | Failure::NoSuchDomain) => {
                Some(format!("{what}: {}", unanswered(failure)))
            }
            _ => None,
        })
        .collect()
}

fn failed(answer: &Answer) -> bool {
    matches!(answer, Err(f) if !matches!(f, Failure::NoRecords | Failure::NoSuchDomain))
}

// =========================
// Cards
// =========================

pub struct Card {
    pub finding: Finding,
    // Whether any question went unanswered, even if the card found something.
    pub limited: bool,
}

fn addresses(lookup: &Lookup) -> Card {
    let started = Instant::now();
    let mut rows: Vec<Detail> = Vec::new();
    let mut aliases: Vec<String> = Vec::new();

    for record in records(&lookup.a).iter().chain(records(&lookup.aaaa)) {
        match &record.data {
            Data::A(ip) => rows.push(detail("IPv4", format!("{ip} · TTL {}", ttl(record.ttl)))),
            Data::Aaaa(ip) => rows.push(detail("IPv6", format!("{ip} · TTL {}", ttl(record.ttl)))),
            Data::Cname(target) => {
                let alias = format!("{} → {}", plain(&record.name), plain(target));
                if !aliases.contains(&alias) {
                    aliases.push(alias);
                }
            }
            _ => {}
        }
    }
    let count = rows.len();
    rows.extend(aliases.iter().map(|alias| detail("Alias", alias)));

    let both_failed = failed(&lookup.a) && failed(&lookup.aaaa);
    let limited = failed(&lookup.a) || failed(&lookup.aaaa);
    let mut note = missing(&[("IPv4", &lookup.a), ("IPv6", &lookup.aaaa)]);

    let (status, summary) = if count > 0 {
        (Status::Ok, addresses_of(count))
    } else if both_failed {
        (Status::Limited, "Limited analysis".to_string())
    } else {
        note.push(
            "This name has no website address. It may be used only for email or other services."
                .to_string(),
        );
        (Status::Info, "No addresses".to_string())
    };

    Card {
        finding: finding(
            &ADDRESSES,
            status,
            summary,
            None,
            rows,
            note,
            Step::new(
                "Looked up the addresses",
                "Asked for the domain's website addresses",
                "Windows DNS client asked for A and AAAA records, which also returns any aliases (CNAME) on the way",
                format!("{} read", addresses_of(count)),
                started,
            ),
        ),
        limited,
    }
}

fn mail_servers(lookup: &Lookup) -> Card {
    let started = Instant::now();
    let mut servers: Vec<(u16, String, u32)> = records(&lookup.mx)
        .iter()
        .filter_map(|record| match &record.data {
            Data::Mx { preference, host } => {
                Some((*preference, plain(host).to_string(), record.ttl))
            }
            _ => None,
        })
        .collect();
    servers.sort();

    // A null MX is a single record with priority 0 and the host ".". It is how a domain says it accepts no email.
    let refuses = servers.len() == 1 && servers[0].0 == 0 && servers[0].1.is_empty();
    let rows: Vec<Detail> = if refuses {
        Vec::new()
    } else {
        servers
            .iter()
            .map(|(preference, host, ttl_seconds)| {
                detail(
                    &format!("Priority {preference}"),
                    format!("{host} · TTL {}", ttl(*ttl_seconds)),
                )
            })
            .collect()
    };

    let limited = failed(&lookup.mx);
    let mut note = missing(&[("Mail servers", &lookup.mx)]);
    let (status, summary) = if refuses {
        note.push("This domain is configured not to accept incoming email.".to_string());
        (Status::Info, "Does not accept email".to_string())
    } else if !rows.is_empty() {
        (Status::Ok, count_of(rows.len(), "mail server"))
    } else if limited {
        (Status::Limited, "Limited analysis".to_string())
    } else {
        note.push(
            "With no mail server record, email to this domain falls back to its website address, and usually fails."
                .to_string(),
        );
        (Status::Info, "No mail servers".to_string())
    };

    Card {
        finding: finding(
            &MAIL,
            status,
            summary,
            None,
            rows,
            note,
            Step::new(
                "Looked up the mail servers",
                "Asked which servers receive email for the domain",
                "Windows DNS client asked for MX records",
                format!("{} read", count_of(servers.len(), "mail server")),
                started,
            ),
        ),
        limited,
    }
}

// The contact in a start-of-authority record is written with a dot where the @ would be.
fn contact(admin: &str) -> String {
    let admin = plain(admin);
    match admin.split_once('.') {
        Some((name, domain)) => format!("{name}@{domain}"),
        None => admin.to_string(),
    }
}

fn name_servers(lookup: &Lookup) -> Card {
    let started = Instant::now();
    let mut rows: Vec<Detail> = Vec::new();

    let mut servers: Vec<String> = records(&lookup.ns)
        .iter()
        .filter_map(|record| match &record.data {
            Data::Ns(host) => Some(plain(host).to_string()),
            _ => None,
        })
        .collect();
    servers.sort();
    servers.dedup();
    rows.extend(servers.iter().map(|host| detail("Name server", host)));

    for record in records(&lookup.soa) {
        if let Data::Soa {
            primary,
            admin,
            serial,
        } = &record.data
        {
            rows.push(detail("Primary server", plain(primary)));
            rows.push(detail("Contact", contact(admin)));
            rows.push(detail("Serial", serial.to_string()));
        }
    }

    let limited = failed(&lookup.ns) || failed(&lookup.soa);
    let mut note = missing(&[
        ("Name servers", &lookup.ns),
        ("Start of authority", &lookup.soa),
    ]);
    let (status, summary) = if !servers.is_empty() {
        (Status::Ok, count_of(servers.len(), "name server"))
    } else if limited {
        (Status::Limited, "Limited analysis".to_string())
    } else {
        note.push(
            "Name servers are normally set on the main domain, such as example.com, not on a subdomain."
                .to_string(),
        );
        (Status::Info, "None at this name".to_string())
    };

    Card {
        finding: finding(
            &NAMES,
            status,
            summary,
            None,
            rows,
            note,
            Step::new(
                "Looked up the name servers",
                "Asked which servers hold the domain's records",
                "Windows DNS client asked for NS and SOA records",
                format!("{} read", count_of(servers.len(), "name server")),
                started,
            ),
        ),
        limited,
    }
}

// What a text record is for, from how it starts.
fn text_kind(text: &str) -> &'static str {
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("v=spf1") {
        "SPF"
    } else if lower.starts_with("v=dmarc1") {
        "DMARC"
    } else if lower.starts_with("v=dkim1") {
        "DKIM"
    } else if [
        "google-site-verification=",
        "ms=",
        "facebook-domain-verification=",
        "apple-domain-verification=",
        "docusign=",
        "atlassian-domain-verification=",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
        || lower.contains("-verification=")
    {
        "Verification"
    } else {
        "Text"
    }
}

fn text_records(lookup: &Lookup) -> Card {
    let started = Instant::now();
    let texts: Vec<&str> = records(&lookup.txt)
        .iter()
        .filter_map(|record| match &record.data {
            Data::Txt(text) => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let mut rows: Vec<Detail> = texts
        .iter()
        .take(MAX_TEXT_ROWS)
        .map(|text| detail(text_kind(text), shorten(text, MAX_TEXT_SHOWN)))
        .collect();
    if texts.len() > MAX_TEXT_ROWS {
        rows.push(detail(
            "More",
            format!("{} more", texts.len() - MAX_TEXT_ROWS),
        ));
    }

    let limited = failed(&lookup.txt);
    let note = missing(&[("Text records", &lookup.txt)]);
    let (status, summary) = if !texts.is_empty() {
        (Status::Ok, count_of(texts.len(), "text record"))
    } else if limited {
        (Status::Limited, "Limited analysis".to_string())
    } else {
        (Status::Info, "No text records".to_string())
    };

    Card {
        finding: finding(
            &TEXT,
            status,
            summary,
            None,
            rows,
            note,
            Step::new(
                "Looked up the text records",
                "Asked for the domain's text records",
                "Windows DNS client asked for TXT records, with the pieces of each record joined",
                format!("{} read", count_of(texts.len(), "text record")),
                started,
            ),
        ),
        limited,
    }
}

// =========================
// Email security
// =========================

// The SPF records among a set of text records. A domain should have exactly one.
fn spf_records(answer: &Answer) -> Vec<&str> {
    records(answer)
        .iter()
        .filter_map(|record| match &record.data {
            Data::Txt(text) if text.to_ascii_lowercase().starts_with("v=spf1") => {
                Some(text.as_str())
            }
            _ => None,
        })
        .collect()
}

fn dmarc_records(answer: &Answer) -> Vec<&str> {
    records(answer)
        .iter()
        .filter_map(|record| match &record.data {
            Data::Txt(text) if text.to_ascii_lowercase().starts_with("v=dmarc1") => {
                Some(text.as_str())
            }
            _ => None,
        })
        .collect()
}

// How an SPF record ends, which says what happens to mail from servers it does not list.
fn spf_ending(record: &str) -> (Status, &'static str, &'static str) {
    let lower = record.to_ascii_lowercase();
    let words: Vec<&str> = lower.split_whitespace().collect();
    match words
        .iter()
        .rev()
        .find(|word| word.trim_start_matches(['+', '-', '~', '?']) == "all")
    {
        // "v=spf1 -all" lists no servers at all, so it authorises none.
        Some(word) if word.starts_with('-') && words.len() == 2 => (
            Status::Ok,
            "Strict: no servers may send email",
            "No servers are authorised to send email for this domain. Mail claiming to come from it is meant to be rejected.",
        ),
        Some(word) if word.starts_with('-') => (
            Status::Ok,
            "Strict: only the listed servers may send",
            "Mail from any other server is meant to be rejected.",
        ),
        Some(word) if word.starts_with('~') => (
            Status::Ok,
            "Soft: other servers are treated as suspicious",
            "Mail from other servers is meant to be flagged, but may still be delivered.",
        ),
        Some(word) if word.starts_with('?') => (
            Status::Info,
            "Neutral: no rule for other servers",
            "This record takes no position on mail from servers it does not list.",
        ),
        Some(_) => (
            Status::Warning,
            "Open: any server may send",
            "This record allows every server to send email as this domain, which defeats its purpose.",
        ),
        None => match words.iter().find(|word| word.starts_with("redirect=")) {
            Some(_) => (
                Status::Ok,
                "Uses another domain's rules",
                "The rules are kept on another domain, which this lookup does not read.",
            ),
            None => (
                Status::Info,
                "No rule for other servers",
                "This record does not say what to do with mail from servers it does not list.",
            ),
        },
    }
}

// The value of a tag in a DMARC record, such as the "reject" in "p=reject".
fn dmarc_tag<'a>(record: &'a str, tag: &str) -> Option<&'a str> {
    record.split(';').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case(tag)
            .then_some(value.trim())
    })
}

fn email_security(lookup: &Lookup) -> Card {
    let started = Instant::now();

    let spf = spf_records(&lookup.txt);
    let dmarc = dmarc_records(&lookup.dmarc);
    let receives_mail = records(&lookup.mx)
        .iter()
        .any(|record| matches!(&record.data, Data::Mx { host, .. } if !plain(host).is_empty()));

    let limited = failed(&lookup.txt) || failed(&lookup.dmarc);
    let note = missing(&[("SPF", &lookup.txt), ("DMARC", &lookup.dmarc)]);
    let mut rows: Vec<Detail> = Vec::new();
    let mut worst = Status::Ok;
    let mut raise = |status: Status| worst = worst.min(status);

    // SPF
    match spf.as_slice() {
        [] if limited && failed(&lookup.txt) => {}
        [] => {
            rows.push(detail("SPF", "No SPF record").because(
                "SPF lists the servers allowed to send email as the domain. Without it, forged mail is easier to pass off as genuine.",
            ));
            raise(if receives_mail {
                Status::Warning
            } else {
                Status::Info
            });
        }
        [record] => {
            let (status, headline, reason) = spf_ending(record);
            let includes = record
                .to_ascii_lowercase()
                .split_whitespace()
                .filter(|word| {
                    word.trim_start_matches(['+', '-', '~', '?'])
                        .starts_with("include:")
                })
                .count();
            let shown = if includes > 0 {
                format!("{headline} · {}", count_of(includes, "included service"))
            } else {
                headline.to_string()
            };
            rows.push(detail("SPF", shown).because(reason));
            raise(status);
        }
        _ => {
            rows.push(detail("SPF", "More than one SPF record").because(
                "A domain must have exactly one. Receivers treat several as an error and may ignore the rules altogether.",
            ));
            raise(Status::Warning);
        }
    }

    // DMARC
    match dmarc.as_slice() {
        [] if failed(&lookup.dmarc) => {}
        [] => {
            rows.push(detail("DMARC", "No DMARC record").because(
                "DMARC tells receivers what to do with mail that fails SPF and DKIM. Without it, they decide for themselves.",
            ));
            raise(if receives_mail && spf.is_empty() {
                Status::Warning
            } else {
                Status::Info
            });
        }
        [record] => {
            let policy = dmarc_tag(record, "p").unwrap_or("").to_ascii_lowercase();
            let (status, headline, reason) = match policy.as_str() {
                "reject" => (
                    Status::Ok,
                    "Reject: failing mail is meant to be refused",
                    "Receivers are asked to refuse mail that fails the checks.",
                ),
                "quarantine" => (
                    Status::Ok,
                    "Quarantine: failing mail is meant to go to spam",
                    "Receivers are asked to treat mail that fails the checks as suspicious.",
                ),
                "none" => (
                    Status::Info,
                    "Monitor only: failing mail is not blocked",
                    "The domain collects reports but asks receivers to take no action on failing mail.",
                ),
                _ => (
                    Status::Warning,
                    "The policy could not be read",
                    "A DMARC record needs a policy of none, quarantine or reject.",
                ),
            };
            rows.push(detail("DMARC", headline).because(reason));
            if let Some(reports) = dmarc_tag(record, "rua") {
                rows.push(detail("Reports sent to", shorten(reports, MAX_TEXT_SHOWN)));
            }
            raise(status);
        }
        _ => {
            rows.push(detail("DMARC", "More than one DMARC record").because(
                "A domain must have exactly one. Receivers ignore DMARC when there are several.",
            ));
            raise(Status::Warning);
        }
    }

    // A question that went unanswered means the picture is incomplete, whatever else it shows.
    let status = if rows.is_empty() || (worst == Status::Ok && limited) {
        Status::Limited
    } else {
        worst
    };
    let summary = match status {
        // A domain that does not receive email is not "set up" in the usual sense.
        Status::Ok if !receives_mail => "Records found",
        Status::Ok => "Set up",
        Status::Limited => "Limited analysis",
        Status::Info => "Not fully set up",
        _ => "Points to note",
    }
    .to_string();
    let action = (status == Status::Warning).then_some(
        "If you manage this domain, add or fix its SPF and DMARC records. If not, treat email claiming to come from it with extra care.",
    );

    Card {
        finding: finding(
            &EMAIL_SECURITY,
            status,
            summary,
            action,
            rows,
            note,
            Step::new(
                "Read the email security records",
                "Looked at the domain's SPF and DMARC settings",
                "SPF read from the domain's text records and DMARC from the text records at _dmarc. Included services are counted, not looked up",
                format!(
                    "{} and {} found",
                    count_of(spf.len(), "SPF record"),
                    count_of(dmarc.len(), "DMARC record")
                ),
                started,
            ),
        ),
        limited,
    }
}

// =========================
// All cards and the result
// =========================

pub fn build(lookup: &Lookup) -> (Verdict, Vec<Finding>) {
    // A name that does not exist has nothing else to show.
    if matches!(lookup.a, Err(Failure::NoSuchDomain)) {
        let started = Instant::now();
        let card = finding(
            &ADDRESSES,
            Status::Info,
            "Does not exist".to_string(),
            None,
            Vec::new(),
            vec![
                "This domain name does not exist in DNS, so there are no records to show."
                    .to_string(),
            ],
            Step::new(
                "Looked up the addresses",
                "Asked for the domain's website addresses",
                "Windows DNS client asked for A records, and the DNS server said the name does not exist",
                "No such domain".to_string(),
                started,
            ),
        );
        return (
            Verdict {
                status: Status::Info,
                headline: "This domain name does not exist.".to_string(),
                detail: "Your DNS server says this domain doesn't exist. Check the spelling, or it may only exist on another network.".to_string(),
            },
            vec![card],
        );
    }

    let cards = vec![
        addresses(lookup),
        mail_servers(lookup),
        name_servers(lookup),
        text_records(lookup),
        email_security(lookup),
    ];

    let everything_failed = [
        &lookup.a,
        &lookup.aaaa,
        &lookup.mx,
        &lookup.ns,
        &lookup.txt,
        &lookup.soa,
    ]
    .iter()
    .all(|answer| failed(answer));
    let any_points = cards
        .iter()
        .any(|card| card.finding.status == Status::Warning);
    let any_limited = cards.iter().any(|card| card.limited);

    let verdict = if everything_failed {
        Verdict {
            status: Status::Limited,
            headline: "Lookup limited: the DNS server did not answer.".to_string(),
            detail: "No DNS records could be retrieved, so this says nothing about the domain. Check your connection and try again.".to_string(),
        }
    } else if any_points {
        Verdict {
            status: Status::Warning,
            headline: "Records found, with points worth noting.".to_string(),
            detail: format!(
                "These are the DNS records returned by your server.{}",
                if any_limited {
                    " Some questions also went unanswered."
                } else {
                    ""
                }
            ),
        }
    } else if any_limited {
        Verdict {
            status: Status::Limited,
            headline: "Records found, but some lookups went unanswered.".to_string(),
            detail: "Some DNS queries returned no answer, so the results are incomplete.".to_string(),
        }
    } else {
        Verdict {
            status: Status::Ok,
            headline: "DNS records found.".to_string(),
            detail: "These are the DNS records returned by your server.".to_string(),
        }
    };

    (
        verdict,
        cards.into_iter().map(|card| card.finding).collect(),
    )
}
