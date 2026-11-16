// Turns what was found about a server's certificate into cards and an overall result.
// There is no network or Windows code here, so every case can be tested.
//
// There are three kinds of result, and they are never mixed up:
//   a valid certificate      Windows trusted it, and its details are shown
//   a certificate problem    Windows would not trust it, and each problem is explained
//   a connection failure     no certificate was read, so nothing can be said about it
// TLS Certificate describes a certificate. It does not say whether a website is good or safe,
// and it does not check whether a certificate has been revoked.

use std::net::IpAddr;

use super::cert::{CertInfo, name_covers};
use super::problems::{Problem, Trust, find};
use crate::finding::{Detail, Finding, Status, Verdict, count_of, detail};

// How many names are listed before the rest are counted.
const MAX_NAME_ROWS: usize = 10;
// A certificate that ends within this many days is pointed out.
const EXPIRES_SOON_DAYS: i64 = 30;

// Why no certificate could be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failed {
    // The name could not be turned into an address.
    NotFound { text: String },
    // The server could not be reached.
    Unreachable { code: Option<u32>, text: String },
    // The server answered, but the secure handshake did not finish.
    Handshake { code: Option<u32>, text: String },
}

// One of these is made per check and used once, so the size of the larger one does not matter.
#[allow(clippy::large_enum_variant)]
pub enum Outcome {
    // The server was reached and sent a certificate. It may not be readable.
    Reached {
        trust: Trust,
        cert: Result<CertInfo, String>,
    },
    Failed(Failed),
}

struct Check {
    id: &'static str,
    title: &'static str,
    checked: &'static str,
    why: &'static str,
}

const TRUST: Check = Check {
    id: "trust",
    title: "Windows trust",
    checked: "I connected to the server and asked Windows whether it trusts the certificate the server presented.",
    why: "A browser only shows a site as secure when its certificate is trusted, so this is the result that matters most.",
};

const NAMES: Check = Check {
    id: "names",
    title: "Names covered",
    checked: "I read which names the certificate says it was issued for.",
    why: "A certificate is only evidence for the names it lists. One issued for other names cannot show you have reached this one.",
};

const VALIDITY: Check = Check {
    id: "validity",
    title: "Dates",
    checked: "I read the dates the certificate is valid between.",
    why: "Certificates expire so that old or stolen ones stop working. An expired certificate is refused by browsers.",
};

const ISSUER: Check = Check {
    id: "issuer",
    title: "Subject and issuer",
    checked: "I read who the certificate was issued to and who issued it.",
    why: "The issuer is the authority that vouches for the certificate. A certificate that vouches for itself proves nothing to others.",
};

const KEY: Check = Check {
    id: "key",
    title: "Key and signature",
    checked: "I read the certificate's public key and the way it was signed.",
    why: "Short keys and old signature methods can be broken, which would let someone forge the certificate.",
};

const CONNECTION: Check = Check {
    id: "connection",
    title: "Connection",
    checked: "I tried to connect to the server and make a secure handshake.",
    why: "A certificate can only be read once the server has been reached and has started the secure handshake.",
};

fn card(
    check: &Check,
    status: Status,
    summary: String,
    action: Option<&str>,
    details: Vec<Detail>,
    note: Option<String>,
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
        note,
        urls: Vec::new(),
        // The steps are the same for the whole check, so the first card carries them.
        steps: Vec::new(),
    }
}

// =========================
// Wording
// =========================

fn hex(code: u32) -> String {
    format!("{code:#010X}").replace("0X", "0x")
}

// What Windows said, with its code, such as "0x800B0101 · A required certificate is not within...".
fn windows_said(code: Option<u32>, text: &str) -> String {
    match code {
        Some(code) => format!("{} · {text}", hex(code)),
        None => text.to_string(),
    }
}

// A length of time in days, written for reading: "12 days", "about 3 months", "about 2 years".
fn span(days: i64) -> String {
    match days {
        0 => "less than a day".to_string(),
        1..=99 => count_of(days as usize, "day"),
        100..=547 => format!("about {}", count_of((days / 30) as usize, "month")),
        _ => format!("about {}", count_of(((days + 182) / 365) as usize, "year")),
    }
}

fn days_from(seconds: i64) -> i64 {
    seconds.div_euclid(86_400)
}

// The common name of a distinguished name such as "C=AU, O=Example, CN=Example CA".
fn common_name(name: &str) -> Option<&str> {
    name.split(", ").find_map(|part| part.strip_prefix("CN="))
}

fn problem_row(problem: Problem, cert: &CertInfo, host: &str, now: i64) -> Detail {
    let clock = " If the date or time on this PC is wrong, a valid certificate can look expired, so check it.";
    match problem {
        Problem::Expired => detail(
            "Expired",
            format!(
                "Ended {} ({})",
                if days_from(now - cert.not_after) == 0 {
                    "today".to_string()
                } else {
                    format!("{} ago", span(days_from(now - cert.not_after)))
                },
                cert.valid_until
            ),
        )
        .because(format!(
            "Certificates have an end date so that old or stolen ones stop working. After it, browsers refuse the site.{clock}"
        )),
        Problem::NotYetValid => detail(
            "Not valid yet",
            format!("Starts {}", cert.valid_from),
        )
        .because(format!(
            "The certificate's start date has not come yet, so it cannot be used.{clock}"
        )),
        Problem::ChainExpired => detail("A certificate above it has expired", "The server's own certificate is in date")
            .because(format!(
                "Windows checks every certificate between this one and the authority at the top. One of them has run out.{clock}"
            )),
        Problem::NameMismatch => detail("Issued for other names", format!("Does not list {host}")).because(format!(
            "A certificate is issued for particular names, and this one was not issued for {host}. It is often a mistake on the server, but it is also what happens when a connection is being intercepted."
        )),
        Problem::SelfSigned => detail("Signed by itself", "No authority has confirmed it").because(
            "The certificate vouches for itself, so Windows has no reason to trust it. This is common on test servers and devices, but a public site should not use one.",
        ),
        Problem::UntrustedIssuer => detail("Issuer not trusted", "Not linked to a trusted authority").because(
            "Windows could not trace the certificate back to an authority it trusts. The server may be missing a certificate, the authority may be unknown, or the connection may be intercepted. A workplace can add its own authorities, so on a managed PC ask your IT team.",
        ),
        Problem::Revoked => detail("Revoked", "The issuer withdrew it").because(
            "The authority that issued it has cancelled it, usually because it was stolen or issued by mistake.",
        ),
        Problem::Rejected => detail("Rejected by Windows", "For a reason Tenax does not recognise").because(
            "Windows refused the certificate. The technical message is shown below.",
        ),
    }
}

fn problem_name(problem: Problem) -> &'static str {
    match problem {
        Problem::Expired => "expired",
        Problem::NotYetValid => "not valid yet",
        Problem::ChainExpired => "a certificate above it has expired",
        Problem::NameMismatch => "issued for other names",
        Problem::SelfSigned => "signed by itself",
        Problem::UntrustedIssuer => "issuer not trusted",
        Problem::Revoked => "revoked",
        Problem::Rejected => "rejected by Windows",
    }
}

// =========================
// Cards for a certificate that was read
// =========================

fn trust_card(
    host: &str,
    address: Option<IpAddr>,
    trust: &Trust,
    cert: &Result<CertInfo, String>,
    now: i64,
) -> (Finding, Vec<Problem>) {
    let mut details = vec![detail("Checked name", host)];
    if let Some(address) = address {
        details.push(detail("Connected to", address.to_string()));
    }

    match trust {
        Trust::Trusted => {
            details.push(detail(
                "Decided by",
                "Windows, using the certificate authorities it trusts",
            ));
            let note = "Windows built a chain from this certificate up to an authority it trusts, and confirmed that the certificate is in date and issued for this name. Authorities added by a workplace count. Acceptance does not mean the website itself is safe. Tenax does not check whether a certificate has been revoked, and shows only the server's own certificate.";
            (
                card(
                    &TRUST,
                    Status::Ok,
                    "Accepted by Windows".to_string(),
                    None,
                    details,
                    Some(note.to_string()),
                ),
                Vec::new(),
            )
        }
        Trust::NotTrusted { code, text } => {
            let problems = match cert {
                Ok(cert) => find(cert, host, *code, now),
                Err(_) => vec![Problem::Rejected],
            };
            if let Ok(cert) = cert {
                for problem in &problems {
                    details.push(problem_row(*problem, cert, host, now));
                }
            }
            details.push(detail("Windows said", windows_said(*code, text)));

            let status = if problems.iter().any(|problem| problem.is_serious()) {
                Status::Risk
            } else {
                Status::Warning
            };
            let summary = match problems.as_slice() {
                [only] => format!("Not trusted: {}", problem_name(*only)),
                many => format!("Not trusted: {}", count_of(many.len(), "problem")),
            };
            (
                card(
                    &TRUST,
                    status,
                    summary,
                    Some("Avoid signing in or sending personal details to this site until this is fixed. If you run the site, replace or renew the certificate."),
                    details,
                    Some("Windows refused the certificate. To explain why, Tenax made a second connection that did not check the certificate and only read it. The certificate is still not trusted. Tenax does not check whether a certificate has been revoked, and shows only the server's own certificate.".to_string()),
                ),
                problems,
            )
        }
    }
}

fn names_card(host: &str, cert: &CertInfo) -> Finding {
    let covered = cert.covers(host);
    let mut details = vec![detail("Checked name", host)];

    let listed = cert.names.len() + cert.addresses.len();
    let mut shown = 0;
    for name in cert.names.iter().take(MAX_NAME_ROWS) {
        let matches = host.parse::<IpAddr>().is_err() && name_covers(name, host);
        details.push(detail(
            "Name",
            if matches {
                format!("{name} · matches")
            } else {
                name.clone()
            },
        ));
        shown += 1;
    }
    for address in cert
        .addresses
        .iter()
        .take(MAX_NAME_ROWS.saturating_sub(shown))
    {
        let matches = host.parse::<IpAddr>().ok() == Some(*address);
        details.push(detail(
            "Address",
            if matches {
                format!("{address} · matches")
            } else {
                address.to_string()
            },
        ));
        shown += 1;
    }
    if listed > shown {
        details.push(detail("More", format!("{} more", listed - shown)));
    }

    let (status, summary, note) = if covered {
        (Status::Ok, format!("Covers {host}"), None)
    } else if listed == 0 {
        (
            Status::Risk,
            "Lists no names".to_string(),
            Some(
                "Browsers only look at the names a certificate lists, and this one lists none."
                    .to_string(),
            ),
        )
    } else {
        (
            Status::Risk,
            format!("Does not cover {host}"),
            Some("A wildcard such as *.example.com covers one extra part in front of the name, such as www, and nothing more.".to_string()),
        )
    };
    card(&NAMES, status, summary, None, details, note)
}

fn validity_card(cert: &CertInfo, now: i64) -> Finding {
    let (status, summary) = if cert.is_expired(now) {
        let days = days_from(now - cert.not_after);
        (
            Status::Warning,
            if days == 0 {
                "Expired today".to_string()
            } else {
                format!("Expired {} ago", span(days))
            },
        )
    } else if cert.not_yet_valid(now) {
        (
            Status::Warning,
            format!("Starts in {}", span(days_from(cert.not_before - now))),
        )
    } else {
        let days = days_from(cert.not_after - now);
        if days < EXPIRES_SOON_DAYS {
            (Status::Warning, format!("Expires in {}", span(days)))
        } else {
            (Status::Ok, format!("{} left", span(days)))
        }
    };
    let action = (status == Status::Warning && !cert.is_expired(now) && !cert.not_yet_valid(now))
        .then_some("If you run this site, renew the certificate before it ends so visitors do not see a warning.");
    card(
        &VALIDITY,
        status,
        summary,
        action,
        vec![
            detail("Valid from", cert.valid_from.clone()),
            detail("Valid until", cert.valid_until.clone()),
        ],
        None,
    )
}

fn issuer_card(cert: &CertInfo) -> Finding {
    let (status, summary) = if cert.self_signed {
        (Status::Warning, "Signed by itself".to_string())
    } else {
        let issuer = common_name(&cert.issuer).unwrap_or(&cert.issuer);
        (Status::Info, format!("Issued by {issuer}"))
    };
    card(
        &ISSUER,
        status,
        summary,
        None,
        vec![
            detail("Subject", cert.subject.clone()),
            detail("Issuer", cert.issuer.clone()),
            detail("Serial number", cert.serial.clone()),
        ],
        Some("Tenax read only the server's own certificate. The certificates above it were checked by Windows and are not listed here.".to_string()),
    )
}

fn key_card(cert: &CertInfo) -> Finding {
    let mut key = detail("Public key", cert.key.clone());
    if let Some(weakness) = cert.key_weakness {
        key = key.because(weakness);
    }
    let mut signature = detail("Signature algorithm", cert.signature.clone());
    if let Some(weakness) = cert.signature_weakness {
        signature = signature.because(weakness);
    }
    let weak = cert.key_weakness.is_some() || cert.signature_weakness.is_some();
    card(
        &KEY,
        if weak { Status::Warning } else { Status::Ok },
        format!("{} · {}", cert.key, cert.signature),
        weak.then_some("If you run this site, replace the certificate with one that uses a stronger key and signature."),
        vec![key, signature],
        None,
    )
}

// =========================
// A certificate that could not be read
// =========================

fn connection_card(host: &str, address: Option<IpAddr>, failed: &Failed) -> Finding {
    let (summary, action, said) = match failed {
        Failed::NotFound { text } => (
            "Server not found",
            "Check the spelling of the name. If it is right, the name may not exist or the DNS server may be having trouble.",
            text.clone(),
        ),
        Failed::Unreachable { code, text } => (
            "Could not connect",
            "Check the internet connection and that the site is online. If it is, it may not accept secure connections on port 443, or something may be blocking the connection.",
            windows_said(*code, text),
        ),
        Failed::Handshake { code, text } => (
            "Secure connection failed",
            "The server answered, but the secure handshake did not finish. It may not offer secure connections here, or may only use methods Windows no longer allows. Try again later, or ask whoever runs it.",
            windows_said(*code, text),
        ),
    };
    let mut details = vec![detail("Host", host)];
    if let Some(address) = address {
        details.push(detail("Address", address.to_string()));
    }
    details.push(detail("Windows said", said));
    card(
        &CONNECTION,
        Status::Unknown,
        summary.to_string(),
        Some(action),
        details,
        Some("No certificate was read, so Tenax cannot say anything about the certificate. A failed connection is not a finding about the site.".to_string()),
    )
}

// =========================
// The result
// =========================

pub fn build(
    host: &str,
    address: Option<IpAddr>,
    outcome: &Outcome,
    now: i64,
) -> (Verdict, Vec<Finding>) {
    match outcome {
        Outcome::Failed(failed) => {
            let (headline, detail) = match failed {
                Failed::NotFound { .. } => (
                    "The server could not be found.",
                    "The name did not lead to an address, so there was nothing to connect to.",
                ),
                Failed::Unreachable { .. } => (
                    "Could not connect to the server.",
                    "No certificate was read, so there is nothing to report about it.",
                ),
                Failed::Handshake { .. } => (
                    "Could not complete a secure connection.",
                    "The server answered, but no certificate was read, so there is nothing to report about it.",
                ),
            };
            (
                Verdict {
                    status: Status::Unknown,
                    headline: headline.to_string(),
                    detail: detail.to_string(),
                },
                vec![connection_card(host, address, failed)],
            )
        }
        Outcome::Reached { trust, cert } => {
            let (trust_card, problems) = trust_card(host, address, trust, cert, now);
            let mut findings = vec![trust_card];
            match cert {
                Ok(cert) => {
                    findings.push(names_card(host, cert));
                    findings.push(validity_card(cert, now));
                    findings.push(issuer_card(cert));
                    findings.push(key_card(cert));
                }
                Err(message) => {
                    findings.push(card(
                        &ISSUER,
                        Status::Unknown,
                        "Could not be read".to_string(),
                        None,
                        Vec::new(),
                        Some(message.clone()),
                    ));
                }
            }

            let worst = findings
                .iter()
                .map(|finding| finding.status)
                .min()
                .unwrap_or(Status::Ok);
            let verdict = match trust {
                Trust::Trusted if worst >= Status::Info => Verdict {
                    status: Status::Ok,
                    headline: "Certificate accepted by Windows.".to_string(),
                    detail: format!(
                        "It is in date and issued for {host} by an authority Windows trusts. That does not mean the website itself is safe, and Tenax does not check whether the certificate has been revoked."
                    ),
                },
                Trust::Trusted => Verdict {
                    status: worst,
                    headline: "Certificate accepted by Windows, with points worth noting.".to_string(),
                    detail: "Windows accepted the certificate, but some of its details deserve attention. Acceptance does not mean the website itself is safe.".to_string(),
                },
                Trust::NotTrusted { .. } => {
                    let names: Vec<&str> =
                        problems.iter().map(|problem| problem_name(*problem)).collect();
                    Verdict {
                        status: worst,
                        headline: "This certificate has problems.".to_string(),
                        detail: format!("Windows does not trust it: {}.", names.join(", ")),
                    }
                }
            };
            (verdict, findings)
        }
    }
}
