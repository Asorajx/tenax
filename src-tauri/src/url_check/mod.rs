// URL Checker: reads one web address and points out signs that it is not what it seems.
// It runs entirely on this PC. The address is never opened, followed, looked up or sent
// anywhere, and nothing is stored or logged. Only its structure is read.
//
// The checks are the same ones the Email Scam Checker uses for the links in an email, run on a
// single address, so the two tools agree. Looking up an address's reputation with an outside
// service is not part of this tool, because it would send the address to a third party.

#[cfg(test)]
mod tests;

use std::time::Instant;

use serde::Serialize;
use url::{Host, Url};

use crate::email_scam::content::RawLink;
use crate::email_scam::links::{self, Issue, Report, registered};
use crate::finding::{Detail, Finding, Status, Step, Verdict, count_of, detail, shorten};

// A longer address than this is not a link that anyone would open.
const MAX_LENGTH: usize = 4096;
// How much of a long path is shown.
const MAX_PATH_SHOWN: usize = 60;

#[derive(Serialize)]
pub struct UrlReport {
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
}

// Called from the interface with invoke("check_url", { url }).
#[tauri::command]
pub fn check_url(url: String) -> Result<UrlReport, String> {
    if url.len() > MAX_LENGTH {
        return Err("That is too long to be a web address.".to_string());
    }
    // The message of a panic can repeat what was being read, so a failure is turned into a
    // plain error here and the address is never part of it.
    std::panic::catch_unwind(|| analyse(&url))
        .unwrap_or_else(|_| Err("Tenax could not read this address.".to_string()))
}

// =========================
// Reading the address
// =========================

// Turns what was typed into an address to check, adding https:// when no scheme was given.
// The second value says whether that was done.
fn normalise(input: &str) -> Result<(String, bool), String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("Enter a web address to check.".to_string());
    }
    if input.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("A web address has no spaces. Paste one link at a time.".to_string());
    }

    let lower = input.to_ascii_lowercase();
    if input.contains("://")
        || ["javascript:", "data:", "vbscript:"]
            .iter()
            .any(|s| lower.starts_with(s))
    {
        return Ok((input.to_string(), false));
    }
    if ["mailto:", "tel:", "sms:"]
        .iter()
        .any(|s| lower.starts_with(s))
    {
        return Err("That is not a web address.".to_string());
    }
    // Something like "example.com/login" is a web address with the scheme left off.
    if input.contains('.') {
        return Ok((format!("https://{input}"), true));
    }
    Err("That does not look like a web address.".to_string())
}

// What the address is made of, so that it can be read part by part.
fn parts(url: &Url) -> Vec<Detail> {
    let mut rows = vec![detail("Scheme", url.scheme())];

    match url.host() {
        Some(Host::Domain(domain)) => {
            let (unicode, _) = idna::domain_to_unicode(domain);
            let site = if unicode == domain {
                domain.to_string()
            } else {
                format!("{unicode} ({domain})")
            };
            rows.push(detail("Site", site));
            if let Some(registered) = registered(domain) {
                let subdomain = domain
                    .strip_suffix(registered.as_str())
                    .unwrap_or("")
                    .trim_end_matches('.');
                rows.push(detail("Registered domain", registered));
                rows.push(detail(
                    "Subdomain",
                    if subdomain.is_empty() {
                        "None"
                    } else {
                        subdomain
                    },
                ));
            }
        }
        Some(Host::Ipv4(address)) => rows.push(detail("Site", address.to_string())),
        Some(Host::Ipv6(address)) => rows.push(detail("Site", address.to_string())),
        None => {}
    }
    if let Some(port) = url.port() {
        rows.push(detail("Port", port.to_string()));
    }
    if url.path().len() > 1 {
        rows.push(detail("Path", shorten(url.path(), MAX_PATH_SHOWN)));
    }
    let parameters = url.query_pairs().count();
    if parameters > 0 {
        rows.push(detail("Parameters", count_of(parameters, "parameter")));
    }
    rows
}

// =========================
// Cards
// =========================

struct Check {
    id: &'static str,
    title: &'static str,
    checked: &'static str,
    why: &'static str,
}

const ADDRESS: Check = Check {
    id: "address",
    title: "The address",
    checked: "I split the address into its parts.",
    why: "Reading an address part by part shows which site it really belongs to.",
};

const LOOKALIKES: Check = Check {
    id: "lookalikes",
    title: "Look-alikes",
    checked: "I compared the site name with well-known companies and looked for look-alike letters.",
    why: "Scam sites often borrow a trusted name or imitate it with similar-looking letters.",
};

const DESTINATION: Check = Check {
    id: "destination",
    title: "Where it goes",
    checked: "I looked for shortened, hidden, encoded or redirecting addresses.",
    why: "A link that hides where it leads stops you from judging it before you open it.",
};

const CONNECTION: Check = Check {
    id: "connection",
    title: "Connection",
    checked: "I looked at how the address connects and what it ends with.",
    why: "These are weaker signs, which matter mostly alongside the others.",
};

// Which card a point belongs on.
#[derive(PartialEq, Clone, Copy)]
enum Group {
    Lookalikes,
    Destination,
    Connection,
}

fn group_of(label: &str) -> Group {
    if label.starts_with("Looks like")
        || label == "Mixed alphabets"
        || label == "International characters"
    {
        Group::Lookalikes
    } else if matches!(label, "Not encrypted" | "Unusual ending") {
        Group::Connection
    } else {
        Group::Destination
    }
}

fn card(
    check: &Check,
    issues: &[&Issue],
    limits: &[String],
    action: Option<&str>,
    step: (&str, &str, &str),
) -> Finding {
    let started = Instant::now();

    let status = match issues.iter().map(|issue| issue.status).min() {
        Some(worst @ (Status::Risk | Status::Warning)) => worst,
        _ if !limits.is_empty() => Status::Limited,
        Some(_) => Status::Info,
        None => Status::Ok,
    };
    let summary = match status {
        Status::Ok => "Checked · no suspicious patterns".to_string(),
        Status::Limited => "Limited analysis".to_string(),
        Status::Info => count_of(issues.len(), "note"),
        _ => count_of(issues.len(), "concern"),
    };

    let rows: Vec<Detail> = issues
        .iter()
        .map(|issue| {
            let row = detail(&issue.label, &issue.value);
            match &issue.reason {
                Some(reason) => row.because(reason),
                None => row,
            }
        })
        .collect();

    Finding {
        id: check.id.to_string(),
        status,
        title: check.title.to_string(),
        summary,
        checked: check.checked.to_string(),
        why: check.why.to_string(),
        action: matches!(status, Status::Risk | Status::Warning)
            .then_some(action)
            .flatten()
            .map(str::to_string),
        details: rows,
        steps: vec![Step::new(
            step.0,
            step.1,
            step.2,
            format!("{} found", count_of(issues.len(), "point")),
            started,
        )],
        note: (!limits.is_empty()).then(|| limits.join(" ")),
        urls: Vec::new(),
    }
}

// The address card is different: it lists the parts, and only says something if it could not
// read the address in full or had to add a scheme.
fn address_card(url: Option<&Url>, assumed: bool, started: Instant) -> Finding {
    let (status, summary, details, mut note) = match url {
        Some(url) => (
            if assumed { Status::Info } else { Status::Ok },
            if assumed {
                "Read · https assumed"
            } else {
                "Read in full"
            },
            parts(url),
            Vec::new(),
        ),
        None => (
            Status::Limited,
            "Limited analysis",
            Vec::new(),
            vec![
                "This could not be read as a complete web address, so it could not be checked."
                    .to_string(),
            ],
        ),
    };
    if assumed {
        note.push("No protocol was specified, so Tenax assumed HTTPS.".to_string());
    }

    Finding {
        id: ADDRESS.id.to_string(),
        status,
        title: ADDRESS.title.to_string(),
        summary: summary.to_string(),
        checked: ADDRESS.checked.to_string(),
        why: ADDRESS.why.to_string(),
        action: None,
        details,
        steps: vec![Step::new(
            "Read the address",
            "Split the address into its parts",
            "Parsed with the url crate. The site name is split into registered domain and subdomain using the public suffix list",
            if url.is_some() {
                "Read in full".to_string()
            } else {
                "Could not be read".to_string()
            },
            started,
        )],
        note: (!note.is_empty()).then(|| note.join(" ")),
        urls: Vec::new(),
    }
}

// =========================
// Analysis
// =========================

fn verdict(cards: &[Finding]) -> Verdict {
    let any = |wanted: Status| cards.iter().any(|card| card.status == wanted);

    if any(Status::Risk) {
        Verdict {
            status: Status::Risk,
            headline: "Strong phishing indicators detected.".to_string(),
            detail:
                "Avoid opening this link. Verify it with the sender through another trusted method."
                    .to_string(),
        }
    } else if any(Status::Warning) {
        Verdict {
            status: Status::Warning,
            headline: "Some suspicious indicators worth checking.".to_string(),
            detail: "Review the findings below before opening this link.".to_string(),
        }
    } else if any(Status::Limited) {
        Verdict {
            status: Status::Limited,
            headline: "Analysis limited by missing information.".to_string(),
            detail: "Tenax couldn't check everything, so this isn't a clean result. What it did check showed no suspicious signs.".to_string(),
        }
    } else {
        Verdict {
            status: Status::Ok,
            headline: "No common phishing indicators detected.".to_string(),
            detail: "Only the link address was checked, not the website itself.".to_string(),
        }
    }
}

fn analyse(input: &str) -> Result<UrlReport, String> {
    let started = Instant::now();
    let (address, assumed) = normalise(input)?;

    let report: Report = links::analyse(
        &[RawLink {
            href: address.clone(),
            shown: None,
        }],
        &[],
        "",
    );
    if report.items.is_empty() {
        return Err("Only web addresses starting with http or https can be checked.".to_string());
    }
    // An address that links could read but the parser could not is incomplete.
    let url = Url::parse(&address)
        .ok()
        .filter(|url| matches!(url.scheme(), "http" | "https"));

    let in_group = |wanted: Group| -> Vec<&Issue> {
        report
            .issues
            .iter()
            .filter(|issue| group_of(&issue.label) == wanted)
            .collect()
    };

    let findings = vec![
        address_card(url.as_ref(), assumed, started),
        card(
            &LOOKALIKES,
            &in_group(Group::Lookalikes),
            &[],
            Some(
                "Do not open this address. Go to the organisation's website by typing its name yourself.",
            ),
            (
                "Compared the site name with well-known companies",
                "Checked whether the site name imitates a company you might trust",
                "Site name compared with a list of well-known companies by registered domain, including look-alike letters, number-for-letter swaps and mixed alphabets",
            ),
        ),
        card(
            &DESTINATION,
            &in_group(Group::Destination),
            &report.limits,
            Some(
                "Do not open this address. Ask the sender for the real destination, or go to the organisation's website yourself.",
            ),
            (
                "Looked for hidden destinations",
                "Looked for signs the address hides or changes where it really goes",
                "Checked for shortening and tracking services, addresses hidden in the query, encoded site names, names placed before the site and numeric addresses. Nothing was opened or followed",
            ),
        ),
        card(
            &CONNECTION,
            &in_group(Group::Connection),
            &[],
            None,
            (
                "Checked the connection",
                "Checked whether the address is encrypted and what it ends with",
                "Scheme and ending of the site name compared with endings often used in scams",
            ),
        ),
    ];

    let verdict = verdict(&findings);
    Ok(UrlReport { verdict, findings })
}
