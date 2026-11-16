// Turns what was found in an email into four cards and an overall verdict.
// A card has one of three outcomes, and they are never mixed up:
//   checked   the information was there, the checks ran and found nothing
//   limited   some information was missing, so the card cannot say either way
//   concern   something suspicious was found, with the reason
// There are no scores. A card can have a concern and a limit together, and both are kept.

use std::time::Instant;

use serde::Serialize;

use super::content::{Content, Source};
use super::links::Report;
use super::signs::{self, Found, Group, Weight};
use crate::finding::{Detail, Finding, Status, Step, UrlItem, count_of, detail};

// How many rows a card lists before the rest are summarised.
const MAX_ROWS: usize = 6;
// How many links the Links card lists. The rest are counted, not listed.
const MAX_URLS: usize = 30;
// How many quoted phrases a note shows.
const MAX_PHRASES: usize = 6;

pub struct Card {
    pub finding: Finding,
    // Whether anything was missing, even if the card also found something.
    pub limited: bool,
}

// What each card looks for and why. These stay the same whatever the result is.
struct Check {
    id: &'static str,
    title: &'static str,
    checked: &'static str,
    why: &'static str,
}

const PRESSURE: Check = Check {
    id: "pressure",
    title: "Pressure and urgency",
    checked: "I looked for deadlines, threats and alarming warnings in the text.",
    why: "Scammers rush you so that you act before you stop to check.",
};

const REQUESTS: Check = Check {
    id: "requests",
    title: "Requests for money or details",
    checked: "I looked for requests for passwords, codes, card details and payments.",
    why: "Taking your login, your money or your details is what most scams are for.",
};

const LINKS: Check = Check {
    id: "links",
    title: "Links",
    checked: "I read where each link goes and compared it with what the email says.",
    why: "Scam links often hide where they lead, or pretend to belong to a company you trust.",
};

const OTHER: Check = Check {
    id: "other",
    title: "Other signs",
    checked: "I looked for generic greetings, prizes, requests for secrecy and risky attachments.",
    why: "These are common in scams, though some also appear in genuine mass emails.",
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
// Coverage
// =========================

// Words that nearly every English sentence has. Wording checks only cover English, so text
// that has almost none of them cannot be checked this way.
const COMMON_WORDS: &[&str] = &[
    "the", "and", "to", "of", "a", "is", "in", "you", "your", "for", "with", "this", "that", "it",
    "on", "be", "are", "as", "we", "will", "have", "not",
];

fn looks_english(text: &str) -> bool {
    let words: Vec<&str> = text.split_whitespace().collect();
    let common = words
        .iter()
        .filter(|word| COMMON_WORDS.contains(&word.trim_matches(|c: char| !c.is_alphanumeric())))
        .count();
    common * 100 >= words.len() * 8
}

// Why the wording checks could not cover the whole email, if they could not.
pub fn text_limit(content: &Content, source: &Source) -> Option<String> {
    if source.encoded {
        Some(
            "Part of this email is encoded and was not decoded, so its words could not be read."
                .to_string(),
        )
    } else if content.images > 0 && content.words < 60 {
        Some("Much of this email appears to be images, which Tenax cannot read.".to_string())
    } else if content.words < 12 {
        Some("There is very little text to check.".to_string())
    } else if content.words >= 25 && !looks_english(&content.text) {
        Some("This email does not look like it is written in English, and the wording checks only cover English.".to_string())
    } else {
        None
    }
}

// =========================
// Wording cards
// =========================

// The wording that was found, quoted, so that the reader can see what Tenax matched.
fn rows(found: &[&Found]) -> Vec<Detail> {
    let mut rows: Vec<Detail> = found
        .iter()
        .take(MAX_ROWS)
        .map(|item| {
            // What was matched, quoted, so the reader can see it. Why it matters is kept in
            // the reason, which the interface folds away until it is asked for.
            let shown: Vec<String> = item
                .phrases
                .iter()
                .take(MAX_PHRASES)
                .map(|phrase| format!("\"{phrase}\""))
                .collect();
            detail(item.category.name, shown.join(", ")).because(item.category.why)
        })
        .collect();
    if found.len() > MAX_ROWS {
        rows.push(detail("More", format!("{} more", found.len() - MAX_ROWS)));
    }
    rows
}

struct Wording<'a> {
    check: &'a Check,
    found: &'a [&'a Found],
    // The status to give if anything was found.
    status: Status,
    limit: Option<&'a str>,
    // Said when what was found is only low-concern.
    context: &'a str,
    step: (&'a str, &'a str),
}

fn wording_card(wording: Wording, extra_notes: Vec<String>) -> Card {
    let started = Instant::now();
    let Wording {
        check,
        found,
        status,
        limit,
        context,
        step,
    } = wording;

    let status = match (found.is_empty(), limit) {
        (true, None) => Status::Ok,
        (true, Some(_)) => Status::Limited,
        (false, _) => status,
    };
    let summary = match status {
        Status::Ok => "Checked · no suspicious patterns".to_string(),
        Status::Limited => "Limited analysis".to_string(),
        _ => {
            let counted = if status == Status::Info {
                count_of(found.len(), "note")
            } else {
                count_of(found.len(), "sign")
            };
            if limit.is_some() {
                format!("{counted} · limited analysis")
            } else {
                counted
            }
        }
    };
    let action = matches!(status, Status::Warning | Status::Risk)
        .then(|| signs::advice(found))
        .flatten();

    let mut note = Vec::new();
    if status == Status::Info && !context.is_empty() {
        note.push(context.to_string());
    }
    note.extend(limit.map(str::to_string));
    note.extend(extra_notes);

    let result = format!("{} matched", count_of(found.len(), "wording type"));
    let finding = finding(
        check,
        status,
        summary,
        action,
        rows(found),
        note,
        Step::new(
            step.0,
            step.1,
            "Whole-word phrase matching on the visible text of the email, with each kind of wording counted once",
            result,
            started,
        ),
    );
    Card {
        finding,
        limited: limit.is_some(),
    }
}

// =========================
// Links card
// =========================

fn links_card(
    report: &Report,
    content: &Content,
    source: &Source,
    refers: bool,
    references: usize,
) -> Card {
    let started = Instant::now();

    let found = report.analysed + report.incomplete;
    let mut limits = report.limits.clone();
    if source.encoded {
        limits.push(
            "Part of this email is encoded, so links inside it could not be read.".to_string(),
        );
    }
    // Words that act as links, such as "click here", with fewer addresses than there are words.
    // Pasted text often keeps the words and drops where they go.
    if found == 0 && refers {
        limits.push(
            "The text mentions links, such as \"click here\", but does not include where they go. Paste the full message source to check them."
                .to_string(),
        );
    } else if !content.is_html && references > found {
        limits.push(format!(
            "The text points at {} in words, such as \"click here\", but only {} included. Paste the full message source to check the rest.",
            count_of(references, "link"),
            count_of(found, "address").replace(" address", if found == 1 { " address is" } else { " addresses are" }),
        ));
    }
    let limited = !limits.is_empty();

    let concerns = report
        .issues
        .iter()
        .filter(|issue| matches!(issue.status, Status::Risk | Status::Warning))
        .count();
    let status = match report.issues.iter().map(|issue| issue.status).min() {
        Some(worst @ (Status::Risk | Status::Warning)) => worst,
        _ if limited => Status::Limited,
        Some(_) => Status::Info,
        None if report.analysed > 0 => Status::Ok,
        None => Status::Info,
    };

    let summary = match status {
        Status::Risk | Status::Warning => {
            let text = format!(
                "{} in {}",
                count_of(concerns, "concern"),
                count_of(found, "link")
            );
            if limited {
                format!("{text} · limited analysis")
            } else {
                text
            }
        }
        Status::Limited => "Limited analysis".to_string(),
        Status::Ok => "Checked · no suspicious patterns".to_string(),
        _ if found == 0 => "No links found in this text".to_string(),
        _ => format!("{} to note", count_of(report.issues.len(), "thing")),
    };

    let mut details = vec![detail("Links found", found.to_string())];
    if report.unknown > 0 {
        details.push(detail(
            "Destination not visible",
            format!("{} of {}", report.unknown, found),
        ));
    }
    details.extend(report.issues.iter().take(MAX_ROWS).map(|issue| {
        let row = detail(&issue.label, &issue.value);
        match &issue.reason {
            Some(reason) => row.because(reason),
            None => row,
        }
    }));
    if report.issues.len() > MAX_ROWS {
        details.push(detail(
            "More",
            format!("{} more", report.issues.len() - MAX_ROWS),
        ));
    }

    let action = matches!(status, Status::Risk | Status::Warning).then_some(
        "Do not click these links. Type the organisation's address into your browser yourself, or use its official app.",
    );

    let mut note = limits;
    if report.items.len() > MAX_URLS {
        note.push(format!(
            "Showing the first {MAX_URLS} of {}.",
            count_of(report.items.len(), "link")
        ));
    }

    let result = format!(
        "{} read, {} not visible",
        count_of(report.analysed, "link"),
        report.unknown
    );
    let mut finding = finding(
        &LINKS,
        status,
        summary,
        action,
        details,
        note,
        Step::new(
            "Checked the links",
            "Looked at where each link goes, without opening any of them",
            "Addresses parsed with the url crate and compared by registered domain using the public suffix list. No link is opened or followed",
            result,
            started,
        ),
    );
    // The addresses themselves, each with its own short assessment. They are shown as text.
    finding.urls = report
        .items
        .iter()
        .take(MAX_URLS)
        .map(|item| UrlItem {
            url: item.url.clone(),
            status: item.status,
            assessment: item.assessment.clone(),
        })
        .collect();
    Card { finding, limited }
}

// =========================
// All cards
// =========================

pub fn cards(
    content: &Content,
    source: &Source,
    found: &[Found],
    report: &Report,
    refers: bool,
    references: usize,
) -> Vec<Card> {
    let limit = text_limit(content, source);
    let limit = limit.as_deref();

    let group = |wanted: Group| -> Vec<&Found> {
        found
            .iter()
            .filter(|item| item.category.group == wanted)
            .collect()
    };
    let (pressure, requests, other) = (
        group(Group::Pressure),
        group(Group::Requests),
        group(Group::Other),
    );
    let has =
        |list: &[&Found], weight: Weight| list.iter().any(|item| item.category.weight == weight);

    let strong_request = has(&requests, Weight::Strong);
    let mild_request = has(&requests, Weight::Mild);
    let other_strong = has(&other, Weight::Strong);
    let elsewhere = strong_request || mild_request || other_strong || report.concern();

    // Wording on its own is only a note. It becomes a concern next to another concern.
    let pressure_status = if elsewhere {
        Status::Warning
    } else {
        Status::Info
    };
    let requests_status = if strong_request {
        Status::Risk
    } else if mild_request && (!pressure.is_empty() || other_strong || report.concern()) {
        Status::Warning
    } else {
        Status::Info
    };
    let other_status = if other_strong {
        Status::Warning
    } else {
        Status::Info
    };

    let mut other_notes = Vec::new();
    if source.has_headers {
        other_notes.push(
            "This looks like a full message. Sender and sign-in checks are in Email Headers, and are kept apart from these results."
                .to_string(),
        );
    }
    vec![
        wording_card(
            Wording {
                check: &PRESSURE,
                found: &pressure,
                status: pressure_status,
                limit,
                context: "Common in ordinary email. It matters mainly alongside other signs.",
                step: (
                    "Looked for pressure and urgency",
                    "Looked for deadlines, threats and alarming warnings",
                ),
            },
            Vec::new(),
        ),
        wording_card(
            Wording {
                check: &REQUESTS,
                found: &requests,
                status: requests_status,
                limit,
                context: "Common in ordinary email. It matters mainly alongside other signs.",
                step: (
                    "Looked for requests for money or details",
                    "Looked for requests for passwords, codes, card details and payments",
                ),
            },
            Vec::new(),
        ),
        links_card(report, content, source, refers, references),
        wording_card(
            Wording {
                check: &OTHER,
                found: &other,
                status: other_status,
                limit,
                context: "",
                step: (
                    "Looked for other signs",
                    "Looked for generic greetings, prizes, requests for secrecy and risky attachments",
                ),
            },
            other_notes,
        ),
    ]
}

// =========================
// Verdict
// =========================

#[derive(Serialize)]
pub struct Verdict {
    pub status: Status,
    pub headline: String,
    pub detail: String,
}

// The overall result, from the cards. A limited analysis is never reported as a clean one.
pub fn verdict(cards: &[Card]) -> Verdict {
    let status_of = |id: &str| {
        cards
            .iter()
            .find(|card| card.finding.id == id)
            .map(|card| card.finding.status)
    };
    let worry = |status: Status| matches!(status, Status::Risk | Status::Warning);

    let any_risk = cards.iter().any(|card| card.finding.status == Status::Risk);
    let any_warning = cards.iter().any(|card| worry(card.finding.status));
    let links_worry = status_of("links").is_some_and(worry);
    let others_worry = cards
        .iter()
        .any(|card| card.finding.id != "links" && worry(card.finding.status));
    let limited: Vec<&str> = cards
        .iter()
        .filter(|card| card.limited)
        .map(|card| card.finding.title.as_str())
        .collect();

    let also_limited = if limited.is_empty() {
        String::new()
    } else {
        format!(" Some checks were also limited: {}.", limited.join(", "))
    };

    if any_risk || (links_worry && others_worry) {
        Verdict {
            status: Status::Risk,
            headline: "Strong scam indicators detected.".to_string(),
            detail: format!(
                "Do not click links, open attachments or reply until you have checked with the sender another way.{also_limited}"
            ),
        }
    } else if any_warning {
        Verdict {
            status: Status::Warning,
            headline: "Some suspicious indicators worth checking.".to_string(),
            detail: format!(
                "Look at the points below before you reply, click or pay.{also_limited}"
            ),
        }
    } else if !limited.is_empty() {
        Verdict {
            status: Status::Limited,
            headline: "Analysis limited by missing information.".to_string(),
            detail: format!(
                "Tenax could not check everything: {}. No scam indicators were found in what it could check, but that is not a clean result.",
                limited.join(", ")
            ),
        }
    } else {
        Verdict {
            status: Status::Ok,
            headline: "No common scam indicators detected.".to_string(),
            detail: "This only reflects the checks Tenax can run on the text you pasted, and it \
                     does not guarantee that the email is safe."
                .to_string(),
        }
    }
}
