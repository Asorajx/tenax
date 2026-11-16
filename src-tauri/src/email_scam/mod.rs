// Email Scam Checker: reads the text of an email and points out common scam signs.
// It runs entirely on this PC. Nothing is sent anywhere and nothing is stored or logged.
// The email is only read as data. No link is opened or followed, and nothing in the HTML is
// run, so it cannot load images or scripts or contact any site.
//
// content.rs  splits off any header block, reads the HTML and finds the links
// links.rs    checks the links and page elements
// signs.rs    finds scam wording, with context
// findings.rs turns all of that into four cards and a verdict
//
// Sender and sign-in results belong to the Email Headers tool, and are not mixed into these.
// The two tools share only the header reader that splits a pasted message in two.

pub(crate) mod content;
mod findings;
// The link checks are written so that the URL Checker can use them too, one address at a time.
pub(crate) mod links;
mod signs;
mod words;

#[cfg(test)]
mod tests;

use std::time::Instant;

use serde::Serialize;

use crate::finding::{Finding, Step, count_of};

// More than this is not an email, so it is refused rather than slowing the app down.
const MAX_LENGTH: usize = 1_000_000;

// Fewer words than this cannot be checked at all.
const MIN_WORDS: usize = 3;

#[derive(Serialize)]
pub struct ScamReport {
    pub verdict: findings::Verdict,
    pub findings: Vec<Finding>,
}

// Called from the interface with invoke("check_email_scam", { raw }).
#[tauri::command]
pub fn check_email_scam(raw: String) -> Result<ScamReport, String> {
    if raw.len() > MAX_LENGTH {
        return Err("That is too much text to be an email.".to_string());
    }
    // The message of a panic can repeat the text being read, so a failure is turned into a
    // plain error here and the email is never part of it.
    std::panic::catch_unwind(|| analyse(&raw))
        .unwrap_or_else(|_| Err("Tenax could not read this email.".to_string()))
}

fn analyse(raw: &str) -> Result<ScamReport, String> {
    let started = Instant::now();

    let source = content::read_source(raw);
    let content = content::read(&source.body, source.subject.as_deref());
    if content.words < MIN_WORDS {
        return Err("There is too little text to check. Paste the whole email.".to_string());
    }

    let report = links::analyse(&content.links, &content.elements, &content.text);
    let found = signs::scan(&content.text);
    let refers = signs::refers_to_links(&content.text);
    let references = signs::link_references(&content.text);

    let coverage = findings::text_limit(&content, &source);
    let read_step = Step::new(
        "Read the pasted email",
        "Read the text and found the links in the email",
        "Split off any header block, decoded the text, parsed any HTML as data without running it, and listed the web links",
        format!(
            "{} read, {} found{}",
            count_of(content.words, "word"),
            count_of(report.analysed + report.incomplete, "link"),
            if source.has_headers {
                ", header block set aside"
            } else {
                ""
            }
        ),
        started,
    );
    let coverage_step = Step::new(
        "Checked how much could be read",
        "Checked whether the whole email could be read and checked",
        "Looked for encoded parts, images, very short text and languages other than English",
        coverage.unwrap_or_else(|| "All of the text could be read".to_string()),
        started,
    );

    let mut cards = findings::cards(&content, &source, &found, &report, refers, references);
    let verdict = findings::verdict(&cards);

    // Reading the text comes first, so its steps lead the first card's steps.
    cards[0].finding.steps.insert(0, coverage_step);
    cards[0].finding.steps.insert(0, read_step);

    Ok(ScamReport {
        verdict,
        findings: cards.into_iter().map(|card| card.finding).collect(),
    })
}
