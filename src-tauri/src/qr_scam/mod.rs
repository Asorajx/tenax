// QR Code Checker: reads what QR codes contain and says whether they look like a scam.
//
// The interface reads the codes out of an image on this PC and sends only their text here. This
// side works out what each one is, and for a web link it uses the URL Checker, so the two tools
// agree. Nothing is opened, followed or sent, and nothing is stored.
//
// The text comes from an image that anyone could have made, so it is treated as untrusted. It is
// only ever read. Its length is capped, hidden characters are taken out, and a secret in it is
// never shown.
//
// payload.rs   works out what a code contains, with no network or Windows code
// findings.rs  turns that into cards

mod findings;
mod payload;

#[cfg(test)]
mod tests;

use std::time::Instant;

use serde::Serialize;

use crate::finding::{Finding, Status, Step, Verdict, detail};
use payload::{MAX_LENGTH, Payload, classify, clean};

// The most codes read from one image. It must match MAX_CODES in src/app/qrImage.ts.
const MAX_CODES: usize = 5;

#[derive(Serialize)]
pub struct QrReport {
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
}

// Called from the interface with invoke("check_qr", { payloads }).
#[tauri::command]
pub fn check_qr(payloads: Vec<String>) -> Result<QrReport, String> {
    if payloads.is_empty() {
        return Err("No QR code was found.".to_string());
    }
    if payloads.len() > MAX_CODES {
        return Err("That image has too many codes to read.".to_string());
    }
    // The message of a panic can repeat what was being read, so a failure becomes a plain error.
    std::panic::catch_unwind(|| Ok(analyse(&payloads)))
        .unwrap_or_else(|_| Err("Tenax could not read this code.".to_string()))
}

// When there are several codes, each card says which code it is about.
fn label(findings: Vec<Finding>, index: usize, total: usize) -> Vec<Finding> {
    if total == 1 {
        return findings;
    }
    findings
        .into_iter()
        .map(|mut finding| {
            finding.id = format!("qr-{}-{}", index + 1, finding.id);
            finding.title = format!("Code {} · {}", index + 1, finding.title);
            finding
        })
        .collect()
}

fn analyse(texts: &[String]) -> QrReport {
    let total = texts.len();
    let mut findings = Vec::new();
    let mut verdicts = Vec::new();

    for (index, text) in texts.iter().enumerate() {
        let started = Instant::now();

        if text.chars().count() > MAX_LENGTH {
            let card = findings::too_long(index, total);
            verdicts.push((
                index,
                Verdict {
                    status: card.status,
                    headline: "This code is too long to read".to_string(),
                    detail: card.action.clone().unwrap_or_default(),
                },
            ));
            findings.push(card);
            continue;
        }

        let (text, hidden) = clean(text);
        let payload = classify(&text);
        let mut card = findings::header(index, total, &payload, hidden);
        card.steps.push(Step::new(
            "Read what the QR code contains",
            "Looked at what the code holds, without opening anything",
            "Pattern match on the text read from the image. No network, no files.",
            format!("{} read", card.summary),
            started,
        ));
        // A web link is judged by the URL Checker, so the two tools agree.
        let verdict = match &payload {
            Payload::Link(address) => match crate::url_check::analyse(address) {
                Ok(report) => {
                    // Hidden characters in the text are a warning of their own, even if the
                    // address itself looks fine.
                    let verdict = if hidden && card.status < report.verdict.status {
                        Verdict {
                            status: card.status,
                            headline: "The link in this code has hidden characters".to_string(),
                            detail: "A genuine code rarely needs text that cannot be seen. Do not open it."
                                .to_string(),
                        }
                    } else {
                        report.verdict
                    };
                    findings.push(card);
                    findings.extend(label(report.findings, index, total));
                    verdicts.push((index, verdict));
                    continue;
                }
                Err(problem) => {
                    card.status = Status::Limited;
                    card.details.push(detail("Problem", problem.clone()));
                    Verdict {
                        status: Status::Limited,
                        headline: "This link could not be checked".to_string(),
                        detail: problem,
                    }
                }
            },
            _ => findings::verdict(&payload, &card),
        };
        findings.push(card);
        verdicts.push((index, verdict));
    }

    // The most serious result speaks for the whole image, and says which code it is about.
    let (index, mut verdict) = verdicts
        .into_iter()
        .min_by_key(|(_, verdict)| verdict.status)
        .expect("there is at least one code");
    if total > 1 {
        verdict.headline = format!("Code {}: {}", index + 1, verdict.headline);
    }
    QrReport { verdict, findings }
}
