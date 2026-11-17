use std::time::Instant;

use serde::Serialize;

// The result shape every tool returns. It must match the Finding type in
// src/components/Finding.tsx.

// Listed from most to least serious, which is also the order findings are shown in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Risk,
    Warning,
    // The check itself failed, so nothing can be said either way.
    Unknown,
    // The check ran, but information it needed was missing, so it cannot say either way.
    Limited,
    Info,
    Ok,
}

#[derive(Debug, Serialize)]
pub struct Detail {
    pub label: String,
    pub value: String,
    // Whether this item is switched on. Left out for items that are not on or off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    // Why this item matters. The interface keeps these folded away until they are asked for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// The overall result of a tool that looks at something and gives an answer in words. A limited
// analysis has its own status because it is not a clean result.
#[derive(Debug, Serialize)]
pub struct Verdict {
    pub status: Status,
    pub headline: String,
    pub detail: String,
}

// A web address a check found, with a short assessment of it. Any tool can list these, and
// the interface shows them as plain text that cannot be clicked.
#[derive(Debug, Clone, Serialize)]
pub struct UrlItem {
    pub url: String,
    pub status: Status,
    pub assessment: String,
}

// One thing Tenax actually did while running a check, recorded as it ran.
#[derive(Debug, Clone, Serialize)]
pub struct Step {
    // A short sentence, such as "Queried Windows Security Center for antivirus status".
    pub action: String,
    // The same step in plain English, for the Basic view.
    pub plain: String,
    // The API or call that was used.
    pub method: String,
    pub ok: bool,
    // What came back, or the error if it failed.
    pub result: String,
    pub ms: f64,
    // Text to hide when the log is copied, such as the hash prefix that was sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redact: Option<String>,
}

impl Step {
    // A step that worked, timed from when it started. The step ends when this is called.
    pub fn new(action: &str, plain: &str, method: &str, result: String, started: Instant) -> Step {
        Step {
            action: action.to_string(),
            plain: plain.to_string(),
            method: method.to_string(),
            ok: true,
            result,
            ms: started.elapsed().as_secs_f64() * 1000.0,
            redact: None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub id: String,
    pub status: Status,
    // The name of the check, such as "Antivirus".
    pub title: String,
    // The state at a glance, such as "On · Microsoft Defender Antivirus".
    pub summary: String,
    // What Tenax actually read, in the first person, so the user does not have to guess.
    pub checked: String,
    // Why Tenax checks it.
    pub why: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<Detail>,
    // A short explanation shown under the details, such as what a result does and does not mean.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    // Web addresses the check found, each with its own assessment.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<UrlItem>,
    // What Tenax did to get this result. Filled in after the readings, not by findings.rs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
}

pub fn detail(label: &str, value: impl Into<String>) -> Detail {
    Detail {
        label: label.to_string(),
        value: value.into(),
        active: None,
        reason: None,
    }
}

impl Detail {
    pub fn because(self, reason: impl Into<String>) -> Detail {
        Detail {
            reason: Some(reason.into()),
            ..self
        }
    }
}

// A detail for something that is either on or off, such as an antivirus product.
pub fn switch(label: &str, value: impl Into<String>, active: bool) -> Detail {
    Detail {
        active: Some(active),
        ..detail(label, value)
    }
}

// A count with its noun in the right form, such as "1 server" or "2 servers".
pub fn count_of(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("{count} {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

// Cuts long text to a number of characters, ending with an ellipsis.
pub fn shorten(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let kept: String = text.chars().take(max - 1).collect();
    format!("{kept}…")
}

// Joins names for a sentence, such as "SPF, DKIM and DMARC" or "SPF, DKIM or DMARC".
pub fn join_names(names: &[&str], last: &str) -> String {
    match names {
        [] => String::new(),
        [only] => only.to_string(),
        [rest @ .., end] => format!("{} {last} {end}", rest.join(", ")),
    }
}
