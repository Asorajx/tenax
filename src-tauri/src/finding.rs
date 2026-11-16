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
    // What Tenax did to get this result. Filled in after the readings, not by findings.rs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
}

pub fn detail(label: &str, value: impl Into<String>) -> Detail {
    Detail {
        label: label.to_string(),
        value: value.into(),
        active: None,
    }
}

// A detail for something that is either on or off, such as an antivirus product.
pub fn switch(label: &str, value: impl Into<String>, active: bool) -> Detail {
    Detail {
        active: Some(active),
        ..detail(label, value)
    }
}
