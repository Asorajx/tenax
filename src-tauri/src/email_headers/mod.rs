// Email Headers check: reads raw email headers and explains what they show.
// It runs entirely on this PC. Nothing is sent anywhere and nothing is stored.
//
// parser.rs   reads the raw text into fields and pulls out addresses and results
// findings.rs turns those into findings, with no Windows or network code in it

mod findings;
mod parser;

use std::time::Instant;

use crate::finding::{Finding, Step};

// More than this is not a set of headers, so it is refused rather than slowing the app down.
const MAX_LENGTH: usize = 1_000_000;

// Called from the interface with invoke("analyse_email_headers", { raw }).
#[tauri::command]
pub fn analyse_email_headers(raw: String) -> Result<Vec<Finding>, String> {
    if raw.len() > MAX_LENGTH {
        return Err("That is too much text to be email headers.".to_string());
    }

    let started = Instant::now();
    let headers = parser::Headers::parse(&raw);
    if headers.len() == 0 {
        return Err(
            "No email headers were found. Paste the full headers, which start with lines such \
             as Received: or From:"
                .to_string(),
        );
    }
    let parse_step = Step::new(
        "Read the pasted headers",
        "Split the pasted text into the email's header fields",
        "Header fields split by line, with folded lines joined, stopping at the first blank line",
        format!("{} read", findings::count_of(headers.len(), "header field")),
        started,
    );

    let mut results = vec![
        findings::authentication(&headers),
        findings::identity(&headers),
        findings::path(&headers),
    ];
    // Reading the text comes first, so its step leads the first finding's steps.
    results[0].steps.insert(0, parse_step);
    Ok(results)
}

// =========================
// Tests
// =========================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Status;

    // A forged message: the sender shows a bank, but replies go elsewhere and DMARC failed.
    const FORGED: &str = "Received: from mx.example.net (mx.example.net [10.0.0.1]) by inbox.example.org with ESMTPS; Tue, 1 Jan 2030 10:10:12 +0000\r\n\
Received: from unknown (cheap-host.example [203.0.113.9]) by mx.example.net; Tue, 1 Jan 2030 10:10:10 +0000\r\n\
Authentication-Results: inbox.example.org; spf=fail smtp.mailfrom=bounce@cheap-host.example; dkim=none; dmarc=fail header.from=bank.example\r\n\
From: \"Bank Support\" <help@bank.example>\r\n\
Reply-To: help@cheap-mail.example\r\n\
Subject: Urgent\r\n\
\r\n\
Body text that is not read.";

    #[test]
    fn a_forged_message_is_flagged() {
        let findings = analyse_email_headers(FORGED.to_string()).unwrap();
        let status = |id: &str| findings.iter().find(|f| f.id == id).unwrap().status;
        assert_eq!(status("authentication"), Status::Risk);
        assert_eq!(status("identity"), Status::Warning);
        assert_eq!(findings[2].summary, "Passed through 2 servers");
        // The first finding leads with the step that read the pasted text.
        assert_eq!(findings[0].steps[0].action, "Read the pasted headers");
    }

    #[test]
    fn text_without_headers_is_refused() {
        assert!(analyse_email_headers("just some words".to_string()).is_err());
        assert!(analyse_email_headers(String::new()).is_err());
    }
}
