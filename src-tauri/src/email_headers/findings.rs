// Turns parsed headers into findings: sender authentication, sender identity and delivery path.
// There is no Windows or network code here, so every case can be tested with pasted headers.

use std::time::Instant;

use super::parser::{
    AuthResult, Headers, address_in_name, authentication_results, authserv_id, domain_of,
    parse_hop, parse_mailbox, received_spf, related_hosts, same_domain,
};
use crate::finding::{Detail, Finding, Status, Step, count_of, detail, switch};

// How many servers of the delivery path are listed before the rest are summarised.
const MAX_HOPS_SHOWN: usize = 10;

// What each check reads and why. These stay the same whatever the result is.
struct Check {
    id: &'static str,
    title: &'static str,
    checked: &'static str,
    why: &'static str,
}

const AUTHENTICATION: Check = Check {
    id: "authentication",
    title: "Sender authentication",
    checked: "I read the results the receiving mail server wrote for SPF, DKIM and DMARC.",
    why: "These checks show whether the message really came from the domain it claims, or \
          was forged.",
};

const IDENTITY: Check = Check {
    id: "identity",
    title: "Sender identity",
    checked: "I compared the domains of the From, Reply-To and Return-Path addresses, and any \
              address written in the display name.",
    why: "Scam emails often show a trusted name or address while replies, or the real sender, \
          go somewhere else.",
};

const PATH: Check = Check {
    id: "path",
    title: "Delivery path",
    checked: "I read the Received headers, which each server adds as it passes a message on.",
    why: "The path shows which servers handled the message. A first server that does not fit \
          the claimed sender can be a sign of forgery.",
};

impl Check {
    fn finding(
        &self,
        status: Status,
        summary: String,
        action: Option<&str>,
        details: Vec<Detail>,
        step: Step,
    ) -> Finding {
        Finding {
            id: self.id.to_string(),
            status,
            title: self.title.to_string(),
            summary,
            checked: self.checked.to_string(),
            why: self.why.to_string(),
            action: action.map(str::to_string),
            details,
            steps: vec![step],
            urls: Vec::new(),
            note: None,
        }
    }
}

// =========================
// Sender authentication
// =========================

// How a check turned out. "none" and a missing result both mean nothing was reported,
// which is not the same as a failure.
#[derive(PartialEq)]
enum Outcome {
    Pass,
    Fail,
    Weak,
    NotReported,
}

fn outcome(result: Option<&AuthResult>) -> Outcome {
    match result.map(|result| result.result.as_str()) {
        Some("pass") => Outcome::Pass,
        Some("fail" | "permerror") => Outcome::Fail,
        Some("none") | None => Outcome::NotReported,
        Some(_) => Outcome::Weak,
    }
}

fn describe(result: &AuthResult) -> String {
    let word = match result.result.as_str() {
        "pass" => "Pass",
        "fail" => "Fail",
        "softfail" => "Soft fail",
        "neutral" => "Neutral",
        "temperror" => "Temporary error",
        "permerror" => "Permanent error",
        other => other,
    };
    match &result.domain {
        Some(domain) => format!("{word} · {domain}"),
        None => word.to_string(),
    }
}

// Joins names for a sentence, such as "SPF, DKIM and DMARC".
fn join_names(names: &[&str], last: &str) -> String {
    match names {
        [] => String::new(),
        [only] => only.to_string(),
        [rest @ .., end] => format!("{} {last} {end}", rest.join(", ")),
    }
}

pub fn authentication(headers: &Headers) -> Finding {
    let started = Instant::now();

    let header = headers.first("Authentication-Results");
    let mut results = header.map(authentication_results).unwrap_or_default();
    // Some mail servers report SPF in its own header instead.
    if !results.iter().any(|result| result.method == "spf")
        && let Some(result) = headers.first("Received-SPF").and_then(received_spf)
    {
        results.push(AuthResult {
            method: "spf".to_string(),
            result,
            domain: None,
        });
    }

    let find = |method: &str| results.iter().find(|result| result.method == method);
    let reported = [
        ("SPF", find("spf")),
        ("DKIM", find("dkim")),
        ("DMARC", find("dmarc")),
    ];

    let mut details: Vec<Detail> = reported
        .iter()
        .map(|(label, result)| match (outcome(*result), result) {
            (Outcome::NotReported, _) | (_, None) => detail(label, "Not reported"),
            (outcome, Some(result)) => switch(label, describe(result), outcome == Outcome::Pass),
        })
        .collect();

    // The results are only as trustworthy as the server that wrote them. A server that wrote
    // them is the receiving one if its name relates to the server that took the message in.
    let recorded_by = header.and_then(authserv_id);
    // Any server that took the message in counts, because the newest Received header can
    // name an internal id, such as Gmail's, instead of a host.
    let receivers: Vec<String> = headers
        .all("Received")
        .into_iter()
        .filter_map(|header| parse_hop(header).by)
        .collect();
    let confirmed = recorded_by
        .as_ref()
        .is_some_and(|name| receivers.iter().any(|by| related_hosts(name, by)));
    if let Some(name) = &recorded_by {
        details.push(detail(
            "Recorded by",
            if confirmed {
                name.clone()
            } else {
                format!("{name} · not confirmed as your mail server")
            },
        ));
    }

    let names = |wanted: Outcome| -> Vec<&str> {
        reported
            .iter()
            .filter(|(_, result)| outcome(*result) == wanted)
            .map(|(label, _)| *label)
            .collect()
    };
    let (passed, failed, weak, missing) = (
        names(Outcome::Pass),
        names(Outcome::Fail),
        names(Outcome::Weak),
        names(Outcome::NotReported),
    );
    let none_reported = missing.len() == 3;

    // SPF and DKIM only prove something about the domain they were checked for. A pass for
    // another domain, such as the email service's own, says nothing about the From address.
    // DMARC passing means that match was already checked, but only if it is about the same
    // domain as the From address.
    let from_domain = headers
        .first("From")
        .and_then(parse_mailbox)
        .map(|mailbox| domain_of(&mailbox.address).to_string())
        .unwrap_or_default();
    let dmarc_mismatch = results.iter().any(|result| {
        result.method == "dmarc"
            && result.result == "pass"
            && !from_domain.is_empty()
            && result
                .domain
                .as_deref()
                .is_some_and(|domain| !same_domain(domain, &from_domain))
    });
    // With no From address there is nothing to match, and the identity card already flags that.
    let backed = from_domain.is_empty() || (!dmarc_mismatch && passes_for(&results, &from_domain));
    // The domains the passing SPF and DKIM checks were about.
    let passed_domains: Vec<&str> = results
        .iter()
        .filter(|result| result.result == "pass" && result.method != "dmarc")
        .filter_map(|result| result.domain.as_deref())
        .collect();
    let unconfirmed = recorded_by.is_some() && !confirmed;

    let (status, summary) = if failed.contains(&"DMARC") || failed.len() >= 2 {
        (Status::Risk, "The sender could not be verified")
    } else if !failed.is_empty() || !weak.is_empty() {
        (Status::Warning, "Some sender checks did not pass")
    } else if dmarc_mismatch {
        (
            Status::Warning,
            "The results are for a different sender domain",
        )
    } else if none_reported {
        (Status::Info, "No authentication results in these headers")
    } else if !backed {
        (Status::Warning, "The passed checks do not match the sender")
    } else if unconfirmed {
        (
            Status::Info,
            "Sender checks passed, but their source is not confirmed",
        )
    } else if passed.contains(&"DMARC") || passed.len() >= 2 {
        (Status::Ok, "Sender authentication passed")
    } else {
        (Status::Info, "Only one sender check passed")
    };

    // What the results say, in plain words. A missing result is not treated as a failure.
    let mut note: Vec<String> = Vec::new();
    if none_reported {
        note.push("No SPF, DKIM or DMARC results were reported.".to_string());
    } else {
        if !passed.is_empty() {
            note.push(format!("{} passed.", join_names(&passed, "and")));
        }
        if !failed.is_empty() {
            note.push(format!("{} failed.", join_names(&failed, "and")));
        }
        if !weak.is_empty() {
            note.push(format!("{} gave a weak result.", join_names(&weak, "and")));
        }
        if !missing.is_empty() {
            note.push(format!(
                "No {} authentication result was reported.",
                join_names(&missing, "or")
            ));
        }
        if dmarc_mismatch {
            note.push(
                "DMARC reports a pass for a different domain than the one in the From address."
                    .to_string(),
            );
        } else if !backed && failed.is_empty() && weak.is_empty() {
            note.push(format!(
                "The passing checks are for {}, not the domain in the From address, so they do \
                 not show who really sent this email.",
                if passed_domains.is_empty() {
                    "another domain".to_string()
                } else {
                    join_names(&passed_domains, "and")
                }
            ));
        }
        if unconfirmed {
            note.push(
                "Tenax could not match the server that wrote these results to the server that \
                 received the email."
                    .to_string(),
            );
        }
        if status == Status::Ok || status == Status::Info {
            note.push("Passing checks do not guarantee that the email is safe.".to_string());
        }
        note.push(
            "Tenax reads these results from the headers and does not run the checks itself, \
             so they are only as trustworthy as the server that wrote them."
                .to_string(),
        );
    }

    let action = match status {
        Status::Risk => Some(
            "Verify the sender through a trusted channel, such as their official website or \
             phone number, before trusting this email. Do not open attachments or follow \
             links until you have.",
        ),
        Status::Warning => Some(
            "Verify the sender through a trusted channel before acting on anything in this \
             email.",
        ),
        _ if none_reported => Some(
            "Paste the full headers of the received message. The results are added by the \
             receiving mail server, so a copied or forwarded message may not have them.",
        ),
        _ => None,
    };

    let mut finding = AUTHENTICATION.finding(
        status,
        summary.to_string(),
        action,
        details,
        Step::new(
            "Read the sender authentication results",
            "Looked for the results of the sender checks the receiving server ran",
            "Authentication-Results header (SPF, DKIM, DMARC), with Received-SPF as a fallback for SPF",
            if none_reported {
                "No results reported".to_string()
            } else {
                format!(
                    "{} of 3 results reported ({})",
                    3 - missing.len(),
                    join_names(
                        &reported
                            .iter()
                            .filter(|(_, result)| outcome(*result) != Outcome::NotReported)
                            .map(|(label, _)| *label)
                            .collect::<Vec<_>>(),
                        "and"
                    )
                )
            },
            started,
        ),
    );
    finding.note = Some(note.join(" "));
    finding
}

// =========================
// Sender identity
// =========================

// Email services that send mail for other companies. Their bounce addresses use their own
// domain, so a Return-Path on one of these is normal. Only domains that are known to belong
// to the service are listed, so that a service is never named on a guess.
const SENDING_SERVICES: &[(&str, &str)] = &[
    ("amazonses.com", "Amazon SES"),
    ("sendgrid.net", "SendGrid"),
    ("mailgun.org", "Mailgun"),
    ("mandrillapp.com", "Mandrill"),
    ("mcsv.net", "Mailchimp"),
    ("sparkpostmail.com", "SparkPost"),
    ("postmarkapp.com", "Postmark"),
    ("mailjet.com", "Mailjet"),
];

// The service a domain belongs to, if it is one of the known ones. The domain has to be the
// service's own or one of its subdomains, so "evil-amazonses.com" does not match.
fn sending_service(domain: &str) -> Option<&'static str> {
    SENDING_SERVICES
        .iter()
        .find(|(suffix, _)| domain == *suffix || domain.ends_with(&format!(".{suffix}")))
        .map(|(_, name)| *name)
}

// Whether a passing result belongs to the From domain: DMARC passed, or SPF or DKIM passed
// for that domain or one of its subdomains. A pass for any other domain does not count.
fn passes_for(results: &[AuthResult], from_domain: &str) -> bool {
    !from_domain.is_empty()
        && results.iter().any(|result| {
            result.result == "pass"
                && match result.method.as_str() {
                    "dmarc" => true,
                    _ => result
                        .domain
                        .as_deref()
                        .is_some_and(|domain| same_domain(domain, from_domain)),
                }
        })
}

// Whether authentication supports the sender's identity even though the Return-Path is on
// another domain.
fn authentication_supports(headers: &Headers, from_domain: &str) -> bool {
    let results = headers
        .first("Authentication-Results")
        .map(authentication_results)
        .unwrap_or_default();
    passes_for(&results, from_domain)
}

// Something that differs between the sender fields.
struct Difference {
    // A warning is worth acting on. Anything else is only a note.
    warning: bool,
    label: &'static str,
    value: String,
    // What to do about it, for a warning.
    advice: String,
    // A short name for the log, such as "Return-Path".
    short: &'static str,
    // Whether the difference is between domains.
    domain: bool,
}

pub fn identity(headers: &Headers) -> Finding {
    let started = Instant::now();

    let from = headers.first("From").and_then(parse_mailbox);
    let reply_to = headers.first("Reply-To").and_then(parse_mailbox);
    // A bounce message has an empty return path, which is not an address.
    let return_path = headers.first("Return-Path").and_then(parse_mailbox);

    let mut details = Vec::new();
    for (label, mailbox) in [
        ("From", &from),
        ("Reply-To", &reply_to),
        ("Return-Path", &return_path),
    ] {
        if let Some(mailbox) = mailbox {
            details.push(detail(label, &mailbox.address));
        }
    }

    let mut differences: Vec<Difference> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut third_party = false;
    match &from {
        None => differences.push(Difference {
            warning: true,
            label: "From address",
            value: "No From address found".to_string(),
            advice: "The sender could not be read from these headers, so check who sent it."
                .to_string(),
            short: "From address",
            domain: false,
        }),
        Some(from) => {
            let from_domain = domain_of(&from.address);

            if let Some(reply_to) = &reply_to {
                let domain = domain_of(&reply_to.address);
                if !same_domain(domain, from_domain) {
                    differences.push(Difference {
                        warning: true,
                        label: "Reply-To differs",
                        value: format!("Replies go to {domain}"),
                        advice: format!(
                            "A reply would go to {domain}, not to the sender. Check that address \
                             before you reply."
                        ),
                        short: "Reply-To",
                        domain: true,
                    });
                }
            }
            if let Some(shown) = from.name.as_deref().and_then(address_in_name) {
                let domain = domain_of(&shown);
                if !same_domain(domain, from_domain) {
                    differences.push(Difference {
                        warning: true,
                        label: "Display name differs",
                        value: format!("The name shows an address at {domain}"),
                        advice: "The name shown does not match the real sender address. Go by the \
                                 address, not the name shown in your email app."
                            .to_string(),
                        short: "display name",
                        domain: false,
                    });
                }
            }
            // Bulk senders and email services use their own domain here, so this is only a
            // note. A service is named only when its domain is a known one.
            if let Some(path) = &return_path {
                let domain = domain_of(&path.address);
                if !same_domain(domain, from_domain) {
                    let service = sending_service(domain);
                    third_party = service.is_some();

                    let mut note = match service {
                        Some(name) => format!(
                            "This email appears to have been sent through {name}, which is common \
                             for automated emails."
                        ),
                        None => "The Return-Path uses a different domain from the From address. \
                                 This is common when a mailing service sends on someone's behalf, \
                                 and is not a problem by itself."
                            .to_string(),
                    };
                    if authentication_supports(headers, from_domain) {
                        note.push_str(
                            " DKIM or DMARC authentication supports the sender's domain.",
                        );
                    }
                    if service.is_some() {
                        note.push_str(
                            " A known service does not by itself make an email trustworthy.",
                        );
                    }
                    notes.push(note);

                    differences.push(Difference {
                        warning: false,
                        label: if service.is_some() {
                            "Third-party service"
                        } else {
                            "Return-Path differs"
                        },
                        value: service.map_or(format!("Uses {domain}"), str::to_string),
                        advice: String::new(),
                        short: "Return-Path",
                        domain: true,
                    });
                }
            }
        }
    }

    for difference in &differences {
        details.push(detail(difference.label, &difference.value));
    }

    let warnings: Vec<&Difference> = differences.iter().filter(|d| d.warning).collect();
    let (status, summary) = if !warnings.is_empty() {
        let summary = if warnings.len() == 1 {
            "1 sender detail looks different".to_string()
        } else {
            format!("{} sender details look different", warnings.len())
        };
        (Status::Warning, summary)
    } else if third_party {
        (
            Status::Info,
            "Sent through a third-party email service".to_string(),
        )
    } else if !differences.is_empty() {
        (
            Status::Info,
            "Return-Path uses a different domain".to_string(),
        )
    } else {
        (Status::Ok, "Sender addresses match".to_string())
    };

    // The advice names the actual concern, so it differs for each kind of difference.
    let action = (!warnings.is_empty()).then(|| {
        warnings
            .iter()
            .map(|difference| difference.advice.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    });

    // For the log, such as "1 domain difference found (Return-Path)".
    let result = if differences.is_empty() {
        "No differences found".to_string()
    } else {
        let kind = if differences.iter().all(|difference| difference.domain) {
            "domain difference"
        } else {
            "difference"
        };
        let shorts: Vec<&str> = differences.iter().map(|d| d.short).collect();
        format!(
            "{} found ({})",
            count_of(differences.len(), kind),
            shorts.join(", ")
        )
    };

    let mut finding = IDENTITY.finding(
        status,
        summary,
        action.as_deref(),
        details,
        Step::new(
            "Compared the sender addresses",
            "Compared the addresses the email shows with the ones it really uses",
            "From, Reply-To and Return-Path domains compared, plus any address inside the From display name",
            result,
            started,
        ),
    );
    if !notes.is_empty() {
        finding.note = Some(notes.join(" "));
    }
    finding
}

// =========================
// Delivery path
// =========================

pub fn path(headers: &Headers) -> Finding {
    let started = Instant::now();

    // The newest Received header is first, so the list is turned around to start at the sender.
    let mut hops: Vec<_> = headers.all("Received").into_iter().map(parse_hop).collect();
    hops.reverse();

    let unknown = || "unknown".to_string();
    let mut details: Vec<Detail> = hops
        .iter()
        .take(MAX_HOPS_SHOWN)
        .enumerate()
        .map(|(index, hop)| {
            let from = hop.from.clone().unwrap_or_else(unknown);
            let by = hop.by.clone().unwrap_or_else(unknown);
            detail(&format!("Server {}", index + 1), format!("{from} → {by}"))
        })
        .collect();
    if hops.len() > MAX_HOPS_SHOWN {
        details.push(detail(
            "More",
            format!("{} more servers", hops.len() - MAX_HOPS_SHOWN),
        ));
    }

    let summary = match hops.len() {
        0 => "No delivery path in these headers".to_string(),
        1 => "Handled by 1 server".to_string(),
        count => format!("Passed through {count} servers"),
    };

    PATH.finding(
        Status::Info,
        summary,
        None,
        details,
        Step::new(
            "Traced the delivery path",
            "Followed the trail of servers the email passed through",
            "Received headers read oldest first (the from and by server of each)",
            format!("{} found", count_of(hops.len(), "server")),
            started,
        ),
    )
}

// =========================
// Tests
// =========================

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Headers {
        Headers::parse(text)
    }

    #[test]
    fn all_checks_passing_is_ok() {
        let headers = parse(
            "Received: from a.example by mx.example.net; x
From: a@example.com
Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=a@example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com",
        );
        assert_eq!(authentication(&headers).status, Status::Ok);
    }

    #[test]
    fn a_failed_dmarc_is_a_risk() {
        let headers = parse(
            "Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=a@example.com; dmarc=fail header.from=example.com",
        );
        assert_eq!(authentication(&headers).status, Status::Risk);
    }

    #[test]
    fn one_failed_check_is_a_warning_and_a_soft_fail_is_too() {
        let failed = parse(
            "Authentication-Results: mx.example.net; spf=fail smtp.mailfrom=a@b.com; dkim=pass header.d=b.com",
        );
        assert_eq!(authentication(&failed).status, Status::Warning);
        let soft = parse(
            "Authentication-Results: mx.example.net; spf=softfail smtp.mailfrom=a@b.com; dkim=pass header.d=b.com",
        );
        assert_eq!(authentication(&soft).status, Status::Warning);
    }

    #[test]
    fn missing_results_are_not_reported_as_a_pass() {
        let finding = authentication(&parse("From: a@b.com"));
        assert_eq!(finding.status, Status::Info);
        assert!(finding.action.is_some());
    }

    #[test]
    fn received_spf_is_used_when_there_is_no_authentication_results() {
        let finding = authentication(&parse("Received-SPF: fail (google.com: not designated)"));
        assert_eq!(finding.status, Status::Warning);
    }

    #[test]
    fn matching_addresses_are_ok() {
        let headers = parse(
            "From: Alice <alice@example.com>\nReply-To: alice@example.com\nReturn-Path: <bounce@mail.example.com>",
        );
        assert_eq!(identity(&headers).status, Status::Ok);
    }

    #[test]
    fn a_different_reply_to_is_a_warning() {
        let headers = parse("From: Bank <help@bank.com>\nReply-To: help@scam-mail.net");
        let finding = identity(&headers);
        assert_eq!(finding.status, Status::Warning);
        assert!(
            finding
                .details
                .iter()
                .any(|detail| detail.value.contains("scam-mail.net"))
        );
    }

    #[test]
    fn a_display_name_showing_another_address_is_a_warning() {
        let headers = parse("From: \"service@paypal.com\" <someone@other.net>");
        assert_eq!(identity(&headers).status, Status::Warning);
    }

    #[test]
    fn a_different_return_path_alone_is_only_a_note() {
        let headers = parse("From: a@example.com\nReturn-Path: <b@mailer.net>");
        assert_eq!(identity(&headers).status, Status::Info);
    }

    #[test]
    fn the_path_starts_at_the_sender() {
        let headers = parse(
            "Received: from b.example by c.example; x\nReceived: from a.example by b.example; y",
        );
        let finding = path(&headers);
        assert_eq!(finding.summary, "Passed through 2 servers");
        assert_eq!(finding.details[0].value, "a.example → b.example");
    }

    #[test]
    fn a_missing_dkim_is_not_a_problem_when_spf_and_dmarc_pass() {
        let headers = parse(
            "Received: from a.example by mx.example.net; x
From: a@example.com
Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=a@example.com; dkim=none; dmarc=pass header.from=example.com",
        );
        let finding = authentication(&headers);
        assert_eq!(finding.status, Status::Ok);
        assert_eq!(finding.summary, "Sender authentication passed");
        assert_eq!(finding.action, None);
        let note = finding.note.unwrap();
        assert!(note.contains("SPF and DMARC passed."));
        assert!(note.contains("No DKIM authentication result was reported."));
        assert!(note.contains("do not guarantee"));
    }

    #[test]
    fn one_passing_check_alone_is_only_a_note() {
        let headers =
            parse("Authentication-Results: mx.example.net; dkim=pass header.d=example.com");
        let finding = authentication(&headers);
        assert_eq!(finding.status, Status::Info);
        assert_eq!(finding.action, None);
    }

    #[test]
    fn advice_matches_how_serious_the_result_is() {
        let risk = authentication(&parse(
            "Authentication-Results: x.example; dmarc=fail header.from=a.com",
        ));
        assert!(risk.action.unwrap().contains("Do not open attachments"));
        let warning = authentication(&parse(
            "Authentication-Results: x.example; spf=fail smtp.mailfrom=a@b.com; dkim=pass header.d=b.com",
        ));
        let advice = warning.action.unwrap();
        assert!(advice.contains("trusted channel"));
        assert!(!advice.contains("attachments"));
    }

    #[test]
    fn says_whether_the_results_came_from_the_receiving_server() {
        let recorded = |finding: Finding| {
            finding
                .details
                .iter()
                .find(|d| d.label == "Recorded by")
                .unwrap()
                .value
                .clone()
        };
        let confirmed = parse(
            "Received: from a.example by smtp.google.com; x
Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=a@b.com",
        );
        assert_eq!(recorded(authentication(&confirmed)), "mx.google.com");
        let unconfirmed = parse(
            "Received: from a.example by inbox.other-provider.org; x
Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=a@b.com",
        );
        assert!(recorded(authentication(&unconfirmed)).contains("not confirmed"));
    }

    #[test]
    fn identity_advice_names_the_actual_concern() {
        let reply = identity(&parse(
            "From: Bank <help@bank.com>
Reply-To: help@scam-mail.net",
        ));
        let advice = reply.action.unwrap();
        assert!(advice.contains("scam-mail.net"));
        assert!(!advice.contains("not the name"));
        let name = identity(&parse("From: \"service@paypal.com\" <someone@other.net>"));
        assert!(name.action.unwrap().contains("not the name"));
    }

    #[test]
    fn an_internal_id_in_the_newest_received_does_not_hide_the_receiving_server() {
        let headers = parse(
            "Received: by 2002:a05:7300:1 with SMTP id abc; x
Received: from a.example by mx.google.com with ESMTPS; y
Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=a@b.com",
        );
        let finding = authentication(&headers);
        let value = &finding
            .details
            .iter()
            .find(|d| d.label == "Recorded by")
            .unwrap()
            .value;
        assert_eq!(value, "mx.google.com");
    }

    #[test]
    fn a_known_email_service_is_named_and_is_not_suspicious() {
        let finding = identity(&parse(
            "From: News <no-reply@example.net>
Return-Path: <abc@us-west-2.amazonses.com>
Authentication-Results: mx.google.com; dkim=pass header.d=example.net; dmarc=pass header.from=example.net",
        ));
        assert_eq!(finding.status, Status::Info);
        assert_eq!(finding.summary, "Sent through a third-party email service");
        assert_eq!(finding.action, None);
        let note = finding.note.unwrap();
        assert!(note.contains("sent through Amazon SES"));
        assert!(note.contains("authentication supports"));
        assert_eq!(
            finding.steps[0].result,
            "1 domain difference found (Return-Path)"
        );
    }

    #[test]
    fn an_unknown_domain_is_described_neutrally_and_a_lookalike_is_not_named() {
        for path in ["mailer.example.org", "evil-amazonses.com"] {
            let finding = identity(&parse(&format!(
                "From: a@example.net
Return-Path: <bounce@{path}>"
            )));
            assert_eq!(finding.status, Status::Info);
            assert_eq!(finding.summary, "Return-Path uses a different domain");
            assert!(!finding.note.unwrap().contains("Amazon"));
        }
    }

    #[test]
    fn log_results_say_what_was_found_in_natural_wording() {
        let none = identity(&parse("From: a@example.net"));
        assert_eq!(none.steps[0].result, "No differences found");
        let two = identity(&parse(
            "From: \"x@paypal.com\" <a@other.net>
Reply-To: b@elsewhere.net",
        ));
        assert_eq!(
            two.steps[0].result,
            "2 differences found (Reply-To, display name)"
        );
        assert_eq!(count_of(1, "server"), "1 server");
        assert_eq!(count_of(3, "server"), "3 servers");
    }

    // Headers as a real message has them: the receiving server's Received header comes first.
    fn message(rest: &str) -> Headers {
        parse(&format!(
            "Received: from a.example by mx.example.net; x\n{rest}"
        ))
    }

    fn row<'a>(finding: &'a Finding, label: &str) -> Option<&'a str> {
        finding
            .details
            .iter()
            .find(|detail| detail.label == label)
            .map(|detail| detail.value.as_str())
    }

    // =========================
    // Alignment and trust
    // =========================

    #[test]
    fn passes_for_other_domains_do_not_authenticate_the_sender() {
        // SPF and DKIM both passed, but for the email service, not for the From domain.
        let finding = authentication(&message(
            "From: a@example.net\nAuthentication-Results: mx.example.net; spf=pass smtp.mailfrom=b@us-west-2.amazonses.com; dkim=pass header.d=amazonses.com",
        ));
        assert_eq!(finding.status, Status::Warning);
        assert_eq!(finding.summary, "The passed checks do not match the sender");
        assert!(
            finding
                .note
                .unwrap()
                .contains("not the domain in the From address")
        );
    }

    #[test]
    fn aligned_dkim_authenticates_even_when_spf_is_for_the_service() {
        let finding = authentication(&message(
            "From: a@example.net\nAuthentication-Results: mx.example.net; spf=pass smtp.mailfrom=b@amazonses.com; dkim=pass header.d=example.net",
        ));
        assert_eq!(finding.status, Status::Ok);
    }

    #[test]
    fn a_dmarc_pass_for_another_domain_is_not_trusted() {
        // The header claims a DMARC pass, but for a domain that is not in the From address.
        let finding = authentication(&message(
            "From: a@example.net\nAuthentication-Results: mx.example.net; spf=pass smtp.mailfrom=a@example.net; dkim=pass header.d=example.net; dmarc=pass header.from=other.example",
        ));
        assert_eq!(finding.status, Status::Warning);
        assert_eq!(
            finding.summary,
            "The results are for a different sender domain"
        );
    }

    #[test]
    fn the_newest_results_header_wins_over_a_forged_one_below_it() {
        let finding = authentication(&message(
            "Authentication-Results: mx.example.net; dmarc=fail header.from=example.net\nFrom: a@example.net\nAuthentication-Results: mx.example.net; spf=pass smtp.mailfrom=a@example.net; dkim=pass header.d=example.net; dmarc=pass header.from=example.net",
        ));
        assert_eq!(finding.status, Status::Risk);
    }

    #[test]
    fn results_from_an_unmatched_server_are_not_fully_trusted() {
        let finding = authentication(&parse(
            "Received: from a.example by inbox.other-provider.org; x\nFrom: a@example.net\nAuthentication-Results: mx.google.com; spf=pass smtp.mailfrom=a@example.net; dkim=pass header.d=example.net; dmarc=pass header.from=example.net",
        ));
        assert_eq!(finding.status, Status::Info);
        assert_eq!(
            finding.summary,
            "Sender checks passed, but their source is not confirmed"
        );
        assert!(
            row(&finding, "Recorded by")
                .unwrap()
                .contains("not confirmed")
        );
    }

    #[test]
    fn results_without_a_server_name_still_work() {
        // Outlook writes the results with no server name in front of them.
        let finding = authentication(&parse(
            "From: a@example.net\nAuthentication-Results: spf=pass smtp.mailfrom=a@example.net; dkim=pass header.d=example.net; dmarc=pass action=none header.from=example.net",
        ));
        assert_eq!(finding.status, Status::Ok);
        assert_eq!(row(&finding, "Recorded by"), None);
    }

    // =========================
    // Look-alike domains and email services
    // =========================

    #[test]
    fn look_alike_domains_are_never_treated_as_the_same() {
        for reply in [
            "bank.example.evil.com",
            "evilbank.example",
            "bank-example.com",
        ] {
            let finding = identity(&parse(&format!(
                "From: Bank <help@bank.example>\nReply-To: help@{reply}"
            )));
            assert_eq!(finding.status, Status::Warning, "{reply}");
        }
    }

    #[test]
    fn a_real_email_service_with_failed_authentication_is_still_a_risk() {
        let headers = message(
            "From: a@example.net\nReturn-Path: <x@us-west-2.amazonses.com>\nAuthentication-Results: mx.example.net; spf=pass smtp.mailfrom=x@us-west-2.amazonses.com; dkim=fail header.d=example.net; dmarc=fail header.from=example.net",
        );
        assert_eq!(authentication(&headers).status, Status::Risk);

        // The service is named, but nothing says authentication supports the sender.
        let finding = identity(&headers);
        let note = finding.note.unwrap();
        assert!(note.contains("sent through Amazon SES"));
        assert!(note.contains("does not by itself make an email trustworthy"));
        assert!(!note.contains("supports"));
    }

    // =========================
    // Wording
    // =========================

    #[test]
    fn nothing_says_an_email_is_safe() {
        let messages = [
            "From: a@example.net\nReturn-Path: <x@us-west-2.amazonses.com>\nAuthentication-Results: mx.example.net; spf=pass smtp.mailfrom=a@example.net; dkim=pass header.d=example.net; dmarc=pass header.from=example.net",
            "From: a@example.net\nAuthentication-Results: mx.example.net; dmarc=fail header.from=example.net",
            "From: a@example.net\nReply-To: b@evil.example",
            "From: a@example.net",
        ];
        for text in messages {
            let headers = message(text);
            for finding in [authentication(&headers), identity(&headers), path(&headers)] {
                let mut words = finding.summary.clone();
                for part in [&finding.note, &finding.action].into_iter().flatten() {
                    words.push(' ');
                    words.push_str(part);
                }
                for detail in &finding.details {
                    words.push(' ');
                    words.push_str(&detail.value);
                }
                // The one allowed use is to say that a pass is not a guarantee.
                let words = words
                    .to_lowercase()
                    .replace("do not guarantee that the email is safe", "");
                for banned in ["safe", "legitimate", "genuine", "verified sender"] {
                    assert!(!words.contains(banned), "{banned} in {words}");
                }
            }
        }
    }
}
