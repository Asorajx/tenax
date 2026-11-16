// Real addresses, run through the whole checker. Each group has addresses that should be left
// alone as well as ones that should be flagged.

use super::*;

fn run(url: &str) -> UrlReport {
    check_url(url.to_string()).expect("the address could be read")
}

fn card<'a>(report: &'a UrlReport, id: &str) -> &'a Finding {
    report
        .findings
        .iter()
        .find(|f| f.id == id)
        .expect("card exists")
}

fn status(report: &UrlReport, id: &str) -> Status {
    card(report, id).status
}

fn has_row(report: &UrlReport, id: &str, label: &str) -> bool {
    card(report, id).details.iter().any(|d| d.label == label)
}

fn row<'a>(report: &'a UrlReport, id: &str, label: &str) -> &'a str {
    &card(report, id)
        .details
        .iter()
        .find(|d| d.label == label)
        .expect("row exists")
        .value
}

fn shape(report: &UrlReport) -> Vec<Status> {
    report.findings.iter().map(|f| f.status).collect()
}

// =========================
// Addresses that should be left alone
// =========================

#[test]
fn a_companys_own_address_is_clean_and_is_read_part_by_part() {
    let report = run("https://www.paypal.com/signin?country=AU&lang=en");
    assert_eq!(report.verdict.status, Status::Ok, "{:?}", shape(&report));
    assert_eq!(
        report.verdict.headline,
        "No common phishing indicators detected."
    );
    assert_eq!(shape(&report), [Status::Ok; 4]);

    assert_eq!(row(&report, "address", "Scheme"), "https");
    assert_eq!(row(&report, "address", "Site"), "www.paypal.com");
    assert_eq!(row(&report, "address", "Registered domain"), "paypal.com");
    assert_eq!(row(&report, "address", "Subdomain"), "www");
    assert_eq!(row(&report, "address", "Path"), "/signin");
    assert_eq!(row(&report, "address", "Parameters"), "2 parameters");
}

#[test]
fn ordinary_addresses_with_other_endings_are_clean() {
    for url in [
        "https://www.bbc.co.uk/news",
        "https://shop.example.com.au/cart",
        "https://accounts.google.com/AccountChooser",
        "https://en.wikipedia.org/wiki/Phishing",
    ] {
        let report = run(url);
        assert_eq!(
            report.verdict.status,
            Status::Ok,
            "{url}: {:?}",
            shape(&report)
        );
    }
    // The registered domain follows the public suffix list.
    assert_eq!(
        row(
            &run("https://www.bbc.co.uk/news"),
            "address",
            "Registered domain"
        ),
        "bbc.co.uk"
    );
}

#[test]
fn the_port_and_a_long_path_are_shown_sensibly() {
    let long_path = "a".repeat(200);
    let report = run(&format!("https://example.com:8443/{long_path}"));
    assert_eq!(row(&report, "address", "Port"), "8443");
    let path = row(&report, "address", "Path");
    assert!(path.ends_with('…') && path.chars().count() <= 60, "{path}");
}

#[test]
fn an_address_typed_without_a_scheme_is_read_with_a_note_that_does_not_change_the_verdict() {
    let report = run("www.paypal.com/signin");
    assert_eq!(status(&report, "address"), Status::Info);
    assert_eq!(card(&report, "address").summary, "Read · https assumed");
    assert!(
        card(&report, "address")
            .note
            .as_deref()
            .unwrap()
            .contains("https:// was assumed")
    );
    assert_eq!(report.verdict.status, Status::Ok);
    // Surrounding spaces and a pasted line break are ignored.
    assert_eq!(
        run("  https://www.amazon.com/orders \n").verdict.status,
        Status::Ok
    );
}

#[test]
fn a_weak_sign_is_only_a_note_and_never_changes_the_verdict() {
    let http = run("http://old.example.org/page");
    assert_eq!(status(&http, "connection"), Status::Info);
    assert_eq!(card(&http, "connection").summary, "1 note");
    assert_eq!(http.verdict.status, Status::Ok);
    let ending = run("https://files.example.zip/archive");
    assert_eq!(status(&ending, "connection"), Status::Info);
    assert_eq!(ending.verdict.status, Status::Ok);
}

// =========================
// Addresses that should be flagged
// =========================

#[test]
fn look_alikes_of_well_known_companies_are_strong() {
    for url in [
        "https://paypa1.com/login",
        "https://paypal.com.account-verify.example/login",
        "https://login-microsoft.support-center.example/mailbox",
        "https://rnicrosoft.com",
        "https://p\u{430}ypal.com/signin",
    ] {
        let report = run(url);
        assert_eq!(
            status(&report, "lookalikes"),
            Status::Risk,
            "{url}: {:?}",
            shape(&report)
        );
        assert_eq!(report.verdict.status, Status::Risk, "{url}");
        assert!(card(&report, "lookalikes").action.is_some(), "{url}");
    }
    // One letter away is only a warning, and a shorter name is not compared that way.
    assert_eq!(run("https://paypall.com").verdict.status, Status::Warning);
    assert_eq!(run("https://apples.com").verdict.status, Status::Ok);
}

#[test]
fn a_name_that_merely_contains_a_company_is_not_an_imitation() {
    for url in ["https://notpaypal.com", "https://pineapple.example"] {
        assert_eq!(run(url).verdict.status, Status::Ok, "{url}");
    }
    // One letter from a company's name is a warning, never a strong sign.
    assert_eq!(
        run("https://paypalm.example").verdict.status,
        Status::Warning
    );
}

#[test]
fn international_names_are_told_apart_from_imitations() {
    let honest = run("https://m\u{fc}nchen.example.org/plan");
    assert_eq!(status(&honest, "lookalikes"), Status::Info);
    assert_eq!(honest.verdict.status, Status::Ok);
    assert_eq!(
        row(&honest, "address", "Site"),
        "münchen.example.org (xn--mnchen-3ya.example.org)"
    );
    let mixed = run("https://exa\u{43c}ple.com");
    assert_eq!(status(&mixed, "lookalikes"), Status::Risk);
    assert!(has_row(&mixed, "lookalikes", "Mixed alphabets"));
    // Punycode written out is read the same way.
    assert_eq!(
        status(&run("https://xn--pypal-4ve.com"), "lookalikes"),
        Status::Risk
    );
}

#[test]
fn hidden_numeric_and_encoded_addresses_are_serious() {
    for (url, label) in [
        (
            "https://paypal.com@evil.example/",
            "Hides the real destination",
        ),
        ("http://192.168.4.7/login", "Address is a number"),
        ("http://3232235777/login", "Address is a number"),
        ("javascript:alert(1)", "Link runs code"),
    ] {
        let report = run(url);
        assert_eq!(status(&report, "destination"), Status::Risk, "{url}");
        assert!(has_row(&report, "destination", label), "{url}");
        assert_eq!(report.verdict.status, Status::Risk, "{url}");
    }
    let encoded = run("https://%65vil.example/");
    assert_eq!(status(&encoded, "destination"), Status::Warning);
    assert!(has_row(&encoded, "destination", "Encoded address"));
}

#[test]
fn a_destination_written_into_the_address_is_read_and_judged() {
    let report =
        run("https://track.example.com/r?url=https%3A%2F%2Fpaypal.com.evil.example%2Flogin");
    assert!(has_row(&report, "destination", "Redirect link"));
    assert_eq!(status(&report, "lookalikes"), Status::Risk);
    assert_eq!(report.verdict.status, Status::Risk);
}

// =========================
// What cannot be seen
// =========================

#[test]
fn a_shortened_link_is_a_warning_and_says_the_destination_is_not_visible() {
    let report = run("https://bit.ly/3abc");
    assert_eq!(status(&report, "destination"), Status::Warning);
    assert!(has_row(&report, "destination", "Shortened link"));
    assert!(
        card(&report, "destination")
            .note
            .as_deref()
            .unwrap()
            .contains("not visible")
    );
    assert_eq!(report.verdict.status, Status::Warning);
}

#[test]
fn a_tracking_address_is_limited_and_never_reported_as_clean() {
    let report = run("https://click.mailer.example.com/c/abc?x=1");
    assert_eq!(status(&report, "destination"), Status::Limited);
    assert_eq!(report.verdict.status, Status::Limited);
    assert_eq!(
        report.verdict.headline,
        "Analysis limited by missing information."
    );
    assert!(report.verdict.detail.contains("not a clean result"));
    // The reason reads naturally for one address.
    let note = card(&report, "destination").note.as_deref().unwrap();
    assert!(note.contains("1 link passes through a tracking or shortening service, so where it finally leads is not visible."), "{note}");
}

#[test]
fn a_name_that_cannot_be_checked_against_the_public_list_is_limited() {
    let report = run("http://intranet/plans");
    assert_eq!(status(&report, "destination"), Status::Limited);
    assert!(
        card(&report, "destination")
            .note
            .as_deref()
            .unwrap()
            .contains("could not be fully examined")
    );
    assert_ne!(report.verdict.status, Status::Ok);
}

#[test]
fn limits_and_concerns_are_both_kept() {
    // A shortened link has a concern and an unknown destination at once.
    let report = run("https://bit.ly/3abc");
    let destination = card(&report, "destination");
    assert_eq!(destination.status, Status::Warning);
    assert!(destination.note.is_some());
}

// =========================
// Input that is not an address
// =========================

#[test]
fn input_that_is_not_a_web_address_is_refused_with_a_clear_reason() {
    for (input, reason) in [
        ("", "Enter a web address"),
        ("   \n ", "Enter a web address"),
        ("two words", "no spaces"),
        ("https://a.example https://b.example", "no spaces"),
        ("hello", "does not look like"),
        ("mailto:a@example.com", "not a web address"),
        ("ftp://files.example.com/a", "Only web addresses"),
        ("file:///c:/secret.txt", "Only web addresses"),
    ] {
        let error = check_url(input.to_string()).err().expect("refused");
        assert!(error.contains(reason), "{input:?}: {error}");
        // The reason never repeats what was typed.
        assert!(input.trim().is_empty() || !error.contains(input.trim()));
    }
    assert!(check_url("a".repeat(5000)).is_err());
}

#[test]
fn a_very_long_valid_address_is_handled() {
    let report = run(&format!("https://www.example.com/{}", "a".repeat(3900)));
    assert_eq!(report.verdict.status, Status::Ok);
}

// =========================
// Agreement, wording and shape
// =========================

#[test]
fn the_url_checker_agrees_with_the_link_checks_the_email_scam_checker_uses() {
    for url in [
        "https://www.paypal.com/signin",
        "https://paypa1.com/login",
        "https://bit.ly/3abc",
        "https://click.mailer.example.com/c/1",
        "http://old.example.org/page",
        "https://paypal.com@evil.example/",
        "http://192.168.4.7/login",
    ] {
        let item = links::analyse(
            &[RawLink {
                href: url.to_string(),
                shown: None,
            }],
            &[],
            "",
        )
        .items
        .into_iter()
        .next()
        .expect("one item");
        let expected = match item.status {
            Status::Risk => Status::Risk,
            Status::Warning => Status::Warning,
            Status::Limited => Status::Limited,
            _ => Status::Ok,
        };
        assert_eq!(run(url).verdict.status, expected, "{url}");
    }
}

#[test]
fn nothing_claims_an_address_is_safe_or_dangerous_for_certain() {
    for url in [
        "https://www.paypal.com/signin",
        "https://paypa1.com/login",
        "https://bit.ly/3abc",
        "https://click.mailer.example.com/c/1",
        "http://old.example.org/page",
        "www.example.com",
    ] {
        let report = run(url);
        let mut words = format!("{} {}", report.verdict.headline, report.verdict.detail);
        for finding in &report.findings {
            words.push(' ');
            words.push_str(&finding.summary);
            for part in [&finding.note, &finding.action].into_iter().flatten() {
                words.push(' ');
                words.push_str(part);
            }
            for detail in &finding.details {
                words.push(' ');
                words.push_str(&detail.value);
                words.push(' ');
                words.push_str(detail.reason.as_deref().unwrap_or(""));
            }
        }
        let words = words
            .to_lowercase()
            .replace("does not guarantee that the site is safe", "");
        for banned in [
            "safe",
            "legitimate",
            "genuine",
            "trustworthy",
            "definitely",
            "is a scam",
            "malicious",
        ] {
            assert!(!words.contains(banned), "{banned} in {words}");
        }
    }
}

#[test]
fn the_address_is_never_part_of_the_log() {
    let report = run("https://paypal.com.account-verify.example/login?token=abc123");
    for step in report.findings.iter().flat_map(|f| f.steps.iter()) {
        for text in [&step.action, &step.plain, &step.method, &step.result] {
            assert!(
                !text.contains("account-verify") && !text.contains("abc123"),
                "{text}"
            );
        }
    }
}

#[test]
fn the_report_is_sent_in_the_shape_the_interface_reads() {
    let json = serde_json::to_value(run("https://paypa1.com/login")).expect("it serialises");
    assert_eq!(json["verdict"]["status"], "risk");
    let ids: Vec<&str> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["address", "lookalikes", "destination", "connection"]);
    assert_eq!(json["findings"][1]["status"], "risk");
    assert!(
        json["findings"][1]["details"][0]["label"]
            .as_str()
            .unwrap()
            .starts_with("Looks like")
    );
    // No address list is sent, since the address is the thing being checked.
    assert!(json["findings"][1].get("urls").is_none());
}

#[test]
fn odd_input_never_panics() {
    let pieces = [
        "http://",
        "https://",
        "%",
        "%zz",
        "&",
        "=",
        "\u{202e}",
        "\u{430}",
        "\u{1f600}",
        "\u{0}",
        "xn--",
        "..",
        "@",
        ":",
        "/",
        "?",
        "#",
        "[",
        "]",
        "paypal",
        "bit.ly",
        "192.168.0.1",
        "\u{e9}\u{301}",
        "-",
        "com",
        ".",
        "javascript:",
        "data:",
    ];
    let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..3_000 {
        let mut text = String::new();
        for _ in 0..12 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            text.push_str(pieces[(seed >> 33) as usize % pieces.len()]);
        }
        let outcome = std::panic::catch_unwind(|| analyse(&text));
        assert!(outcome.is_ok(), "panicked on {text:?}");
    }
}
