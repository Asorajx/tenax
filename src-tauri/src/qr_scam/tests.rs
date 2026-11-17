use super::payload::{MAX_LENGTH, Payload, WifiSecurity, classify, clean, hide_secrets};
use super::{MAX_CODES, analyse, check_qr};
use crate::finding::Status;

fn texts(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| item.to_string()).collect()
}

// =========================
// What a code contains
// =========================

#[test]
fn web_addresses_are_links_with_or_without_the_scheme() {
    for text in [
        "https://example.com/login",
        "HTTP://example.com",
        "example.com/login",
        "www.example.co.uk",
        "sub.example.com:8080/path?x=1",
    ] {
        assert!(matches!(classify(text), Payload::Link(_)), "{text}");
    }
}

#[test]
fn ordinary_text_is_not_mistaken_for_a_link() {
    for text in [
        "hello",
        "Table 4, seat 2",
        "1.5",
        "v1.2.3",
        "Note: bring ID",
        "C:\\Users\\me",
        "",
    ] {
        assert!(matches!(classify(text), Payload::Text(_)), "{text}");
    }
}

#[test]
fn scripts_and_app_links_are_told_apart_from_web_links() {
    for text in [
        "javascript:alert(1)",
        "data:text/html;base64,AAAA",
        "VBSCRIPT:x",
        "file:///C:/x",
    ] {
        assert!(matches!(classify(text), Payload::Script(_)), "{text}");
    }
    for text in [
        "whatsapp://send?text=hi",
        "intent://scan/#Intent;end",
        "market://details?id=x",
    ] {
        assert!(matches!(classify(text), Payload::AppLink(_)), "{text}");
    }
}

#[test]
fn wifi_codes_are_read_and_the_password_is_only_noted() {
    let wpa = classify("WIFI:T:WPA;S:Cafe Guest;P:hunter2;H:true;;");
    assert_eq!(
        wpa,
        Payload::Wifi {
            ssid: "Cafe Guest".to_string(),
            security: WifiSecurity::Wpa,
            hidden: true,
            has_password: true,
        }
    );
    // Escaped separators belong to the name.
    match classify(r"WIFI:T:WPA2;S:a\;b\:c;P:x;;") {
        Payload::Wifi { ssid, security, .. } => {
            assert_eq!(ssid, "a;b:c");
            assert_eq!(security, WifiSecurity::Wpa);
        }
        other => panic!("{other:?}"),
    }
    for (text, wanted) in [
        ("WIFI:T:nopass;S:Free;;", WifiSecurity::Open),
        ("WIFI:S:NoType;;", WifiSecurity::Open),
        ("WIFI:T:WEP;S:Old;P:1234;;", WifiSecurity::Wep),
        ("WIFI:T:SAE;S:New;P:x;;", WifiSecurity::Wpa),
    ] {
        match classify(text) {
            Payload::Wifi { security, .. } => assert_eq!(security, wanted, "{text}"),
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn payments_and_two_factor_codes_are_recognised() {
    assert!(matches!(
        classify("upi://pay?pa=shop@bank&pn=Shop&am=250"),
        Payload::Payment {
            kind: "UPI payment request",
            ..
        }
    ));
    match classify("bitcoin:bc1qexample?amount=0.5") {
        Payload::Payment { payee, amount, .. } => {
            assert_eq!(payee.as_deref(), Some("bc1qexample"));
            assert_eq!(amount.as_deref(), Some("0.5"));
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        classify(
            "00020101021226280012com.example0108123456785204000053033605802US5904Shop6004Town6304ABCD"
        ),
        Payload::Payment { .. }
    ));
    match classify(
        "otpauth://totp/Example%20Co:me%40mail.com?secret=JBSWY3DPEHPK3PXP&issuer=Example%20Co",
    ) {
        Payload::TwoFactor {
            kind,
            account,
            issuer,
        } => {
            assert_eq!(kind, "totp");
            assert_eq!(account.as_deref(), Some("me@mail.com"));
            assert_eq!(issuer.as_deref(), Some("Example Co"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn calls_texts_emails_contacts_and_places_are_recognised() {
    assert_eq!(
        classify("tel:+61400000000"),
        Payload::Phone("+61400000000".to_string())
    );
    assert_eq!(
        classify("SMSTO:+61400000000:Hello"),
        Payload::Sms {
            number: "+61400000000".to_string(),
            has_body: true
        }
    );
    assert_eq!(
        classify("sms:+61400000000"),
        Payload::Sms {
            number: "+61400000000".to_string(),
            has_body: false
        }
    );
    assert_eq!(
        classify("mailto:me@example.com?subject=Hi"),
        Payload::Email {
            address: "me@example.com".to_string(),
            has_body: true
        }
    );
    assert_eq!(
        classify("MATMSG:TO:me@example.com;SUB:Hi;BODY:Text;;"),
        Payload::Email {
            address: "me@example.com".to_string(),
            has_body: true
        }
    );
    assert_eq!(
        classify("BEGIN:VCARD\nVERSION:3.0\nEND:VCARD"),
        Payload::Contact
    );
    assert_eq!(classify("MECARD:N:Smith,John;;"), Payload::Contact);
    assert_eq!(classify("geo:-34.4,150.9"), Payload::Location);
}

#[test]
fn hidden_characters_are_found_and_taken_out() {
    let (text, hidden) = clean("exa\u{200B}mple\u{202E}.com\u{0007}");
    assert_eq!(text, "example.com");
    assert!(hidden);

    // Line breaks and tabs are ordinary, so they are not reported.
    let (text, hidden) = clean("one\ntwo\tthree");
    assert_eq!(text, "one two three");
    assert!(!hidden);
}

#[test]
fn strange_text_never_panics() {
    let long = "a".repeat(100_000);
    let mut inputs: Vec<&str> = vec![
        "",
        " ",
        "\n",
        "WIFI:",
        "wifi:;;;;",
        "WIFI:S:\\",
        "OTPAUTH:",
        "otpauth://",
        "SMSTO:",
        "sms:",
        "SMS:::",
        "mailto:",
        "MATMSG:",
        "MATMSG:TO:",
        "000201",
        "upi:",
        "upi://",
        "bitcoin:",
        "tel:",
        "geo:",
        ":",
        "::",
        "日本語:テスト",
        "データ://x",
        "https://",
        "http://[",
        "a@b@c.com",
        "%",
        "%zz",
        "https://%zz",
        "\u{0}",
        "\u{202E}https://example.com",
        "example.com\u{200B}",
        "WIFI:T:WPA;S:\u{1F600};P:é;;",
    ];
    inputs.push(&long);
    for input in inputs {
        let (cleaned, _) = clean(input);
        let _ = classify(&cleaned);
        let _ = analyse(&[input.to_string()]);
    }
}

// =========================
// The report
// =========================

#[test]
fn a_web_link_is_judged_by_the_url_checker() {
    let report = analyse(&texts(&["https://example.com/"]));
    // One card for the code, then the URL Checker's own cards.
    assert_eq!(report.findings[0].id, "qr-1");
    assert_eq!(report.findings[0].summary, "Web link");
    assert!(report.findings.len() > 1);
    assert!(
        report
            .findings
            .iter()
            .skip(1)
            .all(|card| !card.id.starts_with("qr-"))
    );
}

#[test]
fn a_look_alike_link_is_flagged_more_seriously_than_a_plain_one() {
    let plain = analyse(&texts(&["https://example.com/"]));
    let lookalike = analyse(&texts(&["https://paypa1.com/login"]));
    assert_eq!(lookalike.verdict.status, Status::Risk);
    assert!(lookalike.verdict.status < plain.verdict.status);
}

#[test]
fn the_most_serious_code_speaks_for_the_image() {
    let report = analyse(&texts(&["Table 4", "javascript:alert(1)", "tel:123"]));
    assert_eq!(report.verdict.status, Status::Risk);
    assert_eq!(report.findings.len(), 3);
}

#[test]
fn with_several_codes_the_headline_says_which_one_it_is_about() {
    let report = analyse(&texts(&["https://example.com/", "WIFI:T:nopass;S:Free;;"]));
    assert_eq!(report.verdict.status, Status::Warning);
    assert!(report.verdict.headline.starts_with("Code 2: "));

    let single = analyse(&texts(&["WIFI:T:nopass;S:Free;;"]));
    assert!(!single.verdict.headline.starts_with("Code"));
}

#[test]
fn several_codes_get_distinct_ids_and_titles() {
    let report = analyse(&texts(&[
        "https://example.com/",
        "https://example.org/",
        "plain text",
    ]));
    let mut ids: Vec<&str> = report
        .findings
        .iter()
        .map(|card| card.id.as_str())
        .collect();
    let count = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(
        ids.len(),
        count,
        "ids must be unique, as they are used as keys"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|card| card.title.starts_with("Code 2 · "))
    );
}

#[test]
fn open_and_old_wifi_networks_are_warnings_and_a_password_is_never_shown() {
    let open = analyse(&texts(&["WIFI:T:nopass;S:Free Wifi;;"]));
    assert_eq!(open.verdict.status, Status::Warning);

    let secret = analyse(&texts(&["WIFI:T:WPA;S:Cafe;P:hunter2-secret;;"]));
    assert_eq!(secret.verdict.status, Status::Info);
    let shown = serde_json::to_string(&secret.findings).unwrap();
    assert!(!shown.contains("hunter2-secret"));
    assert!(shown.contains("Included, not shown"));
}

#[test]
fn a_two_factor_secret_is_a_warning_and_is_never_shown() {
    let report = analyse(&texts(&[
        "otpauth://totp/Bank:me?secret=JBSWY3DPEHPK3PXP&issuer=Bank",
    ]));
    assert_eq!(report.verdict.status, Status::Warning);
    assert!(
        !serde_json::to_string(&report.findings)
            .unwrap()
            .contains("JBSWY3DPEHPK3PXP")
    );
}

#[test]
fn hidden_characters_make_a_card_a_warning() {
    let report = analyse(&texts(&["Table\u{202E} 4"]));
    assert_eq!(report.findings[0].status, Status::Warning);
    assert!(
        report.findings[0]
            .note
            .as_deref()
            .unwrap()
            .contains("hidden characters")
    );
}

#[test]
fn hidden_characters_in_a_link_are_in_the_overall_result_too() {
    // The address itself is clean, but a hidden character was in the text.
    let hidden = analyse(&texts(&["https://exa\u{200B}mple.com/"]));
    assert_eq!(hidden.verdict.status, Status::Warning);
    assert!(hidden.verdict.headline.contains("hidden characters"));

    let plain = analyse(&texts(&["https://example.com/"]));
    assert!(plain.verdict.status > Status::Warning);
}

#[test]
fn a_code_that_is_too_long_is_not_read() {
    let long = "x".repeat(MAX_LENGTH + 1);
    let report = analyse(&[long]);
    assert_eq!(report.verdict.status, Status::Limited);
    assert_eq!(report.findings[0].summary, "Too long to read");
}

#[test]
fn the_command_refuses_nothing_and_too_many() {
    assert!(check_qr(Vec::new()).is_err());
    assert!(check_qr(vec!["x".to_string(); MAX_CODES + 1]).is_err());
    assert!(check_qr(texts(&["hello"])).is_ok());
}

#[test]
fn every_card_says_what_was_checked_and_why() {
    let report = analyse(&texts(&[
        "hello",
        "tel:1",
        "WIFI:T:WPA;S:a;P:b;;",
        "https://example.com",
    ]));
    for card in report
        .findings
        .iter()
        .filter(|card| card.id.starts_with("qr-"))
    {
        assert!(card.checked.starts_with("I "));
        assert!(!card.why.is_empty());
    }
}

// =========================
// Secrets in addresses, and hostile text
// =========================

#[test]
fn values_that_look_like_secrets_are_hidden_in_an_address() {
    let (shown, masked) = hide_secrets("https://example.com/reset?token=SUPERSECRET&user=bob");
    assert!(masked);
    assert!(!shown.contains("SUPERSECRET"));
    assert!(shown.contains("token=hidden") && shown.contains("user=bob"));

    for address in [
        "https://user:hunter2@example.com/",
        "https://example.com/cb#access_token=SUPERSECRET&state=x",
        "https://example.com/?API_KEY=SUPERSECRET",
        "https://example.com/?Session_Id=SUPERSECRET",
        "https://example.com/?Password=SUPERSECRET",
    ] {
        let (shown, masked) = hide_secrets(address);
        assert!(masked, "{address}");
        assert!(
            !shown.contains("SUPERSECRET") && !shown.contains("hunter2"),
            "{address} -> {shown}"
        );
    }
}

#[test]
fn an_ordinary_address_is_shown_exactly_as_it_was() {
    for address in [
        "https://example.com/a?x=1&page=2",
        "https://example.com",
        "example.com/login",
        "not a url",
        "https://example.com/?token=",
    ] {
        assert_eq!(
            hide_secrets(address),
            (address.to_string(), false),
            "{address}"
        );
    }
}

#[test]
fn a_secret_in_an_address_is_in_no_card_and_no_step() {
    let report = analyse(&texts(&[
        "https://example.com/reset?token=SUPERSECRET&user=bob",
    ]));
    let everything = serde_json::to_string(&report).unwrap();
    assert!(!everything.contains("SUPERSECRET"));
    assert!(
        report.findings[0]
            .note
            .as_deref()
            .unwrap()
            .contains("hidden")
    );
}

// A small deterministic generator, so that the same hostile text is tried on every run.
fn next(state: &mut u64) -> usize {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    (*state >> 33) as usize
}

#[test]
fn thousands_of_hostile_texts_never_panic_and_stay_fast() {
    let pieces = [
        "WIFI:",
        "T:",
        "S:",
        "P:",
        "H:",
        ";",
        "\\",
        "otpauth://",
        "totp/",
        "?",
        "&",
        "=",
        "%",
        "%zz",
        "%41",
        "https://",
        "http://",
        "@",
        ":",
        "/",
        ".",
        "-",
        "a",
        "b",
        "1",
        " ",
        "\n",
        "\u{202E}",
        "\u{200B}",
        "日本",
        "é",
        "\u{0}",
        "upi://pay?",
        "pa=",
        "tel:",
        "sms:",
        "SMSTO:",
        "mailto:",
        "MATMSG:",
        "TO:",
        "BEGIN:VCARD",
        "geo:",
        "000201",
        "javascript:",
        "data:",
        "xn--",
        "[",
        "]",
        "::1",
        "192.168.0.1",
        "bit.ly/",
        "#",
        "token=",
        "secret",
        "\u{1F600}",
    ];
    let mut state = 12345u64;
    let started = std::time::Instant::now();
    for _ in 0..3000 {
        let length = next(&mut state) % 40;
        let text: String = (0..length)
            .map(|_| pieces[next(&mut state) % pieces.len()])
            .collect();
        let (cleaned, _) = clean(&text);
        let _ = classify(&cleaned);
        let _ = hide_secrets(&cleaned);
        let _ = analyse(&[text]);
    }
    assert!(
        started.elapsed().as_secs() < 30,
        "too slow: {:?}",
        started.elapsed()
    );
}

#[test]
fn very_long_hostile_texts_are_read_quickly() {
    for unit in [
        "%", ";", "\\", ".", "a.", "http://", "@", ":", "WIFI:S:", "?a=", "%zz", "\u{202E}", "日",
    ] {
        let text = unit.repeat(MAX_LENGTH);
        let text: String = text.chars().take(MAX_LENGTH).collect();
        let started = std::time::Instant::now();
        let _ = analyse(&[text]);
        assert!(
            started.elapsed().as_millis() < 1500,
            "{unit:?} took {:?}",
            started.elapsed()
        );
    }
}
