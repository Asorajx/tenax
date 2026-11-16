// Realistic emails, run through the whole checker. Each group has cases that should be left
// alone as well as cases that should be flagged, because a detector that only flags things is
// easy to write and not much use.

use super::*;
use crate::finding::Status;

fn run(text: &str) -> ScamReport {
    check_email_scam(text.to_string()).expect("the email could be read")
}

fn card<'a>(report: &'a ScamReport, id: &str) -> &'a Finding {
    report
        .findings
        .iter()
        .find(|f| f.id == id)
        .expect("card exists")
}

fn status(report: &ScamReport, id: &str) -> Status {
    card(report, id).status
}

fn has_row(report: &ScamReport, id: &str, label: &str) -> bool {
    card(report, id).details.iter().any(|d| d.label == label)
}

// The statuses of the four cards, in order, for readable failures.
fn shape(report: &ScamReport) -> Vec<Status> {
    report.findings.iter().map(|f| f.status).collect()
}

// =========================
// Genuine emails that should be left alone
// =========================

#[test]
fn ordinary_business_urgency_is_not_treated_as_fraud() {
    let report = run(
        "Hi team, the board meets on Friday, so I need the Q3 report urgently. Please send it \
         to me as soon as possible, ideally within 24 hours. Thanks, Priya",
    );
    // Urgent wording is noted, but nothing else is wrong, so it is not a concern.
    assert_eq!(status(&report, "pressure"), Status::Info);
    assert_eq!(report.verdict.status, Status::Ok, "{:?}", shape(&report));
    assert_eq!(
        report.verdict.headline,
        "No common scam indicators detected."
    );
    assert!(
        card(&report, "pressure")
            .note
            .as_deref()
            .unwrap()
            .contains("ordinary email")
    );
}

#[test]
fn a_marketing_email_with_tracking_links_is_limited_not_suspicious() {
    let report = run(
        "<html><body><h1>Spring sale</h1><p>Hi Jo, our big sale ends soon and we saved your favourites. \
         <a href=\"https://click.mailer.example.com/c/abc?x=1\">Shop the sale</a> or visit \
         <a href=\"https://u1.ct.sendgrid.net/ls/click?upn=abc\">www.example-shop.com</a></p>\
         <p><a href=\"https://click.mailer.example.com/unsub\">Unsubscribe</a></p></body></html>",
    );
    // Nothing is a concern, but the real destinations cannot be seen, so it is not a clean result.
    assert_eq!(status(&report, "links"), Status::Limited);
    assert!(
        report
            .findings
            .iter()
            .all(|f| !matches!(f.status, Status::Risk | Status::Warning))
    );
    assert_eq!(report.verdict.status, Status::Limited);
    assert_eq!(
        report.verdict.headline,
        "Analysis limited by missing information."
    );
    assert!(
        card(&report, "links")
            .note
            .as_deref()
            .unwrap()
            .contains("not visible")
    );
}

#[test]
fn a_password_reset_notification_is_not_asking_for_anything() {
    let report = run(
        "Hello Sam, we received a request to reset your password. Use the verification code 482913 \
         to continue. If you did not request this, you can ignore this email. Never share this \
         code or your password with anyone. https://accounts.google.com/signin/recovery",
    );
    assert_eq!(
        status(&report, "requests"),
        Status::Ok,
        "{:?}",
        shape(&report)
    );
    assert_eq!(status(&report, "links"), Status::Ok);
    assert_eq!(report.verdict.status, Status::Ok);
}

#[test]
fn a_genuine_security_notification_with_a_company_link_is_only_a_note() {
    let report = run(
        "We detected suspicious activity on your account from a new device in Sydney. If this was \
         you, no action is needed. If it was not, review your recent activity and secure your \
         account at https://myaccount.google.com/security",
    );
    assert_eq!(status(&report, "pressure"), Status::Info);
    assert_eq!(status(&report, "links"), Status::Ok);
    assert_eq!(report.verdict.status, Status::Ok, "{:?}", shape(&report));
}

#[test]
fn legitimate_third_party_delivery_is_limited_and_never_vouched_for() {
    let report = run(
        "From: Example Shop <orders@shop.example>\nTo: sam@example.net\nSubject: Your receipt\n\
         Date: Tue, 1 Jan 2030 10:00:00 +0000\n\n\
         <html><body><p>Thanks for your order, Sam. Your receipt is ready and will be kept for 90 days.</p>\
         <a href=\"https://u9.ct.sendgrid.net/ls/click?upn=receipt\">View your receipt</a></body></html>",
    );
    assert_eq!(status(&report, "links"), Status::Limited);
    assert_eq!(report.verdict.status, Status::Limited);
    // The sending service is not treated as proof of anything, and headers are kept apart.
    let other = card(&report, "other").note.as_deref().unwrap();
    assert!(other.contains("Email Headers"));
    assert!(!report.verdict.headline.to_lowercase().contains("safe"));
}

// =========================
// Suspicious emails that should be flagged
// =========================

#[test]
fn credential_phishing_with_a_brand_lookalike_is_strong() {
    let report = run(
        "<p>Dear customer, we noticed unusual activity. Your account will be suspended within 24 hours \
         unless you verify your account.</p>\
         <p><a href=\"https://paypal.com.account-verify.example/login\">www.paypal.com/signin</a></p>",
    );
    assert_eq!(status(&report, "links"), Status::Risk);
    assert_eq!(status(&report, "pressure"), Status::Warning);
    assert_eq!(status(&report, "requests"), Status::Warning);
    assert_eq!(report.verdict.status, Status::Risk);
    assert_eq!(report.verdict.headline, "Strong scam indicators detected.");
    assert!(has_row(&report, "links", "Looks like PayPal"));
    assert!(has_row(
        &report,
        "links",
        "Link text differs from where it goes"
    ));
    // What was found, why it matters and what to do are all there.
    let links = card(&report, "links");
    assert!(links.action.as_deref().unwrap().contains("Do not click"));
    assert!(
        card(&report, "requests")
            .action
            .as_deref()
            .unwrap()
            .contains("organisation's website")
    );
}

#[test]
fn payment_redirection_is_invoice_fraud() {
    let report = run(
        "Hi Anna, please note our bank details have changed. Use the new bank details below for \
         invoice 4471 and pay by Friday. Kind regards, Mark",
    );
    assert_eq!(status(&report, "requests"), Status::Risk);
    assert!(has_row(&report, "requests", "Changes where payment goes"));
    assert!(
        card(&report, "requests")
            .action
            .as_deref()
            .unwrap()
            .contains("phoning")
    );
    assert_eq!(report.verdict.status, Status::Risk);
}

#[test]
fn brand_impersonation_through_a_subdomain_is_caught() {
    let report = run(
        "Microsoft Security Team: your mailbox is almost full. Keep your account active by visiting \
         https://login-microsoft.support-center.example/mailbox today.",
    );
    assert_eq!(status(&report, "links"), Status::Risk);
    assert!(has_row(&report, "links", "Looks like Microsoft"));
    assert_eq!(report.verdict.status, Status::Risk);
}

#[test]
fn a_fake_account_suspension_with_a_shortened_link_is_strong() {
    let report = run(
        "Your account has been locked. Action required: sign in at https://bit.ly/3XyZ to unlock \
         your account within 48 hours.",
    );
    assert_eq!(status(&report, "links"), Status::Warning);
    assert!(has_row(&report, "links", "Shortened link"));
    // The shortened link's destination is not known, and that is said as well.
    assert!(card(&report, "links").summary.contains("limited analysis"));
    assert_eq!(report.verdict.status, Status::Risk);
    assert!(report.verdict.detail.contains("also limited"));
}

#[test]
fn a_gift_card_request_with_secrecy_is_strong() {
    let report = run(
        "Hi, are you at your desk? I need you to buy 5 gift cards for a client today and send me \
         the codes. Keep this confidential, I am in a meeting.",
    );
    assert_eq!(status(&report, "requests"), Status::Risk);
    assert_eq!(status(&report, "other"), Status::Warning);
    assert_eq!(report.verdict.status, Status::Risk);
}

#[test]
fn a_cryptocurrency_payment_demand_is_strong() {
    let report =
        run("Send 0.5 bitcoin to the wallet below within 24 hours or your files stay locked.");
    assert_eq!(status(&report, "requests"), Status::Risk);
}

#[test]
fn a_request_for_a_security_code_is_strong() {
    let report = run(
        "This is the bank. Please read out the verification code we just texted to you so we can cancel the fraud.",
    );
    assert_eq!(status(&report, "requests"), Status::Risk);
    assert!(has_row(&report, "requests", "Asks for a security code"));
}

#[test]
fn malicious_and_misleading_links_are_strong() {
    let report = run(
        "<p>Your parcel could not be delivered, please confirm the address and pay the small fee.</p>\
         <a href=\"https://paypal.com@evil.example/pay\">Pay now</a> \
         <a href=\"https://192.168.4.7/track\">Track</a> \
         <a href=\"javascript:void(0)\">Open</a>",
    );
    assert_eq!(status(&report, "links"), Status::Risk);
    for label in [
        "Hides the real destination",
        "Address is a number",
        "Link runs code",
    ] {
        assert!(has_row(&report, "links", label), "{label}");
    }
    assert_eq!(report.verdict.status, Status::Risk);
}

#[test]
fn many_overlapping_indicators_are_counted_once_each() {
    let report = run(
        "URGENT urgent! Act now, respond immediately and urgently. Buy a gift card, then buy more \
         gift cards and send the gift card codes.",
    );
    let pressure = card(&report, "pressure");
    assert_eq!(
        pressure.details.len(),
        1,
        "one kind of wording, however many phrases"
    );
    // Urgent wording next to a request for payment is a concern, not just a note.
    assert_eq!(pressure.summary, "1 sign");
    let requests = card(&report, "requests");
    assert_eq!(requests.details.len(), 1);
    assert_eq!(requests.summary, "1 sign");
}

#[test]
fn a_wire_transfer_request_is_only_a_concern_next_to_pressure() {
    // Urgency and a request to send money by wire: worth checking, but not strong on its own.
    let fraud = run(
        "Are you available? I need you to process an urgent wire transfer today. Do not call me, I am in a meeting.",
    );
    assert_eq!(status(&fraud, "requests"), Status::Warning);
    assert_eq!(status(&fraud, "pressure"), Status::Warning);
    assert_eq!(fraud.verdict.status, Status::Warning);
    // A genuine invoice that merely offers wire transfer is left alone.
    let invoice = run(
        "Hi, please find invoice 1042 for $450, due on 30 June. You can pay by wire transfer or card, whichever you prefer. Thanks, Dana",
    );
    assert_eq!(status(&invoice, "requests"), Status::Ok);
    assert_eq!(invoice.verdict.status, Status::Ok);
}

#[test]
fn genuine_everyday_emails_are_not_flagged() {
    let emails = [
        "Your monthly statement is ready. Log in to online banking to view it. For your security, we will never ask for your password, PIN or full card number by email. https://www.examplebank.com/statements",
        "Your package from Amazon has shipped and will arrive on Tuesday. Track your package: https://www.amazon.com/progress-tracker/package/ref=xyz Thanks for shopping with Amazon.",
        "Urgent: please confirm your attendance for tomorrow's meeting immediately, the room booking closes at noon and we need numbers for catering.",
        "Security alert: new sign-in on Windows. If this was you, you don't need to do anything. If not, we'll help you secure your account. https://accounts.google.com/AccountChooser?continue=https%3A%2F%2Fmyaccount.google.com",
        "Your payment failed. Please update your payment method within 7 days to avoid losing access to your account. https://billing.saas-example.com/update",
    ];
    for email in emails {
        let report = run(email);
        assert!(
            report
                .findings
                .iter()
                .all(|f| !matches!(f.status, Status::Risk | Status::Warning)),
            "{email}: {:?}",
            shape(&report)
        );
        assert_eq!(report.verdict.status, Status::Ok, "{email}");
    }
}

#[test]
fn more_scams_are_flagged_by_what_they_ask_for() {
    let netflix = run(
        "Hello, your Netflix account is on hold. Update your payment details now: http://netflix-billing-update.example.xyz/login",
    );
    assert_eq!(netflix.verdict.status, Status::Risk);
    let tax = run(
        "The tax office has calculated a refund for you. Submit your tax file number and bank account number to receive it within 24 hours.",
    );
    assert_eq!(status(&tax, "requests"), Status::Risk);
    let prize = run(
        "Congratulations! You have won a 1000 dollar gift voucher. Claim your prize now: http://prizes-claim.example.top/win",
    );
    assert_eq!(status(&prize, "other"), Status::Warning);
    assert_eq!(prize.verdict.status, Status::Warning);
}

#[test]
fn a_clean_result_always_says_it_is_not_a_guarantee() {
    let report =
        run("Hi Sam, lunch on Friday? I booked the usual place at one, see you there around noon.");
    assert_eq!(report.verdict.status, Status::Ok);
    assert!(
        report
            .verdict
            .detail
            .contains("does not guarantee that the email is safe")
    );
}

// =========================
// Technical edge cases
// =========================

#[test]
fn a_cyrillic_lookalike_domain_is_caught_in_html() {
    let report = run(
        "<p>Please sign in to continue to your account.</p><a href=\"https://p\u{430}ypal.com/signin\">Sign in</a>",
    );
    assert_eq!(status(&report, "links"), Status::Risk);
    assert!(has_row(&report, "links", "Looks like PayPal"));
}

#[test]
fn punycode_and_international_domains_are_told_apart() {
    let report = run(
        "Visit https://xn--mnchen-3ya.example and https://m\u{fc}nchen.example for the schedule of events this week.",
    );
    // An honest international name is only a note, never a concern.
    assert!(
        report
            .findings
            .iter()
            .all(|f| !matches!(f.status, Status::Risk | Status::Warning))
    );
    assert!(has_row(&report, "links", "International characters"));
}

#[test]
fn an_encoded_destination_is_decoded_and_judged() {
    let report = run(
        "Open https://track.example.com/r?url=https%3A%2F%2Fpaypal.com.evil.example%2Flogin to see your invoice today.",
    );
    assert_eq!(status(&report, "links"), Status::Risk);
    assert!(has_row(&report, "links", "Redirect link"));
}

#[test]
fn malformed_html_and_entities_still_give_a_sensible_result() {
    let report = run(
        "<div><p>Pay &amp; confirm your details now <b>urgently <a href=\"https://pay.example.com/x?a=1&amp;b=2\">www.shop.example.net</a>",
    );
    assert!(has_row(
        &report,
        "links",
        "Link text differs from where it goes"
    ));
    assert_eq!(status(&report, "links"), Status::Warning);
}

#[test]
fn missing_link_targets_are_limited_not_clean() {
    let report = run(
        "<p>Hello, your invoice is ready. <a>Click here</a> to log in and <a href=\"\">view it</a> online today please.</p>",
    );
    assert_eq!(status(&report, "links"), Status::Limited);
    assert!(
        card(&report, "links")
            .note
            .as_deref()
            .unwrap()
            .contains("does not include where they go")
    );

    let plain =
        run("Hello, your invoice is ready. Click here to log in and view it online today please.");
    assert_eq!(status(&plain, "links"), Status::Limited);
    assert_eq!(plain.verdict.status, Status::Limited);
}

#[test]
fn relative_and_malformed_links_are_not_guessed_at() {
    let report = run(
        "<p>Welcome back to your account area, open <a href=\"/account/login\">your profile</a> or <a href=\"http://\">help</a> anytime.</p>",
    );
    assert_eq!(status(&report, "links"), Status::Limited);
    assert!(
        card(&report, "links")
            .note
            .as_deref()
            .unwrap()
            .contains("incomplete or malformed")
    );
}

#[test]
fn plain_text_and_html_give_the_same_answer_for_the_same_link() {
    let plain =
        run("Please log in at https://paypal.com.evil.example/login to continue with your order.");
    let html = run(
        "<p>Please log in at <a href=\"https://paypal.com.evil.example/login\">https://paypal.com.evil.example/login</a> to continue with your order.</p>",
    );
    assert_eq!(status(&plain, "links"), Status::Risk);
    assert_eq!(status(&html, "links"), Status::Risk);
    // The link is only counted once in the HTML version.
    assert_eq!(card(&html, "links").details[0].value, "1");
}

#[test]
fn a_very_long_message_is_handled_and_still_checked() {
    let filler = "The quarterly figures are attached for your review and comments. ".repeat(12_000);
    let report = run(&format!(
        "{filler} Please send us your password to continue."
    ));
    assert_eq!(status(&report, "requests"), Status::Risk);
    // The pasted text is also capped, so something far larger is refused outright.
    assert!(check_email_scam("a ".repeat(MAX_LENGTH)).is_err());
}

#[test]
fn very_deeply_nested_html_does_not_overflow_the_stack() {
    let nested = format!(
        "{}Please confirm your details urgently{}",
        "<div>".repeat(5_000),
        "</div>".repeat(5_000)
    );
    let report = run(&nested);
    assert!(
        card(&report, "requests")
            .details
            .iter()
            .any(|d| d.label == "Asks you to verify your account")
    );
}

#[test]
fn empty_and_whitespace_only_input_is_refused_with_a_clear_message() {
    for text in ["", "   \n\t  ", "hi", "ok thanks"] {
        let error = check_email_scam(text.to_string()).err().expect("refused");
        assert!(error.contains("too little text"), "{text:?}: {error}");
    }
}

#[test]
fn a_few_words_are_checked_but_never_reported_as_clean() {
    let report = run("Thanks, see you at lunch tomorrow then.");
    assert_eq!(report.verdict.status, Status::Limited);
    assert!(
        card(&report, "pressure")
            .note
            .as_deref()
            .unwrap()
            .contains("very little text")
    );
}

#[test]
fn text_that_cannot_be_read_is_limited_not_clean() {
    // Mostly images.
    let images = run(
        "<p>Your statement</p><img src=\"https://cdn.example/a.png\"><img src=\"https://cdn.example/b.png\"> see attached picture of the account please today",
    );
    assert_eq!(
        images.verdict.status,
        Status::Limited,
        "{:?}",
        shape(&images)
    );
    // Encoded parts.
    let encoded = run(
        "Content-Transfer-Encoding: base64\n\nWW91ciBhY2NvdW50IHdpbGwgYmUgc3VzcGVuZGVkIHdpdGhpbiAyNCBob3Vycw==\nWW91ciBhY2NvdW50IHdpbGwgYmUgc3VzcGVuZGVk",
    );
    assert_eq!(encoded.verdict.status, Status::Limited);
    // Another language.
    let french = run(
        "Bonjour Marie, nous vous remercions pour votre commande. Votre colis sera livre demain matin entre neuf heures et midi, merci de votre confiance et a bientot sur notre boutique en ligne.",
    );
    assert_eq!(french.verdict.status, Status::Limited);
    assert!(
        card(&french, "pressure")
            .note
            .as_deref()
            .unwrap()
            .contains("English")
    );
}

// =========================
// When "Checked" is earned
// =========================

#[test]
fn links_are_checked_only_when_their_addresses_were_available_and_read() {
    // Every link is a real address that was read, and nothing is wrong with them.
    let html = run(
        "<p>Your order has shipped and will arrive on Tuesday, thanks for shopping with us.</p><a href=\"https://www.amazon.com/progress-tracker/package/1\">Track it</a>",
    );
    assert_eq!(status(&html, "links"), Status::Ok);
    assert_eq!(
        card(&html, "links").summary,
        "Checked · no suspicious patterns"
    );

    // The same in plain text: the address is the link, so it is read in full.
    let plain = run(
        "Your order has shipped and will arrive on Tuesday. Track it at https://www.amazon.com/progress-tracker/package/1 and thanks for shopping with us.",
    );
    assert_eq!(status(&plain, "links"), Status::Ok);
}

#[test]
fn words_that_act_as_links_without_enough_addresses_are_limited() {
    // Two links in words, one address: the other link's address was lost when it was pasted.
    let report = run(
        "Your statement is ready, click here to view it or click here to change your settings. Direct link: https://www.examplebank.com/statements",
    );
    assert_eq!(status(&report, "links"), Status::Limited);
    assert_eq!(report.verdict.status, Status::Limited);
    let note = card(&report, "links").note.as_deref().unwrap();
    assert!(
        note.contains("2 links in words") && note.contains("only 1 address is included"),
        "{note}"
    );

    // As many addresses as links in words: nothing is missing, so it can be checked.
    let complete = run(
        "Your statement is ready, click here https://www.examplebank.com/statements to view it and thanks for banking with us today.",
    );
    assert_eq!(status(&complete, "links"), Status::Ok);
}

#[test]
fn an_address_that_cannot_be_examined_is_limited_not_checked() {
    let report = run(
        "Please see the plan at http://intranet/plans and let me know what you think by the end of the week.",
    );
    assert_eq!(status(&report, "links"), Status::Limited);
    assert!(
        card(&report, "links")
            .note
            .as_deref()
            .unwrap()
            .contains("could not be fully examined")
    );
}

#[test]
fn encoded_parts_make_the_links_limited_too() {
    let report = run(
        "Content-Transfer-Encoding: base64\n\nWW91ciBpbnZvaWNlIGlzIHJlYWR5IGFuZCB0aGUgbGluayBpcyBpbnNpZGU=\nWW91ciBpbnZvaWNlIGlzIHJlYWR5IGFuZCB0aGUgbGluayBpcyBpbnNpZGU=\nhttps://www.amazon.com/orders",
    );
    assert_eq!(status(&report, "links"), Status::Limited);
    assert!(
        card(&report, "links")
            .note
            .as_deref()
            .unwrap()
            .contains("encoded")
    );
}

// =========================
// Short and folded explanations
// =========================

#[test]
fn reasons_are_kept_apart_from_what_was_found() {
    let report =
        run("URGENT: your account will be suspended within 24 hours. Send us your password now.");
    for id in ["pressure", "requests"] {
        for row in &card(&report, id).details {
            // What was found is short and visible. Why it matters is a separate reason.
            assert!(row.value.starts_with('"'), "{id}: {}", row.value);
            assert!(
                row.reason
                    .as_deref()
                    .is_some_and(|reason| reason.len() > 20),
                "{id}: {}",
                row.label
            );
        }
    }
    // The visible part of the pressure card is short.
    let pressure = card(&report, "pressure");
    let visible: usize = pressure
        .details
        .iter()
        .map(|d| d.label.len() + d.value.len())
        .sum::<usize>()
        + pressure.note.as_deref().map_or(0, str::len)
        + pressure.action.as_deref().map_or(0, str::len);
    assert!(visible < 420, "{visible} characters visible");
}

#[test]
fn a_note_for_low_concern_wording_is_one_short_sentence() {
    let report = run(
        "Please send the report urgently, ideally within 24 hours, as the board meets on Friday morning.",
    );
    let note = card(&report, "pressure").note.as_deref().unwrap();
    assert!(note.len() < 80, "{note}");
}

#[test]
fn repeated_points_about_links_are_joined_into_one_row() {
    let report = run(
        "<p>Hello Jo, our sale ends soon.</p><a href=\"https://click.a-mailer.example.com/1\">One</a><a href=\"https://u1.ct.sendgrid.net/ls/click?upn=2\">Two</a><a href=\"http://old.example.org/x\">Three</a>",
    );
    let links = card(&report, "links");
    let tracking: Vec<_> = links
        .details
        .iter()
        .filter(|d| d.label == "Tracking link")
        .collect();
    assert_eq!(tracking.len(), 1);
    assert!(
        tracking[0].value.contains("click.a-mailer.example.com")
            && tracking[0].value.contains("u1.ct.sendgrid.net")
    );
    assert_eq!(
        tracking[0].reason.as_deref(),
        Some("Counts clicks before passing you on")
    );
}

// =========================
// Notes and the verdict
// =========================

#[test]
fn notes_alone_never_change_the_verdict() {
    // A generic greeting, ordinary urgency, an unencrypted link and an international name:
    // all notes, none a concern, and every address could be read.
    let report = run(
        "Dear customer, please send the signed form urgently, ideally within 24 hours. The schedule \
         is at http://m\u{fc}nchen.example.org/plan and the venue is the usual one.",
    );
    for id in ["pressure", "links", "other"] {
        assert!(
            !matches!(status(&report, id), Status::Risk | Status::Warning),
            "{id}: {:?}",
            shape(&report)
        );
    }
    assert_eq!(report.verdict.status, Status::Ok, "{:?}", shape(&report));
    // Notes are listed, but they do not make the result worse.
    assert!(
        !card(&report, "links")
            .details
            .iter()
            .all(|d| d.label == "Links found")
    );
}

#[test]
fn notes_do_not_hide_a_limited_analysis_either() {
    let report = run(
        "Dear customer, please send the signed form urgently. Click here to open it, thanks for your help with the move.",
    );
    assert_eq!(status(&report, "other"), Status::Info);
    assert_eq!(report.verdict.status, Status::Limited);
    assert!(report.verdict.detail.contains("not a clean result"));
}

#[test]
fn a_note_never_raises_a_concern_on_its_own() {
    // Each of these is a note, and none is a concern when it stands alone.
    for email in [
        "Dear customer, the invoice for last month is below and we hope the service has been good.",
        "Please see the attached invoice and open the attachment for the full breakdown of costs.",
        "This is urgent, please call me back immediately when you have a moment today, thanks.",
    ] {
        let report = run(email);
        assert!(
            report
                .findings
                .iter()
                .all(|f| !matches!(f.status, Status::Risk | Status::Warning)),
            "{email}: {:?}",
            shape(&report)
        );
        assert_ne!(report.verdict.status, Status::Risk, "{email}");
        assert_ne!(report.verdict.status, Status::Warning, "{email}");
    }
}

// =========================
// The listed links
// =========================

fn urls(report: &ScamReport) -> &[crate::finding::UrlItem] {
    &card(report, "links").urls
}

fn assessment_of<'a>(report: &'a ScamReport, url: &str) -> (&'a Status, &'a str) {
    let item = urls(report)
        .iter()
        .find(|item| item.url == url)
        .expect("the link is listed");
    (&item.status, item.assessment.as_str())
}

#[test]
fn each_link_is_listed_with_its_own_short_assessment() {
    let report = run(
        "<p>Hello Sam, here are your links for this week, please look them over today.</p>\
         <a href=\"https://www.amazon.com/orders\">Orders</a>\
         <a href=\"https://paypal.com.account-verify.example/login\">www.paypal.com</a>\
         <a href=\"https://bit.ly/3abc\">Offer</a>\
         <a href=\"https://click.mailer.example.com/c/1\">Shop</a>\
         <a href=\"/account/login\">Profile</a>\
         <a href=\"http://old.example.org/page\">Old page</a>",
    );

    assert_eq!(
        assessment_of(&report, "https://www.amazon.com/orders"),
        (&Status::Ok, "No problems found")
    );
    let (status, text) = assessment_of(&report, "https://paypal.com.account-verify.example/login");
    assert_eq!(status, &Status::Risk);
    assert!(text.contains("Looks like PayPal"), "{text}");
    let (status, text) = assessment_of(&report, "https://bit.ly/3abc");
    assert_eq!(status, &Status::Warning);
    assert!(
        text.starts_with("Shortened link") && text.contains("destination not visible"),
        "{text}"
    );
    assert_eq!(
        assessment_of(&report, "https://click.mailer.example.com/c/1"),
        (&Status::Limited, "Destination not visible")
    );
    assert_eq!(
        assessment_of(&report, "/account/login"),
        (&Status::Limited, "Incomplete address")
    );
    assert_eq!(
        assessment_of(&report, "http://old.example.org/page"),
        (&Status::Info, "Not encrypted")
    );
}

#[test]
fn links_that_are_not_web_links_are_not_listed_and_repeats_are_listed_once() {
    let report = run(
        "<p>Contact us on the number below or by email, and see the page for the opening hours this week.</p>\
         <a href=\"mailto:help@example.net\">Email</a><a href=\"#top\">Top</a><a href=\"tel:+61400000000\">Call</a>\
         <a href=\"https://www.amazon.com/orders\">Orders</a><a href=\"https://www.amazon.com/orders\">Orders again</a>",
    );
    let listed: Vec<&str> = urls(&report).iter().map(|item| item.url.as_str()).collect();
    assert_eq!(listed, ["https://www.amazon.com/orders"]);
}

#[test]
fn a_link_that_runs_code_is_listed_as_a_risk() {
    let report = run(
        "<p>Please open the document using the button below, it expires soon so do it today.</p><a href=\"javascript:void(0)\">Open</a>",
    );
    assert_eq!(
        assessment_of(&report, "javascript:void(0)"),
        (&Status::Risk, "Link runs code")
    );
}

#[test]
fn a_very_long_list_is_capped_and_the_rest_are_counted() {
    let links: String = (0..45)
        .map(|i| format!("<a href=\"https://www.amazon.com/item/{i}\">Item {i}</a> "))
        .collect();
    let report = run(&format!(
        "<p>Hello Sam, here is the full list of items from this week.</p>{links}"
    ));
    assert_eq!(urls(&report).len(), 30);
    assert!(
        card(&report, "links")
            .note
            .as_deref()
            .unwrap()
            .contains("Showing the first 30 of 45 links")
    );
}

#[test]
fn only_the_links_card_lists_links_and_the_listing_is_sent_in_the_shape_the_interface_reads() {
    let report = run(
        "Please log in at https://paypal.com.account-verify.example/login to continue with your order today.",
    );
    let json = serde_json::to_value(&report).expect("it serialises");
    let findings = json["findings"].as_array().unwrap();
    for finding in findings {
        assert_eq!(
            finding.get("urls").is_some(),
            finding["id"] == "links",
            "{}",
            finding["id"]
        );
    }
    let item = &findings[2]["urls"][0];
    assert_eq!(
        item["url"],
        "https://paypal.com.account-verify.example/login"
    );
    assert_eq!(item["status"], "risk");
    assert!(
        item["assessment"]
            .as_str()
            .unwrap()
            .contains("Looks like PayPal")
    );
}

#[test]
fn the_link_checks_can_be_used_for_one_address_on_its_own() {
    // The URL Checker will use the same checks for a single address.
    let single = crate::email_scam::links::analyse(
        &[crate::email_scam::content::RawLink {
            href: "https://paypa1.com/login".to_string(),
            shown: None,
        }],
        &[],
        "",
    );
    assert_eq!(single.items.len(), 1);
    assert_eq!(single.items[0].status, Status::Risk);
    assert!(single.items[0].assessment.contains("Looks like PayPal"));
}

#[test]
fn the_limits_read_naturally_for_one_link_and_for_several() {
    let one = run(
        "<p>Welcome back to your account area, open <a href=\"/account/login\">your profile</a> anytime you like.</p>",
    );
    assert!(
        card(&one, "links")
            .note
            .as_deref()
            .unwrap()
            .contains("1 link is incomplete or malformed, so where it goes cannot be told.")
    );
    let two = run(
        "<p>Welcome back to your account area, open <a href=\"/a\">your profile</a> or <a href=\"/b\">help</a> anytime.</p>",
    );
    assert!(
        card(&two, "links")
            .note
            .as_deref()
            .unwrap()
            .contains("2 links are incomplete or malformed, so where they go cannot be told.")
    );
}

// =========================
// Headers, limits and wording
// =========================

#[test]
fn only_the_subject_and_body_are_read_from_a_full_message() {
    let report = run(
        "Received: from urgent-immediately.example by mx.example.net; Tue, 1 Jan 2030\n\
         From: a@example.net\nTo: b@example.net\nSubject: Final notice\n\n\
         Hello Sam, the meeting notes from Tuesday are below, as discussed over lunch.",
    );
    // The subject counts, but words in other header lines do not.
    let rows: Vec<_> = card(&report, "pressure")
        .details
        .iter()
        .map(|d| d.label.as_str())
        .collect();
    assert_eq!(rows, ["Short deadline"]);
}

#[test]
fn authentication_results_never_soften_what_the_content_shows() {
    let report = run(
        "Authentication-Results: mx.example.net; spf=pass; dkim=pass; dmarc=pass header.from=bank.example\n\
         From: Bank <help@bank.example>\nTo: b@example.net\nSubject: Update\n\n\
         Please send us your password and the verification code, or your account will be suspended.",
    );
    assert_eq!(status(&report, "requests"), Status::Risk);
    assert_eq!(report.verdict.status, Status::Risk);
}

#[test]
fn duplicate_links_make_one_row() {
    let links: String = (0..50)
        .map(|i| format!("<a href=\"https://bit.ly/x{i}\">Offer {i}</a> "))
        .collect();
    let report = run(&format!(
        "<p>Hello Sam, here are fifty offers for you this week only today.</p>{links}"
    ));
    let rows = card(&report, "links")
        .details
        .iter()
        .filter(|d| d.label == "Shortened link")
        .count();
    assert_eq!(rows, 1);
}

#[test]
fn the_steps_describe_what_was_done_without_repeating_the_email() {
    let report = run(
        "Please send us your password to continue, then visit https://paypal.com.evil.example/login today.",
    );
    let steps: Vec<&Step> = report
        .findings
        .iter()
        .flat_map(|f| f.steps.iter())
        .collect();
    assert!(steps.len() >= 6);
    for step in steps {
        for text in [&step.action, &step.plain, &step.method, &step.result] {
            assert!(
                !text.contains("evil.example")
                    && !text.to_lowercase().contains("password to continue"),
                "{text}"
            );
        }
    }
}

#[test]
fn nothing_claims_an_email_is_safe_legitimate_or_definitely_fraudulent() {
    let emails = [
        "Hi Sam, lunch on Friday? I booked the usual place at one, see you there around noon.",
        "<p>Our sale ends soon.</p><a href=\"https://click.mailer.example.com/c/1\">Shop now at www.shop.example</a>",
        "Dear customer, you have won the lottery! Buy gift cards and send the codes. https://bit.ly/abc",
        "Your account will be suspended. Verify your account at https://paypal.com.evil.example/login now",
        "Click here to log in to your account and review the statement we sent you this morning please.",
    ];
    for email in emails {
        let report = run(email);
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
            }
        }
        // The only allowed use is to say that finding nothing is not a guarantee.
        let words = words
            .to_lowercase()
            .replace("does not guarantee that the email is safe", "");
        for banned in [
            "safe",
            "legitimate",
            "genuine email",
            "trustworthy",
            "definitely",
            "is a scam",
            "fraudulent",
        ] {
            assert!(!words.contains(banned), "{banned} in {words}");
        }
    }
}

#[test]
fn a_limited_analysis_is_never_reassuring() {
    for email in [
        "<p>Hello Sam, here is your receipt. <a href=\"https://click.mailer.example.com/r\">Open</a></p>",
        "Click here to sign in and see your statement from this morning, thanks for banking with us today.",
        "ok thanks see you",
    ] {
        let report = check_email_scam(email.to_string());
        if let Ok(report) = report {
            assert_ne!(report.verdict.status, Status::Ok, "{email}");
            assert!(
                report.verdict.detail.contains("not a clean result"),
                "{email}"
            );
        }
    }
}

#[test]
fn every_concern_says_what_it_is_why_it_matters_and_what_to_do() {
    let report = run(
        "Dear customer, your account will be suspended within 24 hours. Send us your password and \
         buy gift cards. Visit https://paypal.com.evil.example/login now.",
    );
    for finding in &report.findings {
        if matches!(finding.status, Status::Risk | Status::Warning) {
            assert!(
                !finding.details.is_empty(),
                "{} lists what was detected",
                finding.id
            );
            assert!(
                finding
                    .details
                    .iter()
                    .all(|d| !d.value.is_empty() && (d.reason.is_some() || finding.id == "links")),
                "{} says what was found and why it matters",
                finding.id
            );
            assert!(finding.action.is_some(), "{} says what to do", finding.id);
        }
    }
    // The same explanation is not repeated on different cards.
    let mut reasons: Vec<&str> = report
        .findings
        .iter()
        .flat_map(|f| f.details.iter().map(|d| d.value.as_str()))
        .collect();
    let before = reasons.len();
    reasons.sort();
    reasons.dedup();
    assert_eq!(before, reasons.len());
}

// =========================
// What the interface receives
// =========================

// The interface reads this JSON through invoke, so its keys and words are part of the contract.
// This is the same serialisation Tauri uses for the command's result.
#[test]
fn the_report_is_sent_in_the_shape_the_interface_reads() {
    let report = run(
        "Dear customer, your account will be suspended within 24 hours unless you verify your account at https://paypal.com.account-verify.example/login",
    );
    let json = serde_json::to_value(&report).expect("it serialises");

    assert_eq!(json["verdict"]["status"], "risk");
    assert!(json["verdict"]["headline"].is_string() && json["verdict"]["detail"].is_string());

    let findings = json["findings"].as_array().expect("a list of findings");
    let ids: Vec<&str> = findings
        .iter()
        .map(|f| f["id"].as_str().expect("an id"))
        .collect();
    assert_eq!(ids, ["pressure", "requests", "links", "other"]);
    for finding in findings {
        // Statuses are lower case words, and every field the interface needs is present.
        assert!(
            ["ok", "info", "limited", "warning", "risk", "unknown"]
                .contains(&finding["status"].as_str().unwrap())
        );
        for key in ["title", "summary", "checked", "why", "steps"] {
            assert!(!finding[key].is_null(), "{key}");
        }
    }

    // A row has its reason apart from what was found, and no empty fields are sent.
    let row = &findings[0]["details"][0];
    assert!(row["value"].as_str().unwrap().starts_with('"'));
    assert!(row["reason"].is_string());
    assert!(row.get("active").is_none());
    // The first card leads with the step that read the email, and steps carry no email text.
    assert_eq!(findings[0]["steps"][0]["action"], "Read the pasted email");
    assert!(
        findings[3].get("action").is_none(),
        "no empty advice is sent"
    );
}

// =========================
// Robustness
// =========================

#[test]
fn odd_input_never_panics() {
    // A simple repeatable mix of awkward characters, tags, entities and addresses.
    let pieces = [
        "<",
        ">",
        "</a>",
        "<a href=\"",
        "https://",
        "http://",
        "%",
        "%zz",
        "&",
        "&amp;",
        "&#x",
        "=",
        "=\n",
        "=3D",
        "\u{202e}",
        "\u{430}",
        "\u{1f600}",
        "\u{0}",
        "\"",
        "'",
        "xn--",
        "..",
        "@",
        ":",
        "/",
        "?",
        "#",
        " ",
        "\n",
        "\r\n",
        "paypal",
        "urgent",
        "gift card",
        "your password",
        "<script>",
        "</script>",
        "<style>",
        "<form action=\"",
        "<meta http-equiv=\"refresh\" content=\"0; url=",
        "[",
        "]",
        "\u{e9}\u{301}",
    ];
    let mut seed: u64 = 0x2545_F491_4F6C_DD1D;
    for _ in 0..3_000 {
        let mut text = String::new();
        for _ in 0..40 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            text.push_str(pieces[(seed >> 33) as usize % pieces.len()]);
        }
        // Either a result or a plain refusal is fine. A panic is not.
        let outcome = std::panic::catch_unwind(|| analyse(&text));
        assert!(outcome.is_ok(), "panicked on {text:?}");
    }
}

#[test]
fn a_failure_never_repeats_the_email() {
    // The command turns any failure into a fixed message that does not contain the text.
    let error = check_email_scam("ok".to_string()).err().unwrap();
    assert!(!error.contains("ok thanks"));
}
