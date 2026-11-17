// Turns what a QR code contains into a card, with what it is, why it matters and what to do.
// There is no Windows or network code here, so every kind can be tested with made-up text.
//
// A secret inside a code, such as a Wi-Fi password or a two-factor key, is never shown. Only the
// fact that it is there is.

use super::payload::{Payload, WifiSecurity, clean, hide_secrets};
use crate::finding::{Detail, Finding, Status, Verdict, detail, shorten};

// How much of a text from a code is shown.
const SHOWN: usize = 120;

const CHECKED: &str =
    "I read what the QR code contains. I did not open, follow or run anything in it.";
const WHY: &str = "A QR code hides what it holds until you scan it. Scammers put fake codes where \
                   people expect real ones, so that a scan leads somewhere they chose.";

// Text from a code, cleaned of hidden characters and cut to a length that fits on a card.
fn shown(text: &str) -> String {
    shorten(&clean(text).0, SHOWN)
}

fn yes_no(value: bool) -> &'static str {
    if value { "Yes" } else { "No" }
}

fn card(
    number: usize,
    total: usize,
    status: Status,
    summary: &str,
    action: Option<&str>,
    details: Vec<Detail>,
    note: Option<&str>,
) -> Finding {
    Finding {
        id: format!("qr-{number}"),
        status,
        title: if total > 1 {
            format!("QR code {number}")
        } else {
            "QR code".to_string()
        },
        summary: summary.to_string(),
        checked: CHECKED.to_string(),
        why: WHY.to_string(),
        action: action.map(str::to_string),
        details,
        note: note.map(str::to_string),
        urls: Vec::new(),
        steps: Vec::new(),
    }
}

// The card for one code. It says what the code is, and for a link the address cards follow it.
pub fn header(index: usize, total: usize, payload: &Payload, hidden: bool) -> Finding {
    let number = index + 1;
    let make = |status, summary: &str, action: Option<&str>, details, note: Option<&str>| {
        card(number, total, status, summary, action, details, note)
    };

    let mut finding = match payload {
        Payload::Link(address) => {
            // A password or sign-in key in the address is not put on the screen.
            let (address, masked) = hide_secrets(address);
            make(
                Status::Info,
                "Web link",
                None,
                vec![detail("Address", shown(&address))],
                masked.then_some("Some values in the address are hidden, because they look like passwords or keys."),
            )
        }
        Payload::AppLink(scheme) => make(
            Status::Limited,
            "Opens another app",
            Some(
                "Tenax cannot check this kind of link. Scan it only if you trust where the code came from.",
            ),
            vec![detail("Opens", shown(scheme))],
            None,
        ),
        Payload::Script(scheme) => make(
            if scheme == "file" {
                Status::Warning
            } else {
                Status::Risk
            },
            "Runs or loads content directly",
            Some("Do not scan this code. A genuine code points to a web address."),
            vec![detail("Kind", shown(scheme))],
            None,
        ),
        Payload::Wifi {
            ssid,
            security,
            hidden: hidden_network,
            has_password,
        } => {
            let (status, label) = match security {
                WifiSecurity::Open => (Status::Warning, "Open, no password".to_string()),
                WifiSecurity::Wep => (Status::Warning, "WEP, an old and weak kind".to_string()),
                WifiSecurity::Wpa => (Status::Info, "WPA".to_string()),
                WifiSecurity::Other(other) => (Status::Info, shown(other)),
            };
            let weak = status == Status::Warning;
            make(
                status,
                "Wi-Fi network",
                weak.then_some("Join only a network you know. Others on a weak or open network can see what you send."),
                vec![
                    detail("Network name", shown(ssid)),
                    detail("Security", label),
                    detail("Password", if *has_password { "Included, not shown" } else { "None" }),
                    detail("Hidden network", yes_no(*hidden_network)),
                ],
                Some("Scanning joins the network. Join only if you trust where the code came from."),
            )
        }
        Payload::Payment {
            kind,
            payee,
            amount,
        } => {
            let mut details = vec![detail("Type", *kind)];
            if let Some(payee) = payee {
                details.push(detail("Pay to", shown(payee)));
            }
            if let Some(amount) = amount {
                details.push(detail("Amount", shown(amount)));
            }
            make(
                Status::Info,
                "Payment request",
                Some(
                    "Pay only if you expected this. Check the name and amount in your payment app before you confirm.",
                ),
                details,
                None,
            )
        }
        Payload::TwoFactor {
            kind,
            account,
            issuer,
        } => {
            let mut details = vec![detail("Type", shown(kind))];
            if let Some(issuer) = issuer {
                details.push(detail("Service", shown(issuer)));
            }
            if let Some(account) = account {
                details.push(detail("Account", shown(account)));
            }
            details.push(detail("Secret", "Included, not shown"));
            make(
                Status::Warning,
                "Two-factor setup code",
                Some(
                    "Do not scan this unless you are setting up that account yourself. Anyone with it can make your sign-in codes.",
                ),
                details,
                None,
            )
        }
        Payload::Phone(number) => make(
            Status::Info,
            "Phone number",
            None,
            vec![detail("Number", shown(number))],
            Some("Scanning may start a call."),
        ),
        Payload::Sms { number, has_body } => make(
            Status::Info,
            "Text message",
            None,
            vec![
                detail("Number", shown(number)),
                detail("Message included", yes_no(*has_body)),
            ],
            Some("Check the number before you send anything."),
        ),
        Payload::Email { address, has_body } => make(
            Status::Info,
            "Email",
            None,
            vec![
                detail("Address", shown(address)),
                detail("Message included", yes_no(*has_body)),
            ],
            None,
        ),
        Payload::Contact => make(
            Status::Info,
            "Contact details",
            None,
            Vec::new(),
            Some("Saving it adds a contact to your device."),
        ),
        Payload::Location => make(Status::Info, "Map location", None, Vec::new(), None),
        Payload::Text(text) => make(
            Status::Info,
            "Text only",
            None,
            vec![detail("Text", shown(text))],
            Some("This code holds no link."),
        ),
    };

    // A genuine code rarely needs text that cannot be seen, so it is called out.
    if hidden {
        if finding.status > Status::Warning {
            finding.status = Status::Warning;
        }
        let warning = "The text had hidden characters. A genuine code rarely needs them.";
        finding.note = Some(match finding.note.take() {
            Some(note) => format!("{note} {warning}"),
            None => warning.to_string(),
        });
    }
    finding
}

// The overall result for a code that is not a web link. A link uses the URL Checker's own.
pub fn verdict(payload: &Payload, header: &Finding) -> Verdict {
    let headline = match payload {
        Payload::Link(_) => "This code holds a web link",
        Payload::AppLink(_) => "This code opens another app",
        Payload::Script(_) => "This code runs content directly",
        Payload::Wifi { .. } => "This code shares a Wi-Fi network",
        Payload::Payment { .. } => "This code is a payment request",
        Payload::TwoFactor { .. } => "This code holds a two-factor secret",
        Payload::Phone(_) => "This code holds a phone number",
        Payload::Sms { .. } => "This code holds a text message",
        Payload::Email { .. } => "This code holds an email",
        Payload::Contact => "This code holds contact details",
        Payload::Location => "This code holds a map location",
        Payload::Text(_) => "This code holds text, not a link",
    };
    Verdict {
        status: header.status,
        headline: headline.to_string(),
        detail: header
            .action
            .clone()
            .unwrap_or_else(|| "Tenax read it and opened nothing.".to_string()),
    }
}

// A code that is too long to read.
pub fn too_long(index: usize, total: usize) -> Finding {
    card(
        index + 1,
        total,
        Status::Limited,
        "Too long to read",
        Some("A genuine code is rarely this long. Do not scan it."),
        Vec::new(),
        None,
    )
}
