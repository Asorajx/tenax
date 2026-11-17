// Works out what a QR code contains, from the text that was read out of it.
//
// That text comes from an image that anyone could have made, so it is only ever read. It is never
// opened, followed or run, and nothing in this file touches the network or the system.

use url::Url;

// A longer text than this is not read.
pub const MAX_LENGTH: usize = 4096;

#[derive(Debug, PartialEq)]
pub enum WifiSecurity {
    Open,
    Wep,
    Wpa,
    Other(String),
}

#[derive(Debug, PartialEq)]
pub enum Payload {
    // A web address, with the scheme left off if the code left it off.
    Link(String),
    // Opens another app, such as WhatsApp. Tenax cannot check these.
    AppLink(String),
    // Content that runs or loads directly, such as javascript: or data:.
    Script(String),
    Wifi {
        ssid: String,
        security: WifiSecurity,
        hidden: bool,
        has_password: bool,
    },
    Payment {
        kind: &'static str,
        payee: Option<String>,
        amount: Option<String>,
    },
    // The secret that makes sign-in codes. Only the label is kept, never the secret.
    TwoFactor {
        kind: String,
        account: Option<String>,
        issuer: Option<String>,
    },
    Phone(String),
    Sms {
        number: String,
        has_body: bool,
    },
    Email {
        address: String,
        has_body: bool,
    },
    Contact,
    Location,
    Text(String),
}

// Takes out characters that cannot be seen but can change how text reads or looks: control
// characters, zero-width characters and the ones that reverse the direction of text. The second
// value says whether any were there.
pub fn clean(text: &str) -> (String, bool) {
    let hidden = |c: char| {
        c.is_control()
            || matches!(c,
                '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}')
    };
    // Line breaks and tabs are ordinary in text, so they are kept as spaces.
    let kept: String = text
        .chars()
        .filter(|c| !hidden(*c) || matches!(c, '\n' | '\r' | '\t'))
        .map(|c| {
            if matches!(c, '\n' | '\r' | '\t') {
                ' '
            } else {
                c
            }
        })
        .collect();
    let removed = text
        .chars()
        .any(|c| hidden(c) && !matches!(c, '\n' | '\r' | '\t'));
    (kept, removed)
}

// The scheme at the start of the text, such as "https" or "upi", in lower case.
fn scheme_of(text: &str) -> Option<String> {
    let end = text.find(':')?;
    let scheme = &text[..end];
    // One letter is a drive, such as C:, and not a scheme.
    let valid = (2..=20).contains(&scheme.len())
        && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'));
    valid.then(|| scheme.to_ascii_lowercase())
}

// Something like "example.com/login", with the scheme left off.
fn looks_like_address(text: &str) -> bool {
    if text.is_empty() || text.chars().any(|c| c.is_whitespace()) {
        return false;
    }
    let host = text.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    let Some((_, tld)) = host.rsplit_once('.') else {
        return false;
    };
    tld.len() >= 2
        && tld.chars().all(|c| c.is_ascii_alphabetic())
        && host.starts_with(|c: char| c.is_alphanumeric())
        && host
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-'))
}

// Splits on a separator, but not where a backslash escapes it. The backslashes stay for unescape.
fn split_unescaped(text: &str, separator: char) -> Vec<String> {
    let mut parts = vec![String::new()];
    let mut escaped = false;
    for c in text.chars() {
        let last = parts.last_mut().unwrap();
        if escaped {
            last.push(c);
            escaped = false;
        } else if c == '\\' {
            last.push(c);
            escaped = true;
        } else if c == separator {
            parts.push(String::new());
        } else {
            last.push(c);
        }
    }
    parts
}

fn unescape(text: &str) -> String {
    let mut out = String::new();
    let mut escaped = false;
    for c in text.chars() {
        if escaped || c != '\\' {
            out.push(c);
            escaped = false;
        } else {
            escaped = true;
        }
    }
    out
}

// WIFI:T:WPA;S:network name;P:password;H:false;;
fn wifi(body: &str) -> Payload {
    let mut ssid = String::new();
    let mut security = String::new();
    let mut has_password = false;
    let mut hidden = false;
    for field in split_unescaped(body, ';') {
        let Some((key, value)) = field.split_once(':') else {
            continue;
        };
        match key.trim().to_ascii_uppercase().as_str() {
            "S" => ssid = unescape(value),
            "T" => security = value.trim().to_ascii_uppercase(),
            // Only whether there is a password is kept, never the password itself.
            "P" => has_password = !value.is_empty(),
            "H" => hidden = value.trim().eq_ignore_ascii_case("true"),
            _ => {}
        }
    }
    let security = match security.as_str() {
        "" | "NOPASS" => WifiSecurity::Open,
        "WEP" => WifiSecurity::Wep,
        other if other.contains("WPA") || other == "SAE" => WifiSecurity::Wpa,
        other => WifiSecurity::Other(other.to_string()),
    };
    Payload::Wifi {
        ssid,
        security,
        hidden,
        has_password,
    }
}

// The value of one parameter in a query, such as "pa" in "pa=a@bank&am=10".
fn parameter(query: &str, name: &str) -> Option<String> {
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(key, value)| key.eq_ignore_ascii_case(name) && !value.is_empty())
        .map(|(_, value)| value.into_owned())
}

fn payment(scheme: &str, text: &str) -> Option<Payload> {
    let (body, query) = text.split_once('?').unwrap_or((text, ""));
    let body = body.split_once(':').map_or("", |(_, rest)| rest);
    let body = body.trim_start_matches('/');
    let currency = |kind: &'static str| {
        Some(Payload::Payment {
            kind,
            payee: Some(body.to_string()).filter(|address| !address.is_empty()),
            amount: parameter(query, "amount").or_else(|| parameter(query, "value")),
        })
    };
    match scheme {
        "upi" => Some(Payload::Payment {
            kind: "UPI payment request",
            payee: parameter(query, "pn").or_else(|| parameter(query, "pa")),
            amount: parameter(query, "am"),
        }),
        "bitcoin" => currency("Bitcoin payment request"),
        "bitcoincash" => currency("Bitcoin Cash payment request"),
        "litecoin" => currency("Litecoin payment request"),
        "ethereum" => currency("Ethereum payment request"),
        "monero" => currency("Monero payment request"),
        "dogecoin" => currency("Dogecoin payment request"),
        _ => None,
    }
}

// Turns %20 and the like back into the characters they stand for.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let pair = bytes
            .get(at + 1..at + 3)
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match (bytes[at], pair) {
            (b'%', Some(byte)) => {
                out.push(byte);
                at += 3;
            }
            (byte, _) => {
                out.push(byte);
                at += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// otpauth://totp/Issuer:account?secret=...&issuer=Issuer
fn two_factor(text: &str) -> Payload {
    let parsed = Url::parse(text).ok();
    let kind = parsed
        .as_ref()
        .and_then(|url| url.host_str().map(str::to_string))
        .unwrap_or_default();
    let label = parsed
        .as_ref()
        .map(|url| percent_decode(url.path().trim_start_matches('/')))
        .unwrap_or_default();
    let query = parsed
        .as_ref()
        .and_then(|url| url.query().map(str::to_string))
        .unwrap_or_default();
    let (label_issuer, account) = match label.split_once(':') {
        Some((issuer, account)) => (Some(issuer.to_string()), account.to_string()),
        None => (None, label),
    };
    Payload::TwoFactor {
        kind,
        account: Some(account).filter(|account| !account.is_empty()),
        issuer: parameter(&query, "issuer").or(label_issuer),
    }
}

// Up to the first character that ends a phone number or an address.
fn first_part(text: &str) -> String {
    text.split([':', '?', ';', ','])
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

// Whether an address part, such as "token" in ?token=abc, usually holds a password or a sign-in key.
fn is_secret_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "passwd",
        "pwd",
        "apikey",
        "api_key",
        "signature",
        "authorization",
        "bearer",
        "jwt",
        "session",
    ]
    .iter()
    .any(|word| name.contains(word))
        || matches!(
            name.as_str(),
            "auth" | "sig" | "sid" | "otp" | "passcode" | "pass"
        )
}

// The address with the values of secret-looking parts hidden, and whether any were. A password in
// the address, a value in ?query=... and one in #fragment=... are all covered. An address with
// nothing to hide is returned exactly as it was.
pub fn hide_secrets(address: &str) -> (String, bool) {
    let Ok(mut url) = Url::parse(address) else {
        return (address.to_string(), false);
    };
    let mut hidden = false;

    if url.password().is_some() {
        let _ = url.set_password(Some("hidden"));
        hidden = true;
    }

    let mask = |part: &str| -> Option<String> {
        let pairs: Vec<(String, String)> = url::form_urlencoded::parse(part.as_bytes())
            .into_owned()
            .collect();
        let secret = |name: &str, value: &str| is_secret_name(name) && !value.is_empty();
        if !pairs.iter().any(|(name, value)| secret(name, value)) {
            return None;
        }
        let mut out = url::form_urlencoded::Serializer::new(String::new());
        for (name, value) in &pairs {
            out.append_pair(name, if secret(name, value) { "hidden" } else { value });
        }
        Some(out.finish())
    };
    let query = url.query().and_then(mask);
    let fragment = url
        .fragment()
        .filter(|part| part.contains('='))
        .and_then(mask);
    if let Some(query) = query {
        url.set_query(Some(&query));
        hidden = true;
    }
    if let Some(fragment) = fragment {
        url.set_fragment(Some(&fragment));
        hidden = true;
    }

    if hidden {
        (url.to_string(), true)
    } else {
        (address.to_string(), false)
    }
}

pub fn classify(text: &str) -> Payload {
    let text = text.trim();
    let upper = text.to_ascii_uppercase();
    // Each prefix is plain text, so slicing after it cannot cut a character in half.
    let after = |prefix: &str| &text[prefix.len()..];

    if upper.starts_with("WIFI:") {
        return wifi(after("WIFI:"));
    }
    if upper.starts_with("BEGIN:VCARD") || upper.starts_with("MECARD:") {
        return Payload::Contact;
    }
    if upper.starts_with("GEO:") {
        return Payload::Location;
    }
    if upper.starts_with("TEL:") {
        return Payload::Phone(first_part(after("TEL:")));
    }
    if upper.starts_with("SMSTO:") || upper.starts_with("SMS:") {
        let rest = after(if upper.starts_with("SMSTO:") {
            "SMSTO:"
        } else {
            "SMS:"
        });
        let number = first_part(rest);
        let has_body = rest
            .split_once([':', '?', ';'])
            .is_some_and(|(_, tail)| !tail.trim().is_empty());
        return Payload::Sms { number, has_body };
    }
    if upper.starts_with("MAILTO:") {
        let rest = after("MAILTO:");
        return Payload::Email {
            address: rest.split('?').next().unwrap_or("").trim().to_string(),
            has_body: rest.contains('?'),
        };
    }
    if upper.starts_with("MATMSG:") {
        let rest = after("MATMSG:");
        let field = |name: &str| {
            split_unescaped(rest, ';')
                .into_iter()
                .find_map(|part| part.strip_prefix(name).map(unescape))
        };
        return Payload::Email {
            address: field("TO:").unwrap_or_default(),
            has_body: field("BODY:").is_some_and(|body| !body.is_empty()),
        };
    }
    if upper.starts_with("OTPAUTH:") {
        return two_factor(text);
    }
    // The bank and card QR standard (EMV) starts with these digits.
    if text.starts_with("000201")
        && text.len() >= 30
        && text.chars().all(|c| c.is_ascii_graphic() || c == ' ')
    {
        return Payload::Payment {
            kind: "Bank or card payment request",
            payee: None,
            amount: None,
        };
    }

    if upper.starts_with("HTTP://") || upper.starts_with("HTTPS://") {
        return Payload::Link(text.to_string());
    }
    if let Some(scheme) = scheme_of(text) {
        if let Some(found) = payment(&scheme, text) {
            return found;
        }
        if matches!(
            scheme.as_str(),
            "javascript" | "data" | "vbscript" | "file" | "blob"
        ) {
            return Payload::Script(scheme);
        }
        // A scheme followed by // opens another app. Without it, the colon is just punctuation.
        let known_apps = [
            "intent", "market", "whatsapp", "tg", "weixin", "skype", "zoommtg",
        ];
        if text[scheme.len() + 1..].starts_with("//") || known_apps.contains(&scheme.as_str()) {
            return Payload::AppLink(scheme);
        }
    }
    if looks_like_address(text) {
        return Payload::Link(text.to_string());
    }
    Payload::Text(text.to_string())
}
