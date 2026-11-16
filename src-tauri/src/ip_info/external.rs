// The optional external lookup. It sends the IP address to ipinfo.io and reads back who runs
// the network and roughly where it is. This is the only network code in IP Information besides
// the reverse DNS lookup, and it only runs when the user has confirmed it for one address.
//
// Nothing else is sent. No redirect is followed, so the address cannot be passed on to another
// host. What comes back is treated as untrusted text, so it is checked and shortened.

use std::net::IpAddr;
use std::time::Duration;

use reqwest::redirect::Policy;
use reqwest::{Client, StatusCode};
use serde_json::Value;

// The name shown to the user wherever the service is mentioned.
pub const SERVICE: &str = "ipinfo.io";

const API: &str = "https://ipinfo.io/";

// How long to wait for a reply before giving up.
const TIMEOUT: Duration = Duration::from_secs(10);

// A real reply is a few hundred bytes. Anything far larger is not one.
const MAX_REPLY: usize = 16 * 1024;

// The longest any one value is shown.
const MAX_SHOWN: usize = 100;

// What the service reported. Every value is optional, because a service may not know them.
#[derive(Debug, Default, PartialEq)]
pub struct Owner {
    // For example "AS15169".
    pub asn: Option<String>,
    // For example "Google LLC".
    pub organisation: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    // A two-letter code, such as "US".
    pub country: Option<String>,
    pub timezone: Option<String>,
    // The service says the address is not a public one.
    pub not_public: bool,
}

// The web address the lookup is sent to. It is shown in the log, so the user can see it.
pub fn url_for(ip: IpAddr) -> String {
    format!("{API}{ip}/json")
}

// Text from outside with anything unprintable removed and the length capped. That includes
// the characters that flip the direction of text, which can make one name look like another.
pub fn printable(text: &str, max: usize) -> String {
    text.chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(
                    c,
                    '\u{200b}'..='\u{200f}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{feff}'
                )
        })
        .take(max)
        .collect()
}

// A value from the reply, cleaned and shortened.
fn text(object: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    let value = printable(object.get(key)?.as_str()?, MAX_SHOWN);
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

// The service writes the network as "AS15169 Google LLC". The number is split from the name.
fn split_network(org: String) -> (Option<String>, Option<String>) {
    if let Some((first, rest)) = org.split_once(' ')
        && first.len() > 2
        && first.starts_with("AS")
        && first[2..].chars().all(|c| c.is_ascii_digit())
    {
        let name = rest.trim();
        return (
            Some(first.to_string()),
            (!name.is_empty()).then(|| name.to_string()),
        );
    }
    (None, Some(org))
}

// Reads the service's reply. It must be about the address that was asked about.
pub fn parse(ip: IpAddr, body: &str) -> Result<Owner, String> {
    let unreadable = || format!("{SERVICE} sent a reply Tenax could not read.");

    let value: Value = serde_json::from_str(body).map_err(|_| unreadable())?;
    let object = value.as_object().ok_or_else(unreadable)?;

    let echoed = text(object, "ip")
        .and_then(|echoed| echoed.parse::<IpAddr>().ok())
        .ok_or_else(unreadable)?;
    if echoed.to_canonical() != ip {
        return Err(format!("{SERVICE} answered about a different address."));
    }

    if object.get("bogon").and_then(Value::as_bool) == Some(true) {
        return Ok(Owner {
            not_public: true,
            ..Owner::default()
        });
    }

    let (asn, organisation) = match text(object, "org") {
        Some(org) => split_network(org),
        None => (None, None),
    };
    Ok(Owner {
        asn,
        organisation,
        city: text(object, "city"),
        region: text(object, "region"),
        country: text(object, "country"),
        timezone: text(object, "timezone"),
        not_public: false,
    })
}

// Sends the address and reads the reply. A failure comes back as a sentence for the user, with
// no web address in it, since the address would be repeated there.
pub async fn fetch(ip: IpAddr) -> Result<Owner, String> {
    let client = Client::builder()
        .timeout(TIMEOUT)
        .user_agent("Tenax")
        .redirect(Policy::none())
        .build()
        .map_err(|_| format!("Tenax could not prepare the request to {SERVICE}."))?;

    let response = client
        .get(url_for(ip))
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|error| {
            if error.is_timeout() {
                format!("{SERVICE} did not answer in time.")
            } else if error.is_connect() {
                format!("Tenax could not reach {SERVICE}. Check the internet connection.")
            } else {
                format!("The request to {SERVICE} failed.")
            }
        })?;

    let status = response.status();
    if status == StatusCode::TOO_MANY_REQUESTS {
        return Err(format!(
            "{SERVICE} is limiting requests right now. Try again later."
        ));
    }
    if !status.is_success() {
        return Err(format!(
            "{SERVICE} answered with an error (HTTP {}).",
            status.as_u16()
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length as usize > MAX_REPLY)
    {
        return Err(format!("{SERVICE} sent a reply that was too large."));
    }

    let body = response
        .text()
        .await
        .map_err(|_| format!("The reply from {SERVICE} was cut off."))?;
    if body.len() > MAX_REPLY {
        return Err(format!("{SERVICE} sent a reply that was too large."));
    }
    parse(ip, &body)
}
