// Decides what Tenax is willing to connect to. Only public hosts on the standard secure web
// port are allowed, so the tool cannot be used to probe a private network or this PC.
// There is no network code here, so every rule can be tested.

use std::net::IpAddr;

use url::Url;

use crate::dns_lookup::normalise;
use crate::ip_info::address::{self, Scope, classify};

// The only port Tenax connects to.
pub const PORT: u16 = 443;

// A longer paste than this is not a host name.
const MAX_INPUT: usize = 2048;

// What to connect to. `host` is the name as it is checked against the certificate, which is a
// domain name in its ASCII form, or an IP address written out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    // Set when an IP address was entered, so no name has to be looked up.
    pub ip: Option<IpAddr>,
}

// Splits "host:port" and removes anything around it. The port is returned when one was given.
fn split(input: &str) -> Result<(String, Option<u16>), String> {
    if input.contains("://") {
        let url = Url::parse(input)
            .map_err(|_| "That is not a web address Tenax can read.".to_string())?;
        let host = url
            .host_str()
            .ok_or_else(|| "That is not a web address Tenax can read.".to_string())?
            .to_string();
        return Ok((host, url.port()));
    }

    // Anything after the name, such as a path, is left off.
    let site = input.split(['/', '?', '#']).next().unwrap_or("");
    let site = site.rsplit('@').next().unwrap_or(site);
    if let Some(rest) = site.strip_prefix('[') {
        // "[2001:db8::1]" or "[2001:db8::1]:443"
        return match rest.split_once(']') {
            Some((inside, "")) => Ok((inside.to_string(), None)),
            Some((inside, after)) => match after.strip_prefix(':').map(str::parse::<u16>) {
                Some(Ok(port)) => Ok((inside.to_string(), Some(port))),
                _ => Err("That is not a valid host name.".to_string()),
            },
            None => Err("That is not a valid host name.".to_string()),
        };
    }
    match site.rsplit_once(':') {
        // One colon with digits after it is a port. More than one colon is an IPv6 address.
        Some((name, port))
            if !name.contains(':')
                && !port.is_empty()
                && port.chars().all(|c| c.is_ascii_digit()) =>
        {
            port.parse::<u16>()
                .map(|port| (name.to_string(), Some(port)))
                .map_err(|_| "That port is not valid.".to_string())
        }
        _ => Ok((site.to_string(), None)),
    }
}

// Turns what was typed into a target, or says why it cannot be used.
pub fn parse(input: &str) -> Result<Target, String> {
    let text = input.trim();
    if text.is_empty() {
        return Err("Enter a host name to check, such as example.com.".to_string());
    }
    if text.len() > MAX_INPUT {
        return Err("That is too long to be a host name.".to_string());
    }
    if text.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("A host name has no spaces. Enter one name at a time.".to_string());
    }

    let (host, port) = split(text)?;
    if port.is_some_and(|port| port != PORT) {
        return Err(format!(
            "Tenax only checks certificates on port {PORT}, the standard secure web port."
        ));
    }

    // An IP address is checked as it is. Anything else must be a domain name.
    if let Ok((ip, _)) = address::parse(&host) {
        return Ok(Target {
            host: ip.to_string(),
            ip: Some(ip),
        });
    }
    let name = normalise(&host)?;
    Ok(Target {
        host: name,
        ip: None,
    })
}

// Whether an address is one Tenax may connect to. Only ordinary public addresses pass, and
// not the tunnelling ranges that can carry a private address inside a public-looking one.
pub fn is_public(ip: IpAddr) -> bool {
    let class = classify(ip);
    class.scope == Scope::Internet
        && matches!(class.kind, "Public address" | "Global unicast address")
}

// Checks every address a name led to. If even one is not public the whole name is refused, so a
// name that mixes public and private addresses cannot be used to reach a private one.
pub fn check_addresses(host: &str, addresses: &[IpAddr]) -> Result<(), String> {
    if addresses.is_empty() {
        return Err("No address was found for that name.".to_string());
    }
    match addresses.iter().find(|ip| !is_public(**ip)) {
        None => Ok(()),
        Some(ip) if host.parse::<IpAddr>().is_ok() => Err(format!(
            "{ip} is not a public address, so Tenax will not connect to it."
        )),
        Some(ip) => Err(format!(
            "{host} points to {ip}, which is not a public address, so Tenax will not connect to it."
        )),
    }
}
