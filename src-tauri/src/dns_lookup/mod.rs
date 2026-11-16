// DNS Lookup: asks DNS about a domain and explains what comes back.
//
// Unlike Tenax's other checks, this one uses the network. It sends the domain name to the DNS
// server this PC already uses, through Windows' own DNS client, so it follows the same settings
// as a browser does, including a VPN's or a workplace's DNS. Tenax does not choose a DNS server
// and never contacts a public one. A DNS server may pass the question on to others, as it does
// for any website visited.
//
// It only runs when the user asks for a lookup. Nothing starts it automatically.
//
// records.rs   the plain types for answers, and the Resolver that asks
// resolver.rs  Windows' DNS client, the only Windows and unsafe code
// findings.rs  turns answers into cards, with no Windows or network code in it

mod findings;
// records and resolver are also used by IP Information, for reverse lookups.
pub(crate) mod records;
#[cfg(windows)]
pub(crate) mod resolver;

#[cfg(test)]
mod tests;

use std::net::IpAddr;
use std::time::Instant;

use serde::Serialize;
use url::Url;

use crate::finding::{Finding, Step, Verdict};
use findings::Lookup;
use records::{Failure, Kind, Resolver};

// A longer paste than this is not a domain name.
const MAX_INPUT: usize = 2048;
// The limits DNS puts on a name and on each part of it.
const MAX_NAME: usize = 253;
const MAX_LABEL: usize = 63;

#[derive(Serialize)]
pub struct DnsReport {
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
}

// =========================
// The name
// =========================

// Turns what was typed into the name to ask about. A pasted web address gives its site name,
// and an international name is written the way DNS needs it.
fn normalise(input: &str) -> Result<String, String> {
    let text = input.trim();
    if text.is_empty() {
        return Err("Enter a domain name to look up.".to_string());
    }
    if text.len() > MAX_INPUT {
        return Err("That is too long to be a domain name.".to_string());
    }
    if text.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("A domain name has no spaces. Enter one name at a time.".to_string());
    }

    let host = if text.contains("://") {
        Url::parse(text)
            .ok()
            .and_then(|url| url.host_str().map(str::to_string))
            .ok_or_else(|| "That is not a web address Tenax can read.".to_string())?
    } else {
        // Anything after the name, such as a path or a port, is left off.
        let site = text.split(['/', '?', '#']).next().unwrap_or("");
        let site = site.rsplit('@').next().unwrap_or(site);
        match site.rsplit_once(':') {
            Some((name, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
                name
            }
            _ => site,
        }
        .to_string()
    };

    let host = host
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_lowercase();
    if host.parse::<IpAddr>().is_ok() {
        return Err("That is an IP address. DNS Lookup needs a domain name.".to_string());
    }
    let name =
        idna::domain_to_ascii(&host).map_err(|_| "That is not a valid domain name.".to_string())?;

    if !name.contains('.') {
        return Err("Enter a full domain name, such as example.com.".to_string());
    }
    let valid_part = |label: &str| {
        !label.is_empty()
            && label.len() <= MAX_LABEL
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    };
    if name.len() > MAX_NAME || !name.split('.').all(valid_part) {
        return Err("That is not a valid domain name.".to_string());
    }
    Ok(name)
}

// =========================
// Asking
// =========================

// Asks the questions, in a fixed order, and only about this domain. If the domain does not
// exist, or no DNS server answers, the rest would get the same answer, so they are not asked.
fn ask(resolver: &dyn Resolver, name: &str) -> Lookup {
    let a = resolver.query(name, Kind::A);

    let stop = match &a {
        Err(Failure::NoSuchDomain) => Some(Failure::NoSuchDomain),
        Err(failure) if failure.is_unreachable() => Some(failure.clone()),
        _ => None,
    };
    if let Some(reason) = stop {
        let same = || Err(reason.clone());
        return Lookup {
            a,
            aaaa: same(),
            mx: same(),
            ns: same(),
            txt: same(),
            soa: same(),
            dmarc: same(),
        };
    }

    Lookup {
        a,
        aaaa: resolver.query(name, Kind::Aaaa),
        mx: resolver.query(name, Kind::Mx),
        ns: resolver.query(name, Kind::Ns),
        txt: resolver.query(name, Kind::Txt),
        soa: resolver.query(name, Kind::Soa),
        dmarc: resolver.query(&format!("_dmarc.{name}"), Kind::Txt),
    }
}

fn run(resolver: &dyn Resolver, input: &str) -> Result<DnsReport, String> {
    let started = Instant::now();
    let name = normalise(input)?;

    let lookup = ask(resolver, &name);
    let (verdict, mut findings) = findings::build(&lookup);

    // The first card leads with what was done to the name before it was sent.
    findings[0].steps.insert(
        0,
        Step::new(
            "Prepared the domain name",
            "Cleaned up the name you entered before asking about it",
            "Lower-cased, took the site name out of a pasted web address, wrote international names in their ASCII form and checked the length and characters",
            "Ready to ask".to_string(),
            started,
        ),
    );
    Ok(DnsReport { verdict, findings })
}

// Called from the interface with invoke("lookup_dns", { domain }).
// The domain name is sent to this PC's DNS server. It runs on a worker thread, since Windows can
// take several seconds when a DNS server is slow, and it never runs without being asked.
#[cfg(windows)]
#[tauri::command]
pub async fn lookup_dns(domain: String) -> Result<DnsReport, String> {
    // The name is checked first, so a typo is refused without asking anyone anything.
    normalise(&domain)?;
    tauri::async_runtime::spawn_blocking(move || run(&resolver::WindowsDns, &domain))
        .await
        // A failure here is turned into a plain message, so the domain is not repeated in it.
        .map_err(|_| "Tenax could not look this domain up.".to_string())?
}

#[cfg(not(windows))]
#[tauri::command]
pub async fn lookup_dns(_domain: String) -> Result<DnsReport, String> {
    Err("This lookup only runs on Windows.".to_string())
}
