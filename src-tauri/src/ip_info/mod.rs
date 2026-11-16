// IP Information: explains what kind of address an IP address is, and offers two optional
// lookups. The three sources are kept apart, so the user always knows where something came from:
//
//   This PC          the kind of address, worked out locally. Nothing is sent. This is the default.
//   This PC's DNS    the name the address points back to (reverse DNS), asked through Windows'
//                    DNS client, so it follows the same settings as a browser, a VPN or a workplace.
//   ipinfo.io        the owner, network and approximate location, from an external service.
//
// A lookup only runs when the user asks for it, and the external one only after the user has
// confirmed that the address will be sent to ipinfo.io. Each command checks the address again,
// so the interface cannot ask for a lookup that makes no sense, such as sending a private
// address to an outside service.
//
// address.rs   reads and classifies addresses, with no network code
// external.rs  the ipinfo.io request, the only web request
// findings.rs  turns what was found into cards, with no network or Windows code

pub(crate) mod address;
mod countries;
pub(crate) mod external;
mod findings;

#[cfg(test)]
mod tests;

use std::net::IpAddr;
use std::time::Instant;

use serde::Serialize;

use crate::dns_lookup::records::{Answer, Kind, Resolver};
use crate::finding::{Finding, Verdict};
use address::{Scope, classify, parse, reverse_name};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpReport {
    // The address as Tenax read it, which the interface sends back for the optional lookups.
    pub address: String,
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
    // Whether each optional lookup makes sense for this kind of address.
    pub can_reverse: bool,
    pub can_external: bool,
}

// Reads the address and says what kind it is. This never touches the network.
fn inspect(input: &str) -> Result<IpReport, String> {
    let started = Instant::now();
    let (ip, mapped) = parse(input)?;
    let scope = classify(ip).scope;
    let (verdict, finding) = findings::address(ip, mapped, started);

    Ok(IpReport {
        address: ip.to_string(),
        verdict,
        findings: vec![finding],
        can_reverse: scope.reverse_dns(),
        can_external: scope.external(),
    })
}

// Asks for the name an address points back to.
fn reverse(resolver: &dyn Resolver, ip: IpAddr) -> Finding {
    let started = Instant::now();
    let question = reverse_name(ip);
    let answer: Answer = resolver.query(&question, Kind::Ptr);
    findings::reverse(&question, &answer, started)
}

// The address the interface sent back, read again and checked against the lookup it wants.
fn checked(input: &str, allowed: fn(Scope) -> bool, refusal: &str) -> Result<IpAddr, String> {
    let (ip, _) = parse(input)?;
    if allowed(classify(ip).scope) {
        Ok(ip)
    } else {
        Err(refusal.to_string())
    }
}

// Called from the interface with invoke("inspect_ip", { address }). It sends nothing anywhere.
#[tauri::command]
pub fn inspect_ip(address: String) -> Result<IpReport, String> {
    inspect(&address)
}

// Called from the interface with invoke("reverse_dns", { address }), only when asked for.
// The address is sent to the DNS server this PC already uses. It runs on a worker thread,
// since Windows can take several seconds when a DNS server is slow.
#[cfg(windows)]
#[tauri::command]
pub async fn reverse_dns(address: String) -> Result<Finding, String> {
    let ip = checked(
        &address,
        Scope::reverse_dns,
        "This kind of address has no name worth asking for.",
    )?;
    tauri::async_runtime::spawn_blocking(move || {
        reverse(&crate::dns_lookup::resolver::WindowsDns, ip)
    })
    .await
    // A failure here is turned into a plain message, so the address is not repeated in it.
    .map_err(|_| "Tenax could not ask for this address's name.".to_string())
}

#[cfg(not(windows))]
#[tauri::command]
pub async fn reverse_dns(_address: String) -> Result<Finding, String> {
    Err("This lookup only runs on Windows.".to_string())
}

// Called from the interface with invoke("lookup_ip_owner", { address }), and only after the user
// has confirmed that the address will be sent to ipinfo.io. Only public addresses are accepted.
#[tauri::command]
pub async fn lookup_ip_owner(address: String) -> Result<Finding, String> {
    let ip = checked(
        &address,
        Scope::external,
        "Only public addresses can be looked up with an external service.",
    )?;
    let started = Instant::now();
    let outcome = external::fetch(ip).await;
    Ok(findings::owner(ip, &outcome, started))
}
