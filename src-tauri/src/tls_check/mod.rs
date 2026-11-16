// TLS Certificate: connects to a server, reads the certificate it presents and explains it.
//
// Unlike Tenax's offline checks, this one connects to the server the user enters, on port 443.
// It makes a TLS handshake and nothing more: no web request is sent, nothing is downloaded and
// no redirect is followed, because the connection is closed once the certificate has been read.
// The server can see this PC's internet address, as any website can. No other service is contacted.
//
// Windows decides whether the certificate is trusted, through its own secure channel (Schannel),
// so it follows the same trusted authorities as a browser, including a workplace's. If Windows
// refuses the certificate, a second handshake that checks nothing is made only to read it, so the
// problem can be explained. A certificate read that way is never treated as trusted.
//
// Only public hosts are allowed. A name is looked up first, and if any address it leads to is
// private, loopback or otherwise not public, nothing is connected to.
//
// target.rs    what may be connected to, with no network code
// session.rs   the handshake, the only network code
// cert.rs      reads a certificate into plain values
// problems.rs  works out what is wrong with a certificate Windows refused
// findings.rs  turns it all into cards, with no network code in it

mod cert;
mod findings;
mod problems;
mod session;
mod target;

#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod tests;

use std::net::{IpAddr, SocketAddr};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::finding::{Finding, Step, Verdict};
use findings::{Failed, Outcome};
use problems::Trust;
use session::{Der, Failure, Stage};
use target::PORT;

// How many of a name's addresses are tried before giving up on reaching it.
const MAX_ADDRESSES: usize = 2;

#[derive(Serialize)]
pub struct TlsReport {
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
}

// What is needed from the outside: looking a name up, and making a handshake. Windows does both
// for real. The tests use a fake one.
pub trait Transport {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String>;
    // With `verify` on, Windows checks the certificate and refuses one it does not trust. With it
    // off, the certificate is only read.
    fn handshake(&self, addr: SocketAddr, host: &str, verify: bool) -> Result<Der, Failure>;
}

#[cfg(windows)]
struct Windows;

#[cfg(windows)]
impl Transport for Windows {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        use std::net::ToSocketAddrs;
        (host, PORT)
            .to_socket_addrs()
            .map(|found| found.map(|addr| addr.ip()).collect())
            .map_err(|error| error.to_string())
    }

    fn handshake(&self, addr: SocketAddr, host: &str, verify: bool) -> Result<Der, Failure> {
        session::handshake(addr, host, verify)
    }
}

fn failed_step(action: &str, plain: &str, method: &str, result: String, started: Instant) -> Step {
    Step {
        ok: false,
        ..Step::new(action, plain, method, result, started)
    }
}

// Runs the whole check. `now` is the time in unix seconds the certificate is judged against.
// An Err is a refusal before anything was connected to, such as a private address.
fn run(transport: &dyn Transport, input: &str, now: i64) -> Result<TlsReport, String> {
    let mut steps = Vec::new();

    let started = Instant::now();
    let target = target::parse(input)?;
    steps.push(Step::new(
        "Prepared the host name",
        "Cleaned up what you entered before connecting",
        "Took the host out of a pasted web address, wrote international names in their ASCII form, checked the port is 443 and checked the name",
        format!("Checking {}", target.host),
        started,
    ));

    // Looking the name up. An address that was typed needs no lookup.
    let started = Instant::now();
    let mut addresses = match target.ip {
        Some(ip) => vec![ip],
        None => match transport.resolve(&target.host) {
            Ok(found) => found,
            Err(text) => {
                steps.push(failed_step(
                    "Looked up the server's address",
                    "Asked this PC for the address behind the name",
                    "Windows name lookup (getaddrinfo), the same one a browser uses",
                    "The name could not be found".to_string(),
                    started,
                ));
                let outcome = Outcome::Failed(Failed::NotFound { text });
                return Ok(finish(&target.host, None, &outcome, now, steps));
            }
        },
    };
    addresses.dedup();
    if target.ip.is_none() {
        steps.push(Step::new(
            "Looked up the server's address",
            "Asked this PC for the address behind the name",
            "Windows name lookup (getaddrinfo), the same one a browser uses",
            format!(
                "{} found",
                crate::finding::count_of(addresses.len(), "address")
            ),
            started,
        ));
    }

    // Every address must be public, including the ones a name led to.
    let started = Instant::now();
    target::check_addresses(&target.host, &addresses)?;
    steps.push(Step::new(
        "Checked the addresses are public",
        "Made sure the server is on the public internet, and not on a private network or this PC",
        "Checked every address against the private, loopback, link-local and reserved ranges",
        "All public".to_string(),
        started,
    ));

    // The first handshake lets Windows check the certificate. It moves on to the next address
    // only when a server cannot be reached at all.
    let started = Instant::now();
    let method = "TLS handshake through Windows (Schannel), certificate checked against the Windows trust store, port 443, no web request";
    let mut unreachable = None;
    let mut reached = None;
    for ip in addresses.iter().take(MAX_ADDRESSES) {
        let addr = SocketAddr::new(*ip, PORT);
        match transport.handshake(addr, &target.host, true) {
            Err(failure) if failure.stage == Stage::Connect => unreachable = Some((*ip, failure)),
            result => {
                reached = Some((addr, result));
                break;
            }
        }
    }

    let (addr, strict) = match reached {
        Some(reached) => reached,
        None => {
            let (ip, failure) = unreachable.expect("at least one address was tried");
            steps.push(failed_step(
                "Connected to the server",
                "Tried to reach the server",
                method,
                failure.text.clone(),
                started,
            ));
            let outcome = Outcome::Failed(Failed::Unreachable {
                code: failure.code,
                text: failure.text,
            });
            return Ok(finish(&target.host, Some(ip), &outcome, now, steps));
        }
    };
    let address = Some(addr.ip());

    let outcome = match strict {
        Ok(der) => {
            steps.push(Step::new(
                "Asked Windows to check the certificate",
                "Connected to the server and let Windows decide whether to trust its certificate",
                method,
                "Windows accepted the certificate".to_string(),
                started,
            ));
            Outcome::Reached {
                trust: Trust::Trusted,
                cert: cert::read(&der),
            }
        }
        Err(refused) => {
            steps.push(failed_step(
                "Asked Windows to check the certificate",
                "Connected to the server and let Windows decide whether to trust its certificate",
                method,
                refused.text.clone(),
                started,
            ));

            // A second handshake that checks nothing, only to read what the server presented.
            let started = Instant::now();
            let method = "TLS handshake through Windows (Schannel) with certificate checks switched off, port 443, no web request. Used only to read the certificate";
            match transport.handshake(addr, &target.host, false) {
                Ok(der) => {
                    steps.push(Step::new(
                        "Read the certificate without trusting it",
                        "Connected again only to read the certificate, so the problem can be explained. It is still not trusted",
                        method,
                        "Certificate read".to_string(),
                        started,
                    ));
                    Outcome::Reached {
                        trust: Trust::NotTrusted {
                            code: refused.code,
                            text: refused.text,
                        },
                        cert: cert::read(&der),
                    }
                }
                Err(_) => {
                    steps.push(failed_step(
                        "Read the certificate without trusting it",
                        "Connected again only to read the certificate",
                        method,
                        "No certificate could be read".to_string(),
                        started,
                    ));
                    Outcome::Failed(Failed::Handshake {
                        code: refused.code,
                        text: refused.text,
                    })
                }
            }
        }
    };

    Ok(finish(&target.host, address, &outcome, now, steps))
}

// Builds the report and gives the first card the steps for the whole check.
fn finish(
    host: &str,
    address: Option<IpAddr>,
    outcome: &Outcome,
    now: i64,
    steps: Vec<Step>,
) -> TlsReport {
    let (verdict, mut findings) = findings::build(host, address, outcome, now);
    if let Some(first) = findings.first_mut() {
        first.steps = steps;
    }
    TlsReport { verdict, findings }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

// Called from the interface with invoke("check_tls", { host }).
// It connects to the host, only when asked. It runs on a worker thread, since a slow server can
// take several seconds, and it refuses private addresses before anything is connected to.
#[cfg(windows)]
#[tauri::command]
pub async fn check_tls(host: String) -> Result<TlsReport, String> {
    // A name that cannot be used is refused first, without a thread or a lookup.
    target::parse(&host)?;
    tauri::async_runtime::spawn_blocking(move || run(&Windows, &host, unix_now()))
        .await
        // A failure here is turned into a plain message, so the host is not repeated in it.
        .map_err(|_| "Tenax could not check this certificate.".to_string())?
}

#[cfg(not(windows))]
#[tauri::command]
pub async fn check_tls(_host: String) -> Result<TlsReport, String> {
    Err("This check only runs on Windows.".to_string())
}
