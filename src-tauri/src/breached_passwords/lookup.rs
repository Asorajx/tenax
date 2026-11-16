// Hashes the password and asks Have I Been Pwned about the start of the hash.
// Only the first 5 characters of the hash are sent. The password is never sent.

use std::time::{Duration, Instant};

use reqwest::Client;
use sha1::{Digest, Sha1};

use super::findings::count_for;
use crate::finding::Step;

const API: &str = "https://api.pwnedpasswords.com/range/";

// How long to wait for a reply before giving up.
const TIMEOUT: Duration = Duration::from_secs(10);

// How many characters of the hash are sent. The service expects exactly 5.
const PREFIX_LENGTH: usize = 5;

// The SHA-1 hash of the password as upper-case hex, which is how the service lists hashes.
pub fn sha1_hex(password: &str) -> String {
    Sha1::digest(password.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

// Records one step as it happens: what Tenax did, how, how it went and how long it took.
fn step(
    action: &str,
    plain: &str,
    method: &str,
    result: String,
    ok: bool,
    started: Instant,
) -> Step {
    Step {
        action: action.to_string(),
        plain: plain.to_string(),
        method: method.to_string(),
        ok,
        result,
        ms: started.elapsed().as_secs_f64() * 1000.0,
        redact: None,
    }
}

// Asks the service for every hash that starts with the prefix.
async fn fetch(prefix: &str) -> Result<String, reqwest::Error> {
    Client::builder()
        .timeout(TIMEOUT)
        .user_agent("Tenax")
        .build()?
        .get(format!("{API}{prefix}"))
        // Pads the reply with fake entries, so its size does not hint at the real matches.
        .header("Add-Padding", "true")
        .send()
        .await?
        .error_for_status()?
        .text()
        .await
}

// Ok(Some(count)) means the password was found in that many breaches. Ok(None) means it was
// not in the list. Err means the lookup failed, which is never reported as "not found".
pub async fn run(password: &str) -> (Result<Option<u64>, String>, Vec<Step>) {
    let mut steps = Vec::new();

    let started = Instant::now();
    let hash = sha1_hex(password);
    let (prefix, suffix) = hash.split_at(PREFIX_LENGTH);
    // The prefix is hidden when the log is copied, since the log may be shared.
    let mark = |mut step: Step| {
        step.redact = Some(prefix.to_string());
        step
    };
    steps.push(mark(step(
        "Hashed the password on this PC",
        "Turned the password into a fingerprint on this PC. The password itself is never sent",
        "SHA-1 (sha1 crate), computed in memory",
        format!(
            "Hash created locally · Sent: {prefix} (first {PREFIX_LENGTH} characters of the hash) · \
             Kept on this PC: the remaining {} characters · Password: never transmitted",
            suffix.len()
        ),
        true,
        started,
    )));

    let started = Instant::now();
    let method = format!("HTTPS GET {API}{prefix} with Add-Padding: true");
    let body = match fetch(prefix).await {
        Ok(body) => body,
        Err(error) => {
            // The web address is left out of the message, because the prefix is shown on its own.
            let error = error.without_url();
            steps.push(mark(step(
                "Asked Have I Been Pwned for matching hashes",
                "Asked Have I Been Pwned for fingerprints that start the same way",
                &method,
                format!("Failed: {error}"),
                false,
                started,
            )));
            return (Err(error.to_string()), steps);
        }
    };
    steps.push(mark(step(
        "Asked Have I Been Pwned for matching hashes",
        "Asked Have I Been Pwned for fingerprints that start the same way",
        &method,
        format!("{} hashes returned", body.lines().count()),
        true,
        started,
    )));

    let started = Instant::now();
    let count = count_for(&body, suffix);
    steps.push(step(
        "Compared the returned hashes on this PC",
        "Looked through the list on this PC for the rest of the fingerprint",
        "Matched the remaining 35 characters of the hash against the list, locally",
        if count.is_some() {
            "Match found"
        } else {
            "No match"
        }
        .to_string(),
        true,
        started,
    ));

    (Ok(count), steps)
}

// =========================
// Tests
// =========================

#[cfg(test)]
mod tests {
    use super::*;

    // Makes a real request, sending only the prefix 5BAA6 of the hash of "password".
    // Run with: cargo test -- --ignored --nocapture
    #[test]
    #[ignore]
    fn prints_a_real_lookup() {
        let (outcome, steps) = tauri::async_runtime::block_on(run("password"));
        for step in &steps {
            println!(
                "{} | {} | {} | {:.0} ms",
                step.action, step.method, step.result, step.ms
            );
        }
        println!("{outcome:?}");
        assert!(matches!(outcome, Ok(Some(count)) if count > 0));
    }
}
