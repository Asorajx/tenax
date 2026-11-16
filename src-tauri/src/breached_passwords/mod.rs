// Breached Passwords check: finds out whether a password appears in known data breaches.
//
// The password is hashed on this PC. Only the first 5 characters of the hash are sent to
// Have I Been Pwned, which returns every hash that starts the same way. The rest of the
// hash is compared here, so the password and its full hash never leave this PC.
//
// lookup.rs   hashes the password and talks to Have I Been Pwned
// findings.rs turns the outcome into a finding, with no network code in it

mod findings;
mod lookup;

use crate::finding::Finding;

// Called from the interface with invoke("check_breached_password", { password }).
// The password only travels from the window to this function on this PC.
#[tauri::command]
pub async fn check_breached_password(password: String) -> Result<Vec<Finding>, String> {
    // The lookup goes to Have I Been Pwned, so it only runs while network access is on, and is
    // dropped if the switch is turned off while it is waiting.
    crate::network::require()?;
    let (outcome, steps) = crate::network::run(lookup::run(&password)).await?;

    let mut finding = findings::build(&outcome);
    // The finding carries the steps that produced it.
    finding.steps = steps;
    Ok(vec![finding])
}
