// Turns the outcome of the lookup into a finding.
// There is no network code here, so every case can be tested with made-up replies.

use crate::finding::{Finding, Status, detail};

// Looks for one hash ending in a list of "SUFFIX:COUNT" lines, as the service returns them.
// Padding entries have a count of 0, so they never count as a match.
pub fn count_for(body: &str, suffix: &str) -> Option<u64> {
    body.lines()
        .filter_map(|line| line.trim().split_once(':'))
        .find(|(listed, _)| listed.eq_ignore_ascii_case(suffix))
        .and_then(|(_, count)| count.trim().parse::<u64>().ok())
        .filter(|count| *count > 0)
}

// Adds commas, such as 3,730,471.
fn with_commas(number: u64) -> String {
    let digits = number.to_string();
    let mut result = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            result.push(',');
        }
        result.push(digit);
    }
    result
}

// What Tenax read and why. These stay the same whatever the result is.
const CHECKED: &str = "I hashed the password on this PC, sent only the first 5 characters of the \
                       hash to Have I Been Pwned, and compared the matches here.";
const WHY: &str = "A password that has appeared in a breach is in the lists attackers try first, \
                   even if it looks complicated.";

fn finding(
    status: Status,
    summary: String,
    action: Option<&str>,
    details: Vec<crate::finding::Detail>,
) -> Finding {
    Finding {
        id: "breach".to_string(),
        status,
        title: "Breach exposure".to_string(),
        summary,
        checked: CHECKED.to_string(),
        why: WHY.to_string(),
        action: action.map(str::to_string),
        details,
        steps: Vec::new(),
        note: None,
    }
}

pub fn build(outcome: &Result<Option<u64>, String>) -> Finding {
    match outcome {
        // A failed lookup must never look like a pass, so it gets its own status.
        Err(error) => finding(
            Status::Unknown,
            "Could not reach the breach list".to_string(),
            Some("Check your internet connection and try again."),
            vec![detail("Error", error)],
        ),
        Ok(Some(count)) => finding(
            Status::Risk,
            format!("Seen {} times in known breaches", with_commas(*count)),
            Some(
                "Do not use this password anywhere. Change it on any account that uses it, \
                 and use a different password for each account.",
            ),
            vec![
                detail("Times seen", with_commas(*count)),
                detail("Checked against", "Have I Been Pwned"),
            ],
        ),
        Ok(None) => finding(
            Status::Ok,
            "Not found in known breaches".to_string(),
            Some(
                "Not being listed does not make a password strong. \
                 Check it on the Password Strength page too.",
            ),
            vec![detail("Checked against", "Have I Been Pwned")],
        ),
    }
}

// =========================
// Tests
// =========================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::breached_passwords::lookup::sha1_hex;

    #[test]
    fn hash_matches_a_known_value() {
        assert_eq!(
            sha1_hex("password"),
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        );
    }

    #[test]
    fn finds_the_hash_in_the_list() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2";
        assert_eq!(
            count_for(body, "00D4F6E8FA6EECAD2A3AA415EEC418D38EC"),
            Some(2)
        );
        assert_eq!(
            count_for(body, "00d4f6e8fa6eecad2a3aa415eec418d38ec"),
            Some(2)
        );
    }

    #[test]
    fn padding_and_missing_hashes_are_not_matches() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2";
        assert_eq!(count_for(body, "0018A45C4D1DEF81644B54AB7F969B88D65"), None);
        assert_eq!(count_for(body, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), None);
        assert_eq!(count_for("", "ABC"), None);
    }

    #[test]
    fn counts_get_commas() {
        assert_eq!(with_commas(7), "7");
        assert_eq!(with_commas(1000), "1,000");
        assert_eq!(with_commas(3730471), "3,730,471");
    }

    #[test]
    fn found_is_a_risk_and_not_found_is_ok() {
        assert_eq!(build(&Ok(Some(5))).status, Status::Risk);
        assert_eq!(build(&Ok(None)).status, Status::Ok);
    }

    #[test]
    fn failed_lookup_is_never_reported_as_ok() {
        let finding = build(&Err("timed out".to_string()));
        assert_eq!(finding.status, Status::Unknown);
        assert!(finding.action.is_some());
    }
}
