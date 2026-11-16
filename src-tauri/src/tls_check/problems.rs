// Works out what is wrong with a certificate that Windows would not trust, in terms a person
// can act on. Windows reports one error code. The certificate itself shows more, such as that
// it is expired and also issued for a different name, so both are looked at.
//
// A certificate that Windows rejected is never treated as trusted, whatever is found here.

use super::cert::CertInfo;

// Whether Windows trusted the certificate when it was checked as a browser would check it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    Trusted,
    NotTrusted {
        // The Windows error code, such as 0x800B0109, and Windows' own wording for it.
        code: Option<u32>,
        text: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Problem {
    // The end date has passed.
    Expired,
    // The start date has not come yet.
    NotYetValid,
    // This certificate is in date, but one above it in the chain has expired.
    ChainExpired,
    // It was issued for other names than the one that was checked.
    NameMismatch,
    // It vouches for itself and no authority has confirmed it.
    SelfSigned,
    // It could not be traced back to an authority Windows trusts.
    UntrustedIssuer,
    // The authority has withdrawn it.
    Revoked,
    // Windows refused it for a reason Tenax does not recognise.
    Rejected,
}

impl Problem {
    // The most serious problems are shown as risks, and the rest as warnings.
    pub fn is_serious(self) -> bool {
        !matches!(
            self,
            Problem::Expired | Problem::NotYetValid | Problem::ChainExpired
        )
    }
}

// What Windows' error code says, grouped.
#[derive(Debug, PartialEq, Eq)]
enum Reason {
    Expired,
    Untrusted,
    NameMismatch,
    Revoked,
    Other,
}

fn reason(code: Option<u32>) -> Reason {
    match code {
        // CERT_E_EXPIRED, SEC_E_CERT_EXPIRED
        Some(0x800B_0101 | 0x8009_0328) => Reason::Expired,
        // CERT_E_UNTRUSTEDROOT, CERT_E_CHAINING, CERT_E_ISSUERCHAINING, CERT_E_UNTRUSTEDTESTROOT,
        // CERT_E_UNTRUSTEDCA, SEC_E_UNTRUSTED_ROOT
        Some(0x800B_0109 | 0x800B_010A | 0x800B_0107 | 0x800B_010D | 0x800B_0112 | 0x8009_0325) => {
            Reason::Untrusted
        }
        // CERT_E_CN_NO_MATCH, SEC_E_WRONG_PRINCIPAL
        Some(0x800B_010F | 0x8009_0322) => Reason::NameMismatch,
        // CERT_E_REVOKED, CRYPT_E_REVOKED
        Some(0x800B_010C | 0x8009_2010) => Reason::Revoked,
        _ => Reason::Other,
    }
}

// Every problem found, most serious first. A certificate Windows rejected always has at least one.
pub fn find(cert: &CertInfo, host: &str, code: Option<u32>, now: i64) -> Vec<Problem> {
    let windows = reason(code);
    let mut found = Vec::new();

    if cert.is_expired(now) {
        found.push(Problem::Expired);
    } else if windows == Reason::Expired {
        found.push(Problem::ChainExpired);
    }
    if cert.not_yet_valid(now) {
        found.push(Problem::NotYetValid);
    }
    if !cert.covers(host) || windows == Reason::NameMismatch {
        found.push(Problem::NameMismatch);
    }
    if cert.self_signed {
        found.push(Problem::SelfSigned);
    } else if windows == Reason::Untrusted {
        found.push(Problem::UntrustedIssuer);
    }
    if windows == Reason::Revoked {
        found.push(Problem::Revoked);
    }
    if found.is_empty() {
        found.push(Problem::Rejected);
    }

    found.sort_by_key(|problem| !problem.is_serious());
    found
}
