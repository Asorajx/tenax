// Reads a certificate into plain values. There is no network code here, so everything can be
// tested with certificates kept in the test files.
//
// Only the server's own certificate is read. Tenax does not rebuild or judge the chain above it,
// because Windows has already done that when it decides whether to trust the certificate.

use std::net::IpAddr;

use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

use crate::ip_info::external::printable;

// The longest any one value is shown.
const MAX_SHOWN: usize = 200;
// A certificate can list hundreds of names. Only this many are kept.
const MAX_NAMES: usize = 100;
// RSA keys shorter than this are considered too short today.
const MIN_RSA_BITS: usize = 2048;

#[derive(Debug, Clone, PartialEq)]
pub struct CertInfo {
    // Who the certificate was issued to, and who issued it, written the way they appear in it.
    pub subject: String,
    pub issuer: String,
    // The first start and end dates, as unix seconds, for working out whether it is current.
    pub not_before: i64,
    pub not_after: i64,
    // The same dates as they are shown, such as "2026-11-16".
    pub valid_from: String,
    pub valid_until: String,
    // The names and addresses the certificate says it is valid for.
    pub names: Vec<String>,
    pub addresses: Vec<IpAddr>,
    // The issuer and the subject are the same, so the certificate vouches for itself.
    pub self_signed: bool,
    pub key: String,
    // Why the key is too weak, when it is.
    pub key_weakness: Option<&'static str>,
    pub signature: String,
    pub signature_weakness: Option<&'static str>,
    pub serial: String,
}

fn shown(text: &str) -> String {
    printable(text, MAX_SHOWN)
}

// What a signature algorithm is called, and what is wrong with it, if anything.
fn signature_name(oid: &str) -> (String, Option<&'static str>) {
    let weak_hash = Some(
        "It uses a hash function that can be forged, so the signature can no longer be relied on.",
    );
    let (name, weakness) = match oid {
        "1.2.840.113549.1.1.4" => ("MD5 with RSA", weak_hash),
        "1.2.840.113549.1.1.5" => ("SHA-1 with RSA", weak_hash),
        "1.2.840.113549.1.1.11" => ("SHA-256 with RSA", None),
        "1.2.840.113549.1.1.12" => ("SHA-384 with RSA", None),
        "1.2.840.113549.1.1.13" => ("SHA-512 with RSA", None),
        "1.2.840.113549.1.1.10" => ("RSA-PSS", None),
        "1.2.840.10045.4.1" => ("SHA-1 with ECDSA", weak_hash),
        "1.2.840.10045.4.3.2" => ("SHA-256 with ECDSA", None),
        "1.2.840.10045.4.3.3" => ("SHA-384 with ECDSA", None),
        "1.2.840.10045.4.3.4" => ("SHA-512 with ECDSA", None),
        "1.3.101.112" => ("Ed25519", None),
        "1.3.101.113" => ("Ed448", None),
        other => return (format!("Not recognised ({other})"), None),
    };
    (name.to_string(), weakness)
}

// What the curve of an elliptic-curve key is called.
fn curve_name(oid: &str) -> String {
    match oid {
        "1.2.840.10045.3.1.7" => "P-256".to_string(),
        "1.3.132.0.34" => "P-384".to_string(),
        "1.3.132.0.35" => "P-521".to_string(),
        other => format!("curve {other}"),
    }
}

pub fn read(der: &[u8]) -> Result<CertInfo, String> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|_| "The server's certificate could not be read.".to_string())?;

    let mut names = Vec::new();
    let mut addresses = Vec::new();
    if let Ok(Some(alternative)) = cert.subject_alternative_name() {
        for name in &alternative.value.general_names {
            match name {
                GeneralName::DNSName(name) if names.len() < MAX_NAMES => {
                    names.push(shown(name).to_lowercase())
                }
                GeneralName::IPAddress(bytes) if addresses.len() < MAX_NAMES => {
                    if let Ok(octets) = <[u8; 4]>::try_from(*bytes) {
                        addresses.push(IpAddr::from(octets));
                    } else if let Ok(octets) = <[u8; 16]>::try_from(*bytes) {
                        addresses.push(IpAddr::from(octets));
                    }
                }
                _ => {}
            }
        }
    }

    let spki = cert.public_key();
    let (key, key_weakness) = match spki.parsed() {
        Ok(PublicKey::RSA(rsa)) => {
            let bits = rsa.key_size();
            (
                format!("RSA, {bits} bits"),
                (bits < MIN_RSA_BITS)
                    .then_some("A key this short can be broken with modern computers."),
            )
        }
        Ok(PublicKey::EC(point)) => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.as_oid().ok())
                .map(|oid| curve_name(&oid.to_id_string()));
            match curve {
                Some(curve) => (format!("Elliptic curve, {curve}"), None),
                None => (format!("Elliptic curve, {} bits", point.key_size()), None),
            }
        }
        _ => match spki.algorithm.algorithm.to_id_string().as_str() {
            "1.3.101.112" => ("Ed25519".to_string(), None),
            "1.3.101.113" => ("Ed448".to_string(), None),
            other => (format!("Not recognised ({other})"), None),
        },
    };

    let (signature, signature_weakness) =
        signature_name(&cert.signature_algorithm.algorithm.to_id_string());

    let validity = cert.validity();
    let date = |time: &x509_parser::time::ASN1Time| time.to_datetime().date().to_string();

    Ok(CertInfo {
        subject: shown(&cert.subject().to_string()),
        issuer: shown(&cert.issuer().to_string()),
        not_before: validity.not_before.timestamp(),
        not_after: validity.not_after.timestamp(),
        valid_from: date(&validity.not_before),
        valid_until: date(&validity.not_after),
        names,
        addresses,
        self_signed: cert.subject() == cert.issuer(),
        key,
        key_weakness,
        signature,
        signature_weakness,
        serial: shown(&cert.raw_serial_as_string()),
    })
}

// =========================
// Names
// =========================

// Whether a name from the certificate covers the name that was asked for. A wildcard such as
// *.example.com covers exactly one extra part in front, so a.example.com but not example.com
// and not a.b.example.com. A wildcard on a bare ending such as *.com covers nothing.
pub fn name_covers(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.');
    let host = host.trim_end_matches('.');
    match pattern.strip_prefix("*.") {
        Some(rest) => {
            rest.contains('.')
                && host
                    .split_once('.')
                    .is_some_and(|(first, tail)| !first.is_empty() && tail == rest)
        }
        None => pattern == host,
    }
}

impl CertInfo {
    // Whether the certificate says it is valid for the host that was entered, which is a name
    // or an IP address.
    pub fn covers(&self, host: &str) -> bool {
        match host.parse::<IpAddr>() {
            Ok(ip) => self.addresses.contains(&ip),
            Err(_) => self.names.iter().any(|name| name_covers(name, host)),
        }
    }

    // Whether the dates have started, and whether they have run out, at a moment in time.
    pub fn is_expired(&self, now: i64) -> bool {
        now > self.not_after
    }

    pub fn not_yet_valid(&self, now: i64) -> bool {
        now < self.not_before
    }
}
