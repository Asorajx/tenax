// The only network code in TLS Certificate. It makes a TLS handshake and nothing more: no web
// request is sent, nothing is downloaded and no redirect can happen, because the connection is
// closed as soon as the server's certificate has been read.
//
// The handshake is done by Windows' own secure channel (Schannel), through native-tls, so it
// trusts the same certificate authorities as a browser, including a workplace's.

use std::error::Error;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use native_tls::{HandshakeError, TlsConnector};

// How long to wait for the connection, and then for each reply during the handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const REPLY_TIMEOUT: Duration = Duration::from_secs(8);

// Where a failed attempt stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    // The server could not be reached at all.
    Connect,
    // The server answered, but the secure handshake did not finish.
    Handshake,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub stage: Stage,
    // The Windows error code, such as 0x800B0101, when Windows gave one.
    pub code: Option<u32>,
    pub text: String,
}

// The server's own certificate, as the bytes it sent.
pub type Der = Vec<u8>;

// The number Windows gave for a failure, such as -2146762495, read from its message. It is
// written there as "(os error -2146762495)" and is the same number as 0x800B0101.
fn code_of(error: &(dyn Error + 'static)) -> Option<u32> {
    let text = error.to_string();
    let digits = text.split("(os error ").nth(1)?.split(')').next()?;
    digits.trim().parse::<i32>().ok().map(|code| code as u32)
}

// Windows adds "(os error N)" to its message. The number is kept in `code`, so it is dropped here.
fn plain(text: String) -> String {
    match text.rfind(" (os error ") {
        Some(end) => text[..end].to_string(),
        None => text,
    }
}

fn handshake_failure(error: &(dyn Error + 'static)) -> Failure {
    Failure {
        stage: Stage::Handshake,
        code: code_of(error),
        text: plain(error.to_string()),
    }
}

// Connects to one address and makes the handshake. With `verify` on, Windows checks the
// certificate as a browser would and the handshake fails if it is not trusted. With it off,
// nothing is checked and the certificate is only read, so it can be explained. Whatever it
// returns in that case is never to be treated as trusted.
pub fn handshake(addr: SocketAddr, host: &str, verify: bool) -> Result<Der, Failure> {
    let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).map_err(|error| Failure {
        stage: Stage::Connect,
        code: error.raw_os_error().map(|code| code as u32),
        text: plain(error.to_string()),
    })?;
    // A server that goes quiet must not hold the check up.
    let _ = stream.set_read_timeout(Some(REPLY_TIMEOUT));
    let _ = stream.set_write_timeout(Some(REPLY_TIMEOUT));

    let mut builder = TlsConnector::builder();
    if !verify {
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
    }
    let connector = builder.build().map_err(|error| handshake_failure(&error))?;

    let tls = match connector.connect(host, stream) {
        Ok(tls) => tls,
        Err(HandshakeError::Failure(error)) => return Err(handshake_failure(&error)),
        Err(HandshakeError::WouldBlock(_)) => {
            return Err(Failure {
                stage: Stage::Handshake,
                code: None,
                text: "The server did not finish the handshake in time.".to_string(),
            });
        }
    };

    let certificate = tls
        .peer_certificate()
        .map_err(|error| handshake_failure(&error))?
        .ok_or_else(|| Failure {
            stage: Stage::Handshake,
            code: None,
            text: "The server did not send a certificate.".to_string(),
        })?;
    certificate
        .to_der()
        .map_err(|error| handshake_failure(&error))
}

#[cfg(test)]
mod tests {
    use std::net::ToSocketAddrs;

    use super::*;

    // Makes real connections to public test servers. Nothing is sent but the handshake.
    // Run with: cargo test -- --ignored --nocapture
    #[test]
    #[ignore]
    fn prints_real_handshakes() {
        for host in [
            "example.com",
            "expired.badssl.com",
            "self-signed.badssl.com",
            "untrusted-root.badssl.com",
            "wrong.host.badssl.com",
            "revoked.badssl.com",
            "1.1.1.1",
        ] {
            let addr = (host, 443).to_socket_addrs().unwrap().next().unwrap();
            let strict = handshake(addr, host, true);
            let lenient = handshake(addr, host, false);
            println!(
                "{host}\n  strict : {:?}\n  lenient: {:?}",
                strict.as_ref().map(|der| der.len()).map_err(|e| (
                    e.stage,
                    e.code.map(|c| format!("{c:#x}")),
                    e.text.clone()
                )),
                lenient.as_ref().map(|der| der.len()).map_err(|e| (
                    e.stage,
                    e.code.map(|c| format!("{c:#x}")),
                    e.text.clone()
                )),
            );
        }
    }
}
