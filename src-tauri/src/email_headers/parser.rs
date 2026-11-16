// Reads raw email headers into fields and pulls out the parts the findings need.
// There is no Windows or network code here, so every case can be tested with pasted text.

// The header fields of one message, in the order they appear.
pub struct Headers {
    fields: Vec<(String, String)>,
}

impl Headers {
    pub fn parse(raw: &str) -> Headers {
        let mut fields: Vec<(String, String)> = Vec::new();

        for line in raw.lines() {
            if line.trim().is_empty() {
                // Blank lines before the first field are skipped. After it, the headers have
                // ended and what follows is the message body.
                if fields.is_empty() {
                    continue;
                }
                break;
            }

            if line.starts_with(' ') || line.starts_with('\t') {
                // A line that starts with a space continues the field above it.
                if let Some((_, value)) = fields.last_mut() {
                    value.push(' ');
                    value.push_str(line.trim());
                }
            } else if let Some((name, value)) = line.split_once(':') {
                // Field names have no spaces. This skips lines such as an mbox "From " line.
                let name = name.trim();
                if !name.is_empty() && !name.contains(char::is_whitespace) {
                    fields.push((name.to_string(), value.trim().to_string()));
                }
            }
        }

        Headers { fields }
    }

    pub fn len(&self) -> usize {
        self.fields.len()
    }

    // Every field with this name, in order. Names are not case sensitive.
    pub fn all(&self, name: &str) -> Vec<&str> {
        self.fields
            .iter()
            .filter(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect()
    }

    pub fn first(&self, name: &str) -> Option<&str> {
        self.all(name).into_iter().next()
    }
}

// Removes (comments), which can hold text that gets in the way, such as extra semicolons.
fn strip_comments(text: &str) -> String {
    let mut depth = 0;
    let mut result = String::new();
    for character in text.chars() {
        match character {
            '(' => depth += 1,
            ')' if depth > 0 => depth -= 1,
            _ if depth == 0 => result.push(character),
            _ => {}
        }
    }
    result
}

// =========================
// Addresses
// =========================

pub struct Mailbox {
    // The name shown in an email app, such as "PayPal".
    pub name: Option<String>,
    // Lower case, such as "service@paypal.com".
    pub address: String,
}

// Reads the first address from a value such as `"Name" <name@example.com>` or `name@example.com`.
pub fn parse_mailbox(value: &str) -> Option<Mailbox> {
    let value = strip_comments(value);

    if let (Some(start), Some(end)) = (value.find('<'), value.find('>'))
        && start < end
        && value[start + 1..end].contains('@')
    {
        let name = value[..start].trim().trim_matches('"').trim();
        return Some(Mailbox {
            name: (!name.is_empty()).then(|| name.to_string()),
            address: value[start + 1..end].trim().to_lowercase(),
        });
    }

    let address = value
        .split([' ', ',', ';'])
        .find(|part| part.contains('@'))?
        .trim_matches(['<', '>', '"']);
    Some(Mailbox {
        name: None,
        address: address.to_lowercase(),
    })
}

// The part after the last @, such as "example.com".
pub fn domain_of(address: &str) -> &str {
    address.rsplit_once('@').map_or("", |(_, domain)| domain)
}

// Whether two domains belong together, such as mail.example.com and example.com.
pub fn same_domain(a: &str, b: &str) -> bool {
    a == b || a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}"))
}

// An email address written inside a display name, such as "service@paypal.com" in
// `"service@paypal.com" <other@example.net>`.
pub fn address_in_name(name: &str) -> Option<String> {
    name.split_whitespace()
        .find(|part| part.contains('@'))
        .map(|part| {
            part.trim_matches(['<', '>', '"', '\'', ',', ';'])
                .to_lowercase()
        })
}

// =========================
// Sender authentication
// =========================

pub struct AuthResult {
    // "spf", "dkim" or "dmarc".
    pub method: String,
    // "pass", "fail", "softfail" and so on.
    pub result: String,
    // The domain the result is about, if the header names one.
    pub domain: Option<String>,
}

// The domain from the first property that names one, such as "smtp.mailfrom=bounce@example.com".
// Values can be a full address, "@domain" or a plain domain.
fn property_domain(tokens: &[&str], keys: &[&str]) -> Option<String> {
    for key in keys {
        for token in tokens {
            let Some(value) = token.strip_prefix(key) else {
                continue;
            };
            let value = value.trim_matches(['"', '<', '>']).to_lowercase();
            let domain = if value.contains('@') {
                domain_of(&value).to_string()
            } else {
                value
            };
            if !domain.is_empty() {
                return Some(domain);
            }
        }
    }
    None
}

// Reads an Authentication-Results header, which the receiving mail server adds. If a method
// appears more than once, the first result is used.
pub fn authentication_results(header: &str) -> Vec<AuthResult> {
    let mut results: Vec<AuthResult> = Vec::new();

    for part in strip_comments(header).split(';') {
        let tokens: Vec<&str> = part.split_whitespace().collect();
        let Some((method, result)) = tokens.first().and_then(|token| token.split_once('=')) else {
            continue;
        };
        let method = method.to_lowercase();
        if !matches!(method.as_str(), "spf" | "dkim" | "dmarc")
            || results.iter().any(|known| known.method == method)
        {
            continue;
        }

        // Which property names the domain depends on the method.
        let wanted: &[&str] = match method.as_str() {
            "spf" => &["smtp.mailfrom=", "smtp.helo="],
            "dkim" => &["header.d=", "header.i="],
            _ => &["header.from="],
        };
        let domain = property_domain(&tokens, wanted);

        results.push(AuthResult {
            method,
            result: result.to_lowercase(),
            domain,
        });
    }

    results
}

// The name of the server that wrote an Authentication-Results header, which is the first
// word, such as "mx.google.com".
pub fn authserv_id(header: &str) -> Option<String> {
    strip_comments(header)
        .split(';')
        .next()
        .and_then(|part| part.split_whitespace().next())
        // Some servers, such as Outlook, start with the results and name no server.
        .filter(|word| !word.contains('='))
        .map(str::to_lowercase)
}

// Whether two server names look like they belong to the same provider, such as
// "mx.google.com" and "smtp.google.com". Only the last two parts of the names are compared,
// so this is a rough check and not proof.
pub fn related_hosts(a: &str, b: &str) -> bool {
    let tail = |host: &str| {
        let host = host.trim_matches(['[', ']']);
        let parts: Vec<&str> = host.rsplit('.').take(2).collect();
        (parts.len() == 2).then(|| parts.join("."))
    };
    matches!((tail(a), tail(b)), (Some(x), Some(y)) if x == y)
}

// The SPF result from a Received-SPF header, which starts with the result, such as "pass".
pub fn received_spf(header: &str) -> Option<String> {
    header
        .split_whitespace()
        .next()
        .map(|word| word.to_lowercase())
}

// =========================
// Delivery path
// =========================

pub struct Hop {
    pub from: Option<String>,
    pub by: Option<String>,
}

// The first (comment) in a text, without the brackets.
fn first_comment(text: &str) -> Option<&str> {
    let start = text.find('(')?;
    let mut depth = 0;
    for (offset, character) in text[start..].char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(text[start + 1..start + offset].trim());
                }
            }
            _ => {}
        }
    }
    None
}

// Reads which server a message came from and which server received it.
pub fn parse_hop(header: &str) -> Hop {
    // The date after the semicolon is not needed here.
    let text = header.split(';').next().unwrap_or("");
    let plain = strip_comments(text);
    let words: Vec<&str> = plain.split_whitespace().collect();

    let after = |keyword: &str| {
        words
            .iter()
            .position(|word| word.eq_ignore_ascii_case(keyword))
            .and_then(|index| words.get(index + 1))
            .map(|word| word.to_lowercase())
    };

    // The name after "from" is whatever the sending server claimed, so it can be forged.
    // The note in brackets, such as "mail.example.com [203.0.113.9]", is written by the
    // receiving server from the real connection, so it is shown when there is one.
    let seen = first_comment(text)
        .filter(|comment| comment.contains('['))
        .map(str::to_lowercase);

    Hop {
        from: seen.or_else(|| after("from")),
        by: after("by"),
    }
}

// =========================
// Tests
// =========================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folded_lines_join_the_field_above() {
        let headers =
            Headers::parse("Subject: Hello\r\n  there\r\nFrom: a@b.com\r\n\r\nBody: not a header");
        assert_eq!(headers.len(), 2);
        assert_eq!(headers.first("subject"), Some("Hello there"));
        assert_eq!(headers.first("Body"), None);
    }

    #[test]
    fn leading_junk_and_blank_lines_are_skipped() {
        let headers = Headers::parse(
            "\nFrom sender@example.com Tue Jan 1 10:10:10 2030\nReceived: by x\nTo: y@z.com",
        );
        assert_eq!(headers.len(), 2);
        assert_eq!(headers.all("received").len(), 1);
    }

    #[test]
    fn reads_addresses_in_common_forms() {
        let named = parse_mailbox("\"PayPal Support\" <Help@Example.com>").unwrap();
        assert_eq!(named.address, "help@example.com");
        assert_eq!(named.name.as_deref(), Some("PayPal Support"));
        assert_eq!(
            parse_mailbox("plain@example.com").unwrap().address,
            "plain@example.com"
        );
        assert!(parse_mailbox("no address here").is_none());
        assert_eq!(domain_of("a@mail.example.com"), "mail.example.com");
    }

    #[test]
    fn subdomains_belong_to_their_parent() {
        assert!(same_domain("mail.example.com", "example.com"));
        assert!(!same_domain("example.com", "evil-example.com"));
    }

    #[test]
    fn finds_an_address_inside_a_display_name() {
        assert_eq!(
            address_in_name("service@paypal.com Support").as_deref(),
            Some("service@paypal.com")
        );
        assert_eq!(address_in_name("PayPal Support"), None);
    }

    #[test]
    fn reads_authentication_results() {
        let results = authentication_results(
            "mx.google.com; dkim=pass header.i=@example.com header.s=s1; \
             spf=softfail (domain does not designate) smtp.mailfrom=bounce@mail.example.com; \
             dmarc=fail (p=REJECT) header.from=example.com",
        );
        let find = |method: &str| {
            results
                .iter()
                .find(|result| result.method == method)
                .unwrap()
        };
        assert_eq!(find("dkim").result, "pass");
        assert_eq!(find("dkim").domain.as_deref(), Some("example.com"));
        assert_eq!(find("spf").result, "softfail");
        assert_eq!(find("spf").domain.as_deref(), Some("mail.example.com"));
        assert_eq!(find("dmarc").result, "fail");
        assert_eq!(find("dmarc").domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn only_the_first_result_per_method_counts() {
        let results = authentication_results(
            "a; spf=pass smtp.mailfrom=x@a.com; spf=fail smtp.mailfrom=y@b.com",
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].result, "pass");
    }

    #[test]
    fn a_claimed_name_is_replaced_by_what_the_receiver_saw() {
        let hop = parse_hop("from legit-bank.example (unknown [203.0.113.9]) by mx.example.net; x");
        assert_eq!(hop.from.as_deref(), Some("unknown [203.0.113.9]"));
        let plain = parse_hop("from relay.example by mx.example.net; x");
        assert_eq!(plain.from.as_deref(), Some("relay.example"));
    }

    #[test]
    fn reads_the_server_that_wrote_the_results() {
        assert_eq!(
            authserv_id("mx.Google.com; spf=pass smtp.mailfrom=a@b.com").as_deref(),
            Some("mx.google.com")
        );
        assert!(related_hosts("mx.google.com", "smtp.google.com"));
        assert!(!related_hosts("mx.google.com", "mx.evil-google.net"));
        assert!(!related_hosts("mx.google.com", "[10.0.0.1]"));
    }

    #[test]
    fn reads_the_servers_in_a_received_header() {
        let hop = parse_hop(
            "from mail.example.com (mail.example.com [1.2.3.4]) by mx.google.com with ESMTPS; Tue, 1 Jan 2030 10:10:10 +0000",
        );
        assert_eq!(hop.from.as_deref(), Some("mail.example.com [1.2.3.4]"));
        assert_eq!(hop.by.as_deref(), Some("mx.google.com"));
        assert_eq!(
            received_spf("Pass (google.com: domain of a@b.com designates 1.2.3.4)").as_deref(),
            Some("pass")
        );
    }
}
