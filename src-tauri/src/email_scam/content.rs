// Reads the pasted email into plain text, links and page elements.
// The HTML is only parsed into a tree of data. Nothing in it is run, opened or loaded, so
// scripts, images and frames in the email cannot do anything while it is analysed.

use scraper::{Html, Node, Selector};

use crate::email_headers::parser::Headers;

// A link in the email: where it goes and the words a reader sees for it.
pub struct RawLink {
    pub href: String,
    pub shown: Option<String>,
}

// Parts of an HTML email that are unusual in a genuine message.
pub enum Element {
    Script,
    // An iframe, embed or object, which can show a page inside the email.
    Frame,
    Form {
        action: Option<String>,
        password: bool,
    },
    // A "refresh" instruction that sends the reader to another page when the email opens.
    Refresh {
        target: String,
    },
}

pub struct Content {
    // The text a reader sees, as lower case on one line, ready for matching phrases.
    pub text: String,
    pub words: usize,
    pub is_html: bool,
    // Images are counted but never loaded.
    pub images: usize,
    pub links: Vec<RawLink>,
    pub elements: Vec<Element>,
}

// =========================
// Source
// =========================

// The pasted text split into its header block, if it has one, and the message itself.
pub struct Source {
    pub body: String,
    pub subject: Option<String>,
    pub has_headers: bool,
    // Whether part of the message is base64, which is not decoded here.
    pub encoded: bool,
}

// Emails are often saved with quoted-printable encoding, where "=3D" stands for "=" and a "="
// at the end of a line joins it to the next. Text that does not look encoded is left alone.
pub fn decode_quoted_printable(raw: &str) -> String {
    if !(raw.contains("=\n") || raw.contains("=\r\n") || raw.contains("=3D")) {
        return raw.to_string();
    }

    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'=' {
            if bytes.get(index + 1) == Some(&b'\n') {
                index += 2;
                continue;
            }
            if bytes.get(index + 1) == Some(&b'\r') && bytes.get(index + 2) == Some(&b'\n') {
                index += 3;
                continue;
            }
            let digit = |offset: usize| {
                bytes
                    .get(index + offset)
                    .and_then(|byte| (*byte as char).to_digit(16))
            };
            if let (Some(high), Some(low)) = (digit(1), digit(2)) {
                decoded.push((high * 16 + low) as u8);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

// Finds where the message starts after a header block: the first blank line.
fn body_start(raw: &str) -> Option<usize> {
    let lf = raw.find("\n\n").map(|at| at + 2);
    let crlf = raw.find("\r\n\r\n").map(|at| at + 4);
    [lf, crlf].into_iter().flatten().min()
}

// Splits off the header block when the paste is a full message, and decodes the message.
pub fn read_source(raw: &str) -> Source {
    let headers = Headers::parse(raw);
    let has_headers = headers.len() >= 3
        && headers.first("From").is_some()
        && ["Subject", "Date", "Received", "To", "Message-ID"]
            .iter()
            .any(|name| headers.first(name).is_some());

    let body = match (has_headers, body_start(raw)) {
        (true, Some(start)) => &raw[start..],
        (true, None) => "",
        (false, _) => raw,
    };
    let encoded = raw
        .to_ascii_lowercase()
        .contains("content-transfer-encoding: base64");

    Source {
        body: decode_quoted_printable(body),
        subject: has_headers
            .then(|| headers.first("Subject").map(str::to_string))
            .flatten(),
        has_headers,
        encoded,
    }
}

// =========================
// Text and links
// =========================

fn collapse(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn selector(css: &str) -> Option<Selector> {
    Selector::parse(css).ok()
}

fn looks_like_html(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "<!doctype",
        "<html",
        "<body",
        "<a ",
        "<div",
        "<p>",
        "<p ",
        "<br",
        "<table",
        "<tr",
        "<td",
        "<span",
        "<img",
        "<form",
        "<input",
        "<button",
        "<meta",
        "<script",
        "<iframe",
        "<style",
        "<center",
        "<font",
        "<ul",
        "<h1",
        "<h2",
    ]
    .iter()
    .any(|tag| lower.contains(tag))
}

// The text of an HTML document that a reader would see. Scripts and styles are not text.
fn visible_text(document: &Html) -> String {
    let mut text = String::new();
    for node in document.root_element().descendants() {
        let Node::Text(content) = node.value() else {
            continue;
        };
        let hidden = node
            .parent()
            .and_then(|parent| parent.value().as_element().map(|e| e.name().to_string()))
            .is_some_and(|name| matches!(name.as_str(), "script" | "style" | "template"));
        if !hidden {
            text.push_str(content);
            text.push(' ');
        }
    }
    collapse(&text)
}

// The words a reader sees for a link: its text, or the description of an image inside it.
fn link_text(anchor: scraper::ElementRef) -> Option<String> {
    let text = collapse(&anchor.text().collect::<Vec<_>>().join(" "));
    if !text.is_empty() {
        return Some(text);
    }
    let image = selector("img")?;
    let alt = anchor
        .select(&image)
        .filter_map(|image| image.value().attr("alt"))
        .collect::<Vec<_>>()
        .join(" ");
    let alt = collapse(&alt);
    (!alt.is_empty()).then_some(alt)
}

// The address in a refresh instruction such as "0; url=https://example.com".
fn refresh_target(content: &str) -> Option<String> {
    let lower = content.to_ascii_lowercase();
    let start = lower.find("url=")? + 4;
    let target = content[start..].trim().trim_matches(['"', '\'']);
    (!target.is_empty()).then(|| target.to_string())
}

// Plain web addresses written in the text, with the characters that end an address removed.
fn written_addresses(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(offset) = ["http://", "https://"]
        .iter()
        .filter_map(|scheme| lower[from..].find(scheme))
        .min()
    {
        let start = from + offset;
        let end = text[start..]
            .find(|c: char| c.is_whitespace() || "<>\"')]".contains(c))
            .map_or(text.len(), |end| start + end);
        let address = text[start..end].trim_end_matches(['.', ',', ';', ':', '!', '?']);
        if !address.is_empty() {
            found.push(address.to_string());
        }
        // The next search starts after the first character, which is always one byte.
        from = end.max(start + 1);
    }
    found
}

pub fn read(body: &str, subject: Option<&str>) -> Content {
    let is_html = looks_like_html(body);

    let mut links: Vec<RawLink> = Vec::new();
    let mut elements: Vec<Element> = Vec::new();
    let mut images = 0;

    let visible = if is_html {
        let document = Html::parse_document(body);

        if let Some(anchors) = selector("a[href], area[href]") {
            for anchor in document.select(&anchors) {
                if let Some(href) = anchor.value().attr("href") {
                    links.push(RawLink {
                        href: href.to_string(),
                        shown: link_text(anchor),
                    });
                }
            }
        }
        if let Some(forms) = selector("form") {
            let password = selector("input[type=password]");
            for form in document.select(&forms) {
                elements.push(Element::Form {
                    action: form.value().attr("action").map(str::to_string),
                    password: password
                        .as_ref()
                        .is_some_and(|password| form.select(password).next().is_some()),
                });
            }
        }
        if selector("script").is_some_and(|s| document.select(&s).next().is_some()) {
            elements.push(Element::Script);
        }
        if selector("iframe, embed, object").is_some_and(|s| document.select(&s).next().is_some()) {
            elements.push(Element::Frame);
        }
        if let Some(metas) = selector("meta[http-equiv]") {
            for meta in document.select(&metas) {
                let refresh = meta
                    .value()
                    .attr("http-equiv")
                    .is_some_and(|value| value.eq_ignore_ascii_case("refresh"));
                if let (true, Some(target)) = (
                    refresh,
                    meta.value().attr("content").and_then(refresh_target),
                ) {
                    elements.push(Element::Refresh { target });
                }
            }
        }
        images = selector("img").map_or(0, |s| document.select(&s).count());

        visible_text(&document)
    } else {
        collapse(body)
    };

    // Addresses written out as text, when they are not already links.
    for address in written_addresses(&visible) {
        if !links.iter().any(|link| link.href == address) {
            links.push(RawLink {
                href: address,
                shown: None,
            });
        }
    }

    let full = match subject {
        Some(subject) => format!("{} {}", subject.trim(), visible),
        None => visible,
    };
    // A curly apostrophe is made plain so that "don’t" matches "don't".
    let text = full.to_lowercase().replace('\u{2019}', "'");

    Content {
        words: text.split_whitespace().count(),
        text,
        is_html,
        images,
        links,
        elements,
    }
}

// =========================
// Tests
// =========================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_printable_is_decoded_and_plain_text_is_left_alone() {
        assert_eq!(
            decode_quoted_printable("<a href=3D\"https://a.example/x?y=3D1\">go=\r\nto</a>"),
            "<a href=\"https://a.example/x?y=1\">goto</a>"
        );
        assert_eq!(decode_quoted_printable("a = b"), "a = b");
    }

    #[test]
    fn a_full_message_is_split_into_headers_and_body() {
        let source = read_source(
            "From: a@example.net\nTo: b@example.net\nSubject: Hello there\n\nThe body text.",
        );
        assert!(source.has_headers);
        assert_eq!(source.subject.as_deref(), Some("Hello there"));
        assert_eq!(source.body, "The body text.");

        let plain = read_source("Dear Sam, here is the plan: Monday at 9.");
        assert!(!plain.has_headers);
        assert!(plain.body.starts_with("Dear Sam"));
        assert!(read_source("Content-Transfer-Encoding: base64\n\nYWJj").encoded);
    }

    #[test]
    fn html_is_reduced_to_what_a_reader_sees() {
        let content = read(
            "<style>p{color:red}</style><p>Verify&nbsp;your <b>Account</b> now &amp; pay</p><script>x()</script>",
            None,
        );
        assert_eq!(content.text, "verify your account now & pay");
        assert!(matches!(content.elements[..], [Element::Script]));
    }

    #[test]
    fn anchors_keep_their_words_and_images_in_them_are_described() {
        let content = read(
            "<a href=\"https://evil.example/x\">www.paypal.com</a><a href=\"https://b.example\"><img src=\"x.png\" alt=\"Open your invoice\"></a><a href=\"https://c.example\"><button>Pay now</button></a>",
            None,
        );
        let shown: Vec<_> = content.links.iter().map(|l| l.shown.as_deref()).collect();
        assert_eq!(
            shown,
            [
                Some("www.paypal.com"),
                Some("Open your invoice"),
                Some("Pay now")
            ]
        );
        assert_eq!(content.images, 1);
    }

    #[test]
    fn written_addresses_are_found_once_even_when_they_are_also_links() {
        let content = read(
            "<a href=\"https://a.example/p\">https://a.example/p</a> and see http://b.example/x, then https://c.example.",
            None,
        );
        let hrefs: Vec<_> = content.links.iter().map(|l| l.href.as_str()).collect();
        assert_eq!(
            hrefs,
            [
                "https://a.example/p",
                "http://b.example/x",
                "https://c.example"
            ]
        );
    }

    #[test]
    fn forms_and_refresh_instructions_are_noted() {
        let content = read(
            "<meta http-equiv=\"refresh\" content=\"0; url=https://evil.example/go\"><form action=\"https://collect.example/post\"><input type=\"password\"></form>",
            None,
        );
        assert!(content.elements.iter().any(|e| matches!(
            e,
            Element::Refresh { target } if target == "https://evil.example/go"
        )));
        assert!(content.elements.iter().any(|e| matches!(
            e,
            Element::Form { action: Some(a), password: true } if a == "https://collect.example/post"
        )));
    }

    #[test]
    fn malformed_html_and_entities_do_not_break_reading() {
        let content = read(
            "<p>Fish &amp; chips <b>unclosed <a href=\"https://x.example\">link",
            None,
        );
        assert_eq!(content.text, "fish & chips unclosed link");
        assert_eq!(content.links.len(), 1);
    }

    #[test]
    fn the_subject_is_part_of_the_text_and_curly_apostrophes_are_plain() {
        let content = read("Don\u{2019}t worry.", Some("Final NOTICE"));
        assert_eq!(content.text, "final notice don't worry.");
    }
}
