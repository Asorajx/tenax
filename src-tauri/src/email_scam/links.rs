// Looks at the links and page elements of an email for signs that they are not what they seem.
// Nothing here follows a link or contacts a site. Only the addresses are read, so a link that
// goes through a tracking or shortening service has a destination that is not known.

use url::{Host, Url};

use super::content::{Element, RawLink};
use super::words::{has_phrase, tokens};
use crate::finding::{Status, count_of};

pub struct Issue {
    pub status: Status,
    pub label: String,
    pub value: String,
    // Why it matters, when the value is only a name and the reason would repeat for each one.
    pub reason: Option<String>,
}

// One link in the email with a short assessment of it.
pub struct Item {
    pub url: String,
    pub status: Status,
    pub assessment: String,
}

pub struct Report {
    // Each web link on its own, in the order it appears and without repeats.
    pub items: Vec<Item>,
    // How many links had an address that could be read.
    pub analysed: usize,
    pub issues: Vec<Issue>,
    // How many links go somewhere that is not visible in the email.
    pub unknown: usize,
    // How many links are not complete web addresses.
    pub incomplete: usize,
    // Plain reasons the analysis is limited.
    pub limits: Vec<String>,
}

impl Report {
    // Whether anything worth acting on was found.
    pub fn concern(&self) -> bool {
        self.issues
            .iter()
            .any(|issue| matches!(issue.status, Status::Risk | Status::Warning))
    }
}

// =========================
// Companies and services
// =========================

// Companies that scammers pretend to be, with the registered domains that belong to them.
// A domain belongs to a company only if it is exactly one of these, never by containing the name.
struct Brand {
    key: &'static str,
    name: &'static str,
    domains: &'static [&'static str],
}

const BRANDS: &[Brand] = &[
    Brand {
        key: "paypal",
        name: "PayPal",
        domains: &["paypal.com", "paypal.me"],
    },
    Brand {
        key: "microsoft",
        name: "Microsoft",
        domains: &[
            "microsoft.com",
            "office.com",
            "live.com",
            "outlook.com",
            "microsoftonline.com",
            "office365.com",
            "windows.com",
            "sharepoint.com",
        ],
    },
    Brand {
        key: "apple",
        name: "Apple",
        domains: &["apple.com", "icloud.com"],
    },
    Brand {
        key: "amazon",
        name: "Amazon",
        domains: &[
            "amazon.com",
            "amazon.co.uk",
            "amazon.com.au",
            "amazon.ca",
            "amazon.de",
            "amazon.in",
            "amazon.fr",
        ],
    },
    Brand {
        key: "google",
        name: "Google",
        domains: &[
            "google.com",
            "google.co.uk",
            "google.com.au",
            "google.ca",
            "google.de",
            "google.fr",
            "google.co.in",
            "gmail.com",
            "youtube.com",
        ],
    },
    Brand {
        key: "netflix",
        name: "Netflix",
        domains: &["netflix.com"],
    },
    Brand {
        key: "dhl",
        name: "DHL",
        domains: &["dhl.com", "dhl.de"],
    },
    Brand {
        key: "fedex",
        name: "FedEx",
        domains: &["fedex.com"],
    },
    Brand {
        key: "docusign",
        name: "DocuSign",
        domains: &["docusign.com", "docusign.net"],
    },
    Brand {
        key: "dropbox",
        name: "Dropbox",
        domains: &["dropbox.com"],
    },
    Brand {
        key: "linkedin",
        name: "LinkedIn",
        domains: &["linkedin.com"],
    },
    Brand {
        key: "facebook",
        name: "Facebook",
        domains: &["facebook.com", "fb.com", "meta.com", "instagram.com"],
    },
];

fn brand_of(registered: &str) -> Option<&'static Brand> {
    BRANDS
        .iter()
        .find(|brand| brand.domains.contains(&registered))
}

// Services that shorten links. The real destination is hidden until the link is opened.
const SHORTENERS: &[&str] = &[
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "tiny.cc",
    "rb.gy",
];

// Email services whose links count clicks and then pass the reader on. These are normal in
// newsletters and receipts, but they hide the real destination.
const TRACKING_SERVICES: &[&str] = &[
    "sendgrid.net",
    "list-manage.com",
    "mailchi.mp",
    "mandrillapp.com",
    "mcsv.net",
    "rsgsv.net",
    "mailgun.org",
    "sparkpostmail.com",
    "postmarkapp.com",
    "mailjet.com",
    "amazonses.com",
    "hubspotemail.net",
    "constantcontact.com",
    "rs6.net",
    "sendibt3.com",
    "customeriomail.com",
    "klaviyomail.com",
    "exacttarget.com",
    "marketo.com",
];

// The first part of an address on a tracking server, such as "click" in "click.mailer.example".
const TRACKING_LABELS: &[&str] = &[
    "click", "clicks", "track", "tracking", "trk", "links", "link", "email", "em", "go", "url",
    "redirect", "r", "t", "e",
];

// Endings that are free or cheap to register and often used in scams, or that can be mistaken
// for a file name. Only a note, since honest sites use them too.
const ODD_ENDINGS: &[&str] = &["zip", "mov", "tk", "ml", "ga", "cf", "gq"];

// Names of the parts of a link address that often hold the real destination.
const REDIRECT_KEYS: &[&str] = &[
    "url",
    "u",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "redirecturl",
    "target",
    "dest",
    "destination",
    "link",
    "goto",
    "return",
    "next",
    "continue",
    "q",
    "to",
    "r",
    "href",
    "out",
];

// =========================
// Domains
// =========================

// The name a site is registered under, such as "paypal.com" for "www.paypal.com", worked out
// with the public suffix list so that endings like "co.uk" are handled correctly.
pub(crate) fn registered(host: &str) -> Option<String> {
    psl::domain(host.as_bytes()).map(|d| String::from_utf8_lossy(d.as_bytes()).into_owned())
}

fn ending_of(host: &str) -> Option<String> {
    psl::suffix(host.as_bytes()).map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
}

// A letter that looks like a plain one, such as the Cyrillic "а" that looks like "a".
fn look_alike(c: char) -> char {
    match c {
        '\u{430}' | '\u{3b1}' => 'a', // Cyrillic and Greek a
        '\u{435}' => 'e',             // Cyrillic e
        '\u{43e}' | '\u{3bf}' => 'o', // Cyrillic and Greek o
        '\u{440}' | '\u{3c1}' => 'p', // Cyrillic and Greek p
        '\u{441}' => 'c',             // Cyrillic c
        '\u{443}' => 'y',             // Cyrillic y
        '\u{445}' => 'x',             // Cyrillic x
        '\u{456}' | '\u{131}' => 'i', // Cyrillic i and dotless i
        '\u{455}' => 's',             // Cyrillic s
        '\u{458}' => 'j',             // Cyrillic j
        '\u{3bd}' => 'v',             // Greek nu
        '\u{4cf}' => 'l',             // Cyrillic palochka
        other => other,
    }
}

// What a name looks like at a glance: look-alike letters made plain, and the digits and pairs
// of letters that stand in for others ("paypa1", "rnicrosoft") replaced.
fn skeleton(name: &str, one_as: char) -> String {
    let plain: String = name
        .chars()
        .map(look_alike)
        .map(|c| match c {
            '0' => 'o',
            '1' => one_as,
            '3' => 'e',
            '5' | '$' => 's',
            '@' => 'a',
            other => other,
        })
        .collect();
    plain.replace("rn", "m").replace("vv", "w")
}

fn skeleton_equals(name: &str, key: &str) -> bool {
    skeleton(name, 'l') == key || skeleton(name, 'i') == key
}

fn edit_distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, x) in a.iter().enumerate() {
        let mut previous = row[0];
        row[0] = i + 1;
        for (j, y) in b.iter().enumerate() {
            let current = row[j + 1];
            row[j + 1] = if x == y {
                previous
            } else {
                1 + previous.min(row[j]).min(current)
            };
            previous = current;
        }
    }
    row[b.len()]
}

fn is_cyrillic(c: char) -> bool {
    ('\u{400}'..='\u{4ff}').contains(&c)
}

fn is_greek(c: char) -> bool {
    ('\u{370}'..='\u{3ff}').contains(&c)
}

// Whether a name mixes alphabets, such as Latin letters with Cyrillic ones.
fn mixes_alphabets(label: &str) -> bool {
    let latin = label.chars().any(|c| c.is_ascii_alphabetic());
    let cyrillic = label.chars().any(is_cyrillic);
    let greek = label.chars().any(is_greek);
    [latin, cyrillic, greek]
        .iter()
        .filter(|&&present| present)
        .count()
        > 1
}

// A site name that imitates a company, and how sure that is.
struct Imitation {
    name: &'static str,
    status: Status,
}

// Compares the name part of a registered domain with each company's name. The domains that
// really belong to the company are never passed in here.
fn imitation(registered_domain: &str) -> Option<Imitation> {
    let ending = ending_of(registered_domain)?;
    let ascii_label = registered_domain
        .strip_suffix(ending.as_str())?
        .trim_end_matches('.');
    let (label, _) = idna::domain_to_unicode(ascii_label);

    for brand in BRANDS {
        if label == brand.key {
            // The company's name with a different ending, such as "paypal.xyz".
            return Some(Imitation {
                name: brand.name,
                status: Status::Warning,
            });
        }
        if skeleton_equals(&label, brand.key) {
            return Some(Imitation {
                name: brand.name,
                status: Status::Risk,
            });
        }
        if brand.key.len() >= 6 && edit_distance(&label, brand.key) == 1 {
            return Some(Imitation {
                name: brand.name,
                status: Status::Warning,
            });
        }
    }
    None
}

// =========================
// Reading a link
// =========================

enum Target {
    Web(Url),
    // Not a complete address, so there is nowhere to check.
    Relative,
    Malformed,
    // A link that runs code instead of opening a page.
    Code,
    // Links that are not web links, such as email addresses and page anchors.
    Ignore,
}

fn target(href: &str) -> Target {
    let href = href.trim();
    let lower = href.to_ascii_lowercase();
    if href.is_empty()
        || href.starts_with('#')
        || ["mailto:", "tel:", "sms:"]
            .iter()
            .any(|s| lower.starts_with(s))
    {
        return Target::Ignore;
    }
    if ["javascript:", "data:", "vbscript:"]
        .iter()
        .any(|s| lower.starts_with(s))
    {
        return Target::Code;
    }
    match Url::parse(href) {
        Ok(url) if matches!(url.scheme(), "http" | "https") => Target::Web(url),
        Ok(_) => Target::Ignore,
        Err(url::ParseError::RelativeUrlWithoutBase) => Target::Relative,
        Err(_) => Target::Malformed,
    }
}

// The part of an address between "://" and the first "/", "?" or "#".
fn authority(raw: &str) -> &str {
    let rest = raw.split_once("://").map_or(raw, |(_, rest)| rest);
    rest.split(['/', '?', '#']).next().unwrap_or("")
}

// Reads standard or URL-safe base64 as text, if it is an address.
fn base64_address(value: &str) -> Option<String> {
    if value.len() < 8 {
        return None;
    }
    let (mut bits, mut count, mut out) = (0u32, 0u32, Vec::new());
    for c in value.trim_end_matches('=').chars() {
        let sextet = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            _ => return None,
        };
        bits = (bits << 6) | sextet;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    let text = String::from_utf8(out).ok()?;
    text.starts_with("http").then_some(text)
}

// An address hidden in a link's query, such as "?url=https%3A%2F%2Fexample.com" or the same in
// base64. This reads the address and does not follow it.
fn embedded_destination(url: &Url) -> Option<Url> {
    for (key, value) in url.query_pairs() {
        if !REDIRECT_KEYS.contains(&key.to_ascii_lowercase().as_str()) {
            continue;
        }
        let value = value.trim();
        for candidate in [Some(value.to_string()), base64_address(value)]
            .into_iter()
            .flatten()
        {
            if let Ok(found) = Url::parse(&candidate)
                && matches!(found.scheme(), "http" | "https")
                && found.host_str() != url.host_str()
            {
                return Some(found);
            }
        }
    }
    None
}

// A site name written in link text, such as "www.paypal.com" in "Log in at www.paypal.com".
fn site_in_text(shown: &str) -> Option<String> {
    const FILE_ENDINGS: &[&str] = &[
        "pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt", "html", "htm",
    ];

    shown.split_whitespace().find_map(|word| {
        let word = word.trim_matches(['.', ',', ';', ':', '(', ')', '[', ']', '<', '>', '"', '\'']);
        let word = word
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let site = word.split(['/', '?', '#']).next()?.to_lowercase();
        let ending = site.rsplit('.').next()?;
        let valid = site.contains('.')
            && site
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
            && ending.len() >= 2
            && ending.chars().all(|c| c.is_ascii_alphabetic())
            && !FILE_ENDINGS.contains(&ending);
        valid.then(|| site.trim_start_matches("www.").to_string())
    })
}

// =========================
// Analysis
// =========================

// What is known about the site a link names.
#[derive(Default)]
struct Site {
    host: String,
    registered: Option<String>,
    tracking: bool,
    shortened: bool,
}

#[derive(Default)]
struct Context {
    issues: Vec<Issue>,
    analysed: usize,
    // Links whose destination is hidden behind a tracking or shortening service.
    hidden: usize,
    incomplete: usize,
    // Addresses whose name cannot be checked against the public suffix list, such as "intranet".
    unresolved: usize,
    // The registered domains the links really lead to, where that is known.
    destinations: Vec<String>,
}

impl Context {
    fn add(&mut self, status: Status, label: &str, value: String) {
        self.issues.push(Issue {
            status,
            label: label.to_string(),
            value,
            reason: None,
        });
    }

    // A point that is made about many links at once, such as a tracking address. The value is
    // just the site, and the reason is said once however many sites there are.
    fn add_named(&mut self, status: Status, label: &str, site: String, reason: String) {
        self.issues.push(Issue {
            status,
            label: label.to_string(),
            value: site,
            reason: Some(reason),
        });
    }

    // Reads one link and says in a few words what was found about it. A link that is not a web
    // link, such as an email address, has nothing to say.
    fn assess(&mut self, link: &RawLink) -> Option<Item> {
        let (before, hidden, incomplete) = (self.issues.len(), self.hidden, self.incomplete);
        self.link(link);
        if matches!(target(&link.href), Target::Ignore) {
            return None;
        }

        let found = &self.issues[before..];
        let hidden = self.hidden > hidden;
        let concerns: Vec<&Issue> = found
            .iter()
            .filter(|issue| matches!(issue.status, Status::Risk | Status::Warning))
            .collect();

        let (status, assessment) = if let Some(worst) = concerns.iter().map(|i| i.status).min() {
            let labels: Vec<&str> = concerns.iter().take(2).map(|i| i.label.as_str()).collect();
            let more = if hidden {
                " · destination not visible"
            } else {
                ""
            };
            (worst, format!("{}{more}", labels.join(" · ")))
        } else if hidden {
            (Status::Limited, "Destination not visible".to_string())
        } else if self.incomplete > incomplete {
            (Status::Limited, "Incomplete address".to_string())
        } else if let Some(note) = found.first() {
            (Status::Info, note.label.clone())
        } else {
            (Status::Ok, "No problems found".to_string())
        };
        Some(Item {
            url: link.href.trim().to_string(),
            status,
            assessment,
        })
    }

    fn link(&mut self, link: &RawLink) {
        match target(&link.href) {
            Target::Ignore => {}
            Target::Code => self.add(
                Status::Risk,
                "Link runs code",
                "A link in the email runs a script instead of opening a site".to_string(),
            ),
            Target::Relative | Target::Malformed => self.incomplete += 1,
            Target::Web(url) => self.web(&url, &link.href, link.shown.as_deref()),
        }
    }

    fn web(&mut self, url: &Url, raw: &str, shown: Option<&str>) {
        self.analysed += 1;
        let carrier = self.check_site(url, raw);

        // A destination written into the link can be read, so it is checked as well.
        let destination = embedded_destination(url);
        let destination_site = destination.as_ref().map(|found| {
            let site = self.check_site(found, found.as_str());
            self.add(
                Status::Info,
                "Redirect link",
                format!("{} passes you on to {}", carrier.host, site.host),
            );
            site
        });

        let hidden = (carrier.tracking || carrier.shortened) && destination_site.is_none();
        if hidden {
            self.hidden += 1;
        } else if let Some(registered) = destination_site
            .as_ref()
            .unwrap_or(&carrier)
            .registered
            .clone()
        {
            self.destinations.push(registered);
        }

        self.compare_text(shown, &carrier, destination_site.as_ref(), hidden);
    }

    // The words say one site and the link goes to another.
    fn compare_text(
        &mut self,
        shown: Option<&str>,
        carrier: &Site,
        destination: Option<&Site>,
        hidden: bool,
    ) {
        let Some(site) = shown.and_then(site_in_text) else {
            return;
        };
        let Some(shown_registered) = registered(&site) else {
            return;
        };
        let actual = destination.unwrap_or(carrier);
        let Some(actual_registered) = actual.registered.as_deref() else {
            return;
        };
        if shown_registered == actual_registered {
            return;
        }

        let imitates = brand_of(&shown_registered).is_some();
        if hidden {
            // A tracking link is expected to lead somewhere else, so only a company name is a worry.
            if imitates {
                self.add(
                    Status::Warning,
                    "Link text differs from where it goes",
                    format!("Shows {site}, but opens through {}, so the real destination is not visible", actual.host),
                );
            }
            return;
        }
        self.add(
            if imitates {
                Status::Risk
            } else {
                Status::Warning
            },
            "Link text differs from where it goes",
            format!("Shows {site}, goes to {}", actual.host),
        );
    }

    fn check_site(&mut self, url: &Url, raw: &str) -> Site {
        let Some(host) = url.host() else {
            return Site::default();
        };
        let shown_host = url.host_str().unwrap_or("").to_string();

        if !url.username().is_empty() || url.password().is_some() {
            self.add(
                Status::Risk,
                "Hides the real destination",
                format!("A name in front of {shown_host} is there to mislead you"),
            );
        }
        if authority(raw).contains('%') {
            self.add(
                Status::Warning,
                "Encoded address",
                "The site name is written with encoded characters, which can hide it".to_string(),
            );
        }
        if url.scheme() == "http" {
            self.add_named(
                Status::Info,
                "Not encrypted",
                shown_host.clone(),
                "Reached without https, so what you send is not encrypted".to_string(),
            );
        }

        let domain = match host {
            Host::Domain(domain) => domain,
            Host::Ipv4(_) | Host::Ipv6(_) => {
                self.add(
                    Status::Risk,
                    "Address is a number",
                    format!("{shown_host} is a numeric address, not the name of a company"),
                );
                return Site {
                    host: shown_host,
                    ..Site::default()
                };
            }
        };

        let registered_domain = registered(domain);
        if registered_domain.is_none() {
            self.unresolved += 1;
        }
        let (unicode, _) = idna::domain_to_unicode(domain);
        let display = if unicode == domain {
            domain.to_string()
        } else {
            format!("{unicode} ({domain})")
        };
        let owner = registered_domain.as_deref().and_then(brand_of);

        // Letters from other alphabets can imitate plain ones.
        if unicode != domain {
            if unicode.split('.').any(mixes_alphabets) {
                self.add(
                    Status::Risk,
                    "Mixed alphabets",
                    format!("{display} mixes alphabets, a trick used to imitate another site"),
                );
            } else if owner.is_none()
                && let Some(brand) = BRANDS.iter().find(|brand| {
                    unicode
                        .split('.')
                        .any(|label| label != brand.key && skeleton_equals(label, brand.key))
                })
            {
                self.add(
                    Status::Risk,
                    &format!("Looks like {}", brand.name),
                    format!("{display} imitates {} with look-alike letters", brand.name),
                );
            } else {
                self.add_named(
                    Status::Info,
                    "International characters",
                    display.clone(),
                    "Uses non-English characters, which can imitate another site".to_string(),
                );
            }
        }

        // A site name that borrows a company's name without being the company's address.
        if owner.is_none() {
            let subdomain = registered_domain
                .as_deref()
                .and_then(|r| domain.strip_suffix(r))
                .unwrap_or("")
                .trim_end_matches('.');
            let own_label = registered_domain
                .as_deref()
                .and_then(|r| r.split('.').next())
                .unwrap_or("");
            let parts: Vec<&str> = subdomain
                .split(['.', '-'])
                .chain(own_label.split('-').filter(|_| own_label.contains('-')))
                .collect();

            if let Some(brand) = BRANDS.iter().find(|brand| parts.contains(&brand.key)) {
                self.add(
                    Status::Risk,
                    &format!("Looks like {}", brand.name),
                    format!("{display} is not a {} address", brand.name),
                );
            } else if let Some(found) = registered_domain.as_deref().and_then(imitation) {
                self.add(
                    found.status,
                    &format!("Looks like {}", found.name),
                    format!("{display} is not a {} address", found.name),
                );
            }
        }

        let shortened = registered_domain
            .as_deref()
            .is_some_and(|r| SHORTENERS.contains(&r));
        if shortened {
            self.add_named(
                Status::Warning,
                "Shortened link",
                shown_host.clone(),
                "Hides where the link really goes".to_string(),
            );
        }

        // A company's own click-tracking addresses are fine. Others hide the destination.
        let first_label = domain.split('.').next().unwrap_or("");
        let tracking = owner.is_none()
            && !shortened
            && (registered_domain
                .as_deref()
                .is_some_and(|r| TRACKING_SERVICES.contains(&r))
                || (domain.split('.').count() >= 3 && TRACKING_LABELS.contains(&first_label)));
        if tracking {
            self.add_named(
                Status::Info,
                "Tracking link",
                shown_host.clone(),
                "Counts clicks before passing you on".to_string(),
            );
        }

        if let Some(ending) = ending_of(domain)
            && ODD_ENDINGS.contains(&ending.as_str())
        {
            self.add_named(
                Status::Info,
                "Unusual ending",
                shown_host.clone(),
                format!(".{ending} is often used in scams, though not always"),
            );
        }

        Site {
            host: shown_host,
            registered: registered_domain,
            tracking,
            shortened,
        }
    }

    fn element(&mut self, element: &Element) {
        match element {
            Element::Script => self.add(
                Status::Warning,
                "Script in the email",
                "Email programs normally block scripts, so one is unusual".to_string(),
            ),
            Element::Frame => self.add(
                Status::Warning,
                "Embedded page",
                "The email can show another page inside it, which is unusual".to_string(),
            ),
            Element::Form { action, password } => {
                let site = match action.as_deref().map(target) {
                    Some(Target::Web(url)) => {
                        Some(self.check_site(&url, action.as_deref().unwrap_or("")))
                    }
                    _ => None,
                };
                let destination = site.map_or("a page".to_string(), |site| site.host);
                if *password {
                    self.add(
                        Status::Risk,
                        "Password box in the email",
                        format!("A password typed here would be sent to {destination}"),
                    );
                } else {
                    self.add(
                        Status::Warning,
                        "Form in the email",
                        format!("Details typed here would be sent to {destination}"),
                    );
                }
            }
            Element::Refresh { target: address } => {
                self.add(
                    Status::Warning,
                    "Redirects when opened",
                    "The email sends the reader to another page as soon as it opens".to_string(),
                );
                if let Target::Web(url) = target(address) {
                    self.check_site(&url, address);
                }
            }
        }
    }

    // Companies the email says it is from, when none of its links go to that company. This is
    // only said when every link's destination is known, so a tracking link is not blamed.
    fn claims(&mut self, text: &str) {
        const ROLES: &[&str] = &[
            "security", "support", "team", "service", "billing", "customer",
        ];
        if self.hidden > 0 || self.incomplete > 0 || self.destinations.is_empty() {
            return;
        }
        let words = tokens(text);
        let destinations = self.destinations.clone();
        for brand in BRANDS {
            let claimed = ROLES
                .iter()
                .any(|role| has_phrase(&words, &format!("{} {role}", brand.key)));
            if claimed
                && !destinations
                    .iter()
                    .any(|d| brand.domains.contains(&d.as_str()))
            {
                self.add(
                    Status::Warning,
                    &format!("Claims to be {}", brand.name),
                    format!("No link goes to a {} address", brand.name),
                );
            }
        }
    }
}

pub fn analyse(links: &[RawLink], elements: &[Element], text: &str) -> Report {
    let mut context = Context::default();
    let mut items: Vec<Item> = Vec::new();
    for link in links {
        if let Some(item) = context.assess(link)
            && !items.iter().any(|known| known.url == item.url)
        {
            items.push(item);
        }
    }
    for element in elements {
        context.element(element);
    }
    context.claims(text);

    // The same point can come up for many links, so each is made once.
    let mut seen: Vec<(String, String)> = Vec::new();
    let mut issues = std::mem::take(&mut context.issues);
    issues.retain(|issue| {
        let key = (issue.label.clone(), issue.value.clone());
        !seen.contains(&key) && {
            seen.push(key);
            true
        }
    });
    // Points that only name a site are joined, so "Tracking link" is one row for all of them.
    let mut joined: Vec<Issue> = Vec::new();
    for issue in issues {
        let same = joined.iter_mut().find(|known| {
            known.reason.is_some() && known.label == issue.label && known.reason == issue.reason
        });
        match same {
            Some(known) => known.value = format!("{}, {}", known.value, issue.value),
            None => joined.push(issue),
        }
    }
    let mut issues = joined;
    // The most serious are listed first.
    issues.sort_by_key(|issue| issue.status);

    let mut limits = Vec::new();
    if context.hidden > 0 {
        limits.push(format!(
            "{} {} through a tracking or shortening service, so where {} is not visible.",
            count_of(context.hidden, "link"),
            if context.hidden == 1 {
                "passes"
            } else {
                "pass"
            },
            if context.hidden == 1 {
                "it finally leads"
            } else {
                "they finally lead"
            },
        ));
    }
    if context.unresolved > 0 {
        limits.push(format!(
            "{} could not be fully examined, because {} not a normal public web address.",
            count_of(context.unresolved, "address"),
            if context.unresolved == 1 {
                "its name is"
            } else {
                "their names are"
            },
        ));
    }
    if context.incomplete > 0 {
        limits.push(format!(
            "{} {} incomplete or malformed, so where {} cannot be told.",
            count_of(context.incomplete, "link"),
            if context.incomplete == 1 { "is" } else { "are" },
            if context.incomplete == 1 {
                "it goes"
            } else {
                "they go"
            },
        ));
    }

    Report {
        items,
        analysed: context.analysed,
        unknown: context.hidden + context.incomplete,
        incomplete: context.incomplete,
        issues,
        limits,
    }
}

// =========================
// Tests
// =========================

#[cfg(test)]
mod tests {
    use super::*;

    fn links(hrefs: &[&str]) -> Vec<RawLink> {
        hrefs
            .iter()
            .map(|href| RawLink {
                href: href.to_string(),
                shown: None,
            })
            .collect()
    }

    fn shown(href: &str, text: &str) -> Vec<RawLink> {
        vec![RawLink {
            href: href.to_string(),
            shown: Some(text.to_string()),
        }]
    }

    fn has(report: &Report, label: &str) -> bool {
        report.issues.iter().any(|issue| issue.label == label)
    }

    fn status_of(report: &Report, label: &str) -> Option<Status> {
        report
            .issues
            .iter()
            .find(|issue| issue.label == label)
            .map(|i| i.status)
    }

    #[test]
    fn registered_domains_use_the_public_suffix_list() {
        assert_eq!(registered("www.paypal.com").as_deref(), Some("paypal.com"));
        assert_eq!(
            registered("login.shop.example.co.uk").as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(
            registered("a.b.example.com.au").as_deref(),
            Some("example.com.au")
        );
    }

    #[test]
    fn a_companys_own_addresses_are_never_flagged() {
        let report = analyse(
            &links(&[
                "https://www.paypal.com/signin",
                "https://login.microsoftonline.com/x",
                "https://www.amazon.co.uk/gp",
            ]),
            &[],
            "",
        );
        assert!(report.issues.is_empty());
        assert_eq!(report.analysed, 3);
        assert_eq!(report.unknown, 0);
    }

    #[test]
    fn a_company_name_in_the_wrong_place_is_impersonation() {
        for href in [
            "https://paypal.com.login-check.example/verify",
            "https://paypal-secure.example/login",
            "https://secure.paypal.verify-now.example/",
        ] {
            let report = analyse(&links(&[href]), &[], "");
            assert_eq!(
                status_of(&report, "Looks like PayPal"),
                Some(Status::Risk),
                "{href}"
            );
        }
    }

    #[test]
    fn containing_a_name_is_not_the_same_as_being_the_company() {
        // None of these have the company name as a whole part, so none are impersonation.
        let report = analyse(
            &links(&[
                "https://notpaypal.com",
                "https://pineapple.example",
                "https://paypalm.example",
            ]),
            &[],
            "",
        );
        assert!(!report.issues.iter().any(|i| i.status == Status::Risk));
    }

    #[test]
    fn look_alike_spellings_are_caught_by_how_sure_they_are() {
        let leet = analyse(
            &links(&["https://paypa1.com/login", "https://rnicrosoft.com"]),
            &[],
            "",
        );
        assert!(has(&leet, "Looks like PayPal"));
        assert!(has(&leet, "Looks like Microsoft"));
        assert!(
            leet.issues
                .iter()
                .all(|i| i.status == Status::Risk || i.status == Status::Info)
        );

        // One letter away is only a warning, and short names are not compared that way.
        let near = analyse(
            &links(&["https://paypall.com", "https://apples.com"]),
            &[],
            "",
        );
        assert_eq!(status_of(&near, "Looks like PayPal"), Some(Status::Warning));
        assert!(!has(&near, "Looks like Apple"));
    }

    #[test]
    fn homograph_and_international_names_are_told_apart() {
        // A Cyrillic "a" in "paypal", and a name that mixes alphabets in one word.
        let imitating = analyse(&links(&["https://p\u{430}ypal.com/login"]), &[], "");
        assert_eq!(
            status_of(&imitating, "Looks like PayPal"),
            Some(Status::Risk)
        );
        let mixed = analyse(&links(&["https://exa\u{43c}ple.com"]), &[], "");
        assert_eq!(status_of(&mixed, "Mixed alphabets"), Some(Status::Risk));
        // An honest international name is only a note.
        let plain = analyse(&links(&["https://m\u{fc}nchen.example"]), &[], "");
        assert_eq!(
            status_of(&plain, "International characters"),
            Some(Status::Info)
        );
        // Punycode as written is read the same way.
        let punycode = analyse(&links(&["https://xn--pypal-4ve.com"]), &[], "");
        assert!(has(&punycode, "Looks like PayPal") || has(&punycode, "International characters"));
    }

    #[test]
    fn numeric_hidden_and_encoded_addresses_are_serious() {
        let report = analyse(
            &links(&[
                "https://192.168.1.5/login",
                "http://3232235777/login",
                "https://paypal.com@evil.example/",
                "https://%65vil.example/",
            ]),
            &[],
            "",
        );
        assert_eq!(
            status_of(&report, "Address is a number"),
            Some(Status::Risk)
        );
        assert_eq!(
            status_of(&report, "Hides the real destination"),
            Some(Status::Risk)
        );
        assert_eq!(status_of(&report, "Encoded address"), Some(Status::Warning));
        // Both the dotted and the single-number forms are caught.
        assert_eq!(
            report
                .issues
                .iter()
                .filter(|i| i.label == "Address is a number")
                .count(),
            2
        );
    }

    #[test]
    fn shortened_links_are_a_warning_with_an_unknown_destination() {
        let report = analyse(&links(&["https://bit.ly/3abc"]), &[], "");
        assert_eq!(status_of(&report, "Shortened link"), Some(Status::Warning));
        assert_eq!(report.unknown, 1);
        assert!(report.limits[0].contains("not visible"));
    }

    #[test]
    fn tracking_links_are_normal_but_their_destination_is_unknown() {
        let report = analyse(
            &links(&[
                "https://click.mailer.example.com/c/abc",
                "https://u123.ct.sendgrid.net/ls/click?upn=x",
            ]),
            &[],
            "",
        );
        assert!(!report.concern());
        assert_eq!(status_of(&report, "Tracking link"), Some(Status::Info));
        assert_eq!(report.unknown, 2);
        // A company's own tracking address is simply its address.
        let own = analyse(&links(&["https://click.paypal.com/x"]), &[], "");
        assert!(own.issues.is_empty());
        assert_eq!(own.unknown, 0);
    }

    #[test]
    fn a_destination_written_into_a_link_is_read_and_checked() {
        let percent = analyse(
            &links(&[
                "https://track.example.com/r?url=https%3A%2F%2Fpaypal.com.evil.example%2Flogin",
            ]),
            &[],
            "",
        );
        assert!(has(&percent, "Redirect link"));
        assert!(has(&percent, "Looks like PayPal"));
        // The destination is known, so the link is not counted as hidden.
        assert_eq!(percent.unknown, 0);

        // The same address, written in base64.
        let encoded = analyse(
            &links(&[
                "https://track.example.com/r?u=aHR0cHM6Ly9wYXlwYWwuY29tLmV2aWwuZXhhbXBsZS9sb2dpbg",
            ]),
            &[],
            "",
        );
        assert!(has(&encoded, "Looks like PayPal"));
    }

    #[test]
    fn link_text_that_names_another_site_is_judged_by_where_it_goes() {
        // A company name shown, with a different real address: serious.
        let report = analyse(&shown("https://evil.example/x", "www.paypal.com"), &[], "");
        assert_eq!(
            status_of(&report, "Link text differs from where it goes"),
            Some(Status::Risk)
        );
        // An ordinary site shown with a different address: a warning.
        let other = analyse(
            &shown("https://elsewhere.example/x", "shop.example.com"),
            &[],
            "",
        );
        assert_eq!(
            status_of(&other, "Link text differs from where it goes"),
            Some(Status::Warning)
        );
        // The same registered domain is fine, including a different subdomain.
        let same = analyse(
            &shown("https://account.example.com/x", "www.example.com"),
            &[],
            "",
        );
        assert!(same.issues.is_empty());
        // File names are not sites.
        let file = analyse(
            &shown("https://files.example.com/a", "invoice.pdf"),
            &[],
            "",
        );
        assert!(file.issues.is_empty());
    }

    #[test]
    fn marketing_links_that_show_an_ordinary_site_are_not_blamed() {
        let report = analyse(
            &shown(
                "https://click.mailer.example.net/c/1",
                "www.shop-example.com",
            ),
            &[],
            "",
        );
        assert!(!report.concern());
        // A company name shown over a tracking link cannot be confirmed, so it is a warning.
        let branded = analyse(
            &shown("https://click.mailer.example.net/c/1", "www.paypal.com"),
            &[],
            "",
        );
        assert_eq!(
            status_of(&branded, "Link text differs from where it goes"),
            Some(Status::Warning)
        );
    }

    #[test]
    fn relative_malformed_and_code_links_are_handled_without_guessing() {
        let report = analyse(
            &links(&["/account/login", "http://", "https://exa mple.com"]),
            &[],
            "",
        );
        assert!(!report.concern());
        assert_eq!(report.unknown, 3);
        let code = analyse(
            &links(&["javascript:alert(1)", "mailto:a@b.example", "#top"]),
            &[],
            "",
        );
        assert_eq!(status_of(&code, "Link runs code"), Some(Status::Risk));
        assert_eq!(code.analysed, 0);
    }

    #[test]
    fn page_elements_are_judged_by_what_they_could_do() {
        let report = analyse(
            &[],
            &[
                Element::Script,
                Element::Frame,
                Element::Refresh {
                    target: "https://evil.example/go".to_string(),
                },
                Element::Form {
                    action: Some("https://collect.example/post".to_string()),
                    password: true,
                },
                Element::Form {
                    action: None,
                    password: false,
                },
            ],
            "",
        );
        assert_eq!(
            status_of(&report, "Script in the email"),
            Some(Status::Warning)
        );
        assert_eq!(status_of(&report, "Embedded page"), Some(Status::Warning));
        assert_eq!(
            status_of(&report, "Redirects when opened"),
            Some(Status::Warning)
        );
        assert_eq!(
            status_of(&report, "Password box in the email"),
            Some(Status::Risk)
        );
        assert_eq!(
            status_of(&report, "Form in the email"),
            Some(Status::Warning)
        );
    }

    #[test]
    fn a_claimed_sender_is_only_questioned_when_every_destination_is_known() {
        let text = "paypal security team: please review";
        let wrong = analyse(&links(&["https://other.example/review"]), &[], text);
        assert!(has(&wrong, "Claims to be PayPal"));
        let right = analyse(&links(&["https://www.paypal.com/review"]), &[], text);
        assert!(!has(&right, "Claims to be PayPal"));
        // A tracking link might lead anywhere, so nothing is claimed about it.
        let hidden = analyse(&links(&["https://click.mailer.example.com/x"]), &[], text);
        assert!(!has(&hidden, "Claims to be PayPal"));
    }

    #[test]
    fn the_same_point_is_made_once() {
        let report = analyse(
            &links(&["https://bit.ly/a", "https://bit.ly/b", "https://bit.ly/c"]),
            &[],
            "",
        );
        assert_eq!(
            report
                .issues
                .iter()
                .filter(|i| i.label == "Shortened link")
                .count(),
            1
        );
        assert_eq!(report.unknown, 3);
    }
}
