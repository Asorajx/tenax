// Finds scam wording in the text of an email.
// Each kind of wording counts once, however many phrases show it. Requests are only counted
// when a word like "send" is close to what is asked for, and not when the email says "never".

use super::words::{find_phrase, has_phrase, tokens};

// How much a kind of wording matters on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Weight {
    // Worth knowing, but not a worry.
    Note,
    // Common in ordinary email. It only matters together with other signs.
    Weak,
    // Suspicious, and more so with other signs.
    Mild,
    // Worth acting on by itself.
    Strong,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Pressure,
    Requests,
    Other,
}

enum Rule {
    // Any of these phrases.
    Phrases(&'static [&'static str]),
    // One of the verbs shortly before one of the objects, such as "send us your password".
    Ask {
        objects: &'static [&'static str],
        verbs: &'static [&'static str],
    },
    // A payment method with a word for paying or buying close by on either side.
    Payment {
        objects: &'static [&'static str],
        verbs: &'static [&'static str],
    },
}

pub struct Category {
    pub name: &'static str,
    // Why scammers use it, in plain words.
    pub why: &'static str,
    // What to do about it.
    pub advice: &'static str,
    pub weight: Weight,
    pub group: Group,
    rule: Rule,
}

// What was found for one kind of wording.
pub struct Found {
    pub category: &'static Category,
    pub phrases: Vec<String>,
}

const SLOW_DOWN: &str = "Do not act on the deadline. Contact the organisation using a number or \
                         website you already trust.";
const NEVER_SEND: &str = "Do not send passwords, codes, card or bank details in reply to an \
                          email. If it might be real, contact the organisation using a number \
                          or website you already know.";
const CHECK_OFFER: &str = "Check offers, secrets and attachments you did not expect with the \
                           sender another way before acting.";

static CATEGORIES: &[Category] = &[
    // Pressure
    Category {
        name: "Urgent wording",
        why: "Urgent wording rushes you into acting before you check",
        advice: SLOW_DOWN,
        weight: Weight::Weak,
        group: Group::Pressure,
        rule: Rule::Phrases(&[
            "urgent",
            "urgently",
            "immediately",
            "act now",
            "action required",
            "immediate action",
            "as soon as possible",
            "asap",
            "right away",
        ]),
    },
    Category {
        name: "Short deadline",
        why: "A short deadline leaves you little time to check",
        advice: SLOW_DOWN,
        weight: Weight::Weak,
        group: Group::Pressure,
        rule: Rule::Phrases(&[
            "within 24 hours",
            "within 48 hours",
            "expires today",
            "expires in 24 hours",
            "limited time",
            "final notice",
            "last warning",
        ]),
    },
    Category {
        name: "Security alert wording",
        why: "An alarming security message makes you click without thinking",
        advice: SLOW_DOWN,
        weight: Weight::Weak,
        group: Group::Pressure,
        rule: Rule::Phrases(&[
            "unusual activity",
            "suspicious activity",
            "unauthorized login",
            "unauthorised login",
            "suspicious sign-in",
            "unusual sign-in",
        ]),
    },
    Category {
        name: "Threat to your account",
        why: "Threatening to close or suspend an account creates fear",
        advice: SLOW_DOWN,
        weight: Weight::Mild,
        group: Group::Pressure,
        rule: Rule::Phrases(&[
            "account will be suspended",
            "account has been suspended",
            "account will be closed",
            "account will be locked",
            "account has been locked",
            "account has been limited",
            "account will be deactivated",
            "access will be restricted",
            "lose access to your account",
        ]),
    },
    Category {
        name: "Threat of legal action",
        why: "Threats of legal action are meant to scare you into paying",
        advice: SLOW_DOWN,
        weight: Weight::Mild,
        group: Group::Pressure,
        rule: Rule::Phrases(&["legal action", "arrest warrant", "criminal charges"]),
    },
    // Requests
    Category {
        name: "Asks for your password",
        why: "Genuine organisations do not ask for your password by email",
        advice: NEVER_SEND,
        weight: Weight::Strong,
        group: Group::Requests,
        rule: Rule::Ask {
            objects: &["password", "passcode", "login details", "login credentials"],
            verbs: &[
                "enter", "send", "provide", "confirm", "share", "give", "submit", "type", "reply",
                "supply", "reenter", "re-enter", "forward", "tell",
            ],
        },
    },
    Category {
        name: "Asks for a security code",
        why: "A code sent to you is for you alone, and scammers use it to take over accounts",
        advice: NEVER_SEND,
        weight: Weight::Strong,
        group: Group::Requests,
        rule: Rule::Ask {
            objects: &[
                "verification code",
                "security code",
                "one-time code",
                "one-time password",
                "otp",
                "authentication code",
                "login code",
            ],
            verbs: &[
                "send", "reply", "tell", "give", "share", "forward", "read", "provide",
            ],
        },
    },
    Category {
        name: "Asks for card, bank or ID details",
        why: "Card, bank and identity details are what a scam is after",
        advice: NEVER_SEND,
        weight: Weight::Strong,
        group: Group::Requests,
        rule: Rule::Ask {
            objects: &[
                "card number",
                "credit card number",
                "debit card number",
                "cvv",
                "bank account number",
                "account number",
                "routing number",
                "sort code",
                "iban",
                "social security number",
                "tax file number",
                "medicare number",
                "passport number",
            ],
            verbs: &[
                "send", "provide", "enter", "confirm", "share", "give", "submit", "reply",
                "update", "verify", "supply", "need",
            ],
        },
    },
    Category {
        name: "Asks for hard-to-trace payment",
        why: "Gift cards, wire transfers and crypto are hard to trace or reverse",
        advice: "Do not pay by gift card, wire transfer or crypto because an email asked you to. \
                 Contact the sender another way first.",
        weight: Weight::Strong,
        group: Group::Requests,
        rule: Rule::Payment {
            objects: &[
                "gift card",
                "gift cards",
                "itunes card",
                "google play card",
                "steam card",
                "western union",
                "moneygram",
                "bitcoin",
                "cryptocurrency",
                "crypto",
                "usdt",
            ],
            verbs: &[
                "buy", "purchase", "send", "pay", "paying", "payment", "transfer", "wire", "redeem",
            ],
        },
    },
    Category {
        name: "Asks for a wire transfer",
        why: "Wire transfers are hard to reverse, and fraudsters often ask for them urgently",
        advice: "Do not make a wire transfer because an email asked you to. Confirm the request                  with the person by phone, using a number you already have.",
        weight: Weight::Mild,
        group: Group::Requests,
        rule: Rule::Payment {
            objects: &["wire transfer", "wire the funds", "wire money"],
            verbs: &[
                "process", "make", "send", "arrange", "initiate", "complete", "request", "need",
                "do",
            ],
        },
    },
    Category {
        name: "Changes where payment goes",
        why: "Asking you to pay new bank details is how invoice fraud works",
        advice: "Before paying or changing any bank details, confirm the new details by phoning \
                 the supplier on a number you already have.",
        weight: Weight::Strong,
        group: Group::Requests,
        rule: Rule::Phrases(&[
            "new bank details",
            "new banking details",
            "our bank details have changed",
            "bank details have changed",
            "banking details have changed",
            "changed our bank",
            "change of bank details",
            "change of banking details",
            "updated bank details",
            "updated banking details",
            "new account number",
            "new payment details",
            "new bank account",
        ]),
    },
    Category {
        name: "Asks you to verify your account",
        why: "Asking you to verify or update an account is a common way to steal logins",
        advice: "Do not use the links in this email to log in or verify anything. Go to the \
                 organisation's website yourself.",
        weight: Weight::Mild,
        group: Group::Requests,
        rule: Rule::Phrases(&[
            "verify your account",
            "verify your identity",
            "confirm your account",
            "confirm your identity",
            "confirm your details",
            "validate your account",
            "update your account",
            "update your payment",
            "update your billing",
            "reactivate your account",
            "unlock your account",
            "restore your account",
        ]),
    },
    Category {
        name: "Overdue payment wording",
        why: "Billing pressure is common, in scams and in genuine notices",
        advice: "Check any bill you did not expect against your own records before paying.",
        weight: Weight::Weak,
        group: Group::Requests,
        rule: Rule::Phrases(&[
            "payment is overdue",
            "overdue payment",
            "unpaid invoice",
            "outstanding balance",
        ]),
    },
    // Other signs
    Category {
        name: "Generic greeting",
        why: "A generic greeting suggests the sender does not know who you are",
        advice: CHECK_OFFER,
        weight: Weight::Note,
        group: Group::Other,
        rule: Rule::Phrases(&[
            "dear customer",
            "dear user",
            "dear account holder",
            "dear client",
            "dear valued customer",
            "dear member",
            "dear sir or madam",
        ]),
    },
    Category {
        name: "Prize or windfall",
        why: "Prizes and unexpected money are a classic advance-fee scam",
        advice: CHECK_OFFER,
        weight: Weight::Strong,
        group: Group::Other,
        rule: Rule::Phrases(&[
            "you have won",
            "you've won",
            "you are the winner",
            "you are a winner",
            "claim your prize",
            "claim your winnings",
            "unclaimed funds",
            "inheritance fund",
            "beneficiary of",
            "you have been selected",
        ]),
    },
    Category {
        name: "Asks for secrecy",
        why: "Asking for secrecy stops you from checking with anyone else",
        advice: CHECK_OFFER,
        weight: Weight::Strong,
        group: Group::Other,
        rule: Rule::Phrases(&[
            "keep this confidential",
            "keep this between us",
            "do not tell anyone",
            "don't tell anyone",
            "keep this secret",
        ]),
    },
    Category {
        name: "Asks you to enable macros",
        why: "Enabling macros in a document can install malware",
        advice: CHECK_OFFER,
        weight: Weight::Strong,
        group: Group::Other,
        rule: Rule::Phrases(&["enable macros", "enable content"]),
    },
    Category {
        name: "Attachment prompt",
        why: "Unexpected attachments can carry malware",
        advice: CHECK_OFFER,
        weight: Weight::Note,
        group: Group::Other,
        rule: Rule::Phrases(&[
            "open the attachment",
            "open the attached",
            "see attached invoice",
            "see the attached invoice",
        ]),
    },
];

// =========================
// Matching
// =========================

// How many words before a request word a "never" or "not" still undoes it.
const NEGATION_REACH: usize = 5;
// How many words a request word can be from what it asks for.
const ASK_REACH: usize = 7;
const PAYMENT_REACH: usize = 8;

const NEGATIONS: &[&str] = &[
    "never", "not", "don't", "dont", "won't", "wont", "cannot", "can't", "cant", "no", "without",
    "avoid",
];

fn negated(words: &[&str], verb_at: usize) -> bool {
    words[verb_at.saturating_sub(NEGATION_REACH)..verb_at]
        .iter()
        .any(|word| NEGATIONS.contains(word))
}

fn ask(words: &[&str], objects: &[&str], verbs: &[&str]) -> Vec<String> {
    let mut found = Vec::new();
    for object in objects {
        let object_words = tokens(object);
        for at in find_phrase(words, &object_words) {
            // The closest request word before what is asked for.
            let verb = (at.saturating_sub(ASK_REACH)..at)
                .rev()
                .find(|&i| verbs.contains(&words[i]));
            if let Some(verb) = verb
                && !negated(words, verb)
            {
                found.push(words[verb..at + object_words.len()].join(" "));
            }
        }
    }
    found
}

fn payment(words: &[&str], objects: &[&str], verbs: &[&str]) -> Vec<String> {
    let mut found = Vec::new();
    for object in objects {
        let object_words = tokens(object);
        for at in find_phrase(words, &object_words) {
            let end = at + object_words.len();
            let near = (at.saturating_sub(PAYMENT_REACH)..(end + PAYMENT_REACH).min(words.len()))
                .filter(|i| !(at..end).contains(i))
                .find(|&i| verbs.contains(&words[i]));
            if let Some(verb) = near
                && !negated(words, verb)
            {
                found.push((*object).to_string());
            }
        }
    }
    found
}

fn phrases(words: &[&str], list: &[&str]) -> Vec<String> {
    list.iter()
        .filter(|phrase| has_phrase(words, phrase))
        .map(|phrase| (*phrase).to_string())
        .collect()
}

// Every kind of wording found in the text, in a fixed order.
pub fn scan(text: &str) -> Vec<Found> {
    let words = tokens(text);
    CATEGORIES
        .iter()
        .filter_map(|category| {
            let mut found = match &category.rule {
                Rule::Phrases(list) => phrases(&words, list),
                Rule::Ask { objects, verbs } => ask(&words, objects, verbs),
                Rule::Payment { objects, verbs } => payment(&words, objects, verbs),
            };
            found.sort();
            found.dedup();
            (!found.is_empty()).then_some(Found {
                category,
                phrases: found,
            })
        })
        .collect()
}

// Whether the text talks about links, such as "click here", whether or not it shows where
// they go. Text pasted from a mail app often keeps the words and loses the addresses.
pub fn refers_to_links(text: &str) -> bool {
    let words = tokens(text);
    [
        "click here",
        "click the link",
        "click the button",
        "click below",
        "follow the link",
        "link below",
        "button below",
        "tap the link",
        "log in",
        "sign in",
        "view in browser",
        "unsubscribe",
    ]
    .iter()
    .any(|phrase| has_phrase(&words, phrase))
}

// How many times the text points at a link in words, such as "click here" or "the button below".
// Each one stands for a link whose address may or may not have been pasted.
pub fn link_references(text: &str) -> usize {
    let words = tokens(text);
    [
        "click here",
        "click the link",
        "click the button",
        "click below",
        "follow the link",
        "link below",
        "button below",
        "tap the link",
    ]
    .iter()
    .map(|phrase| find_phrase(&words, &tokens(phrase)).len())
    .sum()
}

// The advice for the most serious wording found, the first one if several are as serious.
pub fn advice(found: &[&Found]) -> Option<&'static str> {
    found
        .iter()
        .max_by_key(|item| {
            (
                item.category.weight,
                std::cmp::Reverse(position(item.category)),
            )
        })
        .map(|item| item.category.advice)
}

fn position(category: &Category) -> usize {
    CATEGORIES
        .iter()
        .position(|candidate| std::ptr::eq(candidate, category))
        .unwrap_or(usize::MAX)
}

// =========================
// Tests
// =========================

#[cfg(test)]
mod tests {
    use super::*;

    fn names(text: &str) -> Vec<&'static str> {
        scan(&text.to_lowercase())
            .iter()
            .map(|f| f.category.name)
            .collect()
    }

    #[test]
    fn a_plain_message_has_nothing() {
        assert!(names("Hi Sam, lunch on Friday? I booked the usual place at one.").is_empty());
    }

    #[test]
    fn overlapping_phrases_count_as_one_kind() {
        let found = scan("urgent! act now, respond immediately and urgently");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].category.name, "Urgent wording");
        assert_eq!(found[0].phrases.len(), 4);
    }

    #[test]
    fn asking_for_something_needs_a_request_word_close_by() {
        assert!(
            names("Please send us your password to continue.").contains(&"Asks for your password")
        );
        assert!(
            names("Reply with the verification code we texted you.")
                .contains(&"Asks for a security code")
        );
        assert!(
            names("To proceed, confirm your bank account number.")
                .contains(&"Asks for card, bank or ID details")
        );
        // The same objects with no request are ordinary.
        assert!(names("Your password was changed. Your verification code is 482913.").is_empty());
        assert!(names("Your bank account number ends in 4821.").is_empty());
    }

    #[test]
    fn a_warning_not_to_share_is_not_a_request() {
        assert!(names("Never share your password or verification code with anyone.").is_empty());
        assert!(names("We will not ask you to enter your password by email.").is_empty());
        assert!(names("Do not send your card number to anyone who asks.").is_empty());
    }

    #[test]
    fn hard_to_trace_payment_needs_a_payment_word() {
        assert!(
            names("Buy gift cards and send me the codes.")
                .contains(&"Asks for hard-to-trace payment")
        );
        // A wire transfer on its own is only a mild sign, since genuine invoices offer it too.
        assert!(
            !names("Payment must be made by wire transfer today.")
                .contains(&"Asks for hard-to-trace payment")
        );
        assert!(
            names("Are you free? I need you to process an urgent wire transfer today.")
                .contains(&"Asks for a wire transfer")
        );
        assert!(names("You can pay by wire transfer or card, as you prefer.").is_empty());
        assert!(names("Bitcoin reached a new high this week.").is_empty());
        assert!(names("We never accept gift cards as payment.").is_empty());
    }

    #[test]
    fn changed_bank_details_are_invoice_fraud_wording() {
        assert!(
            names("Please note our bank details have changed. Pay to the new account number.")
                .contains(&"Changes where payment goes")
        );
    }

    #[test]
    fn threats_and_deadlines_are_kept_apart_by_weight() {
        let found = scan("your account will be suspended within 24 hours");
        let weights: Vec<_> = found.iter().map(|f| f.category.weight).collect();
        assert_eq!(weights, [Weight::Weak, Weight::Mild]);
    }

    #[test]
    fn ordinary_business_urgency_is_only_weak() {
        let found = scan(
            "please review the attached report as soon as possible, it is urgent for the board",
        );
        assert!(found.iter().all(|f| f.category.weight == Weight::Weak));
    }

    #[test]
    fn whole_words_only_and_the_text_mentioning_links() {
        assert!(names("a lotteryish thing in the groups").is_empty());
        assert!(refers_to_links("click here to log in"));
        assert!(!refers_to_links("see you on friday"));
    }

    #[test]
    fn advice_follows_the_most_serious_wording() {
        let found = scan("you have won! buy gift cards to claim your prize");
        let refs: Vec<&Found> = found.iter().collect();
        assert!(advice(&refs).unwrap().contains("gift card"));
    }
}
