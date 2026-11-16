// Small helpers for finding words and phrases in lower case text.

// The words of a text. Apostrophes and hyphens stay inside words, so "don't" and "one-time"
// are one word each.
pub fn tokens(text: &str) -> Vec<&str> {
    text.split(|c: char| !(c.is_alphanumeric() || c == '\'' || c == '-'))
        .filter(|word| !word.is_empty())
        .collect()
}

// Every place a phrase starts, as an index into the words. A phrase only matches whole words,
// so "ups" is not found inside "groups".
pub fn find_phrase(words: &[&str], phrase: &[&str]) -> Vec<usize> {
    if phrase.is_empty() || words.len() < phrase.len() {
        return Vec::new();
    }
    (0..=words.len() - phrase.len())
        .filter(|&start| words[start..start + phrase.len()] == *phrase)
        .collect()
}

pub fn has_phrase(words: &[&str], phrase: &str) -> bool {
    !find_phrase(words, &tokens(phrase)).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phrases_match_whole_words_only() {
        let words = tokens("buy gift cards for the groups, not bitcoins");
        assert!(has_phrase(&words, "gift cards"));
        assert!(!has_phrase(&words, "gift card"));
        assert!(!has_phrase(&words, "ups"));
        assert!(!has_phrase(&words, "bitcoin"));
    }

    #[test]
    fn apostrophes_and_hyphens_stay_inside_words() {
        assert_eq!(
            tokens("don't use a one-time code."),
            ["don't", "use", "a", "one-time", "code"]
        );
    }
}
