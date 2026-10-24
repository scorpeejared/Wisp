use bip39::Language;
use thiserror::Error;

use crate::secret::SecretBytes;

pub const MIN_LENGTH: usize = 12;
pub const MIN_ENTROPY_BITS: f64 = 60.0;
pub const RECOMMENDED_WORD_COUNT: usize = 8;
const MIN_PHRASE_WORDS: usize = 6;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PassphraseRejection {
    #[error("must be at least {MIN_LENGTH} characters (got {got})")]
    TooShort { got: usize },

    #[error("too predictable — estimated {got} bits of entropy, need {need}")]
    TooPredictable { got: u32, need: u32 },

    #[error("this is a well-known passphrase")]
    WellKnown,

    #[error("must not be entirely whitespace")]
    Blank,
}

const WELL_KNOWN: &[&str] = &[
    "correcthorsebatterystaple",
    "correct horse battery staple",
    "passwordpassword",
    "password123456",
    "qwertyuiopasdfgh",
    "administrator123",
    "letmeinletmein",
    "iloveyouiloveyou",
    "trustno1trustno1",
    "thequickbrownfox",
    "abcdefghijklmnop",
    "1234567890123456",
];

#[derive(Debug, Clone)]
pub struct Assessment {
    pub estimated_bits: u32,
    pub is_word_phrase: bool,
    pub verdict: Result<(), PassphraseRejection>,
}

impl Assessment {
    pub fn is_acceptable(&self) -> bool {
        self.verdict.is_ok()
    }
}

pub fn generate_phrase(word_count: usize) -> SecretBytes {
    let list = Language::English.word_list();
    let mut phrase = String::with_capacity(word_count * 9);

    for i in 0..word_count {
        let mut raw = [0u8; 2];
        crate::crypto::fill_random(&mut raw);
        let index = (u16::from_le_bytes(raw) & 0x07FF) as usize;

        if i > 0 {
            phrase.push(' ');
        }
        phrase.push_str(list[index]);
    }

    let secret = SecretBytes::copy_from_slice(phrase.as_bytes());
    unsafe { phrase.as_bytes_mut().fill(b' ') };
    drop(phrase);
    secret
}

pub fn assess(passphrase: &str) -> Assessment {
    let trimmed = passphrase.trim();

    if trimmed.is_empty() {
        return Assessment {
            estimated_bits: 0,
            is_word_phrase: false,
            verdict: Err(PassphraseRejection::Blank),
        };
    }

    let normalised: String = trimmed.to_lowercase().split_whitespace().collect::<Vec<_>>().join(" ");
    let squashed: String = normalised.chars().filter(|c| !c.is_whitespace()).collect();
    if WELL_KNOWN.contains(&normalised.as_str()) || WELL_KNOWN.contains(&squashed.as_str()) {
        return Assessment {
            estimated_bits: 0,
            is_word_phrase: false,
            verdict: Err(PassphraseRejection::WellKnown),
        };
    }

    let (bits, is_word_phrase) = match word_phrase_bits(trimmed) {
        Some(bits) => (bits, true),
        None => (character_bits(passphrase), false),
    };
    let estimated_bits = bits.round().max(0.0) as u32;

    let char_len = passphrase.chars().count();
    let verdict = if char_len < MIN_LENGTH {
        Err(PassphraseRejection::TooShort { got: char_len })
    } else if bits < MIN_ENTROPY_BITS {
        Err(PassphraseRejection::TooPredictable {
            got: estimated_bits,
            need: MIN_ENTROPY_BITS as u32,
        })
    } else {
        Ok(())
    };

    Assessment {
        estimated_bits,
        is_word_phrase,
        verdict,
    }
}

pub fn enforce(passphrase: &str) -> Result<(), PassphraseRejection> {
    assess(passphrase).verdict
}

fn word_phrase_bits(input: &str) -> Option<f64> {
    let words: Vec<&str> = input.split_whitespace().collect();
    if words.len() < MIN_PHRASE_WORDS {
        return None;
    }
    let list = Language::English.word_list();
    let lowered: Vec<String> = words.iter().map(|w| w.to_lowercase()).collect();
    if !lowered.iter().all(|w| list.contains(&w.as_str())) {
        return None;
    }
    let mut distinct = lowered.clone();
    distinct.sort_unstable();
    distinct.dedup();
    Some(distinct.len() as f64 * 11.0)
}

fn character_bits(input: &str) -> f64 {
    let chars: Vec<char> = input.chars().collect();
    if chars.is_empty() {
        return 0.0;
    }

    let mut pool = 0u32;
    if chars.iter().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if chars.iter().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if chars.iter().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if chars.iter().any(|c| c.is_ascii_punctuation() || *c == ' ') {
        pool += 33;
    }
    if chars.iter().any(|c| !c.is_ascii()) {
        pool += 100;
    }
    if pool < 2 {
        pool = 2;
    }

    let base = chars.len() as f64 * (pool as f64).log2();

    let mut distinct: Vec<char> = chars.clone();
    distinct.sort_unstable();
    distinct.dedup();
    let variety = (distinct.len() as f64 / chars.len() as f64).clamp(0.35, 1.0);

    let predictable_steps = chars
        .windows(2)
        .filter(|w| {
            let (a, b) = (w[0] as i32, w[1] as i32);
            (a - b).abs() <= 1
        })
        .count();
    let run_factor = 1.0 - (predictable_steps as f64 / chars.len() as f64) * 0.6;

    base * variety * run_factor.max(0.3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_blank() {
        assert_eq!(enforce("   "), Err(PassphraseRejection::Blank));
    }

    #[test]
    fn rejects_short_even_when_complex() {
        assert!(matches!(
            enforce("aB3$xY9!"),
            Err(PassphraseRejection::TooShort { got: 8 })
        ));
    }

    #[test]
    fn length_floor_counts_characters_not_bytes() {
        assert!(matches!(
            enforce("日本語日本語日本"),
            Err(PassphraseRejection::TooShort { got: 8 })
        ));
    }

    #[test]
    fn rejects_long_but_repetitive() {
        assert!(enforce("aaaaaaaaaaaaaaaaaaaaaaaa").is_err());
    }

    #[test]
    fn rejects_sequential_runs() {
        assert!(enforce("abcdefghijklmnopqrst").is_err());
        assert!(enforce("123456789012345678").is_err());
    }

    #[test]
    fn rejects_well_known_phrases() {
        assert_eq!(
            enforce("correct horse battery staple"),
            Err(PassphraseRejection::WellKnown)
        );
        assert_eq!(
            enforce("CorrectHorseBatteryStaple"),
            Err(PassphraseRejection::WellKnown)
        );
    }

    #[test]
    fn accepts_a_strong_mixed_passphrase() {
        let a = assess("Tr0ub4dor&3xK!ncq9Zvw");
        assert!(a.is_acceptable(), "{a:?}");
        assert!(!a.is_word_phrase);
    }

    #[test]
    fn accepts_a_generated_word_phrase() {
        let secret = generate_phrase(RECOMMENDED_WORD_COUNT);
        let phrase = std::str::from_utf8(secret.as_slice()).unwrap();
        assert_eq!(phrase.split_whitespace().count(), RECOMMENDED_WORD_COUNT);

        let a = assess(phrase);
        assert!(a.is_acceptable(), "{phrase:?} -> {a:?}");
        assert!(a.is_word_phrase);
        assert!(a.estimated_bits >= 80, "got {} bits", a.estimated_bits);
    }

    #[test]
    fn generated_phrases_differ() {
        let a = generate_phrase(8);
        let b = generate_phrase(8);
        assert_ne!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn generated_phrases_always_pass_the_policy() {
        for _ in 0..200 {
            let secret = generate_phrase(RECOMMENDED_WORD_COUNT);
            let phrase = std::str::from_utf8(secret.as_slice()).unwrap();
            assert!(
                assess(phrase).is_acceptable(),
                "generated phrase was rejected: {phrase:?}"
            );
        }
    }

    #[test]
    fn word_phrase_scoring_ignores_checksum() {
        let phrase = "zebra zone youth yellow wrist wolf window width";
        let a = assess(phrase);
        assert!(a.is_word_phrase);
        assert!(a.is_acceptable(), "{a:?}");
    }

    #[test]
    fn repeated_words_do_not_inflate_the_score() {
        let a = assess("abandon abandon abandon abandon abandon abandon abandon abandon");
        assert!(!a.is_acceptable(), "{a:?}");
    }

    #[test]
    fn four_word_phrase_is_scored_as_characters_not_words() {
        let a = assess("zebra zone youth yellow");
        assert!(!a.is_word_phrase);
    }
}
