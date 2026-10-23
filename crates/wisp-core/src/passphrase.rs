//! Passphrase strength policy.
//!
//! The passphrase is the only factor an attacker who has both the drive and
//! the file still has to break, and Argon2id only multiplies whatever entropy
//! the user supplied — it cannot manufacture any. So weak passphrases are
//! rejected at creation time rather than merely discouraged.
//!
//! Two ways to satisfy the policy:
//!
//! - A generated BIP39-style word phrase (the recommended path). Eight words
//!   from the 2048-word list is 88 bits, memorable, and typeable.
//! - A user-chosen passphrase that clears both a length floor and an estimated
//!   entropy floor.
//!
//! The estimator below is intentionally conservative. It is a floor-enforcer,
//! not an oracle: it under-counts real strength for unusual passphrases, which
//! is the safe direction to be wrong in.

use bip39::Language;
use thiserror::Error;

use crate::secret::SecretBytes;

/// Below this, no amount of character variety is accepted.
pub const MIN_LENGTH: usize = 12;
/// Estimated bits required for a user-chosen passphrase.
pub const MIN_ENTROPY_BITS: f64 = 60.0;
/// Word count for generated phrases. 8 words ≈ 88 bits.
pub const RECOMMENDED_WORD_COUNT: usize = 8;
/// Fewer than this many dictionary words is not treated as a word phrase.
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

/// A handful of passphrases that clear the length and entropy floors on
/// structure alone but are the first things any cracking dictionary tries.
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

/// Result of assessing a candidate passphrase.
#[derive(Debug, Clone)]
pub struct Assessment {
    pub estimated_bits: u32,
    /// True when the input parsed as a run of dictionary words, in which case
    /// `estimated_bits` is computed from the word count instead of characters.
    pub is_word_phrase: bool,
    pub verdict: Result<(), PassphraseRejection>,
}

impl Assessment {
    pub fn is_acceptable(&self) -> bool {
        self.verdict.is_ok()
    }
}

/// Generates a fresh word phrase from the OS CSPRNG.
///
/// Words are drawn uniformly from the BIP39 English wordlist, but this is
/// **not** a BIP39 mnemonic: there is no checksum and no derived seed, and word
/// counts outside BIP39's 12/15/18/21/24 are fine. It borrows the wordlist
/// because that list is deliberately built for unambiguous transcription — no
/// two words share a four-letter prefix. Calling it a mnemonic would wrongly
/// suggest it recovers a wallet or can be restored from elsewhere; it is
/// simply a passphrase with a known, exact entropy of 11 bits per word.
///
/// Returned in protected memory, because the phrase *is* the passphrase.
pub fn generate_phrase(word_count: usize) -> SecretBytes {
    let list = Language::English.word_list();
    let mut phrase = String::with_capacity(word_count * 9);

    for i in 0..word_count {
        // 2048 divides 65536 exactly, so masking a uniform u16 down to 11 bits
        // stays uniform — no modulo bias and no rejection loop needed.
        let mut raw = [0u8; 2];
        crate::crypto::fill_random(&mut raw);
        let index = (u16::from_le_bytes(raw) & 0x07FF) as usize;

        if i > 0 {
            phrase.push(' ');
        }
        phrase.push_str(list[index]);
    }

    // Take the bytes and wipe the String's own buffer, so the only remaining
    // copy is the protected one.
    //
    // SAFETY: the buffer is overwritten with ASCII spaces, which is valid UTF-8,
    // and `phrase` is dropped immediately afterwards regardless.
    let secret = SecretBytes::copy_from_slice(phrase.as_bytes());
    unsafe { phrase.as_bytes_mut().fill(b' ') };
    drop(phrase);
    secret
}

/// Assesses a candidate passphrase against the policy.
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

    // Character count, not byte count: a short passphrase of multi-byte
    // characters must not pass the length floor on byte length alone.
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

/// Enforces the policy, discarding the detail.
pub fn enforce(passphrase: &str) -> Result<(), PassphraseRejection> {
    assess(passphrase).verdict
}

/// If every token is a BIP39 word, scores by word count (11 bits per word).
///
/// Checksum is *not* validated: a user retyping a generated phrase with one
/// word wrong still has a strong passphrase, and failing them for it would
/// only push them toward something weaker.
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
    // Repeated words add far less than 11 bits each; count distinct ones.
    let mut distinct = lowered.clone();
    distinct.sort_unstable();
    distinct.dedup();
    Some(distinct.len() as f64 * 11.0)
}

/// Conservative character-class entropy estimate with a repetition penalty.
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
        // Non-ASCII genuinely widens the pool, but crediting the full Unicode
        // range would let a handful of emoji pass on their own.
        pool += 100;
    }
    if pool < 2 {
        pool = 2;
    }

    let base = chars.len() as f64 * (pool as f64).log2();

    // Penalty 1: repetition. "aaaaaaaaaaaaaaaa" is long and has no strength.
    let mut distinct: Vec<char> = chars.clone();
    distinct.sort_unstable();
    distinct.dedup();
    let variety = (distinct.len() as f64 / chars.len() as f64).clamp(0.35, 1.0);

    // Penalty 2: runs. Each character that simply continues an ascending or
    // descending sequence from the previous one ("abcd", "4321") carries far
    // less information than an independent choice.
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
        // 8 characters, 24 bytes. Must fail on length, not sneak past on bytes.
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

    /// Every generated phrase must clear the policy it will be checked against.
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
        // Valid dictionary words, deliberately not a checksum-valid mnemonic.
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
        // Below MIN_PHRASE_WORDS, so it must not get 11 bits/word credit.
        let a = assess("zebra zone youth yellow");
        assert!(!a.is_word_phrase);
    }
}
