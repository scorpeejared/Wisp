//! The bytes that travel through the relay.
//!
//! The relay carries an opaque blob and knows only who it is for. This module
//! defines what is inside that blob.
//!
//! ```text
//! off  len  field
//!   0    1  format version = 1
//!   1    1  message kind (1 = prekey, 2 = ratchet)
//!   2   32  sender identity key
//!  34    N  libsignal ciphertext
//! ```
//!
//! # The sender field is temporary
//!
//! Carrying the sender in the clear means **the relay can see who is talking to
//! whom**, even though it cannot read a word of what they say. That is exactly
//! the metadata sealed sender exists to remove: under sealed sender the
//! originator moves *inside* the ciphertext, encrypted to the recipient, and
//! the relay sees only a destination.
//!
//! It is here because a recipient must know which session to decrypt with, and
//! until sealed sender lands there is nowhere else to put it. The format is
//! versioned so that change is a new version rather than a redesign.

use crate::error::{MessagingError, MessagingResult};
use crate::Envelope;

const FORMAT_VERSION: u8 = 1;
const KIND_PREKEY: u8 = 1;
const KIND_RATCHET: u8 = 2;
const HEADER_LEN: usize = 2 + 32;

/// An envelope addressed to someone, ready to hand to the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireEnvelope {
    pub sender: [u8; 32],
    pub envelope: Envelope,
}

impl WireEnvelope {
    pub fn new(sender: [u8; 32], envelope: Envelope) -> Self {
        Self { sender, envelope }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.envelope.ciphertext.len());
        out.push(FORMAT_VERSION);
        out.push(if self.envelope.is_prekey {
            KIND_PREKEY
        } else {
            KIND_RATCHET
        });
        out.extend_from_slice(&self.sender);
        out.extend_from_slice(&self.envelope.ciphertext);
        out
    }

    /// Parses bytes that arrived from the relay.
    ///
    /// Total and non-panicking: this is attacker-controlled input that reached
    /// us through a server we do not trust.
    pub fn from_bytes(bytes: &[u8]) -> MessagingResult<Self> {
        if bytes.len() <= HEADER_LEN {
            return Err(MessagingError::Malformed);
        }
        if bytes[0] != FORMAT_VERSION {
            return Err(MessagingError::Malformed);
        }

        let is_prekey = match bytes[1] {
            KIND_PREKEY => true,
            KIND_RATCHET => false,
            _ => return Err(MessagingError::Malformed),
        };

        let mut sender = [0u8; 32];
        sender.copy_from_slice(&bytes[2..HEADER_LEN]);

        Ok(Self {
            sender,
            envelope: Envelope {
                is_prekey,
                ciphertext: bytes[HEADER_LEN..].to_vec(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(is_prekey: bool) -> WireEnvelope {
        WireEnvelope::new(
            [0xAB; 32],
            Envelope {
                is_prekey,
                ciphertext: b"libsignal ciphertext".to_vec(),
            },
        )
    }

    #[test]
    fn envelopes_round_trip() {
        for is_prekey in [true, false] {
            let original = sample(is_prekey);
            let parsed = WireEnvelope::from_bytes(&original.to_bytes()).unwrap();
            assert_eq!(parsed, original);
        }
    }

    /// The kind tag has to survive, because the recipient cannot tell a session
    /// opening message from a ratchet message by looking at the bytes.
    #[test]
    fn the_message_kind_survives_the_round_trip() {
        assert!(
            WireEnvelope::from_bytes(&sample(true).to_bytes())
                .unwrap()
                .envelope
                .is_prekey
        );
        assert!(
            !WireEnvelope::from_bytes(&sample(false).to_bytes())
                .unwrap()
                .envelope
                .is_prekey
        );
    }

    #[test]
    fn truncated_input_is_rejected() {
        let bytes = sample(true).to_bytes();
        for len in 0..=HEADER_LEN {
            assert!(
                WireEnvelope::from_bytes(&bytes[..len]).is_err(),
                "{len} bytes should not parse"
            );
        }
    }

    #[test]
    fn an_unknown_version_is_rejected() {
        let mut bytes = sample(true).to_bytes();
        bytes[0] = 99;
        assert!(WireEnvelope::from_bytes(&bytes).is_err());
    }

    #[test]
    fn an_unknown_kind_is_rejected() {
        let mut bytes = sample(true).to_bytes();
        bytes[1] = 77;
        assert!(WireEnvelope::from_bytes(&bytes).is_err());
    }

    /// Runs on bytes from a server we do not trust.
    #[test]
    fn parsing_never_panics_on_arbitrary_input() {
        for pattern in [0x00u8, 0xFF, 0x01] {
            for len in [0usize, 1, 2, 33, 34, 35, 4096] {
                let _ = WireEnvelope::from_bytes(&vec![pattern; len]);
            }
        }
    }
}
