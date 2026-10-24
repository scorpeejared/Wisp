use crate::error::{MessagingError, MessagingResult};
use crate::Envelope;

const FORMAT_VERSION: u8 = 1;
const KIND_PREKEY: u8 = 1;
const KIND_RATCHET: u8 = 2;
const HEADER_LEN: usize = 2 + 32;

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

    #[test]
    fn parsing_never_panics_on_arbitrary_input() {
        for pattern in [0x00u8, 0xFF, 0x01] {
            for len in [0usize, 1, 2, 33, 34, 35, 4096] {
                let _ = WireEnvelope::from_bytes(&vec![pattern; len]);
            }
        }
    }
}
