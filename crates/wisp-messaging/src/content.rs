use uuid::Uuid;

use crate::error::{MessagingError, MessagingResult};

const FORMAT_VERSION: u8 = 1;
const KIND_DIRECT: u8 = 1;
const KIND_DISTRIBUTION: u8 = 2;
const KIND_GROUP: u8 = 3;

const HEADER_LEN: usize = 2;
const GROUP_HEADER_LEN: usize = HEADER_LEN + 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    Direct { body: String },

    Distribution {
        group: Uuid,
        name: String,
        members: Vec<[u8; 32]>,
        distribution: Vec<u8>,
    },

    Group {
        group: Uuid,
        ciphertext: Vec<u8>,
    },
}

impl Content {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(FORMAT_VERSION);

        match self {
            Content::Direct { body } => {
                out.push(KIND_DIRECT);
                out.extend_from_slice(body.as_bytes());
            }

            Content::Distribution {
                group,
                name,
                members,
                distribution,
            } => {
                out.push(KIND_DISTRIBUTION);
                out.extend_from_slice(group.as_bytes());
                out.extend_from_slice(&(distribution.len() as u32).to_be_bytes());
                out.extend_from_slice(distribution);
                let name = name.as_bytes();
                out.push(name.len().min(u8::MAX as usize) as u8);
                out.extend_from_slice(&name[..name.len().min(u8::MAX as usize)]);
                out.extend_from_slice(&(members.len() as u16).to_be_bytes());
                for member in members {
                    out.extend_from_slice(member);
                }
            }

            Content::Group { group, ciphertext } => {
                out.push(KIND_GROUP);
                out.extend_from_slice(group.as_bytes());
                out.extend_from_slice(ciphertext);
            }
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> MessagingResult<Self> {
        if bytes.len() < HEADER_LEN || bytes[0] != FORMAT_VERSION {
            return Err(MessagingError::Malformed);
        }

        match bytes[1] {
            KIND_DIRECT => Ok(Content::Direct {
                body: text(&bytes[HEADER_LEN..])?,
            }),

            KIND_GROUP => {
                if bytes.len() <= GROUP_HEADER_LEN {
                    return Err(MessagingError::Malformed);
                }
                Ok(Content::Group {
                    group: uuid_at(bytes, HEADER_LEN)?,
                    ciphertext: bytes[GROUP_HEADER_LEN..].to_vec(),
                })
            }

            KIND_DISTRIBUTION => {
                let group = uuid_at(bytes, HEADER_LEN)?;
                let mut cursor = Cursor::new(bytes, GROUP_HEADER_LEN);

                let distribution_len = cursor.u32()? as usize;
                let distribution = cursor.take(distribution_len)?.to_vec();
                let name_len = cursor.u8()? as usize;
                let name = text(cursor.take(name_len)?)?;

                let count = cursor.u16()? as usize;
                let mut members = Vec::with_capacity(count.min(1024));
                for _ in 0..count {
                    members.push(
                        cursor
                            .take(32)?
                            .try_into()
                            .map_err(|_| MessagingError::Malformed)?,
                    );
                }

                Ok(Content::Distribution {
                    group,
                    name,
                    members,
                    distribution,
                })
            }

            _ => Err(MessagingError::Malformed),
        }
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8], at: usize) -> Self {
        Self { bytes, at }
    }

    fn take(&mut self, n: usize) -> MessagingResult<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or(MessagingError::Malformed)?;
        if end > self.bytes.len() {
            return Err(MessagingError::Malformed);
        }
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self) -> MessagingResult<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> MessagingResult<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| MessagingError::Malformed)?,
        ))
    }

    fn u32(&mut self) -> MessagingResult<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| MessagingError::Malformed)?,
        ))
    }
}

fn uuid_at(bytes: &[u8], at: usize) -> MessagingResult<Uuid> {
    let raw: [u8; 16] = bytes
        .get(at..at + 16)
        .ok_or(MessagingError::Malformed)?
        .try_into()
        .map_err(|_| MessagingError::Malformed)?;
    Ok(Uuid::from_bytes(raw))
}

fn text(bytes: &[u8]) -> MessagingResult<String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| MessagingError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group_id() -> Uuid {
        Uuid::from_bytes([0xAB; 16])
    }

    #[test]
    fn direct_messages_round_trip() {
        let content = Content::Direct {
            body: "hello there".into(),
        };
        assert_eq!(Content::from_bytes(&content.to_bytes()).unwrap(), content);
    }

    #[test]
    fn group_messages_round_trip() {
        let content = Content::Group {
            group: group_id(),
            ciphertext: b"a sender key message".to_vec(),
        };
        assert_eq!(Content::from_bytes(&content.to_bytes()).unwrap(), content);
    }

    #[test]
    fn distributions_round_trip() {
        let content = Content::Distribution {
            group: group_id(),
            name: "the group".into(),
            members: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
            distribution: b"skdm bytes".to_vec(),
        };
        assert_eq!(Content::from_bytes(&content.to_bytes()).unwrap(), content);
    }

    #[test]
    fn an_empty_group_distribution_round_trips() {
        let content = Content::Distribution {
            group: group_id(),
            name: String::new(),
            members: Vec::new(),
            distribution: Vec::new(),
        };
        assert_eq!(Content::from_bytes(&content.to_bytes()).unwrap(), content);
    }

    #[test]
    fn kinds_are_distinguished() {
        let direct = Content::Direct { body: "x".into() }.to_bytes();
        let group = Content::Group {
            group: group_id(),
            ciphertext: b"x".to_vec(),
        }
        .to_bytes();
        assert_ne!(direct[1], group[1]);
    }

    #[test]
    fn unicode_survives() {
        let content = Content::Direct {
            body: "héllo — 日本語 🔐".into(),
        };
        assert_eq!(Content::from_bytes(&content.to_bytes()).unwrap(), content);
    }

    #[test]
    fn an_unknown_version_is_rejected() {
        let mut bytes = Content::Direct { body: "x".into() }.to_bytes();
        bytes[0] = 99;
        assert!(Content::from_bytes(&bytes).is_err());
    }

    #[test]
    fn an_unknown_kind_is_rejected() {
        let mut bytes = Content::Direct { body: "x".into() }.to_bytes();
        bytes[1] = 77;
        assert!(Content::from_bytes(&bytes).is_err());
    }

    #[test]
    fn input_too_short_for_its_header_is_rejected() {
        let direct = Content::Direct { body: "hello".into() }.to_bytes();
        for len in 0..HEADER_LEN {
            assert!(Content::from_bytes(&direct[..len]).is_err(), "{len} bytes");
        }

        let group = Content::Group {
            group: group_id(),
            ciphertext: b"abc".to_vec(),
        }
        .to_bytes();
        for len in 0..=GROUP_HEADER_LEN {
            assert!(Content::from_bytes(&group[..len]).is_err(), "{len} bytes");
        }
    }

    #[test]
    fn a_truncated_distribution_is_always_rejected() {
        let bytes = Content::Distribution {
            group: group_id(),
            name: "the group".into(),
            members: vec![[7u8; 32], [8u8; 32]],
            distribution: b"skdm bytes".to_vec(),
        }
        .to_bytes();

        for len in 0..bytes.len() {
            assert!(
                Content::from_bytes(&bytes[..len]).is_err(),
                "{len} of {} bytes parsed when truncated",
                bytes.len()
            );
        }
        assert!(Content::from_bytes(&bytes).is_ok(), "the full message must parse");
    }

    #[test]
    fn a_hostile_length_is_rejected() {
        let mut bytes = Content::Distribution {
            group: group_id(),
            name: "g".into(),
            members: vec![[7u8; 32]],
            distribution: b"skdm".to_vec(),
        }
        .to_bytes();
        bytes[GROUP_HEADER_LEN..GROUP_HEADER_LEN + 4]
            .copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(Content::from_bytes(&bytes).is_err());
    }

    #[test]
    fn a_hostile_member_count_is_rejected() {
        let content = Content::Distribution {
            group: group_id(),
            name: "g".into(),
            members: vec![[7u8; 32]],
            distribution: b"skdm".to_vec(),
        };
        let mut bytes = content.to_bytes();
        let count_at = bytes.len() - 32 - 2;
        bytes[count_at..count_at + 2].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(Content::from_bytes(&bytes).is_err());
    }

    #[test]
    fn parsing_never_panics_on_arbitrary_input() {
        for pattern in [0x00u8, 0x01, 0x02, 0x03, 0xFF] {
            for len in [0usize, 1, 2, 3, 17, 18, 19, 64, 4096] {
                let _ = Content::from_bytes(&vec![pattern; len]);
            }
        }
    }
}
