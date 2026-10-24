use uuid::Uuid;

use crate::error::{MessagingError, MessagingResult};
use crate::vault::Vault;

const NS_GROUP: &str = "group";
pub const MAX_MEMBERS: usize = 128;
pub const MAX_NAME_CHARS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub id: Uuid,
    pub name: String,
    pub members: Vec<[u8; 32]>,
    pub created_at: u64,
}

impl Group {
    pub fn others(&self, me: &[u8; 32]) -> Vec<[u8; 32]> {
        self.members
            .iter()
            .filter(|member| *member != me)
            .copied()
            .collect()
    }

    pub fn contains(&self, member: &[u8; 32]) -> bool {
        self.members.contains(member)
    }

    fn validate(&self) -> MessagingResult<()> {
        let name_len = self.name.chars().count();
        if name_len == 0 || name_len > MAX_NAME_CHARS {
            return Err(MessagingError::Malformed);
        }
        if self.members.is_empty() || self.members.len() > MAX_MEMBERS {
            return Err(MessagingError::Malformed);
        }
        Ok(())
    }

    fn encode(&self) -> MessagingResult<Vec<u8>> {
        self.validate()?;

        let name = self.name.as_bytes();
        let mut out = Vec::with_capacity(1 + 8 + 1 + name.len() + 2 + self.members.len() * 32);
        out.push(1);
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out.push(name.len() as u8);
        out.extend_from_slice(name);
        out.extend_from_slice(&(self.members.len() as u16).to_be_bytes());
        for member in &self.members {
            out.extend_from_slice(member);
        }
        Ok(out)
    }

    fn decode(id: Uuid, bytes: &[u8]) -> MessagingResult<Self> {
        if bytes.len() < 10 || bytes[0] != 1 {
            return Err(MessagingError::Malformed);
        }
        let created_at = u64::from_be_bytes(
            bytes[1..9].try_into().map_err(|_| MessagingError::Malformed)?,
        );

        let name_len = bytes[9] as usize;
        let name_end = 10 + name_len;
        let name = String::from_utf8(
            bytes
                .get(10..name_end)
                .ok_or(MessagingError::Malformed)?
                .to_vec(),
        )
        .map_err(|_| MessagingError::Malformed)?;

        let count = u16::from_be_bytes(
            bytes
                .get(name_end..name_end + 2)
                .ok_or(MessagingError::Malformed)?
                .try_into()
                .map_err(|_| MessagingError::Malformed)?,
        ) as usize;

        let mut members = Vec::with_capacity(count.min(MAX_MEMBERS));
        for index in 0..count {
            let at = name_end + 2 + index * 32;
            members.push(
                bytes
                    .get(at..at + 32)
                    .ok_or(MessagingError::Malformed)?
                    .try_into()
                    .map_err(|_| MessagingError::Malformed)?,
            );
        }

        let group = Self {
            id,
            name,
            members,
            created_at,
        };
        group.validate()?;
        Ok(group)
    }
}

pub struct Groups<'v> {
    vault: &'v Vault,
}

impl<'v> Groups<'v> {
    pub fn new(vault: &'v Vault) -> Self {
        Self { vault }
    }

    pub fn put(&self, group: &Group) -> MessagingResult<()> {
        self.vault
            .put(NS_GROUP, group.id.as_bytes(), &group.encode()?)
    }

    pub fn get(&self, id: &Uuid) -> MessagingResult<Option<Group>> {
        match self.vault.get(NS_GROUP, id.as_bytes())? {
            Some(bytes) => Ok(Some(Group::decode(*id, &bytes)?)),
            None => Ok(None),
        }
    }

    pub fn list(&self) -> MessagingResult<Vec<Group>> {
        let mut groups = Vec::new();
        for key in self.vault.keys(NS_GROUP)? {
            let Ok(raw) = <[u8; 16]>::try_from(key.as_slice()) else {
                continue;
            };
            let id = Uuid::from_bytes(raw);
            if let Ok(Some(group)) = self.get(&id) {
                groups.push(group);
            }
        }
        groups.sort_by_key(|group| group.created_at);
        Ok(groups)
    }

    pub fn forget(&self, id: &Uuid) -> MessagingResult<()> {
        self.vault.delete(NS_GROUP, id.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: [u8; 32] = [1u8; 32];
    const ALICE: [u8; 32] = [2u8; 32];
    const BOB: [u8; 32] = [3u8; 32];

    fn vault() -> Vault {
        Vault::in_memory(b"identity secret").unwrap()
    }

    fn group() -> Group {
        Group {
            id: Uuid::from_bytes([9u8; 16]),
            name: "the group".into(),
            members: vec![ME, ALICE, BOB],
            created_at: 1_700_000_000_000,
        }
    }

    #[test]
    fn groups_round_trip() {
        let vault = vault();
        let groups = Groups::new(&vault);
        groups.put(&group()).unwrap();
        assert_eq!(groups.get(&group().id).unwrap().unwrap(), group());
    }

    #[test]
    fn an_unknown_group_is_none() {
        let vault = vault();
        assert!(Groups::new(&vault)
            .get(&Uuid::from_bytes([0u8; 16]))
            .unwrap()
            .is_none());
    }

    #[test]
    fn groups_list_oldest_first() {
        let vault = vault();
        let groups = Groups::new(&vault);

        for (index, created_at) in [300u64, 100, 200].into_iter().enumerate() {
            groups
                .put(&Group {
                    id: Uuid::from_bytes([index as u8; 16]),
                    created_at,
                    ..group()
                })
                .unwrap();
        }

        let listed: Vec<u64> = groups.list().unwrap().iter().map(|g| g.created_at).collect();
        assert_eq!(listed, vec![100, 200, 300]);
    }

    #[test]
    fn others_excludes_us() {
        assert_eq!(group().others(&ME), vec![ALICE, BOB]);
        assert_eq!(group().others(&[9u8; 32]).len(), 3);
    }

    #[test]
    fn membership_can_be_tested() {
        assert!(group().contains(&ALICE));
        assert!(!group().contains(&[9u8; 32]));
    }

    #[test]
    fn a_group_can_be_forgotten() {
        let vault = vault();
        let groups = Groups::new(&vault);
        groups.put(&group()).unwrap();
        groups.forget(&group().id).unwrap();
        assert!(groups.get(&group().id).unwrap().is_none());
        assert!(groups.list().unwrap().is_empty());
    }

    #[test]
    fn nameless_and_empty_groups_are_refused() {
        let vault = vault();
        let groups = Groups::new(&vault);

        assert!(groups
            .put(&Group {
                name: String::new(),
                ..group()
            })
            .is_err());
        assert!(groups
            .put(&Group {
                members: Vec::new(),
                ..group()
            })
            .is_err());
    }

    #[test]
    fn oversized_groups_are_refused() {
        let vault = vault();
        let groups = Groups::new(&vault);

        assert!(groups
            .put(&Group {
                members: vec![[0u8; 32]; MAX_MEMBERS + 1],
                ..group()
            })
            .is_err());
        assert!(groups
            .put(&Group {
                name: "x".repeat(MAX_NAME_CHARS + 1),
                ..group()
            })
            .is_err());
    }

    #[test]
    fn a_corrupt_record_is_skipped_rather_than_failing_the_list() {
        let vault = vault();
        let groups = Groups::new(&vault);
        groups.put(&group()).unwrap();
        vault
            .put(NS_GROUP, &[0xEEu8; 16], b"not a group record")
            .unwrap();

        let listed = groups.list().unwrap();
        assert_eq!(listed.len(), 1, "the good group should still be listed");
    }

    #[test]
    fn unicode_names_survive() {
        let vault = vault();
        let groups = Groups::new(&vault);
        let named = Group {
            name: "café ☕ 日本語".into(),
            ..group()
        };
        groups.put(&named).unwrap();
        assert_eq!(groups.get(&named.id).unwrap().unwrap().name, named.name);
    }
}
