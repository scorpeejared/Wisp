use libsignal_protocol::{IdentityKeyPair, PrivateKey};
use rand::TryRngCore;

use crate::binding::{
    self, BindingStrength, DeviceIdentifiers, BINDING_SALT_LEN, BINDING_VALUE_LEN,
};
use crate::crypto::{
    self, KdfParams, AEAD_ID_XCHACHA20POLY1305, KDF_ID_ARGON2ID, KDF_SALT_LEN, NONCE_LEN,
};
use crate::error::{Error, Result};
use crate::passphrase;
use crate::secret::SecretBytes;

pub const MAGIC: [u8; 4] = *b"WISP";
pub const FORMAT_VERSION: u16 = 2;
pub const SUPPORTED_FORMAT_VERSION: u16 = 2;

const V1_PREFIX_LEN: usize = 130;
const V2_PREFIX_LEN: usize = 194;

const OFF_VERSION: usize = 4;
const OFF_KDF_ID: usize = 6;
const OFF_AEAD_ID: usize = 7;
const OFF_STRENGTH: usize = 8;
const OFF_MACHINE_FLAG: usize = 9;
const OFF_M_COST: usize = 10;
const OFF_T_COST: usize = 14;
const OFF_P_COST: usize = 18;
const OFF_KDF_SALT: usize = 22;
const OFF_BINDING_SALT: usize = 38;
const OFF_BINDING_VALUE: usize = 70;

const OFF_MACHINE_SALT: usize = 102;
const OFF_MACHINE_VALUE: usize = 134;

const V1_OFF_NONCE: usize = 102;
const V1_OFF_CT_LEN: usize = 126;
const V2_OFF_NONCE: usize = 166;
const V2_OFF_CT_LEN: usize = 190;

fn prefix_len(format_version: u16) -> usize {
    if format_version >= 2 {
        V2_PREFIX_LEN
    } else {
        V1_PREFIX_LEN
    }
}

pub const IDENTITY_DIR: &str = ".wisp";
pub const IDENTITY_FILENAME: &str = "identity.wisp";

const PAYLOAD_VERSION: u8 = 1;
const MAX_KEY_MATERIAL: usize = 1024;
const MIN_USERNAME_CHARS: usize = 3;
const MAX_USERNAME_CHARS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ed25519Seed = 1,
    LibsignalIdentityKeyPair = 2,
    HardwareTokenHandle = 3,
}

impl KeyType {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Ed25519Seed),
            2 => Some(Self::LibsignalIdentityKeyPair),
            3 => Some(Self::HardwareTokenHandle),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct IdentityFile {
    pub format_version: u16,
    pub kdf_params: KdfParams,
    pub binding_strength: BindingStrength,
    pub machine_binding: bool,
    kdf_salt: [u8; KDF_SALT_LEN],
    binding_salt: [u8; BINDING_SALT_LEN],
    binding_value: [u8; BINDING_VALUE_LEN],
    machine_salt: [u8; BINDING_SALT_LEN],
    machine_binding_value: [u8; BINDING_VALUE_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

pub struct UnlockedIdentity {
    key_material: SecretBytes,
    pub key_type: KeyType,
    pub username: String,
    pub created_at: u64,
}

impl std::fmt::Debug for UnlockedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedIdentity")
            .field("key_type", &self.key_type)
            .field("username", &self.username)
            .field("key_material", &"<redacted>")
            .finish()
    }
}

impl UnlockedIdentity {
    pub fn generate(username: &str) -> Result<Self> {
        validate_username(username)?;
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let keypair = IdentityKeyPair::generate(&mut rng);

        let mut private = keypair.private_key().serialize();
        Ok(Self {
            key_material: SecretBytes::from_slice_mut(&mut private),
            key_type: KeyType::LibsignalIdentityKeyPair,
            username: username.to_string(),
            created_at: now_unix(),
        })
    }

    pub fn key_material(&self) -> &SecretBytes {
        &self.key_material
    }

    fn private_key(&self) -> Result<PrivateKey> {
        match self.key_type {
            KeyType::LibsignalIdentityKeyPair => {
                PrivateKey::deserialize(self.key_material.as_slice())
                    .map_err(|_| Error::BadKeyMaterial)
            }
            KeyType::Ed25519Seed => Err(Error::LegacyKeyType),
            KeyType::HardwareTokenHandle => Err(Error::BadKeyMaterial),
        }
    }

    pub fn public_key(&self) -> Result<[u8; 32]> {
        self.private_key()?
            .public_key()
            .map_err(|_| Error::BadKeyMaterial)?
            .public_key_bytes()
            .try_into()
            .map_err(|_| Error::BadKeyMaterial)
    }

    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let signature = self
            .private_key()?
            .calculate_signature(message, &mut rng)
            .map_err(|_| Error::BadKeyMaterial)?;
        signature
            .as_ref()
            .try_into()
            .map_err(|_| Error::BadKeyMaterial)
    }

    pub fn lock(&mut self) {
        self.key_material.wipe();
    }

    fn encode_payload(&self) -> Result<SecretBytes> {
        let key = self.key_material.as_slice();
        if key.is_empty() || key.len() > MAX_KEY_MATERIAL {
            return Err(Error::BadKeyMaterial);
        }
        let username = self.username.as_bytes();

        let mut buf = SecretBytes::zeroed(1 + 1 + 2 + key.len() + 1 + username.len() + 8);
        {
            let out = buf.as_mut_slice();
            let mut i = 0;
            out[i] = PAYLOAD_VERSION;
            i += 1;
            out[i] = self.key_type as u8;
            i += 1;
            out[i..i + 2].copy_from_slice(&(key.len() as u16).to_be_bytes());
            i += 2;
            out[i..i + key.len()].copy_from_slice(key);
            i += key.len();
            out[i] = username.len() as u8;
            i += 1;
            out[i..i + username.len()].copy_from_slice(username);
            i += username.len();
            out[i..i + 8].copy_from_slice(&self.created_at.to_be_bytes());
        }
        Ok(buf)
    }

    fn decode_payload(payload: &SecretBytes) -> Result<Self> {
        let buf = payload.as_slice();
        let mut i = 0;
        let take = |i: &mut usize, n: usize| -> Result<std::ops::Range<usize>> {
            let start = *i;
            let end = start.checked_add(n).ok_or(Error::Malformed)?;
            if end > buf.len() {
                return Err(Error::Malformed);
            }
            *i = end;
            Ok(start..end)
        };

        let r = take(&mut i, 1)?;
        if buf[r.start] != PAYLOAD_VERSION {
            return Err(Error::Malformed);
        }
        let r = take(&mut i, 1)?;
        let key_type = KeyType::from_u8(buf[r.start]).ok_or(Error::Malformed)?;

        let r = take(&mut i, 2)?;
        let key_len = u16::from_be_bytes([buf[r.start], buf[r.start + 1]]) as usize;
        if key_len == 0 || key_len > MAX_KEY_MATERIAL {
            return Err(Error::BadKeyMaterial);
        }
        let r = take(&mut i, key_len)?;
        let key_material = SecretBytes::copy_from_slice(&buf[r]);

        let r = take(&mut i, 1)?;
        let username_len = buf[r.start] as usize;
        let r = take(&mut i, username_len)?;
        let username = std::str::from_utf8(&buf[r])
            .map_err(|_| Error::Malformed)?
            .to_string();
        validate_username(&username)?;

        let r = take(&mut i, 8)?;
        let created_at = u64::from_be_bytes(buf[r].try_into().map_err(|_| Error::Malformed)?);

        Ok(Self {
            key_material,
            key_type,
            username,
            created_at,
        })
    }
}

impl IdentityFile {
    pub fn create(
        identity: &UnlockedIdentity,
        passphrase: &str,
        device: &DeviceIdentifiers,
        machine_id: Option<&str>,
        kdf_params: KdfParams,
    ) -> Result<Self> {
        passphrase::enforce(passphrase)?;

        let binding_strength = device.strength()?;
        let file = Self {
            format_version: FORMAT_VERSION,
            kdf_params,
            binding_strength,
            machine_binding: machine_id.is_some(),
            kdf_salt: crypto::random_array(),
            binding_salt: crypto::random_array(),
            binding_value: [0u8; BINDING_VALUE_LEN],
            machine_salt: [0u8; BINDING_SALT_LEN],
            machine_binding_value: [0u8; BINDING_VALUE_LEN],
            nonce: crypto::random_array(),
            ciphertext: Vec::new(),
        };

        file.seal(identity, passphrase, device, machine_id)
    }

    fn seal(
        mut self,
        identity: &UnlockedIdentity,
        passphrase: &str,
        device: &DeviceIdentifiers,
        machine_id: Option<&str>,
    ) -> Result<Self> {
        self.format_version = FORMAT_VERSION;
        self.machine_binding = machine_id.is_some();
        self.binding_value = device.binding_value(self.binding_strength, &self.binding_salt)?;

        let usb_hash = device.fingerprint_hash(self.binding_strength)?;
        let machine_hash = match machine_id {
            Some(id) => {
                self.machine_salt = crypto::random_array();
                self.machine_binding_value = binding::machine_binding_value(id, &self.machine_salt);
                Some(binding::machine_fingerprint_hash(id))
            }
            None => {
                self.machine_salt = [0u8; BINDING_SALT_LEN];
                self.machine_binding_value = [0u8; BINDING_VALUE_LEN];
                None
            }
        };
        let combined = binding::combined_fingerprint_hash(&usb_hash, machine_hash.as_ref());

        let file_key =
            crypto::derive_file_key(passphrase.as_bytes(), &self.kdf_salt, self.kdf_params)?;
        let aead_key = crypto::derive_aead_key(&file_key, &combined)?;

        let payload = identity.encode_payload()?;
        let ct_len = payload.len() + crypto::TAG_LEN;
        let prefix = self.encode_prefix(ct_len as u32);
        self.ciphertext =
            crypto::aead_encrypt(&aead_key, &self.nonce, &prefix, payload.as_slice())?;
        debug_assert_eq!(self.ciphertext.len(), ct_len);
        Ok(self)
    }

    pub fn rebind(
        &self,
        passphrase: &str,
        device: &DeviceIdentifiers,
        current_machine: Option<&str>,
        new_machine: Option<&str>,
    ) -> Result<Self> {
        let identity = self.unlock(passphrase, device, current_machine)?;

        let fresh = Self {
            format_version: FORMAT_VERSION,
            kdf_params: self.kdf_params,
            binding_strength: self.binding_strength,
            machine_binding: new_machine.is_some(),
            kdf_salt: crypto::random_array(),
            binding_salt: crypto::random_array(),
            binding_value: [0u8; BINDING_VALUE_LEN],
            machine_salt: [0u8; BINDING_SALT_LEN],
            machine_binding_value: [0u8; BINDING_VALUE_LEN],
            nonce: crypto::random_array(),
            ciphertext: Vec::new(),
        };
        fresh.seal(&identity, passphrase, device, new_machine)
    }

    pub fn device_matches(&self, device: &DeviceIdentifiers) -> bool {
        device.matches(self.binding_strength, &self.binding_salt, &self.binding_value)
    }

    pub fn computer_matches(&self, machine_id: Option<&str>) -> bool {
        if !self.machine_binding {
            return true;
        }
        binding::machine_matches(machine_id, &self.machine_salt, &self.machine_binding_value)
    }

    pub fn unlock(
        &self,
        passphrase: &str,
        device: &DeviceIdentifiers,
        machine_id: Option<&str>,
    ) -> Result<UnlockedIdentity> {
        let usb_hash = device.fingerprint_hash(self.binding_strength)?;

        let machine_hash = if self.machine_binding {
            Some(binding::machine_fingerprint_hash(
                machine_id.ok_or(Error::WrongComputer)?,
            ))
        } else {
            None
        };
        let combined = binding::combined_fingerprint_hash(&usb_hash, machine_hash.as_ref());

        let file_key =
            crypto::derive_file_key(passphrase.as_bytes(), &self.kdf_salt, self.kdf_params)?;
        let aead_key = crypto::derive_aead_key(&file_key, &combined)?;

        let prefix = self.encode_prefix(self.ciphertext.len() as u32);
        let payload = crypto::aead_decrypt(&aead_key, &self.nonce, &prefix, &self.ciphertext)?;
        UnlockedIdentity::decode_payload(&payload)
    }

    fn encode_prefix(&self, ct_len: u32) -> Vec<u8> {
        let v2 = self.format_version >= 2;
        let mut out = vec![0u8; prefix_len(self.format_version)];

        out[0..4].copy_from_slice(&MAGIC);
        out[OFF_VERSION..OFF_VERSION + 2].copy_from_slice(&self.format_version.to_be_bytes());
        out[OFF_KDF_ID] = KDF_ID_ARGON2ID;
        out[OFF_AEAD_ID] = AEAD_ID_XCHACHA20POLY1305;
        out[OFF_STRENGTH] = self.binding_strength as u8;
        out[OFF_MACHINE_FLAG] = u8::from(v2 && self.machine_binding);
        out[OFF_M_COST..OFF_M_COST + 4].copy_from_slice(&self.kdf_params.m_cost.to_be_bytes());
        out[OFF_T_COST..OFF_T_COST + 4].copy_from_slice(&self.kdf_params.t_cost.to_be_bytes());
        out[OFF_P_COST..OFF_P_COST + 4].copy_from_slice(&self.kdf_params.p_cost.to_be_bytes());
        out[OFF_KDF_SALT..OFF_KDF_SALT + KDF_SALT_LEN].copy_from_slice(&self.kdf_salt);
        out[OFF_BINDING_SALT..OFF_BINDING_SALT + BINDING_SALT_LEN]
            .copy_from_slice(&self.binding_salt);
        out[OFF_BINDING_VALUE..OFF_BINDING_VALUE + BINDING_VALUE_LEN]
            .copy_from_slice(&self.binding_value);

        let (off_nonce, off_ct_len) = if v2 {
            out[OFF_MACHINE_SALT..OFF_MACHINE_SALT + BINDING_SALT_LEN]
                .copy_from_slice(&self.machine_salt);
            out[OFF_MACHINE_VALUE..OFF_MACHINE_VALUE + BINDING_VALUE_LEN]
                .copy_from_slice(&self.machine_binding_value);
            (V2_OFF_NONCE, V2_OFF_CT_LEN)
        } else {
            (V1_OFF_NONCE, V1_OFF_CT_LEN)
        };

        out[off_nonce..off_nonce + NONCE_LEN].copy_from_slice(&self.nonce);
        out[off_ct_len..off_ct_len + 4].copy_from_slice(&ct_len.to_be_bytes());
        out
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.encode_prefix(self.ciphertext.len() as u32);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < V1_PREFIX_LEN {
            return Err(if bytes.len() >= 4 && bytes[0..4] != MAGIC {
                Error::BadMagic
            } else {
                Error::Malformed
            });
        }
        if bytes[0..4] != MAGIC {
            return Err(Error::BadMagic);
        }

        let format_version = u16::from_be_bytes([bytes[OFF_VERSION], bytes[OFF_VERSION + 1]]);
        if format_version == 0 || format_version > SUPPORTED_FORMAT_VERSION {
            return Err(Error::UnsupportedVersion {
                found: format_version,
                supported: SUPPORTED_FORMAT_VERSION,
            });
        }
        if bytes[OFF_KDF_ID] != KDF_ID_ARGON2ID {
            return Err(Error::UnsupportedKdf(bytes[OFF_KDF_ID]));
        }
        if bytes[OFF_AEAD_ID] != AEAD_ID_XCHACHA20POLY1305 {
            return Err(Error::UnsupportedAead(bytes[OFF_AEAD_ID]));
        }
        let binding_strength =
            BindingStrength::from_u8(bytes[OFF_STRENGTH]).ok_or(Error::Malformed)?;

        let v2 = format_version >= 2;
        let prefix = prefix_len(format_version);
        if bytes.len() < prefix {
            return Err(Error::Malformed);
        }

        let machine_binding = match (v2, bytes[OFF_MACHINE_FLAG]) {
            (false, 0) => false,
            (true, 0) => false,
            (true, 1) => true,
            _ => return Err(Error::Malformed),
        };

        let u32_at = |off: usize| u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap());
        let kdf_params = KdfParams {
            m_cost: u32_at(OFF_M_COST),
            t_cost: u32_at(OFF_T_COST),
            p_cost: u32_at(OFF_P_COST),
        };
        if kdf_params.m_cost > 4 * 1024 * 1024 || kdf_params.t_cost > 64 || kdf_params.p_cost > 64 {
            return Err(Error::BadKdfParams);
        }

        let (off_nonce, off_ct_len) = if v2 {
            (V2_OFF_NONCE, V2_OFF_CT_LEN)
        } else {
            (V1_OFF_NONCE, V1_OFF_CT_LEN)
        };

        let ct_len = u32_at(off_ct_len) as usize;
        if ct_len < crypto::TAG_LEN || bytes.len() != prefix + ct_len {
            return Err(Error::Malformed);
        }

        let (machine_salt, machine_binding_value) = if v2 {
            (
                bytes[OFF_MACHINE_SALT..OFF_MACHINE_SALT + BINDING_SALT_LEN]
                    .try_into()
                    .unwrap(),
                bytes[OFF_MACHINE_VALUE..OFF_MACHINE_VALUE + BINDING_VALUE_LEN]
                    .try_into()
                    .unwrap(),
            )
        } else {
            ([0u8; BINDING_SALT_LEN], [0u8; BINDING_VALUE_LEN])
        };

        Ok(Self {
            format_version,
            kdf_params,
            binding_strength,
            machine_binding,
            kdf_salt: bytes[OFF_KDF_SALT..OFF_KDF_SALT + KDF_SALT_LEN]
                .try_into()
                .unwrap(),
            binding_salt: bytes[OFF_BINDING_SALT..OFF_BINDING_SALT + BINDING_SALT_LEN]
                .try_into()
                .unwrap(),
            binding_value: bytes[OFF_BINDING_VALUE..OFF_BINDING_VALUE + BINDING_VALUE_LEN]
                .try_into()
                .unwrap(),
            machine_salt,
            machine_binding_value,
            nonce: bytes[off_nonce..off_nonce + NONCE_LEN].try_into().unwrap(),
            ciphertext: bytes[prefix..].to_vec(),
        })
    }
}

pub fn normalise_username(input: &str) -> String {
    input.trim().to_lowercase()
}

pub fn check_username(username: &str) -> Result<()> {
    validate_username(username)
}

fn validate_username(username: &str) -> Result<()> {
    let len = username.chars().count();
    if !(MIN_USERNAME_CHARS..=MAX_USERNAME_CHARS).contains(&len) {
        return Err(Error::BadUsername);
    }

    let ok = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    if !username.chars().all(|c| ok(c) || c == '_' || c == '-') {
        return Err(Error::BadUsername);
    }

    let first = username.chars().next().ok_or(Error::BadUsername)?;
    let last = username.chars().next_back().ok_or(Error::BadUsername)?;
    if !ok(first) || !ok(last) {
        return Err(Error::BadUsername);
    }

    Ok(())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: KdfParams = KdfParams::INSECURE_FOR_TESTS;
    const PASS: &str = "Tr0ub4dor&3xK!ncq9Zvw";

    fn device() -> DeviceIdentifiers {
        DeviceIdentifiers {
            device_serial: Some("AA04012700007652".into()),
            volume_serial: Some("1A2B-3C4D".into()),
            vendor: Some("SanDisk".into()),
            product: Some("Cruzer Blade".into()),
        }
    }

    fn other_device() -> DeviceIdentifiers {
        DeviceIdentifiers {
            device_serial: Some("ZZ99999900001111".into()),
            ..device()
        }
    }

    fn sealed() -> IdentityFile {
        let id = UnlockedIdentity::generate("wisp-user").unwrap();
        IdentityFile::create(&id, PASS, &device(), None, P).unwrap()
    }

    #[test]
    fn round_trip_through_bytes_and_back() {
        let id = UnlockedIdentity::generate("wisp-user").unwrap();
        let public = id.public_key().unwrap();
        let file = IdentityFile::create(&id, PASS, &device(), None, P).unwrap();

        let decoded = IdentityFile::decode(&file.encode()).unwrap();
        let unlocked = decoded.unlock(PASS, &device(), None).unwrap();

        assert_eq!(unlocked.username, "wisp-user");
        assert_eq!(unlocked.key_type, KeyType::LibsignalIdentityKeyPair);
        assert_eq!(unlocked.public_key().unwrap(), public);
        assert_eq!(unlocked.key_material().len(), 32);
    }

    #[test]
    fn encoded_length_matches_the_documented_layout() {
        let payload = 1 + 1 + 2 + 32 + 1 + 9 + 8;
        assert_eq!(
            sealed().encode().len(),
            V2_PREFIX_LEN + payload + crypto::TAG_LEN
        );
    }

    #[test]
    fn header_is_readable_without_the_passphrase() {
        let file = IdentityFile::decode(&sealed().encode()).unwrap();
        assert_eq!(file.format_version, FORMAT_VERSION);
        assert_eq!(file.binding_strength, BindingStrength::Strong);
        assert_eq!(file.kdf_params, P);
    }

    #[test]
    fn correct_drive_matches() {
        assert!(sealed().device_matches(&device()));
    }

    #[test]
    fn wrong_drive_does_not_match() {
        assert!(!sealed().device_matches(&other_device()));
    }

    #[test]
    fn correct_passphrase_on_wrong_drive_cannot_decrypt() {
        let file = sealed();
        assert!(matches!(
            file.unlock(PASS, &other_device(), None),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn wrong_passphrase_on_correct_drive_cannot_decrypt() {
        assert!(matches!(
            sealed().unlock("Wr0ng&Passphrase!99xz", &device(), None),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn weak_passphrase_is_refused_at_creation() {
        let id = UnlockedIdentity::generate("wisp-user").unwrap();
        assert!(matches!(
            IdentityFile::create(&id, "short", &device(), None, P),
            Err(Error::WeakPassphrase(_))
        ));
    }

    #[test]
    fn unbindable_device_is_refused_at_creation() {
        let id = UnlockedIdentity::generate("wisp-user").unwrap();
        assert!(matches!(
            IdentityFile::create(&id, PASS, &DeviceIdentifiers::default(), None, P),
            Err(Error::NoDeviceIdentifiers)
        ));
    }

    #[test]
    fn drive_with_no_serial_binds_weakly() {
        let ids = DeviceIdentifiers {
            device_serial: None,
            ..device()
        };
        let id = UnlockedIdentity::generate("wisp-user").unwrap();
        let file = IdentityFile::create(&id, PASS, &ids, None, P).unwrap();
        assert_eq!(file.binding_strength, BindingStrength::Weak);
        assert!(file.unlock(PASS, &ids, None).is_ok());
    }

    #[test]
    fn tampering_with_any_header_byte_breaks_unlock() {
        let original = sealed().encode();
        for i in 0..V2_OFF_CT_LEN {
            let mut bytes = original.clone();
            bytes[i] ^= 0xFF;
            let outcome = IdentityFile::decode(&bytes)
                .and_then(|f| f.unlock(PASS, &device(), None).map(|_| ()));
            assert!(outcome.is_err(), "byte {i} was not authenticated");
        }
    }

    #[test]
    fn downgrading_kdf_cost_breaks_unlock() {
        let mut bytes = sealed().encode();
        bytes[OFF_M_COST..OFF_M_COST + 4].copy_from_slice(&1u32.to_be_bytes());
        let file = IdentityFile::decode(&bytes).unwrap();
        assert!(file.unlock(PASS, &device(), None).is_err());
    }

    #[test]
    fn swapping_in_another_binding_value_breaks_unlock() {
        let file = sealed();
        let mut bytes = file.encode();
        let forged = other_device()
            .binding_value(BindingStrength::Strong, &file.binding_salt)
            .unwrap();
        bytes[OFF_BINDING_VALUE..OFF_BINDING_VALUE + BINDING_VALUE_LEN].copy_from_slice(&forged);

        let forged_file = IdentityFile::decode(&bytes).unwrap();
        assert!(forged_file.device_matches(&other_device()));
        assert!(forged_file.unlock(PASS, &other_device(), None).is_err());
    }

    #[test]
    fn tampering_with_ciphertext_breaks_unlock() {
        let mut bytes = sealed().encode();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(IdentityFile::decode(&bytes).unwrap().unlock(PASS, &device(), None).is_err());
    }

    #[test]
    fn decode_rejects_foreign_files() {
        assert!(matches!(
            IdentityFile::decode(b"PK\x03\x04this is a zip file, not an identity"),
            Err(Error::BadMagic)
        ));
    }

    #[test]
    fn decode_rejects_future_versions() {
        let mut bytes = sealed().encode();
        bytes[OFF_VERSION..OFF_VERSION + 2].copy_from_slice(&99u16.to_be_bytes());
        assert!(matches!(
            IdentityFile::decode(&bytes),
            Err(Error::UnsupportedVersion { found: 99, .. })
        ));
    }

    #[test]
    fn decode_rejects_hostile_kdf_cost() {
        let mut bytes = sealed().encode();
        bytes[OFF_M_COST..OFF_M_COST + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(IdentityFile::decode(&bytes), Err(Error::BadKdfParams)));
    }

    #[test]
    fn decode_never_panics_on_arbitrary_input() {
        let valid = sealed().encode();
        for len in 0..valid.len() {
            let _ = IdentityFile::decode(&valid[..len]);
        }
        let mut truncated = valid.clone();
        truncated.truncate(V2_PREFIX_LEN + 4);
        let _ = IdentityFile::decode(&truncated);

        let mut extended = valid.clone();
        extended.extend_from_slice(&[0xAA; 64]);
        assert!(IdentityFile::decode(&extended).is_err());

        for pattern in [0x00u8, 0xFF, 0xAA] {
            for len in [0usize, 1, 4, 129, 130, 131, 193, 194, 195, 4096] {
                let _ = IdentityFile::decode(&vec![pattern; len]);
            }
        }
    }

    #[test]
    fn usernames_are_bounded() {
        for accepted in ["abc", "wisp-user", "alice_01", &"x".repeat(32)] {
            assert!(
                UnlockedIdentity::generate(accepted).is_ok(),
                "{accepted:?} should be accepted"
            );
        }

        for rejected in [
            "",
            "ab",
            &"x".repeat(33),
            "bad\nusername",
            "Alice",
            "alice bob",
            " alice",
            "alice ",
            "-alice",
            "alice_",
            "аlice",
            "alice@example.com",
        ] {
            assert!(
                UnlockedIdentity::generate(rejected).is_err(),
                "{rejected:?} should be rejected"
            );
        }
    }

    #[test]
    fn usernames_are_normalised_before_validation() {
        assert_eq!(normalise_username("  Alice  "), "alice");
        assert_eq!(normalise_username("WISP-User"), "wisp-user");
        assert!(validate_username(&normalise_username(" -alice ")).is_err());
    }

    #[test]
    fn the_identity_key_signs_and_verifies_as_itself() {
        let identity = UnlockedIdentity::generate("alice").unwrap();
        let message = b"prove it";
        assert!(crate::protocol::verify_signature(
            &identity.public_key().unwrap(),
            message,
            &identity.sign(message).unwrap()
        ));
    }

    #[test]
    fn a_legacy_ed25519_identity_is_refused_clearly() {
        let legacy = UnlockedIdentity {
            key_material: SecretBytes::copy_from_slice(&[7u8; 32]),
            key_type: KeyType::Ed25519Seed,
            username: "old-user".into(),
            created_at: 0,
        };

        assert!(matches!(legacy.public_key(), Err(Error::LegacyKeyType)));
        assert!(matches!(legacy.sign(b"anything"), Err(Error::LegacyKeyType)));
    }

    // --- Trusted computer binding ------------------------------------------

    const OTHER_PASS: &str = "Zx9!qWeRtY&asdfGH42";
    const MACHINE: &str = "2a48fb29-1111-2222-3333-444455556666";
    const OTHER_MACHINE: &str = "9f86d081-884c-4d65-9a2d-1f7a2b3c4d5e";

    fn bound_to_machine() -> IdentityFile {
        let id = UnlockedIdentity::generate("wisp-user").unwrap();
        IdentityFile::create(&id, PASS, &device(), Some(MACHINE), P).unwrap()
    }

    #[test]
    fn an_unbound_identity_opens_on_any_computer() {
        let file = sealed();
        assert!(!file.machine_binding);
        assert!(file.computer_matches(None));
        assert!(file.computer_matches(Some(OTHER_MACHINE)));
        assert!(file.unlock(PASS, &device(), Some(OTHER_MACHINE)).is_ok());
    }

    #[test]
    fn a_bound_identity_opens_on_its_own_computer() {
        let file = bound_to_machine();
        assert!(file.machine_binding);
        assert!(file.computer_matches(Some(MACHINE)));
        assert!(file.unlock(PASS, &device(), Some(MACHINE)).is_ok());
    }

    #[test]
    fn the_right_drive_on_the_wrong_computer_is_refused() {
        let file = bound_to_machine();

        assert!(!file.computer_matches(Some(OTHER_MACHINE)));

        assert!(matches!(
            file.unlock(PASS, &device(), Some(OTHER_MACHINE)),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn an_unidentifiable_computer_is_refused() {
        let file = bound_to_machine();
        assert!(!file.computer_matches(None));
        assert!(matches!(
            file.unlock(PASS, &device(), None),
            Err(Error::WrongComputer)
        ));
    }

    #[test]
    fn the_wrong_drive_on_the_right_computer_is_refused() {
        let file = bound_to_machine();
        assert!(!file.device_matches(&other_device()));
        assert!(file
            .unlock(PASS, &other_device(), Some(MACHINE))
            .is_err());
    }

    #[test]
    fn the_binding_flag_is_authenticated() {
        let file = bound_to_machine();
        let mut bytes = file.encode();

        bytes[OFF_MACHINE_FLAG] = 0;
        let tampered = IdentityFile::decode(&bytes).unwrap();
        assert!(!tampered.machine_binding, "the flag itself did change");
        assert!(
            tampered.unlock(PASS, &device(), Some(MACHINE)).is_err(),
            "flipping one byte disabled the trusted-computer binding"
        );
    }

    #[test]
    fn an_undefined_flag_value_is_rejected() {
        let mut bytes = bound_to_machine().encode();
        bytes[OFF_MACHINE_FLAG] = 7;
        assert!(matches!(IdentityFile::decode(&bytes), Err(Error::Malformed)));
    }

    // --- Enabling and disabling --------------------------------------------

    #[test]
    fn binding_can_be_enabled_and_the_identity_survives() {
        let original = sealed();
        let before = original.unlock(PASS, &device(), None).unwrap();

        let bound = original
            .rebind(PASS, &device(), None, Some(MACHINE))
            .unwrap();
        assert!(bound.machine_binding);

        let after = bound.unlock(PASS, &device(), Some(MACHINE)).unwrap();
        assert_eq!(after.public_key().unwrap(), before.public_key().unwrap());
        assert_eq!(after.username, before.username);
    }

    #[test]
    fn binding_can_be_disabled_again() {
        let bound = bound_to_machine();
        let free = bound
            .rebind(PASS, &device(), Some(MACHINE), None)
            .unwrap();

        assert!(!free.machine_binding);
        assert!(free.unlock(PASS, &device(), Some(OTHER_MACHINE)).is_ok());
    }

    #[test]
    fn changing_the_setting_requires_the_passphrase() {
        let file = sealed();
        assert!(matches!(
            file.rebind(OTHER_PASS, &device(), None, Some(MACHINE)),
            Err(Error::Decrypt)
        ));

        let bound = bound_to_machine();
        assert!(matches!(
            bound.rebind(OTHER_PASS, &device(), Some(MACHINE), None),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn binding_cannot_be_disabled_from_another_computer() {
        let bound = bound_to_machine();
        assert!(bound
            .rebind(PASS, &device(), Some(OTHER_MACHINE), None)
            .is_err());
        assert!(matches!(
            bound.rebind(PASS, &device(), None, None),
            Err(Error::WrongComputer)
        ));
    }

    #[test]
    fn rebinding_uses_fresh_randomness() {
        let original = sealed();
        let rebound = original
            .rebind(PASS, &device(), None, Some(MACHINE))
            .unwrap();

        assert_ne!(original.nonce, rebound.nonce);
        assert_ne!(original.kdf_salt, rebound.kdf_salt);
        assert_ne!(original.binding_salt, rebound.binding_salt);
        assert_ne!(original.ciphertext, rebound.ciphertext);
    }

    #[test]
    fn enabling_twice_produces_unrelated_stored_values() {
        let file = sealed();
        let first = file.rebind(PASS, &device(), None, Some(MACHINE)).unwrap();
        let second = first
            .rebind(PASS, &device(), Some(MACHINE), None)
            .unwrap()
            .rebind(PASS, &device(), None, Some(MACHINE))
            .unwrap();

        assert_ne!(first.machine_binding_value, second.machine_binding_value);
        assert_ne!(first.machine_salt, second.machine_salt);
    }

    #[test]
    fn an_unbound_file_stores_no_machine_material() {
        let file = sealed();
        assert_eq!(file.machine_salt, [0u8; BINDING_SALT_LEN]);
        assert_eq!(file.machine_binding_value, [0u8; BINDING_VALUE_LEN]);
    }

    // --- Format compatibility ----------------------------------------------

    fn sealed_v1() -> Vec<u8> {
        let identity = UnlockedIdentity::generate("wisp-user").unwrap();
        let dev = device();
        let strength = dev.strength().unwrap();

        let kdf_salt: [u8; KDF_SALT_LEN] = crypto::random_array();
        let binding_salt: [u8; BINDING_SALT_LEN] = crypto::random_array();
        let nonce: [u8; NONCE_LEN] = crypto::random_array();

        let file_key = crypto::derive_file_key(PASS.as_bytes(), &kdf_salt, P).unwrap();
        let aead_key =
            crypto::derive_aead_key(&file_key, &dev.fingerprint_hash(strength).unwrap()).unwrap();

        let mut file = IdentityFile {
            format_version: 1,
            kdf_params: P,
            binding_strength: strength,
            machine_binding: false,
            kdf_salt,
            binding_salt,
            binding_value: dev.binding_value(strength, &binding_salt).unwrap(),
            machine_salt: [0u8; BINDING_SALT_LEN],
            machine_binding_value: [0u8; BINDING_VALUE_LEN],
            nonce,
            ciphertext: Vec::new(),
        };

        let payload = identity.encode_payload().unwrap();
        let prefix = file.encode_prefix((payload.len() + crypto::TAG_LEN) as u32);
        file.ciphertext =
            crypto::aead_encrypt(&aead_key, &nonce, &prefix, payload.as_slice()).unwrap();
        file.encode()
    }

    #[test]
    fn format_1_identities_still_open() {
        let bytes = sealed_v1();
        assert_eq!(bytes.len(), V1_PREFIX_LEN + 54 + crypto::TAG_LEN);

        let file = IdentityFile::decode(&bytes).unwrap();
        assert_eq!(file.format_version, 1);
        assert!(!file.machine_binding);

        let unlocked = file.unlock(PASS, &device(), None).unwrap();
        assert_eq!(unlocked.username, "wisp-user");
    }

    #[test]
    fn a_format_1_identity_can_be_bound_and_becomes_format_2() {
        let file = IdentityFile::decode(&sealed_v1()).unwrap();
        let bound = file.rebind(PASS, &device(), None, Some(MACHINE)).unwrap();

        assert_eq!(bound.format_version, 2);
        assert!(bound.machine_binding);
        assert!(bound.unlock(PASS, &device(), Some(MACHINE)).is_ok());
        assert!(bound.unlock(PASS, &device(), Some(OTHER_MACHINE)).is_err());
    }

    #[test]
    fn the_key_schedule_is_unchanged_when_binding_is_off() {
        let v1 = IdentityFile::decode(&sealed_v1()).unwrap();
        let v2 = v1.rebind(PASS, &device(), None, None).unwrap();

        assert_eq!(v2.format_version, 2);
        assert!(!v2.machine_binding);
        assert_eq!(
            v2.unlock(PASS, &device(), None).unwrap().username,
            v1.unlock(PASS, &device(), None).unwrap().username
        );
    }

    #[test]
    fn lock_wipes_key_material() {
        let mut id = UnlockedIdentity::generate("wisp-user").unwrap();
        id.lock();
        assert_eq!(id.key_material().as_slice(), &[0u8; 32]);
    }

    #[test]
    fn two_identities_on_one_drive_are_independent() {
        let a = IdentityFile::create(
            &UnlockedIdentity::generate("alice").unwrap(),
            PASS,
            &device(),
            None,
            P,
        )
        .unwrap();
        let b = IdentityFile::create(
            &UnlockedIdentity::generate("bob").unwrap(),
            PASS,
            &device(),
            None,
            P,
        )
        .unwrap();
        assert_ne!(a.binding_value, b.binding_value, "salts must differ");
        assert_ne!(a.ciphertext, b.ciphertext);
    }
}
