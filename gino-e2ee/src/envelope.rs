//! Envelope header (spec §5.2) and the salted AES-256-GCM envelopes: content
//! (§5.3) and file (§5.4), keyed per envelope from `k_e` (§4.3).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use openmls_traits::random::OpenMlsRand;
use sha2::{Digest, Sha256};

use crate::{Error, Location};

/// The envelope version byte of this specification.
pub const ENVELOPE_VERSION: u8 = 0x01;
/// The only MLS suite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
pub const SUITE: u16 = 0x0001;
/// Header length: version, type, suite, epoch.
pub const HEADER_LEN: usize = 12;
/// Length of an envelope salt.
pub const SALT_LEN: usize = 32;
/// Length of an AEAD tag.
pub const TAG_LEN: usize = 16;
/// Length of a 32-byte key (`k_e`, `d_e`, `k_msg`).
pub const KEY_LEN: usize = 32;

/// HKDF info of the per-envelope key.
const MSG_INFO: &[u8] = b"gino-e2ee/v1 msg";
/// Minimum length of a salted or HPKE envelope with an empty plaintext.
pub(crate) const MIN_SEALED_LEN: usize = HEADER_LEN + 32 + TAG_LEN;

/// An envelope type (spec §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnvelopeType {
    /// `0x01`, a content envelope.
    Content,
    /// `0x02`, a file envelope.
    File,
    /// `0x03`, a drop envelope.
    Drop,
    /// `0x04`, an epoch-link record.
    EpochLink,
    /// `0x05`, a key-history payload of an MLS application message.
    KeyHistory,
    /// `0x06`, a key-history envelope sealed to a leaf.
    KeyHistorySealed,
}

impl EnvelopeType {
    /// The type byte.
    pub fn code(self) -> u8 {
        match self {
            Self::Content => 0x01,
            Self::File => 0x02,
            Self::Drop => 0x03,
            Self::EpochLink => 0x04,
            Self::KeyHistory => 0x05,
            Self::KeyHistorySealed => 0x06,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0x01 => Self::Content,
            0x02 => Self::File,
            0x03 => Self::Drop,
            0x04 => Self::EpochLink,
            0x05 => Self::KeyHistory,
            0x06 => Self::KeyHistorySealed,
            _ => return None,
        })
    }

    /// The shortest valid envelope of this type.
    fn min_len(self) -> usize {
        match self {
            Self::Content | Self::File | Self::Drop => MIN_SEALED_LEN,
            Self::EpochLink => crate::history::EPOCH_LINK_LEN,
            Self::KeyHistory => crate::history::MIN_KEY_HISTORY_LEN,
            Self::KeyHistorySealed => crate::history::MIN_KEY_HISTORY_SEALED_LEN,
        }
    }
}

/// An envelope header: `version (1) || type (1) || suite (u16) || epoch (u64)`.
/// Version and suite are fixed in v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The envelope type.
    pub envelope_type: EnvelopeType,
    /// The MLS epoch whose secrets produced the envelope.
    pub epoch: u64,
}

impl Header {
    /// A v1 header of `envelope_type` for `epoch`.
    pub fn new(envelope_type: EnvelopeType, epoch: u64) -> Self {
        Self {
            envelope_type,
            epoch,
        }
    }

    /// Parses the header of an envelope and checks the envelope against its
    /// type's minimum length. A short envelope is `malformed`, another version
    /// or an unknown type `unsupported_version`, another suite
    /// `unsupported_suite`.
    pub fn parse(envelope: &[u8]) -> Result<Self, Error> {
        let header: &[u8; HEADER_LEN] = envelope.first_chunk().ok_or(Error::Malformed)?;
        let [version, code, s0, s1, epoch @ ..] = *header;
        if version != ENVELOPE_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        let envelope_type = EnvelopeType::from_code(code).ok_or(Error::UnsupportedVersion)?;
        if u16::from_be_bytes([s0, s1]) != SUITE {
            return Err(Error::UnsupportedSuite);
        }
        if envelope.len() < envelope_type.min_len() {
            return Err(Error::Malformed);
        }
        Ok(Self::new(envelope_type, u64::from_be_bytes(epoch)))
    }

    /// Parses the header and requires `expected` as its type; a known type in
    /// the wrong place is `malformed`.
    pub fn parse_as(envelope: &[u8], expected: EnvelopeType) -> Result<Self, Error> {
        let header = Self::parse(envelope)?;
        if header.envelope_type == expected {
            Ok(header)
        } else {
            Err(Error::Malformed)
        }
    }

    /// The 12 header bytes.
    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let mut bytes = [0u8; HEADER_LEN];
        bytes[0] = ENVELOPE_VERSION;
        bytes[1] = self.envelope_type.code();
        bytes[2..4].copy_from_slice(&SUITE.to_be_bytes());
        bytes[4..].copy_from_slice(&self.epoch.to_be_bytes());
        bytes
    }

    /// The AEAD additional data `header || location`.
    pub(crate) fn ad(self, location: &Location) -> Vec<u8> {
        [&self.to_bytes()[..], location.as_bytes()].concat()
    }
}

/// The per-envelope key: `HKDF-Expand(HKDF-Extract(salt, k_e), "gino-e2ee/v1 msg", 32)`.
pub fn message_key(k_e: &[u8; KEY_LEN], salt: &[u8; SALT_LEN]) -> Result<[u8; KEY_LEN], Error> {
    let mut k_msg = [0u8; KEY_LEN];
    Hkdf::<Sha256>::new(Some(&salt[..]), k_e)
        .expand(MSG_INFO, &mut k_msg)
        .map_err(|_| Error::SealFailed)?;
    Ok(k_msg)
}

/// Seals `header || salt || AES-256-GCM(k_msg, 0^12, plaintext, header || location)`
/// with a salt drawn from `rng`.
pub(crate) fn seal_salted(
    header: Header,
    k_e: &[u8; KEY_LEN],
    location: &Location,
    plaintext: &[u8],
    rng: &impl OpenMlsRand,
) -> Result<Vec<u8>, Error> {
    let salt: [u8; SALT_LEN] = rng.random_array().map_err(|_| Error::SealFailed)?;
    let cipher = Aes256Gcm::new(&message_key(k_e, &salt)?.into());
    let ad = header.ad(location);
    let ciphertext = cipher
        .encrypt(
            &Nonce::default(),
            Payload {
                msg: plaintext,
                aad: &ad,
            },
        )
        .map_err(|_| Error::SealFailed)?;
    Ok([&header.to_bytes()[..], &salt, &ciphertext].concat())
}

/// Opens a salted envelope whose header was already parsed. A failure is
/// `open_failed` with the header epoch.
pub(crate) fn open_salted(
    header: Header,
    k_e: &[u8; KEY_LEN],
    envelope: &[u8],
    location: &Location,
) -> Result<Vec<u8>, Error> {
    let failed = Error::OpenFailed {
        epoch: header.epoch,
    };
    let (salt, ciphertext) = envelope
        .get(HEADER_LEN..)
        .and_then(|rest| rest.split_first_chunk::<SALT_LEN>())
        .ok_or(Error::Malformed)?;
    let cipher = Aes256Gcm::new(&message_key(k_e, salt).map_err(|_| failed)?.into());
    let ad = header.ad(location);
    cipher
        .decrypt(
            &Nonce::default(),
            Payload {
                msg: ciphertext,
                aad: &ad,
            },
        )
        .map_err(|_| failed)
}

/// Seals a content envelope (spec §5.3) under the content key `k_e` of `epoch`.
pub fn seal_content(
    k_e: &[u8; KEY_LEN],
    epoch: u64,
    location: &Location,
    plaintext: &[u8],
    rng: &impl OpenMlsRand,
) -> Result<Vec<u8>, Error> {
    seal_salted(
        Header::new(EnvelopeType::Content, epoch),
        k_e,
        location,
        plaintext,
        rng,
    )
}

/// Opens a content envelope under `k_e`, the content key of its header epoch.
pub fn open_content(
    k_e: &[u8; KEY_LEN],
    envelope: &[u8],
    location: &Location,
) -> Result<Vec<u8>, Error> {
    let header = Header::parse_as(envelope, EnvelopeType::Content)?;
    open_salted(header, k_e, envelope, location)
}

/// A sealed file and the attachment descriptor values of its envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedFile {
    /// The file envelope.
    pub envelope: Vec<u8>,
    /// The digest of the envelope.
    pub digest: FileDigest,
}

/// The `sha256` and `size` of a file envelope, checkable without a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDigest {
    /// Lower-case hex SHA-256 of the whole envelope.
    pub sha256: String,
    /// Length of the envelope in bytes.
    pub size: u64,
}

impl FileDigest {
    /// The digest of a file envelope.
    pub fn of(envelope: &[u8]) -> Self {
        Self {
            sha256: crate::hex(&Sha256::digest(envelope)),
            size: envelope.len() as u64,
        }
    }
}

/// Seals a whole file as a file envelope (spec §5.4); the per-file key is the
/// envelope's `k_msg`.
pub fn seal_file(
    k_e: &[u8; KEY_LEN],
    epoch: u64,
    location: &Location,
    bytes: &[u8],
    rng: &impl OpenMlsRand,
) -> Result<SealedFile, Error> {
    let envelope = seal_salted(
        Header::new(EnvelopeType::File, epoch),
        k_e,
        location,
        bytes,
        rng,
    )?;
    let digest = FileDigest::of(&envelope);
    Ok(SealedFile { envelope, digest })
}

/// Opens a file envelope under `k_e`, the content key of its header epoch.
pub fn open_file(
    k_e: &[u8; KEY_LEN],
    envelope: &[u8],
    location: &Location,
) -> Result<Vec<u8>, Error> {
    let header = Header::parse_as(envelope, EnvelopeType::File)?;
    open_salted(header, k_e, envelope, location)
}

#[cfg(test)]
mod tests {
    use openmls_rust_crypto::RustCrypto;

    use super::*;

    const K: [u8; 32] = [7; 32];

    fn location() -> Location {
        Location::new("t-1").unwrap().part("field", "text").unwrap()
    }

    #[test]
    fn content_round_trip_and_layout() {
        let rng = RustCrypto::default();
        let envelope = seal_content(&K, 5, &location(), b"hello", &rng).unwrap();
        assert_eq!(envelope.len(), MIN_SEALED_LEN + 5);
        assert_eq!(&envelope[..4], &[1, 1, 0, 1]);
        assert_eq!(
            Header::parse(&envelope).unwrap(),
            Header::new(EnvelopeType::Content, 5)
        );
        assert_eq!(open_content(&K, &envelope, &location()).unwrap(), b"hello");

        let other = Location::new("t-1").unwrap().part("field", "x").unwrap();
        assert_eq!(
            open_content(&K, &envelope, &other),
            Err(Error::OpenFailed { epoch: 5 })
        );
        assert_eq!(
            open_content(&[8; 32], &envelope, &location()),
            Err(Error::OpenFailed { epoch: 5 })
        );
        assert_eq!(open_file(&K, &envelope, &location()), Err(Error::Malformed));
    }

    #[test]
    fn header_checks() {
        let rng = RustCrypto::default();
        let envelope = seal_content(&K, 1, &location(), b"", &rng).unwrap();
        let with = |i: usize, b: u8| {
            let mut e = envelope.clone();
            e[i] = b;
            Header::parse(&e)
        };
        assert_eq!(with(0, 2), Err(Error::UnsupportedVersion));
        assert_eq!(with(1, 0), Err(Error::UnsupportedVersion));
        assert_eq!(with(1, 7), Err(Error::UnsupportedVersion));
        assert_eq!(with(3, 2), Err(Error::UnsupportedSuite));
        assert_eq!(Header::parse(&envelope[..59]), Err(Error::Malformed));
        assert_eq!(Header::parse(&envelope[..11]), Err(Error::Malformed));
        assert_eq!(Header::parse(&[]), Err(Error::Malformed));
    }

    #[test]
    fn file_digest_covers_the_envelope() {
        let rng = RustCrypto::default();
        let sealed = seal_file(&K, 2, &location(), b"file bytes", &rng).unwrap();
        assert_eq!(sealed.digest, FileDigest::of(&sealed.envelope));
        assert_eq!(sealed.digest.size, sealed.envelope.len() as u64);
        assert_eq!(sealed.digest.sha256.len(), 64);
        assert_eq!(
            open_file(&K, &sealed.envelope, &location()).unwrap(),
            b"file bytes"
        );
    }
}
