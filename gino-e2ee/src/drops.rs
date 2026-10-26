//! Drops (spec §4.4, §5.5, §9): HPKE base mode to a per-epoch key pair
//! derived from the drop seed `d_e`, through the OpenMLS crypto provider.

use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{
    HpkeAeadType, HpkeCiphertext, HpkeConfig, HpkeKdfType, HpkeKemType, HpkePrivateKey,
};

use crate::envelope::{HEADER_LEN, KEY_LEN};
use crate::{EnvelopeType, Error, Header, Location};

/// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
pub(crate) const HPKE_SUITE: HpkeConfig = HpkeConfig(
    HpkeKemType::DhKem25519,
    HpkeKdfType::HkdfSha256,
    HpkeAeadType::AesGcm128,
);
/// Length of an X25519 public key and of the HPKE `enc`.
pub(crate) const ENC_LEN: usize = 32;
/// HPKE info of drop envelopes.
const DROP_INFO: &[u8] = b"gino-e2ee/v1 drop";

/// The drop key pair of an epoch: RFC 9180 `DeriveKeyPair(d_e)`.
#[derive(Clone)]
pub struct DropKeyPair {
    private: HpkePrivateKey,
    public: [u8; ENC_LEN],
}

impl std::fmt::Debug for DropKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DropKeyPair")
            .field("public", &crate::hex(&self.public))
            .finish_non_exhaustive()
    }
}

impl DropKeyPair {
    /// Derives the key pair from the drop seed `d_e`.
    pub fn derive(crypto: &impl OpenMlsCrypto, d_e: &[u8; KEY_LEN]) -> Result<Self, Error> {
        let pair = crypto
            .derive_hpke_keypair(HPKE_SUITE, d_e)
            .map_err(|_| Error::SealFailed)?;
        let public = pair.public.try_into().map_err(|_| Error::SealFailed)?;
        Ok(Self {
            private: pair.private,
            public,
        })
    }

    /// The 32-byte X25519 public key the scope publishes.
    pub fn public_key(&self) -> &[u8; ENC_LEN] {
        &self.public
    }

    /// The 32-byte X25519 private key.
    pub fn private_key(&self) -> &[u8] {
        &self.private
    }
}

/// Compares a logged drop public key of `epoch` with the one derived from
/// `d_e`; a difference is `drop_key_mismatch`.
pub fn verify_drop_public_key(
    crypto: &impl OpenMlsCrypto,
    d_e: &[u8; KEY_LEN],
    epoch: u64,
    logged: &[u8],
) -> Result<(), Error> {
    let pair = DropKeyPair::derive(crypto, d_e)?;
    if pair.public_key().as_slice() == logged {
        Ok(())
    } else {
        Err(Error::DropKeyMismatch { epoch })
    }
}

/// Seals a drop envelope (spec §5.5) to the drop public key `pk` of `epoch`.
/// The HPKE ephemeral key comes from the provider's randomness.
pub fn seal_drop(
    crypto: &impl OpenMlsCrypto,
    pk: &[u8],
    epoch: u64,
    location: &Location,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let header = Header::new(EnvelopeType::Drop, epoch);
    let sealed = hpke_seal(crypto, pk, DROP_INFO, &header.ad(location), plaintext)?;
    Ok([&header.to_bytes()[..], &sealed].concat())
}

/// Opens a drop envelope with the drop seed `d_e` of its header epoch.
pub fn open_drop(
    crypto: &impl OpenMlsCrypto,
    d_e: &[u8; KEY_LEN],
    envelope: &[u8],
    location: &Location,
) -> Result<Vec<u8>, Error> {
    let header = Header::parse_as(envelope, EnvelopeType::Drop)?;
    let failed = Error::OpenFailed {
        epoch: header.epoch,
    };
    let pair = DropKeyPair::derive(crypto, d_e).map_err(|_| failed)?;
    let sealed = envelope.get(HEADER_LEN..).ok_or(Error::Malformed)?;
    hpke_open(
        crypto,
        pair.private_key(),
        DROP_INFO,
        &header.ad(location),
        sealed,
    )
    .map_err(|_| failed)
}

/// HPKE base-mode seal; returns `enc (32) || ciphertext || tag`.
pub(crate) fn hpke_seal(
    crypto: &impl OpenMlsCrypto,
    pk: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    if pk.len() != ENC_LEN {
        return Err(Error::Malformed);
    }
    let sealed = crypto
        .hpke_seal(HPKE_SUITE, pk, info, aad, plaintext)
        .map_err(|_| Error::SealFailed)?;
    let enc = sealed.kem_output.as_slice();
    if enc.len() != ENC_LEN {
        return Err(Error::SealFailed);
    }
    Ok([enc, sealed.ciphertext.as_slice()].concat())
}

/// HPKE base-mode open of `enc (32) || ciphertext || tag`. Any failure is
/// `malformed`; callers map it to their code.
pub(crate) fn hpke_open(
    crypto: &impl OpenMlsCrypto,
    sk: &[u8],
    info: &[u8],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, Error> {
    let (enc, ciphertext) = sealed
        .split_first_chunk::<ENC_LEN>()
        .ok_or(Error::Malformed)?;
    let input = HpkeCiphertext {
        kem_output: enc.to_vec().into(),
        ciphertext: ciphertext.to_vec().into(),
    };
    crypto
        .hpke_open(HPKE_SUITE, &input, sk, info, aad)
        .map_err(|_| Error::Malformed)
}

#[cfg(test)]
mod tests {
    use openmls_rust_crypto::RustCrypto;

    use super::*;

    #[test]
    fn drop_round_trip() {
        let crypto = RustCrypto::default();
        let d_e = [3u8; 32];
        let pair = DropKeyPair::derive(&crypto, &d_e).unwrap();
        let location = Location::new("t-1").unwrap().part("field", "body").unwrap();
        let envelope = seal_drop(&crypto, pair.public_key(), 4, &location, b"hi").unwrap();
        assert_eq!(envelope.len(), 12 + 32 + 2 + 16);
        assert_eq!(
            open_drop(&crypto, &d_e, &envelope, &location).unwrap(),
            b"hi"
        );

        let other = Location::new("t-2").unwrap().part("field", "body").unwrap();
        assert_eq!(
            open_drop(&crypto, &d_e, &envelope, &other),
            Err(Error::OpenFailed { epoch: 4 })
        );
        assert_eq!(
            open_drop(&crypto, &[4u8; 32], &envelope, &location),
            Err(Error::OpenFailed { epoch: 4 })
        );
        assert_eq!(
            seal_drop(&crypto, &[1u8; 31], 4, &location, b"hi"),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn drop_public_key_check() {
        let crypto = RustCrypto::default();
        let d_e = [5u8; 32];
        let pair = DropKeyPair::derive(&crypto, &d_e).unwrap();
        assert_eq!(
            verify_drop_public_key(&crypto, &d_e, 9, pair.public_key()),
            Ok(())
        );
        assert_eq!(
            verify_drop_public_key(&crypto, &d_e, 9, &[0u8; 32]),
            Err(Error::DropKeyMismatch { epoch: 9 })
        );
    }
}
