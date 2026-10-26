//! Failure codes (spec §11).

/// An e2ee failure. Each variant is one §11 detail code; `Display` and
/// `Debug` carry the code and at most an epoch, never plaintext, AAD values or
/// key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The endpoint holds no group state for the scope.
    #[error("not_member")]
    NotMember,
    /// An envelope's epoch is above the endpoint's current epoch.
    #[error("epoch_unknown (epoch {epoch})")]
    EpochUnknown { epoch: u64 },
    /// An older epoch's secrets are unreachable (missing link, policy
    /// cut-off, lost cache).
    #[error("history_unavailable (epoch {epoch})")]
    HistoryUnavailable { epoch: u64 },
    /// An epoch link or key-history entry fails its checks, or yields a key
    /// that does not open its content.
    #[error("link_invalid (epoch {epoch})")]
    LinkInvalid { epoch: u64 },
    /// AEAD or HPKE open failed under a verified key.
    #[error("open_failed (epoch {epoch})")]
    OpenFailed { epoch: u64 },
    /// The location string cannot be built.
    #[error("aad_mismatch")]
    AadMismatch,
    /// A mapped field arrived in plaintext for an encrypted scope.
    #[error("plaintext_rejected")]
    PlaintextRejected,
    /// Unknown envelope version or type.
    #[error("unsupported_version")]
    UnsupportedVersion,
    /// A suite other than `0x0001`.
    #[error("unsupported_suite")]
    UnsupportedSuite,
    /// Bad base64url, wrong length, bad sealed form, wrong envelope type,
    /// invalid UTF-8 or JSON after opening, invalid extension data.
    #[error("malformed")]
    Malformed,
    /// The drop public key logged for an epoch differs from the derived one.
    #[error("drop_key_mismatch (epoch {epoch})")]
    DropKeyMismatch { epoch: u64 },
    /// An outbound value could not be sealed.
    #[error("seal_failed")]
    SealFailed,
}

impl Error {
    /// The wire detail code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotMember => "not_member",
            Self::EpochUnknown { .. } => "epoch_unknown",
            Self::HistoryUnavailable { .. } => "history_unavailable",
            Self::LinkInvalid { .. } => "link_invalid",
            Self::OpenFailed { .. } => "open_failed",
            Self::AadMismatch => "aad_mismatch",
            Self::PlaintextRejected => "plaintext_rejected",
            Self::UnsupportedVersion => "unsupported_version",
            Self::UnsupportedSuite => "unsupported_suite",
            Self::Malformed => "malformed",
            Self::DropKeyMismatch { .. } => "drop_key_mismatch",
            Self::SealFailed => "seal_failed",
        }
    }

    /// The epoch involved, for the codes that carry one.
    pub fn epoch(&self) -> Option<u64> {
        match self {
            Self::EpochUnknown { epoch }
            | Self::HistoryUnavailable { epoch }
            | Self::LinkInvalid { epoch }
            | Self::OpenFailed { epoch }
            | Self::DropKeyMismatch { epoch } => Some(*epoch),
            _ => None,
        }
    }

    /// The `encryption_error` object: `{"code": <code>, "epoch"?: <integer>}`.
    pub fn to_json(&self) -> serde_json::Value {
        let mut object = serde_json::Map::new();
        object.insert("code".into(), self.code().into());
        if let Some(epoch) = self.epoch() {
            object.insert("epoch".into(), epoch.into());
        }
        object.into()
    }
}
