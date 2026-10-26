//! Keyless inspection of public MLS structures for the Delivery Service
//! (spec §3.2, §3.3, §3.5): KeyPackage upload checks, commit and proposal
//! framing, and the recipients of a Welcome.

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_rust_crypto::RustCrypto;

use crate::Error;
use crate::mls::{CIPHERSUITE, POLICY_EXTENSION, PROFILE_EXTENSION, check_credential, deserialize};

/// A rejected input: the spec §11 code (`malformed` or `unsupported_suite`)
/// and a short reason that names no secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{error}: {reason}")]
pub struct InspectError {
    pub error: Error,
    pub reason: &'static str,
}

/// The RefHash label of a KeyPackageRef (RFC 9420 §5.2).
const KEY_PACKAGE_REF_LABEL: &[u8] = b"MLS 1.0 KeyPackage Reference";

fn malformed(reason: &'static str) -> InspectError {
    InspectError {
        error: Error::Malformed,
        reason,
    }
}

/// The public facts of a valid KeyPackage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPackageInfo {
    /// The KeyPackageRef (RFC 9420 §5.2) under suite `0x0001`.
    pub reference: Vec<u8>,
    /// The raw Ed25519 public key of the credential and leaf.
    pub public_key: [u8; 32],
    /// Whether it carries the `last_resort` extension.
    pub last_resort: bool,
    /// Lifetime bounds, seconds since the Unix epoch.
    pub not_before: u64,
    pub not_after: u64,
}

/// Validates an uploaded KeyPackage (TLS-serialized `MLSMessage`) at `now`
/// (seconds since the Unix epoch): the KeyPackage and leaf signatures, suite
/// `0x0001`, the lifetime, the capabilities of spec §2.5 and the credential
/// rule of spec §2.2. A wrong suite is `unsupported_suite`, anything else
/// `malformed`.
pub fn inspect_key_package(bytes: &[u8], now: u64) -> Result<KeyPackageInfo, InspectError> {
    let message = deserialize(bytes).map_err(|_| malformed("not an MLSMessage"))?;
    let MlsMessageBodyIn::KeyPackage(key_package) = message.extract() else {
        return Err(malformed("not a KeyPackage"));
    };
    // version, wire_format, then the KeyPackage's protocol_version and suite.
    if bytes.get(6..8) != Some(&u16::from(CIPHERSUITE).to_be_bytes()[..]) {
        return Err(InspectError {
            error: Error::UnsupportedSuite,
            reason: "suite is not 0x0001",
        });
    }
    let crypto = RustCrypto::default();
    let key_package = key_package
        .validate(&crypto, ProtocolVersion::Mls10)
        .map_err(|_| malformed("KeyPackage validation failed"))?;
    let lifetime = key_package.life_time();
    if now < lifetime.not_before() {
        return Err(malformed("KeyPackage not yet valid"));
    }
    if now > lifetime.not_after() {
        return Err(malformed("KeyPackage expired"));
    }
    let leaf = key_package.leaf_node();
    let extensions = leaf.capabilities().extensions();
    if ![PROFILE_EXTENSION, POLICY_EXTENSION]
        .iter()
        .all(|t| extensions.contains(&ExtensionType::Unknown(*t)))
    {
        return Err(malformed("missing required capabilities"));
    }
    check_credential(leaf.credential(), leaf.signature_key().as_slice())
        .map_err(|_| malformed("credential is not a BasicCredential of the Ed25519 key"))?;
    let public_key = leaf
        .signature_key()
        .as_slice()
        .try_into()
        .map_err(|_| malformed("signature key is not 32 bytes"))?;
    let reference = key_package
        .hash_ref(&crypto)
        .map_err(|_| malformed("KeyPackageRef unavailable"))?;
    Ok(KeyPackageInfo {
        reference: reference.as_slice().to_vec(),
        public_key,
        last_resort: key_package.last_resort(),
        not_before: lifetime.not_before(),
        not_after: lifetime.not_after(),
    })
}

/// The content type of a PublicMessage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageContent {
    Commit,
    Proposal,
    Application,
}

impl MessageContent {
    /// `"commit"`, `"proposal"` or `"application"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Proposal => "proposal",
            Self::Application => "application",
        }
    }
}

/// The cleartext framing of a PublicMessage and the membership changes it
/// carries. Membership of the sender is not verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageInfo {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub content_type: MessageContent,
    /// The sender's leaf index.
    pub sender_leaf: u32,
    /// The KeyPackageRef of each Add proposal carried by value, in order.
    pub adds: Vec<Vec<u8>>,
    /// The leaf index of each Remove proposal carried by value, in order.
    pub removes: Vec<u32>,
    /// The ProposalRefs of proposals a commit carries by reference.
    pub proposal_refs: Vec<Vec<u8>>,
    /// Whether a commit carries an UpdatePath.
    pub updates_path: bool,
}

/// Inspects an `MLSMessage` PublicMessage (spec §3.2). Any other wire
/// format, a non-member sender or a body that does not parse is
/// `malformed`.
pub fn inspect_message(bytes: &[u8]) -> Result<MessageInfo, InspectError> {
    let message = deserialize(bytes).map_err(|_| malformed("not an MLSMessage"))?;
    let public = match message.extract() {
        MlsMessageBodyIn::PublicMessage(public) => public,
        MlsMessageBodyIn::PrivateMessage(_) => {
            return Err(malformed("expected a PublicMessage, got a PrivateMessage"));
        }
        MlsMessageBodyIn::Welcome(_) => {
            return Err(malformed("expected a PublicMessage, got a Welcome"));
        }
        MlsMessageBodyIn::GroupInfo(_) => {
            return Err(malformed("expected a PublicMessage, got a GroupInfo"));
        }
        MlsMessageBodyIn::KeyPackage(_) => {
            return Err(malformed("expected a PublicMessage, got a KeyPackage"));
        }
    };
    let Sender::Member(sender) = public.sender() else {
        return Err(malformed("sender is not a member"));
    };
    let mut info = MessageInfo {
        group_id: public.group_id().as_slice().to_vec(),
        epoch: public.epoch().as_u64(),
        content_type: MessageContent::Application,
        sender_leaf: sender.u32(),
        adds: Vec::new(),
        removes: Vec::new(),
        proposal_refs: Vec::new(),
        updates_path: false,
    };
    let mut body = framed_content_body(bytes).map_err(|_| malformed("bad framing"))?;
    let crypto = RustCrypto::default();
    match public.content_type() {
        ContentType::Application => {}
        ContentType::Proposal => {
            info.content_type = MessageContent::Proposal;
            let proposal =
                ProposalIn::tls_deserialize(&mut body).map_err(|_| malformed("bad proposal"))?;
            info.record(&proposal, &crypto)?;
        }
        ContentType::Commit => {
            info.content_type = MessageContent::Commit;
            let proposals = Vec::<ProposalOrRefIn>::tls_deserialize(&mut body)
                .map_err(|_| malformed("bad commit"))?;
            // The presence octet of `optional<UpdatePath> path`; the path
            // itself was checked when the message parsed.
            info.updates_path = match u8::tls_deserialize(&mut body) {
                Ok(0) => false,
                Ok(1) => true,
                _ => return Err(malformed("bad commit")),
            };
            for proposal in &proposals {
                match proposal {
                    ProposalOrRefIn::Proposal(proposal) => info.record(proposal, &crypto)?,
                    ProposalOrRefIn::Reference(reference) => {
                        info.proposal_refs.push(reference.as_slice().to_vec());
                    }
                }
            }
        }
    }
    Ok(info)
}

impl MessageInfo {
    /// Records an Add or Remove proposal; other types are not reported.
    fn record(&mut self, proposal: &ProposalIn, crypto: &RustCrypto) -> Result<(), InspectError> {
        match proposal {
            ProposalIn::Add(add) => {
                // An Add encodes exactly its KeyPackage.
                let key_package = add
                    .tls_serialize_detached()
                    .map_err(|_| malformed("bad Add proposal"))?;
                let reference =
                    KeyPackageRef::new(&key_package, CIPHERSUITE, crypto, KEY_PACKAGE_REF_LABEL)
                        .map_err(|_| malformed("KeyPackageRef unavailable"))?;
                self.adds.push(reference.as_slice().to_vec());
            }
            ProposalIn::Remove(remove) => self.removes.push(remove.removed().u32()),
            _ => {}
        }
        Ok(())
    }
}

/// The `FramedContent` body of a PublicMessage `MLSMessage` that already
/// parsed: the bytes after `version`, `wire_format`, `group_id`, `epoch`,
/// `sender`, `authenticated_data` and `content_type`.
fn framed_content_body(bytes: &[u8]) -> Result<&[u8], tls_codec::Error> {
    let mut reader = bytes.get(4..).ok_or(tls_codec::Error::EndOfStream)?;
    VLBytes::tls_deserialize(&mut reader)?;
    u64::tls_deserialize(&mut reader)?;
    Sender::tls_deserialize(&mut reader)?;
    VLBytes::tls_deserialize(&mut reader)?;
    u8::tls_deserialize(&mut reader)?;
    Ok(reader)
}

/// The `new_member` KeyPackageRefs of an `MLSMessage` Welcome's `secrets`,
/// in order (spec §3.3). Anything else is `malformed`.
pub fn welcome_recipients(bytes: &[u8]) -> Result<Vec<Vec<u8>>, InspectError> {
    let message = deserialize(bytes).map_err(|_| malformed("not an MLSMessage"))?;
    let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
        return Err(malformed("not a Welcome"));
    };
    Ok(welcome
        .secrets()
        .iter()
        .map(|secrets| secrets.new_member().as_slice().to_vec())
        .collect())
}
