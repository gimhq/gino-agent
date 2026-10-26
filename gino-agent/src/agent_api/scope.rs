//! Caller scopes: run tokens, the token registry, the operator peer check and
//! per-scope connection limits.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use sha2::{Digest, Sha256};
use tokio::net::unix::UCred;

/// Concurrent authenticated connections allowed per run token, and for operator
/// access.
pub(crate) const MAX_CONNECTIONS_PER_SCOPE: usize = 8;

/// The task and thread a run token is bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RunScope {
    pub(crate) task_id: String,
    pub(crate) thread_id: String,
}

/// What a connection may access.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    Operator,
    Run(RunScope),
}

/// A run token's hex secret. `Debug` never prints the value.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RunToken(String);

impl RunToken {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RunToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RunToken(<redacted>)")
    }
}

pub(super) type TokenHash = [u8; 32];

pub(super) fn token_hash(token: &str) -> TokenHash {
    Sha256::digest(token.as_bytes()).into()
}

/// Live run tokens, keyed by the SHA-256 of the secret.
#[derive(Clone, Debug, Default)]
pub(crate) struct TokenRegistry {
    tokens: Arc<Mutex<HashMap<TokenHash, RunScope>>>,
}

impl TokenRegistry {
    fn lock(&self) -> MutexGuard<'_, HashMap<TokenHash, RunScope>> {
        self.tokens.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Mint a fresh token for `scope`.
    pub(crate) fn register(&self, scope: RunScope) -> RunToken {
        let token = RunToken(hex(&random_bytes()));
        self.lock().insert(token_hash(token.as_str()), scope);
        token
    }

    /// Forget `token`; later lookups of it fail.
    pub(crate) fn revoke(&self, token: &str) {
        self.lock().remove(&token_hash(token));
    }

    /// The scope `token` grants, if it is live.
    pub(crate) fn lookup(&self, token: &str) -> Option<RunScope> {
        self.lookup_hash(&token_hash(token))
    }

    fn lookup_hash(&self, hash: &TokenHash) -> Option<RunScope> {
        self.lock().get(hash).cloned()
    }
}

/// 32 bytes from `/dev/urandom`, falling back to the OS RNG behind uuid v4 if
/// the device cannot be read.
fn random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let read = fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes));
    if let Err(err) = read {
        tracing::warn!(error = %err, "reading /dev/urandom failed; using the uuid RNG");
        bytes[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        bytes[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    }
    bytes
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The `user` and `pid` namespace link targets of a process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NsLinks {
    pub(crate) user: PathBuf,
    pub(crate) pid: PathBuf,
}

/// Read `<proc_dir>/ns/{user,pid}`; `None` on any failure.
pub(crate) fn read_ns_links(proc_dir: &Path) -> Option<NsLinks> {
    Some(NsLinks {
        user: fs::read_link(proc_dir.join("ns/user")).ok()?,
        pid: fs::read_link(proc_dir.join("ns/pid")).ok()?,
    })
}

/// Operator iff the uids match and both namespace sets are known and equal.
pub(crate) fn is_operator(
    peer_uid: u32,
    daemon_uid: u32,
    peer_ns: Option<&NsLinks>,
    own_ns: Option<&NsLinks>,
) -> bool {
    match (peer_ns, own_ns) {
        (Some(peer), Some(own)) => peer_uid == daemon_uid && peer == own,
        _ => false,
    }
}

/// Whether the peer behind `cred` gets operator access.
pub(crate) fn peer_is_operator(cred: &UCred) -> bool {
    let peer_ns = cred
        .pid()
        .and_then(|pid| read_ns_links(&Path::new("/proc").join(pid.to_string())));
    let own_ns = read_ns_links(Path::new("/proc/self"));
    is_operator(
        cred.uid(),
        nix::unistd::geteuid().as_raw(),
        peer_ns.as_ref(),
        own_ns.as_ref(),
    )
}

/// Which per-scope connection budget a connection draws on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum LimitKey {
    Operator,
    Token(TokenHash),
}

/// Counts concurrent connections per operator / run token.
#[derive(Clone, Debug, Default)]
pub(crate) struct ConnectionLimits {
    counts: Arc<Mutex<HashMap<LimitKey, usize>>>,
}

impl ConnectionLimits {
    pub(crate) fn acquire_operator(&self) -> Option<ConnectionGuard> {
        self.acquire(LimitKey::Operator)
    }

    pub(crate) fn acquire_token(&self, token: &str) -> Option<ConnectionGuard> {
        self.acquire(LimitKey::Token(token_hash(token)))
    }

    fn acquire(&self, key: LimitKey) -> Option<ConnectionGuard> {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let count = counts.entry(key).or_insert(0);
        if *count >= MAX_CONNECTIONS_PER_SCOPE {
            return None;
        }
        *count += 1;
        Some(ConnectionGuard {
            limits: self.clone(),
            key,
        })
    }
}

/// One counted connection; releases its slot on drop.
#[derive(Debug)]
pub(crate) struct ConnectionGuard {
    limits: ConnectionLimits,
    key: LimitKey,
}

impl ConnectionGuard {
    /// The scope this connection currently holds; `None` once its token has been
    /// revoked.
    pub(crate) fn scope(&self, registry: &TokenRegistry) -> Option<Scope> {
        match &self.key {
            LimitKey::Operator => Some(Scope::Operator),
            LimitKey::Token(hash) => registry.lookup_hash(hash).map(Scope::Run),
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut counts = self
            .limits
            .counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = counts.get_mut(&self.key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.key);
            }
        }
    }
}
