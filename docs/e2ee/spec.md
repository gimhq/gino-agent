# gino e2ee framework specification (v1)

Status: **normative** for envelope version `0x01`. This document is the contract. Profiles sit next to it; the first one is
[`task-content.md`](task-content.md) (gino's task flow), with its machine-readable field map
[`task-content.fieldmap.json`](task-content.fieldmap.json).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119 and only where an
implementation choice affects interoperability or security.

Notation:

- `||` is byte concatenation. `u16`, `u32`, `u64` are unsigned big-endian integers of 2, 4
  and 8 bytes. `len16(x)` is `u16(byte length of x)`.
- `"…"` in a byte formula is the UTF-8 encoding of the string, without a terminator.
- Hex in examples is lower-case. Lengths are in bytes.

## 1. Model and terms

- **Relay.** Any host (the gino host first) that routes, stores, schedules and displays
  metadata. It is untrusted for confidentiality: its database, logs, backups and administrators
  may be read. It never holds a key that opens protected content. It is trusted for routing in
  the baseline (plan §1); an actively malicious relay that rewrites framing is a non-goal.
- **Scope.** The unit of protection a profile chooses (for gino's task flow: one task). A scope
  has a **scope id**, a UTF-8 string assigned by the relay, at most 65535 bytes, not containing
  `|`.
- **Profile.** A document that names a scope kind, the sealed fields of the frames that carry
  it (its field map, §12), their AAD templates and endpoint rules. A profile has a **profile
  id**, an ASCII string matching `^[a-z0-9]+(\.[a-z0-9-]+)*\.v[0-9]+$`.
- **MLS group.** One RFC 9420 group per scope (§2). Its group id is derived from the profile
  id and the scope id.
- **Member.** A party holding a leaf in the scope's group: a runner, or a client device. Only
  members can open or seal content.
- **Delivery Service (DS).** The relay's role for MLS (§3): the ordered handshake log, the
  KeyPackage directory, Welcome delivery and the storage of history records. The DS stores
  only opaque bytes and public material.
- **Drop sender.** A writer without membership (inbound webhook, external service, the relay
  itself acting for one). It can seal to a scope's published drop public key (§9) and cannot
  read anything.
- **Epoch secrets.** For each MLS epoch `e` of a scope, the pair `E_e = (k_e, d_e)`: the
  content key `k_e` and the drop seed `d_e` (§4).

Visible to the relay (metadata): party, scope, task, thread and message ids; `seq`, epochs,
timestamps; frame types and kinds, tool names, status, failure reasons, sizes and counts;
suite ids, public keys, credentials, the membership list (MLS handshake messages are
PublicMessages, §2.6); every field a profile does not seal. Protected (confidentiality and
integrity): every field a profile seals, each bound to its location by its AAD (§6).

## 2. MLS profile

### 2.1 Ciphersuite

v1 uses exactly one suite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (`0x0001`). A party
MUST reject a KeyPackage, Welcome, GroupInfo or message of any other suite with
`unsupported_suite`. Further suites come from the RFC 9420 registry and are announced through
the capability (§10).

### 2.2 Credential

- Credential type `basic` (`0x0001`). The BasicCredential `identity` is the **raw 32-byte
  Ed25519 public key** of the party. The leaf's `signature_key` MUST be the same 32 bytes. A
  leaf or KeyPackage where they differ is rejected (`malformed`).
- The signature scheme is `ed25519` (`0x0807`).
- The private key is the 32-byte Ed25519 seed (RFC 8032). It never leaves the party.
- The binding of a public key to a party (runner `agentId`, client user and device) is held by
  the DS directory (§3.5), not by MLS.

### 2.3 Group id

```
group_id = SHA-256("gino-e2ee/v1 group" || len16(P) || P || len16(S) || S)
```

where `P` is the UTF-8 profile id and `S` the UTF-8 scope id. The group id is 32 bytes. A
member joining from a Welcome MUST recompute it from the profile id extension (§2.4) and the
scope id it was told, and MUST reject the Welcome if it differs (`malformed`).

Example: `P = "gino.task-content.v1"`, `S = "t-1"` hashes
`"gino-e2ee/v1 group" || 0014 || "gino.task-content.v1" || 0003 || "t-1"`.

### 2.4 Group context extensions

Both extensions use RFC 9420 private-use extension types (`0xF000..=0xFFFF`). Their
`extension_data` is given below; MLS adds its own length prefix around it.

| type | name | `extension_data` |
|---|---|---|
| `0xF0E1` | profile id | the UTF-8 profile id, raw (no further length prefix) |
| `0xF0E2` | history policy | one of the encodings below |

History policy encoding:

| policy | bytes |
|---|---|
| `full` | `00` |
| `from_epoch N` | `01 \|\| u64(N)` (9 bytes) |
| `from_join` | `02` |

Any other value is `malformed`. Both extensions MUST be present in every group, from epoch 0.
The profile id extension MUST NOT change. The history policy changes only by a Commit carrying
a GroupContextExtensions proposal; that proposal replaces the whole list, so it repeats the
profile id extension and the required capabilities unchanged.

### 2.5 Capabilities

- Every leaf (group creator config and every KeyPackage) advertises capabilities with:
  versions `[mls10]`, ciphersuites `[0x0001]`, extensions `[0xF0E1, 0xF0E2, 0x000A]`,
  credentials `[basic]`, proposals as the MLS default. `last_resort` (`0x000A`) is listed
  because OpenMLS accepts a KeyPackage only if every extension it carries is in its leaf
  capabilities, and last-resort KeyPackages (§2.7) carry it.
- The group context carries a `required_capabilities` extension with extension types
  `[0xF0E1, 0xF0E2]`, proposal types `[]` and credential types `[]` (BasicCredential is
  enforced by §2.2, not by this list). A KeyPackage without both extension types cannot be
  added (OpenMLS fails with `InsufficientCapabilities`).
- Welcome messages carry the ratchet tree in the GroupInfo (`ratchet_tree` extension), so the
  DS never serves trees.

### 2.6 Wire format

- All MLS messages travel as TLS-serialized `MLSMessage` (RFC 9420 §6), version `mls10`.
- **Handshake messages (Commit, Proposal) are `PublicMessage`** (wire format `0x0001`). The DS
  reads `group_id`, `epoch`, `content_type` and `sender` from them without keys. With OpenMLS
  this is `MIXED_PLAINTEXT_WIRE_FORMAT_POLICY` (outgoing handshake as PublicMessage, incoming
  mixed). The membership list is metadata anyway (§1).
- **Application messages are `PrivateMessage`** (wire format `0x0002`); their cleartext
  framing still carries `group_id`, `epoch` and `content_type`. v1 uses application messages
  only for key-history messages (§5.7).
- Welcome (`0x0003`), GroupInfo (`0x0004`) and KeyPackage (`0x0005`) as RFC 9420.
- External commits and external proposals are not used in v1. A member rejects them.

### 2.7 KeyPackages

- **One-time KeyPackages**: no `last_resort` extension. Each is claimed at most once (§3.5).
- **Last-resort KeyPackage**: carries the `last_resort` extension (type `0x000A`; OpenMLS
  `KeyPackageBuilder::mark_as_last_resort`). A party keeps exactly one current last-resort
  KeyPackage at the DS. It is handed out when the one-time pool is empty and is not consumed.
  A party that joined through its last-resort KeyPackage SHOULD commit an Update of its own leaf
  soon after joining, where its profile allows it to commit.
- **Lifetime**: `not_before = now − 3600 s`, `not_after = now + 7257600 s` (84 days; the
  OpenMLS default). A party replaces its last-resort KeyPackage when less than 28 days remain
  and keeps its one-time pool topped up (profiles give sizes). Members MUST NOT add an expired
  KeyPackage.

### 2.8 Group lifecycle

- The creator creates the group at epoch 0 with itself as the only member, both extensions
  set, and registers the scope at the DS (§3.6) with the epoch-0 drop public key.
- Every later change is a Commit. Content can be sealed at epoch 0.

## 3. Delivery Service contract

Any relay acting as DS MUST implement this section. It never holds or derives a key that
opens content, epoch secrets or drops.

### 3.1 Handshake log

- One log per group. Entries are numbered by `seq`, a `u64` starting at 1, increasing by
  exactly 1 per accepted entry, never reused.
- Entry kinds:

| kind | content | accepted when |
|---|---|---|
| `commit` | an `MLSMessage` PublicMessage, `content_type = commit` | §3.2 |
| `proposal` | an `MLSMessage` PublicMessage, `content_type = proposal` | framing checks of §3.2 with `content_type = proposal`; does not advance the epoch |
| `key_history` | an `MLSMessage` PrivateMessage, `content_type = application` | `group_id` matches and `epoch` equals the current epoch |
| `key_history_sealed` | a key-history sealed envelope (§5.7) | header framing valid and header `epoch` equals the current epoch |

- Each entry records `seq`, `kind`, `epoch` (the epoch the message was sent in), the submitting
  party, the accepted time and the exact bytes. A `commit` entry also records the drop public
  key of epoch `epoch + 1` (§3.2).
- Members MUST process entries strictly in `seq` order and MUST NOT skip a `commit`.

### 3.2 Commit acceptance

The DS cannot decrypt, so "valid" means these framing checks, all of which MUST pass:

1. The bytes parse as an `MLSMessage` with `version = mls10` and `wire_format =
   mls_public_message`.
2. `group_id` equals the scope's group id.
3. `epoch` equals the scope's current epoch.
4. `content_type = commit` and `sender.sender_type = member`.
5. The submitter is an authenticated party whose pinned key (§3.5) is the credential of the
   leaf at `sender.leaf_index` as tracked from the log. A DS that does not track the tree MAY
   skip this check; members still verify the commit cryptographically.

A commit is submitted as one unit with:

- `drop_public_key`: 32 bytes, the drop public key of epoch `epoch + 1` (§4.4), computed by
  the committer from its staged commit;
- `welcome`: the Welcome, required iff the commit adds members;
- `epoch_link`: the epoch-link record for `epoch + 1` (§5.6), required iff the history
  policy of epoch `epoch + 1` calls for it (§7.2); the DS stores it as in §3.4;
- `key_history`: optional key-history entries (§5.7) for the new epoch.

The DS accepts the whole unit or nothing. The **first** valid commit for an epoch wins: the DS
appends it, advances the scope's current epoch to `epoch + 1`, stores `drop_public_key` as the
current drop public key, appends the `key_history` entries after it, and queues the Welcome.
Any later commit for the same (now old) epoch is rejected with `epoch_conflict` and the current
epoch; the committer discards its pending commit, catches up and retries.

### 3.3 Welcome delivery

- The DS reads the `new_member` KeyPackageRefs of the Welcome's `secrets` (cleartext) and maps
  each to the party whose KeyPackage it handed out (KeyPackageRef as RFC 9420 §5.2, computable
  by the DS from the stored KeyPackage).
- It delivers the Welcome to each such party together with the `seq` of its commit. The joiner
  continues the log after that `seq`.
- A Welcome is kept until each recipient acknowledges it or leaves the group.

### 3.4 History records

- **Epoch links**, keyed by `(scope, epoch)` where `epoch = e + 1` is the epoch whose key seals
  the link. The DS checks framing only: header version `0x01`, type `epoch_link`, suite
  `0x0001`, header epoch equal to the key, total length exactly 124 bytes. The **first** link
  per key wins; a later submission for the same key is rejected with `link_exists` and the
  stored record. A link for an epoch greater than the current epoch is rejected.
- Links are written by the committer (with the commit unit) or later by any member (repair,
  §7.4), accepted from any authenticated current member.
- **Key-history entries** are log entries (§3.1).
- Records are returned **byte for byte**. The DS MUST NOT re-encode, trim or merge them.

### 3.5 Directory

Per party the DS stores:

- **Identity.** The Ed25519 public key (32 bytes) and the party id it belongs to. The first key
  registered for a party is **pinned**. A different key for the same party is not applied
  silently: the DS records a key change with both fingerprints, shows a change warning to
  operators and to clients that add the party, and refuses KeyPackages under the new key until
  an operator re-pins it. Clients SHOULD also pin keys they have seen and warn on change.
- **Fingerprint.** `SHA-256(raw Ed25519 public key)`, canonical form 64 lower-case hex
  characters; display form the same characters in 16 groups of 4 joined by single spaces.
- **KeyPackages.** On upload the DS verifies: it parses as a KeyPackage, suite `0x0001`, the
  credential and leaf signature key equal the pinned key, the KeyPackage and leaf signatures
  verify, the lifetime is current, the capabilities of §2.5 are present. A pool of one-time
  KeyPackages and at most one current last-resort KeyPackage (an upload replaces the previous
  one).
- **Claim.** A claim for a party returns one one-time KeyPackage and deletes it atomically, so
  no two claimers receive the same one; if the pool is empty it returns the last-resort
  KeyPackage without deleting it. Expired KeyPackages are deleted and never returned.
- **Capability.** The party's latest `e2ee` capability object (§10).

### 3.6 Scope record

Per scope: `scope_id`, `profile_id`, `group_id`, `encrypted` (always `true` once set),
`epoch` (current), `drop_public_key` (of the current epoch), creation time.

- Created once by the group creator with epoch 0 and the epoch-0 drop public key. The DS MUST
  check `group_id` against §2.3.
- `encrypted` MUST NOT be removed or set to false. The record MUST NOT be replaced by one with
  another group id or profile id.
- `epoch` and `drop_public_key` change only by an accepted commit (§3.2).

### 3.7 Catch-up reads

- `log(group, after_seq)` returns entries with `seq > after_seq` in order.
- `log_from_epoch(group, e)` returns entries from the first entry whose `epoch ≥ e`.
- `epoch_link(scope, e)` returns the stored link for `e` or "absent".
- The DS serves reads only to current members (authorization, defence in depth).

### 3.8 Downgrade refusal

- Mapped fields (§12) of a frame for an encrypted scope are accepted only in the sealed form;
  a plaintext value is refused with `plaintext_rejected` and the frame is not stored or
  forwarded.
- Work for an encrypted scope is never dispatched or assigned to a party without the `e2ee`
  capability or without a leaf in the scope's group (profiles name the HTTP status and code;
  gino uses 409 `runner_without_encryption`).
- The DS never decrypts, re-seals or strips a sealed value. `encryption_error` details
  reported by endpoints are stored and shown as received.

DS rejection codes (returned to the submitting party): `epoch_conflict`, `link_exists`,
`plaintext_rejected`, `malformed` (framing check failed), `not_member`, `scope_exists`.

## 4. Key schedule

### 4.1 Exporter context

For a scope with id `S`, the exporter context is `ctx = S` as UTF-8 bytes. The group binding
comes from the exporter secret, which is per group and per epoch.

### 4.2 Content key

```
k_e = MLS-Exporter("gino-e2ee/v1 content", ctx, 32)
```

evaluated in epoch `e` (RFC 9420 §8.5; OpenMLS `export_secret(crypto, "gino-e2ee/v1 content",
ctx, 32)`). A committer obtains `k_{e+1}` from its staged commit before the commit is accepted.

### 4.3 Per-envelope key

For every salted envelope (content, file, epoch link; §5) a fresh 32-byte random `salt`:

```
PRK   = HKDF-Extract(salt = salt, IKM = k_e)          (HKDF-SHA256, RFC 5869)
k_msg = HKDF-Expand(PRK, info = "gino-e2ee/v1 msg", L = 32)
```

`k_msg` is used once, with AES-256-GCM, a 12-byte all-zero nonce and a 16-byte tag. The salt
MUST come from a CSPRNG; it is never reused under the same `k_e`. The envelope type in the AEAD
additional data (§5.2) separates the envelope kinds.

### 4.4 Drop key pair

```
d_e      = MLS-Exporter("gino-e2ee/v1 drop", ctx, 32)
(sk, pk) = DeriveKeyPair(d_e)       (RFC 9180 §7.1.3, DHKEM(X25519, HKDF-SHA256))
```

`pk` is the 32-byte X25519 public key; OpenMLS: `derive_hpke_keypair(HpkeConfig(DhKem25519,
HkdfSha256, AesGcm128), d_e)`. The committer computes `pk` of the new epoch from its staged
commit and submits it with the commit (§3.2). Every member that processes the commit derives
`pk` itself and compares it with the logged value; a mismatch raises `drop_key_mismatch`, and a
member able to commit SHOULD commit an Update so a correct key is published.

### 4.5 Files

A file is sealed whole as a file envelope (§5.4). Its per-file key is the `k_msg` derived from
the envelope's own salt under `k_e`; there is no separately wrapped file key.

### 4.6 Retained secrets

MLS keeps exporter access only for the current epoch. Members therefore keep `E_e = (k_e, d_e)`
for every epoch they pass through (deriving both right after merging each commit) and recover
older ones through epoch links and key-history messages (§7).

## 5. Envelopes

### 5.1 Encoding on JSON wires

Every binary value that travels in JSON (envelopes, keys, group ids, MLS messages) is
**base64url without padding** (RFC 4648 §5). Decoders MUST reject `=` padding, whitespace,
characters outside the alphabet and non-zero trailing bits (`malformed`). The exceptions are
existing hex fields (attachment `sha256`) and fingerprints (§3.5).

### 5.2 Header

```
header = version (1) || type (1) || suite (u16) || epoch (u64)        12 bytes
```

- `version`: `0x01`. Any other value: `unsupported_version`.
- `type`: from the table below. An unknown value: `unsupported_version`. A known type in a
  place that expects another one: `malformed`.
- `suite`: the MLS suite of the scope, `0x0001`. Any other value: `unsupported_suite`.
- `epoch`: the MLS epoch whose secrets produced the envelope.

For every AEAD in this section the additional data is

```
ad = header || location
```

where `location` is the UTF-8 AAD string of §6. The location is never stored in the envelope;
the reader rebuilds it.

| type | name | section |
|---|---|---|
| `0x00` | reserved | — |
| `0x01` | `content` | §5.3 |
| `0x02` | `file` | §5.4 |
| `0x03` | `drop` | §5.5 |
| `0x04` | `epoch_link` | §5.6 |
| `0x05` | `key_history` | §5.7 (payload of an MLS application message) |
| `0x06` | `key_history_sealed` | §5.7 (HPKE to a leaf) |
| `0x07..0xFF` | reserved for later revisions | — |

### 5.3 Content envelope

```
header(type = 0x01) || salt (32) || ciphertext || tag (16)
```

`ciphertext || tag = AES-256-GCM(k_msg, nonce = 0^12, plaintext, ad)`. Minimum length 60.
The plaintext encoding is set by the field kind (§12.4).

### 5.4 File envelope

```
header(type = 0x02) || salt (32) || ciphertext || tag (16)
```

Same construction as §5.3 over the whole file bytes. The attachment descriptor's `sha256` is
the lower-case hex SHA-256 of the **whole file envelope** and `size` its length, so the byte
channel checks integrity without a key. Its `content_type` is `application/octet-stream`. Files
are sealed and opened whole (no chunking in v1).

### 5.5 Drop envelope

```
header(type = 0x03, epoch = e) || enc (32) || ciphertext || tag (16)
```

- HPKE base mode (RFC 9180 §5.1.1) with KEM `0x0020` DHKEM(X25519, HKDF-SHA256), KDF
  `0x0001` HKDF-SHA256, AEAD `0x0001` AES-128-GCM, to the drop public key `pk` of epoch `e`.
- `info = "gino-e2ee/v1 drop"`; HPKE `aad = ad` (header || location); `enc` is the 32-byte
  KEM output.
- Minimum length 60. The reader derives `sk` from `d_e` (§4.4).
- A drop sender takes `e` and `pk` from the scope record (§3.6).

### 5.6 Epoch-link record

```
header(type = 0x04, epoch = e + 1) || salt (32) || ciphertext (64) || tag (16)      124 bytes
```

- The content construction of §5.3 under `k_{e+1}`, plaintext `k_e || d_e` (64 bytes).
- `location = "scope:<S>|epoch_link:<e+1>"` (§6), with `<e+1>` in decimal.
- One per `(scope, e + 1)`; the DS keeps the first (§3.4). Rewriting an identical link is
  harmless; the DS answers `link_exists`.

### 5.7 Key-history payloads

Entry list:

```
entries = count (u32) || count × ( epoch (u64) || k_epoch (32) || d_epoch (32) )
```

Entries are in strictly increasing epoch order and every epoch is lower than the epoch `n` of
the carrying message. `count ≥ 1`.

**MLS application message (`key_history`).** The application data of an MLS PrivateMessage
sent in epoch `n` is

```
header(type = 0x05, epoch = n) || entries
```

with no further encryption (MLS provides it). It is addressed to the whole group. It is
logged as a `key_history` entry and processed in log order, so a joiner reads it in its join
epoch, before any later commit.

**HPKE to a leaf (`key_history_sealed`).** For one joiner only:

```
header(type = 0x06, epoch = n) || leaf_index (u32) || enc (32) || ciphertext || tag (16)
```

- HPKE base mode with the drop suite of §5.5 to the leaf encryption key (`encryption_key` of
  the leaf node) at `leaf_index` in epoch `n`.
- `info = "gino-e2ee/v1 key-history"`; `location = "scope:<S>|key_history:<n>|leaf:<leaf_index>"`;
  HPKE `aad = header || location`; plaintext `entries`.
- The recipient opens it with its leaf's private encryption key (with OpenMLS, read through the
  storage provider's `encryption_key_pair` lookup by public key). Sending it is optional; every
  implementation MUST be able to open it.

## 6. AAD (location strings)

A location is the UTF-8 string of `name:value` parts joined by `|`:

```
scope:<S>|<name>:<value>|…
```

- The first part is always `scope:<S>` with the scope id.
- A name is a non-empty ASCII string of `[a-z0-9_]`. A value is non-empty and does not contain
  `|`. A value MAY contain `:`. **No escaping**: a part that breaks these rules is an error
  (`aad_mismatch`), never escaped.
- Parts appear in the order the template gives (§12.3); they are never sorted.
- Integers are written in decimal ASCII without sign or leading zeros (`0` is `0`).
- The location is passed as AEAD additional data (after the header) and is never stored with
  the envelope.

Examples:

```
scope:t-1|epoch_link:8
scope:t-1|key_history:8|leaf:3
scope:t-1|frame:message|field:text
scope:t-1|frame:thread_message|thread:01jbx0q7m0v3k2m4n5p6q7r8s9|seq:7|field:input
```

**Binding and replay.** A location binds only the values its template names. A value an
endpoint seals before the relay mints the ids of its frame (in gino's task profile
`message.data.text` and `cron_upsert.data.prompt`, sealed by clients before `msgId`, `threadId`
or `cronId` exist) binds the scope and the field only. The relay could replay such a value into
another frame of the same field within the same scope; doing so needs an actively malicious
relay, which the threat model lists as a non-goal (§1). Values sealed after their ids are
assigned (transcript events, results) bind those ids.

## 7. History

### 7.1 Policy semantics

The history policy is the value of extension `0xF0E2` in the group context (§2.4).

- `full` (default): an epoch link is written for every transition `e → e + 1`. A member reads
  all content since epoch 0.
- `from_epoch N`: a link is written for the transition `e → e + 1` iff `e ≥ N`. A member that
  joined after `N` reads content from epoch `N` on.
- `from_join`: no links are written. A joiner reads from its join epoch on, plus whatever a
  key-history message gives it.

### 7.2 Writing links

- The policy that applies to a transition is the one in the group context of epoch `e + 1`.
- The committer of the transition computes `E_{e+1}` from its staged commit and submits the
  link with the commit (§3.2) whenever §7.1 calls for it.
- Tightening the policy does not remove links already written (the relay could delete them,
  but that is not a cryptographic guarantee). Restricting history that was already linked
  needs a history rekey (§8).

### 7.3 Backward walk

A reader at current epoch `n` holding `E_n` that needs `E_e`, `e < n`:

1. If `E_e` is in its key cache, use it.
2. Otherwise let `i` be the lowest epoch above `e` for which it holds `E_i`. While `i > e`:
   1. Fetch `epoch_link(scope, i)`. Absent: `history_unavailable` for every epoch `< i`; stop.
   2. Check the header: type `epoch_link`, suite `0x0001`, epoch `i`, length 124; otherwise
      `link_invalid`.
   3. Open it under `k_i` with location `scope:<S>|epoch_link:<i>`. Failure: `link_invalid`.
   4. Its plaintext is `k_{i-1} || d_{i-1}`; cache `E_{i-1}` and set `i = i − 1`.
3. Open the requested envelope under `E_e`.

Integrity: a link that opens under `k_i` was written by a holder of `k_i`, so `k_i` is
verified by that open. The last recovered `E_e` is **unverified** until an envelope of epoch
`e` opens under it (or a link of epoch `e` opens under `k_e`). If the first epoch-`e` envelope
the reader tries fails under an unverified key, the reader raises `link_invalid` (not
`open_failed`), discards the key and the link result, and retries the walk once; a verified key
that fails raises `open_failed`. The same rule applies to keys from key-history messages.

A missing or invalid link only affects content older than it. Content of epochs at or above the
gap stays readable.

### 7.4 Repair

Any member holding `E_e` and `E_{e+1}` MAY write the missing link for `e + 1` if the policy of
epoch `e + 1` calls for it. The DS keeps the first link (§3.4). Members SHOULD write a missing
link they discover while holding both keys.

### 7.5 Key-history messages

Under `from_join` (or to give a joiner keys a policy would not link), the committer of an Add
MAY attach key-history entries (§5.7) for any range it holds. Recipients cache the entries as
unverified keys (§7.3).

### 7.6 Member key cache

- Members cache `E_e` per scope and epoch, **encrypted at rest** (profiles say under which
  key). The cache format is private to the implementation.
- A lost cache is rebuilt from `E_n` (from the MLS state) plus the links. Under `from_join`
  history before the join epoch is lost with the cache unless a key-history message is still
  readable; this is stated, not repaired.

## 8. Removal, PCS and forward secrecy

- A Remove Commit moves the group to `e + 1` with a fresh epoch secret (RFC 9420). The removed
  member never learns `k_{e+1}` or any later key. Links point backwards only, so nothing it holds
  opens content sealed after its removal (post-compromise security for future content).
- **Held history is not revoked.** A removed member keeps the epoch secrets it held and can open
  ciphertext of those epochs if it obtains it. The relay stops serving its reads; that is
  authorization, not cryptography.
- **No forward secrecy for durable content.** Anyone holding a later epoch key of a scope with
  `full` history can open all earlier durable content. MLS application messages keep MLS's
  forward secrecy.
- **Later option: history rekey.** Re-seal every stored envelope of a scope under fresh epoch
  keys with a new link chain. Not part of v1.
- Endpoints seal under the newest epoch they have merged. They process log entries as they
  arrive, including during long-running work, before sealing the next value. The DS does not
  reject content for its epoch (replayed outbox frames may carry older epochs).

## 9. Drops

- Anyone holding the published drop public key can seal a drop: drop senders, the relay acting
  for one, and members.
- Drops are **unauthenticated by design**: the opened plaintext proves only that the sender knew
  the public key of epoch `e`. Profiles MUST treat drop plaintext as untrusted input and say
  which fields accept drops (§12.2 `envelopes`).
- A drop envelope sits wherever the field map allows `drop`; the reader dispatches on the header
  type. Its location is the field's location.
- Opening needs `d_e` for the header epoch; older seeds are recovered like content keys (§7).

## 10. Versioning and capability

- The envelope `version` byte `0x01` is this specification. An incompatible revision uses a new
  envelope version and a new capability version; `0x01` is never redefined.
- MLS suites are RFC 9420 registry values.
- The profile id is in the group context (§2.4); a profile revision gets a new profile id.
- A party advertises its capability with this exact JSON object (the carrying message is defined
  by the protocol):

```json
{ "e2ee": { "versions": [1], "mls_suites": [1],
            "credential": { "type": "basic", "public_key": "<base64url, 32-byte Ed25519 key>" } } }
```

  `versions` lists supported envelope versions, `mls_suites` supported MLS suite ids (JSON
  integers), `credential.type` the MLS credential type name, `public_key` the identity key.
  Receivers ignore unknown members of the object. A party is e2ee-capable iff the object is
  present, `versions` contains `1`, `mls_suites` contains `1` and `public_key` decodes to 32
  bytes.

## 11. Failure codes

Endpoints report failures as `encryption_error = {"code": <code>, "epoch"?: <integer>}`. It
never contains plaintext, AAD values or key material. Endpoints **never fall back to
plaintext**: they do not use content they could not open, do not accept a plaintext value where
a sealed one is required, and do not send a value they could not seal.

| code | meaning | raised by |
|---|---|---|
| `not_member` | the endpoint holds no group state for the scope (no Welcome processed, removed, state lost) | runner, client |
| `epoch_unknown` | an envelope's epoch is above the endpoint's epoch after catching up the log | runner, client |
| `history_unavailable` | an older epoch's secrets are unreachable: missing link, policy cut-off, lost cache | runner, client |
| `link_invalid` | an epoch link or key-history entry fails its checks or yields a key that does not open its content | runner, client |
| `open_failed` | AEAD or HPKE open failed under a verified key (tampering, moved ciphertext, wrong location) | runner, client |
| `aad_mismatch` | the location cannot be built: missing placeholder value, a value with `\|`, an invalid name, a scope prefix that does not match | runner, client |
| `plaintext_rejected` | a mapped field arrived in plaintext for an encrypted scope | runner, client, DS |
| `unsupported_version` | unknown envelope version or type, unknown capability version, a profile id the endpoint does not support | runner, client |
| `unsupported_suite` | an MLS or envelope suite other than `0x0001` | runner, client, DS |
| `malformed` | bad base64url, wrong length, bad sealed form, wrong envelope type for the field, invalid UTF-8 or JSON after opening, invalid extension or credential | runner, client, DS |
| `drop_key_mismatch` | the drop public key logged for an epoch differs from the derived one | runner, client |
| `seal_failed` | the endpoint could not seal an outbound value (no current epoch secrets, crypto failure) | runner, client |

`epoch` is present for `epoch_unknown`, `history_unavailable`, `link_invalid`, `open_failed`
and `drop_key_mismatch`: the epoch involved (JSON integer ≤ 2^53 − 1).

An endpoint asked to act in a scope whose profile it does not support reports
`unsupported_version`; there is no separate profile code.

A failure that is decided without content (a timeout or a lost endpoint, not an open or seal
failure) carries no `encryption_error` and no sealed fields. In the task-content profile, a
`thread_result` the runner's synchronous reapers (watchdog, offline, unrunnable) write for an
encrypted task carries `status` and `failure_reason` only: no `result`, `error`, `attachments`
or `encryption_error`. The reaper has no content key at hand and nothing to seal; omitting the
fields is not a plaintext fallback.

## 12. Field map format

### 12.1 File

A profile's field map is one JSON file, `docs/e2ee/<profile-name>.fieldmap.json`:

```json
{
  "format": "gino-e2ee/field-map/v1",
  "profile": "<profile id>",
  "frames": {
    "<frame type>": {
      "direction": "host_to_agent" | "agent_to_host",
      "scope": "<path of the scope id>",
      "fields": [ <field rule>, … ]
    }
  }
}
```

A frame type absent from `frames` has no sealed fields. `scope` is the frame path whose value is
the scope id.

### 12.2 Field rule

```json
{ "path": "<path>", "kind": "text" | "json" | "blob",
  "envelopes": ["content" | "drop" | "file", …],
  "aad": "<template>",
  "when"?: { "path": "<path>", "op": "eq" | "ne", "value": "<string>" },
  "keyed_plain"?: { "key": "<path>", "table": { "<key value>": ["<plain path>", …], … } } }
```

- `path`: dot-separated object keys from the frame root (`data.output.content`). A segment
  followed by `[]` (`data.attachments[]`) means every element of that array. Keys contain
  only `[A-Za-z0-9_]`.
- All paths are optional: if any segment is absent (or `null` for an intermediate object), the
  rule does not apply. A present field is always sealed.
- `kind`: `text` (the value is a JSON string), `json` (any JSON value), `blob` (the path names
  an attachment descriptor whose referenced bytes are a file envelope, §5.4; the descriptor
  itself is not replaced).
- `envelopes`: the envelope types allowed at this path. `text`/`json` rules allow `content` and
  optionally `drop`; `blob` rules allow exactly `file`.
- `when`: the rule applies only if the string at `when.path` equals (`eq`) or differs from
  (`ne`) `value`; an absent `when.path` counts as differing.
- Two `text`/`json` rules MUST NOT both apply to the same value, and no applying `text`/`json`
  rule's path may be a prefix of another's. A `blob` rule may share a prefix with them (it
  replaces nothing).
- `keyed_plain`: only on `json` rules; leaves chosen parts of the value in plaintext, selected
  by a cleartext discriminator (§12.5). Without it the value is sealed whole.

### 12.3 AAD template

A location string (§6) whose values may be placeholders `{<path>}`:

- the first part is `scope:{<frame scope path>}`;
- a placeholder is a whole value; names are always literal;
- a placeholder path that contains `[]` MUST share the rule path's prefix up to that `[]`, and
  resolves in the same array element;
- a placeholder resolves to a cleartext JSON string (used as is) or a non-negative integer
  (decimal); anything else, an absent value, or a value breaking §6 is `aad_mismatch`.

Every cleartext field a template references is part of the stored record: a relay that stores
a frame MUST store and return those fields unchanged together with the sealed value, so later
readers can rebuild the location.

### 12.4 Sealed wire form and plaintext encoding

A sealed value **replaces** the plaintext value at its path with a JSON object of exactly one
member:

```json
{ "e2ee": "<base64url envelope>" }
```

- `text`: plaintext is the UTF-8 bytes of the string. After opening, invalid UTF-8 is
  `malformed`.
- `json`: plaintext is the compact JSON serialization of the value (no insignificant
  whitespace). After opening, it MUST parse as one JSON value, else `malformed`.
- `blob`: the value is not replaced; the bytes behind the descriptor are a file envelope whose
  location is the rule's template.

Receivers of a frame for an encrypted scope:

- a mapped value that is not the sealed form is rejected with `plaintext_rejected`;
- a sealed form with extra members, a non-string `e2ee`, or an envelope type outside
  `envelopes` is `malformed`.

On a scope that is not encrypted, the sealed form is never interpreted and mapped fields carry
plaintext.

A `json` rule with `keyed_plain` follows §12.5 instead of the whole-value form above when its
discriminator selects plain paths.

### 12.5 Keyed plain paths

`keyed_plain` lets a relay read the parts of a `json` value it needs to act on, chosen per value
of a cleartext discriminator (for example the method of an action), while every other part
stays sealed.

```json
"keyed_plain": { "key": "data.input.method",
                 "table": { "issue.set_status": ["issue_id", "status"],
                            "form.submit": ["fields.title", "labels[]"] } }
```

**Discriminator.** `key` is a frame path (§12.2) without `[]`. Its value is cleartext: the path
MUST NOT be at or below the path of another `text`/`json` rule that can apply to the same frame.
Two rules are exclusive only when their `when` conditions name the same path and value with
`eq` and `ne`. The discriminator is not part of any location.

**Mode.** When the rule applies:

- if the discriminator value is a JSON string that is a key of `table` with a non-empty list,
  the value is **split** with that list as its plain set `P`;
- otherwise (discriminator absent or not a string, not in `table`, or an empty list), the value
  is **sealed whole** exactly as §12.4, at the rule's location. An empty `table` seals every
  value whole.

**Plain paths.** A plain path is relative to the rule's value: one or more segments joined by
`.`; a segment is `name` or `name[]`, `name` matching `[A-Za-z0-9_]+` and not equal to `e2ee`.
`name` steps into the object member `name`; `name[]` steps into that member and then into every
element of the array there. So `status`, `fields.title`, `labels[]` (each element of `labels`)
and `items[].id` (member `id` of each element of `items`). Read as a sequence of steps (member
`name`, every element), a list is valid iff it has no duplicates, no path is a prefix of
another, and no position is followed by a member step in one path and an element step in another.
The generator refuses an invalid list.

**Split walk.** Positions are step sequences from the value root (the empty sequence). A
position is *plain* if it is in `P`, *descend* if it is a proper prefix of a path in `P` (its
container type is object when the next step is a member, array when it is an element), and
*sealed* otherwise. The sealer walks the value from the root:

- at a plain position the value stays as it is, whatever its type;
- at a descend position whose value has the container type, every object member (in ascending
  byte order of key) or array element (in index order) is walked at the extended position;
- at a descend position whose value has another type, and at every sealed position, the value
  is sealed as one `json` envelope (§12.4 encoding) and replaced by `{"e2ee": "<base64url>"}`.

So the root is sealed whole if it is not an object, a nested plain path keeps its containers
with each non-plain sibling sealed individually, and empty containers stay as they are. A
sealer MUST produce exactly this output: it never seals a plain position and never seals a
descend position whose value has the container type.

**Locations.** The concrete path of a position is its member keys and array indexes (decimal)
joined by `.`. A part sealed at concrete path `c` uses the rule's template with `.c` appended to
the value of its last part; the root (empty `c`) uses the template unchanged. The last part of a
`keyed_plain` rule's template MUST be literal.

Example, template `…|seq:{data.seq}|field:input.params`, method `form.submit` (plain set
`fields.title`, `labels[]`):

```json
{ "fields": { "title": "T", "body": "B" }, "labels": ["a", "b"], "note": "N" }
{ "fields": { "title": "T", "body": { "e2ee": "…" } }, "labels": ["a", "b"], "note": { "e2ee": "…" } }
```

with locations `…|field:input.params.fields.body` and `…|field:input.params.note`. With plain
set `items[].id`, `{"items": [{"id": "1", "x": "y"}]}` seals `x` at `…|field:input.params.items.0.x`.

**Keys outside the path syntax.** A member key that becomes part of a concrete path (a member
of an object at a descend position) MUST be non-empty and contain neither `.` nor `|`. Keys
inside a sealed or plain value are unconstrained. A sealer refuses such a value (`aad_mismatch`)
and sends nothing; a reader rejects it with `aad_mismatch`, a DS with `malformed`.

**Reading (encrypted scope).** Sealed whole: §12.4. Split, from the root:

- at a plain position the value is accepted as it is and never opened, even if it looks like a
  sealed form;
- at a descend or sealed position, an object whose only member is `e2ee` with a string value is
  a sealed part and is opened at that position (its envelope type checked against `envelopes`);
- at a descend position whose value has the container type, the walk continues;
- at a sealed position, any other value is `plaintext_rejected`, or `malformed` if it is an
  object whose only member is `e2ee` with a non-string value;
- at a descend position, any other value is `plaintext_rejected`.

A descend object whose own member is `e2ee` is not ambiguous: `e2ee` is never a plain name, so
that member is itself sealed and its value is an object, not a string. Opened parts are put back
at their positions; the result is the original value.

Plain parts are metadata visible to the relay. Changing a table changes what the relay sees
and is a profile revision (§10).

### 12.6 Generated code

`sdks/e2ee/scripts/gen-field-map.ts` reads every `docs/e2ee/*.fieldmap.json`, validates it against
§12.1–§12.3 and §12.5 and writes `gino-e2ee/src/field_map/generated.rs` and
`sdks/e2ee/src/field-map.generated.ts`. Both outputs are committed. `--check` regenerates in
memory and exits non-zero if a committed output differs; CI runs it.

## 13. Test vectors

`docs/e2ee/test-vectors.json` is generated by the `gino-e2ee` crate and checked by every
implementation. Raw bytes are lower-case hex; wire forms that are base64url in production are
given in both encodings where a section says so; strings are UTF-8.

```json
{
  "format": "gino-e2ee/test-vectors/v1",
  "envelope_version": 1,
  "suite": 1,
  "group_id":     [ { "profile": "", "scope": "", "group_id": "<hex>" } ],
  "fingerprint":  [ { "public_key": "<hex>", "fingerprint": "<hex>", "display": "" } ],
  "aad":          [ { "template": "", "frame": {}, "element"?: 0, "location": "" } ],
  "policy":       [ { "policy": "full" | "from_join" | { "from_epoch": 0 }, "extension_data": "<hex>" } ],
  "content":      [ { "k_e": "<hex>", "epoch": 0, "salt": "<hex>", "location": "",
                      "plaintext": "<hex>", "k_msg": "<hex>", "envelope": "<hex>",
                      "envelope_b64url": "" } ],
  "file":         [ { "k_e": "<hex>", "epoch": 0, "salt": "<hex>", "location": "",
                      "plaintext": "<hex>", "envelope": "<hex>", "sha256": "<hex>", "size": 0 } ],
  "drop":         [ { "d_e": "<hex>", "sk": "<hex>", "pk": "<hex>", "epoch": 0, "location": "",
                      "plaintext": "<hex>", "ikm_e"?: "<hex>", "envelope": "<hex>" } ],
  "epoch_link":   [ { "epoch": 0, "k_e": "<hex>", "d_e": "<hex>", "k_next": "<hex>",
                      "salt": "<hex>", "scope": "", "envelope": "<hex>" } ],
  "key_history":  [ { "epoch": 0, "entries": [ { "epoch": 0, "k": "<hex>", "d": "<hex>" } ],
                      "payload": "<hex>",
                      "sealed"?: { "scope": "", "leaf_index": 0, "leaf_sk": "<hex>", "leaf_pk": "<hex>",
                                   "ikm_e"?: "<hex>", "envelope": "<hex>" } } ],
  "history_walk": [ { "description": "", "scope": "", "policy": "…",
                      "current": { "epoch": 0, "k": "<hex>", "d": "<hex>" },
                      "links": { "<epoch>": "<hex>" },
                      "content": [ { "epoch": 0, "location": "", "envelope": "<hex>",
                                     "plaintext"?: "<hex>", "error"?: { "code": "", "epoch"?: 0 } } ] } ],
  "field_map":    [ { "description": "", "profile": "", "map"?: {}, "frame": {},
                      "secrets": { "<epoch>": { "k": "<hex>", "d": "<hex>" } },
                      "salts": [ "<hex>" ], "sealed_frame": {} | null, "error"?: { "code": "" } } ],
  "negative":     [ { "section": "", "description": "", "input": {}, "error": { "code": "", "epoch"?: 0 } } ]
}
```

- **Injected randomness.** `salt` (and `salts`, consumed in field-map rule order, then array
  order, then split-walk order of §12.5) replaces the CSPRNG. Where an HPKE implementation accepts an injected ephemeral key,
  `ikm_e` (RFC 9180 `DeriveKeyPair` input) makes `envelope` reproducible; otherwise the vector is
  checked by opening only.
- `content`, `file`, `epoch_link`, `key_history.payload`: sealing with the injected salt gives
  exactly `envelope`; opening gives `plaintext`.
- `drop`, `key_history.sealed`: `sk`/`pk` derive from `d_e` (§4.4); opening gives the plaintext.
- `epoch_link`: `epoch` is `e`; the record carries `E_e` under `k_next = k_{e+1}`, and its header
  epoch and location use `e + 1`.
- `history_walk`: the walk of §7.3 over `links` gives each `plaintext` or the expected `error`.
  The `content` items are opened in order by one reader; `error.epoch` is the item's epoch.
  `policy` (same encoding as `policy.policy`) names the policy the links were written under; the
  walk itself does not read it.
- `field_map`: sealing `frame` with the profile's map, `secrets` (highest epoch current) and
  `salts` gives `sealed_frame`; opening `sealed_frame` gives `frame`. `map`, when present, is an
  inline field map (§12.1) used instead of the profile's, so split values of §12.5 are covered
  even when a profile's tables are empty. `description` names the case. An entry with `error`
  expects a failure with that code: if `sealed_frame` is `null` the error is seal-side (sealing
  `frame` fails with it); otherwise opening `sealed_frame` fails with it.
- `negative` covers at least: flipped byte in header, salt, ciphertext and tag; wrong location;
  wrong version byte; unknown type; wrong suite; truncation below the minimum; bad base64url
  (padding, non-canonical tail); missing link; tampered link; plaintext in a mapped field; sealed
  form with extra members; wrong envelope type for a field; invalid UTF-8 and JSON after opening;
  a `|` in a placeholder value; for §12.5, a plaintext part at a sealed position, a split value
  for a discriminator that selects whole sealing, and a key with `.` or `|` on a concrete path.
  Each names its §11 code.
- `negative.input` holds the inputs of the section's open or parse operation: `content` and
  `file` `{k_e, location, envelope, kind?}` (`kind` `text` or `json` decodes the opened plaintext
  as in §12.4), `drop` `{d_e, location, envelope}`, `drop_key` `{d_e, epoch, public_key}` (§4.4),
  `epoch_link` `{scope, epoch, k_next, envelope}`, `key_history` `{payload}`,
  `key_history_sealed` `{scope, leaf_index, leaf_sk, envelope}`, `history_walk`
  `{scope, current, links, location, envelope}`, `aad` `{template, frame, element?}`, `policy`
  `{extension_data}`, `base64url` `{text}` and `sealed_form` `{value}` (§12.4).
- MLS itself is checked with the RFC 9420 test vectors against the OpenMLS build, not here.
  Exporter outputs are inputs (`k_e`, `d_e`) in these vectors.

## 14. Decisions taken in this spec

1. Group id `= SHA-256("gino-e2ee/v1 group" || len16(P) || P || len16(S) || S)`.
2. Profile id extension type `0xF0E1` (raw UTF-8 data), next to the spike's history policy type
   `0xF0E2`; the spike's test encoding (`00` / `01 || u64` / `02`) is adopted as normative.
3. Required capabilities list both extension types, no proposal or credential types;
   BasicCredential is enforced by validation.
4. BasicCredential identity is the raw Ed25519 public key and MUST equal the signature key.
5. Handshake messages are PublicMessage (`MIXED_PLAINTEXT_WIRE_FORMAT_POLICY`); application
   messages PrivateMessage. External commits and proposals are unused in v1.
6. KeyPackage lifetime is the OpenMLS default (84 days + 1 h margin); last resort uses the
   `last_resort` extension `0x000A`; refresh below 28 days.
7. The exporter context is the UTF-8 scope id (as in the plan and the spike).
8. `k_msg` uses the envelope salt as the HKDF **salt** and `k_e` as IKM; one info label
   `"gino-e2ee/v1 msg"` for content, file and link envelopes, separated by the header in the AEAD
   additional data.
9. The AEAD additional data is `header || location` for every envelope (the header is
   authenticated, so a relay cannot relabel type, suite or epoch).
10. Files use a per-file key derived from the file envelope's salt under `k_e`, not a separately
    wrapped key: the current attachment descriptor has no field to carry a wrapped key, and the
    derived key is equally independent per file. `sha256`/`size` cover the whole file envelope.
11. **Epoch links and key-history entries carry `d_e` next to `k_e`** (64-byte link plaintext).
    MLS gives exporter access only in the current epoch, so without it a later joiner, or a member
    that advanced, could not open older drops.
12. Drops use HPKE `info = "gino-e2ee/v1 drop"` and `aad = header || location`.
13. Key-history entry list `u32 count || (u64 epoch || k || d)*`, ascending; the MLS variant is
    logged in the handshake log so joiners read it in their join epoch; the HPKE-to-leaf variant
    is optional to send and mandatory to open (OpenMLS exposes the leaf private key only through
    the storage provider; the spike did not exercise it).
14. Envelope type codes `0x01..0x06` as in §5.2.
15. base64url without padding for every binary JSON value; existing hex fields and fingerprints
    stay hex.
16. Fingerprint = lower-case hex SHA-256 of the raw Ed25519 key; display in groups of 4.
17. The DS log has four entry kinds; a commit is accepted as a unit with its drop public key,
    Welcome, link and key-history entries. Drop public keys are verified by members on merge
    (`drop_key_mismatch`).
18. A key recovered from a link stays unverified until an envelope opens under it; failure under
    an unverified key is `link_invalid`, under a verified key `open_failed`.
19. `from_epoch N` links transitions with `e ≥ N`; `from_join` writes no links; the policy of the
    new epoch governs each transition; tightening does not delete existing links.
20. Failure code set of §11 (adds `drop_key_mismatch` and `seal_failed` to the suggested list);
    DS rejection codes `epoch_conflict`, `link_exists`, `scope_exists`.
21. Capability object `{"e2ee": {"versions", "mls_suites", "credential": {"type", "public_key"}}}`.
22. Sealed wire form `{"e2ee": "<base64url>"}`; field-map rules with `[]` element paths, optional
    paths, `when` conditions and per-path AAD templates; generated outputs at
    `gino-e2ee/src/field_map/generated.rs` and `sdks/e2ee/src/field-map.generated.ts`.
23. **Per-action plain parameters** (`keyed_plain`, §12.5): a `json` value is never sealed whole
    when a cleartext discriminator selects plain paths for it; those paths stay plaintext, every
    other part is sealed individually at its own location (`…|field:<field>.<concrete path>`).
    A discriminator value not in the profile's static table, or with no plain paths, seals the
    value whole. Tables are declared by the profile, not supplied per scope at run time; keys
    that cannot be written in a concrete path are refused. Applied to host-action `params`,
    dispatched on `input.method`.
24. **Replay of client-sealed values**: values sealed before the relay mints their frame ids
    (gino: `message.data.text`, `cron_upsert.data.prompt`) bind scope and field only, so replay
    within a scope needs an actively malicious relay, a non-goal of the threat model (§6).
25. **Leaf capabilities list `last_resort` (`0x000A`)** next to `0xF0E1` and `0xF0E2` (§2.5):
    OpenMLS rejects a KeyPackage carrying an extension its leaf capabilities do not list.
