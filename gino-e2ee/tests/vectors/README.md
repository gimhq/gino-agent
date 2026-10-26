# RFC 9420 interoperability test vectors

Source: <https://github.com/mlswg/mls-implementations>, directory `test-vectors/`, commit
`2034fe72e0c805a683ba76165660c834f2a8142a` (2026-10-07). Published by the IETF MLS working
group as public interoperability test data; the repository carries no licence file.

Vendored subsets (unmodified JSON entries, re-serialized by `jq`):

| file | subset |
|---|---|
| `key-schedule.json` | entries with `cipher_suite` 1 |
| `crypto-basics.json` | entries with `cipher_suite` 1 |
| `welcome.json` | entries with `cipher_suite` 1 |
| `messages.json` | the first 8 entries (the file is suite independent) |

`tests/mls_vectors.rs` runs them. Not run: `tree-math`, `secret-tree`, `tree-validation`,
`tree-operations`, `treekem`, `message-protection`, `transcript-hashes`, `psk_secret`,
`passive-client-*`: OpenMLS 0.9.1 exposes no public API for these computations (its runners
are crate-private), so checking them would only test a re-implementation.
