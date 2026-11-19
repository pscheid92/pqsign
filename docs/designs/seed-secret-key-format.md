# Seed-Based Secret Key Format

*   **Author:** Patrick Scheid
*   **Status:** Proposed
*   **Date:** 2026-11-18

--------------------------------------------------------------------------------

## Overview

pqsign stores each secret key in an encrypted file of 4,159 bytes. 4,032 of them are the expanded ML-DSA-65 secret key. FIPS 204 can rebuild that key from a 32-byte seed, ξ, and the two IETF standards for hybrid ML-DSA signatures, RFC 10073 and RFC 9980, store ML-DSA keys as that seed.

This design adds **secret key format version 2**. It stores the 32-byte Ed25519 private key and the 32-byte ML-DSA seed ξ instead of the expanded keys, so a new secret key file is 151 bytes. `pqsign generate` always writes it. Secret key files in format version 1, written by pqsign 0.1.0 to 0.3.1, keep working for signing. Public keys, fingerprints, key IDs and signatures don't change.

## The Problem

The secret key file is about 27 times larger than it needs to be. Two 32-byte values determine the key pair completely:

*   the RFC 8032 Ed25519 private key, which is itself a 32-byte seed, held in pqsign's `Ed25519SecretKey` type
*   the ML-DSA-65 seed ξ

pqsign already generates both in `KeyPair::new`. It then discards ξ, keeping only the expanded ML-DSA key derived from it. In the rest of this document, "Ed25519 private key" always means that 32-byte value, and "the two seeds" means it together with ξ.

That has three consequences:

*   **Size.** This is the main reason for the change.
    *   At 4,159 bytes, a secret key doesn't fit in one QR code, which holds at most 2,953 bytes of binary data. Its base64 form, 5,548 characters, is impractical to retype from paper, and in a password manager it fits only a notes field.
    *   At 151 bytes, the base64 form is 204 characters: short enough for one QR code, for retyping, or for a single password-manager field that is copied as one value.
*   **Divergence from the standards.** RFC 10073 and RFC 9980 store the ML-DSA private key as the 32-byte seed. pqsign's expanded form can't be turned back into a seed, so a pqsign key can never be represented in the standards' private key format.
*   **A larger input to validate.** An expanded ML-DSA key has structure that can be malformed.
    *   fips204 0.5.0's changelog records the fix: "`PrivateKey::try_from_bytes` rejects a key whose s1 or s2 has a coefficient outside [−η, η]". 0.4.6 accepted such keys.
    *   A seed has no such structure: every 32-byte value is a valid seed.
    *   pqsign was never exposed, because the encrypted payload of a key file is authenticated by XChaCha20-Poly1305 under a key derived from the password. This is defense in depth, not a fix.

The change can't help existing keys:

*   An expanded key doesn't contain the seed it came from, so a key file in format version 1 can't be converted. It stays in that format until its owner generates a new key, which also means a new fingerprint.
*   This includes the release signing key. Its fingerprint is published in README.md, docs/install.md, SECURITY.md and the release notes, and there is no plan to rotate it.

The new format therefore helps new keys only, and pqsign has to read format version 1 permanently.

## Goals

*   `pqsign generate` writes secret key files in format version 2: exactly 151 bytes, holding the Ed25519 private key and the ML-DSA seed ξ.
*   Secret key files in format version 1 keep working for signing, permanently. Two committed test fixtures guard this, and they are in place before the writer changes. One is written by pqsign 0.1.1, which writes the same files as 0.1.0, the first release, and the other by pqsign 0.3.1, the newest.
*   Nothing in pqsign writes format version 1 any more, and today's encoder for it is removed. Future Improvements describes how keys can be re-encrypted later.
*   A format version 2 file stores no key ID in its encrypted payload. After decryption, pqsign derives both public keys from the two seeds. It then requires the first 8 bytes of their fingerprint, a BLAKE2b-256 hash over both public keys, to equal the key ID in the file header.
*   Public keys stay at their current format (`pqsign:v1:`), and fingerprints, key IDs and signatures don't change. Every existing public key and signature keeps verifying.
*   `pqsign inspect` shows which format version a secret key file has.
*   From 0.4 on, version errors name the file type and what to do, for every file type. Signatures already use "format v2", so a bare "format v3" could mean either file type.
    *   This can't change what pqsign 0.1.0 to 0.3.1 print when they meet a secret key file in format version 2 (CUJ 3).
    *   For that case, the 0.4.0 release notes quote the message and explain it.

## Non-Goals

*   **Converting existing keys.** An expanded ML-DSA key doesn't contain its seed, so it's impossible.
*   **Smaller public keys or signatures.** Their sizes, 1,984 and about 3,400 bytes, are set by ML-DSA-65.
*   **Writing format version 1 on request.** No `generate` option writes it. Older pqsign versions fail on new key files with a version error, and their users can update.
*   **A password-change or re-encryption command.** See Future Improvements. Until one exists, nothing can rewrite an existing key file; that is already the case today.
*   **Key rotation tooling, or importing and exporting keys in RFC 10073 form.** No command needs them yet; `SecretSeeds` is where they would start.
*   **Changing the KDF or the AEAD**, including authenticating the header as associated data, or dropping the random nonce.
*   **Dropping support for format version 1 secret keys.** See Alternative G.

## Open Questions

None.

## Critical User Journeys (CUJs)

### CUJ 1: Generate a new key

*   **Given**: pqsign 0.4 or later, and no key at the target path.
*   **When**: the user runs `pqsign generate -s new.key` and enters a password.
*   **Then**: `new.key` is a 151-byte file in secret key format version 2. `new.key.pub` is a `pqsign:v1:` public key, unchanged from today's format. The key ID is the first 8 bytes of the key's fingerprint; `generate` prints the key ID in hex and the fingerprint in base64.

### CUJ 2: Keep signing with an existing key

*   **Given**: a secret key file in format version 1, written by pqsign 0.1.0 to 0.3.1, such as the release key in CI.
*   **When**: `pqsign sign` runs with it under pqsign 0.4.
*   **Then**: signing works exactly as before. The signature verifies against the key's existing public key, and the fingerprint is unchanged. Nothing rewrites the key file.

### CUJ 3: An older pqsign meets a new key file

*   **Given**: a secret key file in format version 2, and pqsign 0.1.0 to 0.3.1.
*   **When**: the user runs `sign` or `inspect` with it.
*   **Then**: the command fails with exit status 2. `sign` fails before asking for the password. Every release from 0.1.0 to 0.3.1 prints `error: invalid format: file requires pqsign format v2, this build supports v1`; the same message is in `src/format/header.rs` at every release tag from v0.1.0 to v0.3.1. The user updates pqsign.

### CUJ 4: Tell old and new key files apart

*   **Given**: secret key files in both formats.
*   **When**: the user runs `pqsign inspect` on each.
*   **Then**: the type line reads `Secret key (format v1, encrypted)` or `Secret key (format v2, encrypted)`. No password is asked for.

### CUJ 5: A damaged or mislabelled key file

*   **Given**: a format version 2 file that is truncated, padded, relabelled as format version 1 in its header, or has a changed header key ID.
*   **When**: `pqsign sign` uses it.
*   **Then**: a wrong length, whether from truncation, padding or relabelling, is reported as a corrupt file before the password prompt. A changed key ID is caught after decryption by the derived-key-ID check, with its own error message. pqsign never signs with a key that doesn't match the header's key ID.

### CUJ 6: Back up a key as text and restore it

*   **Given**: a 151-byte key file in format version 2.
*   **When**: the user stores it as text, for example `base64 < new.key` in a password manager field or a QR code. Later they restore it with `base64 -d > new.key`, and sign with it.
*   **Then**: the restored file works like the original. pqsign has no backup command, so this procedure stays outside pqsign. Its limit: a restore mistake can show up as a format error, as a corrupt file, as the key-ID mismatch error, or as `wrong password`, because the AEAD can't tell a damaged file from a wrong password. The reliable check is to sign a test file and verify the signature against the key's `.pub` file; `pqsign inspect` only confirms the file type and the format version.

## Technical Plan (Architecture)

### Secret key format version 2

The file keeps the layout of the first 71 bytes of format version 1. Only the version byte (offset 4) and the encrypted payload differ:

```text
Offset  Size  Field
0       4     Magic: "PQSN"
4       1     Format version: 2
5       1     File type: 0x02 = SecretKey
6       8     Key ID (the first 8 bytes of the key's fingerprint)
14      1     KDF: 0x02 = Argon2id
15      8     Argon2id memory in bytes (u64, little-endian)
23      8     Argon2id iterations (u64, little-endian)
31      16    Argon2id salt
47      24    XChaCha20-Poly1305 nonce
71      80    Encrypted payload (64 bytes) and Poly1305 tag (16 bytes)
              = 151 bytes
```

The encrypted payload is:

```text
ed25519_private_key (32 bytes)   the RFC 8032 private key
mldsa65_seed        (32 bytes)   ξ, the input to FIPS 204 ML-DSA.KeyGen_internal
```

The Ed25519 private key comes first. That matches every other pqsign structure, RFC 9980, and the first 32 bytes of the format version 1 payload. RFC 10073 serializes the other way round, `mldsaSeed || tradSK`, so a future export to that form would swap the two halves.

There is no key ID in the payload. Format version 1 carried one as a corruption check. In format version 2, the derived-key-ID check below replaces it.

### A dedicated seed type in the domain

A new type, `SecretSeeds`, holds the two seeds. It lives in `src/domain/keys.rs`, next to `KeyPair`:

```text
SecretSeeds { ed25519: Ed25519SecretKey, mldsa65: MlDsa65Seed }   // wiped on drop, not Clone, redacted Debug

SecretSeeds::generate() -> SecretSeeds            // 64 random bytes from rand::rng()
SecretSeeds::from_parts(Ed25519SecretKey, MlDsa65Seed) -> SecretSeeds   // infallible: every 32-byte value is a valid seed
SecretSeeds::ed25519(&self) -> &Ed25519SecretKey
SecretSeeds::mldsa65(&self) -> &MlDsa65Seed
SecretSeeds::key_pair(&self) -> KeyPair            // runs both key generations
```

*   `MlDsa65Seed` is a new 32-byte secret byte type in `src/domain/types.rs`, made with the existing `secret_byte_type!` macro, so it's wiped on drop, prints as `[REDACTED]`, and can't be cloned or compared.
*   `key_pair` runs the standard key generation of each algorithm on its seed: FIPS 204's for ξ, and RFC 8032's for the Ed25519 private key. It sets the key ID of both keys to the first 8 bytes of their fingerprint, exactly as `KeyPair::new` does today.
*   `fips204` takes ξ by reference. So for format version 2, pqsign no longer hands the expanded secret key to `fips204` by value, as format version 1 loading does today. The general caveat about moved values in `docs/cryptography.md`'s Memory Safety section still applies.
*   `KeyPair::new()` becomes `SecretSeeds::generate().key_pair()`, which generates keys with the same algorithms, sizes and fingerprint-based key ID as today, and stays for tests and benchmarks. The helpers `gen_ed25519_keys` and `gen_mldsa65_keys` are removed; their seed handling moves into `SecretSeeds::generate`, and key generation happens only in `SecretSeeds::key_pair`.
*   `SecretKey` doesn't change. It stays a signing-only type that doesn't know which format it was loaded from.

Within pqsign, only two places produce a `SecretSeeds`: generating a new key, and loading a format version 2 file. `SecretSeeds::from_parts` is public, because the vector tests and a future import need it. Loading builds the `SecretSeeds` internally, derives the keys from it and discards it; nothing returns it. A key loaded from a format version 1 file has no seeds, so the type system rules out writing it as format version 2.

### Writing

```text
generate ──► SecretSeeds::generate()
               │
               └─► format::write_key_pair(paths, &seeds, password, overwrite, kdf)
                     ├─► secret_key::encode_v2(&seeds, …)        ──► 151-byte secret key file
                     │     (derives the key ID from the seeds itself)
                     ├─► public key from seeds.key_pair()        ──► .pub file
                     └─► returns that PublicKey ──► generate prints key ID, fingerprint, public key text
```

*   `format::write_key_pair` takes `&SecretSeeds` instead of `&KeyPair` and returns the `PublicKey` it wrote. `generate` prints from that return value, so it shows exactly what was written. Everything else about writing stays the same:
    *   both files are staged and synced first
    *   the public key is placed first and the secret key last
    *   the file modes don't change
*   `format::write_secret_key(path, &SecretSeeds, password, kdf)` writes format version 2.
*   The format version 2 encoder takes only the seeds, and derives the header's key ID from them itself. No caller can hand it a key ID, so it can't write a file whose key ID doesn't match its keys.
*   Nothing writes format version 1 any more. Today's encoder, which takes a `&SecretKey`, is removed, so no public function can create a new format version 1 file. Tests that need a format version 1 file use the committed fixtures, or copies of their bytes.

### Reading

`secret_key::read_with` stays one function and branches on the header's version byte:

```text
read file (bounded) → header (must be SecretKey) → KDF parameters → salt → nonce   ── shared, unchanged
        │
        ├─ version 1: ciphertext must be 4,088 bytes ─┐
        └─ version 2: ciphertext must be    80 bytes ─┤   both checked BEFORE the password is requested
                                                      ▼
                                       password_fn(&kdf) → decrypt (wrong password → Error::WrongPassword)
        │
        ├─ version 1: decode as today (unchanged, frozen): Ed25519 key, expanded ML-DSA key, key ID;
        │             payload key ID must equal header key ID; SecretKey::from_parts
        └─ version 2: split into Ed25519 key and ξ → SecretSeeds::from_parts → key_pair()
                      fingerprint's first 8 bytes must equal header key ID → SecretKey
```

*   The payload length depends on the version. So a file relabelled from one format version to the other fails the length check before the password prompt. The header is still not authenticated by the AEAD, and doesn't need to be for this.
*   Exact lengths also mean trailing bytes are rejected in both format versions.
*   Every supported version has its own arm in the `match` on the version, and a catch-all arm rejects anything else. The catch-all is unreachable while `FileHeader::read` rejects versions other than 1 and 2.

### The derived-key-ID check (format version 2 only)

After decrypting a format version 2 payload, pqsign derives both public keys and computes the fingerprint. It then requires the fingerprint's first 8 bytes to equal the key ID in the file header. On a mismatch, `read_with` fails with the key-ID mismatch error:

```text
error: crypto error: the key in this secret key file does not match its key ID; the file is corrupt, or this pqsign build derives keys differently from the one that wrote it; restore the file from a backup, and if the file is intact, report this as a pqsign bug
```

*   It replaces format version 1's stored key ID copy, and checks more. It catches a changed header key ID. It also catches a pqsign build whose `fips204` or `ed25519-dalek` turns the same seed into a different key, which a stored copy would not notice.
*   It's a format rule: in format version 2, the header key ID is always the fingerprint's first 8 bytes. The encoder derives the key ID from the seeds it encodes and takes no key ID from outside, so it can't write anything else.
*   It never applies to format version 1. Keys from pqsign 0.1 have random key IDs, and format version 1 keeps its existing payload-versus-header check unchanged.
*   Cost: the check adds nothing beyond the key generation that format version 2 loading needs anyway. Compared with format version 1 loading, that key generation costs about 164 µs in total, including about 125 µs for ML-DSA-65 and about 13 µs for Ed25519 and the fingerprint (`docs/benchmarks.md`, Apple M2). Argon2id, at about 0.4 s, dominates every load.

### Header versions per file type

`FileType::latest_version` gets one arm per type:

```text
PublicKey => 1   (unchanged: the pqsign:v1: text form requires header version 1)
SecretKey => 2   (new)
Signature => 2   (unchanged)
```

Today public and secret keys share one arm. Changing that arm to 2 would move public keys to version 2 too, and pqsign would then reject its own `pqsign:v1:` public keys. Each file type's version changes on its own, only when that type's bytes change.

The version error names the file type and what to do, for every file type:

```text
error: invalid format: this secret key file is format v3, which needs a newer pqsign (this build reads up to v2)
```

### `inspect`

`FileInfo::SecretKey` gains the format version, and the type line shows it:

```text
Type:        Secret key (format v2, encrypted)
```

`inspect` still reads only the header and the KDF parameters, and never decrypts.

### Compatibility

| File | pqsign 0.1.0 to 0.3.1 | pqsign 0.4 |
|---|---|---|
| Secret key, format v1 | reads | reads; never written |
| Secret key, format v2 | rejected with a version error; `sign` fails before the password prompt | reads and writes |
| Public key `pqsign:v1:` | reads | reads and writes, unchanged |
| Signatures (signature formats v1 and v2) | unchanged by this design | unchanged by this design |

The release ships as 0.4.0, because 0.3.x can't read the new key files. The 0.4.0 release notes will quote the exact error message older releases print.

### Test strategy

The hard requirement, that format version 1 keys keep working, is guarded by files, not by the current writer:

1.  **Before any writer change, committed first:** two format version 1 key fixtures, each with its public key, known password and pinned fingerprint.
    *   One is written by the published pqsign 0.1.1 crate. 0.1.1 writes the same files as 0.1.0: between the two release tags, the secret key code differs only in nonce parsing. The fixture has a random key ID and the default Argon2id parameters, since 0.1.1 can't write any others, so loading it takes about 0.4 s.
    *   The other is written by the published pqsign 0.3.1 crate, with a fingerprint-based key ID and small KDF parameters.

    Tests load each fixture, sign, verify against its public key, and check the fingerprint.
2.  **A format version 2 golden fixture**, written once by the new encoder with a known password and small KDF parameters, then frozen. The test checks its exact length (151 bytes), fingerprint and key ID, so a change that breaks format version 2 fails this test.
3.  **Known-answer tests from seed to public key**, one set for each half, so a failure names the algorithm that drifted:
    *   ML-DSA-65: Wycheproof's `mldsa_65_sign_seed_test.json`. 39 of its groups map a 32-byte `privateSeed` (ξ) to its `publicKey`. The 3 `IncorrectPrivateKeyLength` groups, with seeds of 0, 31 and 33 bytes, are skipped, because `MlDsa65Seed` can only hold 32 bytes.
    *   Ed25519: the RFC 8032 Section 7.1 test vectors, which map a private key to its public key.

    Derivation drift then shows up in a test, not first at load time. The format version 2 golden fixture pins both halves together through its fingerprint.
4.  **Negative tests:**
    *   a format version 2 file relabelled as format version 1, and the reverse
    *   truncated and padded format version 2 files
    *   a changed header key ID, which must give the new error
    *   a public key header at version 2, still rejected

## Risks & Mitigations

*   **Derivation drift.**
    *   *Risk:* format version 2 makes every key load depend on `fips204` and `ed25519-dalek` turning a seed into the same key permanently. A dependency update that changes that derivation would make every format version 2 key fail to load.
    *   *Mitigation:*
        *   The known-answer tests and the golden fixture fail on such an update. They run in CI and in the release workflow, so a build whose derivation differs on any pinned vector can't be released.
        *   That holds for builds from `Cargo.lock`, which pqsign's release builds, Homebrew and the README's `cargo install --locked` use. A build that resolves newer semver-compatible dependencies, such as `cargo install` without `--locked`, isn't covered.
        *   The seed itself is never lost: any pqsign build with the original derivation can load the key.
        *   A deliberate change of derivation needs a new secret key format version, never a change to version 2. This change adds that rule to ARCHITECTURE.md as an invariant.
        *   If a broken build reaches a user anyway, the key-ID mismatch error tells them to restore the file from a backup and, if the file is intact, to report a pqsign bug.
*   **No rollback for new keys.**
    *   *Risk:* a format version 2 key can't be used with pqsign 0.1.0 to 0.3.1, and no tool converts it back.
    *   *Mitigation:* the 0.4.0 release notes will say so. A bug in the format version 2 path needs a fixed 0.4.x, which the fixtures and vector tests make less likely. See Non-Functional Requirements.
*   **Damaged text restores.**
    *   *Risk:* a restore mistake that keeps the length can read as `wrong password` (CUJ 6).
    *   *Mitigation:* this change adds the sign-and-verify check for a restored key to the README.
*   **The permanent cost of format version 1.**
    *   *Risk:* pqsign reads format version 1 permanently, at the cost of one reader branch, two fixtures and a second documented layout.
    *   *Mitigation:* the format version 1 decoder is frozen and fixture-tested, and nothing writes the format any more.

## Alternatives Considered

### Alternative 0: Keep secret key format version 1 unchanged

Leave secret key files as they are.

*   **Pros**:
    *   No second reader and no permanent dependence on seed-to-key derivation at load time.
    *   No new fixtures, vectors or documentation.
    *   fips204 0.5.0 already rejects malformed expanded keys.
*   **Cons**:
    *   A 4,159-byte key doesn't fit one QR code or a single password-manager field.
    *   It stays apart from the standards' seed form.
*   **Reason for Rejection**: Rejected by author: file size is the main reason for the change. The cost is one reader branch, a frozen decoder, two version 1 fixtures, a second documented layout, and a permanent dependence on seed-to-key derivation at load time, guarded by the known-answer tests (see Risks & Mitigations).

### Alternative A: One 32-byte master seed

Store a single random 32-byte value. Derive the Ed25519 private key and ξ from it with labelled one-way hashes, for example keyed BLAKE2b-256 with distinct labels. The file would be 119 bytes.

*   **Pros**: 32 bytes smaller. Backing up a single value is simpler, for example as a mnemonic.
*   **Cons**:
    *   It needs a pqsign-specific derivation. The hash function, keyed or not, the labels, the input order and the output length all have to be specified byte for byte, with test vectors only pqsign can produce.
    *   "Secure if either algorithm holds" would then also depend on the derivation being one-way. Breaking Ed25519 or ML-DSA yields that algorithm's secret, not the master seed, but only as long as the hash can't be inverted.
    *   A key generated elsewhere, for example in RFC 10073 form, could never be stored this way.
*   **Reason for Rejection**: Rejected by author: the 32 bytes saved, 21% of the 151-byte file, don't change what fits, since both sizes fit one QR code and a single password-manager field. They don't justify a custom derivation and an extra assumption in the hybrid guarantee. Two seeds use only the standard FIPS 204 and RFC 8032 key generation.

### Alternative B: Two seeds with the key ID kept in the payload

The format version 1 approach, with seeds instead of expanded keys: the Ed25519 private key, ξ and the 8-byte key ID, for 159 bytes.

*   **Pros**: the same corruption check as format version 1, with no key derivation needed to run it.
*   **Cons**:
    *   8 bytes larger.
    *   A stored copy only shows that the payload and header agree. It can't notice a changed derivation, where the file decrypts fine but yields a different key.
*   **Reason for Rejection**: Rejected by author: deriving the fingerprint and comparing it with the header key ID is stronger and costs no stored bytes.

### Alternative C: ML-DSA seed first in the payload

`ξ || ed25519_sk`, the order of RFC 10073's private key serialization.

*   **Pros**: a future export to RFC 10073's private key form would be a straight copy of the payload.
*   **Cons**:
    *   The standards disagree on the order. RFC 9980 puts the Ed25519 key first, so this matches one standard, not "the standards".
    *   It would be the only pqsign structure with ML-DSA first, an inconsistency that needs comments at the encoder and decoder and a note in the docs.
*   **Reason for Rejection**: Rejected by author: with the standards split, consistency with the rest of pqsign decides. The only gain is that an export this design doesn't include could copy the payload instead of swapping its two halves.

### Alternative D: `KeyPair` carries the seeds

A private seed field on `KeyPair`, with the format version 2 writer taking a `&KeyPair`.

*   **Pros**: the smallest code change. pqsign itself builds a `KeyPair` only through `KeyPair::new`, so its own code would write only generated keys as format version 2.
*   **Cons**:
    *   `KeyPair` turns from a pair of usable keys into a "generated key" type, carrying seeds that only the writer needs.
    *   A future import would have to build a `KeyPair` from external seeds, so any code path that can construct a `KeyPair` could produce one with seeds.
*   **Reason for Rejection**: Rejected by author: a dedicated `SecretSeeds` type keeps `KeyPair` a pair of usable keys. It gives the format version 2 writer a single, explicit input, and it's the type a future import or export would use.

### Alternative E: Optional seeds inside `SecretKey`

`SecretKey` gets an `Option` holding the seeds, and the writer returns an error when it's empty.

*   **Pros**: the fewest changes to function signatures.
*   **Cons**:
    *   "This key can't be written as format version 2" becomes a runtime error instead of a compile error.
    *   Every `SecretKey` carries hidden state about where it came from.
*   **Reason for Rejection**: Rejected by author: the compiler should rule out writing a key loaded from format version 1 as format version 2.

### Alternative F: A fixed nonce instead of the random 24-byte nonce

Each file's random salt already makes the Argon2id key single-use, so a fixed nonce is safe as long as every encryption uses a fresh random salt. It saves 24 bytes, for 127 bytes.

*   **Pros**: 24 bytes smaller.
*   **Cons**:
    *   If a salt ever repeated under the same password, the key and nonce would repeat. That could happen after a random generator failure, or in a future re-encryption command that reuses the salt. A repeated key and nonce exposes the XOR of the two plaintexts and allows forged ciphertexts.
    *   It would also change the offsets that both format versions share.
*   **Reason for Rejection**: Rejected by author: 24 bytes don't justify losing the random nonce's protection against a repeated salt.

### Alternative G: Drop format version 1 secret keys (a breaking change)

Read and write only format version 2.

*   **Pros**: one reader, one layout, less code.
*   **Cons**:
    *   pqsign could no longer sign with any existing key.
    *   The release key would have to be rotated, and its published fingerprint replaced in README.md, docs/install.md, SECURITY.md and the release notes.
    *   pqsign 0.1.0 to 0.3.1 are published on crates.io and Homebrew, so there may be users the author doesn't know about.
*   **Reason for Rejection**: Rejected by author: the only saving is code size. Keeping format version 1 costs one reader branch, two fixtures and a second documented layout, and the reader is today's code.

### Alternative H: Write format version 1 on request

An option for `generate`, like `sign --format v1`, so older pqsign versions can read new keys.

*   **Pros**: a key could be shared with a machine running pqsign 0.3.1 or older.
*   **Cons**: a second write path for new keys, kept alive indefinitely, that defeats the purpose of the change.
*   **Reason for Rejection**: Rejected by author: an older pqsign fails cleanly on a new key file, before asking for the password, and its user can update. Secret keys, unlike signatures, aren't exchanged with other people.

### Alternative I: Authenticate the 71-byte prefix as associated data

Pass the header, KDF parameters, salt and nonce to XChaCha20-Poly1305 as associated data, so any change to them fails decryption.

*   **Pros**: authenticates the header and the KDF parameters, at no size cost.
*   **Cons**:
    *   It changes the encryption functions, which this design keeps out of scope.
    *   Header tampering would then show up as "wrong password".
*   **Reason for Rejection**: Rejected by author: the length-by-version rule and the derived-key-ID check catch relabelling and key ID changes. An edited KDF parameter still reads as a wrong password, and changing the AEAD stays a separate decision.

### Alternative J: Keep the format version 1 encoder for later re-encryption

Keep today's encoder, which builds a format version 1 file from a `SecretKey`, so a format version 1 key, such as the release key, can be given a new password later.

*   **Pros**: re-encrypting a format version 1 key would need no new code. Tests could build fresh format version 1 files from in-memory keys.
*   **Cons**:
    *   No command calls it, so it's code kept for a future feature.
    *   It would be the only public way to create new format version 1 files, which the design otherwise rules out.
    *   It only covers format version 1. Re-encrypting a format version 2 key would need a reader that returns the seeds, which loading doesn't provide.
*   **Reason for Rejection**: Rejected by author: the re-encryption in Future Improvements covers both format versions and needs no format-specific writer. Until it exists, the format version 1 fixtures replace the encoder in tests.

--------------------------------------------------------------------------------

## Non-Functional Requirements

*   **Security**:
    *   The seeds are held in types that are wiped on drop: `MlDsa65Seed`, `Ed25519SecretKey` and `SecretSeeds`.
    *   The decrypted payload is held in `Zeroizing`, as today.
    *   For format version 2, the expanded secret key is no longer handed to `fips204` by value; see "A dedicated seed type in the domain".
    *   The header stays unauthenticated by the AEAD. The length-by-version rule and the derived-key-ID check stop relabelling and key ID changes from producing a usable key.
*   **Performance**, all figures from `docs/benchmarks.md` on an Apple M2:
    *   Compared with format version 1, loading a format version 2 key adds one key generation, about 164 µs.
    *   Writing one runs it twice, about 330 µs.
    *   Signing still derives the public key for the signer fingerprint, about 117 µs, as today.
    *   Argon2id, at about 0.4 s, dominates every load and every write.
*   **Storage**: a new secret key file is 151 bytes instead of 4,159.
*   **Rollout and rollback**:
    *   This ships as 0.4.0.
    *   Rolling back doesn't work for key files. A format version 2 key can't be used with pqsign 0.3.x, and no tool converts it back. If 0.4 has a bug in the format version 2 path, the user needs a fixed 0.4.x, not a downgrade. The release notes say so.
    *   Format version 1 keys can move between 0.3.x and 0.4 freely.

--------------------------------------------------------------------------------

### Additional Resources

*   [`seed-secret-key-format-brief.md`](seed-secret-key-format-brief.md): the brainstorm brief. This design settles the payload order the brief left open, removes the format version 1 encoder the brief kept, and writes one format version 1 fixture with pqsign 0.1.1 instead of 0.3.1.
*   [`docs/cryptography.md`](../cryptography.md): key encryption, file formats and the "Relation to Standards" section
*   [`ARCHITECTURE.md`](../../ARCHITECTURE.md): layers and the invariants this design must keep
*   [`docs/benchmarks.md`](../benchmarks.md): the timing figures
*   [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), Section 5.1 and Algorithm 6 (`ML-DSA.KeyGen_internal`): ξ as the key generation seed
*   [RFC 10073](https://www.rfc-editor.org/rfc/rfc10073), Section 4.2: the private key as `mldsaSeed || tradSK`
*   [RFC 9980](https://www.rfc-editor.org/rfc/rfc9980), Section 5.3.2.2: the Ed25519 secret key followed by the 32-byte ML-DSA seed in OpenPGP
*   [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032), Section 7.1: Ed25519 test vectors
*   [Wycheproof `mldsa_65_sign_seed_test.json`](https://github.com/C2SP/wycheproof/blob/7a325932231bd7a724c791c8b0d65ea4d6d2f435/testvectors_v1/mldsa_65_sign_seed_test.json): seed-to-key test vectors

### Future Improvements

*   **A re-encryption command** that changes a key file's password or KDF parameters, for both format versions. It would:
    *   read the file as `read_with` does, including the length check for its version
    *   decrypt the payload, and decode it only to validate it, including the derived-key-ID check for format version 2
    *   encrypt the same payload bytes again under a fresh salt, a fresh nonce and the new password
    *   write the header back with the version and key ID it was read with

    It never needs to know how to build a payload, so it doesn't need the removed format version 1 encoder, and the fingerprint is kept by construction. It needs one internal helper that returns the decrypted payload bytes in `Zeroizing`. `read_with` can use the same helper.
*   **Import and export in RFC 10073 private key form** (`mldsaSeed || tradSK`), built on `SecretSeeds`. Only format version 2 keys can be exported.
*   **A length check in `inspect`**, so a truncated secret key file is flagged without a password.

--------------------------------------------------------------------------------

## Detailed Implementation Plan

The work lands in four commits, in this order. Commit 1 must pass on today's code before anything else changes. That makes the format version 1 guarantee independent of the writer.

1.  Format version 1 key fixtures and their tests.
2.  `SecretSeeds` in the domain, with no change to any file format.
3.  Secret key format version 2: header, reader, writer, `inspect`, `generate`, and the tests.
4.  Documentation.

### Target Files to Create/Modify

#### Commit 1: Freeze format version 1

##### 1. `tests/fixtures/secret-keys/v1.key`, `tests/fixtures/secret-keys/v1.key.pub` (Create)

*   **Type / Scope**: Test fixtures, binary key file and text public key.
*   **Proposed Changes**:
    *   A key pair written by pqsign 0.3.1's own code, not by the current tree.
    *   Made with a scratch program outside the repository that depends on `pqsign = "=0.3.1"` from crates.io and calls `KeyPair::new()`, `format::write_secret_key` and `format::write_public_key`.
    *   The password is `fixture-password`, with KDF parameters `Kdf::Argon2id { mem_limit: 64 * 1024, ops_limit: 1 }`, so loading it costs milliseconds.
    *   Its key ID is the fingerprint prefix, as for every key since 0.2.

##### 2. `tests/fixtures/secret-keys/v1-random-id.key`, `tests/fixtures/secret-keys/v1-random-id.key.pub` (Create)

*   **Type / Scope**: Test fixtures.
*   **Proposed Changes**:
    *   A format version 1 key written by pqsign 0.1.1's own code, the oldest published writer of the format.
    *   Made with a second scratch program that depends on `pqsign = "=0.1.1"` from crates.io and calls `KeyPair::new()`, `format::write_secret_key(path, &secret_key, password)` and `format::write_public_key`. All three are public in 0.1.1, and its `KeyPair::new` gives each key a random key ID.
    *   This was checked at git tag `v0.1.1`:
        *   `src/lib.rs` exports `domain` and `format`
        *   `src/format/mod.rs` re-exports `write_secret_key` and `write_public_key`
        *   `src/format/secret_key.rs:20` takes no KDF parameter
        *   `src/domain/keys.rs:27` uses `KeyId::random`
    *   0.1.1's `write_secret_key` takes no KDF parameter, so the file uses the default Argon2id parameters (256 MiB, 3 passes). Loading it takes about 0.4 s in the test suite. The password is `fixture-password`.
    *   0.1.1 writes the same files as 0.1.0, so this fixture stands for both. It checks that a key written by 0.1.1 still loads, and that the format version 2 key-ID rule is never applied to format version 1.

##### 3. `tests/fixtures/secret-keys/README.md` (Create)

*   **Type / Scope**: Documentation for the fixtures.
*   **Proposed Changes**:
    *   Says that these are test-only keys whose password is published, and must never sign anything real.
    *   Records how each fixture was made: the pqsign version or path, the scratch program's code, the password and the KDF parameters.
    *   Records each fixture's fingerprint.
    *   Says that fixtures are never regenerated. A new format version adds new fixtures next to these.

##### 4. `tests/fixtures.rs` (Modify)

*   **Type / Scope**: Integration tests for committed files.
*   **Proposed Changes**: Three tests, following the existing signature fixture tests. The file only reads fixtures, so it defines no `TEST_KDF`.
    *   `test_v1_secret_key_fixture_signs`:
        *   reads `v1.key` with `format::read_secret_key` and the password `fixture-password`
        *   checks its key ID and fingerprint against the values pinned in the test
        *   signs a temporary file in signature format v2, and verifies it against `v1.key.pub`
    *   `test_v1_random_id_secret_key_fixture_signs`: the same steps for `v1-random-id.key`. It also asserts that its key ID differs from its fingerprint prefix.
    *   `test_v1_secret_key_header_key_id_mismatch_is_rejected`:
        *   copies `v1.key` and flips one bit in each of bytes 6–13, the header key ID
        *   writes the copy to a temporary directory and reads it with `format::read_secret_key` and the fixture password
        *   expects `Error::Crypto` whose message contains "decrypted key ID doesn't match header"

        The header isn't authenticated by the AEAD, so the copy decrypts and the frozen payload-versus-header check fires.

#### Commit 2: Seeds in the domain

##### 5. `src/domain/types.rs` (Modify)

*   **Type / Scope**: Domain byte types.
*   **Proposed Changes**: Add `secret_byte_type!(MlDsa65Seed, 32)`. A comment names it as FIPS 204's ξ, the input to `ML-DSA.KeyGen_internal`. `Ed25519SecretKey` needs no change: it already holds the 32-byte RFC 8032 private key.

##### 6. `src/domain/keys.rs` (Modify)

*   **Type / Scope**: Domain key types.
*   **Proposed Changes**:
    *   Add `pub struct SecretSeeds { ed25519: Ed25519SecretKey, mldsa65: MlDsa65Seed }`, deriving `ZeroizeOnDrop`, with a `Debug` that prints `SecretSeeds([REDACTED])` and no `Clone` or `PartialEq`. Its fields are private.
    *   `SecretSeeds::generate() -> Self` fills `Ed25519SecretKey` and `MlDsa65Seed` directly from `rand::rng()`, using their `LEN`, with no intermediate copy.
    *   `SecretSeeds::from_parts(ed25519: Ed25519SecretKey, mldsa65: MlDsa65Seed) -> Self` is public and takes ownership. It's infallible, because every 32-byte value is a valid seed.
    *   `ed25519(&self) -> &Ed25519SecretKey` and `mldsa65(&self) -> &MlDsa65Seed`, for the encoder.
    *   `SecretSeeds::key_pair(&self) -> KeyPair`:
        *   `ml_dsa_65::KG::keygen_from_seed(self.mldsa65.as_bytes())`
        *   `ed25519::SigningKey::from_bytes(self.ed25519.as_bytes())`
        *   the key ID is `Fingerprint::of(&verifying_key, &mldsa_public_key).key_id()` for both the secret key and the public key, as `KeyPair::new` does today
    *   A doc comment on `key_pair` says that this derivation is part of secret key format version 2 and must not change.
    *   `KeyPair::new()` becomes `SecretSeeds::generate().key_pair()`.
    *   Removed:
        *   `gen_ed25519_keys` and `gen_mldsa65_keys`, whose seed handling moves into `SecretSeeds::generate`
        *   `KeyPair::ED25519_SEED_LEN` and `KeyPair::MLDSA65_SEED_LEN`
        *   the `Zeroizing` import, if it becomes unused

##### 7. `src/domain/mod.rs` (Modify)

*   **Type / Scope**: Domain module, re-exports and unit tests.
*   **Proposed Changes**:
    *   Re-export `SecretSeeds` and `MlDsa65Seed`.
    *   Add `SecretSeeds` and `MlDsa65Seed` to `test_secret_key_types_are_wiped_on_drop`.
    *   Add `MlDsa65Seed` and `SecretSeeds` to `test_secret_key_bytes_are_never_printed`.
    *   New tests:
        *   the same seeds always give the same key pair: equal fingerprints and equal encoded public keys
        *   the key ID of `key_pair()` is the fingerprint prefix
        *   a key pair from seeds signs and verifies
        *   two `generate()` calls give different fingerprints
        *   the Ed25519 half is pinned by known answers. For TEST 1, TEST 2 and TEST 3 of RFC 8032 Section 7.1, `SecretSeeds::from_parts(Ed25519SecretKey::from_bytes(SECRET KEY), MlDsa65Seed::from_bytes([0u8; 32])).key_pair()` gives an Ed25519 verifying key equal to the listed PUBLIC KEY. A unit test can read the `pub(crate)` field.

#### Commit 3: Secret key format version 2

##### 8. `src/format/header.rs` (Modify)

*   **Type / Scope**: File header.
*   **Proposed Changes**:
    *   `latest_version` gets one arm per type: `PublicKey => 1`, `SecretKey => 2`, `Signature => 2`. The doc comment says each file type's version changes on its own.
    *   Add a private `FileType::name(self) -> &'static str`, returning `"public key"`, `"secret key"` or `"signature"`.
    *   `check_version`'s message for a too-new version becomes `this {name} file is format v{version}, which needs a newer pqsign (this build reads up to v{latest})`. The message for version 0 doesn't change.

##### 9. `src/format/secret_key.rs` (Modify)

*   **Type / Scope**: Secret key encoding and decoding.
*   **Proposed Changes**:
    *   **Constants and lengths.**
        *   `V1_PAYLOAD_LEN = 32 + 4032 + 8` (4,072) and `V2_PAYLOAD_LEN = 32 + 32` (64).
        *   A private `fn ciphertext_len(version: u8) -> Result<usize, Error>` returns 4,088 for version 1, 80 for version 2, and otherwise `Error::InvalidFormat(format!("unsupported secret key format v{version}"))`.
        *   `check_ciphertext_len` takes the version, and its message is exactly `secret key file is truncated or corrupt ({len} bytes of key data, expected {expected} for format v{version})`.
    *   **`pub fn write(path, seeds: &SecretSeeds, password, kdf)`** writes format version 2 through `pub(super) fn encode_v2(seeds: &SecretSeeds, password, kdf)`. `encode_v2` takes no key ID parameter. It does, in order:
        1.  `kdf.check()`
        2.  builds the payload `ed25519_sk || ξ` in a `Zeroizing<Vec<u8>>` with exact capacity 64
        3.  builds the header with `FileHeader::new(FileType::SecretKey, seeds.key_pair().public_key.key_id())`, which is version 2
        4.  encrypts the payload under a fresh salt and nonce

        Its output bytes are the header, KDF block, salt, nonce and ciphertext, as in the layout table.
    *   **Today's encoder is removed:** `write(path, &SecretKey, …)`, `encode(&SecretKey, …)` and `serialize_payload`, together with the import `fips204::traits::SerDes`, which only `serialize_payload` used. Nothing writes format version 1 any more.
    *   **`read_with`** keeps its signature and its order: header, KDF, salt and nonce, then `check_ciphertext_len(header.version, len)`, all before `password_fn`.
        *   Decryption moves into a private helper, `decrypt_payload`, that returns the plaintext in `Zeroizing`, so a future re-encryption command can reuse it.
        *   After decryption, a `match header.version` with one arm per supported version calls one of two decoders:
            *   `decode_v1`: today's `deserialize_payload`, the payload-versus-header key ID check with its existing message, and `SecretKey::from_parts`, all unchanged. It gets the doc comment "Frozen: decodes secret key format v1, which pqsign no longer writes. Never change it; the fixtures in tests/fixtures/secret-keys guard it."
            *   `decode_v2`: reads `Ed25519SecretKey` and then `MlDsa65Seed` from the payload, builds `SecretSeeds::from_parts`, then `key_pair()`. If `key_pair.public_key.key_id() != header.key_id`, it returns the key-ID mismatch error, `Error::Crypto("the key in this secret key file does not match its key ID; the file is corrupt, or this pqsign build derives keys differently from the one that wrote it; restore the file from a backup, and if the file is intact, report this as a pqsign bug")`. Otherwise it returns the secret key from `key_pair.into_parts()`. The key-ID mismatch error is an `Error::Crypto`, not the `Error::KeyIdMismatch` used in signature verification.
        *   A catch-all arm returns the same `unsupported secret key format v{version}` error as `ciphertext_len`. Both are unreachable once item 8 makes `FileHeader::read` reject versions other than 1 and 2.
    *   `read` (with a password) doesn't change.

##### 10. `src/format/key_pair.rs` (Modify)

*   **Type / Scope**: Writing a key pair.
*   **Proposed Changes**:
    *   The signature becomes `write_key_pair(secret_path, public_path, seeds: &SecretSeeds, password, overwrite, kdf) -> Result<PublicKey, Error>`.
    *   It encodes the secret key with `secret_key::encode_v2(seeds, …)`, which derives the key ID itself. It encodes the public key with `public_key::encode_text(&seeds.key_pair().public_key)`, then returns that public key. The encoder keeps its guarantee and needs no key ID from outside; for the cost, see Non-Functional Requirements.
    *   Staging, commit order, file modes and the clean-up on failure don't change.
    *   The import `crate::domain::KeyPair` is replaced by `SecretSeeds` and `PublicKey`.

##### 11. `src/format/mod.rs` (no change)

*   **Type / Scope**: Re-exports.
*   **Proposed Changes**: The re-export `write as write_secret_key` stays. It's listed because `write_secret_key` now takes `&SecretSeeds` and writes format version 2. No re-export for writing format version 1 exists.

##### 12. `src/format/inspect.rs` (Modify)

*   **Type / Scope**: `inspect` output.
*   **Proposed Changes**: `FileInfo::SecretKey` gains `version: u8`, set from the header. `Display` prints `Type:        Secret key (format v{version}, encrypted)`. Everything else in the output, including the "Fingerprint: not stored in plain text" line, doesn't change.

##### 13. `src/commands/generate.rs` (Modify)

*   **Type / Scope**: `generate` command.
*   **Proposed Changes**:
    *   `KeyPair::new()` is replaced by `let seeds = SecretSeeds::generate()`, and `format::write_key_pair(…, &seeds, …)` returns the `PublicKey`.
    *   The key ID, the fingerprint and the encoded public key are printed from that returned key, so the output matches what was written.
    *   The output format doesn't change. The import `crate::domain::KeyPair` is replaced by `SecretSeeds`.

##### 14. `src/format/tests.rs` (Modify)

*   **Type / Scope**: Unit tests for formats.
*   **Proposed Changes**: The unit tests read the version 1 fixture with `std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/secret-keys/v1.key"))`, as `tests/fixtures.rs` reads its fixtures.
    *   **Existing tests that change:**
        *   `test_header_roundtrip` expects version 2 for a new secret key header.
        *   `test_header_versions_are_per_file_type`:
            *   the secret key case accepts version 2, and rejects version 3 with `this secret key file is format v3, which needs a newer pqsign (this build reads up to v2)`
            *   the signature case rejects version 3 with `this signature file is format v3, which needs a newer pqsign (this build reads up to v2)`
            *   a public key header at version 2 is rejected
        *   `test_public_key_wrong_file_type_in_binary` builds its header as `FileHeader { version: 1, file_type: FileType::SecretKey, key_id }` instead of `FileHeader::new`, so it still reaches the file-type check.
        *   `test_public_key_text_and_header_versions_must_match` stays as it is. Its doc comment becomes: "The prefix and the header must agree. Secret keys moved to format v2 while public keys stay at v1, so a v2 header inside `pqsign:v1:` text is rejected by this check."
        *   `test_secret_key_wrong_length_detected_before_password` runs for two inputs:
            *   the bytes of the version 1 fixture
            *   a format version 2 file freshly written from `SecretSeeds::generate()`

            For each, it builds a copy truncated by one byte (`&data[..data.len() - 1]`) and a copy padded with `b"extra"`. It expects `Error::InvalidFormat` whose message contains "truncated or corrupt" and names the version, without calling `password_fn`.
    *   **The other call sites of `write_secret_key`** switch to `SecretSeeds::generate()` and format version 2:

        | Test | After the change |
        |---|---|
        | `test_secret_key_roundtrip_with_password` | writes from `SecretSeeds::generate()`, reads back, and compares the key ID and fingerprint with `seeds.key_pair()` |
        | `test_secret_key_wrong_password` | format version 2 file; the wrong password gives `Error::WrongPassword` |
        | `test_secret_key_records_its_kdf_parameters` | format version 2 file; `read_secret_key_with` reports the written KDF parameters |
        | `test_secret_key_write_rejects_invalid_kdf_parameters` | `write_secret_key(&path, &seeds, …, &invalid_kdf)` fails, because `encode_v2` runs `kdf.check()` first |
        | `test_secret_key_is_raw_binary` | format version 2 file; it starts with `PQSN` and isn't text |
        | `test_read_signature_on_secret_key_file_fails` | uses a format version 2 key file as the wrong file |
        | `test_read_public_key_text_on_secret_key_binary_fails` | uses a format version 2 key file as the wrong file |

    *   **New tests:**
        *   a format version 2 file is exactly 151 bytes, and its header key ID equals the fingerprint prefix
        *   a format version 2 round trip signs and verifies
        *   a format version 2 file relabelled as version 1, and a copy of the version 1 fixture relabelled as version 2, both fail the length check without calling `password_fn`
        *   a format version 2 file with a changed header key ID fails with the key-ID mismatch error

##### 15. `tests/fixtures/secret-keys/v2.key`, `tests/fixtures/secret-keys/v2.key.pub` (Create), `tests/fixtures/secret-keys/README.md` and `tests/fixtures.rs` (Modify)

*   **Type / Scope**: A golden fixture for format version 2.
*   **Proposed Changes**:
    *   Made once, after commit 3 builds, with a third scratch program outside the repository. It depends on the branch's checkout by path (`pqsign = { path = "…" }`) and calls `SecretSeeds::generate()` and `format::write_key_pair(…, &seeds, password, false, &Kdf::Argon2id { mem_limit: 64 * 1024, ops_limit: 1 })`, with password `fixture-password`. Its code, the password, the KDF values and the fingerprint go into the fixtures README.
    *   New test `test_v2_secret_key_fixture_signs`:
        *   the file is 151 bytes
        *   it reads, and its key ID and fingerprint match the pinned values
        *   it signs, and the signature verifies against `v2.key.pub`

##### 16. `tests/inspect.rs` (Modify)

*   **Type / Scope**: `inspect` integration tests.
*   **Proposed Changes**:
    *   In `test_inspect_encrypted_secret_key`:
        *   `let seeds = SecretSeeds::generate();` replaces the `KeyPair` line
        *   `format::write_secret_key(&sk_path, &seeds, pw("pass"), &TEST_KDF)`
        *   the key ID assertion compares with `seeds.key_pair().public_key.key_id()`
        *   the output must also contain `Secret key (format v2, encrypted)`

        The import `KeyPair` becomes `SecretSeeds`, if nothing else in the file uses `KeyPair`.
    *   A new test runs `inspect` on `tests/fixtures/secret-keys/v1.key` and asserts `Secret key (format v1, encrypted)`.

##### 17. `tests/integration.rs` (Modify)

*   **Type / Scope**: Integration tests.
*   **Proposed Changes**:
    *   In `test_write_key_pair_without_overwrite_never_replaces_files`, the call and its error check become `let result = format::write_key_pair(&sk_path, &pk_path, &SecretSeeds::generate(), pw("test-pw"), false, &TEST_KDF);` followed by `assert!(matches!(result, Err(pqsign::errors::Error::FileExists(_))));`. That replaces both the `unwrap_err()` line, which would need `PublicKey: Debug`, and the separate `matches!` line.
    *   The test's other assertions stay.
    *   The tests that read back with `read_secret_key` don't change.

##### 18. `tests/cli.rs` (Modify)

*   **Type / Scope**: CLI tests.
*   **Proposed Changes**:
    *   The `generate_key` helper passes `&SecretSeeds::generate()` to `write_key_pair`. The import `pqsign::domain::KeyPair` becomes `SecretSeeds`.
    *   `test_cli_generate` also asserts that the secret key file is 151 bytes, and that `pqsign inspect` on it prints `Secret key (format v2, encrypted)`.
    *   A new CLI test signs with `tests/fixtures/secret-keys/v1.key` through `--password-file` (password `fixture-password`), and verifies against `v1.key.pub`.

##### 19. `tests/vectors/wycheproof/mldsa_65_sign_seed_test.json` (Create) and `tests/vectors/wycheproof/README.md` (Modify)

*   **Type / Scope**: Vendored test vectors, excluded from the crates.io package by the existing `tests/vectors/` rule.
*   **Proposed Changes**:
    *   Copy `testvectors_v1/mldsa_65_sign_seed_test.json`, 886 KB, from the same Wycheproof commit as the two vendored files, `mldsa_65_verify_test.json` and `mldsa_65_sign_noseed_test.json`: `7a325932231bd7a724c791c8b0d65ea4d6d2f435`.
    *   The README lists it next to those two files, with the commit that last changed it in C2SP/wycheproof, and its update instruction says "copy all three files".

##### 20. `tests/mldsa_vectors.rs` (Modify)

*   **Type / Scope**: Vector tests.
*   **Proposed Changes**:
    *   New test `test_mldsa65_seed_vectors`, with the same counting rules as `test_mldsa65_signing_vectors`:
        *   **Skipped cases:** cases flagged `IncorrectPrivateKeyLength`, `Internal` or `Randomized` count as skipped.
        *   **Checked cases:** every other case is checked. A valid case must give Wycheproof's signature, and an invalid case, such as tcId 5 with `InvalidContext`, must fail to sign. Signing uses the `PrivateKey` from `ml_dsa_65::KG::keygen_from_seed(&seed)` and `try_sign_with_seed(&[0u8; 32], msg, ctx)`.
        *   **Total:** the test asserts `checked + skipped == numberOfTests` (105).
        *   **Public keys, once per group whose `privateSeed` is 32 bytes (39 groups):**
            *   `keygen_from_seed` must give `publicKey` byte for byte
            *   so must pqsign's own path:
                1.  take `format::encode_public_key(&SecretSeeds::from_parts(Ed25519SecretKey::from_bytes([0u8; 32]), MlDsa65Seed::from_bytes(seed)).key_pair().public_key)`
                2.  strip the `pqsign:v1:` prefix and the trailing newline, and base64-decode
                3.  compare bytes 46 to the end with `publicKey`

                The binary form is the 14-byte header, the 32-byte Ed25519 key, then the 1,952-byte ML-DSA key.
    *   The module doc names the seed file. It says that pqsign stores seeds since 0.4, and the expanded form in format v1, and that the seed file guards secret key format version 2.

#### Commit 4: Documentation

The wording rule applies to every user-facing file this commit edits: `docs/cryptography.md`, `ARCHITECTURE.md` and `README.md`. They say "secret key format v1/v2" and "signature format v1/v2", never a bare "v2".

##### 21. `docs/cryptography.md` (Modify)

*   **Type / Scope**: Design documentation.
*   **Proposed Changes**:
    *   **"ML-DSA-65" bullet, line 29:** the 4,032-byte secret key is "stored as its 32-byte seed since pqsign 0.4".
    *   **"What Gets Encrypted":**
        *   the format version 2 payload (the Ed25519 private key, then ξ, 64 bytes, 80 encrypted)
        *   then the derived-key-ID check
        *   then this sentence on text backups: "A restore mistake can show up as a format error, as a corrupt file, as the key-ID mismatch error, or as `wrong password`, because the AEAD can't tell a damaged file from a wrong password. The reliable check is to sign a test file and verify the signature against the key's `.pub` file; `pqsign inspect` only confirms the file type and the format version."
        *   the current text moves to a "Secret key format v1 (pqsign 0.1 to 0.3)" subsection, including its key ID cross-check
    *   **"Memory Safety":**
        *   the list of wiped types names `SecretSeeds` and `MlDsa65Seed`
        *   the remark that `fips204` takes the secret key bytes by value applies to secret key format v1 only
    *   **"File Format":** the version row lists each file type: "1 for public keys, 2 for secret keys (1 before pqsign 0.4), 2 for signatures (1 before pqsign 0.2)". The secret key layout table shows format version 2 at 151 bytes, followed by format version 1 at 4,159 bytes.
    *   **"Relation to Standards":**
        *   the "ML-DSA secret key stored as" row for pqsign becomes "The 32-byte seed (secret key format v1: the expanded key, 4032 bytes)"
        *   the seed bullet under "Possible alignment" is removed, since it's done
    *   **"Implementation Status", line 265:** the sentence saying the vector tests sign "from the expanded secret keys pqsign stores" also names the seed vectors. It says that pqsign stores seeds since 0.4, and expanded keys in secret key format v1.

##### 22. `ARCHITECTURE.md` (Modify)

*   **Type / Scope**: Architecture documentation.
*   **Proposed Changes**:
    *   **`src/commands/` bullet for `generate`, line 37:** it generates `SecretSeeds` and writes them with `format::write_key_pair`, which returns the public key it prints. Today's text says it "generates a `KeyPair`".
    *   **`src/domain/` bullets:** `SecretSeeds`, the two seeds a new key is generated from. It's the only input for writing secret key format v2.
    *   **`src/format/` bullets:** secret keys are written in secret key format v2. Secret key format v1 is still read, and never written.
    *   **`tests/` bullet, line 79:** `tests/` holds "fixtures for both signature formats and both secret key formats".
    *   **"Secrets are wiped" invariant, lines 92–95:** the copy `fips204` takes by value happens only when a secret key format v1 key is loaded. A format v2 key hands it only a reference to the seed.
    *   **Invariants**, two new ones:
        *   every secret key format pqsign has written stays readable, enforced by the committed fixtures
        *   the derivation from seeds to keys (FIPS 204 `KeyGen_internal` and RFC 8032) is part of secret key format v2 and must not change; a different derivation needs a new secret key format version
    *   **Strict parsing:** "signature format v2 files and secret key files in both formats reject trailing bytes".

##### 23. `README.md` (Modify)

*   **Type / Scope**: User documentation.
*   **Proposed Changes**:
    *   **"Generate a key pair":**
        *   one sentence saying that pqsign 0.4 and later write a smaller secret key format, which pqsign 0.3 and older can't read, and that existing keys keep working
        *   on text backups: back up with `base64`, then the sentence from item 21 about restore mistakes and the sign-and-verify check
    *   **"How It Works":** the secret key sentence mentions that the ML-DSA-65 key is stored as its 32-byte seed.

**Release notes:** the 0.4.0 notes, written in step 4 of `docs/releasing.md`, quote the version error that pqsign 0.1.0 to 0.3.1 print for a secret key format v2 file. They also state that secret key format v2 keys can't be used with those releases.

**Not changed by this design:**
*   `Cargo.toml`: the version moves to 0.4.0 in the separate release pull request, following `docs/releasing.md`.
*   `benches/cli.rs` and `benches/crypto.rs`: `generate::run` keeps its signature, and `KeyPair::new` stays.

### Verification Plan

*   **Compilation/Build**: `cargo build --locked`, `cargo bench --no-run --locked`.
*   **Unit and Integration Tests**: `cargo test --locked`. Commit 1 must pass on its own, before commit 2, against the unchanged code.
*   **Static Analysis & Linting**: `cargo clippy --locked --all-targets -- -D warnings`, which also catches every import or constant the change leaves unused; `cargo fmt --check`; `cargo audit`.
*   **Test Coverage Requirement**: these paths have a test:
    *   both reader branches
    *   the length check per version, truncated and padded
    *   the derived-key-ID check and the key-ID mismatch error
    *   the format version 1 payload-versus-header key ID check
    *   both relabel directions
    *   the per-file-type version messages
    *   both format version 1 fixtures, from pqsign 0.1.1 and 0.3.1
    *   `inspect` for both versions
    *   the seed-to-key vectors for both algorithms
    *   the format version 2 golden fixture
*   **E2E / Manual**: with a release build of the branch and the published 0.3.1 binary:
    *   `pqsign generate` writes a 151-byte key
    *   it signs, and both binaries verify the signature
    *   `inspect` shows `Secret key (format v2, encrypted)`
    *   pqsign 0.3.1 run on the new key fails with `file requires pqsign format v2, this build supports v1`, before asking for the password
    *   the new binary signs with the committed fixtures `tests/fixtures/secret-keys/v1-random-id.key` and `v1.key` (password `fixture-password`), and both signatures verify against their `.pub` files

--------------------------------------------------------------------------------

<!-- Provenance: Indicates initial structural drafting via EGM. -->

*Drafted with EGM*
