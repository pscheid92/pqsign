# Seed-based secret key format

* **Author:** Patrick Scheid
* **Date:** 2026-11-18

## Overview

pqsign's secret key files are 4,159 bytes today. Almost all of that is the expanded ML-DSA-65 secret key, 4,032 bytes. FIPS 204 can regenerate that key from a 32-byte seed, ξ, and RFC 10073 and RFC 9980 store ML-DSA keys that way. This concept adds a new secret key format, version 2 for the secret key file type. It stores seeds instead of expanded keys, and shrinks new key files by about 96%.

The main reason is a smaller file. A secondary reason is to store keys the way the standards do. Only newly generated keys use the new format. Existing key files cannot be converted, because an expanded ML-DSA key does not contain the seed it was made from. They keep working for signing. Public keys, fingerprints, key IDs and signatures do not change.

pqsign's owner is probably its only user, and the release signing key is in the old format and will not be rotated soon. So in practice, the benefit reaches new keys only.

## Analysis

### Which payload

Five payload variants were compared. Each file has the same 71-byte prefix (header 14, KDF parameters 17, salt 16, nonce 24) and a 16-byte authentication tag after the payload.

| Payload | File size |
|---|---|
| Today: Ed25519 key, expanded ML-DSA key, key ID | 4,159 bytes |
| Two seeds and key ID | 159 bytes |
| Two seeds, no key ID | 151 bytes |
| One master seed and key ID | 127 bytes |
| One master seed, no key ID | 119 bytes |

Every variant cuts the file by 96–97%, so the main goal does not decide between them. All seven review lenses recommended **two seeds without the key ID, 151 bytes**, and the author chose it: the 32-byte Ed25519 private key, which pqsign already stores today, and the 32-byte ML-DSA seed ξ, which `KeyPair::new` already generates and then discards.

- **It adds no new cryptography.** Turning each seed into a key is plain RFC 8032 and FIPS 204 key generation. A master seed would need a pqsign-specific derivation (a hash function, labels, byte order, output length), a written specification, and test vectors that only pqsign can produce.
- **The hybrid guarantee stays unconditional.** With a master seed, "secure if either algorithm holds" still holds, but only if the derivation is one-way. Breaking Ed25519 with a quantum computer gives the Ed25519 scalar, and breaking ML-DSA gives s1 and s2. Getting from either back to the master seed would mean inverting a hash. That's an extra assumption the docs would have to state. With two seeds, no such assumption exists.
- **It matches the standards' private key components.** RFC 10073 stores exactly these two 32-byte values, with the ML-DSA seed first. With two seeds, keys could later be both exported to and imported from that form. A master seed allows only export: a key generated elsewhere could never become one.
- **The cost is 32 bytes**, under 1% of today's file. A master seed only pays off if a single secret is itself the goal, for example a paper or QR backup of one value, or deriving several keys from one seed. Neither has been named as a goal.

### Key ID: derive it, don't store it

The key ID inside the payload goes away. After decryption, pqsign derives both public keys from the seeds, computes the fingerprint, and requires its first 8 bytes to equal the key ID in the file header.

- That saves 8 bytes and checks more than today's copy does. It catches a corrupted or edited header, and also a pqsign build that generates keys differently from the one that wrote the file. A stored key ID copy would still match in that case.
- It costs nothing extra: signing in signature format v2 computes the fingerprint anyway.
- It is only valid for new keys, whose key ID is by definition the start of their fingerprint. That becomes a format rule. **Version 1 files keep their current check unchanged**, because keys from pqsign 0.1 have random key IDs.
- The new check gets its own error message, for example "the key derived from this file does not match its key ID: the file is corrupt, or this pqsign build derives keys differently".

### Risks the review found

- **Nothing tests reading an old key file.** Every secret key test creates its file with the current writer. Once the writer produces version 2, those tests quietly become version 2 tests, and the first sign of a broken version 1 reader would be a failed release. A version 1 key file made by pqsign 0.3.1, with its public key, fingerprint, password and cheap KDF settings, must be committed as a test fixture *before* the writer changes. A second fixture with a random key ID covers pqsign 0.1 keys, and a version 2 fixture guards the new format the same way.
- **Public and secret keys share one version number in the code.** `FileType::PublicKey | FileType::SecretKey => 1` in `header.rs`. Changing it to 2 would also move public keys to version 2, and pqsign would then reject its own `pqsign:v1:` public keys. The two arms have to be split, with a test that new public keys still encode as version 1.
- **Key generation becomes part of every load.** A version 1 file holds the finished keys. A version 2 file holds seeds, so a change in how `fips204` or `ed25519-dalek` turns a seed into a key would produce a different key from the same file. The derived-key-ID check above detects it. Known-answer tests from ξ to the public key detect it earlier: Wycheproof's `mldsa_65_sign_seed_test.json` provides them. `fips204` 0.5 implements the final FIPS 204 key generation, which hashes ξ together with the parameters k and l, so its keys match the standard's.
- **The current code cannot express "write version 2".** `write_secret_key` takes a `SecretKey`, which holds only the expanded keys. The seeds have to live in the type that `generate` creates, for example `KeyPair` or a dedicated generated-key type. Then the compiler rules out writing a key loaded from a version 1 file. `SecretKey` stays a signing-only type that doesn't know which format it came from.
- **A version 1 key's password could never change.** No password-change command exists today. If pqsign dropped the version 1 encoder, the release key's password and KDF settings would be fixed for good. The author decided to keep the roughly 25-line encoder, used only for re-encrypting existing version 1 keys and never by `generate`.
- **"Format v2" already means something.** Users know "format v2" as the signature format. An older pqsign reading a new key file prints `file requires pqsign format v2, this build supports v1`, which reads as a contradiction. New builds should name the file type and the fix in this message, for every file type. The docs should always say "secret key format" or "signature format", never a bare "v2".
- **Is it worth it?** One reviewer questioned the feature itself. 4 KB costs nothing, the key that matters stays in the old format, and fips204 0.5 already rejects malformed keys. The cost is permanent: a second reader, a second fixture, a second layout in the docs. The owner has decided to go ahead. This argues for the variant with the smallest lasting footprint, which is two seeds.

### What stays simple

- **One reader with one branch.** Bytes 0–70 stay identical in both versions, so header, KDF, salt and nonce parsing, and the part `inspect` reads, are shared. `read_with` picks the expected ciphertext length and the payload decoder by header version, still checks the length before asking for the password, and decodes with either the existing version 1 code, which stays frozen, or a new version 2 decoder. That's an estimated 15–60 lines.
- **The header is still unauthenticated, and that's acceptable.** Because the version decides the payload length, relabelling a version 1 file as version 2, or the reverse, fails before the password prompt. This needs a test in both directions.
- **Memory wiping gets slightly better.** Version 2 hands ξ to `fips204` by reference, so the documented caveat that fips204 receives an unwipeable copy of the secret key applies to version 1 files only.
- **Performance doesn't change noticeably.** One ML-DSA key generation per signature costs about 125 µs, against about 0.4 s for Argon2id.

## Goals vs. Non-Goals

* **In-Scope Goals:**
  * A new secret key format, version 2, that stores the Ed25519 private key and the ML-DSA seed ξ, for a 151-byte file.
  * `generate` always writes version 2. No option writes version 1.
  * Version 1 files keep working for signing, for good, guarded by committed fixtures made with pqsign 0.3.1.
  * The version 1 encoder stays in the code, internal only. It lets an existing version 1 key be re-encrypted later, for example with a new password, without losing its fingerprint. `generate` never uses it.
  * The key ID is derived from the seeds and checked against the header for version 2 only.
  * `inspect` shows a secret key file's format version.
  * Clearer version errors that name the file type, for all file types.
* **Out-of-Scope Non-Goals:**
  * Converting existing keys. This is impossible, because an expanded key doesn't contain its seed.
  * Smaller public keys or signatures. Their size is set by ML-DSA-65.
  * Key rotation tooling, a password-change command, import or export of keys in RFC 10073 form.
  * Changing the KDF or the AEAD, including authenticating the header as associated data.
  * Dropping support for version 1 secret keys.

## Alternatives Weighed

* **One 32-byte master seed, 119 bytes.** Rejected by author, following all review lenses: it saves 32 bytes, but it adds a pqsign-specific derivation that needs its own specification and test vectors. It makes the hybrid guarantee depend on that derivation being one-way, and it can't represent a key imported from RFC 10073. Reconsider it if a single-value backup becomes a goal.
* **Two seeds with the key ID kept in the payload, 159 bytes.** Rejected: the derived-fingerprint check makes the copy redundant and checks more.
* **A fixed nonce instead of the 24-byte random nonce.** Rejected by the author: a repeated salt under the same password would then be catastrophic, a future password-change command could reuse a salt, and a fixed nonce would move the offsets that both formats share.
* **A breaking change that drops version 1 secret keys.** Rejected by the author: it would force the release key to be rotated and its published fingerprint replaced, and versions 0.1 to 0.3.1 on crates.io and Homebrew may have users the author doesn't know about.
* **Writing version 1 on request, like `sign --format v1`.** Rejected by the author as overly cautious: an older pqsign failing on a new key file is acceptable, since it can be updated.
* **Authenticating the 71-byte prefix as AEAD associated data.** Not adopted: it would change the encryption calls, which is out of scope, and would make header tampering show up as "wrong password". The derived-key-ID check covers most of what it would add.

## Key Decisions & Staging for Next Steps

Decided during ideation:

1. Old secret keys keep working for signing; there is no breaking change.
2. New keys always use the new format; there is no option to write the old one.
3. Older pqsign versions may fail on new key files; users can update.
4. Keep the random 24-byte nonce.
5. Public keys, fingerprints, key IDs and signatures do not change.
6. The payload is two seeds, the Ed25519 private key and the ML-DSA seed ξ, not a master seed.
7. The version 1 encoder stays, internal only, so version 1 keys can be re-encrypted later.

Proposed by the review, for the author to confirm in `/egm-draft`:

1. **No key ID in the version 2 payload**, replaced by the derived-fingerprint check for version 2 only, with its own error message. That gives the 151-byte file.
2. **Payload order:** ML-DSA seed first, as in RFC 10073, or Ed25519 first, as in the rest of pqsign. The payload is encrypted and read by pqsign only.
3. **Where the seeds live** in the domain model, and how the public write functions change: one that writes version 2 from a freshly generated key, and the kept version 1 encoder for keys loaded from version 1 files.
4. **Error and `inspect` wording**, and the rule to always say "secret key format" or "signature format".
5. **Test plan:**
   - commit version 1 fixtures from pqsign 0.3.1, one with a fingerprint-based key ID and one with a random key ID, before changing the writer
   - a version 2 golden fixture with its exact length
   - known-answer tests from ξ to the public key, from Wycheproof's `mldsa_65_sign_seed_test.json`
   - relabelling tests in both directions
   - a test that version 2 rejects trailing bytes
6. **Release as 0.4.0**, since 0.3.x can't read the new keys. The release notes quote 0.3.1's exact error message.
