# Cryptographic Design

This document explains the cryptographic decisions behind pqsign and why they were made.

## Why Hybrid Signatures?

Post-quantum algorithms like ML-DSA-65 are relatively new. While they have undergone extensive analysis and NIST standardization, they lack the decades of real-world scrutiny that Ed25519 has. Conversely, Ed25519 is well-understood today but will be broken by a sufficiently large quantum computer running Shor's algorithm.

A hybrid scheme provides a simple guarantee: **if either algorithm remains secure, your signatures remain secure.** A quantum computer that breaks Ed25519 still has to break ML-DSA-65, and a classical attack on the younger ML-DSA-65, or a flaw in its implementation, still has to get past Ed25519.

## Algorithm Choices

### Ed25519

The classical component. Chosen for:

- Small signatures (64 bytes) and keys (32 bytes)
- Fast signing and verification
- Mature, widely used implementation (`ed25519-dalek`); see [Implementation Status](#implementation-status) for its review history
- Deterministic signing (no nonce reuse risk)

### ML-DSA-65 (FIPS 204)

The post-quantum component. Chosen for:

- NIST standardized (FIPS 204, finalized 2024) — the successor to the CRYSTALS-Dilithium candidate
- Security level 3 (roughly equivalent to AES-192) — a pragmatic middle ground between ML-DSA-44 (level 2) and ML-DSA-87 (level 5)
- Lattice-based, well-studied problem (Module-LWE/Module-SIS)
- Larger signatures (3309 bytes) and keys (1952-byte public key, 4032-byte secret key), but acceptable for file signing where signatures are stored on disk

We chose level 3 over level 5 because the size/performance tradeoff is significant (ML-DSA-87 signatures are 4627 bytes) and level 3 already provides a substantial security margin.

### BLAKE2b-512

Used to prehash files before signing. Chosen over SHA-512 for:

- Faster in software (no hardware acceleration needed)
- 512-bit output avoids any collision concerns
- Streaming interface allows signing files of arbitrary size without loading them into memory

## Signature Construction

Since pqsign 0.2, signatures use format v2. Both algorithms sign one **record** that holds everything the signature asserts, and the two signatures are **nested**:

```
file_hash   = BLAKE2b-512(file_contents)
record      = 0x02 || suite || key_id || signer_fingerprint || file_hash || len(comment) || comment
ed25519_sig = Ed25519.Sign(ed25519_sk, "pqsign-v2-ed25519" || record)
mldsa65_sig = ML-DSA-65.Sign(mldsa65_sk, record || ed25519_sig, ctx="pqsign-v2-mldsa65")
```

`suite` is `0x01` for Ed25519 + ML-DSA-65 over BLAKE2b-512, `key_id` is 8 bytes, `signer_fingerprint` is the 32-byte fingerprint of the signing key, and `len(comment)` is a little-endian u64. Every field but the comment has a fixed length, and the comment is length-prefixed, so the record is unambiguous.

Each algorithm signs the whole record on its own, so the file, the comment, the key ID and the signer stay protected even if one algorithm is broken or a verifier only checks one of them.

### Format v1

pqsign 0.1 wrote format v1, which pqsign still verifies and writes on request with `sign --format v1`, for verifiers older than 0.2:

```
ed25519_sig = Ed25519.Sign(ed25519_sk, "pqsign-ed25519" || file_hash || trusted_comment)
mldsa65_sig = ML-DSA-65.Sign(mldsa65_sk, file_hash || ed25519_sig, ctx="pqsign-mldsa65")
```

In v1, neither algorithm signs the key ID, and ML-DSA-65 covers the comment only through the Ed25519 signature bytes. A full verification still binds the comment, because changing it breaks the Ed25519 check, and defeating that even with Ed25519 broken would take a second preimage in SHA-512. But a verifier that checks only ML-DSA-65 would accept a changed comment, and the key ID can be changed freely.

### Why Nesting?

If the two signatures were independent (both signing just the file hash), an attacker who breaks one algorithm could replace that signature component while keeping the other. With nesting, ML-DSA-65 signs over the Ed25519 signature, creating an interdependency. Replacing the Ed25519 signature invalidates the ML-DSA-65 signature, and vice versa.

### Why Not Sign the Same Message?

An alternative would be to have both algorithms sign the identical message. The nesting approach has a specific advantage: the ML-DSA-65 signature commits to the exact Ed25519 signature bytes, which means any modification to the Ed25519 component (even a valid re-signature) is detected.

### Domain Separation

Each algorithm uses a distinct context to prevent cross-protocol attacks, and each format its own, so no message of one format is valid in the other:

- Ed25519 prepends `"pqsign-v2-ed25519"` (v1: `"pqsign-ed25519"`) to the signed message
- ML-DSA-65 uses `"pqsign-v2-mldsa65"` (v1: `"pqsign-mldsa65"`) as the context parameter (per FIPS 204 context string mechanism)

Note: Ed25519 context is prepended manually to the message rather than using RFC 8032's Ed25519ctx mechanism. Ed25519ctx (`dom2(0, context)` on the raw message) is not exposed by `ed25519-dalek` — the library only offers Ed25519ph (`dom2(1, context)` on a SHA-512 prehash), which is a different algorithm. Using Ed25519ph would double-hash our BLAKE2b output through SHA-512 for no security benefit. Manual prepending with plain Ed25519 achieves the same domain separation goal without altering the underlying signature construction.

### Trusted Comment Binding

The trusted comment (timestamp, filename, user-provided text) is part of the record both algorithms sign, so modifying it invalidates both signatures. In v1 it is part of the Ed25519 message only, and bound to ML-DSA-65 through the Ed25519 signature.

The comment is `timestamp:<unix time>\tfile:<file name>`, followed by a tab and the text given with `-t`. The file name is the base name only, so a signature does not reveal the directory it was signed in.

A trusted comment is at most 1024 bytes and may not contain control characters other than tab, or Unicode bidirectional overrides and isolates. Such characters could move the cursor, erase or recolor terminal output, or make text read differently than it is: `invoice\u{202e}fdp.exe` displays as `invoiceexe.pdf`. `sign` refuses a `-t` text that breaks these rules before asking for the password, and escapes them in file names, for example as `\t` or `\u{202e}`. Signature files whose comment breaks them are rejected by `verify` and `inspect`, so a comment can never reach the terminal raw. Like minisign, pqsign rejects rather than escapes on read; the addition is the bidirectional characters.

`inspect` does not check signatures, so it labels the comment as unverified. Only the comment printed by `verify` after a successful verification is trusted.

## Key IDs and Fingerprints

Every key file and signature carries an 8-byte **key ID**, so a signature can be matched with the key that made it. Since pqsign 0.2, a new key's ID is the first 8 bytes of its fingerprint; keys generated with 0.1 have random IDs and keep working. A key ID locates a key but does not identify it: 64 bits are too few to rule out another key with the same ID. In v2 signatures both algorithms sign the key ID; in v1 signatures neither does.

v2 signatures also carry the signer's fingerprint, which both algorithms sign. `inspect` shows it as the claimed signer, and `verify` checks it first, so a signature checked against the wrong key fails with a message that names both keys.

A key's **fingerprint** identifies it:

```
fingerprint = BLAKE2b-256("pqsign fingerprint: Ed25519 + ML-DSA-65" || ed25519_public_key || mldsa65_public_key)
```

Both public keys have a fixed length, so the concatenation is unambiguous. The key ID is not part of the input, so changing a file's key ID never changes its fingerprint. Fingerprints are shown as `BLAKE2b-256:` followed by unpadded base64, in the style of ssh's `SHA256:` fingerprints, by `generate`, by `inspect` on a public key, and by `verify`. `inspect` cannot show it for a secret key file, because the public key material there is encrypted.

## Key Encryption

Secret keys are always encrypted at rest.

### Key Derivation: Argon2id

Password-based key derivation uses Argon2id (RFC 9106) with:

- **256 MiB memory** — makes GPU/ASIC attacks expensive
- **3 iterations** — additional time hardening
- **1 lane of parallelism** — conservative choice
- **16-byte random salt** — unique per key

Argon2id was chosen over scrypt or bcrypt for its resistance to both time-memory tradeoff attacks (Argon2d property) and side-channel attacks (Argon2i property).

The parameters are stored in the key file. When reading it, pqsign checks them before asking for the password: at most 1 GiB of memory and 16 iterations, memory in whole KiB, and nothing Argon2id itself rejects. The upper limits keep a corrupt or tampered file from tying pqsign up for hours or exhausting memory; they cover libsodium's SENSITIVE preset (1 GiB, 4 iterations). Tampering cannot weaken a key: different parameters derive a different key, and decryption fails.

### Encryption: XChaCha20-Poly1305

The derived 256-bit key encrypts the secret key material using XChaCha20-Poly1305 (AEAD) with:

- **24-byte random nonce** — XChaCha20's extended nonce eliminates nonce reuse concerns
- **Poly1305 authentication tag** — detects tampering and wrong passwords

XChaCha20-Poly1305 was chosen over AES-GCM for its nonce safety (24 bytes vs 12 bytes) and consistent software performance without requiring AES-NI hardware.

### What Gets Encrypted

The encrypted payload contains:

```
ed25519_secret_key  (32 bytes)
mldsa65_secret_key  (4032 bytes)
key_id              (8 bytes)
```

That is 4072 bytes, or 4088 bytes encrypted with the 16-byte Poly1305 tag. pqsign checks this length before asking for the password, so a truncated key file is reported as corrupt rather than as a wrong password.

The key ID is duplicated inside the encrypted payload and in the plaintext header. On decryption, these are cross-checked to detect file corruption.

## Memory Safety

Secret material is wiped from memory as soon as it is no longer needed:

- `SecretKey` implements `ZeroizeOnDrop`, and so do the Ed25519 and ML-DSA-65 key types inside it.
- The byte wrappers for secret keys used while reading and writing key files wipe themselves on drop, print as `[REDACTED]`, and cannot be cloned or compared.
- Key generation seeds, passwords, the serialized and the decrypted key payload are held in zeroizing buffers.
- The key derived by Argon2id and the cipher's copy of it are wiped on drop.
- Argon2id's initial hash and its 256 MiB of working memory are wiped after every key derivation.

This shortens how long secrets linger; it does not guarantee that no copy remains. Rust moves values on the stack without wiping the old location, and the cryptographic libraries make internal copies; `fips204`, for example, takes the secret key bytes by value. Memory may also reach swap or a core dump while pqsign runs; pqsign does not lock memory or disable core dumps.

- Secret key files are written with Unix permissions `0600`, also when `--overwrite` replaces an existing file, and directories pqsign creates get `0700`. On Windows, files inherit the permissions of their directory; the default key directory lies inside the user profile.
- Key files are written atomically: a temporary file in the same directory is synced and then renamed into place, so an interrupted write never destroys an existing key. `generate` places the public key first and the secret key last.
- `sign` warns when the secret key file is accessible by other users.

## File Format

All binary files share a common header:

```
Offset  Size  Field
0       4     Magic: "PQSN"
4       1     Format version: 1 for key files, 2 for signatures (1 for signatures before pqsign 0.2)
5       1     File type: 0x01=PublicKey, 0x02=SecretKey, 0x03=Signature
6       8     Key ID
```

Each file type has its own version, so a new signature format does not relabel key files. Readers reject version 0 and versions newer than they support for that file type, with a message naming the version required.

A v2 signature file continues with:

```
Offset  Size  Field
14      1     Algorithm suite: 0x01 = Ed25519 + ML-DSA-65 over BLAKE2b-512
15      32    Signer fingerprint
47      64    Ed25519 signature
111     3309  ML-DSA-65 signature
3420    4     Comment length (u32, little-endian, at most 1024)
3424    n     Trusted comment (UTF-8)
```

A v1 signature file has no suite and fingerprint: the Ed25519 signature follows the header directly. Nothing may follow the comment in a v2 file.

Public keys use a text format (`pqsign:v1:<base64>`) for easy sharing in text-based channels. The base64 payload contains the same binary header followed by the raw key bytes. The version in the prefix must match the format version byte in that header, which is authoritative; pqsign rejects public keys where the two differ.

## Implementation Status

pqsign itself has not been independently audited. It relies on these crates for its cryptography:

| Purpose | Crate | Version | Review status |
|---|---|---|---|
| ML-DSA-65 | [`fips204`](https://github.com/integritychain/fips204) | 0.4.6 | No published audit. Its maintainers call it experimental, with constant-time behavior targeted at the source-code level only. |
| Ed25519 | [`ed25519-dalek`](https://github.com/dalek-cryptography/curve25519-dalek), `curve25519-dalek` | 3.0, 5.0 | [Quarkslab reviewed](https://blog.quarkslab.com/security-audit-of-dalek-libraries.html) `curve25519-dalek` in 2019 and looked briefly at `ed25519-dalek`; both have had major releases since. A timing issue in `curve25519-dalek` was found in 2024 and fixed ([RUSTSEC-2024-0344](https://rustsec.org/advisories/RUSTSEC-2024-0344.html)). |
| Key encryption | [`chacha20poly1305`](https://github.com/RustCrypto/AEADs) | 0.11 | [NCC Group reviewed](https://www.nccgroup.com/research/public-report-rustcrypto-aesgcm-and-chacha20pluspoly1305-implementation-review/) the late-2019 implementation in 2020. |
| Key derivation | [`argon2`](https://github.com/RustCrypto/password-hashes) | 0.6 | No published audit found. |
| File hash, fingerprints | [`blake2`](https://github.com/RustCrypto/hashes) | 0.11 | No published audit found. |

No ML-DSA implementation in Rust is both audited and stable yet. RustCrypto's [`ml-dsa`](https://github.com/RustCrypto/signatures/tree/master/ml-dsa) has never been independently audited, and [`libcrux-ml-dsa`](https://github.com/cryspen/libcrux) is partly formally verified but still pre-release, with a 2026 advisory for accepting invalid signatures ([RUSTSEC-2026-0077](https://rustsec.org/advisories/RUSTSEC-2026-0077.html)).

This is what the hybrid design is for. A signature is accepted only when both the Ed25519 and the ML-DSA-65 signature verify, so a flaw in the young ML-DSA implementation does not on its own let anyone forge a signature, and neither does a flaw in Ed25519.

Vulnerabilities are reported as described in [SECURITY.md](../SECURITY.md).

## Known Limitations

- **One algorithm suite** — v2 signatures name their algorithm suite, so a future version can add another, but only Ed25519 + ML-DSA-65 exists today and there is no negotiation.
- **No streaming signatures** — the file is hashed in a single pass, but the hash must complete before signing begins. This is inherent to the prehash approach.
- **BLAKE2b-512 is not post-quantum as a hash** — however, Grover's algorithm only halves the effective security of hash functions, leaving BLAKE2b-512 at 256-bit post-quantum security, which is more than sufficient.
