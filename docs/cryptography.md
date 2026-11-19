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
- Larger signatures (3309 bytes) and keys (1952-byte public key, 4032-byte secret key, stored as its 32-byte seed since pqsign 0.4), but acceptable for file signing where signatures are stored on disk

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

### Signature format v1

pqsign 0.1 wrote signature format v1, which pqsign still verifies and writes on request with `sign --format v1`, for verifiers older than 0.2:

```
ed25519_sig = Ed25519.Sign(ed25519_sk, "pqsign-ed25519" || file_hash || trusted_comment)
mldsa65_sig = ML-DSA-65.Sign(mldsa65_sk, file_hash || ed25519_sig, ctx="pqsign-mldsa65")
```

In signature format v1, neither algorithm signs the key ID, and ML-DSA-65 covers the comment only through the Ed25519 signature bytes. A full verification still binds the comment, because changing it breaks the Ed25519 check, and defeating that even with Ed25519 broken would take a second preimage in SHA-512. But a verifier that checks only ML-DSA-65 would accept a changed comment, and the key ID can be changed freely: someone can copy another key's ID into their own public key and v1 signature, and the signature still verifies. `verify` notes this after a v1 signature checks out, and `inspect` marks a v1 key ID as not signed.

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

The trusted comment (timestamp, filename, user-provided text) is part of the record both algorithms sign, so modifying it invalidates both signatures. In signature format v1 it is part of the Ed25519 message only, and bound to ML-DSA-65 through the Ed25519 signature.

The comment is `timestamp:<unix time>\tfile:<file name>`, followed by a tab and the text given with `-t`. The file name is the base name only, so a signature does not reveal the directory it was signed in.

A trusted comment is at most 1024 bytes and may not contain control characters other than tab, or Unicode bidirectional overrides and isolates. Such characters could move the cursor, erase or recolor terminal output, or make text read differently than it is: `invoice\u{202e}fdp.exe` displays as `invoiceexe.pdf`. `sign` refuses a `-t` text that breaks these rules before asking for the password, and escapes them in file names, for example as `\t` or `\u{202e}`. Signature files whose comment breaks them are rejected by `verify` and `inspect`, so a comment can never reach the terminal raw. Like minisign, pqsign rejects rather than escapes on read; the addition is the bidirectional characters. Paths that pqsign prints, in its status lines, warnings and error messages, are escaped the same way, so a hostile file name cannot reach the terminal raw either.

`inspect` does not check signatures, so it labels the comment as unverified. Only the comment printed by `verify` after a successful verification is trusted.

## Key IDs and Fingerprints

Every key file and signature carries an 8-byte **key ID**, so a signature can be matched with the key that made it. Since pqsign 0.2, a new key's ID is the first 8 bytes of its fingerprint; keys generated with 0.1 have random IDs and keep working. A key ID locates a key but does not identify it: 64 bits are too few to rule out another key with the same ID. In signature format v2 both algorithms sign the key ID; in signature format v1 neither does.

Signature format v2 files also carry the signer's fingerprint, which both algorithms sign. `inspect` shows it as the claimed signer, and `verify` checks it first, so a signature checked against the wrong key fails with a message that names both keys.

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

Since pqsign 0.4, secret keys are written in secret key format v2. Its encrypted payload holds the two 32-byte values the key pair is generated from:

```
ed25519_private_key  (32 bytes)   the RFC 8032 private key, itself a seed
mldsa65_seed         (32 bytes)   ξ, the input to FIPS 204 ML-DSA.KeyGen_internal
```

That is 64 bytes, or 80 bytes encrypted with the 16-byte Poly1305 tag. On every load, pqsign rebuilds both keys from the seeds with the standard key generation of each algorithm. The Ed25519 private key comes first, as in every other pqsign structure.

The payload holds no key ID. After decryption, the start of the rebuilt keys' fingerprint must equal the key ID in the plaintext header, which for secret key format v2 is always the fingerprint prefix. This catches a damaged or changed header, and also a pqsign build whose dependencies would turn the same seed into a different key. That derivation is part of the format and must never change. Known-answer tests pin it: RFC 8032's Ed25519 vectors and Wycheproof's seeded ML-DSA-65 vectors.

pqsign checks the payload length for the file's format version before asking for the password. A truncated, padded or relabelled key file is therefore reported as corrupt rather than as a wrong password.

A secret key file of 151 bytes is small enough to back up as text, for example with `base64`, in a QR code or a single password-manager field. A restore mistake can show up as a format error, as a corrupt file, as the key-ID mismatch error, or as `wrong password`, because the AEAD can't tell a damaged file from a wrong password. The reliable check is to sign a test file and verify the signature against the key's `.pub` file; `pqsign inspect` only confirms the file type and the format version.

#### Secret key format v1 (pqsign 0.1 to 0.3)

pqsign 0.1 to 0.3 wrote secret key format v1, which pqsign still reads and no longer writes. An expanded key doesn't contain the seed it was made from, so a format v1 key can't be converted; it stays in that format until its owner generates a new key. Its encrypted payload contains:

```
ed25519_secret_key  (32 bytes)
mldsa65_secret_key  (4032 bytes)
key_id              (8 bytes)
```

That is 4072 bytes, or 4088 bytes encrypted with the 16-byte Poly1305 tag. The key ID is duplicated inside the encrypted payload and in the plaintext header. On decryption, these are cross-checked to detect file corruption.

## Memory Safety

Secret material is wiped from memory as soon as it is no longer needed:

- `SecretKey` implements `ZeroizeOnDrop`, and so do the Ed25519 and ML-DSA-65 key types inside it, and `SecretSeeds` and `MlDsa65Seed`, which hold the seeds a key is generated from.
- The byte wrappers for secret keys used while reading and writing key files wipe themselves on drop, print as `[REDACTED]`, and cannot be cloned or compared.
- Passwords, the serialized secret key format v2 payload and the decrypted key payload are held in zeroizing buffers. Key generation seeds go straight into `SecretSeeds` and `MlDsa65Seed`, with no intermediate buffer.
- The key derived by Argon2id and the cipher's copy of it are wiped on drop.
- Argon2id's initial hash and its 256 MiB of working memory are wiped after every key derivation.

This shortens how long secrets linger; it does not guarantee that no copy remains. Rust moves values on the stack without wiping the old location, and the cryptographic libraries make internal copies; `fips204`, for example, takes the secret key bytes by value when a secret key format v1 key is loaded. A secret key format v2 key hands it only a reference to the seed. Memory may also reach swap or a core dump while pqsign runs; pqsign does not lock memory or disable core dumps.

- Secret key files are written with Unix permissions `0600`, whatever the umask and also when `--overwrite` replaces an existing file, and directories `generate` creates get `0700`. On Windows, files inherit the permissions of their directory; the default key directory lies inside the user profile.
- Key files and signatures are written atomically: a temporary file in the same directory is synced and then renamed into place, so an interrupted write never destroys an existing key or leaves a truncated signature. `generate` places the public key first and the secret key last.
- `sign` refuses a signature path that names the file being signed, its secret key or that key's `.pub` file, also through a symlink and, on Unix, a hard link, before asking for the password.
- `sign` warns when the secret key file is accessible by other users. `sign` and `generate` warn when a `--password-file` is accessible by other users, and when other users can write to the directory that holds the secret key and so replace it; a sticky directory such as `/tmp` does not let them, so it does not count. Only that directory is checked, not its parents.

## File Format

All binary files share a common header:

```
Offset  Size  Field
0       4     Magic: "PQSN"
4       1     Format version: 1 for public keys, 2 for secret keys (1 before pqsign 0.4), 2 for signatures (1 before pqsign 0.2)
5       1     File type: 0x01=PublicKey, 0x02=SecretKey, 0x03=Signature
6       8     Key ID
```

Each file type has its own version, so a new signature or secret key format does not relabel the other files. Readers reject version 0 and versions newer than they support for that file type, with a message naming the file type and the version required.

A signature format v2 file continues with:

```
Offset  Size  Field
14      1     Algorithm suite: 0x01 = Ed25519 + ML-DSA-65 over BLAKE2b-512
15      32    Signer fingerprint
47      64    Ed25519 signature
111     3309  ML-DSA-65 signature
3420    4     Comment length (u32, little-endian, at most 1024)
3424    n     Trusted comment (UTF-8)
```

A signature format v1 file has no suite and fingerprint: the Ed25519 signature follows the header directly. Nothing may follow the comment in a signature format v2 file.

A secret key file in format v2 continues with:

```
Offset  Size  Field
14      1     KDF: 0x02 = Argon2id
15      8     Argon2id memory in bytes (u64, little-endian)
23      8     Argon2id iterations (u64, little-endian)
31      16    Argon2id salt
47      24    XChaCha20-Poly1305 nonce
71      80    Encrypted payload and Poly1305 tag
```

A secret key file in format v2 is 151 bytes. A secret key file in format v1, written by pqsign 0.1 to 0.3, has version 1 in its header and continues with:

```
Offset  Size  Field
14      1     KDF: 0x02 = Argon2id
15      8     Argon2id memory in bytes (u64, little-endian)
23      8     Argon2id iterations (u64, little-endian)
31      16    Argon2id salt
47      24    XChaCha20-Poly1305 nonce
71      4088  Encrypted payload and Poly1305 tag
```

A secret key file in format v1 is 4159 bytes. Secret key files in both formats reject trailing bytes.

The KDF byte follows libsodium's numbering, in which 0x01 is Argon2i and 0x02 is Argon2id. pqsign only uses Argon2id and rejects every other value, 0x01 included.

Public keys use a text format (`pqsign:v1:<base64>`) for easy sharing in text-based channels. The base64 payload contains the same binary header followed by the raw key bytes. The version in the prefix must match the format version byte in that header, which is authoritative; pqsign rejects public keys where the two differ.

## Relation to Standards

pqsign's format predates the IETF's standards for hybrid post-quantum signatures, and it follows none of them byte for byte. Three documents from 2026 cover the same ground:

- [RFC 10073](https://www.rfc-editor.org/rfc/rfc10073), Composite ML-DSA (Standards Track, November 2026), defines composite signature algorithms for X.509. One of them, `id-MLDSA65-Ed25519-SHA512`, combines the same two algorithms as pqsign.
- [RFC 9980](https://www.rfc-editor.org/rfc/rfc9980), Post-Quantum Cryptography in OpenPGP (Standards Track, June 2026), makes ML-DSA-65+Ed25519 the signature algorithm every implementation must support.
- [RFC 9955](https://www.rfc-editor.org/rfc/rfc9955), Hybrid Signature Spectrums (Informational, July 2026), defines no algorithm. It gives the vocabulary for comparing hybrid signatures, used below.

### Construction compared

| | pqsign (signature format v2, secret key format v2) | RFC 10073, ML-DSA-65 + Ed25519 | RFC 9980, ML-DSA-65+Ed25519 |
|---|---|---|---|
| How the two signatures relate | Nested: ML-DSA-65 also signs the Ed25519 signature | Parallel: both sign the same message representative `M'` | Parallel: both sign the same OpenPGP signature digest |
| What is hashed | The file, with BLAKE2b-512; the hash goes into the record | The message, with SHA-512, inside `M'` | The OpenPGP signature data, with a hash of at least 256 bits |
| Ed25519 signs | `"pqsign-v2-ed25519" \|\| record` | `M'`, which starts with the prefix `"CompositeAlgorithmSignatures2025"` | The digest; the EdDSA context is empty |
| ML-DSA-65 signs | `record \|\| ed25519_sig`, context `"pqsign-v2-mldsa65"` | `M'`, context `"COMPSIG-MLDSA65-Ed25519-SHA512"` | The digest; the context is empty |
| ML-DSA variant | Pure ML-DSA, hedged | Pure ML-DSA | Pure ML-DSA, hedged |
| ML-DSA secret key stored as | The 32-byte seed (secret key format v1: the expanded key, 4032 bytes) | The 32-byte seed | The 32-byte seed |
| Component order in keys and signatures | Ed25519 first, also in the secret key payload | ML-DSA first | Ed25519 first |

All three accept a signature only if both components verify, and all three sign a message that holds a hash rather than the raw data. What a signature asserts besides the data is up to the application in RFC 10073; pqsign's record makes both algorithms sign the key ID, the signer's fingerprint and the trusted comment, and RFC 9980 covers its metadata through the OpenPGP signature packet.

### Non-separability

RFC 9955 describes how hard it is to turn a hybrid signature back into a signature of one algorithm alone:

- **Weak non-separability**: an attacker cannot remove one component signature without leaving evidence behind, in the message, the signature or the protocol.
- **Strong non-separability**: an attacker cannot take a hybrid signature and its message and produce a valid signature of one component at all.

RFC 9955 notes that a nested construction, where the second algorithm signs the message together with the first signature, can reach weak non-separability, depending on whether the inner or the outer signature is stripped.

pqsign has weak non-separability for both components. If the ML-DSA-65 signature is removed, the Ed25519 signature that remains signs a message starting with `"pqsign-v2-ed25519"` and holding a pqsign record. If the Ed25519 signature is removed, the ML-DSA-65 signature that remains signs a message that contains the Ed25519 signature, under the context `"pqsign-v2-mldsa65"`. pqsign does not have strong non-separability: anyone holding a signature can extract a valid ML-DSA-65 signature over `record || ed25519_sig` with pqsign's context. RFC 10073 claims weak non-separability for both of its components and only a limited form of the strong property for the ML-DSA component, relying on its fixed prefix and context in the same way. RFC 9980 instead relies on OpenPGP's signature packet, which includes the algorithm ID in the signed data.

Nesting goes one step further than both standards in one respect: ML-DSA-65 commits to the exact Ed25519 signature bytes, so even a different valid Ed25519 signature over the same record does not verify.

### Possible alignment

Secret key format v2, since pqsign 0.4, already stores ML-DSA-65 secret keys as the 32-byte seed, as FIPS 204, RFC 10073 and RFC 9980 do. One direction a future signature format version could take, not a decision:

- **Use RFC 10073's ML-DSA-65 + Ed25519 algorithm as a new signature suite**, with pqsign's record as the message. The construction would be one that reviewers recognize and that can be checked against the RFC's test vectors, at the cost of the nesting and of a new signature format.

## Implementation Status

pqsign itself has not been independently audited. It relies on these crates for its cryptography:

| Purpose | Crate | Version | Review status |
|---|---|---|---|
| ML-DSA-65 | [`fips204`](https://github.com/integritychain/fips204) | 0.5.0 | No published audit. Its maintainers state that key generation and signing are constant-time within each attempt, checked by source review and statistical timing measurements, at the source-code level only. |
| Ed25519 | [`ed25519-dalek`](https://github.com/dalek-cryptography/curve25519-dalek), `curve25519-dalek` | 3.0, 5.0 | [Quarkslab reviewed](https://blog.quarkslab.com/security-audit-of-dalek-libraries.html) `curve25519-dalek` in 2019 and looked briefly at `ed25519-dalek`; both have had major releases since. A timing issue in `curve25519-dalek` was found in 2024 and fixed ([RUSTSEC-2024-0344](https://rustsec.org/advisories/RUSTSEC-2024-0344.html)). |
| Key encryption | [`chacha20poly1305`](https://github.com/RustCrypto/AEADs) | 0.11 | [NCC Group reviewed](https://www.nccgroup.com/research/public-report-rustcrypto-aesgcm-and-chacha20pluspoly1305-implementation-review/) the late-2019 implementation in 2020. |
| Key derivation | [`argon2`](https://github.com/RustCrypto/password-hashes) | 0.6 | No published audit found. |
| File hash, fingerprints | [`blake2`](https://github.com/RustCrypto/hashes) | 0.11 | No published audit found. |

No ML-DSA implementation in Rust is both audited and stable yet. RustCrypto's [`ml-dsa`](https://github.com/RustCrypto/signatures/tree/master/ml-dsa) has never been independently audited, and [`libcrux-ml-dsa`](https://github.com/cryspen/libcrux) is partly formally verified but still pre-release, with a 2026 advisory for accepting invalid signatures ([RUSTSEC-2026-0077](https://rustsec.org/advisories/RUSTSEC-2026-0077.html)).

pqsign's tests run [Wycheproof's ML-DSA-65 vectors](../tests/vectors/wycheproof/README.md) against `fips204`. It passes all 210 verification cases, including the malformed hint encodings and norm violations that the other two crates accepted, and signs exactly as expected from the expanded secret keys of secret key format v1. Since pqsign 0.4, secret keys are stored as seeds, and Wycheproof's seeded vectors check that fips204 and pqsign rebuild the right key from each seed and sign with it as expected. `fips204` rejects every malformed secret key in the vectors; before 0.5 it accepted two whose coefficients were out of range, which pqsign never creates.

This is what the hybrid design is for. A signature is accepted only when both the Ed25519 and the ML-DSA-65 signature verify, so a flaw in the young ML-DSA implementation does not on its own let anyone forge a signature, and neither does a flaw in Ed25519.

Vulnerabilities are reported as described in [SECURITY.md](../SECURITY.md).

## Known Limitations

- **One algorithm suite** — signature format v2 files name their algorithm suite, so a future version can add another, but only Ed25519 + ML-DSA-65 exists today and there is no negotiation.
- **No streaming signatures** — the file is hashed in a single pass, but the hash must complete before signing begins. This is inherent to the prehash approach.
- **BLAKE2b-512 is not post-quantum as a hash** — however, Grover's algorithm only halves the effective security of hash functions, leaving BLAKE2b-512 at 256-bit post-quantum security, which is more than sufficient.
