# Cryptographic Design

This document explains the cryptographic decisions behind pqsign and why they were made.

## Why Hybrid Signatures?

Post-quantum algorithms like ML-DSA-65 are relatively new. While they have undergone extensive analysis and NIST standardization, they lack the decades of real-world scrutiny that Ed25519 has. Conversely, Ed25519 is well-understood today but will be broken by a sufficiently large quantum computer running Shor's algorithm.

A hybrid scheme provides a simple guarantee: **if either algorithm remains secure, your signatures remain secure.** This protects against both classical attacks (where ML-DSA-65 holds) and quantum attacks (where ML-DSA-65 holds while Ed25519 falls).

## Algorithm Choices

### Ed25519

The classical component. Chosen for:

- Small signatures (64 bytes) and keys (32 bytes)
- Fast signing and verification
- Mature, widely audited implementations (`ed25519-dalek`)
- Deterministic signing (no nonce reuse risk)

### ML-DSA-65 (FIPS 204)

The post-quantum component. Chosen for:

- NIST standardized (FIPS 204, finalized 2024) — the successor to the CRYSTALS-Dilithium candidate
- Security level 3 (roughly equivalent to AES-192) — a pragmatic middle ground between ML-DSA-44 (level 2) and ML-DSA-87 (level 5)
- Lattice-based, well-studied problem (Module-LWE/Module-SIS)
- Larger signatures (3309 bytes) and keys (1952/2560 bytes), but acceptable for file signing where signatures are stored on disk

We chose level 3 over level 5 because the size/performance tradeoff is significant (ML-DSA-87 signatures are 4627 bytes) and level 3 already provides a substantial security margin.

### BLAKE2b-512

Used to prehash files before signing. Chosen over SHA-512 for:

- Faster in software (no hardware acceleration needed)
- 512-bit output avoids any collision concerns
- Streaming interface allows signing files of arbitrary size without loading them into memory

## Signature Construction

The two signatures are not independent — they are **nested**:

```
file_hash     = BLAKE2b-512(file_contents)
ed25519_sig   = Ed25519.Sign(ed25519_sk, "pqsign-ed25519" || file_hash || trusted_comment)
mldsa65_sig   = ML-DSA-65.Sign(mldsa65_sk, file_hash || ed25519_sig, ctx="pqsign-mldsa65")
```

### Why Nesting?

If the two signatures were independent (both signing just the file hash), an attacker who breaks one algorithm could replace that signature component while keeping the other. With nesting, ML-DSA-65 signs over the Ed25519 signature, creating an interdependency. Replacing the Ed25519 signature invalidates the ML-DSA-65 signature, and vice versa.

### Why Not Sign the Same Message?

An alternative would be to have both algorithms sign the identical message. The nesting approach has a specific advantage: the ML-DSA-65 signature commits to the exact Ed25519 signature bytes, which means any modification to the Ed25519 component (even a valid re-signature) is detected.

### Domain Separation

Each algorithm uses a distinct context to prevent cross-protocol attacks:

- Ed25519 prepends `"pqsign-ed25519"` to the signed message
- ML-DSA-65 uses `"pqsign-mldsa65"` as the context parameter (per FIPS 204 context string mechanism)

Note: Ed25519 context is prepended manually to the message rather than using RFC 8032's Ed25519ctx mechanism. Ed25519ctx (`dom2(0, context)` on the raw message) is not exposed by `ed25519-dalek` — the library only offers Ed25519ph (`dom2(1, context)` on a SHA-512 prehash), which is a different algorithm. Using Ed25519ph would double-hash our BLAKE2b output through SHA-512 for no security benefit. Manual prepending with plain Ed25519 achieves the same domain separation goal without altering the underlying signature construction.

### Trusted Comment Binding

The trusted comment (timestamp, filename, user-provided text) is included in the Ed25519 signed message. Since ML-DSA-65 signs over the Ed25519 signature, the comment is transitively bound to both signatures. Modifying the comment invalidates the Ed25519 signature, which in turn invalidates the ML-DSA-65 signature.

## Key Encryption

Secret keys are always encrypted at rest.

### Key Derivation: Argon2id

Password-based key derivation uses Argon2id (RFC 9106) with:

- **256 MiB memory** — makes GPU/ASIC attacks expensive
- **3 iterations** — additional time hardening
- **1 lane of parallelism** — conservative choice
- **16-byte random salt** — unique per key

Argon2id was chosen over scrypt or bcrypt for its resistance to both time-memory tradeoff attacks (Argon2d property) and side-channel attacks (Argon2i property).

### Encryption: XChaCha20-Poly1305

The derived 256-bit key encrypts the secret key material using XChaCha20-Poly1305 (AEAD) with:

- **24-byte random nonce** — XChaCha20's extended nonce eliminates nonce reuse concerns
- **Poly1305 authentication tag** — detects tampering and wrong passwords

XChaCha20-Poly1305 was chosen over AES-GCM for its nonce safety (24 bytes vs 12 bytes) and consistent software performance without requiring AES-NI hardware.

### What Gets Encrypted

The encrypted payload contains:

```
ed25519_secret_key  (32 bytes)
mldsa65_secret_key  (2544 bytes)
key_id              (8 bytes)
```

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
4       1     Format version (currently 1)
5       1     File type: 0x01=PublicKey, 0x02=SecretKey, 0x03=Signature
6       8     Key ID (random, for cross-referencing)
```

The version byte allows future format changes without breaking existing files. Readers reject versions higher than what they support.

Public keys use a text format (`pqsign:v1:<base64>`) for easy sharing in text-based channels. The base64 payload contains the same binary header followed by the raw key bytes.

## Known Limitations

- **No algorithm agility in signatures** — the algorithm pair is fixed. A future version could add a negotiation mechanism, but for now simplicity is preferred over flexibility.
- **No streaming signatures** — the file is hashed in a single pass, but the hash must complete before signing begins. This is inherent to the prehash approach.
- **BLAKE2b-512 is not post-quantum as a hash** — however, Grover's algorithm only halves the effective security of hash functions, leaving BLAKE2b-512 at 256-bit post-quantum security, which is more than sufficient.
