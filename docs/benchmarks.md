# Benchmarks

Performance measurements for pqsign. Two benchmark suites are provided:

- **`crypto`** — Pure cryptographic operations (library API). No disk I/O for keys, no Argon2id.
- **`cli`** — End-to-end command pipeline including Argon2id key decryption, file I/O, and serialization.

All benchmarks use [Criterion.rs](https://github.com/bheisler/criterion.rs) and can be reproduced with:

```sh
cargo bench                           # run all benchmarks
cargo bench --bench crypto            # library only
cargo bench --bench crypto breakdown  # the parts of signing and verifying
cargo bench --bench cli               # end-to-end only
```

Measured on an Apple M2 with signature format v2, while other applications were running. The benchmarks are single-threaded; spot checks of `pqsign sign` runs before and after them, with `/usr/bin/time -l`, showed a performance core at 3.2–3.5 GHz. Your results will vary by hardware.

## Library (`crypto`)

These benchmarks operate on the library API directly (key generation, signing, verification). They isolate the pure cryptographic cost without Argon2id or key file I/O.

### Key Generation

| Operation | Time |
|-----------|------|
| keygen | ~164 µs |

Key generation is dominated by ML-DSA-65 key pair generation (~125 µs). The rest is Ed25519 key generation and the fingerprint (~13 µs), from which the key ID is taken.

### Signing

| File Size | Time |
|-----------|------|
| 0 B | ~501 µs |
| 1 KiB | ~527 µs |
| 1 MiB | ~1.61 ms |
| 10 MiB | ~10.8 ms |
| 100 MiB | ~105 ms |

The ~500 µs baseline is the cryptography: ML-DSA-65 signing (~379 µs), deriving the ML-DSA-65 public key for the signer fingerprint that v2 signatures carry (~117 µs), and Ed25519 signing (~12 µs). ML-DSA-65 signing uses rejection sampling, so its time varies from signature to signature. As file size grows, BLAKE2b-512 hashing dominates.

### Verification

| File Size | Time |
|-----------|------|
| 0 B | ~143 µs |
| 1 KiB | ~143 µs |
| 1 MiB | ~1.12 ms |
| 10 MiB | ~10.0 ms |
| 100 MiB | ~103 ms |

Verification is faster than signing at small file sizes (~143 µs vs ~501 µs): ML-DSA-65 verification (~92 µs) is much cheaper than signing, Ed25519 verification takes ~29 µs, and the public key's fingerprint ~13 µs. At large file sizes, both converge since BLAKE2b-512 hashing dominates.

### Breakdown

| Part | Time |
|------|------|
| ML-DSA-65 sign | ~379 µs |
| ML-DSA-65 key generation | ~125 µs |
| Fingerprint of a secret key (derives the ML-DSA-65 public key) | ~117 µs |
| ML-DSA-65 verify | ~92 µs |
| Ed25519 verify | ~29 µs |
| Fingerprint of a public key | ~13 µs |
| Ed25519 sign | ~12 µs |

Measured on a 180-byte message, about the size of a v2 signed record with a short trusted comment.

## End-to-end (`cli`)

These benchmarks run the full command pipeline: key file I/O, Argon2id key derivation (256 MiB, 3 iterations), signing/verification, and signature serialization.

### Key Generation + Encryption

| Operation | Time |
|-----------|------|
| generate | ~389 ms |

Almost entirely Argon2id (256 MiB, 3 iterations). Key generation (~164 µs) and writing both key files atomically, synced to disk, are small next to it.

### Signing (with key decryption)

| File Size | Time |
|-----------|------|
| 0 B | ~416 ms |
| 1 KiB | ~391 ms |
| 1 MiB | ~401 ms |
| 10 MiB | ~481 ms |
| 100 MiB | ~504 ms |

Argon2id dominates at all file sizes. Up to 10 MiB, the rows differ by Argon2id's run-to-run variance, about ±10% in these runs, rather than by file size: hashing 10 MiB adds only ~11 ms. Only at 100 MiB does BLAKE2b-512 hashing become visible (~105 ms on top of the Argon2id floor).

### Verification

| File Size | Time |
|-----------|------|
| 0 B | ~207 µs |
| 1 KiB | ~230 µs |
| 1 MiB | ~1.47 ms |
| 10 MiB | ~11.4 ms |
| 100 MiB | ~116 ms |

Verification does not involve Argon2id (only the public key is needed), so it is close to the library benchmark. The overhead of about 65 µs at small sizes is reading and parsing the public key and signature files.

## Observations

- **Argon2id dominates signing**: Key decryption (~380–400 ms) dwarfs everything else. The actual sign operation adds about half a millisecond for small files.
- **Verification is fast**: No password-based key derivation is needed, so verification takes about 0.2 ms for small files even end to end.
- **Hashing throughput**: BLAKE2b-512 hashes at about 1 GB/s in software, making it negligible for small files and the bottleneck for large ones.
- **ML-DSA-65 is the expensive part of the cryptography**: ML-DSA-65 signing (~379 µs) and verification (~92 µs) cost far more than Ed25519 signing (~12 µs) and verification (~29 µs). Signature format v2 adds ~117 µs per signature, because the secret key derives its public key to include the signer's fingerprint.

See also: [Brute-Force Resistance](brute-force-resistance.md) for an analysis of password cracking times based on these benchmarks.
