# Benchmarks

Performance measurements for pqsign. Two benchmark suites are provided:

- **`crypto`** — Pure cryptographic operations (library API). No disk I/O for keys, no Argon2id.
- **`cli`** — End-to-end command pipeline including Argon2id key decryption, file I/O, and serialization.

All benchmarks use [Criterion.rs](https://github.com/bheisler/criterion.rs) and can be reproduced with:

```sh
cargo bench                # run all benchmarks
cargo bench --bench crypto # library only
cargo bench --bench cli    # end-to-end only
```

Measured on an Apple M-series chip. Your results will vary by hardware.

## Library (`crypto`)

These benchmarks operate on the library API directly (key generation, signing, verification). They isolate the pure cryptographic cost without Argon2id or key file I/O.

### Key Generation

| Operation | Time |
|-----------|------|
| keygen | ~156 us |

Key generation is dominated by ML-DSA-65 key pair generation. Ed25519 key generation is negligible in comparison.

### Signing

| File Size | Time |
|-----------|------|
| 0 B | ~400 us |
| 1 KiB | ~400 us |
| 1 MiB | ~1.4 ms |
| 10 MiB | ~10.7 ms |
| 100 MiB | ~106 ms |

The ~400 us baseline is the cost of the cryptographic operations (Ed25519 + ML-DSA-65 signing). As file size grows, BLAKE2b-512 hashing dominates.

### Verification

| File Size | Time |
|-----------|------|
| 0 B | ~133 us |
| 1 KiB | ~134 us |
| 1 MiB | ~1.15 ms |
| 10 MiB | ~10.4 ms |
| 100 MiB | ~106 ms |

Verification is faster than signing at small file sizes (~133 us vs ~400 us) because signature verification is cheaper than signature generation, particularly for ML-DSA-65. At large file sizes, both converge since BLAKE2b-512 hashing dominates.

## End-to-end (`cli`)

These benchmarks run the full command pipeline: key file I/O, Argon2id key derivation (256 MiB, 3 iterations), signing/verification, and signature serialization.

### Key Generation + Encryption

| Operation | Time |
|-----------|------|
| generate | ~379 ms |

Almost entirely Argon2id (256 MiB, 3 iterations). The actual key generation (~156 us) is negligible.

### Signing (with key decryption)

| File Size | Time |
|-----------|------|
| 0 B | ~380 ms |
| 1 KiB | ~400 ms |
| 1 MiB | ~389 ms |
| 10 MiB | ~398 ms |
| 100 MiB | ~486 ms |

Argon2id dominates at all file sizes. The ~380 ms baseline is almost entirely key decryption. Only at 100 MiB does BLAKE2b-512 hashing become visible (~106 ms on top of the Argon2id floor).

### Verification

| File Size | Time |
|-----------|------|
| 0 B | ~178 us |
| 1 KiB | ~181 us |
| 1 MiB | ~1.19 ms |
| 10 MiB | ~10.8 ms |
| 100 MiB | ~106 ms |

Verification does not involve Argon2id (only the public key is needed), so it is nearly identical to the library benchmark. The small overhead (~45 us) is from reading the public key and signature files from disk.

## Observations

- **Argon2id dominates signing**: Key decryption (~378 ms) dwarfs everything else. The actual sign operation adds < 1 ms for small files.
- **Verification is fast**: No password-based key derivation needed, so verification is sub-millisecond for small files even in the end-to-end path.
- **Hashing throughput**: BLAKE2b-512 hashes at approximately 1 GiB/s in software, making it negligible for small files and the bottleneck for large ones.
- **ML-DSA-65 is the expensive crypto**: The ~267 us gap between signing and verification baselines (in the library benchmarks) is almost entirely ML-DSA-65. Ed25519 sign/verify are both sub-microsecond.

See also: [Brute-Force Resistance](brute-force-resistance.md) for an analysis of password cracking times based on these benchmarks.
