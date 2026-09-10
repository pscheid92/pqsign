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
| keygen | ~148 us |

Key generation is dominated by ML-DSA-65 key pair generation. Ed25519 key generation is negligible in comparison.

### Signing

| File Size | Time |
|-----------|------|
| 0 B | ~385 us |
| 1 KiB | ~394 us |
| 1 MiB | ~1.36 ms |
| 10 MiB | ~10.5 ms |
| 100 MiB | ~106 ms |

The ~385 us baseline is the cost of the cryptographic operations (Ed25519 + ML-DSA-65 signing). As file size grows, BLAKE2b-512 hashing dominates.

### Verification

| File Size | Time |
|-----------|------|
| 0 B | ~135 us |
| 1 KiB | ~146 us |
| 1 MiB | ~1.36 ms |
| 10 MiB | ~10.9 ms |
| 100 MiB | ~106 ms |

Verification is faster than signing at small file sizes (~135 us vs ~385 us) because signature verification is cheaper than signature generation, particularly for ML-DSA-65. At large file sizes, both converge since BLAKE2b-512 hashing dominates.

## End-to-end (`cli`)

These benchmarks run the full command pipeline: key file I/O, Argon2id key derivation (256 MiB, 3 iterations), signing/verification, and signature serialization.

### Key Generation + Encryption

| Operation | Time |
|-----------|------|
| generate | ~419 ms |

Almost entirely Argon2id (256 MiB, 3 iterations). The actual key generation (~148 us) is negligible.

### Signing (with key decryption)

| File Size | Time |
|-----------|------|
| 0 B | ~407 ms |
| 1 KiB | ~392 ms |
| 1 MiB | ~377 ms |
| 10 MiB | ~438 ms |
| 100 MiB | ~493 ms |

Argon2id dominates at all file sizes. The ~380–410 ms baseline is almost entirely key decryption; the spread between sizes below 10 MiB is Argon2id run-to-run variance, not file size. Only at 100 MiB does BLAKE2b-512 hashing become visible (~106 ms on top of the Argon2id floor).

### Verification

| File Size | Time |
|-----------|------|
| 0 B | ~186 us |
| 1 KiB | ~191 us |
| 1 MiB | ~1.46 ms |
| 10 MiB | ~10.7 ms |
| 100 MiB | ~107 ms |

Verification does not involve Argon2id (only the public key is needed), so it is nearly identical to the library benchmark. The small overhead (~50 us) is from reading the public key and signature files from disk.

## Observations

- **Argon2id dominates signing**: Key decryption (~390 ms) dwarfs everything else. The actual sign operation adds < 1 ms for small files.
- **Verification is fast**: No password-based key derivation needed, so verification is sub-millisecond for small files even in the end-to-end path.
- **Hashing throughput**: BLAKE2b-512 hashes at approximately 1 GiB/s in software, making it negligible for small files and the bottleneck for large ones.
- **ML-DSA-65 is the expensive crypto**: The ~250 us gap between signing and verification baselines (in the library benchmarks) is almost entirely ML-DSA-65. Ed25519 sign/verify are both sub-microsecond.

See also: [Brute-Force Resistance](brute-force-resistance.md) for an analysis of password cracking times based on these benchmarks.
