# KDF Parameter Comparison

A comparison of Argon2id parameter choices and their impact on performance and brute-force resistance.

## Presets

| Preset | Memory | Iterations | Source |
|--------|--------|------------|--------|
| pqsign (current) | 256 MiB | 3 | — |
| libsodium SENSITIVE | 1 GiB | 4 | libsodium `crypto_pwhash_*_SENSITIVE` |

## Benchmark Results

Measured on an Apple M-series chip using the end-to-end CLI benchmarks.

### Key Generation + Encryption

| Preset | Time |
|--------|------|
| pqsign (256 MiB / 3) | ~379 ms |
| SENSITIVE (1 GiB / 4) | ~2.13 s |

### Signing (includes key decryption)

| File Size | pqsign (256 MiB / 3) | SENSITIVE (1 GiB / 4) |
|-----------|----------------------|-----------------------|
| 0 B | ~380 ms | ~2.10 s |
| 1 KiB | ~400 ms | ~2.08 s |
| 1 MiB | ~389 ms | ~2.09 s |
| 10 MiB | ~398 ms | ~2.13 s |
| 100 MiB | ~486 ms | ~2.28 s |

### Verification (no KDF involved)

Verification times are identical across presets since only the public key is needed.

## Brute-Force Cost

Attempts per second on a single core:

| Preset | Time per attempt | Attempts/sec | Attempts/sec (100 cores) |
|--------|-----------------|--------------|--------------------------|
| pqsign (256 MiB / 3) | ~378 ms | ~2.6 | ~260 |
| SENSITIVE (1 GiB / 4) | ~2.1 s | ~0.48 | ~48 |

Time to exhaust common password spaces (single core, average case):

| Password type | Search space | pqsign (256 MiB / 3) | SENSITIVE (1 GiB / 4) |
|---|---|---|---|
| 4-digit PIN | 10,000 | ~32 min | ~2.9 hours |
| 6-digit PIN | 1,000,000 | ~2.2 days | ~12.1 days |
| Dictionary (100K) | 100,000 | ~5.3 hours | ~29 hours |
| 8-char lowercase | 209 billion | ~1,275 years | ~7,000 years |
| 4-word diceware | 3.66 quadrillion | ~22.3 million years | ~121 million years |

## Analysis

The SENSITIVE preset is ~5.6x slower per attempt, which:

- **Improves** brute-force resistance by the same 5.6x factor
- **Worsens** every sign operation by ~1.7 seconds
- **Does not affect** verification at all

For pqsign's use case (file signing, not a login flow), the current 256 MiB / 3 preset is a reasonable choice:

- Signing is interactive and infrequent — ~380 ms is noticeable but tolerable
- ~2.1 s per sign would be annoying for batch operations
- The 5.6x brute-force improvement doesn't change the security class — a weak PIN is still crackable in hours, and a decent passphrase is still unbreakable with either preset
- The real defense is password entropy, not KDF tuning past a reasonable threshold
