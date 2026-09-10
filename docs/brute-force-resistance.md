# Brute-Force Resistance

Analysis of how well pqsign's key encryption holds up if an attacker steals the encrypted secret key file.

## Threat Model

An attacker has obtained the encrypted `.key` file and attempts to recover the secret key by brute-forcing the password offline. Each attempt requires running the full Argon2id KDF (256 MiB, 3 iterations) before testing a candidate password.

From [benchmarks](benchmarks.md), each attempt costs ~390 ms on a single CPU core (~2.6 attempts/sec).

## GPU Parallelism

Argon2id's 256 MiB memory requirement limits GPU parallelism. Each attempt needs its own 256 MiB allocation, so the number of parallel attempts is bounded by VRAM, not compute:

| GPU | VRAM | Max parallel attempts |
|-----|------|-----------------------|
| RTX 4090 | 24 GB | ~96 |
| A100 / H100 | 80 GB | ~320 |

This is a fraction of the thousands of parallel hashes GPUs can run against memory-cheap KDFs like bcrypt or PBKDF2. Additionally, Argon2id's sequential memory access pattern (1 lane of parallelism) maps poorly to GPU architectures, making each attempt slower on a GPU than on a CPU core.

In practice, a single high-end GPU provides roughly the same throughput as 100 CPU cores for this workload.

## Time to Crack

Average time to exhaust half the search space (i.e., expected time to find the password):

| Password type | Search space | 1 CPU core | 100 CPU cores | RTX 4090 (~96) | A100 (~320) |
|---|---|---|---|---|---|
| 4-digit PIN | 10,000 | ~32 min | ~19 sec | ~20 sec | ~6 sec |
| 6-digit PIN | 1,000,000 | ~2.2 days | ~32 min | ~33 min | ~10 min |
| Dictionary word (100K) | 100,000 | ~5.3 hours | ~3.2 min | ~3.3 min | ~1 min |
| 8-char lowercase | 26^8 (~209 billion) | ~1,275 years | ~12.7 years | ~13.3 years | ~4 years |
| 8-char alphanumeric | 62^8 (~218 trillion) | ~1.33M years | ~13.3K years | ~13.9K years | ~4.2K years |
| 4-word diceware passphrase | 7776^4 (~3.66 quadrillion) | ~22.3M years | ~223K years | ~232K years | ~69.7K years |
| 30-char random (a-z, A-Z, 0-9, symbols) | 95^30 (~2.15 × 10^59) | ~1.31 × 10^51 years | ~1.31 × 10^49 years | ~1.36 × 10^49 years | ~4.1 × 10^48 years |

## Bottom Line

The Argon2id parameters (256 MiB, 3 iterations) make brute-force expensive, but **password entropy is the real defense**:

- **Weak passwords (PINs, dictionary words) fall in minutes to hours** regardless of KDF tuning. No amount of memory-hardness saves a 4-digit PIN.
- **8+ character random passwords are safe** against any single attacker, even with high-end GPU hardware.
- **4+ word diceware passphrases are effectively unbreakable** — hundreds of thousands of years even on datacenter GPUs.

Choose a strong password. The KDF buys time; the password provides the actual security.
