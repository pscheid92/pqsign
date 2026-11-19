# Wycheproof ML-DSA-65 test vectors

`mldsa_65_verify_test.json`, `mldsa_65_sign_noseed_test.json` and `mldsa_65_sign_seed_test.json` are copied unchanged from `testvectors_v1/` of [C2SP/wycheproof](https://github.com/C2SP/wycheproof) at commit `7a325932231bd7a724c791c8b0d65ea4d6d2f435`. All three last changed in `20b256949ea8f21a11375619b1825027ca0668bd`, "mldsa: regenerate FIPS 204 edge cases", on 2026-10-06. Wycheproof is licensed under the Apache License 2.0, included as `LICENSE`.

[`tests/mldsa_vectors.rs`](../../mldsa_vectors.rs) runs them against the ML-DSA-65 implementation pqsign uses. The crates.io package leaves them out.

The seed file maps each 32-byte ML-DSA-65 seed to its public key and signatures. It guards secret key format v2, which stores keys as seeds, against a change in how a seed becomes a key.

To update them, copy all three files from a newer commit and change the commit above.
