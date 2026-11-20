//! Wycheproof's ML-DSA-65 test vectors, run against the implementation pqsign uses, the way pqsign uses it: keys
//! and signatures of fixed length, and the external interface with a context string. pqsign stores secret keys as
//! 32-byte seeds since 0.4 (secret key format v2) and in the expanded 4,032-byte form in secret key format v1, so
//! both forms are tested: the seed file guards format v2 against a change in how a seed becomes a key. See
//! tests/vectors/wycheproof/README.md.

use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use pqsign::domain::{Ed25519SecretKey, MlDsa65Seed, SecretSeeds};
use pqsign::format;
use serde_json::Value;

/// The published crate leaves the vectors out, so the tests skip themselves there.
fn load(name: &str) -> Option<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/wycheproof").join(name);
    let Ok(text) = std::fs::read_to_string(path) else {
        eprintln!("skipped: the Wycheproof vectors are not part of this checkout");
        return None;
    };
    Some(serde_json::from_str(&text).unwrap())
}

/// Every test case with the group it belongs to.
fn cases(vectors: &Value) -> impl Iterator<Item = (&Value, &Value)> {
    let groups = vectors["testGroups"].as_array().unwrap();
    groups
        .iter()
        .flat_map(|group| group["tests"].as_array().unwrap().iter().map(move |case| (group, case)))
}

fn hex(value: &Value) -> Vec<u8> {
    let text = value.as_str().unwrap_or("");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn describe(case: &Value) -> String {
    format!("tcId {} ({}): {}", case["tcId"], case["result"], case["comment"])
}

fn verify(public_key: &[u8], message: &[u8], signature: &[u8], ctx: &[u8]) -> bool {
    let (Ok(public_key), Ok(signature)) = (
        <[u8; ml_dsa_65::PK_LEN]>::try_from(public_key),
        <[u8; ml_dsa_65::SIG_LEN]>::try_from(signature),
    ) else {
        return false;
    };
    ml_dsa_65::PublicKey::try_from_bytes(public_key).is_ok_and(|key| key.verify(message, &signature, ctx))
}

/// The deterministic variant of ML-DSA signing, with all-zero randomness, which Wycheproof's signatures use.
fn sign(secret_key: &[u8], message: &[u8], ctx: &[u8]) -> Option<[u8; ml_dsa_65::SIG_LEN]> {
    let secret_key = <[u8; ml_dsa_65::SK_LEN]>::try_from(secret_key).ok()?;
    let secret_key = ml_dsa_65::PrivateKey::try_from_bytes(secret_key).ok()?;
    secret_key.try_sign_with_seed(&[0u8; 32], message, ctx).ok()
}

/// Includes the malformed hint encodings and norm violations that RustCrypto's ml-dsa and libcrux-ml-dsa accepted.
#[test]
fn test_mldsa65_verification_vectors() {
    let Some(vectors) = load("mldsa_65_verify_test.json") else { return };

    let mut checked = 0;
    let mut failures = Vec::new();
    for (group, case) in cases(&vectors) {
        let accepted = verify(&hex(&group["publicKey"]), &hex(&case["msg"]), &hex(&case["sig"]), &hex(&case["ctx"]));
        if accepted != (case["result"] == "valid") {
            failures.push(describe(case));
        }
        checked += 1;
    }

    assert_eq!(checked, vectors["numberOfTests"], "not every test case was checked");
    assert!(
        failures.is_empty(),
        "{} of {checked} cases failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Each valid case must give exactly Wycheproof's signature, and every invalid secret key must be rejected,
/// including the two whose s1 or s2 is out of range, which fips204 accepted before 0.5. Cases for ML-DSA's
/// internal interface, which pqsign does not use, and the one randomized case are skipped.
#[test]
fn test_mldsa65_signing_vectors() {
    let Some(vectors) = load("mldsa_65_sign_noseed_test.json") else { return };

    let (mut checked, mut skipped) = (0, 0);
    let mut failures = Vec::new();
    for (group, case) in cases(&vectors) {
        let flags = case["flags"].as_array().unwrap();
        if flags.iter().any(|flag| flag == "Internal" || flag == "Randomized") {
            skipped += 1;
            continue;
        }
        checked += 1;

        let signature = sign(&hex(&group["privateKey"]), &hex(&case["msg"]), &hex(&case["ctx"]));
        let correct = match signature {
            Some(signature) => case["result"] == "valid" && signature[..] == hex(&case["sig"])[..],
            None => case["result"] != "valid",
        };
        if !correct {
            failures.push(describe(case));
        }
    }

    assert_eq!(checked + skipped, vectors["numberOfTests"], "not every test case was checked");
    assert!(
        failures.is_empty(),
        "{} of {checked} cases failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The ML-DSA-65 public key pqsign derives from a seed, read back through its public key text form: after the
/// `pqsign:v1:` prefix, the binary form is a 14-byte header, the 32-byte Ed25519 key and the ML-DSA-65 key.
fn pqsign_mldsa65_public_key(seed: [u8; 32]) -> Vec<u8> {
    let seeds = SecretSeeds::from_parts(Ed25519SecretKey::from_bytes([0u8; 32]), MlDsa65Seed::from_bytes(seed));
    let text = format::encode_public_key(&seeds.key_pair().public_key);
    let blob = STANDARD.decode(text.trim_end().strip_prefix("pqsign:v1:").unwrap()).unwrap();
    blob[14 + 32..].to_vec()
}

/// Secret key format v2 rebuilds the ML-DSA-65 key from its seed on every load, so seed to key must match FIPS 204
/// exactly: both fips204 itself and pqsign's own path must give Wycheproof's public key, and signatures made with
/// the seed's key must match Wycheproof's. Cases for the internal interface, the randomized case and the seeds of
/// the wrong length, which `MlDsa65Seed` can't hold, are skipped.
#[test]
fn test_mldsa65_seed_vectors() {
    let Some(vectors) = load("mldsa_65_sign_seed_test.json") else { return };
    let skip = ["IncorrectPrivateKeyLength", "Internal", "Randomized"];

    let (mut checked, mut skipped, mut public_keys) = (0, 0, 0);
    let mut failures = Vec::new();
    for group in vectors["testGroups"].as_array().unwrap() {
        let seed = <[u8; 32]>::try_from(hex(&group["privateSeed"])).ok();
        if let Some(seed) = seed {
            let expected = hex(&group["publicKey"]);
            let (public_key, _) = ml_dsa_65::KG::keygen_from_seed(&seed);
            if public_key.into_bytes()[..] != expected[..] {
                failures.push(format!("fips204 public key for seed {}", group["privateSeed"]));
            }
            if pqsign_mldsa65_public_key(seed) != expected {
                failures.push(format!("pqsign public key for seed {}", group["privateSeed"]));
            }
            public_keys += 1;
        }

        for case in group["tests"].as_array().unwrap() {
            let flags = case["flags"].as_array().unwrap();
            if flags.iter().any(|flag| skip.iter().any(|name| flag == name)) {
                skipped += 1;
                continue;
            }
            checked += 1;

            let Some(seed) = seed else {
                failures.push(format!("{}: seed is not 32 bytes", describe(case)));
                continue;
            };
            let (_, secret_key) = ml_dsa_65::KG::keygen_from_seed(&seed);
            let signature = secret_key.try_sign_with_seed(&[0u8; 32], &hex(&case["msg"]), &hex(&case["ctx"])).ok();
            let correct = match signature {
                Some(signature) => case["result"] == "valid" && signature[..] == hex(&case["sig"])[..],
                None => case["result"] != "valid",
            };
            if !correct {
                failures.push(describe(case));
            }
        }
    }

    assert_eq!(checked + skipped, vectors["numberOfTests"], "not every test case was checked");
    assert_eq!(public_keys, 39, "every group with a 32-byte seed checks its public key");
    assert!(
        failures.is_empty(),
        "{} of {checked} cases or public keys failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
