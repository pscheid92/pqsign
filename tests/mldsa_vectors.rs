//! Wycheproof's ML-DSA-65 test vectors, run against the implementation pqsign uses, the way pqsign uses it: keys
//! and signatures of fixed length, the external interface with a context string, and secret keys in the expanded
//! 4,032-byte form that pqsign stores. See tests/vectors/wycheproof/README.md.

use std::path::Path;

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};
use serde_json::Value;

/// fips204 0.4.6 signs with these malformed secret keys instead of rejecting them. pqsign never reads such a key:
/// its secret keys come from fips204's own key generation and are stored encrypted and authenticated. When a fips204
/// release rejects them, the signing test fails and the exception can go.
const SIGNS_WITH_MALFORMED_KEY: [u64; 2] = [
    56, // private key with s1 vector out of range
    57, // private key with s2 vector out of range
];

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

/// Each valid case must give exactly Wycheproof's signature. Cases for ML-DSA's internal interface, which pqsign
/// does not use, and the one randomized case are skipped.
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
        if SIGNS_WITH_MALFORMED_KEY.contains(&case["tcId"].as_u64().unwrap()) {
            if signature.is_none() {
                let failure = format!("{}: now rejected; remove it from SIGNS_WITH_MALFORMED_KEY", describe(case));
                failures.push(failure);
            }
            continue;
        }
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
