use std::fs;

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, Signer as _, Verifier as _};
use tempfile::TempDir;

use pqsign::domain::KeyPair;

fn create_test_file(dir: &TempDir, size: usize) -> std::path::PathBuf {
    let path = dir.path().join(format!("test_{size}.bin"));
    let data = vec![0xABu8; size];
    fs::write(&path, &data).unwrap();
    path
}

fn bench_keygen(c: &mut Criterion) {
    c.bench_function("keygen", |b| {
        b.iter(KeyPair::new);
    });
}

fn bench_sign(c: &mut Criterion) {
    let sizes: &[(usize, &str)] = &[
        (0, "0B"),
        (1024, "1KiB"),
        (1024 * 1024, "1MiB"),
        (10 * 1024 * 1024, "10MiB"),
        (100 * 1024 * 1024, "100MiB"),
    ];

    let dir = TempDir::new().unwrap();
    let (sk, _pk) = KeyPair::new().into_parts();

    let mut group = c.benchmark_group("sign");
    for &(size, label) in sizes {
        let path = create_test_file(&dir, size);
        group.bench_with_input(BenchmarkId::from_parameter(label), &path, |b, path| {
            b.iter(|| sk.sign(path, "benchmark"));
        });
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let sizes: &[(usize, &str)] = &[
        (0, "0B"),
        (1024, "1KiB"),
        (1024 * 1024, "1MiB"),
        (10 * 1024 * 1024, "10MiB"),
        (100 * 1024 * 1024, "100MiB"),
    ];

    let dir = TempDir::new().unwrap();
    let (sk, pk) = KeyPair::new().into_parts();

    let mut group = c.benchmark_group("verify");
    for &(size, label) in sizes {
        let path = create_test_file(&dir, size);
        let sig = sk.sign(&path, "benchmark").unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(label), &(&sig, &pk, &path), |b, &(sig, pk, path)| {
            b.iter(|| sig.verify(pk, path));
        });
    }
    group.finish();
}

/// The parts that make up signing and verification, to explain the numbers above. The message has about the
/// size of a v2 signed record with a short trusted comment.
fn bench_breakdown(c: &mut Criterion) {
    let message = [7u8; 180];
    let mut group = c.benchmark_group("breakdown");

    let (sk, pk) = KeyPair::new().into_parts();
    group.bench_function("fingerprint/secret-key", |b| b.iter(|| sk.fingerprint()));
    group.bench_function("fingerprint/public-key", |b| b.iter(|| pk.fingerprint()));

    let ed25519_sk = SigningKey::from_bytes(&[42u8; 32]);
    let ed25519_pk = ed25519_sk.verifying_key();
    let ed25519_sig = ed25519_sk.sign(&message);
    group.bench_function("ed25519/sign", |b| b.iter(|| ed25519_sk.sign(black_box(&message))));
    group.bench_function("ed25519/verify", |b| b.iter(|| ed25519_pk.verify(black_box(&message), &ed25519_sig)));

    let (mldsa65_pk, mldsa65_sk) = ml_dsa_65::KG::keygen_from_seed(&[42u8; 32]);
    let mldsa65_sig = mldsa65_sk.try_sign(&message, b"bench").unwrap();
    group.bench_function("ml-dsa-65/keygen", |b| b.iter(|| ml_dsa_65::KG::keygen_from_seed(black_box(&[42u8; 32]))));
    group.bench_function("ml-dsa-65/sign", |b| b.iter(|| mldsa65_sk.try_sign(black_box(&message), b"bench")));
    group.bench_function("ml-dsa-65/verify", |b| {
        b.iter(|| mldsa65_pk.verify(black_box(&message), &mldsa65_sig, b"bench"))
    });

    group.finish();
}

criterion_group!(benches, bench_keygen, bench_sign, bench_verify, bench_breakdown);
criterion_main!(benches);
