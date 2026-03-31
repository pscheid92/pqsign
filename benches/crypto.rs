use std::fs;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
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

criterion_group!(benches, bench_keygen, bench_sign, bench_verify);
criterion_main!(benches);
