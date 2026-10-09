use std::fs;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use tempfile::TempDir;
use zeroize::Zeroizing;

use pqsign::commands::{generate, sign, verify};
use pqsign::domain::SignatureFormat;
use pqsign::password::PasswordSource;

fn password() -> Zeroizing<String> {
    Zeroizing::new("benchmark-password".to_string())
}

fn setup_keys(dir: &TempDir) {
    generate::run(generate::Options {
        secret_key: Some(dir.path().join("test.key")),
        password: PasswordSource::Given(password()),
        overwrite: true,
    })
    .unwrap();
}

fn create_test_file(dir: &TempDir, size: usize) -> std::path::PathBuf {
    let path = dir.path().join(format!("test_{size}.bin"));
    let data = vec![0xABu8; size];
    fs::write(&path, &data).unwrap();
    path
}

fn bench_generate(c: &mut Criterion) {
    let dir = TempDir::new().unwrap();

    c.bench_function("cli/generate", |b| {
        b.iter(|| {
            generate::run(generate::Options {
                secret_key: Some(dir.path().join("bench.key")),
                password: PasswordSource::Given(password()),
                overwrite: true,
            })
            .unwrap();
        });
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
    setup_keys(&dir);

    let mut group = c.benchmark_group("cli/sign");
    group.sample_size(10);
    for &(size, label) in sizes {
        let path = create_test_file(&dir, size);
        group.bench_with_input(BenchmarkId::from_parameter(label), &path, |b, path| {
            b.iter(|| {
                sign::run(sign::Options {
                    file: path.clone(),
                    secret_key: Some(dir.path().join("test.key")),
                    sig_file: Some(dir.path().join("test.pqsig")),
                    trusted_comment: Some("benchmark".to_string()),
                    password: PasswordSource::Given(password()),
                    format: SignatureFormat::V2,
                })
                .unwrap();
            });
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
    setup_keys(&dir);

    let mut group = c.benchmark_group("cli/verify");
    for &(size, label) in sizes {
        let path = create_test_file(&dir, size);

        // Pre-sign so we have a signature to verify
        sign::run(sign::Options {
            file: path.clone(),
            secret_key: Some(dir.path().join("test.key")),
            sig_file: Some(dir.path().join(format!("test_{size}.pqsig"))),
            trusted_comment: Some("benchmark".to_string()),
            password: PasswordSource::Given(password()),
            format: SignatureFormat::V2,
        })
        .unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(label), &path, |b, path| {
            b.iter(|| {
                verify::run(verify::Options {
                    file: path.clone(),
                    public_key: Some(dir.path().join("test.key.pub")),
                    public_key_string: None,
                    sig_file: Some(dir.path().join(format!("test_{size}.pqsig"))),
                    quiet: true,
                })
                .unwrap();
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_generate, bench_sign, bench_verify);
criterion_main!(benches);
