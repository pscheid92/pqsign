use std::fs;

use assert_cmd::Command;

fn cmd() -> Command {
    Command::cargo_bin("pqsign").unwrap()
}

fn generate_key(sk: &std::path::Path) {
    cmd()
        .args(["generate", "-s", sk.to_str().unwrap()])
        .write_stdin("test-pw\ntest-pw\n")
        .assert()
        .success();
}

fn sign_file(file: &std::path::Path, sk: &std::path::Path, sig: &std::path::Path) {
    cmd()
        .args(["sign", file.to_str().unwrap(), "-s", sk.to_str().unwrap(), "-x", sig.to_str().unwrap()])
        .write_stdin("test-pw\n")
        .assert()
        .success();
}

// -- version subcommand --

#[test]
fn test_cli_version_subcommand() {
    cmd().arg("version").assert().success().stdout(predicates::str::contains("pqsign "));
}

// -- generate subcommand --

#[test]
fn test_cli_generate() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");

    cmd()
        .args(["generate", "-s", sk.to_str().unwrap()])
        .write_stdin("mypass\nmypass\n")
        .assert()
        .success()
        .stderr(predicates::str::contains("Key ID:"));

    assert!(sk.exists());
    assert!(dir.path().join("test.key.pub").exists());
}

#[test]
fn test_cli_generate_refuses_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    fs::write(&sk, b"").unwrap();

    cmd()
        .args(["generate", "-s", sk.to_str().unwrap()])
        .write_stdin("pw\npw\n")
        .assert()
        .failure()
        .stderr(predicates::str::contains("already exists"));
}

#[test]
fn test_cli_generate_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let pk = dir.path().join("test.key.pub");
    fs::write(&sk, b"old").unwrap();
    fs::write(&pk, b"old").unwrap();

    cmd()
        .args(["generate", "-s", sk.to_str().unwrap(), "--overwrite"])
        .write_stdin("pw\npw\n")
        .assert()
        .success();

    assert_ne!(fs::read(&sk).unwrap(), b"old");
}

// -- sign + verify subcommands --

#[test]
fn test_cli_sign_and_verify() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let pk = dir.path().join("test.key.pub");
    let file = dir.path().join("msg.txt");
    let sig = dir.path().join("msg.txt.pqsig");

    fs::write(&file, b"hello cli").unwrap();
    generate_key(&sk);
    sign_file(&file, &sk, &sig);

    cmd()
        .args(["verify", file.to_str().unwrap(), "-p", pk.to_str().unwrap(), "-x", sig.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::contains("Signature: OK"));
}

#[test]
fn test_cli_verify_tampered_fails() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let pk = dir.path().join("test.key.pub");
    let file = dir.path().join("msg.txt");
    let sig = dir.path().join("msg.txt.pqsig");

    fs::write(&file, b"original").unwrap();
    generate_key(&sk);
    sign_file(&file, &sk, &sig);

    fs::write(&file, b"tampered").unwrap();

    cmd()
        .args(["verify", file.to_str().unwrap(), "-p", pk.to_str().unwrap(), "-x", sig.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicates::str::contains("error:"));
}

// -- inspect subcommand --

#[test]
fn test_cli_inspect_public_key() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let pk = dir.path().join("test.key.pub");

    generate_key(&sk);

    cmd()
        .args(["inspect", pk.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::contains("Public key"));
}

#[test]
fn test_cli_inspect_secret_key() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");

    generate_key(&sk);

    cmd()
        .args(["inspect", sk.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::contains("encrypted"));
}

#[test]
fn test_cli_inspect_signature() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let file = dir.path().join("msg.txt");
    let sig = dir.path().join("msg.txt.pqsig");

    fs::write(&file, b"data").unwrap();
    generate_key(&sk);
    sign_file(&file, &sk, &sig);

    cmd()
        .args(["inspect", sig.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::contains("Signature"));
}

// -- error cases --

#[test]
fn test_cli_no_subcommand() {
    cmd().assert().failure();
}

#[test]
fn test_cli_sign_nonexistent_file() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");

    generate_key(&sk);

    cmd()
        .args(["sign", "/no/such/file.txt", "-s", sk.to_str().unwrap()])
        .write_stdin("test-pw\n")
        .assert()
        .failure()
        .stderr(predicates::str::contains("error:"));
}

#[test]
fn test_cli_sign_with_custom_comment() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let pk = dir.path().join("test.key.pub");
    let file = dir.path().join("msg.txt");
    let sig = dir.path().join("msg.txt.pqsig");

    fs::write(&file, b"data").unwrap();
    generate_key(&sk);

    cmd()
        .args([
            "sign",
            file.to_str().unwrap(),
            "-s",
            sk.to_str().unwrap(),
            "-x",
            sig.to_str().unwrap(),
            "-t",
            "release v2.0",
        ])
        .write_stdin("test-pw\n")
        .assert()
        .success();

    cmd()
        .args(["verify", file.to_str().unwrap(), "-p", pk.to_str().unwrap(), "-x", sig.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::contains("release v2.0"));
}

// -- new CLI features --

#[test]
fn test_cli_generate_force_alias() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let pk = dir.path().join("test.key.pub");
    fs::write(&sk, b"old").unwrap();
    fs::write(&pk, b"old").unwrap();

    cmd()
        .args(["generate", "-s", sk.to_str().unwrap(), "--force"])
        .write_stdin("pw\npw\n")
        .assert()
        .success();

    assert_ne!(fs::read(&sk).unwrap(), b"old");
}

#[test]
fn test_cli_verify_quiet_success() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let pk = dir.path().join("test.key.pub");
    let file = dir.path().join("msg.txt");
    let sig = dir.path().join("msg.txt.pqsig");

    fs::write(&file, b"data").unwrap();
    generate_key(&sk);
    sign_file(&file, &sk, &sig);

    cmd()
        .args([
            "verify",
            file.to_str().unwrap(),
            "-p",
            pk.to_str().unwrap(),
            "-x",
            sig.to_str().unwrap(),
            "-q",
        ])
        .assert()
        .success()
        .stdout(predicates::str::is_empty());
}

#[test]
fn test_cli_verify_quiet_failure() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let pk = dir.path().join("test.key.pub");
    let file = dir.path().join("msg.txt");
    let sig = dir.path().join("msg.txt.pqsig");

    fs::write(&file, b"original").unwrap();
    generate_key(&sk);
    sign_file(&file, &sk, &sig);

    fs::write(&file, b"tampered").unwrap();

    cmd()
        .args([
            "verify",
            file.to_str().unwrap(),
            "-p",
            pk.to_str().unwrap(),
            "-x",
            sig.to_str().unwrap(),
            "--quiet",
        ])
        .assert()
        .failure()
        .stdout(predicates::str::is_empty());
}

#[test]
fn test_cli_verify_inline_public_key() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let pk = dir.path().join("test.key.pub");
    let file = dir.path().join("msg.txt");
    let sig = dir.path().join("msg.txt.pqsig");

    fs::write(&file, b"data").unwrap();
    generate_key(&sk);
    sign_file(&file, &sk, &sig);

    let pk_string = fs::read_to_string(&pk).unwrap();

    cmd()
        .args(["verify", file.to_str().unwrap(), "-P", pk_string.trim(), "-x", sig.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::contains("Signature: OK"))
        .stdout(predicates::str::contains("<inline>"));
}

#[test]
fn test_cli_sign_nonexistent_file_error_message() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");

    generate_key(&sk);

    cmd()
        .args(["sign", "/no/such/file.txt", "-s", sk.to_str().unwrap()])
        .write_stdin("test-pw\n")
        .assert()
        .failure()
        .stderr(predicates::str::contains("no such file"));
}

#[test]
fn test_cli_inspect_fallback_to_pqsig() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let file = dir.path().join("msg.txt");
    let sig = dir.path().join("msg.txt.pqsig");

    fs::write(&file, b"data").unwrap();
    generate_key(&sk);
    sign_file(&file, &sk, &sig);

    cmd()
        .args(["inspect", file.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::contains("Signature"))
        .stderr(predicates::str::contains("inspecting"));
}
