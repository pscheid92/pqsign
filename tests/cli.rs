use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;

fn cmd() -> Command {
    Command::cargo_bin("pqsign").unwrap()
}

fn generate_key(sk: &std::path::Path) {
    cmd()
        .args(["generate", "-s", sk.to_str().unwrap(), "--password-stdin"])
        .write_stdin("test-pw\n")
        .assert()
        .success();
}

fn sign_file(file: &std::path::Path, sk: &std::path::Path, sig: &std::path::Path) {
    cmd()
        .args([
            "sign",
            file.to_str().unwrap(),
            "-s",
            sk.to_str().unwrap(),
            "-x",
            sig.to_str().unwrap(),
            "--password-stdin",
        ])
        .write_stdin("test-pw\n")
        .assert()
        .success();
}

// -- version subcommand --

#[test]
fn test_cli_version_subcommand() {
    cmd().arg("version").assert().success().stdout(predicates::str::contains("pqsign "));
    cmd().arg("--version").assert().success().stdout(predicates::str::contains("pqsign "));
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains("Print version information").not());
}

// -- generate subcommand --

#[test]
fn test_cli_generate() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");

    let assert = cmd()
        .args(["generate", "-s", sk.to_str().unwrap(), "--password-stdin"])
        .write_stdin("mypass\n")
        .assert()
        .success()
        .stderr(predicates::str::contains("Key ID:").and(predicates::str::contains("pqsign:v1:").not()));

    // The public key is the command's output, on stdout, exactly as written to the .pub file.
    let public_key = fs::read_to_string(dir.path().join("test.key.pub")).unwrap();
    assert_eq!(String::from_utf8_lossy(&assert.get_output().stdout), public_key);
    assert!(sk.exists());
}

#[test]
fn test_cli_generate_refuses_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    fs::write(&sk, b"").unwrap();

    cmd()
        .args(["generate", "-s", sk.to_str().unwrap(), "--password-stdin"])
        .write_stdin("pw\n")
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
        .args(["generate", "-s", sk.to_str().unwrap(), "--overwrite", "--password-stdin"])
        .write_stdin("pw\n")
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
        .args(["sign", "/no/such/file.txt", "-s", sk.to_str().unwrap(), "--password-stdin"])
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
            "--password-stdin",
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
        .args(["generate", "-s", sk.to_str().unwrap(), "--force", "--password-stdin"])
        .write_stdin("pw\n")
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
        .args(["sign", "/no/such/file.txt", "-s", sk.to_str().unwrap(), "--password-stdin"])
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

// -- password sources --

fn generate_key_with_stdin_password(sk: &std::path::Path, password: &str) -> assert_cmd::assert::Assert {
    cmd()
        .args(["generate", "-s", sk.to_str().unwrap(), "--password-stdin"])
        .write_stdin(password)
        .assert()
}

fn sign_with_stdin_password(file: &std::path::Path, sk: &std::path::Path, sig: &std::path::Path, password: &str) -> assert_cmd::assert::Assert {
    cmd()
        .args([
            "sign",
            file.to_str().unwrap(),
            "-s",
            sk.to_str().unwrap(),
            "-x",
            sig.to_str().unwrap(),
            "--password-stdin",
        ])
        .write_stdin(password)
        .assert()
}

#[test]
fn test_cli_password_file_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let pk = dir.path().join("test.key.pub");
    let pw_file = dir.path().join("password.txt");
    let file = dir.path().join("msg.txt");
    let sig = dir.path().join("msg.txt.pqsig");

    fs::write(&pw_file, "file-pw\r\nsecond line is ignored\n").unwrap();
    fs::write(&file, b"data").unwrap();

    cmd()
        .args(["generate", "-s", sk.to_str().unwrap(), "--password-file", pw_file.to_str().unwrap()])
        .assert()
        .success();

    cmd()
        .args([
            "sign",
            file.to_str().unwrap(),
            "-s",
            sk.to_str().unwrap(),
            "-x",
            sig.to_str().unwrap(),
            "--password-file",
            pw_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    cmd()
        .args(["verify", file.to_str().unwrap(), "-p", pk.to_str().unwrap(), "-x", sig.to_str().unwrap()])
        .assert()
        .success();

    // The key was encrypted with exactly "file-pw": neither the line ending nor the second line were part of it.
    sign_with_stdin_password(&file, &sk, &sig, "file-pw\n").success();
}

#[test]
fn test_cli_password_stdin_preserves_trailing_whitespace() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let file = dir.path().join("msg.txt");
    let sig = dir.path().join("msg.txt.pqsig");
    fs::write(&file, b"data").unwrap();

    generate_key_with_stdin_password(&sk, "pw \n").success();

    sign_with_stdin_password(&file, &sk, &sig, "pw\n")
        .failure()
        .stderr(predicates::str::contains("wrong password"));
    sign_with_stdin_password(&file, &sk, &sig, "pw \n").success();
}

#[test]
fn test_cli_password_stdin_reads_first_line_only() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let file = dir.path().join("msg.txt");
    let sig = dir.path().join("msg.txt.pqsig");
    fs::write(&file, b"data").unwrap();

    generate_key_with_stdin_password(&sk, "pw\nsecond line\n").success();
    sign_with_stdin_password(&file, &sk, &sig, "pw\n").success();
}

#[test]
fn test_cli_password_stdin_without_line_ending() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let file = dir.path().join("msg.txt");
    let sig = dir.path().join("msg.txt.pqsig");
    fs::write(&file, b"data").unwrap();

    generate_key_with_stdin_password(&sk, "pw").success();
    sign_with_stdin_password(&file, &sk, &sig, "pw\r\n").success();
}

#[test]
fn test_cli_password_stdin_empty_fails() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");

    generate_key_with_stdin_password(&sk, "")
        .failure()
        .stderr(predicates::str::contains("password cannot be empty"));
    generate_key_with_stdin_password(&sk, "\n")
        .failure()
        .stderr(predicates::str::contains("password cannot be empty"));

    assert!(!sk.exists());
}

#[test]
fn test_cli_password_flags_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");

    cmd()
        .args([
            "generate",
            "-s",
            sk.to_str().unwrap(),
            "--password-stdin",
            "--password-file",
            "password.txt",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("cannot be used with"));
}

#[test]
fn test_cli_password_file_missing_fails() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");

    cmd()
        .args(["generate", "-s", sk.to_str().unwrap(), "--password-file", "/no/such/password.txt"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("no such file"));
}

/// Without a terminal and without a password option, the command must fail with a hint instead of
/// silently reading standard input. Only meaningful where no controlling terminal exists (CI, IDE
/// test runners); skipped when run from an interactive shell.
#[cfg(unix)]
#[test]
fn test_cli_sign_without_terminal_requires_password_option() {
    if fs::File::open("/dev/tty").is_ok() {
        eprintln!("skipped: a controlling terminal is available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let file = dir.path().join("msg.txt");
    fs::write(&file, b"data").unwrap();
    generate_key(&sk);

    cmd()
        .args(["sign", file.to_str().unwrap(), "-s", sk.to_str().unwrap()])
        .write_stdin("test-pw\n")
        .assert()
        .failure()
        .stderr(predicates::str::contains("--password-stdin"));
}

// -- secret key file permissions --

#[cfg(unix)]
#[test]
fn test_cli_sign_warns_about_key_accessible_by_others() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let file = dir.path().join("msg.txt");
    let sig = dir.path().join("msg.txt.pqsig");
    fs::write(&file, b"data").unwrap();
    generate_key(&sk);

    let sign = || {
        cmd()
            .args([
                "sign",
                file.to_str().unwrap(),
                "-s",
                sk.to_str().unwrap(),
                "-x",
                sig.to_str().unwrap(),
                "--password-stdin",
            ])
            .write_stdin("test-pw\n")
            .assert()
            .success()
    };

    sign().stderr(predicates::str::contains("warning").not());

    fs::set_permissions(&sk, fs::Permissions::from_mode(0o644)).unwrap();
    sign().stderr(predicates::str::contains("is accessible by other users (mode 0644)").and(predicates::str::contains("chmod 600")));
}

// -- bounded reads --

#[test]
fn test_cli_inspect_large_file_falls_back_to_pqsig() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let file = dir.path().join("data.bin");
    let sig = dir.path().join("data.bin.pqsig");

    fs::write(&file, vec![0u8; 1024 * 1024]).unwrap();
    generate_key(&sk);
    sign_file(&file, &sk, &sig);

    cmd()
        .args(["inspect", file.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::contains("Signature"))
        .stderr(predicates::str::contains("inspecting"));

    fs::remove_file(&sig).unwrap();
    cmd()
        .args(["inspect", file.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicates::str::contains("data.bin.pqsig"));
}

/// Readers must stop after a few kilobytes instead of reading an endless device until memory runs out.
#[cfg(unix)]
#[test]
fn test_cli_readers_stop_on_endless_input() {
    let timeout = std::time::Duration::from_secs(30);
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let pk = dir.path().join("test.key.pub");
    let file = dir.path().join("msg.txt");
    let sig = dir.path().join("msg.txt.pqsig");
    fs::write(&file, b"data").unwrap();
    generate_key(&sk);
    sign_file(&file, &sk, &sig);

    cmd()
        .args(["inspect", "/dev/zero"])
        .timeout(timeout)
        .assert()
        .failure()
        .stderr(predicates::str::contains("/dev/zero.pqsig"));

    cmd()
        .args(["verify", file.to_str().unwrap(), "-p", pk.to_str().unwrap(), "-x", "/dev/zero"])
        .timeout(timeout)
        .assert()
        .failure()
        .stderr(predicates::str::contains("larger than 64 KiB"));

    cmd()
        .args(["verify", file.to_str().unwrap(), "-p", "/dev/zero", "-x", sig.to_str().unwrap()])
        .timeout(timeout)
        .assert()
        .failure()
        .stderr(predicates::str::contains("larger than 64 KiB"));

    cmd()
        .args([
            "sign",
            file.to_str().unwrap(),
            "-s",
            "/dev/zero",
            "-x",
            sig.to_str().unwrap(),
            "--password-stdin",
        ])
        .write_stdin("test-pw\n")
        .timeout(timeout)
        .assert()
        .failure()
        .stderr(predicates::str::contains("larger than 64 KiB"));
}

// -- trusted comment hygiene --

fn trusted_comment_of(sig: &std::path::Path) -> String {
    pqsign::format::read_signature(sig).unwrap().trusted_comment
}

#[test]
fn test_cli_sign_records_file_name_only() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let file = dir.path().join("sub").join("msg.txt");
    let sig = dir.path().join("msg.txt.pqsig");
    fs::create_dir(dir.path().join("sub")).unwrap();
    fs::write(&file, b"data").unwrap();
    generate_key(&sk);

    // An absolute path as typed used to end up in the comment in full.
    sign_file(&file, &sk, &sig);

    let comment = trusted_comment_of(&sig);
    assert!(comment.contains("\tfile:msg.txt"), "got: {comment:?}");
    assert!(!comment.contains("sub"), "got: {comment:?}");
}

#[cfg(unix)]
#[test]
fn test_cli_sign_escapes_odd_file_names() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let pk = dir.path().join("test.key.pub");
    let file = dir.path().join("a\tb\nc\u{202e}d.txt");
    let sig = dir.path().join("odd.pqsig");
    fs::write(&file, b"data").unwrap();
    generate_key(&sk);

    sign_file(&file, &sk, &sig);

    assert!(
        trusted_comment_of(&sig).ends_with("\tfile:a\\tb\\nc\\u{202e}d.txt"),
        "got: {:?}",
        trusted_comment_of(&sig)
    );
    cmd()
        .args(["verify", file.to_str().unwrap(), "-p", pk.to_str().unwrap(), "-x", sig.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::contains("file:a\\tb\\nc\\u{202e}d.txt"));
}

/// The password file does not exist: an error about it would mean the comment was checked too late.
#[test]
fn test_cli_sign_rejects_bad_comment_before_password() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let file = dir.path().join("msg.txt");
    fs::write(&file, b"data").unwrap();
    generate_key(&sk);

    let long = "x".repeat(1100);
    for (comment, expected) in [
        ("release\x1b[2K", "forbidden character"),
        ("a\u{202e}b", "forbidden character"),
        (long.as_str(), "too long"),
    ] {
        cmd()
            .args([
                "sign",
                file.to_str().unwrap(),
                "-s",
                sk.to_str().unwrap(),
                "-t",
                comment,
                "--password-file",
                "/no/such/password",
            ])
            .assert()
            .failure()
            .stderr(predicates::str::contains(expected).and(predicates::str::contains("no such file").not()));
    }
}

#[test]
fn test_cli_sign_allows_tab_in_comment() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
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
            "version:1.2\tchannel:stable",
            "--password-stdin",
        ])
        .write_stdin("test-pw\n")
        .assert()
        .success();

    assert!(trusted_comment_of(&sig).ends_with("\tversion:1.2\tchannel:stable"));
}

#[test]
fn test_cli_inspect_labels_comment_unverified() {
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
        .stdout(predicates::str::contains("Comment (unverified): timestamp:").and(predicates::str::contains("Trusted comment").not()));
}

#[test]
fn test_cli_rejects_signature_with_forbidden_comment() {
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
            "abcd",
            "--password-stdin",
        ])
        .write_stdin("test-pw\n")
        .assert()
        .success();
    let mut data = fs::read(&sig).unwrap();
    let len = data.len();
    data[len - 4..].copy_from_slice(b"a\x1b[K");
    fs::write(&sig, &data).unwrap();

    cmd()
        .args(["verify", file.to_str().unwrap(), "-p", pk.to_str().unwrap(), "-x", sig.to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicates::str::is_empty())
        .stderr(predicates::str::contains("forbidden character (\\u{1b})"));
    cmd()
        .args(["inspect", sig.to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicates::str::is_empty())
        .stderr(predicates::str::contains("forbidden character"));
}

// -- fingerprints --

#[test]
fn test_cli_generate_inspect_and_verify_show_the_same_fingerprint() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let pk = dir.path().join("test.key.pub");
    let file = dir.path().join("msg.txt");
    let sig = dir.path().join("msg.txt.pqsig");
    fs::write(&file, b"data").unwrap();

    generate_key(&sk);
    let expected = format!("Fingerprint: {}", pqsign::format::read_public_key(&pk).unwrap().fingerprint());

    cmd()
        .args(["generate", "-s", dir.path().join("other.key").to_str().unwrap(), "--password-stdin"])
        .write_stdin("pw\n")
        .assert()
        .success()
        .stderr(predicates::str::contains("Fingerprint: BLAKE2b-256:"));
    cmd()
        .args(["inspect", pk.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::contains(expected.as_str()));

    sign_file(&file, &sk, &sig);
    cmd()
        .args(["verify", file.to_str().unwrap(), "-p", pk.to_str().unwrap(), "-x", sig.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::contains(expected.as_str()));
}

// -- signature formats --

#[test]
fn test_cli_sign_writes_v2_by_default_and_v1_on_request() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("test.key");
    let pk = dir.path().join("test.key.pub");
    let file = dir.path().join("msg.txt");
    let v2 = dir.path().join("msg.txt.pqsig");
    let v1 = dir.path().join("msg.txt.v1.pqsig");
    fs::write(&file, b"data").unwrap();
    generate_key(&sk);
    let fingerprint = pqsign::format::read_public_key(&pk).unwrap().fingerprint();

    sign_file(&file, &sk, &v2);
    cmd()
        .args([
            "sign",
            file.to_str().unwrap(),
            "-s",
            sk.to_str().unwrap(),
            "-x",
            v1.to_str().unwrap(),
            "--format",
            "v1",
            "--password-stdin",
        ])
        .write_stdin("test-pw\n")
        .assert()
        .success();

    cmd()
        .args(["inspect", v2.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::contains("Signature (format v2)").and(predicates::str::contains(format!("Signer (unverified):  {fingerprint}"))));
    cmd()
        .args(["inspect", v1.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::contains("Signature (format v1)").and(predicates::str::contains("Signer").not()));

    for sig in [&v2, &v1] {
        cmd()
            .args(["verify", file.to_str().unwrap(), "-p", pk.to_str().unwrap(), "-x", sig.to_str().unwrap()])
            .assert()
            .success();
    }
}

#[test]
fn test_cli_verify_names_both_keys_when_the_signer_differs() {
    let dir = tempfile::tempdir().unwrap();
    let sk = dir.path().join("signer.key");
    let other = dir.path().join("other.key");
    let file = dir.path().join("msg.txt");
    let sig = dir.path().join("msg.txt.pqsig");
    fs::write(&file, b"data").unwrap();
    generate_key(&sk);
    generate_key(&other);
    sign_file(&file, &sk, &sig);

    let signer = pqsign::format::read_public_key(&dir.path().join("signer.key.pub")).unwrap().fingerprint();
    let given = pqsign::format::read_public_key(&dir.path().join("other.key.pub")).unwrap().fingerprint();

    cmd()
        .args([
            "verify",
            file.to_str().unwrap(),
            "-p",
            dir.path().join("other.key.pub").to_str().unwrap(),
            "-x",
            sig.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(format!(
            "signed by key {signer}, but the public key is {given}"
        )));
}

#[test]
fn test_cli_sign_rejects_unknown_format() {
    cmd()
        .args(["sign", "msg.txt", "--format", "v3"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("invalid value 'v3'"));
}

// -- KDF parameters read from key files --

/// Overwrites the Argon2id parameters stored in a secret key file: memory limit and iteration count as u64 LE
/// after the 14-byte header and the 1-byte algorithm ID.
fn patch_kdf(sk: &std::path::Path, mem_limit: Option<u64>, ops_limit: Option<u64>) {
    let mut data = fs::read(sk).unwrap();
    if let Some(mem) = mem_limit {
        data[15..23].copy_from_slice(&mem.to_le_bytes());
    }
    if let Some(ops) = ops_limit {
        data[23..31].copy_from_slice(&ops.to_le_bytes());
    }
    fs::write(sk, data).unwrap();
}

/// The password file does not exist: an error about it would mean the parameters were checked too late.
#[test]
fn test_cli_rejects_excessive_kdf_parameters_before_the_password() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("msg.txt");
    fs::write(&file, b"data").unwrap();

    let cases = [
        (None, Some(1_000_000), "asks for 1000000 Argon2id iterations; pqsign accepts at most 16"),
        (Some((1u64 << 42) + 256 * 1024 * 1024), None, "asks for 4194560 MiB of Argon2id memory"),
        (None, Some(0), "invalid Argon2id parameters"),
    ];
    for (i, (mem, ops, expected)) in cases.into_iter().enumerate() {
        let sk = dir.path().join(format!("key{i}.key"));
        generate_key(&sk);
        patch_kdf(&sk, mem, ops);

        cmd()
            .args([
                "sign",
                file.to_str().unwrap(),
                "-s",
                sk.to_str().unwrap(),
                "--password-file",
                "/no/such/password",
            ])
            .timeout(std::time::Duration::from_secs(30))
            .assert()
            .failure()
            .stderr(predicates::str::contains(expected).and(predicates::str::contains("no such file").not()));
        cmd()
            .args(["inspect", sk.to_str().unwrap()])
            .assert()
            .failure()
            .stdout(predicates::str::is_empty())
            .stderr(predicates::str::contains(expected));
    }
}

// -- exit status --

/// 0 on success, 1 if a signature does not verify, 2 for any other error, like minisign and gpgv.
#[test]
fn test_cli_exit_status() {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name);
    let arg = |name: &str| path(name).to_str().unwrap().to_owned();

    fs::write(path("f.txt"), b"data").unwrap();
    fs::write(path("g.txt"), b"other data").unwrap();
    fs::write(path("wrong.txt"), b"wrong\n").unwrap();
    generate_key(&path("a.key"));
    generate_key(&path("b.key"));
    sign_file(&path("f.txt"), &path("a.key"), &path("f.txt.pqsig"));
    cmd()
        .args([
            "sign",
            &arg("f.txt"),
            "-s",
            &arg("a.key"),
            "-x",
            &arg("f.v1.pqsig"),
            "--format",
            "v1",
            "--password-stdin",
        ])
        .write_stdin("test-pw\n")
        .assert()
        .success();
    fs::copy(path("f.txt.pqsig"), path("g.txt.pqsig")).unwrap();
    fs::write(path("broken.pqsig"), &fs::read(path("f.txt.pqsig")).unwrap()[..100]).unwrap();

    let cases: Vec<(&str, Vec<String>, i32)> = vec![
        ("valid signature", vec!["verify".into(), arg("f.txt"), "-p".into(), arg("a.key.pub")], 0),
        (
            "file changed after signing",
            vec!["verify".into(), arg("g.txt"), "-p".into(), arg("a.key.pub")],
            1,
        ),
        (
            "v2 signature, wrong key",
            vec!["verify".into(), arg("f.txt"), "-p".into(), arg("b.key.pub")],
            1,
        ),
        (
            "v1 signature, wrong key",
            vec![
                "verify".into(),
                arg("f.txt"),
                "-p".into(),
                arg("b.key.pub"),
                "-x".into(),
                arg("f.v1.pqsig"),
            ],
            1,
        ),
        (
            "signed file missing",
            vec![
                "verify".into(),
                arg("nope.txt"),
                "-p".into(),
                arg("a.key.pub"),
                "-x".into(),
                arg("f.txt.pqsig"),
            ],
            2,
        ),
        (
            "signature file missing",
            vec![
                "verify".into(),
                arg("g.txt"),
                "-p".into(),
                arg("a.key.pub"),
                "-x".into(),
                arg("nope.pqsig"),
            ],
            2,
        ),
        ("public key missing", vec!["verify".into(), arg("f.txt"), "-p".into(), arg("nope.pub")], 2),
        (
            "signature file truncated",
            vec![
                "verify".into(),
                arg("f.txt"),
                "-p".into(),
                arg("a.key.pub"),
                "-x".into(),
                arg("broken.pqsig"),
            ],
            2,
        ),
        ("unknown option", vec!["verify".into(), arg("f.txt"), "--bogus".into()], 2),
        (
            "sign, wrong password",
            vec![
                "sign".into(),
                arg("f.txt"),
                "-s".into(),
                arg("a.key"),
                "-x".into(),
                arg("x.pqsig"),
                "--password-file".into(),
                arg("wrong.txt"),
            ],
            2,
        ),
        (
            "generate, key exists",
            vec!["generate".into(), "-s".into(), arg("a.key"), "--password-file".into(), arg("wrong.txt")],
            2,
        ),
        ("inspect, not a pqsign file", vec!["inspect".into(), arg("wrong.txt")], 2),
        ("no subcommand", vec![], 2),
    ];

    for (label, args, expected) in cases {
        let output = cmd().args(&args).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{label}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn test_cli_inspect_reports_both_files_when_neither_is_pqsign() {
    let dir = tempfile::tempdir().unwrap();
    let notes = dir.path().join("notes.txt");
    fs::write(&notes, b"hello").unwrap();

    let notes = notes.to_str().unwrap();
    cmd().args(["inspect", notes]).assert().code(2).stderr(predicates::str::contains(format!(
        "{notes} is not a pqsign file, and {notes}.pqsig does not exist"
    )));
}

// -- file names that are not valid UTF-8 --

/// Two files whose names differ only in a byte that is not valid UTF-8 used to share one signature file.
/// Linux allows such names; macOS's APFS rejects them, so the test skips itself there.
#[cfg(unix)]
#[test]
fn test_cli_signs_files_whose_names_are_not_utf8() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join(OsStr::from_bytes(b"caf\xe9.txt"));
    let second = dir.path().join(OsStr::from_bytes(b"caf\xe8.txt"));
    if fs::write(&first, b"first").is_err() {
        eprintln!("skipped: this file system rejects file names that are not valid UTF-8");
        return;
    }
    fs::write(&second, b"second").unwrap();

    let sk = dir.path().join("test.key");
    let pk = dir.path().join("test.key.pub");
    generate_key(&sk);

    let cases = [
        (&first, &b"caf\xe9.txt.pqsig"[..], "file:caf\\xe9.txt"),
        (&second, &b"caf\xe8.txt.pqsig"[..], "file:caf\\xe8.txt"),
    ];
    for (file, _, _) in cases {
        cmd()
            .arg("sign")
            .arg(file)
            .args(["-s", sk.to_str().unwrap(), "--password-stdin"])
            .write_stdin("test-pw\n")
            .assert()
            .success();
    }
    for (file, signature, comment) in cases {
        assert!(
            dir.path().join(OsStr::from_bytes(signature)).exists(),
            "missing {}",
            signature.escape_ascii()
        );
        cmd()
            .arg("verify")
            .arg(file)
            .args(["-p", pk.to_str().unwrap()])
            .assert()
            .success()
            .stdout(predicates::str::contains(comment));
    }
}
