#![forbid(unsafe_code)]

use std::panic;
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use pqsign::commands::{change_password, generate, inspect, sign, verify};
use pqsign::domain::SignatureFormat;
use pqsign::errors::Error;
use pqsign::format::Kdf;
use pqsign::password::PasswordSource;
use pqsign::terminal::SafeText;

/// Exit status when a signature does not verify. Like minisign and gpgv, every other error exits with 2, as
/// usage errors from clap already do, so scripts can tell a bad signature from a check that could not happen.
const EXIT_NOT_VERIFIED: u8 = 1;
const EXIT_ERROR: u8 = 2;

const EXIT_STATUS_HELP: &str = "Exit status: 0 on success, 1 if a signature does not verify, 2 for any other error.";

/// Stack size of the thread that runs pqsign. `fips204` keeps ML-DSA-65 keys (17 KiB expanded) and its working values
/// on the stack. On the main thread on macOS, a debug build of `sign` needs 512 to 768 KiB with `fips204` optimized,
/// as Cargo.toml sets it for tests, and 768 KiB to 1 MiB without; an unoptimized build has overflowed the 1 MiB a
/// Windows main thread gets. 8 MiB matches the main thread on Linux and macOS and leaves room on every platform.
const STACK_SIZE: usize = 8 * 1024 * 1024;

const CHANGE_PASSWORD_HELP: &str = "\
The key, its key ID, its fingerprint and its .pub file stay the same, so existing signatures still verify and \
nobody needs the public key again. The file is replaced, not edited in place, and written with pqsign's \
default Argon2id parameters (256 MiB, 3 passes).

--password-stdin and --password-file give the current password; --new-password-file gives the new one.

A new password does not protect copies of the secret key file made before the change: backups, synced copies, \
other hard links to the file. If the secret key file and its password were exposed together, generate a new key.";

fn main() -> ExitCode {
    // Named "main" so that a panic message reads the same as on the real main thread.
    let worker = thread::Builder::new().name("main".into()).stack_size(STACK_SIZE).spawn(run);
    match worker {
        // Re-raise a panic here so that it exits with the same status as a panic on the main thread.
        Ok(handle) => handle.join().unwrap_or_else(|payload| panic::resume_unwind(payload)),
        // The thread could not be created (out of memory): try on the main thread instead.
        Err(_) => run(),
    }
}

fn run() -> ExitCode {
    match Cli::parse().run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Paths in errors are escaped where they are formatted; this also covers any message that is not.
            eprintln!("error: {}", SafeText(&e.to_string()));
            let code = if e.is_verification_failure() { EXIT_NOT_VERIFIED } else { EXIT_ERROR };
            ExitCode::from(code)
        }
    }
}

/// Where to get the secret key password from. Without either option, pqsign prompts on the terminal.
#[derive(Args)]
#[group(multiple = false)]
struct PasswordArgs {
    /// Read the password from the first line of standard input
    #[arg(long)]
    password_stdin: bool,

    /// Read the password from the first line of a file
    #[arg(long, value_name = "PATH")]
    password_file: Option<PathBuf>,
}

impl From<PasswordArgs> for PasswordSource {
    fn from(args: PasswordArgs) -> Self {
        match args {
            PasswordArgs { password_stdin: true, .. } => PasswordSource::Stdin,
            PasswordArgs {
                password_file: Some(path), ..
            } => PasswordSource::File(path),
            PasswordArgs { .. } => PasswordSource::Prompt,
        }
    }
}

/// The `-s` option of every command that uses a secret key.
#[derive(Args)]
struct SecretKeyArg {
    #[arg(short = 's', long = "secret-key", help = "Secret key file path [default: ~/.pqsign/default.key]")]
    secret_key: Option<PathBuf>,
}

/// Signature format to write.
#[derive(Clone, Copy, ValueEnum)]
enum FormatArg {
    /// The current format
    V2,
    /// The format of pqsign 0.1, for verifiers that cannot read v2 yet
    V1,
}

impl From<FormatArg> for SignatureFormat {
    fn from(arg: FormatArg) -> Self {
        match arg {
            FormatArg::V2 => SignatureFormat::V2,
            FormatArg::V1 => SignatureFormat::V1,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new key pair
    #[command(after_help = "The public key is written alongside the secret key with a .pub extension.")]
    Generate {
        #[command(flatten)]
        secret_key: SecretKeyArg,

        /// Overwrite existing key files
        #[arg(short = 'f', long, alias = "force")]
        overwrite: bool,

        #[command(flatten)]
        password: PasswordArgs,
    },

    /// Sign a file
    Sign {
        /// File to sign
        file: PathBuf,

        #[command(flatten)]
        secret_key: SecretKeyArg,

        /// Signature file path
        #[arg(short = 'x', long = "sig-file")]
        sig_file: Option<PathBuf>,

        /// Trusted comment
        #[arg(short = 't', long = "trusted-comment")]
        trusted_comment: Option<String>,

        /// Signature format
        #[arg(long, value_enum, default_value_t = FormatArg::V2)]
        format: FormatArg,

        #[command(flatten)]
        password: PasswordArgs,
    },

    /// Change the password of a secret key
    #[command(after_help = CHANGE_PASSWORD_HELP)]
    ChangePassword {
        #[command(flatten)]
        secret_key: SecretKeyArg,

        #[command(flatten)]
        password: PasswordArgs,

        /// Read the new password from the first line of a file
        #[arg(long, value_name = "PATH")]
        new_password_file: Option<PathBuf>,
    },

    /// Verify a signature
    #[command(
        after_help = "Exit status: 0 if the signature is valid, 1 if it does not verify (the file changed or another key \
                            made it), 2 if it could not be checked (missing or malformed files)."
    )]
    Verify {
        /// File to verify
        file: PathBuf,

        #[arg(
            short = 'p',
            long = "public-key",
            conflicts_with = "public_key_string",
            help = "Public key file path [default: ~/.pqsign/default.key.pub]"
        )]
        public_key: Option<PathBuf>,

        /// Public key as inline string (e.g. "pqsign:v1:...")
        #[arg(short = 'P', long = "public-key-string", conflicts_with = "public_key")]
        public_key_string: Option<String>,

        /// Signature file path
        #[arg(short = 'x', long = "sig-file")]
        sig_file: Option<PathBuf>,

        /// Suppress output, rely on exit code only
        #[arg(short = 'q', long)]
        quiet: bool,
    },

    /// Inspect a key or signature file
    Inspect {
        /// File to inspect (.pub, .key, or .pqsig)
        file: PathBuf,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: Shell,
    },

    /// Print version information (same as --version)
    #[command(hide = true)]
    Version,
}

#[derive(Parser)]
#[command(name = "pqsign", version, about = "Hybrid post-quantum file signing (Ed25519 + ML-DSA-65)", after_help = EXIT_STATUS_HELP)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    fn run(self) -> Result<(), Error> {
        match self.command {
            Command::Generate {
                secret_key,
                overwrite,
                password,
            } => generate::run(generate::Options {
                secret_key: secret_key.secret_key,
                password: password.into(),
                overwrite,
                kdf: Kdf::argon2id(),
            }),

            Command::Sign {
                file,
                secret_key,
                sig_file,
                trusted_comment,
                format,
                password,
            } => sign::run(sign::Options {
                file,
                secret_key: secret_key.secret_key,
                sig_file,
                trusted_comment,
                password: password.into(),
                format: format.into(),
            }),

            Command::ChangePassword {
                secret_key,
                password,
                new_password_file,
            } => change_password::run(change_password::Options {
                secret_key: secret_key.secret_key,
                password: password.into(),
                new_password: new_password_file.map_or(PasswordSource::Prompt, PasswordSource::File),
                kdf: Kdf::argon2id(),
            }),

            Command::Verify {
                file,
                public_key,
                public_key_string,
                sig_file,
                quiet,
            } => verify::run(verify::Options {
                file,
                public_key,
                public_key_string,
                sig_file,
                quiet,
            }),

            Command::Inspect { file } => inspect::run(&file),

            Command::Completions { shell } => {
                clap_complete::generate(shell, &mut Cli::command(), "pqsign", &mut std::io::stdout());
                Ok(())
            }

            Command::Version => {
                println!("pqsign {}", env!("CARGO_PKG_VERSION"));
                Ok(())
            }
        }
    }
}
