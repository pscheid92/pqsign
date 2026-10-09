use std::path::PathBuf;
use std::process;

use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use pqsign::commands::{generate, inspect, sign, verify};
use pqsign::errors::Error;
use pqsign::password::PasswordSource;

fn main() {
    if let Err(e) = Cli::parse().run() {
        eprintln!("error: {e}");
        process::exit(1);
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

#[derive(Subcommand)]
enum Command {
    /// Generate a new key pair
    #[command(after_help = "The public key is written alongside the secret key with a .pub extension.")]
    Generate {
        #[arg(short = 's', long = "secret-key", help = "Secret key file path [default: ~/.pqsign/default.key]")]
        secret_key: Option<PathBuf>,

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

        #[arg(short = 's', long = "secret-key", help = "Secret key file path [default: ~/.pqsign/default.key]")]
        secret_key: Option<PathBuf>,

        /// Signature file path
        #[arg(short = 'x', long = "sig-file")]
        sig_file: Option<PathBuf>,

        /// Trusted comment
        #[arg(short = 't', long = "trusted-comment")]
        trusted_comment: Option<String>,

        #[command(flatten)]
        password: PasswordArgs,
    },

    /// Verify a signature
    #[command(after_help = "Exits 0 if the signature is valid, 1 otherwise.")]
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

    /// Print version information
    Version,
}

#[derive(Parser)]
#[command(name = "pqsign", version, about = "Hybrid post-quantum file signing (Ed25519 + ML-DSA-65)")]
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
                secret_key,
                password: password.into(),
                overwrite,
            }),

            Command::Sign {
                file,
                secret_key,
                sig_file,
                trusted_comment,
                password,
            } => sign::run(sign::Options {
                file,
                secret_key,
                sig_file,
                trusted_comment,
                password: password.into(),
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

            Command::Inspect { file } => inspect::run(file),

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
