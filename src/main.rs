use std::path::PathBuf;
use std::process;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use pqsign::commands::{generate, inspect, sign, verify};
use pqsign::errors::Error;

fn main() {
    if let Err(e) = Cli::parse().run() {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new key pair
    #[command(
        after_help = "The public key is written alongside the secret key with a .pub extension."
    )]
    Generate {
        #[arg(
            short = 's',
            long = "secret-key",
            help = "Secret key file path [default: ~/.pqsign/default.key]"
        )]
        secret_key: Option<PathBuf>,

        /// Overwrite existing key files
        #[arg(short = 'f', long, alias = "force")]
        overwrite: bool,
    },

    /// Sign a file
    Sign {
        /// File to sign
        file: PathBuf,

        #[arg(
            short = 's',
            long = "secret-key",
            help = "Secret key file path [default: ~/.pqsign/default.key]"
        )]
        secret_key: Option<PathBuf>,

        /// Signature file path
        #[arg(short = 'x', long = "sig-file")]
        sig_file: Option<PathBuf>,

        /// Trusted comment
        #[arg(short = 't', long = "trusted-comment")]
        trusted_comment: Option<String>,
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
}

#[derive(Parser)]
#[command(
    name = "pqsign",
    version,
    about = "Hybrid post-quantum file signing (Ed25519 + ML-DSA-65)"
)]
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
            } => generate::run(generate::Options {
                secret_key,
                password: None,
                overwrite,
            }),

            Command::Sign {
                file,
                secret_key,
                sig_file,
                trusted_comment,
            } => sign::run(sign::Options {
                file,
                secret_key,
                sig_file,
                trusted_comment,
                password: None,
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
                clap_complete::generate(
                    shell,
                    &mut Cli::command(),
                    "pqsign",
                    &mut std::io::stdout(),
                );
                Ok(())
            }
        }
    }
}
