use clap::Parser;
use std::path::PathBuf;

/// biscuit creation and inspection CLI. Run `biscuit --help` to see what's available.
#[derive(Parser)]
#[clap(version = "1.0", author = "Clément D. <clement@delafargue.name>")]
pub struct Opts {
    // /// Sets a custom config file. Could have been an Option<T> with no default too
    // #[clap(short, long, default_value = "default.conf")]
    // config: String,
    // /// Some input. Because this isn't an Option<T> it's required to be used
    // input: String,
    // /// A level of verbosity, and can be used multiple times
    // #[clap(short, long, parse(from_occurrences))]
    // verbose: i32,
    #[clap(subcommand)]
    pub subcmd: SubCommand,
}

#[derive(Parser)]
pub enum SubCommand {
    #[clap(name = "keypair")]
    KeyPairCmd(KeyPairCmd),
    #[clap()]
    Inspect(Inspect),
    #[clap()]
    Generate(Generate),
    #[clap()]
    Attenuate(Attenuate),
}

/// Create and manipulate key pairs
#[derive(Parser)]
pub struct KeyPairCmd {
    /// Generate the keypair from the given private key. If omitted, a random keypair will be generated
    #[clap(long, conflicts_with("from-private-key-file"))]
    pub from_private_key: Option<String>,
    /// Generate the keypair from a private key stored in the given file (or use `-` to read it from stdin). If omitted, a random keypair will be generated
    #[clap(long, parse(from_os_str))]
    pub from_private_key_file: Option<PathBuf>,
    /// Read the private key raw bytes directly, with no hex decoding
    #[clap(long, requires("from-private-key-file"))]
    pub from_raw_private_key: bool,
    /// Only output the public part of the key pair
    #[clap(long, conflicts_with("only-private-key"))]
    pub only_public_key: bool,
    /// Output the public key raw bytes directly, with no hex encoding
    #[clap(long, requires("only-public-key"))]
    pub raw_public_key_output: bool,
    /// Only output the public part of the key pair
    #[clap(long, conflicts_with("only-public-key"))]
    pub only_private_key: bool,
    /// Output the private key raw bytes directly, with no hex encoding
    #[clap(long, requires("only-private-key"))]
    pub raw_private_key_output: bool,
}

/// Generate a biscuit from a private key and an authority block
#[derive(Parser)]
pub struct Generate {
    /// Read the authority block from the given file (or use `-` to read from stdin). If omitted, an interactive $EDITOR will be opened.
    #[clap(parse(from_os_str))]
    pub authority_file: Option<PathBuf>,
    /// Output the biscuit raw bytes directly, with no base64 encoding
    #[clap(long)]
    pub raw: bool,
    /// The private key used to sign the token
    #[clap(long, required_unless_present("private-key-file"))]
    pub private_key: Option<String>,
    /// The private key used to sign the token
    #[clap(
        long,
        parse(from_os_str),
        required_unless_present("private-key"),
        conflicts_with = "private-key"
    )]
    pub private_key_file: Option<PathBuf>,
    /// Read the private key raw bytes directly (only available when reading the private key from a file)
    #[clap(long, conflicts_with = "private-key", requires = "private-key-file")]
    pub raw_private_key: bool,
    /// The optional context string attached to the authority block
    #[clap(long)]
    pub context: Option<String>,
}

/// Attenuate an existing biscuit by adding a new block
#[derive(Parser)]
pub struct Attenuate {
    /// Read the biscuit from the given file (or use `-` to read from stdin)
    #[clap(parse(from_os_str))]
    pub biscuit_file: PathBuf,
    /// Read the biscuit raw bytes directly, with no base64 parsing
    #[clap(long)]
    pub raw_input: bool,
    /// Output the biscuit raw bytes directly, with no base64 encoding
    #[clap(long)]
    pub raw_output: bool,
    /// The block to append to the token. If `--block` and `--block-file` are omitted, an interactive $EDITOR will be opened.
    #[clap(long)]
    pub block: Option<String>,
    /// The block to append to the token. If `--block` and `--block-file` are omitted, an interactive $EDITOR will be opened.
    #[clap(long, parse(from_os_str), conflicts_with = "block")]
    pub block_file: Option<PathBuf>,
    /// The optional context string attached to the new block
    #[clap(long)]
    pub context: Option<String>,
}

/// Inspect a biscuit and optionally check its public key
#[derive(Parser)]
pub struct Inspect {
    /// Read the biscuit from the given file (or use `-` to read from stdin)
    #[clap(parse(from_os_str))]
    pub biscuit_file: PathBuf,
    /// Read the biscuit raw bytes directly, with no base64 parsing
    #[clap(long)]
    pub raw_input: bool,
    /// Check the biscuit public key
    #[clap(long, conflicts_with("public-key-file"))]
    pub public_key: Option<String>,
    /// Check the biscuit public key
    #[clap(long, conflicts_with("public-key"), parse(from_os_str))]
    pub public_key_file: Option<PathBuf>,
    /// Read the public key raw bytes directly
    #[clap(long, requires("public-key-file"), conflicts_with("public-key"))]
    pub raw_public_key: bool,
    /// Open $EDITOR to provide a authorizer.
    #[clap(
        long,
        conflicts_with("verify-with"),
        conflicts_with("verify-with-file")
    )]
    pub verify_interactive: bool,
    /// Verify the biscuit with the provided authorizer.
    #[clap(
        long,
        conflicts_with("verify-with"),
        conflicts_with("verify-interactive")
    )]
    pub verify_with_file: Option<PathBuf>,
    /// Verify the biscuit with the provided authorizer
    #[clap(
        long,
        conflicts_with("verify-with-file"),
        conflicts_with("verify-interactive")
    )]
    pub verify_with: Option<String>,
}
