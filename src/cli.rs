use clap::Parser;
use std::path::PathBuf;

use crate::input::*;

/// biscuit creation and inspection CLI. Run `biscuit --help` to see what's available.
#[derive(Parser)]
#[clap(version, author)]
pub struct Opts {
    #[clap(subcommand)]
    pub subcmd: SubCommand,
}

#[derive(Parser)]
pub enum SubCommand {
    #[clap(name = "keypair")]
    KeyPairCmd(KeyPairCmd),
    Inspect(Inspect),
    InspectSnapshot(InspectSnapshot),
    Generate(Generate),
    Attenuate(Attenuate),
    GenerateRequest(GenerateRequest),
    GenerateThirdPartyBlock(GenerateThirdPartyBlock),
    AppendThirdPartyBlock(AppendThirdPartyBlock),
    Seal(Seal),
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
    /// Provide a root key id, as a hint for public key selection
    #[clap(long)]
    pub root_key_id: Option<u32>,
    #[clap(flatten)]
    pub param_arg: common_args::ParamArg,
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
    /// Add a TTL check to the generated authority block (either a RFC3339 datetime or a duration like '1d')
    #[clap(long, parse(try_from_str = parse_ttl))]
    pub add_ttl: Option<Ttl>,
}

/// Attenuate an existing biscuit by adding a new block
#[derive(Parser)]
pub struct Attenuate {
    #[clap(flatten)]
    pub biscuit_input_args: common_args::BiscuitInputArgs,
    /// Output the biscuit raw bytes directly, with no base64 encoding
    #[clap(long)]
    pub raw_output: bool,
    #[clap(flatten)]
    pub block_args: common_args::BlockArgs,
    #[clap(flatten)]
    pub param_arg: common_args::ParamArg,
}

/// Attenuate an existing biscuit by adding a new third-party block
#[derive(Parser)]
pub struct AppendThirdPartyBlock {
    #[clap(flatten)]
    pub biscuit_input_args: common_args::BiscuitInputArgs,
    /// Output the biscuit raw bytes directly, with no base64 encoding
    #[clap(long)]
    pub raw_output: bool,
    /// The third-party block to append to the token.
    #[clap(long)]
    pub block_contents: Option<String>,
    /// The third-party block to append to the token
    #[clap(
        long,
        parse(from_os_str),
        conflicts_with("block-contents"),
        required_unless_present("block-contents")
    )]
    pub block_contents_file: Option<PathBuf>,
    /// Read the third-party block contents raw bytes directly, with no base64 parsing
    #[clap(long, requires("block-contents-file"))]
    pub raw_block_contents: bool,
}

/// Inspect a biscuit and optionally check its public key
#[derive(Parser)]
pub struct Inspect {
    /// Output the results in a machine-readable format
    #[clap(long)]
    pub json: bool,
    #[clap(flatten)]
    pub biscuit_input_args: common_args::BiscuitInputArgs,
    /// Check the biscuit public key
    #[clap(long, conflicts_with("public-key-file"))]
    pub public_key: Option<String>,
    /// Check the biscuit public key
    #[clap(long, conflicts_with("public-key"), parse(from_os_str))]
    pub public_key_file: Option<PathBuf>,
    /// Read the public key raw bytes directly
    #[clap(long, requires("public-key-file"), conflicts_with("public-key"))]
    pub raw_public_key: bool,
    #[clap(flatten)]
    pub authorization_args: common_args::AuthorizeArgs,
    #[clap(flatten)]
    pub query_args: common_args::QueryArgs,
    #[clap(flatten)]
    pub param_arg: common_args::ParamArg,
    /// Save an authorizer snapshot to a file
    #[clap(long, parse(from_os_str))]
    pub dump_snapshot_to: Option<PathBuf>,
    /// Output the snapshot raw bytes directly, with no base64 encoding
    #[clap(long, requires("dump-snapshot-to"))]
    pub dump_raw_snapshot: bool,
}

/// Inspect a snapshot
#[derive(Parser)]
pub struct InspectSnapshot {
    /// Output the results in a machine-readable format
    #[clap(long)]
    pub json: bool,
    /// Read the snapshot from the given file (or use `-` to read from stdin)
    #[clap(parse(from_os_str))]
    pub snapshot_file: PathBuf,
    /// Read the snapshot raw bytes directly, with no base64 parsing
    #[clap(long)]
    pub raw_input: bool,
    #[clap(flatten)]
    pub authorization_args: common_args::AuthorizeArgs,
    #[clap(flatten)]
    pub query_args: common_args::QueryArgs,
    #[clap(flatten)]
    pub param_arg: common_args::ParamArg,
}

/// Generate a third-party block request from an existing biscuit
#[derive(Parser)]
pub struct GenerateRequest {
    #[clap(flatten)]
    pub biscuit_input_args: common_args::BiscuitInputArgs,
    /// Output the request raw bytes directly, with no base64 encoding
    #[clap(long)]
    pub raw_output: bool,
}

/// Generate a third-party block from a request
#[derive(Parser)]
pub struct GenerateThirdPartyBlock {
    /// Read the request from the given file (or use `-` to read from stdin)
    #[clap(parse(from_os_str))]
    pub request_file: PathBuf,
    /// Read the request raw bytes directly, with no base64 parsing
    #[clap(long)]
    pub raw_input: bool,
    /// The private key used to sign the third-party block
    #[clap(long, required_unless_present("private-key-file"))]
    pub private_key: Option<String>,
    /// The private key used to sign the third-party block
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
    /// Output the block raw bytes directly, with no base64 encoding
    #[clap(long)]
    pub raw_output: bool,
    #[clap(flatten)]
    pub block_args: common_args::BlockArgs,
    #[clap(flatten)]
    pub param_arg: common_args::ParamArg,
}

/// Seal a token, preventing further attenuation
#[derive(Parser)]
pub struct Seal {
    #[clap(flatten)]
    pub biscuit_input_args: common_args::BiscuitInputArgs,
    /// Output the biscuit raw bytes directly, with no base64 encoding
    #[clap(long)]
    pub raw_output: bool,
}

mod common_args {
    use crate::input::*;
    use biscuit_auth::builder::Rule;
    use chrono::Duration;
    use clap::Parser;
    use std::path::PathBuf;

    /// Arguments related to queries
    #[derive(Parser)]
    pub struct QueryArgs {
        /// Query the authorizer after evaluation. If no authorizer is provided, query the token after evaluation.
        #[clap(
        long,
        value_parser = clap::builder::ValueParser::new(parse_rule),
    )]
        pub query: Option<Rule>,
        /// Query facts from all blocks (not just authority, authorizer or explicitly trusted blocks). Be careful, this can return untrustworthy facts.
        #[clap(long, requires("query"))]
        pub query_all: bool,
    }

    /// Arguments related to providing datalog parameters
    #[derive(Parser)]
    pub struct ParamArg {
        /// Provide a value for a datalog parameter. `type` is optional and defaults to `string`. Possible types are pubkey, string, integer, date, bytes or bool.
        /// Bytes values must be hex-encoded and start with `hex:`
        /// Public keys must be hex-encoded and start with `ed25519/`
        #[clap(
        long,
        value_parser = clap::builder::ValueParser::new(parse_param),
        value_name = "key[:type]=value"
    )]
        pub param: Vec<Param>,
    }

    /// Arguments related to running authorization
    #[derive(Parser)]
    pub struct AuthorizeArgs {
        /// Open $EDITOR to provide an authorizer.
        #[clap(
            long,
            alias("verify-interactive"),
            conflicts_with("authorize-with"),
            conflicts_with("authorize-with-file")
        )]
        pub authorize_interactive: bool,
        /// Authorize the biscuit with the provided authorizer.
        #[clap(
            long,
            parse(from_os_str),
            alias("verify-with-file"),
            conflicts_with("authorize-with"),
            conflicts_with("authorize-interactive")
        )]
        pub authorize_with_file: Option<PathBuf>,
        /// Authorize the biscuit with the provided authorizer
        #[clap(
            long,
            alias("verify-with"),
            conflicts_with("authorize-with-file"),
            conflicts_with("authorize-interactive")
        )]
        pub authorize_with: Option<String>,
        /// Configure the maximum amount of facts that can be generated
        /// before aborting evaluation
        #[clap(
            long,
            requires("authorize-with"),
            requires("authorize-interactive"),
            requires("authorize-with-file")
        )]
        pub max_facts: Option<u64>,
        /// Configure the maximum amount of iterations before aborting
        /// evaluation
        #[clap(
            long,
            requires("authorize-with"),
            requires("authorize-interactive"),
            requires("authorize-with-file")
        )]
        pub max_iterations: Option<u64>,
        /// Configure the maximum evaluation duration before aborting
        #[clap(
            long,
            requires("authorize-with"),
            requires("authorize-interactive"),
            requires("authorize-with-file"),
            parse(try_from_str = parse_duration)
        )]
        pub max_time: Option<Duration>,
        /// Include the current time in the verifier facts
        #[clap(long)]
        pub include_time: bool,
    }

    /// Arguments related to defining a block
    #[derive(Parser)]
    pub struct BlockArgs {
        /// The block to append to the token. If `--block` and `--block-file` are omitted, an interactive $EDITOR will be opened.
        #[clap(long)]
        pub block: Option<String>,
        /// The block to append to the token. If `--block` and `--block-file` are omitted, an interactive $EDITOR will be opened.
        #[clap(long, parse(from_os_str), conflicts_with = "block")]
        pub block_file: Option<PathBuf>,
        /// The optional context string attached to the new block
        #[clap(long)]
        pub context: Option<String>,
        /// Add a TTL check to the generated block (either a RFC3339 datetime or a duration like '1d')
        #[clap(long, parse(try_from_str = parse_ttl))]
        pub add_ttl: Option<Ttl>,
    }

    /// Arguments related to reading a biscuit
    #[derive(Parser)]
    pub struct BiscuitInputArgs {
        /// Read the biscuit from the given file (or use `-` to read from stdin)
        #[clap(parse(from_os_str))]
        pub biscuit_file: PathBuf,
        /// Read the biscuit raw bytes directly, with no base64 parsing
        #[clap(long)]
        pub raw_input: bool,
    }
}

#[test]
fn verify_cli() {
    use clap::CommandFactory;
    Opts::command().debug_assert();
}
