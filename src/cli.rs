use biscuit_auth::{builder::Term, PublicKey};
use chrono::Duration;
use clap::Parser;
use std::convert::TryInto;
use std::path::PathBuf;

use crate::input::*;

#[derive(Debug, Clone)]
pub enum Param {
    Term(String, Term),
    PublicKey(String, PublicKey),
}

fn parse_param(kv: &str) -> Result<Param, std::io::Error> {
    use std::io::{Error, ErrorKind};
    let (name, value) = (kv.split_once('=').ok_or_else(|| Error::new(
        ErrorKind::Other,
        "Params must be `key=value` or `key=value::type` where type is pubkey, integer, date or bytes",
    )))?;
    if let Some(encoded) = value.strip_suffix("::pubkey") {
        let bytes =
            hex::decode(encoded).map_err(|e| Error::new(ErrorKind::Other, format!("{}", &e)));
        let pubkey = PublicKey::from_bytes(&bytes?)
            .map_err(|e| Error::new(ErrorKind::Other, format!("{}", &e)))?;
        Ok(Param::PublicKey(name.to_string(), pubkey))
    } else if let Some(int_str) = value.strip_suffix("::integer") {
        let int = int_str
            .parse()
            .map_err(|e| Error::new(ErrorKind::Other, format!("{}", &e)))?;
        Ok(Param::Term(name.to_string(), Term::Integer(int)))
    } else if let Some(date_str) = value.strip_suffix("::date") {
        let date =
            time::OffsetDateTime::parse(date_str, &time::format_description::well_known::Rfc3339)
                .map_err(|e| Error::new(ErrorKind::Other, format!("{}", &e)))?;
        let timestamp = date
            .unix_timestamp()
            .try_into()
            .map_err(|e| Error::new(ErrorKind::Other, format!("{}", &e)))?;
        Ok(Param::Term(name.to_string(), Term::Date(timestamp)))
    } else if let Some(bytes_str) = value.strip_suffix("::bytes") {
        let bytes =
            hex::decode(bytes_str).map_err(|e| Error::new(ErrorKind::Other, format!("{}", &e)))?;
        Ok(Param::Term(name.to_string(), Term::Bytes(bytes)))
    } else if let Some(value) = value.strip_suffix("::string") {
        Ok(Param::Term(name.to_string(), Term::Str(value.to_string())))
    } else {
        Ok(Param::Term(name.to_string(), Term::Str(value.to_string())))
    }
}

/// biscuit creation and inspection CLI. Run `biscuit --help` to see what's available.
#[derive(Parser)]
#[clap(version = "0.2.0", author = "Clément D. <clement@delafargue.name>")]
pub struct Opts {
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
    InspectSnapshot(InspectSnapshot),
    #[clap()]
    Generate(Generate),
    #[clap()]
    Attenuate(Attenuate),
    #[clap()]
    GenerateRequest(GenerateRequest),
    #[clap()]
    GenerateThirdPartyBlock(GenerateThirdPartyBlock),
    #[clap()]
    AppendThirdPartyBlock(AppendThirdPartyBlock),
    #[clap()]
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
#[derive(Parser, Debug)]
pub struct Generate {
    /// Read the authority block from the given file (or use `-` to read from stdin). If omitted, an interactive $EDITOR will be opened.
    #[clap(parse(from_os_str))]
    pub authority_file: Option<PathBuf>,
    /// Provide a value for a datalog parameter
    #[clap(
        long,
        value_parser = clap::builder::ValueParser::new(parse_param),
        value_name = "key=value::type"
    )]
    pub param: Vec<Param>,
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
    /// Add a TTL check to the generated authority block
    #[clap(long, parse(try_from_str = parse_duration))]
    pub add_ttl: Option<Duration>,
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
    /// Add a TTL check to the generated block
    #[clap(long, parse(try_from_str = parse_duration))]
    pub add_ttl: Option<Duration>,
    /// Provide a value for a datalog parameter
    #[clap(
        long,
        value_parser = clap::builder::ValueParser::new(parse_param),
        value_name = "key=value::type"
    )]
    pub param: Vec<Param>,
}

/// Attenuate an existing biscuit by adding a new third-party block
#[derive(Parser)]
pub struct AppendThirdPartyBlock {
    /// Read the biscuit from the given file (or use `-` to read from stdin)
    #[clap(parse(from_os_str))]
    pub biscuit_file: PathBuf,
    /// Read the biscuit raw bytes directly, with no base64 parsing
    #[clap(long)]
    pub raw_input: bool,
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
    #[clap(
        long,
        requires("authorize-with"),
        requires("authorize-interactive"),
        requires("authorize-with-file"),
        parse(try_from_str = parse_duration)
    )]
    /// Configure the maximum evaluation duration before aborting
    pub max_time: Option<Duration>,
    /// Include the current time in the verifier facts
    #[clap(long)]
    pub include_time: bool,
    /// Provide a value for a datalog parameter
    #[clap(
        long,
        value_parser = clap::builder::ValueParser::new(parse_param),
        value_name = "key=value::type",
        requires("authorize-with"),
        requires("authorize-interactive"),
        requires("authorize-with-file")
    )]
    pub param: Vec<Param>,
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
    /// Read the snapshot from the given file (or use `-` to read from stdin)
    #[clap(parse(from_os_str))]
    pub snapshot_file: PathBuf,
    /// Read the snapshot raw bytes directly, with no base64 parsing
    #[clap(long)]
    pub raw_input: bool,
}

/// Generate a third-party block request from an existing biscuit
#[derive(Parser)]
pub struct GenerateRequest {
    /// Read the biscuit from the given file (or use `-` to read from stdin)
    #[clap(parse(from_os_str))]
    pub biscuit_file: PathBuf,
    /// Read the biscuit raw bytes directly, with no base64 parsing
    #[clap(long)]
    pub raw_input: bool,
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
    /// The block to generate. If `--block` and `--block-file` are omitted, an interactive $EDITOR will be opened.
    #[clap(long)]
    pub block: Option<String>,
    /// The block to generate. If `--block` and `--block-file` are omitted, an interactive $EDITOR will be opened.
    #[clap(long, parse(from_os_str), conflicts_with = "block")]
    pub block_file: Option<PathBuf>,
    /// The optional context string attached to the new block
    #[clap(long)]
    pub context: Option<String>,
    /// Add a TTL check to the generated block
    #[clap(long, parse(try_from_str = parse_duration))]
    pub add_ttl: Option<Duration>,
    /// Provide a value for a datalog parameter
    #[clap(
        long,
        value_parser = clap::builder::ValueParser::new(parse_param),
        value_name = "key=value::type",
    )]
    pub param: Vec<Param>,
}

/// Seal a token, preventing further attenuation
#[derive(Parser)]
pub struct Seal {
    /// Read the biscuit from the given file (or use `-` to read from stdin)
    #[clap(parse(from_os_str))]
    pub biscuit_file: PathBuf,
    /// Read the biscuit raw bytes directly, with no base64 parsing
    #[clap(long)]
    pub raw_input: bool,
    /// Output the biscuit raw bytes directly, with no base64 encoding
    #[clap(long)]
    pub raw_output: bool,
}
