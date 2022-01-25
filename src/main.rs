use atty::Stream;
use biscuit_auth::{
    builder::{BiscuitBuilder, BlockBuilder, Policy},
    error::{FailedCheck, Logic, MatchedPolicy, RunLimit, Token},
    parser::{parse_block_source, parse_source},
    Authorizer, Biscuit, UnverifiedBiscuit, {KeyPair, PrivateKey, PublicKey},
};
use clap::Parser;
use std::env;
use std::error::Error;
use std::fmt;
use std::fmt::Display;
use std::fs;
use std::io::Write;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::Command;

/// biscuit creation and inspection CLI. Run `biscuit --help` to see what's available.
#[derive(Parser)]
#[clap(version = "1.0", author = "Clément D. <clement@delafargue.name>")]
struct Opts {
    // /// Sets a custom config file. Could have been an Option<T> with no default too
    // #[clap(short, long, default_value = "default.conf")]
    // config: String,
    // /// Some input. Because this isn't an Option<T> it's required to be used
    // input: String,
    // /// A level of verbosity, and can be used multiple times
    // #[clap(short, long, parse(from_occurrences))]
    // verbose: i32,
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Parser)]
enum SubCommand {
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
struct KeyPairCmd {
    /// Generate the keypair from the given private key. If omitted, a random keypair will be generated
    #[clap(long, conflicts_with("from-private-key-file"))]
    from_private_key: Option<String>,
    /// Generate the keypair from a private key stored in the given file (or use `-` to read it from stdin). If omitted, a random keypair will be generated
    #[clap(long, parse(from_os_str))]
    from_private_key_file: Option<PathBuf>,
    /// Read the private key raw bytes directly, with no hex decoding
    #[clap(long, requires("from-private-key-file"))]
    from_raw_private_key: bool,
    /// Only output the public part of the key pair
    #[clap(long, conflicts_with("only-private-key"))]
    only_public_key: bool,
    /// Output the public key raw bytes directly, with no hex encoding
    #[clap(long, requires("only-public-key"))]
    raw_public_key_output: bool,
    /// Only output the public part of the key pair
    #[clap(long, conflicts_with("only-public-key"))]
    only_private_key: bool,
    /// Output the private key raw bytes directly, with no hex encoding
    #[clap(long, requires("only-private-key"))]
    raw_private_key_output: bool,
}

/// Generate a biscuit from a private key and an authority block
#[derive(Parser)]
struct Generate {
    /// Read the authority block from the given file (or use `-` to read from stdin). If omitted, an interactive $EDITOR will be opened.
    #[clap(parse(from_os_str))]
    authority_file: Option<PathBuf>,
    /// Output the biscuit raw bytes directly, with no base64 encoding
    #[clap(long)]
    raw: bool,
    /// The private key used to sign the token
    #[clap(long, required_unless_present("private-key-file"))]
    private_key: Option<String>,
    /// The private key used to sign the token
    #[clap(
        long,
        parse(from_os_str),
        required_unless_present("private-key"),
        conflicts_with = "private-key"
    )]
    private_key_file: Option<PathBuf>,
    /// Read the private key raw bytes directly (only available when reading the private key from a file)
    #[clap(long, conflicts_with = "private-key", requires = "private-key-file")]
    raw_private_key: bool,
    /// The optional context string attached to the authority block
    #[clap(long)]
    context: Option<String>,
}

/// Attenuate an existing biscuit by adding a new block
#[derive(Parser)]
struct Attenuate {
    /// Read the biscuit from the given file (or use `-` to read from stdin)
    #[clap(parse(from_os_str))]
    biscuit_file: PathBuf,
    /// Read the biscuit raw bytes directly, with no base64 parsing
    #[clap(long)]
    raw_input: bool,
    /// Output the biscuit raw bytes directly, with no base64 encoding
    #[clap(long)]
    raw_output: bool,
    /// The block to append to the token. If `--block` and `--block-file` are omitted, an interactive $EDITOR will be opened.
    #[clap(long)]
    block: Option<String>,
    /// The block to append to the token. If `--block` and `--block-file` are omitted, an interactive $EDITOR will be opened.
    #[clap(long, parse(from_os_str), conflicts_with = "block")]
    block_file: Option<PathBuf>,
    /// The optional context string attached to the new block
    #[clap(long)]
    context: Option<String>,
}

/// Inspect a biscuit and optionally check its public key
#[derive(Parser)]
struct Inspect {
    /// Read the biscuit from the given file (or use `-` to read from stdin)
    #[clap(parse(from_os_str))]
    biscuit_file: PathBuf,
    /// Read the biscuit raw bytes directly, with no base64 parsing
    #[clap(long)]
    raw_input: bool,
    /// Check the biscuit public key
    #[clap(long, conflicts_with("public-key-file"))]
    public_key: Option<String>,
    /// Check the biscuit public key
    #[clap(long, conflicts_with("public-key"), parse(from_os_str))]
    public_key_file: Option<PathBuf>,
    /// Read the public key raw bytes directly
    #[clap(long, requires("public-key-file"), conflicts_with("public-key"))]
    raw_public_key: bool,
    /// Open $EDITOR to provide a authorizer.
    #[clap(
        long,
        conflicts_with("verify-with"),
        conflicts_with("verify-with-file")
    )]
    verify_interactive: bool,
    /// Verify the biscuit with the provided authorizer.
    #[clap(
        long,
        conflicts_with("verify-with"),
        conflicts_with("verify-interactive")
    )]
    verify_with_file: Option<PathBuf>,
    /// Verify the biscuit with the provided authorizer
    #[clap(
        long,
        conflicts_with("verify-with-file"),
        conflicts_with("verify-interactive")
    )]
    verify_with: Option<String>,
}

pub enum BiscuitFormat {
    RawBiscuit,
    Base64Biscuit,
}

pub enum KeyFormat {
    RawBytes,
    HexKey,
}

// `Base64String` is never constructed, but is still handled in
// `cli.rs`
#[allow(dead_code)]
pub enum BiscuitBytes {
    FromStdin(BiscuitFormat),
    FromFile(BiscuitFormat, PathBuf),
    Base64String(String),
}

// `FromStdin` is never constructed, but is still handled in
// `cli.rs`
#[allow(dead_code)]
pub enum KeyBytes {
    FromStdin(KeyFormat),
    FromFile(KeyFormat, PathBuf),
    HexString(String),
}

pub enum DatalogInput {
    FromEditor,
    FromStdin,
    FromFile(PathBuf),
    DatalogString(String),
}

fn ensure_no_input_conflict(
    datalog: &DatalogInput,
    biscuit: &BiscuitBytes,
) -> Result<(), Box<dyn Error>> {
    match (datalog, biscuit) {
        // running $EDITOR as a child process requires a working stdin. When contents from stdin has already been read, this is
        // not the case. This could be handled by reopening stdin on /dev/tty, but it's not portable (and as such, more complicated
        // to do in rust than just disallowing a fringe use-case)
        (DatalogInput::FromEditor, BiscuitBytes::FromStdin(_)) => Err(E {
            msg: "I cannot read input from both stdin and an interactive editor. Please use proper files or flags instead.".to_owned(),
        }
        .into()),
        // this combination should be prevented by the clap configuration
        (DatalogInput::FromStdin, BiscuitBytes::FromStdin(_)) => Err(E {
            msg: "I cannot read several pieces of input from stdin at the same time. Please use proper files or flags instead.".to_owned(),
        }
        .into()),
        _ => Ok(()),
    }
}

#[derive(Debug, Clone)]
struct E {
    msg: String,
}

impl Display for E {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.msg)
    }
}

impl Error for E {}

fn read_stdin_string(desc: &str) -> Result<String, Box<dyn Error>> {
    if atty::is(Stream::Stdin) && atty::is(Stream::Stderr) {
        eprintln!("Please input a {}, followed by <enter> and ^D", &desc);
    }
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;
    Ok(buffer.trim().to_owned())
}

fn read_stdin_bytes() -> Result<Vec<u8>, Box<dyn Error>> {
    if atty::is(Stream::Stdin) {
        return Err(E { msg: "Can't read binary content from an interactive terminal. Please pipe the content or use a proper file.".to_owned() }.into());
    }
    let mut buffer = Vec::new();
    io::stdin().read_to_end(&mut buffer).map(|_| ())?;
    Ok(buffer)
}

fn read_editor_string() -> Result<String, Box<dyn Error>> {
    let file = tempfile::Builder::new()
        .suffix(".biscuit-datalog")
        .tempfile()?;
    let path = &file.path();

    if atty::isnt(Stream::Stdin) || atty::isnt(Stream::Stdout) {
        return Err(E {
            msg: "Can't start an editor outside of an interactive terminal.".to_owned(),
        }
        .into());
    }

    let editor = match env::var("EDITOR") {
        Ok(e) => Ok(e),
        Err(env::VarError::NotPresent) => Ok("vim".to_owned()),
        e => e,
    }?;

    let result = Command::new(&editor).arg(&path).spawn()?.wait()?;

    if result.success() {
        Ok(fs::read_to_string(&path)?)
    } else {
        Err(E {
            msg: "Failed reading the datalog temporary file".to_owned(),
        }
        .into())
    }
}

fn read_authority_from(
    from: &DatalogInput,
    context: &Option<String>,
    builder: &mut BiscuitBuilder,
) -> Result<(), Box<dyn Error>> {
    let string = match from {
        DatalogInput::FromEditor => read_editor_string()?,
        DatalogInput::FromStdin => read_stdin_string("datalog program")?,
        DatalogInput::FromFile(f) => fs::read_to_string(&f)?,
        DatalogInput::DatalogString(str) => str.to_owned(),
    };
    let result = parse_block_source(&string).map_err(|_| E {
        msg: "parse error".into(),
    })?;

    for (fact_str, _) in result.facts {
        builder.add_authority_fact(fact_str)?;
    }
    for (rule_str, _) in result.rules {
        builder.add_authority_rule(rule_str)?;
    }
    for (check_str, _) in result.checks {
        builder.add_authority_check(check_str)?;
    }

    if let Some(ctx) = context {
        builder.set_context(ctx.to_owned());
    }

    Ok(())
}

fn read_block_from(
    from: &DatalogInput,
    context: &Option<String>,
    builder: &mut BlockBuilder,
) -> Result<(), Box<dyn Error>> {
    let string = match from {
        DatalogInput::FromEditor => read_editor_string()?,
        DatalogInput::FromStdin => read_stdin_string("datalog program")?,
        DatalogInput::FromFile(f) => fs::read_to_string(&f)?,
        DatalogInput::DatalogString(str) => str.to_owned(),
    };
    let result = parse_block_source(&string).map_err(|_| E {
        msg: "parse error".into(),
    })?;

    for (fact_str, _) in result.facts {
        builder.add_fact(fact_str)?;
    }
    for (rule_str, _) in result.rules {
        builder.add_rule(rule_str)?;
    }
    for (check_str, _) in result.checks {
        builder.add_check(check_str)?;
    }

    if let Some(ctx) = context {
        builder.set_context(ctx.to_owned());
    }

    Ok(())
}

fn read_authorizer_from(
    from: &DatalogInput,
    authorizer: &mut Authorizer,
) -> Result<(), Box<dyn Error>> {
    let string = match from {
        DatalogInput::FromEditor => read_editor_string()?,
        DatalogInput::FromStdin => read_stdin_string("datalog program")?,
        DatalogInput::FromFile(f) => fs::read_to_string(&f)?,
        DatalogInput::DatalogString(str) => str.to_owned(),
    };
    let result = parse_source(&string).map_err(|_| E {
        msg: "parse error".into(),
    })?;

    for (fact_str, _) in result.facts {
        authorizer.add_fact(fact_str)?;
    }
    for (rule_str, _) in result.rules {
        authorizer.add_rule(rule_str)?;
    }
    for (check_str, _) in result.checks {
        authorizer.add_check(check_str)?;
    }

    for (policy_str, _) in result.policies {
        authorizer.add_policy(policy_str)?;
    }

    Ok(())
}

fn read_private_key_from(from: &KeyBytes) -> Result<PrivateKey, Box<dyn Error>> {
    let bytes = match from {
        KeyBytes::FromStdin(KeyFormat::RawBytes) => read_stdin_bytes(),
        KeyBytes::FromStdin(KeyFormat::HexKey) => {
            hex::decode(read_stdin_string("hex-encoded private key")?).map_err(|e| e.into())
        }
        KeyBytes::FromFile(KeyFormat::RawBytes, path) => fs::read(&path).map_err(|e| e.into()),
        KeyBytes::FromFile(KeyFormat::HexKey, path) => {
            hex::decode(fs::read_to_string(&path)?.trim()).map_err(|e| e.into())
        }
        KeyBytes::HexString(str) => hex::decode(&str).map_err(|e| e.into()),
    };
    PrivateKey::from_bytes(&bytes?).map_err(|e| {
        E {
            msg: format!("invalid private key: {}", e),
        }
        .into()
    })
}

fn read_public_key_from(from: &KeyBytes) -> Result<PublicKey, Box<dyn Error>> {
    let bytes = match from {
        KeyBytes::FromStdin(KeyFormat::RawBytes) => read_stdin_bytes(),
        KeyBytes::FromStdin(KeyFormat::HexKey) => {
            hex::decode(read_stdin_string("hex-encoded public key")?).map_err(|e| e.into())
        }
        KeyBytes::FromFile(KeyFormat::RawBytes, path) => fs::read(&path).map_err(|e| e.into()),
        KeyBytes::FromFile(KeyFormat::HexKey, path) => {
            hex::decode(fs::read_to_string(&path)?.trim()).map_err(|e| e.into())
        }
        KeyBytes::HexString(str) => hex::decode(&str).map_err(|e| e.into()),
    };
    PublicKey::from_bytes(&bytes?).map_err(|e| {
        E {
            msg: format!("invalid public key: {}", e),
        }
        .into()
    })
}

fn read_biscuit_from(from: &BiscuitBytes) -> Result<UnverifiedBiscuit, Box<dyn Error>> {
    match from {
        BiscuitBytes::FromStdin(BiscuitFormat::RawBiscuit) => {
            UnverifiedBiscuit::from(&read_stdin_bytes()?).map_err(|e| e.into())
        }
        BiscuitBytes::FromStdin(BiscuitFormat::Base64Biscuit) => {
            UnverifiedBiscuit::from_base64(&read_stdin_string("base64-encoded biscuit")?)
                .map_err(|e| e.into())
        }
        BiscuitBytes::FromFile(BiscuitFormat::RawBiscuit, path) => {
            UnverifiedBiscuit::from(&fs::read(&path)?).map_err(|e| e.into())
        }
        BiscuitBytes::FromFile(BiscuitFormat::Base64Biscuit, path) => {
            UnverifiedBiscuit::from_base64(fs::read_to_string(&path)?.trim()).map_err(|e| e.into())
        }
        BiscuitBytes::Base64String(str) => {
            UnverifiedBiscuit::from_base64(&str).map_err(|e| e.into())
        }
    }
}

fn handle_command(cmd: &SubCommand) -> Result<(), Box<dyn Error>> {
    match cmd {
        SubCommand::KeyPairCmd(key_pair_cmd) => handle_keypair(&key_pair_cmd),
        SubCommand::Inspect(inspect) => handle_inspect(&inspect),
        SubCommand::Generate(generate) => handle_generate(&generate),
        SubCommand::Attenuate(attenuate) => handle_attenuate(&attenuate),
    }
}

fn handle_keypair(key_pair_cmd: &KeyPairCmd) -> Result<(), Box<dyn Error>> {
    let stdin_path = PathBuf::from("-");
    let private_key_from = &match (
        &key_pair_cmd.from_private_key,
        &key_pair_cmd.from_private_key_file,
        &key_pair_cmd.from_raw_private_key,
    ) {
        (Some(hex_string), None, false) => Some(KeyBytes::HexString(hex_string.to_owned())),
        (None, Some(path), true) if path == &stdin_path => {
            Some(KeyBytes::FromStdin(KeyFormat::RawBytes))
        }
        (None, Some(file), true) => {
            Some(KeyBytes::FromFile(KeyFormat::RawBytes, file.to_path_buf()))
        }
        (None, Some(path), false) if path == &stdin_path => {
            Some(KeyBytes::FromStdin(KeyFormat::HexKey))
        }
        (None, Some(file), false) => {
            Some(KeyBytes::FromFile(KeyFormat::HexKey, file.to_path_buf()))
        }
        (None, None, false) => None,
        // the other combinations are prevented by clap
        _ => unreachable!(),
    };

    let private_key: Option<PrivateKey> = if let Some(f) = private_key_from {
        Some(read_private_key_from(&f)?)
    } else {
        None
    };

    let key_pair = if let Some(private) = private_key {
        KeyPair::from(private)
    } else {
        KeyPair::new()
    };

    match (
        &key_pair_cmd.only_private_key,
        &key_pair_cmd.raw_private_key_output,
        &key_pair_cmd.only_public_key,
        &key_pair_cmd.raw_public_key_output,
    ) {
        (false, false, false, false) => {
            if private_key_from.is_some() {
                println!("Generating a keypair for the provided private key");
            } else {
                println!("Generating a new random keypair");
            }
            println!(
                "Private key: {}",
                hex::encode(&key_pair.private().to_bytes())
            );
            println!("Public key: {}", hex::encode(&key_pair.public().to_bytes()));
        }
        (true, true, false, false) => {
            let _ = io::stdout().write_all(&key_pair.private().to_bytes());
        }
        (true, false, false, false) => {
            println!("{}", hex::encode(&key_pair.private().to_bytes()));
        }
        (false, false, true, true) => {
            let _ = io::stdout().write_all(&key_pair.public().to_bytes());
        }
        (false, false, true, false) => {
            println!("{}", hex::encode(&key_pair.public().to_bytes()));
        }
        // the other combinations are prevented by clap
        _ => unreachable!(),
    }
    Ok(())
}

fn handle_inspect(inspect: &Inspect) -> Result<(), Box<dyn Error>> {
    let biscuit_format = if inspect.raw_input {
        BiscuitFormat::RawBiscuit
    } else {
        BiscuitFormat::Base64Biscuit
    };

    let biscuit_from = if inspect.biscuit_file == PathBuf::from("-") {
        BiscuitBytes::FromStdin(biscuit_format)
    } else {
        BiscuitBytes::FromFile(biscuit_format, inspect.biscuit_file.clone())
    };

    let public_key_from = match (
        &inspect.public_key_file,
        &inspect.public_key,
        &inspect.raw_public_key,
    ) {
        (Some(file), None, true) => {
            Some(KeyBytes::FromFile(KeyFormat::RawBytes, file.to_path_buf()))
        }
        (Some(file), None, false) => {
            Some(KeyBytes::FromFile(KeyFormat::HexKey, file.to_path_buf()))
        }
        (None, Some(str), false) => Some(KeyBytes::HexString(str.to_owned())),
        (None, None, false) => None,
        // the other combinations are prevented by clap
        _ => unreachable!(),
    };

    let authorizer_from = match (
        &inspect.verify_interactive,
        &inspect.verify_with,
        &inspect.verify_with_file,
    ) {
        (false, None, None) => None,
        (true, None, None) => Some(DatalogInput::FromEditor),
        (false, Some(str), None) => Some(DatalogInput::DatalogString(str.to_owned())),
        (false, None, Some(path)) => Some(DatalogInput::FromFile(path.to_path_buf())),
        // the other combinations are prevented by clap
        _ => unreachable!(),
    };

    if let Some(vf) = &authorizer_from {
        ensure_no_input_conflict(&vf, &biscuit_from)?;
    }

    let biscuit = read_biscuit_from(&biscuit_from)?;

    let content_revocation_ids = biscuit.revocation_identifiers();
    for i in 0..biscuit.block_count() {
        if i == 0 {
            println!("Authority block:");
        } else {
            println!("Block n°{}:", i);
        }

        println!("== Datalog ==");
        println!(
            "{}",
            biscuit.print_block_source(i).unwrap_or_else(String::new)
        );

        println!("== Revocation id ==");
        let content_id = content_revocation_ids
            .get(i)
            .map(|bytes| hex::encode(&bytes))
            .unwrap_or_else(|| "n/a".to_owned());
        println!("{}", &content_id);
        println!("\n==========\n");
    }

    if let Some(key_from) = public_key_from {
        let key = read_public_key_from(&key_from)?;
        let sig_result = biscuit.check_signature(|_| key);
        if sig_result.is_err() {
            println!("❌ Public key check failed 🔑");
        }
        let biscuit = sig_result?;
        println!("✅ Public key check succeeded 🔑");

        if let Some(auth_from) = authorizer_from {
            let mut authorizer_builder = biscuit.authorizer()?;
            read_authorizer_from(&auth_from, &mut authorizer_builder)?;
            let (_, _, _, policies) = authorizer_builder.dump();
            let authorizer_result = authorizer_builder.authorize();
            match authorizer_result {
                Ok(i) => {
                    println!("✅ Authorizer check succeeded 🛡️");
                    println!(
                        "Matched allow policy: {}",
                        policies.get(i).expect("Incorrect policy index")
                    );
                }

                Err(e) => {
                    println!("❌ Authorizer check failed 🛡️");
                    match e {
                        Token::FailedLogic(l) => display_logic_error(&policies, &l),
                        Token::RunLimit(l) => display_run_limit(&l),
                        _ => {}
                    }
                }
            }
        } else {
            println!("🙈 Datalog check skipped 🛡️");
        }
    } else {
        println!("🙈 Public key check skipped 🔑");
        println!("🙈 Datalog check skipped 🛡️");
        if authorizer_from.is_some() {
            return Err(E {
                msg: "A public key is required when authorizng a biscuit".to_owned(),
            }
            .into());
        }
    }

    Ok(())
}

fn display_logic_error(policies: &[Policy], e: &Logic) {
    match e {
        Logic::Unauthorized { policy, checks } => {
            display_matched_policy(policies, &policy);
            display_failed_checks(&checks);
        }
        Logic::NoMatchingPolicy { checks } => {
            println!("No policy matched");
            display_failed_checks(&checks);
        }
        e => println!("An execution error happened during authorization: {:?}", &e),
    }
}

fn display_matched_policy(policies: &[Policy], policy: &MatchedPolicy) {
    match policy {
        MatchedPolicy::Allow(i) => {
            let policy = policies.get(*i);
            println!(
                "An allow policy matched: {}",
                policy.expect("Incorrect policy index")
            );
        }
        MatchedPolicy::Deny(i) => {
            let policy = policies.get(*i);
            println!(
                "A deny policy matched: {}",
                policy.expect("Incorrect policy index")
            );
        }
    }
}

fn display_failed_checks(checks: &Vec<FailedCheck>) {
    if checks.len() > 0 {
        println!("The following checks failed:");
    }
    for c in checks {
        match c {
            FailedCheck::Block(bc) => {
                let block_name = if bc.block_id == 0 {
                    "Authority block".to_owned()
                } else {
                    format!("Block {}", &bc.block_id)
                };
                println!("  {} check: {}", &block_name, &bc.rule);
            }
            FailedCheck::Authorizer(ac) => println!("  Authorizer check: {}", &ac.rule),
        }
    }
}

fn display_run_limit(e: &RunLimit) {
    println!("The authorizer execution was aborted: {}", &e.to_string());
}

fn handle_generate(generate: &Generate) -> Result<(), Box<dyn Error>> {
    let authority_from = match &generate.authority_file {
        Some(path) if path == &PathBuf::from("-") => DatalogInput::FromStdin,
        Some(path) => DatalogInput::FromFile(path.to_path_buf()),
        None => DatalogInput::FromEditor,
    };

    let private_key: Result<PrivateKey, Box<dyn Error>> = read_private_key_from(&match (
        &generate.private_key,
        &generate.private_key_file,
        &generate.raw_private_key,
    ) {
        (Some(hex_string), None, false) => KeyBytes::HexString(hex_string.to_owned()),
        (None, Some(file), true) => KeyBytes::FromFile(KeyFormat::RawBytes, file.to_path_buf()),
        (None, Some(file), false) => KeyBytes::FromFile(KeyFormat::HexKey, file.to_path_buf()),
        // the other combinations are prevented by clap
        _ => unreachable!(),
    });

    let root = KeyPair::from(private_key?);
    let mut builder = Biscuit::builder(&root);
    read_authority_from(&authority_from, &generate.context, &mut builder)?;
    let biscuit = builder.build().expect("Error building biscuit"); // todo display error
    let encoded = if generate.raw {
        biscuit.to_vec().expect("Error serializing token")
    } else {
        biscuit
            .to_base64()
            .expect("Error serializing token")
            .into_bytes()
    };
    let _ = io::stdout().write_all(&encoded);
    Ok(())
}

fn handle_attenuate(attenuate: &Attenuate) -> Result<(), Box<dyn Error>> {
    let biscuit_format = if attenuate.raw_input {
        BiscuitFormat::RawBiscuit
    } else {
        BiscuitFormat::Base64Biscuit
    };

    let biscuit_from = if attenuate.biscuit_file == PathBuf::from("-") {
        BiscuitBytes::FromStdin(biscuit_format)
    } else {
        BiscuitBytes::FromFile(biscuit_format, attenuate.biscuit_file.clone())
    };

    let block_from = match (&attenuate.block_file, &attenuate.block) {
        (Some(file), None) => DatalogInput::FromFile(file.to_path_buf()),
        (None, Some(str)) => DatalogInput::DatalogString(str.to_owned()),
        (None, None) => DatalogInput::FromEditor,
        // the other combinations are prevented by clap
        _ => unreachable!(),
    };

    ensure_no_input_conflict(&block_from, &biscuit_from)?;

    let biscuit = read_biscuit_from(&biscuit_from)?;
    let mut block_builder = biscuit.create_block();

    read_block_from(&block_from, &attenuate.context, &mut block_builder)?;

    let new_biscuit = biscuit.append(block_builder)?;
    let encoded = if attenuate.raw_output {
        new_biscuit.to_vec()?
    } else {
        new_biscuit.to_base64()?.into_bytes()
    };
    let _ = io::stdout().write_all(&encoded);
    Ok(())
}

pub fn main() {
    let opts: Opts = Opts::parse();
    let _ = handle_command(&opts.subcmd).unwrap();
}
