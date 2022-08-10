use atty::Stream;
use biscuit_auth::{
    builder::{BiscuitBuilder, BlockBuilder},
    parser::{parse_block_source, parse_source},
    Authorizer, UnverifiedBiscuit, {PrivateKey, PublicKey},
};
use chrono::Duration;
use parse_duration as duration_parser;
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::Command;

use crate::errors::*;

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

pub fn ensure_no_input_conflict(
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

pub fn read_stdin_string(desc: &str) -> Result<String, Box<dyn Error>> {
    if atty::is(Stream::Stdin) && atty::is(Stream::Stderr) {
        eprintln!("Please input a {}, followed by <enter> and ^D", &desc);
    }
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;
    Ok(buffer.trim().to_owned())
}

pub fn read_stdin_bytes() -> Result<Vec<u8>, Box<dyn Error>> {
    if atty::is(Stream::Stdin) {
        return Err(E { msg: "Can't read binary content from an interactive terminal. Please pipe the content or use a proper file.".to_owned() }.into());
    }
    let mut buffer = Vec::new();
    io::stdin().read_to_end(&mut buffer).map(|_| ())?;
    Ok(buffer)
}

pub fn read_editor_string() -> Result<String, Box<dyn Error>> {
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

    let result = get_editor_command()?.arg(&path).spawn()?.wait()?;

    if result.success() {
        Ok(fs::read_to_string(&path)?)
    } else {
        Err(E {
            msg: "Failed reading the datalog temporary file".to_owned(),
        }
        .into())
    }
}

pub fn get_editor_command() -> Result<Command, Box<dyn Error>> {
    let editor_unparsed = match env::var("EDITOR") {
        Ok(e) => Ok(e),
        Err(env::VarError::NotPresent) => Ok("vim".to_owned()),
        e => e,
    }?;

    let editor_parts = shell_words::split(&editor_unparsed)?;
    match editor_parts.split_first() {
        Some((editor_binary, editor_args)) => {
            let mut editor_cmd = Command::new(editor_binary);
            editor_cmd.args(editor_args);
            Ok(editor_cmd)
        }
        None => Err(E {
            msg: "Failed to parse EDITOR environment variable".to_owned(),
        }
        .into()),
    }
}

pub fn read_authority_from(
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

pub fn read_block_from(
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

pub fn read_authorizer_from(
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

pub fn read_private_key_from(from: &KeyBytes) -> Result<PrivateKey, Box<dyn Error>> {
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

pub fn read_public_key_from(from: &KeyBytes) -> Result<PublicKey, Box<dyn Error>> {
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

pub fn read_biscuit_from(from: &BiscuitBytes) -> Result<UnverifiedBiscuit, Box<dyn Error>> {
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

pub fn parse_duration(str: &str) -> Result<Duration, E> {
    let std_duration = duration_parser::parse(str).map_err(|_| E {
        msg: "Could not parse duration".to_string(),
    })?;
    let duration = Duration::from_std(std_duration).map_err(|_| E {
        msg: "Duration outside representable intervals".to_string(),
    })?;
    Ok(duration)
}
