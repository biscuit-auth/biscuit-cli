use anyhow::Result;
use atty::Stream;
use biscuit_auth::{
    builder::{BiscuitBuilder, BlockBuilder, Rule, Term},
    Algorithm, Authorizer, AuthorizerBuilder, PrivateKey, PublicKey, ThirdPartyRequest,
    UnverifiedBiscuit,
};
use chrono::{DateTime, Duration, Utc};
use parse_duration as duration_parser;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::Command;
use std::{collections::HashMap, convert::TryInto};

use crate::errors::CliError::*;

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

pub fn ensure_no_input_conflict(datalog: &DatalogInput, biscuit: &BiscuitBytes) -> Result<()> {
    match (datalog, biscuit) {
        // running $EDITOR as a child process requires a working stdin. When contents from stdin has already been read, this is
        // not the case. This could be handled by reopening stdin on /dev/tty, but it's not portable (and as such, more complicated
        // to do in rust than just disallowing a fringe use-case)
        (DatalogInput::FromEditor, BiscuitBytes::FromStdin(_)) => Err(StdinEditorConflict)?,
        // this combination should be prevented by the clap configuration
        (DatalogInput::FromStdin, BiscuitBytes::FromStdin(_)) => Err(MultipleStdinsConflict)?,
        _ => Ok(()),
    }
}

pub fn ensure_no_input_conflict_third_party(
    block: &BiscuitBytes,
    biscuit: &BiscuitBytes,
) -> Result<()> {
    match (block, biscuit) {
        (BiscuitBytes::FromStdin(_), BiscuitBytes::FromStdin(_)) => Err(MultipleStdinsConflict)?,
        _ => Ok(()),
    }
}

pub fn read_stdin_string(desc: &str) -> Result<String> {
    if atty::is(Stream::Stdin) && atty::is(Stream::Stderr) {
        eprintln!("Please input a {}, followed by <enter> and ^D", &desc);
    }
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;
    Ok(buffer.trim().to_owned())
}

pub fn read_stdin_bytes() -> Result<Vec<u8>> {
    if atty::is(Stream::Stdin) {
        Err(BinaryFromTTY)?
    }
    let mut buffer = Vec::new();
    io::stdin().read_to_end(&mut buffer).map(|_| ())?;
    Ok(buffer)
}

pub fn read_editor_string() -> Result<String> {
    let file = tempfile::Builder::new()
        .suffix(".biscuit-datalog")
        .tempfile()?;
    let path = &file.path();

    if atty::isnt(Stream::Stdin) || atty::isnt(Stream::Stdout) {
        Err(EditorOutsideTTY)?
    }

    let result = get_editor_command()?.arg(path).spawn()?.wait()?;

    if result.success() {
        Ok(fs::read_to_string(path).map_err(|_| FileNotFound(path.to_path_buf()))?)
    } else {
        Err(FailedReadingTempFile)?
    }
}

pub fn get_editor_command() -> Result<Command> {
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
        None => Err(FailedParsingEditorEnvVar)?,
    }
}

pub fn read_authority_from(
    from: &DatalogInput,
    all_params: &[Param],
    context: &Option<String>,
    builder: BiscuitBuilder,
) -> Result<BiscuitBuilder> {
    let string = match from {
        DatalogInput::FromEditor => read_editor_string()?,
        DatalogInput::FromStdin => read_stdin_string("datalog program")?,
        DatalogInput::FromFile(f) => fs::read_to_string(f)?,
        DatalogInput::DatalogString(str) => str.to_owned(),
    };

    let mut params = HashMap::new();
    let mut scope_params = HashMap::new();
    for p in all_params {
        match p {
            Param::Term(name, t) => {
                params.insert(name.clone(), t.clone());
            }
            Param::PublicKey(name, pk) => {
                scope_params.insert(name.clone(), *pk);
            }
        }
    }

    let mut builder = builder
        .code_with_params(&string, params, scope_params)
        .map_err(|e| ParseError("datalog statements".to_string(), e.to_string()))?;
    if let Some(ctx) = context {
        builder = builder.context(ctx.to_owned());
    }

    Ok(builder)
}

pub fn read_block_from(
    from: &DatalogInput,
    all_params: &[Param],
    context: &Option<String>,
    builder: BlockBuilder,
) -> Result<BlockBuilder> {
    let string = match from {
        DatalogInput::FromEditor => read_editor_string()?,
        DatalogInput::FromStdin => read_stdin_string("datalog program")?,
        DatalogInput::FromFile(f) => fs::read_to_string(f)?,
        DatalogInput::DatalogString(str) => str.to_owned(),
    };

    let mut params = HashMap::new();
    let mut scope_params = HashMap::new();
    for p in all_params {
        match p {
            Param::Term(name, t) => {
                params.insert(name.clone(), t.clone());
            }
            Param::PublicKey(name, pk) => {
                scope_params.insert(name.clone(), *pk);
            }
        }
    }
    let mut builder = builder
        .code_with_params(&string, params, scope_params)
        .map_err(|e| ParseError("datalog statements".to_string(), e.to_string()))?;

    if let Some(ctx) = context {
        builder = builder.context(ctx.to_owned());
    }

    Ok(builder)
}

pub fn read_authorizer_from(
    from: &DatalogInput,
    all_params: &[Param],
    builder: AuthorizerBuilder,
) -> Result<AuthorizerBuilder> {
    let string = match from {
        DatalogInput::FromEditor => read_editor_string()?,
        DatalogInput::FromStdin => read_stdin_string("datalog program")?,
        DatalogInput::FromFile(f) => fs::read_to_string(f)?,
        DatalogInput::DatalogString(str) => str.to_owned(),
    };

    let mut params = HashMap::new();
    let mut scope_params = HashMap::new();
    for p in all_params {
        match p {
            Param::Term(name, t) => {
                params.insert(name.clone(), t.clone());
            }
            Param::PublicKey(name, pk) => {
                scope_params.insert(name.clone(), *pk);
            }
        }
    }
    let builder = builder
        .code_with_params(&string, params, scope_params)
        .map_err(|e| ParseError("datalog statements".to_string(), e.to_string()))?;

    Ok(builder)
}

pub fn read_private_key_from(from: &KeyBytes, alg: Algorithm) -> Result<PrivateKey> {
    let bytes = match from {
        KeyBytes::FromStdin(KeyFormat::RawBytes) => read_stdin_bytes()?,
        KeyBytes::FromStdin(KeyFormat::HexKey) => {
            hex::decode(read_stdin_string("hex-encoded private key")?)?
        }
        KeyBytes::FromFile(KeyFormat::RawBytes, path) => {
            fs::read(path).map_err(|_| FileNotFound(path.clone()))?
        }
        KeyBytes::FromFile(KeyFormat::HexKey, path) => hex::decode(
            fs::read_to_string(path)
                .map_err(|_| FileNotFound(path.clone()))?
                .trim(),
        )?,
        KeyBytes::HexString(str) => hex::decode(str)?,
    };
    PrivateKey::from_bytes(&bytes, alg)
        .map_err(|e| ParseError("private key".to_string(), format!("{}", &e)).into())
}

pub fn read_public_key_from(from: &KeyBytes, alg: Algorithm) -> Result<PublicKey> {
    let bytes = match from {
        KeyBytes::FromStdin(KeyFormat::RawBytes) => read_stdin_bytes()?,
        KeyBytes::FromStdin(KeyFormat::HexKey) => {
            hex::decode(read_stdin_string("hex-encoded public key")?)?
        }
        KeyBytes::FromFile(KeyFormat::RawBytes, path) => {
            fs::read(path).map_err(|_| FileNotFound(path.clone()))?
        }
        KeyBytes::FromFile(KeyFormat::HexKey, path) => hex::decode(
            fs::read_to_string(path)
                .map_err(|_| FileNotFound(path.clone()))?
                .trim(),
        )?,
        KeyBytes::HexString(str) => hex::decode(str)?,
    };
    PublicKey::from_bytes(&bytes, alg)
        .map_err(|e| ParseError("public key".to_string(), format!("{}", &e)).into())
}

pub fn read_biscuit_from(from: &BiscuitBytes) -> Result<UnverifiedBiscuit> {
    let b = match from {
        BiscuitBytes::FromStdin(BiscuitFormat::RawBiscuit) => {
            UnverifiedBiscuit::from(read_stdin_bytes()?)?
        }
        BiscuitBytes::FromStdin(BiscuitFormat::Base64Biscuit) => {
            UnverifiedBiscuit::from_base64(read_stdin_string("base64-encoded biscuit")?)?
        }
        BiscuitBytes::FromFile(BiscuitFormat::RawBiscuit, path) => {
            UnverifiedBiscuit::from(fs::read(path).map_err(|_| FileNotFound(path.clone()))?)?
        }
        BiscuitBytes::FromFile(BiscuitFormat::Base64Biscuit, path) => {
            UnverifiedBiscuit::from_base64(
                fs::read_to_string(path)
                    .map_err(|_| FileNotFound(path.clone()))?
                    .trim(),
            )?
        }
        BiscuitBytes::Base64String(str) => UnverifiedBiscuit::from_base64(str)?,
    };
    Ok(b)
}

pub fn read_request_from(from: &BiscuitBytes) -> Result<ThirdPartyRequest> {
    let req = match from {
        BiscuitBytes::FromStdin(BiscuitFormat::RawBiscuit) => {
            ThirdPartyRequest::deserialize(&read_stdin_bytes()?)?
        }
        BiscuitBytes::FromStdin(BiscuitFormat::Base64Biscuit) => {
            ThirdPartyRequest::deserialize_base64(read_stdin_string(
                "base64-encoded third-party block request",
            )?)?
        }
        BiscuitBytes::FromFile(BiscuitFormat::RawBiscuit, path) => ThirdPartyRequest::deserialize(
            &fs::read(path).map_err(|_| FileNotFound(path.clone()))?,
        )?,
        BiscuitBytes::FromFile(BiscuitFormat::Base64Biscuit, path) => {
            ThirdPartyRequest::deserialize_base64(
                fs::read_to_string(path)
                    .map_err(|_| FileNotFound(path.clone()))?
                    .trim(),
            )?
        }
        BiscuitBytes::Base64String(str) => ThirdPartyRequest::deserialize_base64(str)?,
    };
    Ok(req)
}

pub fn read_snapshot_from(from: &BiscuitBytes) -> Result<Authorizer> {
    let b = match from {
        BiscuitBytes::FromStdin(BiscuitFormat::RawBiscuit) => {
            Authorizer::from_raw_snapshot(&read_stdin_bytes()?)?
        }
        BiscuitBytes::FromStdin(BiscuitFormat::Base64Biscuit) => {
            Authorizer::from_base64_snapshot(&read_stdin_string("base64-encoded biscuit")?)?
        }
        BiscuitBytes::FromFile(BiscuitFormat::RawBiscuit, path) => {
            Authorizer::from_raw_snapshot(&fs::read(path).map_err(|_| FileNotFound(path.clone()))?)?
        }
        BiscuitBytes::FromFile(BiscuitFormat::Base64Biscuit, path) => {
            Authorizer::from_base64_snapshot(
                fs::read_to_string(path)
                    .map_err(|_| FileNotFound(path.clone()))?
                    .trim(),
            )?
        }
        BiscuitBytes::Base64String(str) => Authorizer::from_base64_snapshot(str)?,
    };
    Ok(b)
}

pub fn append_third_party_from(
    biscuit: &UnverifiedBiscuit,
    from: &BiscuitBytes,
) -> Result<UnverifiedBiscuit> {
    let b = match from {
        BiscuitBytes::FromStdin(BiscuitFormat::RawBiscuit) => {
            biscuit.append_third_party(&read_stdin_bytes()?)?
        }
        BiscuitBytes::FromStdin(BiscuitFormat::Base64Biscuit) => biscuit
            .append_third_party_base64(read_stdin_string("base64-encode third-party block")?)?,
        BiscuitBytes::FromFile(BiscuitFormat::RawBiscuit, path) => {
            biscuit.append_third_party(&fs::read(path).map_err(|_| FileNotFound(path.clone()))?)?
        }
        BiscuitBytes::FromFile(BiscuitFormat::Base64Biscuit, path) => biscuit
            .append_third_party_base64(
                fs::read_to_string(path)
                    .map_err(|_| FileNotFound(path.clone()))?
                    .trim(),
            )?,
        BiscuitBytes::Base64String(str) => biscuit.append_third_party_base64(str)?,
    };
    Ok(b)
}

#[derive(Debug)]
pub enum Ttl {
    Duration(Duration),
    DateTime(DateTime<Utc>),
}

impl Ttl {
    pub fn to_datetime(&self) -> DateTime<Utc> {
        match self {
            Self::Duration(d) => Utc::now() + *d,
            Self::DateTime(d) => *d,
        }
    }
}

pub fn parse_duration(str: &str) -> Result<Duration> {
    let std_duration = duration_parser::parse(str)
        .map_err(|e| ParseError("duration".to_string(), e.to_string()))?;
    let duration = Duration::from_std(std_duration).map_err(|_| InvalidDuration)?;
    Ok(duration)
}

pub fn parse_date(str: &str) -> Result<DateTime<Utc>> {
    let r = DateTime::parse_from_rfc3339(str)?;
    Ok(r.into())
}

pub fn parse_ttl(str: &str) -> Result<Ttl> {
    parse_date(str)
        .map(Ttl::DateTime)
        .or_else(|_| parse_duration(str).map(Ttl::Duration))
}

#[derive(Debug, Clone)]
pub enum Param {
    Term(String, Term),
    PublicKey(String, PublicKey),
}

pub fn parse_param(kv: &str) -> Result<Param, std::io::Error> {
    use std::io::{Error, ErrorKind};
    let (binding, value) = (kv.split_once('=').ok_or_else(|| Error::new(
        ErrorKind::Other,
        "Params must be `key=value` or `key:type=value` where type is pubkey, string, integer, date, bytes or bool.",
    )))?;

    let (name, annotation) = match binding.rsplit_once(':') {
        None => (binding, None),
        Some((name, annotation)) => (name, Some(annotation)),
    };

    match annotation {
      Some("pubkey") => {
        let hex_key = value.strip_prefix("ed25519/").ok_or_else(|| Error::new(
        ErrorKind::Other,
        "Unsupported public key type. Only hex-encoded ed25519 public keys are supported. They must start with `ed25519/`.",
        ))?;
        let bytes =
            hex::decode(hex_key).map_err(|e| Error::new(ErrorKind::Other, format!("{}", &e)));
        let pubkey = PublicKey::from_bytes(&bytes?, Algorithm::Ed25519)
            .map_err(|e| Error::new(ErrorKind::Other, format!("{}", &e)))?;
        Ok(Param::PublicKey(name.to_string(), pubkey))
      },
      Some("integer") => {
        let int = value
            .parse()
            .map_err(|e| Error::new(ErrorKind::Other, format!("{}", &e)))?;
        Ok(Param::Term(name.to_string(), Term::Integer(int)))
      },
      Some("date") => {
        let date =
            time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
                .map_err(|e| Error::new(ErrorKind::Other, format!("{}", &e)))?;
        let timestamp = date
            .unix_timestamp()
            .try_into()
            .map_err(|e| Error::new(ErrorKind::Other, format!("{}", &e)))?;
        Ok(Param::Term(name.to_string(), Term::Date(timestamp)))
      },
      Some("bytes") => {
        let hex_bytes = value.strip_prefix("hex:").ok_or_else(|| {
            Error::new(
        ErrorKind::Other,
        "Unusupported byte array literal. Byte arrays must be hex-encoded and start with `hex:`."
        )
        })?;
        let bytes =
            hex::decode(hex_bytes).map_err(|e| Error::new(ErrorKind::Other, format!("{}", &e)))?;
        Ok(Param::Term(name.to_string(), Term::Bytes(bytes)))
      },
      Some("bool") => {
        if value.to_lowercase() == "true" {
            Ok(Param::Term(name.to_string(), Term::Bool(true)))
        } else if value.to_lowercase() == "false" {
            Ok(Param::Term(name.to_string(), Term::Bool(false)))
        } else {
            Err(Error::new(
                ErrorKind::Other,
                "Boolean params must be either \"true\" or \"false\".",
            ))
        }
      },
      Some("string") | None => {
        Ok(Param::Term(name.to_string(), Term::Str(value.to_string())))
      },
      _ => {
        Err(Error::new(
                ErrorKind::Other,
                "Unsupported parameter type. Supported types are `pubkey`, `string`, `integer`, `date`, `bytes`, or `bool`.",
            ))
      }
    }
}

pub fn parse_rule(rule: &str) -> Result<Rule, std::io::Error> {
    use std::io::{Error, ErrorKind};
    rule.try_into()
        .map_err(|e| Error::new(ErrorKind::Other, format!("Could not parse rule: {e}")))
}
