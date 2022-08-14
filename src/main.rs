use biscuit_auth::{
    builder::BlockBuilder,
    Biscuit, {KeyPair, PrivateKey},
};
use chrono::Utc;
use clap::Parser;
use std::error::Error;
use std::io::Write;
use std::io::{self};
use std::path::PathBuf;
use std::process;

mod cli;
mod errors;
mod input;
mod inspect;

use cli::*;
use input::*;
use inspect::*;

fn handle_command(cmd: &SubCommand) -> Result<(), Box<dyn Error>> {
    match cmd {
        SubCommand::KeyPairCmd(key_pair_cmd) => handle_keypair(key_pair_cmd),
        SubCommand::Inspect(inspect) => handle_inspect(inspect),
        SubCommand::Generate(generate) => handle_generate(generate),
        SubCommand::Attenuate(attenuate) => handle_attenuate(attenuate),
        SubCommand::GenerateRequest(generate_request) => handle_generate_request(generate_request),
        SubCommand::GenerateThirdPartyBlock(generate_third_party_block) => {
            handle_generate_third_party_block(generate_third_party_block)
        }
        SubCommand::AppendThirdPartyBlock(append_third_party_block) => {
            handle_append_third_party_block(append_third_party_block)
        }
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
        Some(read_private_key_from(f)?)
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
    let mut builder = Biscuit::builder();
    read_authority_from(&authority_from, &generate.context, &mut builder)?;

    if let Some(duration) = generate.add_ttl {
        let expiration = Utc::now() + duration;
        builder.add_check::<&str>(&format!(
            "check if time($t), $t < {}",
            &expiration.to_rfc3339()
        ))?;
    }
    let biscuit = builder.build(&root).expect("Error building biscuit"); // todo display error
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
    let mut block_builder = BlockBuilder::new();

    read_block_from(&block_from, &attenuate.context, &mut block_builder)?;

    if let Some(duration) = attenuate.add_ttl {
        let expiration = Utc::now() + duration;
        block_builder.add_check::<&str>(&format!(
            "check if time($t), $t < {}",
            &expiration.to_rfc3339()
        ))?;
    }

    let new_biscuit = biscuit.append(block_builder)?;
    let encoded = if attenuate.raw_output {
        new_biscuit.to_vec()?
    } else {
        new_biscuit.to_base64()?.into_bytes()
    };
    let _ = io::stdout().write_all(&encoded);
    Ok(())
}

fn handle_generate_request(generate_request: &GenerateRequest) -> Result<(), Box<dyn Error>> {
    let biscuit_format = if generate_request.raw_input {
        BiscuitFormat::RawBiscuit
    } else {
        BiscuitFormat::Base64Biscuit
    };

    let biscuit_from = if generate_request.biscuit_file == PathBuf::from("-") {
        BiscuitBytes::FromStdin(biscuit_format)
    } else {
        BiscuitBytes::FromFile(biscuit_format, generate_request.biscuit_file.clone())
    };

    let biscuit = read_biscuit_from(&biscuit_from)?;

    let request = biscuit.third_party_request()?;

    let encoded = if generate_request.raw_output {
        request.serialize()?
    } else {
        request.serialize_base64()?
    };
    let _ = io::stdout().write_all(&encoded);
    Ok(())
}

fn handle_generate_third_party_block(
    generate_third_party_block: &GenerateThirdPartyBlock,
) -> Result<(), Box<dyn Error>> {
    let block_format = if generate_third_party_block.raw_input {
        BiscuitFormat::RawBiscuit
    } else {
        BiscuitFormat::Base64Biscuit
    };

    let request_from = if generate_third_party_block.request_file == PathBuf::from("-") {
        BiscuitBytes::FromStdin(block_format)
    } else {
        BiscuitBytes::FromFile(
            block_format,
            generate_third_party_block.request_file.clone(),
        )
    };

    let block_from = match (
        &generate_third_party_block.block_file,
        &generate_third_party_block.block,
    ) {
        (Some(file), None) => DatalogInput::FromFile(file.to_path_buf()),
        (None, Some(str)) => DatalogInput::DatalogString(str.to_owned()),
        (None, None) => DatalogInput::FromEditor,
        // the other combinations are prevented by clap
        _ => unreachable!(),
    };

    ensure_no_input_conflict(&block_from, &request_from)?;

    let private_key: Result<PrivateKey, Box<dyn Error>> = read_private_key_from(&match (
        &generate_third_party_block.private_key,
        &generate_third_party_block.private_key_file,
        &generate_third_party_block.raw_private_key,
    ) {
        (Some(hex_string), None, false) => KeyBytes::HexString(hex_string.to_owned()),
        (None, Some(file), true) => KeyBytes::FromFile(KeyFormat::RawBytes, file.to_path_buf()),
        (None, Some(file), false) => KeyBytes::FromFile(KeyFormat::HexKey, file.to_path_buf()),
        // the other combinations are prevented by clap
        _ => unreachable!(),
    });

    let mut request = read_request_from(&request_from)?;

    read_block_from(
        &block_from,
        &generate_third_party_block.context,
        &mut request,
    )?;

    if let Some(duration) = generate_third_party_block.add_ttl {
        let expiration = Utc::now() + duration;
        request.add_check::<&str>(&format!(
            "check if time($t), $t < {}",
            &expiration.to_rfc3339()
        ))?;
    }

    let encoded = if generate_third_party_block.raw_output {
        request.create_response(private_key?)?
    } else {
        request.create_response_base64(private_key?)?
    };
    let _ = io::stdout().write_all(&encoded);
    Ok(())
}

fn handle_append_third_party_block(
    append_third_party_block: &AppendThirdPartyBlock,
) -> Result<(), Box<dyn Error>> {
    let biscuit_format = if append_third_party_block.raw_input {
        BiscuitFormat::RawBiscuit
    } else {
        BiscuitFormat::Base64Biscuit
    };

    let biscuit_from = if append_third_party_block.biscuit_file == PathBuf::from("-") {
        BiscuitBytes::FromStdin(biscuit_format)
    } else {
        BiscuitBytes::FromFile(
            biscuit_format,
            append_third_party_block.biscuit_file.clone(),
        )
    };

    let block_file_format = if append_third_party_block.raw_block_contents {
        BiscuitFormat::RawBiscuit
    } else {
        BiscuitFormat::Base64Biscuit
    };

    let block_from = match (
        &append_third_party_block.block_contents_file,
        &append_third_party_block.block_contents,
    ) {
        (Some(file), None) if file == &PathBuf::from("-") => {
            BiscuitBytes::FromStdin(block_file_format)
        }
        (Some(file), None) => BiscuitBytes::FromFile(block_file_format, file.to_path_buf()),
        (None, Some(str)) => BiscuitBytes::Base64String(str.to_owned()),
        // the other combinations are prevented by clap
        _ => unreachable!(),
    };

    ensure_no_input_conflict_third_party(&block_from, &biscuit_from)?;

    let biscuit = read_biscuit_from(&biscuit_from)?;

    let new_biscuit = append_third_party_from(&biscuit, &block_from)?;

    let encoded = if append_third_party_block.raw_output {
        new_biscuit.to_vec()?
    } else {
        new_biscuit.to_base64()?.into_bytes()
    };
    let _ = io::stdout().write_all(&encoded);
    Ok(())
}

pub fn main() {
    let opts: Opts = Opts::parse();
    match handle_command(&opts.subcmd) {
        Ok(()) => process::exit(0),
        Err(e) => {
            eprintln!("[Error] {}", &e);
            process::exit(1);
        }
    }
}
