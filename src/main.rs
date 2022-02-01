use biscuit_auth::{
    Biscuit, {KeyPair, PrivateKey},
};
use clap::Parser;
use std::error::Error;
use std::io::Write;
use std::io::{self};
use std::path::PathBuf;

mod cli;
mod errors;
mod input;
mod inspect;

use cli::*;
use input::*;
use inspect::*;

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
