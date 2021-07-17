use biscuit_auth::crypto::{KeyPair, PrivateKey, PublicKey};
use biscuit_auth::parser::parse_block_source;
use biscuit_auth::token::builder::BiscuitBuilder;
use biscuit_auth::token::Biscuit;
use std::env::var;
use std::io::{self, Read};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "biscuit", about = "Manipulate biscuit tokens")]
enum Command {
    GenerateKeyPair {},
    GetPublicKey {},
    Inspect {
        #[structopt(long)]
        check_signature_with_key: Option<String>,
        #[structopt(long)]
        dump_symbols: bool,
    },
    Verify {
        #[structopt(long)]
        max_facts: Option<u8>,
        #[structopt(long)]
        max_iterations: Option<u8>,
        #[structopt(long)]
        dump_generated_facts: bool,
        #[structopt(parse(from_os_str))]
        verifier: PathBuf,
    },
    Generate {},
    Attenuate {
        #[structopt(long)]
        block: String,
    },
}

fn main() {
    let opt = Command::from_args();
    handle_command(&opt);
}

fn read_private_key() -> PrivateKey {
    let str_value =
        var("BISCUIT_PRIVATE_KEY").expect("Couldn't read private key from BISCUIT_PRIVATE_KEY");
    let bytes = hex::decode(&str_value.into_bytes())
        .expect("Couldn't read hex-encoded private key from BISCUIT_PRIVATE_KEY");
    PrivateKey::from_bytes(&bytes).expect("Couldn't parse private key from BISCUIT_PRIVATE_KEY")
}

fn read_body() -> String {
    let mut buffer = String::new();
    io::stdin()
        .read_to_string(&mut buffer)
        .expect("Couldn't read from standard input");
    buffer.trim().to_owned()
}

fn read_authority_from_stdin<'a>(builder: &mut BiscuitBuilder) {
    let input = read_body();
    let (remaining, result) =
        parse_block_source(&input).expect("Could not parse block from standard input");
    if remaining.to_owned() != "" {
        panic!("remaining input");
    }
    for (fact_str, _) in result.facts {
        builder.add_authority_fact(fact_str).unwrap();
    }
    for (rule_str, _) in result.rules {
        builder.add_authority_rule(rule_str).unwrap();
    }
    for (check_str, _) in result.checks {
        builder.add_authority_rule(check_str).unwrap();
    }
}

fn handle_command(command: &Command) {
    match command {
        Command::GenerateKeyPair {} => {
            let pair = KeyPair::new();
            let pub_bytes = PublicKey::to_bytes(&pair.public());
            let priv_bytes = PrivateKey::to_bytes(&pair.private());
            let encoded_pub = hex::encode(&pub_bytes);
            let encoded_priv = hex::encode(&priv_bytes);
            println!("Generating a new random keypair");
            println!("Private key: {}", &encoded_priv);
            println!("Public key: {}", &encoded_pub);
        }
        Command::GetPublicKey {} => {
            let encoded_priv = read_body();
            let priv_bytes = hex::decode(&encoded_priv)
                .expect("Couldn't read private key from hex-encoded standard input");
            let private_key = PrivateKey::from_bytes(&priv_bytes)
                .expect("Couldn't parse private key from standard input");
            let pair = KeyPair::from(private_key);
            let pub_bytes = pair.public().to_bytes();
            let encoded_pub = hex::encode(&pub_bytes);
            println!("{}", &encoded_pub);
        }
        Command::Generate {} => {
            let root = KeyPair::from(read_private_key());
            let mut builder = Biscuit::builder(&root);
            read_authority_from_stdin(&mut builder);
            let biscuit = builder.build().expect("Error building biscuit"); // todo display error
            let encoded = biscuit.to_base64().expect("Error serializing token");
            println!("{}", &encoded);
        }
        Command::Inspect {
            check_signature_with_key,
            dump_symbols: _,
        } => {
            let encoded_biscuit = read_body();
            let biscuit =
                Biscuit::from_base64(&encoded_biscuit).expect("Couldn't parse biscuit from stdin");

            println!("{}", biscuit.print());

            match check_signature_with_key {
                None => {}
                Some(pub_string) => {
                    let bytes = hex::decode(&pub_string.as_bytes())
                        .expect("Couldn't read hex-encoded public key from the provided value");
                    let public_key = PublicKey::from_bytes(&bytes)
                        .expect("Couldn't parse public key from the provided value");
                    let sig_result = biscuit.check_root_key(public_key);
                    match sig_result {
                        Err(_) => println!("Signature check failed"),
                        Ok(_) => println!("Signature check passed"),
                    }
                }
            }
        }
        _ => println!("todo"),
    }
}
