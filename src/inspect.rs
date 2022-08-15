use anyhow::Result;
use biscuit_auth::{
    builder::Policy,
    error::{FailedCheck, Logic, MatchedPolicy, RunLimit, Token},
};
use chrono::offset::Utc;
use std::path::PathBuf;

use crate::cli::*;
use crate::errors::CliError::*;
use crate::input::*;

pub fn handle_inspect(inspect: &Inspect) -> Result<()> {
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
        ensure_no_input_conflict(vf, &biscuit_from)?;
    }

    let biscuit = read_biscuit_from(&biscuit_from)?;

    let content_revocation_ids = biscuit.revocation_identifiers();
    let external_keys = biscuit.external_public_keys();
    for i in 0..biscuit.block_count() {
        if i == 0 {
            println!("Authority block:");
        } else if let Some(Some(epk)) = external_keys.get(i) {
            println!(
                "Block n°{}, (third party, signed by {}):",
                i,
                hex::encode(&epk)
            );
        } else {
            println!("Block n°{}:", i);
        }

        println!("== Datalog ==");
        println!("{}", biscuit.print_block_source(i)?);

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
            if inspect.include_time {
                let now = Utc::now().to_rfc3339();
                let time_fact = format!("time({})", now);
                authorizer_builder.add_fact(time_fact.as_ref())?;
            }
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
            Err(MissingPublicKeyForAuthorization)?
        }
    }

    Ok(())
}

fn display_logic_error(policies: &[Policy], e: &Logic) {
    match e {
        Logic::Unauthorized { policy, checks } => {
            display_matched_policy(policies, policy);
            display_failed_checks(checks);
        }
        Logic::NoMatchingPolicy { checks } => {
            println!("No policy matched");
            display_failed_checks(checks);
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
    if !checks.is_empty() {
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
