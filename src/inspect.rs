use anyhow::Result;
use biscuit_auth::{
    builder::{Fact, Rule},
    datalog::RunLimits,
    error::{FailedCheck, Logic, MatchedPolicy, RunLimit, Token},
    Authorizer, UnverifiedBiscuit,
};
use chrono::offset::Utc;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;

use crate::cli::*;
use crate::errors::CliError::*;
use crate::input::*;

#[derive(Serialize)]
struct TokenBlock {
    code: String,
    external_key: Option<String>,
    revocation_id: String,
}

#[derive(Serialize)]
struct TokenDescription {
    sealed: bool,
    root_key_id: Option<u32>,
    blocks: Vec<TokenBlock>,
}

impl TokenDescription {
    fn render(&self) {
        if self.sealed {
            println!("Sealed biscuit");
        } else {
            println!("Open biscuit");
        }

        for (i, block) in self.blocks.iter().enumerate() {
            if i == 0 {
                if let Some(root_key_id) = self.root_key_id {
                    println!("Authority block (root key identifier: {}):", &root_key_id);
                } else {
                    println!("Authority block:");
                }
            } else if let Some(epk) = &block.external_key {
                println!("Block n°{}, (third party, signed by {}):", i, epk);
            } else {
                println!("Block n°{}:", i);
            }

            println!("== Datalog ==");
            println!("{}", block.code);

            println!("== Revocation id ==");
            println!("{}", block.revocation_id);
            println!("\n==========\n");
        }
    }
}

#[derive(Copy, Clone, Serialize)]
#[serde(untagged)]
enum RResult<A, E> {
    Ok(A),
    Err { error: E },
}

impl<A, E> From<std::result::Result<A, E>> for RResult<A, E> {
    fn from(value: std::result::Result<A, E>) -> Self {
        match value {
            Ok(a) => Self::Ok(a),
            Err(error) => Self::Err { error },
        }
    }
}

impl<A, E> RResult<A, E> {
    pub fn into_result(self) -> std::result::Result<A, E> {
        match self {
            Self::Ok(a) => Ok(a),
            Self::Err { error } => Err(error),
        }
    }
}

#[derive(Serialize)]
struct QueryResult {
    query: String,
    query_all: bool,
    facts: RResult<Vec<String>, Token>,
}

impl QueryResult {
    fn render(&self) {
        println!();
        if self.query_all {
            println!("🔎 Running query on all facts: {}", &self.query);
        } else {
            println!("🔎 Running query: {}", &self.query);
        }
        match &self.facts.clone().into_result() {
            Ok(facts) => {
                if facts.is_empty() {
                    println!("❌ No results");
                } else {
                    for fact in facts {
                        println!("{}", &fact);
                    }
                }
            }
            Err(_) => {
                println!("❌ Query failed");
            }
        }
    }
}

#[derive(Serialize)]
struct AuthResult {
    policies: Vec<String>,
    result: RResult<(usize, String), Token>,
}

impl AuthResult {
    fn render(&self) {
        match &self.result.clone().into_result() {
            Ok((_, policy)) => {
                println!("✅ Authorizer check succeeded 🛡️");
                println!("Matched allow policy: {}", policy);
            }
            Err(e) => {
                println!("❌ Authorizer check failed 🛡️");
                match e {
                    Token::FailedLogic(l) => display_logic_error(&self.policies, l),
                    Token::RunLimit(l) => display_run_limit(l),
                    _ => {}
                }
            }
        }
    }
}

#[derive(Serialize)]
pub struct InspectionResults {
    token: TokenDescription,
    signatures_check: Option<bool>,
    auth: Option<AuthResult>,
    query: Option<QueryResult>,
}

impl InspectionResults {
    pub fn render(&self) {
        self.token.render();

        match self.signatures_check {
            None => println!("🙈 Public key check skipped 🔑"),
            Some(true) => println!("✅ Public key check succeeded 🔑"),
            Some(false) => println!("❌ Public key check failed 🔑"),
        }

        match &self.auth {
            None => println!("🙈 Datalog check skipped 🛡️"),
            Some(auth_result) => auth_result.render(),
        }

        match &self.query {
            None => {}
            Some(query_result) => query_result.render(),
        }
    }

    pub fn ensure_success(&self) -> Result<()> {
        if self.signatures_check == Some(false) {
            Err(SignaturesCheckFailed)?;
        }

        if let Some(ref auth) = self.auth {
            if auth.result.clone().into_result().is_err() {
                Err(AuthorizationFailed)?;
            }
        }

        if let Some(ref query) = self.query {
            if query.facts.clone().into_result().is_err() {
                Err(QueryFailed)?;
            }
        }

        Ok(())
    }
}

fn handle_query(
    query: &Rule,
    query_all: bool,
    all_params: &[Param],
    authorizer: &mut Authorizer,
) -> Result<QueryResult> {
    let mut rule = query.clone();

    for p in all_params {
        match p {
            Param::Term(name, t) => {
                rule.set_lenient(name, t)?;
            }
            Param::PublicKey(name, pk) => {
                rule.set_scope_lenient(name, *pk)?;
            }
        }
    }

    let facts: std::result::Result<Vec<Fact>, Token> = if query_all {
        authorizer.query_all(rule.clone())
    } else {
        authorizer.query(rule.clone())
    };

    Ok(QueryResult {
        query: query.to_string(),
        query_all,
        facts: facts
            .map(|fs| fs.iter().map(|f| f.to_string()).collect::<Vec<_>>())
            .into(),
    })
}

pub fn handle_inspect(inspect: &Inspect) -> Result<()> {
    let res = handle_inspect_inner(inspect)?;
    if inspect.json {
        println!("{}", serde_json::to_string(&res)?);
    } else {
        res.render();
    }
    res.ensure_success()
}

pub fn handle_inspect_inner(inspect: &Inspect) -> Result<InspectionResults> {
    let biscuit_format = if inspect.biscuit_input_args.raw_input {
        BiscuitFormat::RawBiscuit
    } else {
        BiscuitFormat::Base64Biscuit
    };

    let biscuit_from = if inspect.biscuit_input_args.biscuit_file == PathBuf::from("-") {
        BiscuitBytes::FromStdin(biscuit_format)
    } else {
        BiscuitBytes::FromFile(
            biscuit_format,
            inspect.biscuit_input_args.biscuit_file.clone(),
        )
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
        &inspect.authorization_args.authorize_interactive,
        &inspect.authorization_args.authorize_with,
        &inspect.authorization_args.authorize_with_file,
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

    if inspect.query_args.query.is_some() && public_key_from.is_none() {
        Err(MissingPublicKeyForQuerying)?;
    }

    let biscuit = read_biscuit_from(&biscuit_from)?;
    let is_sealed = is_sealed(&biscuit)?;

    let mut blocks = vec![];

    let revocation_ids = biscuit.revocation_identifiers();
    let external_keys = biscuit.external_public_keys();
    for i in 0..biscuit.block_count() {
        let external_key = external_keys
            .get(i)
            .expect("Incorrect block index")
            .clone()
            .map(hex::encode);
        blocks.push(TokenBlock {
            code: biscuit.print_block_source(i)?,
            external_key,
            revocation_id: revocation_ids
                .get(i)
                .map(hex::encode)
                .unwrap_or_else(|| "n/a".to_owned()),
        });
    }

    let token_description = TokenDescription {
        sealed: is_sealed,
        root_key_id: biscuit.root_key_id(),
        blocks,
    };

    let signatures_check;
    let auth_result;
    let query_result;

    if let Some(key_from) = public_key_from {
        let key = read_public_key_from(&key_from)?;
        let sig_result = biscuit.check_signature(|_| key);
        signatures_check = Some(sig_result.is_ok());

        if let Ok(biscuit) = sig_result {
            let mut authorizer_builder = biscuit.authorizer()?;
            if let Some(auth_from) = authorizer_from {
                read_authorizer_from(
                    &auth_from,
                    &inspect.param_arg.param,
                    &mut authorizer_builder,
                )?;
                if inspect.authorization_args.include_time {
                    let now = Utc::now().to_rfc3339();
                    let time_fact = format!("time({})", now);
                    authorizer_builder.add_fact(time_fact.as_ref())?;
                }
                let (_, _, _, policies) = authorizer_builder.dump();

                let authorizer_result = authorizer_builder.authorize_with_limits(RunLimits {
                    max_facts: inspect
                        .authorization_args
                        .max_facts
                        .unwrap_or_else(|| RunLimits::default().max_facts),
                    max_iterations: inspect
                        .authorization_args
                        .max_iterations
                        .unwrap_or_else(|| RunLimits::default().max_iterations),
                    max_time: inspect
                        .authorization_args
                        .max_time
                        .map_or_else(|| RunLimits::default().max_time, |d| d.to_std().unwrap()),
                });

                auth_result = Some(AuthResult {
                    policies: policies.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
                    result: authorizer_result
                        .map(|i| {
                            (
                                i,
                                policies.get(i).expect("Incorrect policy index").to_string(),
                            )
                        })
                        .into(),
                });

                if let Some(snapshot_file) = &inspect.dump_snapshot_to {
                    if inspect.dump_raw_snapshot {
                        let bytes = authorizer_builder.to_raw_snapshot()?;
                        fs::write(snapshot_file, bytes)?;
                    } else {
                        let str = authorizer_builder.to_base64_snapshot()?;
                        fs::write(snapshot_file, str)?;
                    }
                }

                if let Some(query) = &inspect.query_args.query {
                    query_result = Some(handle_query(
                        query,
                        inspect.query_args.query_all,
                        &inspect.param_arg.param,
                        &mut authorizer_builder,
                    )?);
                } else {
                    query_result = None;
                }
            } else {
                auth_result = None;
                if let Some(query) = &inspect.query_args.query {
                    query_result = Some(handle_query(
                        query,
                        inspect.query_args.query_all,
                        &inspect.param_arg.param,
                        &mut authorizer_builder,
                    )?);
                } else {
                    query_result = None;
                }
            }
        } else {
            auth_result = None;
            query_result = None;
        }
    } else {
        signatures_check = None;
        auth_result = None;
        query_result = None;

        if authorizer_from.is_some() {
            Err(MissingPublicKeyForAuthorization)?
        }
    }

    Ok(InspectionResults {
        token: token_description,
        signatures_check,
        auth: auth_result,
        query: query_result,
    })
}

pub fn handle_inspect_snapshot(inspect_snapshot: &InspectSnapshot) -> Result<()> {
    let snapshot_format = if inspect_snapshot.raw_input {
        BiscuitFormat::RawBiscuit
    } else {
        BiscuitFormat::Base64Biscuit
    };

    let snapshot_from = if inspect_snapshot.snapshot_file == PathBuf::from("-") {
        BiscuitBytes::FromStdin(snapshot_format)
    } else {
        BiscuitBytes::FromFile(snapshot_format, inspect_snapshot.snapshot_file.clone())
    };

    let authorizer_from = match (
        &inspect_snapshot.authorization_args.authorize_interactive,
        &inspect_snapshot.authorization_args.authorize_with,
        &inspect_snapshot.authorization_args.authorize_with_file,
    ) {
        (false, None, None) => None,
        (true, None, None) => Some(DatalogInput::FromEditor),
        (false, Some(str), None) => Some(DatalogInput::DatalogString(str.to_owned())),
        (false, None, Some(path)) => Some(DatalogInput::FromFile(path.to_path_buf())),
        // the other combinations are prevented by clap
        _ => unreachable!(),
    };

    if let Some(vf) = &authorizer_from {
        ensure_no_input_conflict(vf, &snapshot_from)?;
    }

    let mut authorizer = read_snapshot_from(&snapshot_from)?;

    println!("{}", authorizer.dump_code());

    if let Some(auth_from) = authorizer_from {
        read_authorizer_from(
            &auth_from,
            &inspect_snapshot.param_arg.param,
            &mut authorizer,
        )?;
        if inspect_snapshot.authorization_args.include_time {
            let now = Utc::now().to_rfc3339();
            let time_fact = format!("time({})", now);
            authorizer.add_fact(time_fact.as_ref())?;
        }
        let (_, _, _, policies) = authorizer.dump();

        let authorizer_result = authorizer.authorize_with_limits(RunLimits {
            max_facts: inspect_snapshot
                .authorization_args
                .max_facts
                .unwrap_or_else(|| RunLimits::default().max_facts),
            max_iterations: inspect_snapshot
                .authorization_args
                .max_iterations
                .unwrap_or_else(|| RunLimits::default().max_iterations),
            max_time: inspect_snapshot
                .authorization_args
                .max_time
                .map_or_else(|| RunLimits::default().max_time, |d| d.to_std().unwrap()),
        });

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
                    Token::FailedLogic(l) => display_logic_error(
                        &policies.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
                        &l,
                    ),
                    Token::RunLimit(l) => display_run_limit(&l),
                    _ => {}
                }
            }
        }
    }

    if let Some(query) = &inspect_snapshot.query_args.query {
        handle_query(
            query,
            inspect_snapshot.query_args.query_all,
            &inspect_snapshot.param_arg.param,
            &mut authorizer,
        )?;
    }

    Ok(())
}

fn display_logic_error(policies: &[String], e: &Logic) {
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

fn display_matched_policy(policies: &[String], policy: &MatchedPolicy) {
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

fn is_sealed(b: &UnverifiedBiscuit) -> Result<bool> {
    match b.seal() {
        Ok(_) => Ok(false),
        Err(Token::AlreadySealed) => Ok(true),
        Err(e) => Err(e.into()),
    }
}
