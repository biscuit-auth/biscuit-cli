use anyhow::Result;
use biscuit_auth::{
    builder::{Fact, Rule},
    datalog::RunLimits,
    error::{FailedCheck, Logic, MatchedPolicy, RunLimit, Token},
    Authorizer, UnverifiedBiscuit,
};
use chrono::offset::Utc;
use serde::Serialize;
use serde_json::json;
use std::path::PathBuf;
use std::{fmt::Display, fs};

use crate::cli::*;
use crate::errors::CliError::*;
use crate::input::*;

#[derive(Serialize, Debug)]
struct TokenBlock {
    version: u32,
    code: String,
    external_key: Option<String>,
    revocation_id: String,
}

#[derive(Serialize, Debug)]
struct TokenDescription {
    sealed: bool,
    root_key_id: Option<u32>,
    blocks: Vec<TokenBlock>,
}

fn get_version_string(v: u32) -> String {
    match v {
        3 => "v3.0".to_string(),
        4 => "v3.1".to_string(),
        5 => "v3.2".to_string(),
        6 => "v3.3".to_string(),
        _ => "(unsupported version)".to_string(),
    }
}

impl Display for TokenDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.sealed {
            writeln!(f, "Sealed biscuit")?;
        } else {
            writeln!(f, "Open biscuit")?;
        }

        for (i, block) in self.blocks.iter().enumerate() {
            if i == 0 {
                if let Some(root_key_id) = self.root_key_id {
                    writeln!(
                        f,
                        "Authority block (root key identifier: {}):",
                        &root_key_id
                    )?;
                } else {
                    writeln!(f, "Authority block:")?;
                }
            } else if let Some(epk) = &block.external_key {
                writeln!(f, "Block n°{}, (third party, signed by {}):", i, epk)?;
            } else {
                writeln!(f, "Block n°{}:", i)?;
            }

            writeln!(f, "== Datalog {} ==", get_version_string(block.version))?;
            writeln!(f, "{}", block.code)?;

            writeln!(f, "== Revocation id ==")?;
            writeln!(f, "{}", block.revocation_id)?;
            writeln!(f, "\n==========\n")?;
        }
        Ok(())
    }
}

#[derive(Copy, Clone, Serialize, Debug)]
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
    pub fn is_err(&self) -> bool {
        match self {
            Self::Ok(_) => false,
            Self::Err { .. } => true,
        }
    }

    pub fn into_result(self) -> std::result::Result<A, E> {
        match self {
            Self::Ok(a) => Ok(a),
            Self::Err { error } => Err(error),
        }
    }
}

#[derive(Serialize, Debug)]
struct QueryResult {
    query: String,
    query_all: bool,
    facts: RResult<Vec<String>, Token>,
    elapsed_micros: u128,
}

impl Display for QueryResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        if self.query_all {
            writeln!(
                f,
                "🔎 Running query on all facts: {} ({}μs)",
                &self.query, self.elapsed_micros
            )?;
        } else {
            writeln!(
                f,
                "🔎 Running query: {} ({}μs)",
                &self.query, self.elapsed_micros
            )?;
        }
        match &self.facts.clone().into_result() {
            Ok(facts) => {
                if facts.is_empty() {
                    writeln!(f, "❌ No results")?;
                } else {
                    for fact in facts {
                        writeln!(f, "{}", &fact)?;
                    }
                }
            }
            Err(_) => {
                writeln!(f, "❌ Query failed")?;
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Debug)]
struct AuthResult {
    policies: Vec<String>,
    result: RResult<(usize, String), Token>,
    iterations: u64,
    elapsed_micros: Option<u128>,
}

impl Display for AuthResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.result.clone().into_result() {
            Ok((_, policy)) => {
                writeln!(
                    f,
                    "✅ Authorizer check succeeded 🛡️ ({}μs, {} iterations)",
                    self.elapsed_micros
                        .map(|e| e.to_string())
                        .unwrap_or("n/a".to_string()),
                    self.iterations,
                )?;
                writeln!(f, "Matched allow policy: {}", policy)
            }
            Err(e) => {
                writeln!(
                    f,
                    "❌ Authorizer check failed 🛡️ ({}μs, {} iterations)",
                    self.elapsed_micros
                        .map(|e| e.to_string())
                        .unwrap_or("n/a".to_string()),
                    self.iterations,
                )?;
                match e {
                    Token::FailedLogic(l) => display_logic_error(f, &self.policies, l),
                    Token::RunLimit(l) => display_run_limit(f, l),
                    _ => Ok(()),
                }
            }
        }
    }
}

#[derive(Serialize, Debug)]
pub struct InspectionResults {
    token: TokenDescription,
    signatures_check: Option<bool>,
    auth: Option<AuthResult>,
    query: Option<QueryResult>,
}

impl Display for InspectionResults {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.token.fmt(f)?;

        match self.signatures_check {
            None => writeln!(f, "🙈 Public key check skipped 🔑")?,
            Some(true) => writeln!(f, "✅ Public key check succeeded 🔑")?,
            Some(false) => writeln!(f, "❌ Public key check failed 🔑")?,
        }

        match &self.auth {
            None => writeln!(f, "🙈 Datalog check skipped 🛡️")?,
            Some(auth_result) => auth_result.fmt(f)?,
        }

        match &self.query {
            None => Ok(()),
            Some(query_result) => query_result.fmt(f),
        }
    }
}

impl InspectionResults {
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

#[derive(Serialize)]
struct SnapshotDescription {
    code: String,
    iterations: u64,
    elapsed_micros: Option<u128>,
    already_evaluated: bool,
}

impl Display for SnapshotDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.code)?;

        if let Some(elapsed_micros) = self.elapsed_micros {
            writeln!(
                f,
                "⏱️ Execution time: {}μs ({} iterations)",
                elapsed_micros, self.iterations
            )
        } else {
            writeln!(f, "⏱️ Execution time: not evaluated yet")
        }
    }
}

#[derive(Serialize)]
pub struct SnapshotInspectionResults {
    contents: SnapshotDescription,
    evaluation: RResult<SnapshotEvaluationResults, Token>,
}

impl Display for SnapshotInspectionResults {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.contents.fmt(f)?;

        match &self.evaluation {
            RResult::Ok(r) => r.fmt(f),
            RResult::Err { error } => writeln!(f, "❌ Evaluation failed: {}", error),
        }
    }
}

impl SnapshotInspectionResults {
    pub fn ensure_success(&self) -> Result<()> {
        match self.evaluation {
            RResult::Ok(ref eval_result) => eval_result.ensure_success(),
            RResult::Err { .. } => Err(EvaluationFailed)?,
        }
    }
}

#[derive(Serialize, Debug)]
pub struct SnapshotEvaluationResults {
    iterations: u64,
    auth: AuthResult,
    query: Option<QueryResult>,
}

impl Display for SnapshotEvaluationResults {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.auth.fmt(f)?;

        match &self.query {
            None => Ok(()),
            Some(query_result) => query_result.fmt(f),
        }?;

        Ok(())
    }
}

impl SnapshotEvaluationResults {
    pub fn ensure_success(&self) -> Result<()> {
        if self.auth.result.is_err() {
            Err(AuthorizationFailed)?;
        }

        if let Some(ref query_result) = self.query {
            if query_result.facts.is_err() {
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
) -> std::result::Result<QueryResult, Token> {
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
        elapsed_micros: authorizer
            .execution_time()
            .expect("Missing execution time")
            .as_micros(),
    })
}

pub fn handle_inspect(inspect: &Inspect) -> Result<()> {
    match handle_inspect_inner(inspect) {
        Ok(res) => {
            if inspect.json {
                println!("{}", serde_json::to_string(&res)?);
            } else {
                println!("{}", &res);
            }
            res.ensure_success()
        }
        Err(e) => {
            if inspect.json {
                println!("{}", json!({ "error": e.to_string() }))
            }
            Err(e)
        }
    }
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
        &inspect.authorization_args.authorize_with_snapshot,
        &inspect.authorization_args.authorize_with_snapshot_file,
    ) {
        (false, None, None, None, None) => None,
        (true, None, None, None, None) => Some(AuthorizerInput::FromDatalog(
            DatalogInput::FromEditor,
            inspect.param_arg.param.clone(),
        )),
        (false, Some(str), None, None, None) => Some(AuthorizerInput::FromDatalog(
            DatalogInput::DatalogString(str.to_owned()),
            inspect.param_arg.param.clone(),
        )),
        (false, None, Some(path), None, None) => Some(AuthorizerInput::FromDatalog(
            DatalogInput::FromFile(path.to_path_buf()),
            inspect.param_arg.param.clone(),
        )),
        (false, None, None, Some(str), None) => Some(AuthorizerInput::FromSnapshot(
            SnapshotInput::FromString(str.to_owned()),
        )),
        (false, None, None, None, Some(path)) => {
            Some(AuthorizerInput::FromSnapshot(SnapshotInput::FromFile(
                path.to_path_buf(),
                if inspect.authorization_args.authorize_with_raw_snapshot_file {
                    BiscuitFormat::RawBiscuit
                } else {
                    BiscuitFormat::Base64Biscuit
                },
            )))
        }
        // the other combinations are prevented by clap
        _ => unreachable!(),
    };

    if let Some(AuthorizerInput::FromDatalog(dlf, _)) = &authorizer_from {
        ensure_no_input_conflict(dlf, &biscuit_from)?;
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
            .map(|pk| pk.to_string());
        blocks.push(TokenBlock {
            code: biscuit.print_block_source(i)?,
            external_key,
            revocation_id: revocation_ids
                .get(i)
                .map(hex::encode)
                .unwrap_or_else(|| "n/a".to_owned()),
            version: biscuit.block_version(i)?,
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
        let key = read_public_key_from(&key_from, &inspect.key_algorithm)?;
        let sig_result = biscuit.verify(key);
        signatures_check = Some(sig_result.is_ok());

        if let Ok(biscuit) = sig_result {
            let mut authorizer_builder;
            if let Some(auth_from) = authorizer_from {
                authorizer_builder = read_authorizer_from(&auth_from)?;
                if inspect.authorization_args.include_time {
                    let now = Utc::now().to_rfc3339();
                    let time_fact = format!("time({})", now);
                    authorizer_builder = authorizer_builder.fact(time_fact.as_ref())?;
                }
                if let Some(policies_snapshot_file) = &inspect.dump_policies_snapshot_to {
                    if inspect.dump_raw_raw_policies_snapshot {
                        let bytes = authorizer_builder.to_raw_snapshot()?;
                        fs::write(policies_snapshot_file, bytes)?;
                    } else {
                        let str = authorizer_builder.to_base64_snapshot()?;
                        fs::write(policies_snapshot_file, str)?;
                    }
                }

                let mut authorizer = authorizer_builder.build(&biscuit)?;
                let (_, _, _, policies) = authorizer.dump();

                let authorizer_result = authorizer.authorize_with_limits(RunLimits {
                    max_facts: inspect
                        .run_limits_args
                        .max_facts
                        .unwrap_or_else(|| RunLimits::default().max_facts),
                    max_iterations: inspect
                        .run_limits_args
                        .max_iterations
                        .unwrap_or_else(|| RunLimits::default().max_iterations),
                    max_time: inspect
                        .run_limits_args
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
                    iterations: authorizer.iterations(),
                    elapsed_micros: authorizer.execution_time().map(|e| e.as_micros()),
                });

                if let Some(snapshot_file) = &inspect.dump_snapshot_to {
                    if inspect.dump_raw_snapshot {
                        let bytes = authorizer.to_raw_snapshot()?;
                        fs::write(snapshot_file, bytes)?;
                    } else {
                        let str = authorizer.to_base64_snapshot()?;
                        fs::write(snapshot_file, str)?;
                    }
                }

                if let Some(query) = &inspect.query_args.query {
                    query_result = Some(handle_query(
                        query,
                        inspect.query_args.query_all,
                        &inspect.param_arg.param,
                        &mut authorizer,
                    )?);
                } else {
                    query_result = None;
                }
            } else {
                auth_result = None;
                let mut authorizer = biscuit.authorizer()?;
                if let Some(query) = &inspect.query_args.query {
                    query_result = Some(handle_query(
                        query,
                        inspect.query_args.query_all,
                        &inspect.param_arg.param,
                        &mut authorizer,
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
    match handle_inspect_snapshot_inner(inspect_snapshot) {
        Ok(res) => {
            if inspect_snapshot.json {
                println!("{}", serde_json::to_string(&res)?);
            } else {
                println!("{}", &res);
            }
            res.ensure_success()
        }
        Err(e) => {
            if inspect_snapshot.json {
                println!("{}", json!({ "error": e.to_string() }))
            }
            Err(e)
        }
    }
}

pub fn handle_inspect_snapshot_inner(
    inspect_snapshot: &InspectSnapshot,
) -> Result<SnapshotInspectionResults> {
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

    let mut authorizer = read_snapshot_from(&snapshot_from)?;

    let contents = SnapshotDescription {
        code: authorizer.to_string(),
        iterations: authorizer.iterations(),
        elapsed_micros: authorizer.execution_time().map(|d| d.as_micros()),
        already_evaluated: authorizer.execution_time().is_some(),
    };

    let evaluation = handle_snapshot_evaluation(inspect_snapshot, &mut authorizer);

    Ok(SnapshotInspectionResults {
        contents,
        evaluation: evaluation.into(),
    })
}

fn handle_snapshot_evaluation(
    inspect_snapshot: &InspectSnapshot,
    authorizer: &mut Authorizer,
) -> std::result::Result<SnapshotEvaluationResults, Token> {
    let _ = authorizer.run()?;

    let (_, _, _, policies) = authorizer.dump();
    let policies: Vec<String> = policies.into_iter().map(|p| p.to_string()).collect();

    let authorizer_result = authorizer.authorize_with_limits(RunLimits {
        max_facts: inspect_snapshot
            .run_limits_args
            .max_facts
            .unwrap_or_else(|| RunLimits::default().max_facts),
        max_iterations: inspect_snapshot
            .run_limits_args
            .max_iterations
            .unwrap_or_else(|| RunLimits::default().max_iterations),
        max_time: inspect_snapshot
            .run_limits_args
            .max_time
            .map_or_else(|| RunLimits::default().max_time, |d| d.to_std().unwrap()),
    });

    let result = match authorizer_result {
        Ok(policy_id) => RResult::Ok((
            policy_id,
            policies
                .get(policy_id)
                .expect("Incorrect policy index")
                .to_string(),
        )),
        Err(e) => RResult::Err { error: e },
    };

    let auth = AuthResult {
        policies,
        result,
        iterations: authorizer.iterations(),
        elapsed_micros: authorizer.execution_time().map(|e| e.as_micros()),
    };

    let query = inspect_snapshot
        .query_args
        .query
        .as_ref()
        .map(|query| {
            handle_query(
                query,
                inspect_snapshot.query_args.query_all,
                &inspect_snapshot.param_arg.param,
                authorizer,
            )
        })
        .transpose()?;

    Ok(SnapshotEvaluationResults {
        iterations: authorizer.iterations(),
        auth,
        query,
    })
}

fn display_logic_error(
    f: &mut std::fmt::Formatter<'_>,
    policies: &[String],
    e: &Logic,
) -> std::fmt::Result {
    match e {
        Logic::Unauthorized { policy, checks } => {
            display_matched_policy(f, policies, policy)?;
            display_failed_checks(f, checks)
        }
        Logic::NoMatchingPolicy { checks } => {
            writeln!(f, "No policy matched")?;
            display_failed_checks(f, checks)
        }
        e => writeln!(
            f,
            "An execution error happened during authorization: {:?}",
            &e
        ),
    }
}

fn display_matched_policy(
    f: &mut std::fmt::Formatter<'_>,
    policies: &[String],
    policy: &MatchedPolicy,
) -> std::fmt::Result {
    match policy {
        MatchedPolicy::Allow(i) => {
            let policy = policies.get(*i);
            writeln!(
                f,
                "An allow policy matched: {}",
                policy.expect("Incorrect policy index")
            )
        }
        MatchedPolicy::Deny(i) => {
            let policy = policies.get(*i);
            writeln!(
                f,
                "A deny policy matched: {}",
                policy.expect("Incorrect policy index")
            )
        }
    }
}

fn display_failed_checks(
    f: &mut std::fmt::Formatter<'_>,
    checks: &Vec<FailedCheck>,
) -> std::fmt::Result {
    if !checks.is_empty() {
        writeln!(f, "The following checks failed:")?;
    }
    for c in checks {
        match c {
            FailedCheck::Block(bc) => {
                let block_name = if bc.block_id == 0 {
                    "Authority block".to_owned()
                } else {
                    format!("Block {}", &bc.block_id)
                };
                writeln!(f, "  {} check: {}", &block_name, &bc.rule)?;
            }
            FailedCheck::Authorizer(ac) => writeln!(f, "  Authorizer check: {}", &ac.rule)?,
        }
    }
    Ok(())
}

fn display_run_limit(f: &mut std::fmt::Formatter<'_>, e: &RunLimit) -> std::fmt::Result {
    writeln!(
        f,
        "The authorizer execution was aborted: {}",
        &e.to_string()
    )
}

fn is_sealed(b: &UnverifiedBiscuit) -> Result<bool> {
    match b.seal() {
        Ok(_) => Ok(false),
        Err(Token::AlreadySealed) => Ok(true),
        Err(e) => Err(e.into()),
    }
}
