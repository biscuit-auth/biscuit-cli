use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CliError {
    #[error("file not found: {0}")]
    FileNotFound(PathBuf),
    #[error("I cannot read input from both stdin and an interactive editor. Please use proper files or flags instead.")]
    StdinEditorConflict,
    #[error("I cannot read several pieces of input from stdin at the same time. Please use proper files or flags instead.")]
    MultipleStdinsConflict,
    #[error("Can't read binary content from an interactive terminal. Please pipe the content or use a proper file.")]
    BinaryFromTTY,
    #[error("Can't start an editor outside of an interactive terminal")]
    EditorOutsideTTY,
    #[error("Failed reading the datalog temporary file")]
    FailedReadingTempFile,
    #[error("Failed to parse EDITOR environment variable")]
    FailedParsingEditorEnvVar,
    #[error("Failed to parse {0}: {1}")]
    ParseError(String, String),
    #[error("Duration outside representable intervals")]
    InvalidDuration,
    #[error("A public key is required when authorizing a biscuit")]
    MissingPublicKeyForAuthorization,
    #[error("A public key is required when querying a biscuit")]
    MissingPublicKeyForQuerying,
    #[error("Signatures check failed")]
    SignaturesCheckFailed,
    #[error("Authorization failed")]
    AuthorizationFailed,
    #[error("Querying failed")]
    QueryFailed,
}
