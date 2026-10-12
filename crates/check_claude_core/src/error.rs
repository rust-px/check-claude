use std::io;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CheckError {
    #[error("Command execution failed for '{cmd}': {details}")]
    CommandExecutionFailed { cmd: String, details: String },

    #[error("Network probe failed for '{target}': {details}")]
    NetworkProbeFailed { target: String, details: String },

    #[error("Invalid check identifier '{0}': ID must be non-empty and ASCII alphanumeric/dash/underscore")]
    InvalidCheckId(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("Internal diagnostic error: {0}")]
    Internal(String),
}

impl From<io::Error> for CheckError {
    fn from(err: io::Error) -> Self {
        Self::Io(err.to_string())
    }
}
