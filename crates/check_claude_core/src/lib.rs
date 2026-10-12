pub mod context;
pub mod error;
pub mod rule;
pub mod runner;
pub mod types;

#[cfg(test)]
mod tests;

pub use context::{is_fake_ip, is_fake_ip_str, CheckContext, CommandOutput};
pub use error::CheckError;
pub use rule::CheckRule;
pub use runner::CheckRunner;
pub use types::{
    CheckCategory, CheckId, CheckReport, CheckResult, CheckSeverity, CheckStatus, DiagnosticDetail,
    Language,
};

