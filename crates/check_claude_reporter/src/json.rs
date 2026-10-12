use check_claude_core::{CheckError, CheckReport};

pub struct JsonReporter;

impl JsonReporter {
    pub fn render(report: &CheckReport) -> Result<String, CheckError> {
        serde_json::to_string_pretty(report)
            .map_err(|err| CheckError::Internal(format!("JSON serialization failed: {}", err)))
    }
}
