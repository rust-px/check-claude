use crate::context::CheckContext;
use crate::error::CheckError;
use crate::types::{CheckCategory, CheckId, CheckResult, CheckSeverity};

pub trait CheckRule: Send + Sync {
    fn id(&self) -> &CheckId;
    fn name(&self) -> &str;
    fn category(&self) -> CheckCategory;
    fn severity(&self) -> CheckSeverity;
    fn description(&self) -> &str;
    fn run(&self, ctx: &CheckContext) -> Result<CheckResult, CheckError>;
}
