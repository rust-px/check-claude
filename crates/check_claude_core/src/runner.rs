use crate::context::CheckContext;
use crate::error::CheckError;
use crate::rule::CheckRule;
use crate::types::{CheckCategory, CheckReport, CheckResult};

pub struct CheckRunner {
    rules: Vec<Box<dyn CheckRule>>,
}

impl Default for CheckRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckRunner {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: impl CheckRule + 'static) {
        self.rules.push(Box::new(rule));
    }

    pub fn add_boxed_rule(&mut self, rule: Box<dyn CheckRule>) {
        self.rules.push(rule);
    }

    pub fn run(&self, ctx: &CheckContext) -> Result<CheckReport, CheckError> {
        let mut results = Vec::with_capacity(self.rules.len());
        for rule in &self.rules {
            let result = rule.run(ctx)?;
            results.push(result);
        }
        Ok(CheckReport::new(results))
    }

    pub fn run_categories(
        &self,
        categories: &[CheckCategory],
        ctx: &CheckContext,
    ) -> Result<CheckReport, CheckError> {
        let mut results = Vec::new();
        for rule in &self.rules {
            if categories.contains(&rule.category()) {
                let result = rule.run(ctx)?;
                results.push(result);
            }
        }
        Ok(CheckReport::new(results))
    }
}
