use crate::error::CheckError;
use getset::{CopyGetters, Getters};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckCategory {
    RegionEligibility,
    IpRiskProfile,
    EndpointAccess,
    FingerprintAudit,
    Network,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    #[default]
    Chinese,
    English,
}

impl Language {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Chinese => "zh",
            Self::English => "en",
        }
    }

    pub fn from_code(code: &str) -> Option<Self> {
        match code.trim().to_lowercase().as_str() {
            "zh" | "cn" | "chinese" | "zh-cn" | "zh_cn" | "zh-hans" => Some(Self::Chinese),
            "en" | "eng" | "english" => Some(Self::English),
            _ => None,
        }
    }
}

impl CheckCategory {
    pub const fn label(&self) -> &'static str {
        self.label_localized(Language::Chinese)
    }

    pub const fn label_localized(&self, lang: Language) -> &'static str {
        match lang {
            Language::Chinese => match self {
                Self::RegionEligibility => "Claude 官方地区可用性",
                Self::IpRiskProfile => "IP 风险画像与机房属性",
                Self::EndpointAccess => "Anthropic 接口与 WAF 拦截状态",
                Self::FingerprintAudit => "客户端时区与语言环境指纹",
                Self::Network => "网络连通性与 Fake-IP 路由",
            },
            Language::English => match self {
                Self::RegionEligibility => "Claude Region Eligibility",
                Self::IpRiskProfile => "IP Risk & ASN Attributes",
                Self::EndpointAccess => "Anthropic Endpoint & WAF Status",
                Self::FingerprintAudit => "Environment & Timezone Consistency",
                Self::Network => "Network Connectivity",
            },
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckSeverity {
    Required,
    Recommended,
    Optional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CheckId(String);

impl CheckId {
    pub fn try_new(raw: impl Into<String>) -> Result<Self, CheckError> {
        let val = raw.into();
        let trimmed = val.trim();
        if trimmed.is_empty() {
            return Err(CheckError::InvalidCheckId("ID cannot be empty".to_string()));
        }
        let is_valid = trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.');
        if !is_valid {
            return Err(CheckError::InvalidCheckId(trimmed.to_string()));
        }
        Ok(Self(trimmed.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CheckId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Getters)]
#[getset(get = "pub")]
pub struct DiagnosticDetail {
    key: String,
    value: String,
}

impl DiagnosticDetail {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Getters, CopyGetters)]
pub struct CheckResult {
    #[getset(get = "pub")]
    id: CheckId,

    #[getset(get = "pub")]
    name: String,

    #[getset(get_copy = "pub")]
    category: CheckCategory,

    #[getset(get_copy = "pub")]
    severity: CheckSeverity,

    #[getset(get_copy = "pub")]
    status: CheckStatus,

    #[getset(get = "pub")]
    summary: String,

    #[getset(get = "pub")]
    details: Vec<DiagnosticDetail>,

    #[getset(get = "pub")]
    suggestion: Option<String>,

    #[getset(get_copy = "pub")]
    duration_ms: u64,
}

impl CheckResult {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: CheckId,
        name: impl Into<String>,
        category: CheckCategory,
        severity: CheckSeverity,
        status: CheckStatus,
        summary: impl Into<String>,
        details: Vec<DiagnosticDetail>,
        suggestion: Option<String>,
        duration_ms: u64,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            category,
            severity,
            status,
            summary: summary.into(),
            details,
            suggestion,
            duration_ms,
        }
    }

    pub fn pass(
        id: CheckId,
        name: impl Into<String>,
        category: CheckCategory,
        severity: CheckSeverity,
        summary: impl Into<String>,
        details: Vec<DiagnosticDetail>,
        duration_ms: u64,
    ) -> Self {
        Self::new(
            id,
            name,
            category,
            severity,
            CheckStatus::Pass,
            summary,
            details,
            None,
            duration_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn warn(
        id: CheckId,
        name: impl Into<String>,
        category: CheckCategory,
        severity: CheckSeverity,
        summary: impl Into<String>,
        details: Vec<DiagnosticDetail>,
        suggestion: impl Into<String>,
        duration_ms: u64,
    ) -> Self {
        Self::new(
            id,
            name,
            category,
            severity,
            CheckStatus::Warn,
            summary,
            details,
            Some(suggestion.into()),
            duration_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn fail(
        id: CheckId,
        name: impl Into<String>,
        category: CheckCategory,
        severity: CheckSeverity,
        summary: impl Into<String>,
        details: Vec<DiagnosticDetail>,
        suggestion: impl Into<String>,
        duration_ms: u64,
    ) -> Self {
        Self::new(
            id,
            name,
            category,
            severity,
            CheckStatus::Fail,
            summary,
            details,
            Some(suggestion.into()),
            duration_ms,
        )
    }

    pub fn skipped(
        id: CheckId,
        name: impl Into<String>,
        category: CheckCategory,
        severity: CheckSeverity,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(
            id,
            name,
            category,
            severity,
            CheckStatus::Skipped,
            reason,
            Vec::new(),
            None,
            0,
        )
    }

    pub fn is_pass(&self) -> bool {
        self.status == CheckStatus::Pass
    }

    pub fn is_fail(&self) -> bool {
        self.status == CheckStatus::Fail
    }

    pub fn is_warn(&self) -> bool {
        self.status == CheckStatus::Warn
    }

    pub fn is_critical_failure(&self) -> bool {
        self.severity == CheckSeverity::Required && self.status == CheckStatus::Fail
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Getters)]
#[getset(get = "pub")]
pub struct CheckReport {
    results: Vec<CheckResult>,
}

impl CheckReport {
    pub fn new(results: Vec<CheckResult>) -> Self {
        Self { results }
    }

    pub fn has_critical_failures(&self) -> bool {
        self.results.iter().any(|r| r.is_critical_failure())
    }

    pub fn pass_count(&self) -> usize {
        self.results.iter().filter(|r| r.is_pass()).count()
    }

    pub fn warn_count(&self) -> usize {
        self.results.iter().filter(|r| r.is_warn()).count()
    }

    pub fn fail_count(&self) -> usize {
        self.results.iter().filter(|r| r.is_fail()).count()
    }

    pub fn skipped_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.status == CheckStatus::Skipped)
            .count()
    }

    pub fn total_count(&self) -> usize {
        self.results.len()
    }

    pub fn pass_rate(&self) -> f64 {
        if self.results.is_empty() {
            100.0
        } else {
            (self.pass_count() as f64 / self.total_count() as f64) * 100.0
        }
    }

    pub fn results_by_category(&self, category: CheckCategory) -> Vec<&CheckResult> {
        self.results.iter().filter(|r| r.category == category).collect()
    }
}
