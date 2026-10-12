use crate::context::CheckContext;
use crate::error::CheckError;
use crate::rule::CheckRule;
use crate::runner::CheckRunner;
use crate::types::{
    CheckCategory, CheckId, CheckReport, CheckResult, CheckSeverity, CheckStatus, DiagnosticDetail,
};
use std::collections::HashMap;

struct MockRule {
    id: CheckId,
    should_pass: bool,
}

impl CheckRule for MockRule {
    fn id(&self) -> &CheckId {
        &self.id
    }

    fn name(&self) -> &str {
        "Mock Rule"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::IpRiskProfile
    }

    fn severity(&self) -> CheckSeverity {
        CheckSeverity::Required
    }

    fn description(&self) -> &str {
        "A mock diagnostic rule for unit testing"
    }

    fn run(&self, _ctx: &CheckContext) -> Result<CheckResult, CheckError> {
        if self.should_pass {
            Ok(CheckResult::pass(
                self.id.clone(),
                "Mock Rule",
                CheckCategory::IpRiskProfile,
                CheckSeverity::Required,
                "Passed successfully",
                vec![DiagnosticDetail::new("key", "val")],
                5,
            ))
        } else {
            Ok(CheckResult::fail(
                self.id.clone(),
                "Mock Rule",
                CheckCategory::IpRiskProfile,
                CheckSeverity::Required,
                "Failed requirement",
                vec![],
                "Please fix this mock issue",
                10,
            ))
        }
    }
}

#[test]
fn test_check_id_validation() {
    let valid = CheckId::try_new("node_runtime-18");
    assert!(valid.is_ok());
    if let Ok(id) = valid {
        assert_eq!(id.as_str(), "node_runtime-18");
    }

    let empty = CheckId::try_new("   ");
    assert!(empty.is_err());

    let invalid_chars = CheckId::try_new("invalid id with spaces!");
    assert!(invalid_chars.is_err());
}

#[test]
fn test_check_result_predicates() -> Result<(), CheckError> {
    let id = CheckId::try_new("test_rule")?;

    let pass_res = CheckResult::pass(
        id.clone(),
        "Test Pass",
        CheckCategory::RegionEligibility,
        CheckSeverity::Required,
        "All good",
        vec![],
        1,
    );
    assert!(pass_res.is_pass());
    assert!(!pass_res.is_fail());
    assert!(!pass_res.is_critical_failure());

    let fail_res = CheckResult::fail(
        id,
        "Test Fail",
        CheckCategory::RegionEligibility,
        CheckSeverity::Required,
        "Failed",
        vec![],
        "Suggestion",
        1,
    );
    assert!(fail_res.is_fail());
    assert!(fail_res.is_critical_failure());
    Ok(())
}

#[test]
fn test_check_report_aggregation() -> Result<(), CheckError> {
    let id1 = CheckId::try_new("rule_1")?;
    let id2 = CheckId::try_new("rule_2")?;

    let res1 = CheckResult::pass(
        id1,
        "Rule 1",
        CheckCategory::IpRiskProfile,
        CheckSeverity::Required,
        "Pass",
        vec![],
        2,
    );
    let res2 = CheckResult::warn(
        id2,
        "Rule 2",
        CheckCategory::Network,
        CheckSeverity::Recommended,
        "Warn",
        vec![],
        "Fix it",
        4,
    );

    let report = CheckReport::new(vec![res1, res2]);
    assert_eq!(report.pass_count(), 1);
    assert_eq!(report.warn_count(), 1);
    assert_eq!(report.fail_count(), 0);
    assert_eq!(report.total_count(), 2);
    assert!((report.pass_rate() - 50.0).abs() < f64::EPSILON);
    assert!(!report.has_critical_failures());

    let ip_results = report.results_by_category(CheckCategory::IpRiskProfile);
    assert_eq!(ip_results.len(), 1);
    Ok(())
}

#[test]
fn test_runner_execution() -> Result<(), CheckError> {
    let mut runner = CheckRunner::new();
    let id = CheckId::try_new("mock_test")?;
    runner.add_rule(MockRule {
        id,
        should_pass: true,
    });

    let mut env = HashMap::new();
    env.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
    let ctx = CheckContext::with_env(env, true, false, 1000, crate::types::Language::English);

    let report = runner.run(&ctx)?;
    assert_eq!(report.pass_count(), 1);
    assert!(!report.has_critical_failures());
    Ok(())
}

#[test]
fn test_language_parsing() {
    use crate::types::Language;
    assert_eq!(Language::from_code("en"), Some(Language::English));
    assert_eq!(Language::from_code("ENG"), Some(Language::English));
    assert_eq!(Language::from_code("English"), Some(Language::English));
    assert_eq!(Language::from_code("zh"), Some(Language::Chinese));
    assert_eq!(Language::from_code("zh-cn"), Some(Language::Chinese));
    assert_eq!(Language::from_code("Chinese"), Some(Language::Chinese));
    assert_eq!(Language::from_code("fr"), None);
    assert_eq!(Language::default(), Language::Chinese);
    assert_eq!(Language::Chinese.as_str(), "zh");
    assert_eq!(Language::English.as_str(), "en");
}


#[test]
fn test_fake_ip_identification() {
    use crate::context::{is_fake_ip, is_fake_ip_str};
    use std::net::IpAddr;

    // Standard Clash / Mihomo / Sing-box / Surge Fake-IP (198.18.0.0/15)
    assert!(is_fake_ip_str("198.18.0.1"));
    assert!(is_fake_ip_str("198.18.100.200"));
    assert!(is_fake_ip_str("198.19.0.1"));
    assert!(is_fake_ip_str("198.19.255.254"));

    if let Ok(ip_fake) = "198.18.0.2".parse::<IpAddr>() {
        assert!(is_fake_ip(&ip_fake));
    }

    // IPv6 Fake-IP (Clash Meta fake-ip-range6 default: fc00::/18)
    assert!(is_fake_ip_str("fc00::1"));
    assert!(is_fake_ip_str("fc10::1"));

    // Real IPs and public routable IPs
    assert!(!is_fake_ip_str("160.79.104.10")); // Anthropic direct IP
    assert!(!is_fake_ip_str("104.28.19.2"));   // Cloudflare
    assert!(!is_fake_ip_str("1.1.1.1"));
    assert!(!is_fake_ip_str("198.20.0.1"));    // Outside /15
    assert!(!is_fake_ip_str("192.168.1.1"));   // Private RFC 1918
    assert!(!is_fake_ip_str("127.0.0.1"));     // Loopback
    assert!(!is_fake_ip_str("2606:4700::6810")); // Real IPv6
    assert!(!is_fake_ip_str("not_an_ip"));
}
