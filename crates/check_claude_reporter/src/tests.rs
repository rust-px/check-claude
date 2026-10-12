use crate::console::ConsoleReporter;
use crate::json::JsonReporter;
use check_claude_core::{
    CheckCategory, CheckError, CheckId, CheckReport, CheckResult, CheckSeverity, DiagnosticDetail,
};

#[test]
fn test_json_reporter_validity() -> Result<(), CheckError> {
    let id = CheckId::try_new("sample_rule")?;
    let res = CheckResult::pass(
        id,
        "Sample Rule",
        CheckCategory::RegionEligibility,
        CheckSeverity::Required,
        "Location verified",
        vec![DiagnosticDetail::new("country", "US")],
        5,
    );

    let report = CheckReport::new(vec![res]);
    let json_str = JsonReporter::render(&report)?;

    assert!(json_str.contains("sample_rule"));
    assert!(json_str.contains("Location verified"));
    assert!(json_str.contains("US"));
    Ok(())
}

#[test]
fn test_console_reporter_rendering() -> Result<(), CheckError> {
    let id = CheckId::try_new("sample_rule")?;
    let res = CheckResult::warn(
        id,
        "Sample Warning",
        CheckCategory::IpRiskProfile,
        CheckSeverity::Recommended,
        "Minor issue detected",
        vec![DiagnosticDetail::new("region", "CN")],
        "Configure proxy endpoint",
        1,
    );

    let report = CheckReport::new(vec![res]);
    let reporter_en = ConsoleReporter::new(true, true, check_claude_core::Language::English);
    let output_en = reporter_en.render(&report);

    assert!(output_en.contains("Sample Warning"));
    assert!(output_en.contains("Minor issue detected"));
    assert!(output_en.contains("Actionable Recommendations:"));
    assert!(output_en.contains("Configure proxy endpoint"));
    assert!(output_en.contains("Summary:"));

    let reporter_zh = ConsoleReporter::new(true, true, check_claude_core::Language::Chinese);
    let output_zh = reporter_zh.render(&report);

    assert!(output_zh.contains("Sample Warning"));
    assert!(output_zh.contains("整改与修复建议："));
    assert!(output_zh.contains("汇总统计："));
    assert!(output_zh.contains("Claude 地区与网络可用性诊断工具"));
    Ok(())
}

