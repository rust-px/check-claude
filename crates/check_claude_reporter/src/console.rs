use check_claude_core::{
    CheckCategory, CheckReport, CheckResult, CheckSeverity, CheckStatus, Language,
};
use colored::Colorize;

pub struct ConsoleReporter {
    verbose: bool,
    show_suggestions: bool,
    language: Language,
}

impl ConsoleReporter {
    pub fn new(verbose: bool, show_suggestions: bool, language: Language) -> Self {
        Self {
            verbose,
            show_suggestions,
            language,
        }
    }

    fn status_badge(status: CheckStatus) -> String {
        match status {
            CheckStatus::Pass => "[PASS]".bold().green().to_string(),
            CheckStatus::Warn => "[WARN]".bold().yellow().to_string(),
            CheckStatus::Fail => "[FAIL]".bold().red().to_string(),
            CheckStatus::Skipped => "[SKIP]".bold().cyan().to_string(),
        }
    }

    fn severity_tag(severity: CheckSeverity, lang: Language) -> &'static str {
        match lang {
            Language::Chinese => match severity {
                CheckSeverity::Required => "(必选项)",
                CheckSeverity::Recommended => "(推荐项)",
                CheckSeverity::Optional => "(可选项)",
            },
            Language::English => match severity {
                CheckSeverity::Required => "(required)",
                CheckSeverity::Recommended => "(recommended)",
                CheckSeverity::Optional => "(optional)",
            },
        }
    }

    pub fn render(&self, report: &CheckReport) -> String {
        let mut out = String::with_capacity(4096);
        let lang = self.language;

        let banner_title = match lang {
            Language::Chinese => "Claude 地区与网络可用性诊断工具",
            Language::English => "Claude Region & Network Availability Checker",
        };

        out.push_str("\n");
        out.push_str(&format!(
            "{}\n",
            "============================================================"
                .bold()
                .cyan()
        ));
        out.push_str(&format!(
            "  {}\n",
            banner_title.bold().white()
        ));
        out.push_str(&format!(
            "{}\n\n",
            "============================================================"
                .bold()
                .cyan()
        ));


        let categories = [
            CheckCategory::RegionEligibility,
            CheckCategory::IpRiskProfile,
            CheckCategory::EndpointAccess,
            CheckCategory::FingerprintAudit,
            CheckCategory::Network,
        ];

        for cat in categories {
            let cat_results = report.results_by_category(cat);
            if cat_results.is_empty() {
                continue;
            }

            out.push_str(&format!(
                "{} {}\n",
                ">>".bold().cyan(),
                cat.label_localized(lang).bold().underline()
            ));

            for res in cat_results {
                let badge = Self::status_badge(res.status());
                let sev = Self::severity_tag(res.severity(), lang).dimmed();
                let duration_tag = if res.duration_ms() > 0 {
                    format!(" ({}ms)", res.duration_ms()).dimmed().to_string()
                } else {
                    String::new()
                };

                out.push_str(&format!(
                    "  {} {} {} {}\n",
                    badge,
                    res.name().bold(),
                    sev,
                    duration_tag
                ));
                out.push_str(&format!("         {}\n", res.summary()));

                if self.verbose && !res.details().is_empty() {
                    for d in res.details() {
                        out.push_str(&format!(
                            "           - {}: {}\n",
                            d.key().dimmed(),
                            d.value()
                        ));
                    }
                }
            }
            out.push_str("\n");
        }

        // Suggestions block
        let issues: Vec<&CheckResult> = report
            .results()
            .iter()
            .filter(|r| r.status() == CheckStatus::Fail || r.status() == CheckStatus::Warn)
            .collect();

        if (self.show_suggestions || !issues.is_empty()) && !issues.is_empty() {
            out.push_str(&format!(
                "{}\n",
                "------------------------------------------------------------".dimmed()
            ));
            let rec_title = match lang {
                Language::Chinese => "整改与修复建议：",
                Language::English => "Actionable Recommendations:",
            };
            out.push_str(&format!("{}\n", rec_title.bold().yellow()));

            for issue in &issues {
                if let Some(sug) = issue.suggestion() {
                    let marker = if issue.status() == CheckStatus::Fail {
                        "[!]".bold().red()
                    } else {
                        "[*]".bold().yellow()
                    };
                    out.push_str(&format!("  {} {}:\n", marker, issue.name().bold()));
                    out.push_str(&format!("      {}\n", sug));
                }
            }
            out.push_str("\n");
        }

        // Summary Bar
        out.push_str(&format!(
            "{}\n",
            "------------------------------------------------------------".dimmed()
        ));
        let pass_rate = report.pass_rate();
        let pass_rate_str = format!("{:.1}%", pass_rate);
        let pass_rate_badge = if (pass_rate - 100.0).abs() < f64::EPSILON {
            pass_rate_str.bold().green()
        } else if pass_rate >= 60.0 {
            pass_rate_str.bold().yellow()
        } else {
            pass_rate_str.bold().red()
        };

        let summary_line = match lang {
            Language::Chinese => format!(
                "汇总统计：{} 通过, {} 警告, {} 失败, {} 跳过 (通过率: {})\n",
                report.pass_count().to_string().bold().green(),
                report.warn_count().to_string().bold().yellow(),
                report.fail_count().to_string().bold().red(),
                report.skipped_count().to_string().bold().cyan(),
                pass_rate_badge
            ),
            Language::English => format!(
                "Summary: {} passed, {} warnings, {} failed, {} skipped (Pass Rate: {})\n",
                report.pass_count().to_string().bold().green(),
                report.warn_count().to_string().bold().yellow(),
                report.fail_count().to_string().bold().red(),
                report.skipped_count().to_string().bold().cyan(),
                pass_rate_badge
            ),
        };
        out.push_str(&summary_line);

        if report.has_critical_failures() {
            let verdict_text = match lang {
                Language::Chinese => {
                    "检测判定：环境未达到要求，存在关键阻断项，请先解决上述问题！"
                }
                Language::English => {
                    "Verdict: Environment is NOT ready for Claude Code. Please resolve critical failures above."
                }
            };
            out.push_str(&format!("{}\n\n", verdict_text.bold().red()));
        } else if report.warn_count() > 0 {
            let verdict_text = match lang {
                Language::Chinese => {
                    "检测判定：环境满足基本要求，但存在次要警告风险，建议适当优化。"
                }
                Language::English => {
                    "Verdict: Environment satisfies requirements with minor warnings. Claude Code can run."
                }
            };
            out.push_str(&format!("{}\n\n", verdict_text.bold().yellow()));
        } else {
            let verdict_text = match lang {
                Language::Chinese => "检测判定：环境完全符合 Claude Code 运行要求！",
                Language::English => "Verdict: Environment is fully ready for Claude Code!",
            };
            out.push_str(&format!("{}\n\n", verdict_text.bold().green()));
        }

        out

    }
}
