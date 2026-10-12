use crate::region::RegionEligibilityRule;
use check_claude_core::{
    CheckCategory, CheckContext, CheckError, CheckId, CheckResult, CheckRule, CheckSeverity,
    DiagnosticDetail,
};
use std::fs;
use std::path::Path;
use std::time::Instant;

pub struct FingerprintAuditRule {
    id: CheckId,
}

impl FingerprintAuditRule {
    pub fn try_new() -> Result<Self, CheckError> {
        let id = CheckId::try_new("timezone_consistency_audit")?;
        Ok(Self { id })
    }

    pub fn detect_local_timezone(ctx: &CheckContext) -> String {
        // 1. Check TZ environment variable
        if let Some(tz) = ctx.get_env("TZ") {
            if !tz.trim().is_empty() {
                return tz.trim().to_string();
            }
        }

        // 2. Check /etc/timezone (Debian/Ubuntu)
        if let Ok(content) = fs::read_to_string("/etc/timezone") {
            let trimmed = content.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }

        // 3. Check /etc/localtime symlink target
        if let Ok(target) = fs::read_link("/etc/localtime") {
            let path_str = target.to_string_lossy();
            if let Some(idx) = path_str.find("zoneinfo/") {
                return path_str[idx + 9..].to_string();
            }
        }

        "Unknown/UTC".to_string()
    }

    pub fn detect_system_locale(ctx: &CheckContext) -> String {
        // 1. Check LC_ALL (highest priority)
        if let Some(lc) = ctx.get_env("LC_ALL") {
            if !lc.trim().is_empty() {
                return lc.trim().to_string();
            }
        }

        // 2. Check LC_MESSAGES
        if let Some(lc) = ctx.get_env("LC_MESSAGES") {
            if !lc.trim().is_empty() {
                return lc.trim().to_string();
            }
        }

        // 3. Check LANG
        if let Some(lang) = ctx.get_env("LANG") {
            if !lang.trim().is_empty() {
                return lang.trim().to_string();
            }
        }

        // 4. Check LANGUAGE
        if let Some(lang) = ctx.get_env("LANGUAGE") {
            if !lang.trim().is_empty() {
                return lang.trim().to_string();
            }
        }

        // 5. Check /etc/locale.conf (systemd Linux)
        if let Ok(content) = fs::read_to_string("/etc/locale.conf") {
            for line in content.lines() {
                if let Some(val) = line.trim().strip_prefix("LANG=") {
                    let clean = val.trim_matches('"').trim_matches('\'').trim();
                    if !clean.is_empty() {
                        return clean.to_string();
                    }
                }
            }
        }

        // 6. Check /etc/default/locale (Debian/Ubuntu)
        if let Ok(content) = fs::read_to_string("/etc/default/locale") {
            for line in content.lines() {
                if let Some(val) = line.trim().strip_prefix("LANG=") {
                    let clean = val.trim_matches('"').trim_matches('\'').trim();
                    if !clean.is_empty() {
                        return clean.to_string();
                    }
                }
            }
        }

        "en_US.UTF-8".to_string()
    }

    pub fn is_chinese_locale(locale: &str) -> bool {
        let lower = locale.to_ascii_lowercase();
        lower.contains("zh_cn")
            || lower.contains("zh_hk")
            || lower.contains("zh_mo")
            || lower.contains("zh_tw")
            || lower.contains("zh-cn")
            || lower.contains("zh-hans")
            || lower.contains("chinese")
    }

    pub fn is_china_timezone(tz: &str) -> bool {
        let lower = tz.to_ascii_lowercase();
        lower.contains("shanghai")
            || lower.contains("chongqing")
            || lower.contains("beijing")
            || lower.contains("prc")
            || lower.contains("cst-8")
            || lower.contains("asia/urumqi")
            || lower.contains("asia/harbin")
    }

    pub fn is_western_region(loc: &str) -> bool {
        matches!(
            loc,
            "US" | "CA" | "GB" | "DE" | "FR" | "NL" | "IE" | "ES" | "IT" | "SE" | "CH" | "NO" | "AU"
        )
    }
}

impl CheckRule for FingerprintAuditRule {
    fn id(&self) -> &CheckId {
        &self.id
    }

    fn name(&self) -> &str {
        "Environment & Timezone Consistency"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::FingerprintAudit
    }

    fn severity(&self) -> CheckSeverity {
        CheckSeverity::Recommended
    }

    fn description(&self) -> &str {
        "Audits host system timezone and locale/language settings against egress IP location to detect high-risk client inconsistencies"
    }

    fn run(&self, ctx: &CheckContext) -> Result<CheckResult, CheckError> {
        let lang = ctx.language();
        let name = match lang {
            check_claude_core::Language::English => "Environment & Timezone Consistency",
            check_claude_core::Language::Chinese => "系统时区与语言环境指纹审计",
        };

        if ctx.skip_network() {
            let skip_msg = match lang {
                check_claude_core::Language::English => {
                    "Timezone and locale consistency audit skipped by configuration (--skip-network)"
                }
                check_claude_core::Language::Chinese => {
                    "已按配置跳过系统时区与语言环境一致性审计 (--skip-network)"
                }
            };
            return Ok(CheckResult::skipped(
                self.id.clone(),
                name,
                self.category(),
                self.severity(),
                skip_msg,
            ));
        }

        let start = Instant::now();
        let timeout_ms = ctx.timeout_ms().clamp(1000, 5000);
        let local_tz = Self::detect_local_timezone(ctx);
        let local_locale = Self::detect_system_locale(ctx);

        let trace_result = RegionEligibilityRule::fetch_cloudflare_trace(timeout_ms);
        let duration_ms = start.elapsed().as_millis() as u64;

        let loc = match trace_result {
            Ok((_, l, _)) => l,
            Err(_) => "UNKNOWN".to_string(),
        };

        let is_cn_tz = Self::is_china_timezone(&local_tz);
        let is_cn_locale = Self::is_chinese_locale(&local_locale);
        let is_west_loc = Self::is_western_region(&loc);

        let key_tz = match lang {
            check_claude_core::Language::English => "Local System Timezone",
            check_claude_core::Language::Chinese => "本机系统时区",
        };
        let key_locale = match lang {
            check_claude_core::Language::English => "System Locale / Language",
            check_claude_core::Language::Chinese => "系统区域与语言 (Locale)",
        };
        let key_loc = match lang {
            check_claude_core::Language::English => "Egress Country/Region",
            check_claude_core::Language::Chinese => "出站出口国家/地区",
        };

        let mut details = vec![
            DiagnosticDetail::new(key_tz, local_tz.clone()),
            DiagnosticDetail::new(key_locale, local_locale.clone()),
            DiagnosticDetail::new(key_loc, loc.clone()),
        ];

        if (is_cn_tz || is_cn_locale) && is_west_loc {
            let conflict_summary = match lang {
                check_claude_core::Language::English => {
                    if is_cn_tz && is_cn_locale {
                        format!("System timezone ({}) and locale ({}) conflict significantly with egress IP location ({})", local_tz, local_locale, loc)
                    } else if is_cn_locale {
                        format!("System locale ({}) conflicts with western egress IP location ({})", local_locale, loc)
                    } else {
                        format!("System timezone ({}) conflicts with western egress IP location ({})", local_tz, loc)
                    }
                }
                check_claude_core::Language::Chinese => {
                    if is_cn_tz && is_cn_locale {
                        format!("系统时区 ({}) 与语言环境 ({}) 与出口 IP 地区 ({}) 存在严重冲突倒挂", local_tz, local_locale, loc)
                    } else if is_cn_locale {
                        format!("系统语言环境 ({}) 与西方出口 IP 地区 ({}) 存在指纹偏差", local_locale, loc)
                    } else {
                        format!("系统时区 ({}) 与西方出口 IP 地区 ({}) 存在指纹偏差", local_tz, loc)
                    }
                }
            };

            let (risk_key, risk_val) = match lang {
                check_claude_core::Language::English => (
                    "Risk Factor",
                    "Severe Client Fingerprint/Geo Discrepancy",
                ),
                check_claude_core::Language::Chinese => (
                    "风控风险项",
                    "时区/语言与网络出口地理严重倒挂",
                ),
            };
            details.push(DiagnosticDetail::new(risk_key, risk_val));

            let suggestion = match lang {
                check_claude_core::Language::English => {
                    "Current system locale is Chinese (e.g. zh_CN) or timezone is UTC+8, while the network egress IP is located in a western country. This prominent fingerprint discrepancy is easily captured by Anthropic client behavioral telemetry (such as Claude Code / Statsig), elevating proxy fraud risk and ban probability. Recommended terminal configuration:\n\
                     export TZ=\"America/New_York\"  # or matching your proxy region\n\
                     export LANG=\"en_US.UTF-8\"     # set English environment to align fingerprints"
                }
                check_claude_core::Language::Chinese => {
                    "当前系统语言为中文（如 zh_CN）或时区为东八区，而网络出口位于远端节点。此类明显的客户端指纹偏差容易被 Anthropic 行为风控画像捕获（如 Claude Code / Statsig 遥测），判定为代理欺诈并增加封号概率。建议在终端执行：\n\
                     export TZ=\"America/New_York\"  # 或与节点所在时区一致\n\
                     export LANG=\"en_US.UTF-8\"     # 设为英文语言环境以对齐指纹"
                }
            };

            Ok(CheckResult::warn(
                self.id.clone(),
                name,
                self.category(),
                self.severity(),
                conflict_summary,
                details,
                suggestion,
                duration_ms,
            ))
        } else {
            let (check_key, check_val) = match lang {
                check_claude_core::Language::English => (
                    "Consistency Check",
                    "Timezone and locale alignment within normal boundaries",
                ),
                check_claude_core::Language::Chinese => (
                    "一致性审计",
                    "时区与语言设置在正常匹配范围内",
                ),
            };
            details.push(DiagnosticDetail::new(check_key, check_val));

            let summary = match lang {
                check_claude_core::Language::English => format!(
                    "System timezone ({}) and locale ({}) are reasonably consistent with egress region ({})",
                    local_tz, local_locale, loc
                ),
                check_claude_core::Language::Chinese => format!(
                    "系统时区 ({}) 与语言 ({}) 与出口地区 ({}) 基本一致或无明显冲突",
                    local_tz, local_locale, loc
                ),
            };

            Ok(CheckResult::pass(
                self.id.clone(),
                name,
                self.category(),
                self.severity(),
                summary,
                details,
                duration_ms,
            ))
        }
    }
}

