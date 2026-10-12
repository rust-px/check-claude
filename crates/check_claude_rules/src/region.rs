use check_claude_core::{
    CheckCategory, CheckContext, CheckError, CheckId, CheckResult, CheckRule, CheckSeverity,
    DiagnosticDetail,
};
use serde::Deserialize;
use std::time::Instant;

#[derive(Debug, Deserialize)]
struct IpInfoTraceResponse {
    ip: Option<String>,
    country: Option<String>,
}

pub struct RegionEligibilityRule {
    id: CheckId,
}

impl RegionEligibilityRule {
    pub fn try_new() -> Result<Self, CheckError> {
        let id = CheckId::try_new("region_claude_eligibility")?;
        Ok(Self { id })
    }

    pub fn is_supported_region(code: &str) -> bool {
        let upper = code.to_ascii_uppercase();
        SUPPORTED_REGIONS.contains(&upper.as_str())
    }

    pub fn parse_trace_response(body: &str) -> (Option<String>, Option<String>, Option<String>) {
        let mut ip = None;
        let mut loc = None;
        let mut colo = None;

        for line in body.lines() {
            if let Some((k, v)) = line.split_once('=') {
                match k.trim() {
                    "ip" => ip = Some(v.trim().to_string()),
                    "loc" => loc = Some(v.trim().to_uppercase()),
                    "colo" => colo = Some(v.trim().to_string()),
                    _ => {}
                }
            }
        }

        (ip, loc, colo)
    }

    pub fn parse_domestic_ipip_response(body: &str) -> Option<(String, String)> {
        let trimmed = body.trim();
        if let Some(rest) = trimmed.strip_prefix("当前 IP：") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if let Some(ip_str) = parts.first() {
                let loc = if trimmed.contains("中国") {
                    "CN".to_string()
                } else if trimmed.contains("香港") {
                    "HK".to_string()
                } else if trimmed.contains("台湾") {
                    "TW".to_string()
                } else if trimmed.contains("日本") {
                    "JP".to_string()
                } else if trimmed.contains("新加坡") {
                    "SG".to_string()
                } else if trimmed.contains("美国") {
                    "US".to_string()
                } else {
                    "CN".to_string()
                };
                return Some((ip_str.to_string(), loc));
            }
        }
        None
    }

    pub fn fetch_cloudflare_trace(timeout_ms: u64) -> Result<(String, String, Option<String>), CheckError> {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .build();

        // 1. High-availability Cloudflare trace endpoints (primary)
        let cf_endpoints = [
            "https://speed.cloudflare.com/cdn-cgi/trace",
            "https://cloudflare.com/cdn-cgi/trace",
        ];

        for endpoint in cf_endpoints {
            if let Ok(resp) = agent.get(endpoint).call() {
                if let Ok(body) = resp.into_string() {
                    let (ip_opt, loc_opt, colo_opt) = Self::parse_trace_response(&body);
                    if let (Some(ip), Some(loc)) = (ip_opt, loc_opt) {
                        return Ok((ip, loc, colo_opt));
                    }
                }
            }
        }

        // 2. Global HTTPS fallback (ipinfo.io)
        if let Ok(resp) = agent.get("https://ipinfo.io/json").call() {
            if let Ok(info) = resp.into_json::<IpInfoTraceResponse>() {
                if let (Some(ip), Some(country)) = (info.ip, info.country) {
                    return Ok((ip, country.to_uppercase(), Some("ipinfo".to_string())));
                }
            }
        }

        // 3. Domestic China fallback (myip.ipip.net)
        // If overseas endpoints are blocked by GFW, domestic endpoint will immediately confirm Mainland China direct connection
        if let Ok(resp) = agent.get("http://myip.ipip.net").call() {
            if let Ok(body) = resp.into_string() {
                if let Some((ip, loc)) = Self::parse_domestic_ipip_response(&body) {
                    return Ok((ip, loc, Some("Direct-Domestic".to_string())));
                }
            }
        }

        Err(CheckError::NetworkProbeFailed {
            target: "cloudflare.com / ipinfo.io / myip.ipip.net".to_string(),
            details: "All overseas and domestic IP probes timed out or were unreachable".to_string(),
        })
    }
}

impl CheckRule for RegionEligibilityRule {
    fn id(&self) -> &CheckId {
        &self.id
    }

    fn name(&self) -> &str {
        "Claude Region Eligibility"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::RegionEligibility
    }

    fn severity(&self) -> CheckSeverity {
        CheckSeverity::Required
    }

    fn description(&self) -> &str {
        "Verifies whether egress public IP country is officially supported by Claude (Anthropic)"
    }

    fn run(&self, ctx: &CheckContext) -> Result<CheckResult, CheckError> {
        let lang = ctx.language();
        let name = match lang {
            check_claude_core::Language::English => "Claude Region Eligibility",
            check_claude_core::Language::Chinese => "出口 IP 地区可用性",
        };

        if ctx.skip_network() {
            let skip_msg = match lang {
                check_claude_core::Language::English => "Region eligibility check skipped by configuration (--skip-network)",
                check_claude_core::Language::Chinese => "已按配置跳过出口地区合规性检查 (--skip-network)",
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
        let timeout_ms = ctx.timeout_ms().clamp(1000, 10000);

        match Self::fetch_cloudflare_trace(timeout_ms) {
            Ok((ip, loc, colo)) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                let (key_ip, key_loc, key_colo) = match lang {
                    check_claude_core::Language::English => ("Egress IP", "Detected Country/Region", "Cloudflare Edge Colo"),
                    check_claude_core::Language::Chinese => ("出口 IP", "检测到的国家/地区", "Cloudflare 边缘节点"),
                };
                let mut details = vec![
                    DiagnosticDetail::new(key_ip, ip),
                    DiagnosticDetail::new(key_loc, loc.clone()),
                ];
                if let Some(c) = colo {
                    details.push(DiagnosticDetail::new(key_colo, c));
                }

                // Check critical high-risk regions
                if loc == "CN" {
                    let (summary, suggestion) = match lang {
                        check_claude_core::Language::English => (
                            "Egress IP is in Mainland China (CN), which is explicitly unsupported by Claude",
                            "Claude does NOT officially support connections from Mainland China. Please configure a proxy node in an officially supported region (e.g. Japan, Singapore, US, or Taiwan).",
                        ),
                        check_claude_core::Language::Chinese => (
                            "出口 IP 位于中国大陆 (CN)，Claude 官方明确不支持直连",
                            "Claude 官方不支持中国大陆直连。请使用受支持地区的代理或网络节点（如日本、新加坡、美国、中国台湾等）。",
                        ),
                    };
                    return Ok(CheckResult::fail(
                        self.id.clone(),
                        name,
                        self.category(),
                        self.severity(),
                        summary,
                        details,
                        suggestion,
                        duration_ms,
                    ));
                }

                if loc == "HK" {
                    let (summary, suggestion) = match lang {
                        check_claude_core::Language::English => (
                            "Egress IP is in Hong Kong (HK). Claude does NOT support Hong Kong (High Ban Risk)",
                            "Anthropic does NOT support Hong Kong (HK)! HK nodes are the most frequent source of account bans. Switch to Japan (JP), Singapore (SG), US, or Taiwan (TW) immediately.",
                        ),
                        check_claude_core::Language::Chinese => (
                            "出口 IP 位于中国香港 (HK)，Anthropic 官方未开放该地区（高危封号受灾区）",
                            "Anthropic 官方未开放中国香港 (HK) 地区！香港节点是国内用户最常见的封号重灾区。请立即切换至日本 (JP)、新加坡 (SG)、美国 (US) 或中国台湾 (TW) 节点。",
                        ),
                    };
                    return Ok(CheckResult::fail(
                        self.id.clone(),
                        name,
                        self.category(),
                        self.severity(),
                        summary,
                        details,
                        suggestion,
                        duration_ms,
                    ));
                }

                if loc == "MO" {
                    let (summary, suggestion) = match lang {
                        check_claude_core::Language::English => (
                            "Egress IP is in Macau (MO), which is not supported by Claude",
                            "Anthropic does not officially support Macau. Please switch to an officially supported region.",
                        ),
                        check_claude_core::Language::Chinese => (
                            "出口 IP 位于中国澳门 (MO)，Claude 官方未支持",
                            "Anthropic 官方未开放中国澳门地区。请切换至官方受支持地区节点。",
                        ),
                    };
                    return Ok(CheckResult::fail(
                        self.id.clone(),
                        name,
                        self.category(),
                        self.severity(),
                        summary,
                        details,
                        suggestion,
                        duration_ms,
                    ));
                }

                if loc == "RU" || loc == "BY" || loc == "IR" || loc == "KP" {
                    let (summary, suggestion) = match lang {
                        check_claude_core::Language::English => (
                            format!("Egress IP is in {} which is under strict Anthropic trade restriction", loc),
                            "The current region is under strict trade restrictions and cannot access Claude. Please switch your outbound node.",
                        ),
                        check_claude_core::Language::Chinese => (
                            format!("出口 IP 位于 {}，受 Anthropic 严格合规限制", loc),
                            "当前地区受 Anthropic 严格合规限制，无法使用 Claude。请更换出口节点。",
                        ),
                    };
                    return Ok(CheckResult::fail(
                        self.id.clone(),
                        name,
                        self.category(),
                        self.severity(),
                        summary,
                        details,
                        suggestion,
                        duration_ms,
                    ));
                }

                if Self::is_supported_region(&loc) {
                    let summary = match lang {
                        check_claude_core::Language::English => {
                            format!("Egress IP region ({}) is officially supported by Claude", loc)
                        }
                        check_claude_core::Language::Chinese => {
                            format!("出口 IP 所在地区 ({}) 已获得 Claude 官方正式支持", loc)
                        }
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
                } else {
                    let (summary, suggestion) = match lang {
                        check_claude_core::Language::English => (
                            format!("Egress region ({}) is not in the recognized Anthropic supported list", loc),
                            "The current region may not have official Anthropic support. We recommend switching to US, Japan (JP), or Singapore (SG).",
                        ),
                        check_claude_core::Language::Chinese => (
                            format!("出口地区 ({}) 暂未列入 Anthropic 官方支持名单", loc),
                            "当前地区可能未获得 Anthropic 官方支持。建议更换为美国 (US)、日本 (JP) 或新加坡 (SG) 节点以确保稳定。",
                        ),
                    };
                    Ok(CheckResult::warn(
                        self.id.clone(),
                        name,
                        self.category(),
                        self.severity(),
                        summary,
                        details,
                        suggestion,
                        duration_ms,
                    ))
                }
            }
            Err(err) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                let (key_err, summary, suggestion) = match lang {
                    check_claude_core::Language::English => (
                        "Error Details",
                        "Failed to determine egress IP and country through Cloudflare trace",
                        "Cannot connect to Cloudflare to probe egress IP. Please verify network/proxy connection and routing rules.",
                    ),
                    check_claude_core::Language::Chinese => (
                        "错误详情",
                        "无法连接 Cloudflare 探测出口 IP 与国家代码",
                        "无法连接 Cloudflare 探测出口 IP。请检查网络连接、海外代理是否正常开启，并确认网络分流配置。",
                    ),
                };
                let details = vec![DiagnosticDetail::new(key_err, err.to_string())];
                Ok(CheckResult::fail(
                    self.id.clone(),
                    name,
                    self.category(),
                    self.severity(),
                    summary,
                    details,
                    suggestion,
                    duration_ms,
                ))
            }
        }
    }
}


// Anthropic Official Supported Countries & Territories (ISO 3166-1 alpha-2)
const SUPPORTED_REGIONS: &[&str] = &[
    "US", "CA", "GB", "DE", "FR", "JP", "SG", "TW", "KR", "AU", "NZ", "IT", "ES", "NL", "SE",
    "CH", "NO", "DK", "FI", "IE", "BE", "AT", "PT", "PL", "CZ", "RO", "HU", "GR", "BG", "HR",
    "SK", "SI", "LT", "LV", "EE", "CY", "LU", "MT", "IS", "LI", "IL", "AE", "SA", "QA", "KW",
    "BH", "OM", "IN", "MY", "TH", "VN", "ID", "PH", "BR", "MX", "AR", "CL", "CO", "PE", "ZA",
    "EG", "NG", "KE", "MA", "DZ", "TN", "GH", "SN", "CI", "CM", "UG", "TZ", "ET", "CR", "PA",
    "DO", "GT", "SV", "HN", "NI", "EC", "UY", "PY", "BO", "TT", "JM", "BB", "BS", "BZ", "SR",
    "GY", "AM", "AZ", "GE", "KZ", "UZ", "KG", "TJ", "MN", "NP", "BD", "LK", "MV", "BT", "LA",
    "KH", "BN", "PG", "FJ", "SB", "VU", "WS", "TO", "FM", "PW", "MH", "AL", "BA", "ME", "MK",
    "RS", "MD", "UA", "AD", "MC", "SM", "VA",
];
