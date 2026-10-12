use check_claude_core::{
    CheckCategory, CheckContext, CheckError, CheckId, CheckResult, CheckRule, CheckSeverity,
    DiagnosticDetail,
};
use serde::Deserialize;
use std::time::Instant;

#[derive(Debug, Deserialize)]
struct IpApiResponse {
    status: Option<String>,
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    isp: Option<String>,
    org: Option<String>,
    #[serde(rename = "as")]
    as_info: Option<String>,
    hosting: Option<bool>,
    proxy: Option<bool>,
    query: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpWhoIsConnection {
    asn: Option<i64>,
    org: Option<String>,
    isp: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpWhoIsSecurity {
    proxy: Option<bool>,
    vpn: Option<bool>,
    hosting: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct IpWhoIsResponse {
    success: Option<bool>,
    ip: Option<String>,
    country_code: Option<String>,
    connection: Option<IpWhoIsConnection>,
    security: Option<IpWhoIsSecurity>,
}

#[derive(Debug, Deserialize)]
struct IpInfoRiskResponse {
    ip: Option<String>,
    org: Option<String>,
}

pub struct IpRiskProfileRule {
    id: CheckId,
}

impl IpRiskProfileRule {
    pub fn try_new() -> Result<Self, CheckError> {
        let id = CheckId::try_new("ip_risk_and_type")?;
        Ok(Self { id })
    }

    pub fn is_known_datacenter_org(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        let dc_keywords = [
            "amazon", "aws", "digitalocean", "linode", "akamai", "oracle", "hetzner",
            "ovh", "vultr", "choopa", "the constant company", "google cloud", "microsoft",
            "azure", "alibaba", "tencent", "m247", "leaseweb", "cogent", "contabo",
            "racknerd", "buyvm", "colocrossing", "hostinger", "server", "hosting",
            "datacenter", "data center", "cloud", "vps", "dedipath", "kamatera",
        ];

        dc_keywords.iter().any(|&kw| lower.contains(kw))
    }

    pub fn probe_ip_intelligence(timeout_ms: u64) -> Result<(String, String, bool, bool), CheckError> {
        let per_endpoint_timeout = timeout_ms.clamp(800, 2500);
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_millis(per_endpoint_timeout))
            .build();

        // 1. Try ip-api.com as primary (supports native 'hosting' & 'proxy' classification)
        let ip_api_url = "http://ip-api.com/json/?fields=status,countryCode,isp,org,as,hosting,proxy,query";
        if let Ok(resp) = agent.get(ip_api_url).call() {
            if let Ok(body) = resp.into_json::<IpApiResponse>() {
                if body.status.as_deref() == Some("success") {
                    let ip = body.query.unwrap_or_else(|| "Unknown".to_string());
                    let as_info = body.as_info.as_deref().unwrap_or("");
                    let isp = body.isp.as_deref().unwrap_or("");
                    let org = body.org.as_deref().unwrap_or("");

                    let org_desc = if !as_info.is_empty() && !isp.is_empty() && !as_info.contains(isp) {
                        format!("{as_info} ({isp})")
                    } else if !as_info.is_empty() {
                        as_info.to_string()
                    } else if !isp.is_empty() {
                        isp.to_string()
                    } else if !org.is_empty() {
                        org.to_string()
                    } else {
                        "Unknown Provider".to_string()
                    };

                    let is_dc_by_keyword = Self::is_known_datacenter_org(&org_desc)
                        || Self::is_known_datacenter_org(as_info)
                        || Self::is_known_datacenter_org(isp)
                        || Self::is_known_datacenter_org(org);

                    let is_hosting = body.hosting.unwrap_or(false) || is_dc_by_keyword;
                    let is_proxy = body.proxy.unwrap_or(false);
                    return Ok((ip, org_desc, is_hosting, is_proxy));
                }
            }
        }

        // 2. Try ipinfo.io as fallback HTTPS provider
        if let Ok(resp) = agent.get("https://ipinfo.io/json").call() {
            if let Ok(body) = resp.into_json::<IpInfoRiskResponse>() {
                if let Some(org_desc) = body.org {
                    let ip = body.ip.unwrap_or_else(|| "Unknown".to_string());
                    let is_hosting = Self::is_known_datacenter_org(&org_desc);
                    return Ok((ip, org_desc, is_hosting, false));
                }
            }
        }

        // 3. Try ipwho.is as fallback
        let ipwho_url = "https://ipwho.is/";
        if let Ok(resp) = agent.get(ipwho_url).call() {
            if let Ok(body) = resp.into_json::<IpWhoIsResponse>() {
                if body.success.unwrap_or(false) {
                    let ip = body.ip.unwrap_or_else(|| "Unknown".to_string());
                    let (org_desc, is_dc_keyword) = if let Some(conn) = body.connection {
                        let name = conn.org.or(conn.isp).unwrap_or_else(|| "Unknown Provider".to_string());
                        let is_kw = Self::is_known_datacenter_org(&name);
                        (name, is_kw)
                    } else {
                        ("Unknown Provider".to_string(), false)
                    };

                    let (is_hosting, is_proxy) = if let Some(sec) = body.security {
                        (sec.hosting.unwrap_or(false) || is_dc_keyword, sec.proxy.unwrap_or(false) || sec.vpn.unwrap_or(false))
                    } else {
                        (is_dc_keyword, false)
                    };

                    return Ok((ip, org_desc, is_hosting, is_proxy));
                }
            }
        }

        Err(CheckError::NetworkProbeFailed {
            target: "ip-api.com / ipinfo.io / ipwho.is".to_string(),
            details: "Failed to query IP intelligence endpoints".to_string(),
        })
    }
}

impl CheckRule for IpRiskProfileRule {
    fn id(&self) -> &CheckId {
        &self.id
    }

    fn name(&self) -> &str {
        "IP Risk & ASN Attributes"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::IpRiskProfile
    }

    fn severity(&self) -> CheckSeverity {
        CheckSeverity::Recommended
    }

    fn description(&self) -> &str {
        "Inspects public IP ASN attributes and detects Datacenter/Hosting vs Residential IP risk"
    }

    fn run(&self, ctx: &CheckContext) -> Result<CheckResult, CheckError> {
        let lang = ctx.language();
        let name = match lang {
            check_claude_core::Language::English => "IP Risk & ASN Attributes",
            check_claude_core::Language::Chinese => "IP 风险画像与机房属性",
        };

        if ctx.skip_network() {
            let skip_msg = match lang {
                check_claude_core::Language::English => "IP risk profile check skipped by configuration (--skip-network)",
                check_claude_core::Language::Chinese => "已按配置跳过 IP 风险画像检查 (--skip-network)",
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

        match Self::probe_ip_intelligence(timeout_ms) {
            Ok((ip, org, is_hosting, is_proxy)) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                let (ip_type_str, risk_level) = match lang {
                    check_claude_core::Language::English => {
                        let t = if is_hosting { "Data Center / Cloud Hosting" } else { "ISP / Residential Broadband" };
                        let r = if is_hosting { "High Ban Risk" } else { "Low Ban Risk / Safe" };
                        (t, r)
                    }
                    check_claude_core::Language::Chinese => {
                        let t = if is_hosting { "机房 / 云服务器 (Data Center)" } else { "家庭宽带 / 原生住宅 (Residential)" };
                        let r = if is_hosting { "封号风险较高" } else { "相对安全" };
                        (t, r)
                    }
                };

                let (key_ip, key_org, key_type, key_risk) = match lang {
                    check_claude_core::Language::English => ("Target IP", "Organization / ISP", "Network Type", "Ban Risk Assessment"),
                    check_claude_core::Language::Chinese => ("目标 IP", "运营商 / 组织", "网络类型", "封号风险评估"),
                };

                let mut details = vec![
                    DiagnosticDetail::new(key_ip, ip),
                    DiagnosticDetail::new(key_org, org.clone()),
                    DiagnosticDetail::new(key_type, ip_type_str.to_string()),
                    DiagnosticDetail::new(key_risk, risk_level.to_string()),
                ];

                if is_proxy {
                    let (key_proxy, val_proxy) = match lang {
                        check_claude_core::Language::English => ("Proxy/VPN Flag", "Detected"),
                        check_claude_core::Language::Chinese => ("代理/VPN 特征", "已检测到"),
                    };
                    details.push(DiagnosticDetail::new(key_proxy, val_proxy));
                }

                if is_hosting {
                    let (summary, suggestion) = match lang {
                        check_claude_core::Language::English => (
                            format!("Egress IP is identified as a Data Center IP ({})", org),
                            "The current node is a Data Center / Cloud VPS IP. Anthropic strictly audits datacenter IPs and frequently applies bulk risk controls. Consider using a native Residential/ISP proxy to improve stability.",
                        ),
                        check_claude_core::Language::Chinese => (
                            format!("出口 IP 被识别为数据中心/云机房 IP ({})", org),
                            "当前节点为数据中心/云机房 IP（如 VPS 或机场常见机房）。Anthropic 对机房 IP 的审计极严，容易遭遇批量连坐封号。建议选用原生住宅宽带（Residential/ISP）节点以提高账号安全性。",
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
                } else {
                    let summary = match lang {
                        check_claude_core::Language::English => {
                            format!("Egress IP is identified as an ISP/Residential network ({})", org)
                        }
                        check_claude_core::Language::Chinese => {
                            format!("出口 IP 属于原生住宅/ISP 宽带网络 ({})", org)
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
                }
            }
            Err(err) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                let (key_probe, summary, suggestion) = match lang {
                    check_claude_core::Language::English => (
                        "Probe Warning",
                        "Could not resolve IP ASN risk profile (API query timed out)",
                        "Unable to fetch IP ASN attributes, but fundamental connectivity is intact.",
                    ),
                    check_claude_core::Language::Chinese => (
                        "探测警告",
                        "无法获取 IP 的 ASN 风险画像（API 查询超时）",
                        "无法获取 IP 的 ASN 属性，但不影响基础通信。建议关注节点是否为住宅 IP。",
                    ),
                };
                let details = vec![DiagnosticDetail::new(key_probe, err.to_string())];
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
    }
}

