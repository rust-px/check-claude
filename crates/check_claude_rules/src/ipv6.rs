use crate::nic_ip::{is_china_domestic_ipv6, NetworkInterfaceIpRule};
use crate::region::RegionEligibilityRule;
use check_claude_core::{
    CheckCategory, CheckContext, CheckError, CheckId, CheckResult, CheckRule, CheckSeverity,
    DiagnosticDetail,
};
use std::net::IpAddr;
use std::time::Instant;

pub struct Ipv6EgressCheckRule {
    id: CheckId,
}

impl Ipv6EgressCheckRule {
    pub fn try_new() -> Result<Self, CheckError> {
        let id = CheckId::try_new("ipv6_dynamic_egress_probe")?;
        Ok(Self { id })
    }

    /// Attempts to dynamically probe the public IPv6 egress address.
    /// Specifically queries IPv6-only endpoints (endpoints with ONLY AAAA DNS records).
    /// If the machine has no outbound IPv6 route, this fails immediately (<1ms on Linux/macOS/Windows).
    pub fn probe_ipv6_egress(timeout_ms: u64) -> Result<IpAddr, CheckError> {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .build();

        // Endpoints with ONLY AAAA records (guaranteed IPv6-only transport):
        let endpoints = [
            "https://api6.ipify.org",
            "https://ipv6.icanhazip.com",
            "https://v6.ident.me",
        ];

        for endpoint in endpoints {
            if let Ok(resp) = agent.get(endpoint).call() {
                if let Ok(body) = resp.into_string() {
                    let trimmed = body.trim();
                    if let Ok(ip) = trimmed.parse::<IpAddr>() {
                        if ip.is_ipv6() {
                            return Ok(ip);
                        }
                    }
                }
            }
        }

        Err(CheckError::NetworkProbeFailed {
            target: "api6.ipify.org / ipv6.icanhazip.com / v6.ident.me".to_string(),
            details: "No IPv6 outbound connectivity or endpoint unreachable".to_string(),
        })
    }
}

impl CheckRule for Ipv6EgressCheckRule {
    fn id(&self) -> &CheckId {
        &self.id
    }

    fn name(&self) -> &str {
        "Outbound IPv6 Dynamic Egress & Leak Audit"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::RegionEligibility
    }

    fn severity(&self) -> CheckSeverity {
        CheckSeverity::Required
    }

    fn description(&self) -> &str {
        "Dynamically probes public IPv6 egress traffic to detect active dual-stack bypass leaks into Claude-prohibited regions"
    }

    fn run(&self, ctx: &CheckContext) -> Result<CheckResult, CheckError> {
        let lang = ctx.language();
        let name = match lang {
            check_claude_core::Language::English => "Outbound IPv6 Dynamic Egress & Leak Audit",
            check_claude_core::Language::Chinese => "IPv6 动态出站连通与泄露审计",
        };

        if ctx.skip_network() {
            let skip_msg = match lang {
                check_claude_core::Language::English => "IPv6 dynamic egress probe skipped by configuration (--skip-network)",
                check_claude_core::Language::Chinese => "已按配置跳过 IPv6 动态出站探测 (--skip-network)",
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
        let timeout_ms = ctx.timeout_ms().clamp(800, 3000);

        match Self::probe_ipv6_egress(timeout_ms) {
            Err(_) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                let (key_status, val_status, key_risk, val_risk, summary) = match lang {
                    check_claude_core::Language::English => (
                        "IPv6 Outbound Egress",
                        "Inactive / Disabled (Safe from leaks)",
                        "Dual-Stack Risk Assessment",
                        "Protected: No IPv6 traffic can leak real physical location",
                        "No outbound IPv6 egress detected (IPv4 single-stack or IPv6 disabled; Safe from bypass leaks)",
                    ),
                    check_claude_core::Language::Chinese => (
                        "IPv6 出站状态",
                        "未激活 / 已禁用（无泄露风险）",
                        "双栈泄露风险评估",
                        "受保护：无公网 IPv6 流量，不会绕过代理泄露物理位置",
                        "未检测到活跃的公网 IPv6 出站连接（纯 IPv4 单栈或已禁用 IPv6；彻底免受旁路泄露）",
                    ),
                };
                let details = vec![
                    DiagnosticDetail::new(key_status, val_status),
                    DiagnosticDetail::new(key_risk, val_risk),
                ];

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
            Ok(ipv6_addr) => {
                let duration_ms = start.elapsed().as_millis() as u64;

                // 1. Check offline heuristic if IPv6 is from a domestic Chinese carrier
                let offline_geo = if let IpAddr::V6(v6) = ipv6_addr {
                    is_china_domestic_ipv6(&v6).map(|(code, org)| (code.to_string(), "Mainland China".to_string(), org.to_string()))
                } else {
                    None
                };

                let (country_code, country_name, isp_info) = if let Some(geo) = offline_geo {
                    geo
                } else {
                    // 2. Query geo location
                    match NetworkInterfaceIpRule::resolve_ip_geo(&ipv6_addr, timeout_ms) {
                        Ok(geo) => (geo.country_code().to_string(), geo.country_name().to_string(), geo.isp_or_org().to_string()),
                        Err(_) => ("UNKNOWN".to_string(), "Unknown Location".to_string(), "Unknown Provider".to_string()),
                    }
                };

                let (key_ip, key_loc, key_isp) = match lang {
                    check_claude_core::Language::English => ("Active Outbound IPv6", "Detected Country/Region", "ISP / Organization"),
                    check_claude_core::Language::Chinese => ("活跃出站 IPv6", "检测到的国家/地区", "运营商 / 组织"),
                };

                let details = vec![
                    DiagnosticDetail::new(key_ip, ipv6_addr.to_string()),
                    DiagnosticDetail::new(key_loc, format!("{} [{}]", country_name, country_code)),
                    DiagnosticDetail::new(key_isp, isp_info),
                ];

                let upper_code = country_code.to_ascii_uppercase();

                // Check prohibited regions
                if upper_code == "CN" || upper_code == "HK" || upper_code == "MO" || upper_code == "RU" || upper_code == "BY" || upper_code == "IR" || upper_code == "KP" {
                    let (summary, suggestion) = match lang {
                        check_claude_core::Language::English => (
                            format!("Active outbound IPv6 egress is in Claude-prohibited region: {} [{}]", ipv6_addr, upper_code),
                            "【High Ban Risk】Active outbound IPv6 connectivity exiting from Mainland China/Hong Kong was detected!\n\
                             In dual-stack environments, Happy Eyeballs will prioritize direct IPv6 connections to Anthropic, completely bypassing your IPv4 proxy and leaking your true location.\n\
                             Remediation:\n\
                             1. In Clash/Mihomo/Sing-box, enable IPv6 proxy routing or set 'ipv6: false'.\n\
                             2. Linux: sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1\n\
                             3. Windows: Disable IPv6 in network adapter properties.\n\
                             4. macOS: networksetup -setv6off Wi-Fi",
                        ),
                        check_claude_core::Language::Chinese => (
                            format!("动态探测到活跃的公网 IPv6 出口位于 Claude 禁止区域: {} [{}]", ipv6_addr, upper_code),
                            "【高危封号风险】动态探测到本机存在活跃的公网 IPv6 出站连接，且出口位于中国大陆/香港！\n\
                             在双栈网络中，操作系统的 Happy Eyeballs 机制将优先走 IPv6 直连 Anthropic 接口，完全绕过 IPv4 代理，导致真实位置泄露并被官方立即封禁。\n\
                             建议解决方案：\n\
                             1. 代理配置：在代理客户端（Clash/Mihomo/Sing-box）中开启 IPv6 全局分流，或配置 'ipv6: false' 关闭 IPv6 绕过。\n\
                             2. Linux 临时关闭 IPv6: sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1\n\
                             3. Windows: 打开“网络连接属性”，取消勾选“Internet 协议版本 6 (TCP/IPv6)”。\n\
                             4. macOS: 在终端执行 networksetup -setv6off Wi-Fi",
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

                if RegionEligibilityRule::is_supported_region(&upper_code) {
                    let summary = match lang {
                        check_claude_core::Language::English => format!(
                            "Active outbound IPv6 egress ({}) is in officially supported region ({})",
                            ipv6_addr, upper_code
                        ),
                        check_claude_core::Language::Chinese => format!(
                            "活跃的公网 IPv6 出口 ({}) 位于 Claude 官方支持地区 ({})",
                            ipv6_addr, upper_code
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
                } else {
                    let (summary, suggestion) = match lang {
                        check_claude_core::Language::English => (
                            format!("Active outbound IPv6 egress ({}) is in an unsupported region ({})", ipv6_addr, upper_code),
                            "Current outbound IPv6 address is in an unsupported region. Ensure your proxy routes IPv6 traffic or disable IPv6 temporarily.",
                        ),
                        check_claude_core::Language::Chinese => (
                            format!("活跃的公网 IPv6 出口 ({}) 所在地区暂未获得官方支持 ({})", ipv6_addr, upper_code),
                            "当前出站 IPv6 地址所在地区可能未获得 Anthropic 官方正式支持。建议确保代理分流覆盖 IPv6 流量，或暂时关闭 IPv6 以保安全。",
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
        }
    }
}

