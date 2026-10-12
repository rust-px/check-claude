use check_claude_core::{
    CheckCategory, CheckContext, CheckError, CheckId, CheckResult, CheckRule, CheckSeverity,
    DiagnosticDetail,
};
use getset::{CopyGetters, Getters};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use crate::region::RegionEligibilityRule;

#[derive(Debug, Deserialize)]
struct IpApiQueryResponse {
    status: Option<String>,
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    country: Option<String>,
    isp: Option<String>,
    org: Option<String>,
    #[serde(rename = "as")]
    as_info: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpWhoIsQueryConnection {
    org: Option<String>,
    isp: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpWhoIsQueryResponse {
    success: Option<bool>,
    country_code: Option<String>,
    country: Option<String>,
    connection: Option<IpWhoIsQueryConnection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Getters)]
#[getset(get = "pub")]
pub struct IpGeoInfo {
    country_code: String,
    country_name: String,
    isp_or_org: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Getters, CopyGetters)]
pub struct NicInterfaceAddress {
    #[getset(get = "pub")]
    interface_name: String,

    #[getset(get_copy = "pub")]
    ip: IpAddr,

    #[getset(get_copy = "pub")]
    is_public: bool,
}

impl NicInterfaceAddress {
    pub fn new(interface_name: impl Into<String>, ip: IpAddr) -> Self {
        let name = interface_name.into();
        let is_pub = is_public_ip(&ip);
        Self {
            interface_name: name,
            ip,
            is_public: is_pub,
        }
    }
}

/// Determines whether an IPv4 address is globally routable according to RFC specifications.
pub fn is_public_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 0.0.0.0/8 (Current network)
    if octets[0] == 0 {
        return false;
    }
    // 10.0.0.0/8 (RFC 1918 Private)
    if octets[0] == 10 {
        return false;
    }
    // 100.64.0.0/10 (RFC 6598 Shared Address Space / CGNAT)
    if octets[0] == 100 && (octets[1] & 0xc0) == 64 {
        return false;
    }
    // 127.0.0.0/8 (RFC 1122 Loopback)
    if octets[0] == 127 {
        return false;
    }
    // 169.254.0.0/16 (RFC 3927 Link-Local)
    if octets[0] == 169 && octets[1] == 254 {
        return false;
    }
    // 172.16.0.0/12 (RFC 1918 Private)
    if octets[0] == 172 && (octets[1] & 0xf0) == 16 {
        return false;
    }
    // 192.0.0.0/24 (RFC 6890 IETF Protocol Assignments)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return false;
    }
    // 192.0.2.0/24 (RFC 5737 Documentation TEST-NET-1)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return false;
    }
    // 192.88.99.0/24 (RFC 7526 6to4 Relay Anycast)
    if octets[0] == 192 && octets[1] == 88 && octets[2] == 99 {
        return false;
    }
    // 192.168.0.0/16 (RFC 1918 Private)
    if octets[0] == 192 && octets[1] == 168 {
        return false;
    }
    // 198.18.0.0/15 (RFC 2544 Benchmarking / Clash Fake-IP)
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return false;
    }
    // 198.51.100.0/24 (RFC 5737 Documentation TEST-NET-2)
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return false;
    }
    // 203.0.113.0/24 (RFC 5737 Documentation TEST-NET-3)
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return false;
    }
    // 224.0.0.0/4 (RFC 5771 Multicast)
    if octets[0] >= 224 && octets[0] <= 239 {
        return false;
    }
    // 240.0.0.0/4 (RFC 1112 Reserved / Class E) & 255.255.255.255 (Broadcast)
    if octets[0] >= 240 {
        return false;
    }
    true
}

/// Determines whether an IPv6 address is globally routable according to RFC specifications.
pub fn is_public_ipv6(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    // ::/128 (Unspecified)
    if ip.is_unspecified() {
        return false;
    }
    // ::1/128 (Loopback)
    if ip.is_loopback() {
        return false;
    }
    // IPv4-mapped (::ffff:0:0/96)
    if segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0xffff
    {
        let v4 = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            (segments[6] & 0xff) as u8,
            (segments[7] >> 8) as u8,
            (segments[7] & 0xff) as u8,
        );
        return is_public_ipv4(&v4);
    }
    // 64:ff9b::/96 (RFC 6052 NAT64)
    if segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
    {
        return false;
    }
    // 100::/64 (RFC 6666 Discard-Only)
    if segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 {
        return false;
    }
    // 2001:db8::/32 (RFC 3849 Documentation)
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return false;
    }
    // 2001:20::/28 (RFC 5180 Benchmarking)
    if segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0020 {
        return false;
    }
    // fc00::/7 (RFC 4193 Unique Local Address - ULA, covers Fake-IP fc00::/18)
    if (segments[0] & 0xfe00) == 0xfc00 {
        return false;
    }
    // fe80::/10 (RFC 4291 Link-Local Unicast)
    if (segments[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    // fec0::/10 (RFC 3879 Site-Local - Deprecated)
    if (segments[0] & 0xffc0) == 0xfec0 {
        return false;
    }
    // ff00::/8 (RFC 4291 Multicast)
    if (segments[0] & 0xff00) == 0xff00 {
        return false;
    }
    // 2000::/3 (Global Unicast Address range: 0x2000 to 0x3fff)
    (segments[0] & 0xe000) == 0x2000
}

/// Determines whether an IP address is a public, globally routable address.
pub fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_ipv4(v4),
        IpAddr::V6(v6) => is_public_ipv6(v6),
    }
}

/// Fast offline heuristic to identify Mainland China telecom operator IPv6 prefixes.
/// Zero-latency and works completely offline without network requests.
pub fn is_china_domestic_ipv6(ip: &Ipv6Addr) -> Option<(&'static str, &'static str)> {
    let segments = ip.segments();
    // China Telecom (240e::/20)
    if segments[0] == 0x240e {
        return Some(("CN", "China Telecom (中国电信)"));
    }
    // China Unicom (2408::/22)
    if segments[0] == 0x2408 {
        return Some(("CN", "China Unicom (中国联通)"));
    }
    // China Mobile (2409::/21)
    if segments[0] == 0x2409 {
        return Some(("CN", "China Mobile (中国移动)"));
    }
    // CERNET (2001:da8::/32)
    if segments[0] == 0x2001 && segments[1] == 0x0da8 {
        return Some(("CN", "CERNET (中国教育网)"));
    }
    // CSTNET (2001:cc0::/32)
    if segments[0] == 0x2001 && segments[1] == 0x0cc0 {
        return Some(("CN", "CSTNET (中科院科技网)"));
    }
    None
}

pub struct NetworkInterfaceIpRule {
    id: CheckId,
}

impl NetworkInterfaceIpRule {
    pub fn try_new() -> Result<Self, CheckError> {
        let id = CheckId::try_new("nic_public_ip_eligibility")?;
        Ok(Self { id })
    }

    /// Resolves geolocation country and organization for a given public IP address.
    pub fn resolve_ip_geo(ip: &IpAddr, timeout_ms: u64) -> Result<IpGeoInfo, CheckError> {
        // 1. Fast offline heuristic for Chinese IPv6
        if let IpAddr::V6(v6) = ip {
            if let Some((code, org)) = is_china_domestic_ipv6(v6) {
                return Ok(IpGeoInfo {
                    country_code: code.to_string(),
                    country_name: "Mainland China".to_string(),
                    isp_or_org: org.to_string(),
                });
            }
        }

        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .build();

        let ip_str = ip.to_string();

        // 2. Primary endpoint: ip-api.com
        let ip_api_url = format!(
            "http://ip-api.com/json/{}?fields=status,countryCode,country,isp,org,as",
            ip_str
        );
        if let Ok(resp) = agent.get(&ip_api_url).call() {
            if let Ok(body) = resp.into_json::<IpApiQueryResponse>() {
                if body.status.as_deref() == Some("success") {
                    if let Some(code) = body.country_code {
                        let name = body.country.unwrap_or_else(|| code.clone());
                        let org = body
                            .org
                            .or(body.isp)
                            .or(body.as_info)
                            .unwrap_or_else(|| "Unknown Provider".to_string());
                        return Ok(IpGeoInfo {
                            country_code: code.to_ascii_uppercase(),
                            country_name: name,
                            isp_or_org: org,
                        });
                    }
                }
            }
        }

        // 3. Fallback endpoint: ipwho.is (HTTPS)
        let ipwho_url = format!("https://ipwho.is/{}", ip_str);
        if let Ok(resp) = agent.get(&ipwho_url).call() {
            if let Ok(body) = resp.into_json::<IpWhoIsQueryResponse>() {
                if body.success.unwrap_or(false) {
                    if let Some(code) = body.country_code {
                        let name = body.country.unwrap_or_else(|| code.clone());
                        let org = body
                            .connection
                            .and_then(|c| c.org.or(c.isp))
                            .unwrap_or_else(|| "Unknown Provider".to_string());
                        return Ok(IpGeoInfo {
                            country_code: code.to_ascii_uppercase(),
                            country_name: name,
                            isp_or_org: org,
                        });
                    }
                }
            }
        }

        Err(CheckError::NetworkProbeFailed {
            target: format!("IP geo lookup for {}", ip_str),
            details: "All remote IP geo endpoints timed out or failed".to_string(),
        })
    }

    /// Collects all non-loopback network interfaces and flags public IP addresses.
    pub fn collect_interface_addresses() -> Result<Vec<NicInterfaceAddress>, CheckError> {
        let ifaces = if_addrs::get_if_addrs().map_err(|err| CheckError::Io(err.to_string()))?;


        let mut list = Vec::new();
        for iface in ifaces {
            if iface.is_loopback() {
                continue;
            }
            let ip = iface.ip();
            list.push(NicInterfaceAddress::new(iface.name, ip));
        }

        Ok(list)
    }
}

impl CheckRule for NetworkInterfaceIpRule {
    fn id(&self) -> &CheckId {
        &self.id
    }

    fn name(&self) -> &str {
        "Network Interface Public IP & Leak Audit"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::RegionEligibility
    }

    fn severity(&self) -> CheckSeverity {
        CheckSeverity::Required
    }

    fn description(&self) -> &str {
        "Scans local network interfaces for public IPv4/IPv6 addresses and verifies they are not in Claude-prohibited regions"
    }

    fn run(&self, ctx: &CheckContext) -> Result<CheckResult, CheckError> {
        let start = Instant::now();
        let timeout_ms = ctx.timeout_ms().clamp(1000, 10000);

        let interfaces = Self::collect_interface_addresses()?;
        let public_interfaces: Vec<&NicInterfaceAddress> =
            interfaces.iter().filter(|addr| addr.is_public()).collect();

        // Fast-path: Clean NAT environment without public IPs bound to NICs
        let lang = ctx.language();
        let name = match lang {
            check_claude_core::Language::English => "Network Interface Public IP & Leak Audit",
            check_claude_core::Language::Chinese => "网卡公网 IP 绑定与泄露审计",
        };

        // Fast-path: Clean NAT environment without public IPs bound to NICs
        if public_interfaces.is_empty() {
            let duration_ms = start.elapsed().as_millis() as u64;
            let (key_count, key_type, val_type, summary) = match lang {
                check_claude_core::Language::English => (
                    "Public IP Count",
                    "Environment Type",
                    "Clean Local / NAT Subnet (No Public IP Exposed)",
                    "No public IPv4/IPv6 addresses bound directly to local network interfaces (Clean NAT)",
                ),
                check_claude_core::Language::Chinese => (
                    "公网 IP 数量",
                    "网络环境类型",
                    "纯局域网 / NAT 子网（无公网 IP 暴露）",
                    "本机网卡未直接绑定公网 IPv4/IPv6 地址（纯内网 NAT 环境，无泄露风险）",
                ),
            };
            let mut details = vec![
                DiagnosticDetail::new(key_count, "0"),
                DiagnosticDetail::new(key_type, val_type),
            ];
            if ctx.verbose() && !interfaces.is_empty() {
                let summary_interfaces: Vec<String> = interfaces
                    .iter()
                    .take(6)
                    .map(|i| format!("{}: {}", i.interface_name(), i.ip()))
                    .collect();
                let joined = summary_interfaces.join(", ");
                let text = if interfaces.len() > 6 {
                    format!("{} (and {} more)", joined, interfaces.len() - 6)
                } else {
                    joined
                };
                let key_scanned = match lang {
                    check_claude_core::Language::English => "Scanned Interfaces",
                    check_claude_core::Language::Chinese => "已扫描网卡接口",
                };
                details.push(DiagnosticDetail::new(key_scanned, text));
            }

            return Ok(CheckResult::pass(
                self.id.clone(),
                name,
                self.category(),
                self.severity(),
                summary,
                details,
                duration_ms,
            ));
        }

        // Public IPs detected on network interfaces
        let mut details = Vec::new();
        let mut geo_map: HashMap<IpAddr, Option<IpGeoInfo>> = HashMap::new();
        let mut has_prohibited_region = false;
        let mut prohibited_reasons = Vec::new();
        let mut has_ipv6_leak = false;
        let mut has_ipv4_restricted = false;
        let mut unsupported_regions = Vec::new();

        for nic_addr in &public_interfaces {
            let ip = nic_addr.ip();
            let iface_name = nic_addr.interface_name();
            let ip_version = match ip {
                IpAddr::V4(_) => "IPv4",
                IpAddr::V6(_) => "IPv6",
            };

            // Fast offline heuristic check first
            let offline_geo = if let IpAddr::V6(v6) = ip {
                is_china_domestic_ipv6(&v6).map(|(code, org)| IpGeoInfo {
                    country_code: code.to_string(),
                    country_name: "Mainland China".to_string(),
                    isp_or_org: org.to_string(),
                })
            } else {
                None
            };

            let geo_opt = if let Some(geo) = offline_geo {
                Some(geo)
            } else if ctx.skip_network() {
                None
            } else {
                match geo_map.get(&ip) {
                    Some(cached) => cached.clone(),
                    None => {
                        let res = Self::resolve_ip_geo(&ip, timeout_ms).ok();
                        geo_map.insert(ip, res.clone());
                        res
                    }
                }
            };

            if let Some(ref geo) = geo_opt {
                let code = geo.country_code().to_ascii_uppercase();
                let key_prefix = match lang {
                    check_claude_core::Language::English => format!("Interface '{}' ({})", iface_name, ip_version),
                    check_claude_core::Language::Chinese => format!("网卡接口 '{}' ({})", iface_name, ip_version),
                };
                details.push(DiagnosticDetail::new(
                    key_prefix,
                    format!("{} - {} [{}] ({})", ip, geo.country_name(), code, geo.isp_or_org()),
                ));

                if code == "CN" || code == "HK" || code == "MO" || code == "RU" || code == "BY" || code == "IR" || code == "KP" {
                    has_prohibited_region = true;
                    if ip.is_ipv6() {
                        has_ipv6_leak = true;
                    } else {
                        has_ipv4_restricted = true;
                    }
                    prohibited_reasons.push(format!("{}: {} ({})", iface_name, ip, code));
                } else if !RegionEligibilityRule::is_supported_region(&code) {
                    unsupported_regions.push(format!("{}: {} ({})", iface_name, ip, code));
                }
            } else {
                let key_prefix = match lang {
                    check_claude_core::Language::English => format!("Interface '{}' ({})", iface_name, ip_version),
                    check_claude_core::Language::Chinese => format!("网卡接口 '{}' ({})", iface_name, ip_version),
                };
                let val_skipped = match lang {
                    check_claude_core::Language::English => format!("{} (Geo probe skipped or timed out)", ip),
                    check_claude_core::Language::Chinese => format!("{} (地理位置探测跳过或超时)", ip),
                };
                details.push(DiagnosticDetail::new(key_prefix, val_skipped));
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        if has_prohibited_region {
            let summary = match lang {
                check_claude_core::Language::English => format!(
                    "Public IP in Claude-prohibited region bound to interface: {}",
                    prohibited_reasons.join(", ")
                ),
                check_claude_core::Language::Chinese => format!(
                    "物理网卡绑定了 Claude 限制地区的公网 IP: {}",
                    prohibited_reasons.join(", ")
                ),
            };

            let remediation = match lang {
                check_claude_core::Language::English => {
                    if has_ipv6_leak && has_ipv4_restricted {
                        "【High Ban Risk】Both public IPv4 and IPv6 addresses in unsupported regions are bound to local network interfaces!\n\
                         Your host environment directly reveals this IP, which Claude clients can detect. Dual-stack traffic will completely expose your true location and trigger account suspension.\n\
                         Remediation:\n\
                         1. IPv6 Leak Prevention: Enable IPv6 routing in Clash/Mihomo/Sing-box, or set 'ipv6: false'. Alternatively, disable IPv6 on your system.\n\
                         2. Server Direct IP: If running on a cloud server, configure global TUN mode proxy or migrate to a server in a supported region (US, JP, SG)."
                    } else if has_ipv6_leak {
                        "【High Ban Risk】A public IPv6 address in Mainland China/Hong Kong is assigned directly to your network interface!\n\
                         Your host environment directly reads this IP, and Claude clients can detect it identically. Dual-stack requests or telemetry can leak your real location, leading to immediate bans.\n\
                         Remediation:\n\
                         1. Proxy config: Enable IPv6 routing in your proxy client (Clash/Mihomo/Sing-box), or set 'ipv6: false' to prevent leaks.\n\
                         2. Linux: Temporarily disable IPv6: sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1\n\
                         3. Windows: In Network Adapter Properties, uncheck 'Internet Protocol Version 6 (TCP/IPv6)'.\n\
                         4. macOS: Run: networksetup -setv6off Wi-Fi"
                    } else {
                        "【Compliance Warning】A public IPv4 address in Mainland China/Hong Kong is directly bound to your network interface.\n\
                         This local IP is detectable by client environments. Claude does NOT support Hong Kong or Mainland China (HK nodes are heavily scrutinized).\n\
                         Remediation: Configure a global TUN mode outbound proxy, or migrate to a server in a supported region (US, JP, SG)."
                    }
                }
                check_claude_core::Language::Chinese => {
                    if has_ipv6_leak && has_ipv4_restricted {
                        "【高危封号风险】检测到本机网卡同时挂载了不支持地区的公网 IPv4 及双栈 IPv6 地址！\n\
                         本机环境能直接获取到网卡公网 IP，Claude 官方客户端与运行时同样能直接读取检测到；同时双栈网络或客户端遥测上报将直接暴露真实物理位置并触发封禁。\n\
                         建议解决方案：\n\
                         1. IPv6 防泄露：在代理软件（Clash/Mihomo/Sing-box）中开启 IPv6 分流或设置 'ipv6: false'，或在系统网络适配器中关闭 IPv6。\n\
                         2. 服务器公网 IP 防范：如当前为云服务器，请务必启用全局出站代理（TUN 模式），或迁移至美国 (US)、日本 (JP)、新加坡 (SG) 节点。"
                    } else if has_ipv6_leak {
                        "【高危封号风险】检测到物理网卡挂载了中国大陆/香港公网 IPv6 地址！\n\
                         本机环境能直接读取到该网卡公网 IP，Claude 官方客户端与运行时同样能直接探测到此接口地址；同时双栈网络请求或客户端遥测极易暴露真实位置，导致账号被官方直接风控封禁。\n\
                         建议解决方案：\n\
                         1. 代理配置：在代理客户端（Clash/Mihomo/Sing-box）中启用 IPv6 分流，或配置 'ipv6: false' 避免泄露。\n\
                         2. Linux 临时关闭 IPv6: sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1\n\
                         3. Windows: 打开“网络连接属性”，取消勾选“Internet 协议版本 6 (TCP/IPv6)”。\n\
                         4. macOS: 在终端执行 networksetup -setv6off Wi-Fi"
                    } else {
                        "【高危合规告警】当前机器网卡直接绑定了不支持地区的公网 IP（中国香港/大陆）。\n\
                         本机能直接检测到该网卡公网 IP，Claude 官方客户端与运行时同样能直接读取检测到；Claude 官方未开放中国香港及大陆地区服务（香港节点是国内最常见的封号重灾区）。\n\
                         建议解决方案：\n\
                         如需在服务器上使用 Claude Code，请配置系统级全局出站代理（TUN 模式），或迁移至美国 (US)、日本 (JP)、新加坡 (SG) 等官方受支持地区的云服务器。"
                    }
                }
            };

            return Ok(CheckResult::fail(
                self.id.clone(),
                name,
                self.category(),
                self.severity(),
                summary,
                details,
                remediation,
                duration_ms,
            ));
        }

        if !unsupported_regions.is_empty() {
            let (summary, suggestion) = match lang {
                check_claude_core::Language::English => (
                    format!(
                        "Interface public IP is in an unrecognized or unsupported region: {}",
                        unsupported_regions.join(", ")
                    ),
                    "Some network interface public IPs are in unrecognized regions. We recommend switching nodes to ensure stability and compliance.",
                ),
                check_claude_core::Language::Chinese => (
                    format!(
                        "网卡公网 IP 所在地区暂未获得官方正式支持: {}",
                        unsupported_regions.join(", ")
                    ),
                    "部分网卡公网 IP 所在地区可能未获得 Anthropic 官方正式支持，建议切换节点以确保稳定性与安全性。",
                ),
            };

            return Ok(CheckResult::warn(
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

        let summary = match lang {
            check_claude_core::Language::English => format!(
                "All {} interface public IP(s) are in officially supported regions",
                public_interfaces.len()
            ),
            check_claude_core::Language::Chinese => format!(
                "检测到的 {} 个网卡公网 IP 均位于 Claude 官方支持地区",
                public_interfaces.len()
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
