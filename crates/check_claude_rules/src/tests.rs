use crate::endpoint::EndpointAccessRule;
use crate::fingerprint::FingerprintAuditRule;
use crate::ip_risk::IpRiskProfileRule;
use crate::ipv6::Ipv6EgressCheckRule;
use crate::network::AnthropicNetworkCheckRule;
use crate::nic_ip::{
    is_china_domestic_ipv6, is_public_ip, is_public_ipv4, is_public_ipv6, NetworkInterfaceIpRule,
};
use crate::region::RegionEligibilityRule;
use crate::registry::default_rules;
use check_claude_core::{CheckContext, CheckError, CheckRule, CheckStatus, Language};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};



#[test]
fn test_network_endpoint_parsing() {
    let (h1, p1) = AnthropicNetworkCheckRule::parse_host_and_port("https://api.anthropic.com");
    assert_eq!(h1, "api.anthropic.com");
    assert_eq!(p1, 443);

    let (h2, p2) = AnthropicNetworkCheckRule::parse_host_and_port("http://proxy.local:8080/v1");
    assert_eq!(h2, "proxy.local");
    assert_eq!(p2, 8080);
}

#[test]
fn test_fake_ip_detection_integration() {
    use check_claude_core::is_fake_ip_str;
    assert!(is_fake_ip_str("198.18.0.1"));
    assert!(is_fake_ip_str("198.18.254.100"));
    assert!(is_fake_ip_str("198.19.0.1"));
    assert!(!is_fake_ip_str("160.79.104.10"));
    assert!(!is_fake_ip_str("1.1.1.1"));
}

#[test]
fn test_region_eligibility_whitelist() {
    assert!(RegionEligibilityRule::is_supported_region("US"));
    assert!(RegionEligibilityRule::is_supported_region("JP"));
    assert!(RegionEligibilityRule::is_supported_region("SG"));
    assert!(RegionEligibilityRule::is_supported_region("TW"));
    assert!(RegionEligibilityRule::is_supported_region("GB"));
    assert!(RegionEligibilityRule::is_supported_region("de"));

    // Forbidden / unsupported regions
    assert!(!RegionEligibilityRule::is_supported_region("CN"));
    assert!(!RegionEligibilityRule::is_supported_region("HK"));
    assert!(!RegionEligibilityRule::is_supported_region("MO"));
    assert!(!RegionEligibilityRule::is_supported_region("RU"));

    // Trace parsing
    let sample_trace = "fl=38f123\nip=104.28.19.2\nts=1690000000\ncolo=NRT\nloc=JP\n";
    let (ip, loc, colo) = RegionEligibilityRule::parse_trace_response(sample_trace);
    assert_eq!(ip.as_deref(), Some("104.28.19.2"));
    assert_eq!(loc.as_deref(), Some("JP"));
    assert_eq!(colo.as_deref(), Some("NRT"));

    // Domestic fallback parsing
    let sample_domestic = "当前 IP：114.247.50.2  来自于：中国 北京 北京  电信\n";
    let domestic_parsed = RegionEligibilityRule::parse_domestic_ipip_response(sample_domestic);
    assert_eq!(domestic_parsed, Some(("114.247.50.2".to_string(), "CN".to_string())));
}

#[test]
fn test_ip_risk_datacenter_detection() {
    assert!(IpRiskProfileRule::is_known_datacenter_org("DigitalOcean, LLC"));
    assert!(IpRiskProfileRule::is_known_datacenter_org("Amazon.com, Inc."));
    assert!(IpRiskProfileRule::is_known_datacenter_org("Linode, LLC"));
    assert!(IpRiskProfileRule::is_known_datacenter_org("Oracle Corporation"));
    assert!(IpRiskProfileRule::is_known_datacenter_org("Hetzner Online GmbH"));
    assert!(IpRiskProfileRule::is_known_datacenter_org("Bandwidth VPS Cloud"));

    // Residential/ISP
    assert!(!IpRiskProfileRule::is_known_datacenter_org("Comcast Cable Communications, LLC"));
    assert!(!IpRiskProfileRule::is_known_datacenter_org("AT&T Services, Inc."));
    assert!(!IpRiskProfileRule::is_known_datacenter_org("NTT Communications Corporation"));
}

#[test]
fn test_endpoint_evaluation() {
    // 401 with authentication_error: PASS
    let (pass, blocked, _) = EndpointAccessRule::evaluate_api_response(
        401,
        "{\"type\":\"error\",\"error\":{\"type\":\"authentication_error\",\"message\":\"invalid x-api-key\"}}",
        None,
    );
    assert!(pass);
    assert!(!blocked);

    // 403 with region block: FAIL (blocked = true)
    let (pass2, blocked2, _) = EndpointAccessRule::evaluate_api_response(
        403,
        "{\"type\":\"error\",\"error\":{\"type\":\"permission_error\",\"message\":\"Anthropic's services are not currently available in your region.\"}}",
        None,
    );
    assert!(!pass2);
    assert!(blocked2);

    // Cloudflare 1020: FAIL
    let (pass3, blocked3, _) = EndpointAccessRule::evaluate_api_response(
        403,
        "<html><body>Error 1020 Ray ID: 89abcdef</body></html>",
        None,
    );
    assert!(!pass3);
    assert!(!blocked3);

    // Cloudflare challenge header: FAIL
    let (pass4, blocked4, _) = EndpointAccessRule::evaluate_api_response(
        403,
        "<html><body>Checking your browser</body></html>",
        Some("challenge"),
    );
    assert!(!pass4);
    assert!(!blocked4);
}

#[test]
fn test_fingerprint_timezone_matching() {
    assert!(FingerprintAuditRule::is_china_timezone("Asia/Shanghai"));
    assert!(FingerprintAuditRule::is_china_timezone("PRC"));
    assert!(FingerprintAuditRule::is_china_timezone("CST-8"));
    assert!(FingerprintAuditRule::is_china_timezone("Asia/Chongqing"));

    assert!(!FingerprintAuditRule::is_china_timezone("America/New_York"));
    assert!(!FingerprintAuditRule::is_china_timezone("Asia/Tokyo"));
    assert!(!FingerprintAuditRule::is_china_timezone("Europe/London"));

    assert!(FingerprintAuditRule::is_western_region("US"));
    assert!(FingerprintAuditRule::is_western_region("DE"));
    assert!(!FingerprintAuditRule::is_western_region("JP"));
    assert!(!FingerprintAuditRule::is_western_region("SG"));

    // Locale and language checks
    assert!(FingerprintAuditRule::is_chinese_locale("zh_CN.UTF-8"));
    assert!(FingerprintAuditRule::is_chinese_locale("zh_HK.UTF-8"));
    assert!(FingerprintAuditRule::is_chinese_locale("zh_TW.UTF-8"));
    assert!(FingerprintAuditRule::is_chinese_locale("zh-CN"));
    assert!(FingerprintAuditRule::is_chinese_locale("Chinese"));

    assert!(!FingerprintAuditRule::is_chinese_locale("en_US.UTF-8"));
    assert!(!FingerprintAuditRule::is_chinese_locale("ja_JP.UTF-8"));
    assert!(!FingerprintAuditRule::is_chinese_locale("de_DE.UTF-8"));
}

#[test]
fn test_default_rules_creation() -> Result<(), CheckError> {
    let rules = default_rules()?;
    assert_eq!(rules.len(), 7);
    assert!(rules.iter().any(|r| r.id().as_str() == "nic_public_ip_eligibility"));
    assert!(rules.iter().any(|r| r.id().as_str() == "ipv6_dynamic_egress_probe"));
    Ok(())
}


#[test]
fn test_public_ipv4_classification() {
    // Non-public: loopback, private, link-local, cgnat, fake-ip, multicast, reserved
    assert!(!is_public_ipv4(&Ipv4Addr::new(127, 0, 0, 1)));
    assert!(!is_public_ipv4(&Ipv4Addr::new(10, 0, 1, 2)));
    assert!(!is_public_ipv4(&Ipv4Addr::new(172, 16, 0, 1)));
    assert!(!is_public_ipv4(&Ipv4Addr::new(172, 31, 255, 254)));
    assert!(!is_public_ipv4(&Ipv4Addr::new(192, 168, 1, 1)));
    assert!(!is_public_ipv4(&Ipv4Addr::new(169, 254, 10, 20)));
    assert!(!is_public_ipv4(&Ipv4Addr::new(100, 64, 0, 1)));
    assert!(!is_public_ipv4(&Ipv4Addr::new(100, 127, 255, 254)));
    assert!(!is_public_ipv4(&Ipv4Addr::new(198, 18, 0, 1)));
    assert!(!is_public_ipv4(&Ipv4Addr::new(198, 19, 255, 254)));
    assert!(!is_public_ipv4(&Ipv4Addr::new(192, 0, 2, 1)));
    assert!(!is_public_ipv4(&Ipv4Addr::new(224, 0, 0, 1)));
    assert!(!is_public_ipv4(&Ipv4Addr::new(240, 0, 0, 1)));
    assert!(!is_public_ipv4(&Ipv4Addr::new(255, 255, 255, 255)));
    assert!(!is_public_ipv4(&Ipv4Addr::new(0, 0, 0, 0)));

    // Public IPv4 addresses
    assert!(is_public_ipv4(&Ipv4Addr::new(8, 8, 8, 8)));
    assert!(is_public_ipv4(&Ipv4Addr::new(1, 1, 1, 1)));
    assert!(is_public_ipv4(&Ipv4Addr::new(114, 114, 114, 114)));
    assert!(is_public_ipv4(&Ipv4Addr::new(54, 213, 42, 1)));
    assert!(is_public_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
}

#[test]
fn test_public_ipv6_classification() {
    // Non-public: loopback, unspecified, link-local, ula, documentation, discard, multicast
    assert!(!is_public_ipv6(&Ipv6Addr::LOCALHOST));
    assert!(!is_public_ipv6(&Ipv6Addr::UNSPECIFIED));
    assert!(!is_public_ipv6(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
    assert!(!is_public_ipv6(&Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)));
    assert!(!is_public_ipv6(&Ipv6Addr::new(0xfd12, 0x3456, 0x789a, 0, 0, 0, 0, 1)));
    assert!(!is_public_ipv6(&Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)));
    assert!(!is_public_ipv6(&Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)));
    assert!(!is_public_ipv6(&Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 1)));

    // Public IPv6 addresses
    let ct_v6 = Ipv6Addr::new(0x240e, 0x0382, 0x0001, 0x0002, 0, 0, 0, 1);
    assert!(is_public_ipv6(&ct_v6));
    assert!(is_public_ip(&IpAddr::V6(ct_v6)));

    let cf_v6 = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
    assert!(is_public_ipv6(&cf_v6));
    assert!(is_public_ip(&IpAddr::V6(cf_v6)));
}

#[test]
fn test_china_domestic_ipv6_heuristic() {
    // China Telecom (240e::)
    let ct = Ipv6Addr::new(0x240e, 0x0382, 0x1234, 0x5678, 0, 0, 0, 1);
    let ct_res = is_china_domestic_ipv6(&ct);
    assert_eq!(ct_res.map(|(c, _)| c), Some("CN"));

    // China Unicom (2408::)
    let cu = Ipv6Addr::new(0x2408, 0x8207, 0x1234, 0x5678, 0, 0, 0, 1);
    let cu_res = is_china_domestic_ipv6(&cu);
    assert_eq!(cu_res.map(|(c, _)| c), Some("CN"));

    // China Mobile (2409::)
    let cm = Ipv6Addr::new(0x2409, 0x8800, 0x1234, 0x5678, 0, 0, 0, 1);
    let cm_res = is_china_domestic_ipv6(&cm);
    assert_eq!(cm_res.map(|(c, _)| c), Some("CN"));

    // CERNET (2001:da8::)
    let cernet = Ipv6Addr::new(0x2001, 0x0da8, 0x0200, 0x0001, 0, 0, 0, 1);
    let cernet_res = is_china_domestic_ipv6(&cernet);
    assert_eq!(cernet_res.map(|(c, _)| c), Some("CN"));

    // CSTNET (2001:cc0::)
    let cstnet = Ipv6Addr::new(0x2001, 0x0cc0, 0x0100, 0x0001, 0, 0, 0, 1);
    let cstnet_res = is_china_domestic_ipv6(&cstnet);
    assert_eq!(cstnet_res.map(|(c, _)| c), Some("CN"));

    // Non-China (Cloudflare / Google)
    let cf = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
    assert!(is_china_domestic_ipv6(&cf).is_none());

    let google = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
    assert!(is_china_domestic_ipv6(&google).is_none());
}

#[test]
fn test_nic_rule_execution() -> Result<(), CheckError> {
    let rule = NetworkInterfaceIpRule::try_new()?;
    assert_eq!(rule.id().as_str(), "nic_public_ip_eligibility");

    let ctx_en = CheckContext::new(true, true, 2000, Language::English);
    let res_en = rule.run(&ctx_en)?;
    assert_eq!(res_en.id().as_str(), "nic_public_ip_eligibility");
    assert_eq!(res_en.name(), "Network Interface Public IP & Leak Audit");
    assert!(res_en.status() == CheckStatus::Pass || res_en.status() == CheckStatus::Warn);

    let ctx_zh = CheckContext::new(true, true, 2000, Language::Chinese);
    let res_zh = rule.run(&ctx_zh)?;
    assert_eq!(res_zh.name(), "网卡公网 IP 绑定与泄露审计");
    Ok(())
}

#[test]
fn test_ipv6_egress_rule_execution() -> Result<(), CheckError> {
    let rule = Ipv6EgressCheckRule::try_new()?;
    assert_eq!(rule.id().as_str(), "ipv6_dynamic_egress_probe");

    // 1. In skip-network mode
    let ctx_skip = CheckContext::new(true, true, 2000, Language::English);
    let res_skip = rule.run(&ctx_skip)?;
    assert_eq!(res_skip.status(), CheckStatus::Skipped);

    // 2. In active mode: on host without IPv6 egress, it cleanly returns Pass
    let ctx_active = CheckContext::new(false, true, 2000, Language::English);
    let res_active = rule.run(&ctx_active)?;
    assert!(
        res_active.status() == CheckStatus::Pass
            || res_active.status() == CheckStatus::Warn
            || res_active.status() == CheckStatus::Fail
    );
    Ok(())
}

#[test]
fn test_rules_i18n_localization() -> Result<(), CheckError> {
    let ep_rule = EndpointAccessRule::try_new()?;
    let ctx_skip_en = CheckContext::new(true, false, 1000, Language::English);
    let ctx_skip_zh = CheckContext::new(true, false, 1000, Language::Chinese);

    let res_ep_en = ep_rule.run(&ctx_skip_en)?;
    assert_eq!(res_ep_en.name(), "Anthropic Endpoint & WAF Status");
    assert!(res_ep_en.summary().contains("skipped"));

    let res_ep_zh = ep_rule.run(&ctx_skip_zh)?;
    assert_eq!(res_ep_zh.name(), "Anthropic 官方端点与 WAF 状态");
    assert!(res_ep_zh.summary().contains("跳过"));

    let fp_rule = FingerprintAuditRule::try_new()?;
    let res_fp_en = fp_rule.run(&ctx_skip_en)?;
    assert_eq!(res_fp_en.name(), "Environment & Timezone Consistency");

    let res_fp_zh = fp_rule.run(&ctx_skip_zh)?;
    assert_eq!(res_fp_zh.name(), "系统时区与语言环境指纹审计");

    let net_rule = AnthropicNetworkCheckRule::try_new()?;
    let res_net_en = net_rule.run(&ctx_skip_en)?;
    assert_eq!(res_net_en.name(), "Anthropic API Network Connectivity");

    let res_net_zh = net_rule.run(&ctx_skip_zh)?;
    assert_eq!(res_net_zh.name(), "Anthropic API 网络连通性与代理识别");

    Ok(())
}


