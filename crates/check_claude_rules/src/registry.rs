use crate::endpoint::EndpointAccessRule;
use crate::fingerprint::FingerprintAuditRule;
use crate::ip_risk::IpRiskProfileRule;
use crate::ipv6::Ipv6EgressCheckRule;
use crate::network::AnthropicNetworkCheckRule;
use crate::nic_ip::NetworkInterfaceIpRule;
use crate::region::RegionEligibilityRule;
use check_claude_core::{CheckError, CheckRule};

pub fn default_rules() -> Result<Vec<Box<dyn CheckRule>>, CheckError> {
    let rules: Vec<Box<dyn CheckRule>> = vec![
        Box::new(RegionEligibilityRule::try_new()?),
        Box::new(NetworkInterfaceIpRule::try_new()?),
        Box::new(Ipv6EgressCheckRule::try_new()?),
        Box::new(IpRiskProfileRule::try_new()?),
        Box::new(EndpointAccessRule::try_new()?),
        Box::new(FingerprintAuditRule::try_new()?),
        Box::new(AnthropicNetworkCheckRule::try_new()?),
    ];

    Ok(rules)
}


