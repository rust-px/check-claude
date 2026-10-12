use check_claude_core::{
    is_fake_ip, CheckCategory, CheckContext, CheckError, CheckId, CheckResult, CheckRule,
    CheckSeverity, DiagnosticDetail,
};

pub struct AnthropicNetworkCheckRule {
    id: CheckId,
}

impl AnthropicNetworkCheckRule {
    pub fn try_new() -> Result<Self, CheckError> {
        let id = CheckId::try_new("network_anthropic_api")?;
        Ok(Self { id })
    }

    pub(crate) fn parse_host_and_port(endpoint: &str) -> (String, u16) {
        let clean = endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let host_port_part = clean.split('/').next().unwrap_or("api.anthropic.com");

        if let Some((host, port_str)) = host_port_part.split_once(':') {
            let port = port_str.parse::<u16>().unwrap_or(443);
            (host.to_string(), port)
        } else {
            (host_port_part.to_string(), 443)
        }
    }
}

impl CheckRule for AnthropicNetworkCheckRule {
    fn id(&self) -> &CheckId {
        &self.id
    }

    fn name(&self) -> &str {
        "Anthropic API Network Connectivity"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::Network
    }

    fn severity(&self) -> CheckSeverity {
        CheckSeverity::Recommended
    }

    fn description(&self) -> &str {
        "Probes TCP connectivity to Anthropic API endpoint and detects Fake-IP proxy routing (Clash / Mihomo / Sing-box / Surge)"
    }

    fn run(&self, ctx: &CheckContext) -> Result<CheckResult, CheckError> {
        let lang = ctx.language();
        let name = match lang {
            check_claude_core::Language::English => "Anthropic API Network Connectivity",
            check_claude_core::Language::Chinese => "Anthropic API 网络连通性与代理识别",
        };

        if ctx.skip_network() {
            let skip_msg = match lang {
                check_claude_core::Language::English => {
                    "Network probe skipped by configuration (--skip-network)"
                }
                check_claude_core::Language::Chinese => {
                    "已按配置跳过网络连通性检查 (--skip-network)"
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

        let custom_base = ctx.get_env("ANTHROPIC_BASE_URL");
        let (host, port) = match custom_base {
            Some(url) if !url.trim().is_empty() => Self::parse_host_and_port(url),
            _ => ("api.anthropic.com".to_string(), 443),
        };

        let key_host = match lang {
            check_claude_core::Language::English => "Target Host",
            check_claude_core::Language::Chinese => "目标主机",
        };
        let key_port = match lang {
            check_claude_core::Language::English => "Target Port",
            check_claude_core::Language::Chinese => "目标端口",
        };

        let mut details = vec![
            DiagnosticDetail::new(key_host, host.clone()),
            DiagnosticDetail::new(key_port, port.to_string()),
        ];

        // DNS resolution & Fake-IP detection
        let resolved_ips = ctx.resolve_ips(&host, port).unwrap_or_default();
        let fake_ip_found = resolved_ips.iter().find(|ip| is_fake_ip(ip)).copied();

        let key_dns = match lang {
            check_claude_core::Language::English => "DNS Resolved IP",
            check_claude_core::Language::Chinese => "DNS 解析 IP",
        };
        let key_proxy_status = match lang {
            check_claude_core::Language::English => "Proxy Software Status",
            check_claude_core::Language::Chinese => "代理软件分流状态",
        };

        if let Some(fip) = fake_ip_found {
            let val_proxy = match lang {
                check_claude_core::Language::English => {
                    "Detected via Fake-IP (Clash / Mihomo / Sing-box / Surge TUN mode capturing traffic)"
                }
                check_claude_core::Language::Chinese => {
                    "已识别 Fake-IP（Clash / Mihomo / Sing-box / Surge TUN 模式接管流量）"
                }
            };
            details.push(DiagnosticDetail::new(
                key_dns,
                format!("{} (Fake-IP)", fip),
            ));
            details.push(DiagnosticDetail::new(
                key_proxy_status,
                val_proxy,
            ));
        } else if let Some(ip) = resolved_ips.first() {
            let val_proxy = match lang {
                check_claude_core::Language::English => {
                    "No Fake-IP detected (Direct resolution or standard HTTP proxy)"
                }
                check_claude_core::Language::Chinese => {
                    "未检测到 Fake-IP（直连解析或标准 HTTP 代理）"
                }
            };
            details.push(DiagnosticDetail::new(
                key_dns,
                format!("{} (Real IP)", ip),
            ));
            details.push(DiagnosticDetail::new(
                key_proxy_status,
                val_proxy,
            ));
        }

        let https_proxy = ctx.get_env("HTTPS_PROXY").or_else(|| ctx.get_env("https_proxy"));
        let http_proxy = ctx.get_env("HTTP_PROXY").or_else(|| ctx.get_env("http_proxy"));

        if let Some(proxy) = https_proxy {
            details.push(DiagnosticDetail::new("HTTPS_PROXY", proxy));
        }
        if let Some(proxy) = http_proxy {
            details.push(DiagnosticDetail::new("HTTP_PROXY", proxy));
        }

        let timeout_ms = ctx.timeout_ms().clamp(500, 10000);
        match ctx.probe_tcp(&host, port, timeout_ms) {
            Ok(latency_ms) => {
                let key_latency = match lang {
                    check_claude_core::Language::English => "TCP Latency",
                    check_claude_core::Language::Chinese => "TCP 延迟",
                };
                details.push(DiagnosticDetail::new(key_latency, format!("{} ms", latency_ms)));

                let summary = match lang {
                    check_claude_core::Language::English => {
                        if let Some(fip) = fake_ip_found {
                            format!(
                                "Successfully connected to {}:{} in {} ms (Fake-IP: {} - Proxy software active)",
                                host, port, latency_ms, fip
                            )
                        } else if let Some(ip) = resolved_ips.first() {
                            format!(
                                "Successfully connected to {}:{} in {} ms (Real IP: {})",
                                host, port, latency_ms, ip
                            )
                        } else {
                            format!(
                                "Successfully connected to {}:{} in {} ms",
                                host, port, latency_ms
                            )
                        }
                    }
                    check_claude_core::Language::Chinese => {
                        if let Some(fip) = fake_ip_found {
                            format!(
                                "成功连接至 {}:{}，耗时 {} ms（Fake-IP: {} - 代理软件接管生效中）",
                                host, port, latency_ms, fip
                            )
                        } else if let Some(ip) = resolved_ips.first() {
                            format!(
                                "成功连接至 {}:{}，耗时 {} ms（真实 IP: {}）",
                                host, port, latency_ms, ip
                            )
                        } else {
                            format!(
                                "成功连接至 {}:{}，耗时 {} ms",
                                host, port, latency_ms
                            )
                        }
                    }
                };

                Ok(CheckResult::pass(
                    self.id.clone(),
                    name,
                    self.category(),
                    self.severity(),
                    summary,
                    details,
                    latency_ms,
                ))
            }
            Err(err) => {
                let key_err = match lang {
                    check_claude_core::Language::English => "Connection Error",
                    check_claude_core::Language::Chinese => "连接错误",
                };
                details.push(DiagnosticDetail::new(key_err, err.to_string()));

                let (summary, suggestion) = match lang {
                    check_claude_core::Language::English => {
                        if let Some(fip) = fake_ip_found {
                            (
                                format!("Failed to reach {}:{} (Fake-IP: {} resolved)", host, port, fip),
                                "Fake-IP is active but TCP connection failed. Check if your proxy client (Clash/Mihomo) node is connected and rules route Anthropic domains correctly.",
                            )
                        } else {
                            (
                                format!("Failed to reach {}:{} within {} ms", host, port, timeout_ms),
                                "Failed to connect via Real IP. In Mainland China, proxy software (Clash/Mihomo TUN mode or HTTPS_PROXY) is required to access Claude.",
                            )
                        }
                    }
                    check_claude_core::Language::Chinese => {
                        if let Some(fip) = fake_ip_found {
                            (
                                format!("无法连接至 {}:{}（已解析 Fake-IP: {}）", host, port, fip),
                                "Fake-IP 已生效但 TCP 连接失败。请检查代理客户端（Clash/Mihomo）节点是否连通，且路由规则是否正确分流 Anthropic 域名。",
                            )
                        } else {
                            (
                                format!("在 {} ms 内无法连接至 {}:{}", timeout_ms, host, port),
                                "直连真实 IP 失败。在中国大陆等限制地区，必须通过代理软件（Clash/Mihomo TUN 模式或 HTTPS_PROXY 环境变量）访问 Claude。",
                            )
                        }
                    }
                };

                Ok(CheckResult::warn(
                    self.id.clone(),
                    name,
                    self.category(),
                    self.severity(),
                    summary,
                    details,
                    suggestion,
                    timeout_ms,
                ))
            }
        }
    }
}
