use check_claude_core::{
    CheckCategory, CheckContext, CheckError, CheckId, CheckResult, CheckRule, CheckSeverity,
    DiagnosticDetail,
};
use std::time::Instant;

pub struct EndpointAccessRule {
    id: CheckId,
}

impl EndpointAccessRule {
    pub fn try_new() -> Result<Self, CheckError> {
        let id = CheckId::try_new("anthropic_endpoint_waf")?;
        Ok(Self { id })
    }

    pub fn evaluate_api_response(
        status: u16,
        body: &str,
        cf_mitigated: Option<&str>,
    ) -> (bool, bool, String) {
        Self::evaluate_api_response_localized(
            status,
            body,
            cf_mitigated,
            check_claude_core::Language::English,
        )
    }

    pub fn evaluate_api_response_localized(
        status: u16,
        body: &str,
        cf_mitigated: Option<&str>,
        lang: check_claude_core::Language,
    ) -> (bool, bool, String) {
        // Returns (is_pass, is_region_blocked, summary)
        let body_lower = body.to_ascii_lowercase();

        // Check for Cloudflare challenge
        if cf_mitigated == Some("challenge")
            || body_lower.contains("cf-browser-verification")
            || body_lower.contains("just a moment...")
        {
            let summary = match lang {
                check_claude_core::Language::English => {
                    "Cloudflare WAF challenge/captcha triggered (IP threat score too high)"
                        .to_string()
                }
                check_claude_core::Language::Chinese => {
                    "触发 Cloudflare WAF 人机验证 / 质询（当前 IP 威胁评分过高）".to_string()
                }
            };
            return (false, false, summary);
        }

        // Check Cloudflare 1020
        if body_lower.contains("error 1020")
            || (body_lower.contains("access denied") && body_lower.contains("ray id"))
        {
            let summary = match lang {
                check_claude_core::Language::English => {
                    "Cloudflare WAF Access Denied (Error 1020 / High Risk IP)".to_string()
                }
                check_claude_core::Language::Chinese => {
                    "Cloudflare WAF 拒绝访问（Error 1020 / 高风险 IP）".to_string()
                }
            };
            return (false, false, summary);
        }

        // Check Anthropic region restriction
        if status == 403 {
            if body_lower.contains("not currently available in your region")
                || body_lower.contains("permission_error")
                || body_lower.contains("region")
            {
                let summary = match lang {
                    check_claude_core::Language::English => {
                        "Anthropic API rejected request: Service is not available in your region (HTTP 403)".to_string()
                    }
                    check_claude_core::Language::Chinese => {
                        "Anthropic API 拒绝访问：当前地区不可用 (HTTP 403)".to_string()
                    }
                };
                return (false, true, summary);
            }
            let summary = match lang {
                check_claude_core::Language::English => {
                    format!("Anthropic API returned HTTP 403 Forbidden: {}", body)
                }
                check_claude_core::Language::Chinese => {
                    format!("Anthropic API 返回 HTTP 403 禁止访问: {}", body)
                }
            };
            return (false, false, summary);
        }

        // Check 401: Clean API response
        if status == 401 {
            if body_lower.contains("authentication_error")
                || body_lower.contains("api_key")
                || body_lower.contains("invalid x-api-key")
            {
                let summary = match lang {
                    check_claude_core::Language::English => {
                        "Anthropic API reached cleanly (401 Authentication Error proves no regional/WAF blockage)".to_string()
                    }
                    check_claude_core::Language::Chinese => {
                        "Anthropic API 成功直通（401 鉴权未通过，证实未受区域或 WAF 阻断）".to_string()
                    }
                };
                return (true, false, summary);
            }
            let summary = match lang {
                check_claude_core::Language::English => {
                    "Endpoint reachable (HTTP 401 Unauthorized)".to_string()
                }
                check_claude_core::Language::Chinese => {
                    "端点可达 (HTTP 401 Unauthorized)".to_string()
                }
            };
            return (true, false, summary);
        }

        // 200 OK
        if status == 200 {
            let summary = match lang {
                check_claude_core::Language::English => {
                    "Anthropic API endpoint returned HTTP 200 OK".to_string()
                }
                check_claude_core::Language::Chinese => {
                    "Anthropic API 端点返回 HTTP 200 OK".to_string()
                }
            };
            return (true, false, summary);
        }

        // Other status codes
        let summary = match lang {
            check_claude_core::Language::English => {
                format!("Unexpected response from Anthropic API (HTTP {})", status)
            }
            check_claude_core::Language::Chinese => {
                format!("Anthropic API 返回未预期状态码 (HTTP {})", status)
            }
        };
        (false, false, summary)
    }
}

impl CheckRule for EndpointAccessRule {
    fn id(&self) -> &CheckId {
        &self.id
    }

    fn name(&self) -> &str {
        "Anthropic Endpoint & WAF Status"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::EndpointAccess
    }

    fn severity(&self) -> CheckSeverity {
        CheckSeverity::Required
    }

    fn description(&self) -> &str {
        "Probes api.anthropic.com for real-time region blocking and Cloudflare WAF challenges"
    }

    fn run(&self, ctx: &CheckContext) -> Result<CheckResult, CheckError> {
        let lang = ctx.language();
        let name = match lang {
            check_claude_core::Language::English => "Anthropic Endpoint & WAF Status",
            check_claude_core::Language::Chinese => "Anthropic 官方端点与 WAF 状态",
        };

        if ctx.skip_network() {
            let skip_msg = match lang {
                check_claude_core::Language::English => {
                    "Anthropic endpoint probe skipped by configuration (--skip-network)"
                }
                check_claude_core::Language::Chinese => {
                    "已按配置跳过 Anthropic 端点探测 (--skip-network)"
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
        let timeout_ms = ctx.timeout_ms().clamp(1000, 15000);

        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .build();

        let base_url = ctx
            .get_env("ANTHROPIC_BASE_URL")
            .unwrap_or("https://api.anthropic.com")
            .trim_end_matches('/');

        let target_url = format!("{}/v1/messages", base_url);

        let key_target = match lang {
            check_claude_core::Language::English => "Target Endpoint",
            check_claude_core::Language::Chinese => "目标 API 端点",
        };
        let key_status = match lang {
            check_claude_core::Language::English => "HTTP Status",
            check_claude_core::Language::Chinese => "HTTP 状态码",
        };
        let key_ray = "Cloudflare Ray ID";

        let mut details = vec![DiagnosticDetail::new(key_target, target_url.clone())];

        let req = agent
            .post(&target_url)
            .set("content-type", "application/json")
            .set("anthropic-version", "2023-06-01")
            .set("x-api-key", "test-connectivity-probe");

        let response_result = req.send_string("{}");
        let duration_ms = start.elapsed().as_millis() as u64;

        match response_result {
            Ok(resp) => {
                let status = resp.status();
                let cf_mitigated = resp.header("cf-mitigated").map(|s| s.to_string());
                let cf_ray = resp.header("cf-ray").unwrap_or("none").to_string();
                let body = resp.into_string().unwrap_or_default();

                details.push(DiagnosticDetail::new(key_status, status.to_string()));
                details.push(DiagnosticDetail::new(key_ray, cf_ray));

                let (is_pass, is_region_blocked, summary) = Self::evaluate_api_response_localized(
                    status,
                    &body,
                    cf_mitigated.as_deref(),
                    lang,
                );

                if is_pass {
                    Ok(CheckResult::pass(
                        self.id.clone(),
                        name,
                        self.category(),
                        self.severity(),
                        summary,
                        details,
                        duration_ms,
                    ))
                } else if is_region_blocked {
                    let suggestion = match lang {
                        check_claude_core::Language::English => {
                            "Anthropic official endpoint returned an explicit regional restriction error (HTTP 403). Switch your proxy exit node to an officially supported region (strictly avoid Mainland China and Hong Kong)."
                        }
                        check_claude_core::Language::Chinese => {
                            "Anthropic 官方端点返回了明确的区域限制错误 (HTTP 403)。请更换出口节点至官方受支持地区（严禁使用中国大陆与香港节点）。"
                        }
                    };
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
                } else {
                    let suggestion = match lang {
                        check_claude_core::Language::English => {
                            "Request was blocked by Cloudflare edge WAF or returned abnormal response. This indicates the exit IP has a high threat/fraud score, which can trigger account bans. Recommended: switch to a clean residential or high-reputation proxy node."
                        }
                        check_claude_core::Language::Chinese => {
                            "请求遭到 Cloudflare 边缘 WAF 拦截或异常响应。说明当前节点的 IP 欺诈分过高，极易导致账号封禁。建议更换干净的住宅宽带节点。"
                        }
                    };
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
            Err(ureq::Error::Status(status, resp)) => {
                let cf_mitigated = resp.header("cf-mitigated").map(|s| s.to_string());
                let cf_ray = resp.header("cf-ray").unwrap_or("none").to_string();
                let body = resp.into_string().unwrap_or_default();

                details.push(DiagnosticDetail::new(key_status, status.to_string()));
                details.push(DiagnosticDetail::new(key_ray, cf_ray));

                let (is_pass, is_region_blocked, summary) = Self::evaluate_api_response_localized(
                    status,
                    &body,
                    cf_mitigated.as_deref(),
                    lang,
                );

                if is_pass {
                    Ok(CheckResult::pass(
                        self.id.clone(),
                        name,
                        self.category(),
                        self.severity(),
                        summary,
                        details,
                        duration_ms,
                    ))
                } else if is_region_blocked {
                    let suggestion = match lang {
                        check_claude_core::Language::English => {
                            "Anthropic official endpoint returned an explicit regional restriction error (HTTP 403). Switch your proxy exit node to an officially supported region (strictly avoid Mainland China and Hong Kong)."
                        }
                        check_claude_core::Language::Chinese => {
                            "Anthropic 官方端点返回了明确的区域限制错误 (HTTP 403)。请更换出口节点至官方受支持地区（严禁使用中国大陆与香港节点）。"
                        }
                    };
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
                } else {
                    let suggestion = match lang {
                        check_claude_core::Language::English => {
                            "Request was blocked by Cloudflare WAF. Current exit node IP threat score is too high. Recommended: switch to a clean overseas proxy node."
                        }
                        check_claude_core::Language::Chinese => {
                            "请求遭到 Cloudflare WAF 拦截。当前节点 IP 风险过高，容易触发连坐封号。请更换干净的海外节点。"
                        }
                    };
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
            Err(ureq::Error::Transport(err)) => {
                let key_transport = match lang {
                    check_claude_core::Language::English => "Transport Error",
                    check_claude_core::Language::Chinese => "传输错误",
                };
                details.push(DiagnosticDetail::new(key_transport, err.to_string()));
                let summary = match lang {
                    check_claude_core::Language::English => {
                        format!("Failed to establish secure TLS connection to {}: {}", target_url, err)
                    }
                    check_claude_core::Language::Chinese => {
                        format!("无法建立与 {} 的安全 TLS 连接: {}", target_url, err)
                    }
                };
                let suggestion = match lang {
                    check_claude_core::Language::English => {
                        "Failed to connect to Anthropic API endpoint. Possible reasons include GFW SNI blocking, DNS poisoning, or proxy connectivity issues. Check your proxy and routing configuration."
                    }
                    check_claude_core::Language::Chinese => {
                        "无法连接 Anthropic API 端点。可能是 GFW SNI 阻断、DNS 劫持或代理连通性故障，请检查海外代理与网络路由设置。"
                    }
                };
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
