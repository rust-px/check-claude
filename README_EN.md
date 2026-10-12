# check-claude

<div align="center">

[![Rust](https://img.shields.io/badge/Rust-2024%20Edition-orange?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](#)
[![Zero Panic](https://img.shields.io/badge/Safety-Zero--Panic%20Strict-success.svg)](#)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](#)
[![i18n](https://img.shields.io/badge/i18n-English%20%7C%20Chinese-blueviolet.svg)](#)

**A modern, industrial-grade diagnostic CLI tool to verify Claude & Anthropic official region eligibility, audit anti-ban risk factors, prevent dual-stack IPv6 leaks, and test endpoint connectivity.**

[English](README_EN.md) | [简体中文](README.md)

</div>

---

## Table of Contents

- [Why check-claude? (Pain Points)](#why-check-claude-pain-points)
- [Key Features](#key-features)
- [Diagnostic Rules Matrix (7 Core Checks)](#diagnostic-rules-matrix-7-core-checks)
- [Installation & Build](#installation--build)
- [Usage & CLI Reference](#usage--cli-reference)
  - [1. Interactive Mode](#1-interactive-mode)
  - [2. Language Selection (Bilingual)](#2-language-selection-bilingual)
  - [3. Verbose Diagnostics with Remediation](#3-verbose-diagnostics-with-remediation)
  - [4. Category Filtering](#4-category-filtering)
  - [5. Offline Fast Check Mode](#5-offline-fast-check-mode)
  - [6. Machine-Readable JSON Output](#6-machine-readable-json-output)
  - [7. Complete Command-Line Options](#7-complete-command-line-options)
- [Sample Diagnostic Output](#sample-diagnostic-output)
- [Troubleshooting & Remediation](#troubleshooting--remediation)
- [Workspace Architecture](#workspace-architecture)
- [Engineering Standards & Testing](#engineering-standards--testing)
- [License](#license)

---

## Why check-claude? (Pain Points)

Developers and teams using **Claude Code**, the **Claude Web Interface (claude.ai)**, **Claude Desktop**, or direct **Anthropic APIs** frequently experience unexpected account suspensions, HTTP 403 Forbidden responses, or `"Claude is not available in your country"` errors. Anthropic enforces some of the strictest geographical and anti-abuse policies in the industry:

1. **Sneaky Dual-Stack IPv6 Bypass Leaks (The #1 Ban Cause)**  
   Local ISPs frequently allocate public IPv6 addresses (e.g., China Telecom `240e`, China Unicom `2408`, China Mobile `2409`). When developers configure proxy tools (such as Clash, Mihomo, Surge, Sing-box), often only IPv4 traffic is routed through the proxy. Because Anthropic endpoints and Cloudflare CDNs support dual-stack resolution, client requests often prefer direct IPv6 routing. This leaks the user's physical geographic location and triggers instant account bans.
2. **Datacenter / Hosting IP Mass-Bans**  
   Using cheap VPS providers or public cloud instances (AWS, GCP, DigitalOcean, Linode, Vultr, etc.) tags the egress IP as `Hosting / Data Center` in ASN databases. Anthropic continuously flags and performs mass banwaves against datacenter IP pools.
3. **Cloudflare WAF Challenges & HTTP 1020 Blocks**  
   If an egress IP carries a high threat score, Cloudflare triggers Turnstile/Captcha challenges or drops the connection with `HTTP 1020 Access Denied`, preventing CLI tools like Claude Code from functioning properly.
4. **Client Fingerprint & Timezone Discrepancies**  
   Even if the egress IP is situated in an approved region (e.g., US, UK, Singapore), a host operating system configured with `Asia/Shanghai` timezone and a Chinese locale creates a blatant fraud/bot fingerprint.
5. **Direct NIC Public IP Exposure & TUN Fake-IP Misrouting**  
   Network interfaces directly bound to public IPs or misconfigured TUN Fake-IP (`198.18.0.0/15`) routing rules may cause DNS resolution or network traffic to bypass proxy tunnels.

`check-claude` comprehensively audits your host environment and network topology in seconds, identifying compliance vulnerabilities and providing actionable remediation recommendations.

---

## Key Features

- 🛡️ **7-Dimensional Diagnostic Matrix**: Audits egress geolocation, local NIC IP binding, dynamic IPv6 bypass leaks, IP risk profiles (Hosting vs Residential), endpoint WAF status, system timezone fingerprints, and Fake-IP proxy routing.
- 🌐 **Native Bilingual Support (i18n)**: Full diagnostic engine, console output, and remediation guides are localized in English and Chinese. Automatically prompts for language preference in interactive TTYs, with manual overrides via `--lang` or `CHECK_CLAUDE_LANG`.
- ⚡ **Zero-Panic Guarantee**: Enforces strict workspace lints across all crates: `unwrap_used = "deny"`, `expect_used = "deny"`, `panic = "deny"`, and `todo = "deny"`. Errors are safely propagated via `Result<T, CheckError>`.
- 🚀 **High-Performance Local Heuristics**: Zero-latency offline detection for major ISP IPv6 prefixes; supports `--skip-network` for instant offline host validation.
- 📊 **CI/CD & Automation Ready**: Provides `--json` structured output and standard POSIX exit codes (returns non-zero on critical required failures, `0` when clean or on non-blocking warnings).
- 🔒 **Read-Only & Privacy Preserving**: Completely non-destructive. Never alters host network configuration, never collects or leaks API keys, tokens, or credentials.

---

## Diagnostic Rules Matrix (7 Core Checks)

| Category | Check ID | Rule Name | Severity | Purpose & Technical Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **Region Eligibility** (`region`) | `region_claude_eligibility` | Claude Region Eligibility | **Required** | Probes egress IP via Cloudflare trace endpoints and compares against Anthropic's official supported regions whitelist (flags CN, HK, MO, RU, etc.). |
| **Region Eligibility** (`region`) | `nic_public_ip_eligibility` | Network Interface Public IP & Leak Audit | **Required** | Inspects all physical and virtual interfaces (`if-addrs`) for directly bound public IPv4/IPv6 addresses that bypass local proxy routing. |
| **Region Eligibility** (`region`) | `ipv6_dynamic_egress_probe` | Outbound IPv6 Dynamic Egress & Leak Audit | **Required** | Probes outbound IPv6-only endpoints to detect active dual-stack leaks that route traffic to prohibited regions. |
| **IP Risk Profile** (`ip_risk`) | `ip_risk_and_type` | IP Risk & ASN Attributes | **Recommended** | Audits egress IP ASN, organization, and network type to differentiate Hosting / Data Center IPs from Residential / ISP connections. |
| **Endpoint Access** (`endpoint`) | `anthropic_endpoint_waf` | Anthropic Endpoint & WAF Status | **Required** | Tests live HTTPS connectivity to `api.anthropic.com` and `claude.ai`, evaluating HTTP status (401 expected vs 403 / 1020 / Captcha challenges). |
| **Fingerprint Audit** (`fingerprint`) | `timezone_consistency_audit` | Environment & Timezone Consistency | **Recommended** | Cross-references host OS timezone (`TZ` / `/etc/localtime`) and locale against the detected egress country to flag anti-fraud discrepancies. |
| **Network** (`network` / `net`) | `network_anthropic_api` | Anthropic API Network Connectivity | **Recommended** | Measures TCP handshake latency to `api.anthropic.com:443` and verifies TUN Fake-IP (`198.18.0.0/15`) routing status. |

---

## Installation & Build

### Prerequisites
- Rust toolchain installed (compatible with the Rust 2024 Edition, managed via `rustup`).

### 1. Install from Source via Cargo
```bash
git clone https://github.com/rust-px/check-claude.git
cd check-claude
cargo install --path apps/check_claude
```
Once installed, run `check-claude` directly from anywhere in your shell.

### 2. Build Release Binary
```bash
cargo build --release
# Executable located at: ./target/release/check_claude
./target/release/check_claude --help
```

### 3. Run Directly in Workspace
```bash
cargo run -p check_claude
```

---

## Usage & CLI Reference

### 1. Interactive Mode
When run without explicit language flags in a terminal, `check-claude` prompts for your preferred display language:
```bash
check_claude
```
*Prompt:*
```text
请选择语言 / Select language: [1] 中文  [2] English (默认/Default: 1): 2
```

### 2. Language Selection (Bilingual)
Specify your language directly using `-l` or `--lang` (`en` or `zh`):
```bash
# English mode
check_claude -l en

# Chinese mode
check_claude -l zh
```
Alternatively, configure the default language using an environment variable:
```bash
export CHECK_CLAUDE_LANG=en
check_claude
```

### 3. Verbose Diagnostics with Remediation
Use `-v` (`--verbose`) to print detailed diagnostic metadata (IP, Cloudflare Ray ID, latency, interfaces) and `--suggest` to display actionable remediation instructions:
```bash
check_claude -v --suggest
```

### 4. Category Filtering
Run specific check categories using `-c` or `--category`:
```bash
# Region eligibility and IPv6 leak audit
check_claude -c region

# IP risk profile (Data Center vs Residential)
check_claude -c ip_risk

# Anthropic endpoint connectivity and WAF checks
check_claude -c endpoint

# Host timezone and locale fingerprint consistency
check_claude -c fingerprint

# TCP latency and Fake-IP proxy audit
check_claude -c net
```

### 5. Offline Fast Check Mode
To verify local host interfaces and timezone configurations without making remote network calls, use `--skip-network`:
```bash
check_claude --skip-network -l en
```

### 6. Machine-Readable JSON Output
Output diagnostic results in structured JSON for CI/CD pipelines, bot notifications, or automated scripts:
```bash
check_claude --json > report.json
```

### 7. Complete Command-Line Options

| Option | Short | Default | Description |
| :--- | :---: | :---: | :--- |
| `--help` | `-h` | - | Print command-line help and usage |
| `--version` | `-V` | - | Print version information |
| `--lang <LANG>` | `-l` | Interactive/`zh` | Display language: `en` (English) or `zh` (Chinese) |
| `--verbose` | `-v` | `false` | Display detailed diagnostic metadata, latency, and context |
| `--suggest` | - | `false` | Always show actionable remediation recommendations |
| `--skip-network` | - | `false` | Skip remote network and endpoint probes (offline mode) |
| `--timeout <MS>` | - | `3000` | Network probe timeout in milliseconds |
| `--category <CAT>`| `-c` | All | Filter checks by category: `region`, `ip_risk`, `endpoint`, `fingerprint`, `net` |
| `--json` | - | `false` | Output structured JSON report (silences interactive prompts) |

---

## Sample Diagnostic Output

### Console Rendering (English Mode)

```text
============================================================
  Claude Region & Network Availability Checker
============================================================

>> Claude Region Eligibility
  [PASS] Claude Region Eligibility (required)  (283ms)
         Egress IP region (US) is officially supported by Claude
           - Egress IP: 198.51.100.xx
           - Detected Country: US
           - Cloudflare Colo: SJC
  [PASS] Network Interface Public IP & Leak Audit (required) 
         No public IPv4/IPv6 addresses bound directly to local network interfaces (Clean NAT)
           - Public IP Count: 0
           - Network Environment: Pure Local Area Network / NAT Subnet
  [PASS] Outbound IPv6 Dynamic Egress & Leak Audit (required)  (141ms)
         No active public IPv6 egress connection detected (IPv4 single-stack or IPv6 disabled; leak-proof)
           - IPv6 Egress Status: Inactive / Disabled
           - Dual-Stack Leak Risk: Protected: No public IPv6 traffic leaking physical location

>> IP Risk & ASN Attributes
  [WARN] IP Risk & ASN Attributes (recommended)  (234ms)
         Egress IP is identified as a Data Center / Cloud Hosting IP (AS14061 DigitalOcean, LLC)
           - Target IP: 198.51.100.xx
           - ISP / Organization: AS14061 DigitalOcean, LLC
           - Network Type: Data Center / Hosting
           - Account Ban Risk: Elevated Ban Risk

>> Anthropic Endpoint & WAF Status
  [PASS] Anthropic Endpoint & WAF Status (required)  (531ms)
         Anthropic API reachable (HTTP 401 Unauthorized expected; no regional or WAF block)
           - Target Endpoint: https://api.anthropic.com/v1/messages
           - HTTP Status: 401
           - Cloudflare Ray ID: 8f1234567890abcd-SJC

>> Environment & Timezone Consistency
  [PASS] Environment & Timezone Consistency (recommended)  (218ms)
         System timezone (America/Los_Angeles) and locale (en_US.UTF-8) are consistent with egress region (US)

>> Network Connectivity
  [PASS] Anthropic API Network Connectivity (recommended)  (68ms)
         Connected to api.anthropic.com:443 in 68 ms (Resolved IP: 160.79.104.x)

------------------------------------------------------------
Remediation Recommendations:
  [*] IP Risk & ASN Attributes:
      Current node is hosted in a Data Center / VPS facility. Anthropic enforces strict scrutiny on hosting IPs, which frequently triggers banwaves. Consider switching to a Residential / ISP node.

------------------------------------------------------------
Summary: 6 passed, 1 warnings, 0 failed, 0 skipped (Pass Rate: 85.7%)
Verdict: Environment meets requirements with minor warnings. Optimization recommended.
```

### JSON Format (`--json`)

```json
{
  "results": [
    {
      "id": "region_claude_eligibility",
      "name": "Claude Region Eligibility",
      "category": "region_eligibility",
      "severity": "required",
      "status": "pass",
      "summary": "Egress IP region (US) is officially supported by Claude",
      "details": [
        { "key": "Egress IP", "value": "198.51.100.xx" },
        { "key": "Detected Country", "value": "US" }
      ],
      "suggestion": null,
      "duration_ms": 283
    },
    {
      "id": "ip_risk_and_type",
      "name": "IP Risk & ASN Attributes",
      "category": "ip_risk_profile",
      "severity": "recommended",
      "status": "warn",
      "summary": "Egress IP is identified as a Data Center / Cloud Hosting IP",
      "details": [
        { "key": "Network Type", "value": "Data Center / Hosting" },
        { "key": "Account Ban Risk", "value": "Elevated Ban Risk" }
      ],
      "suggestion": "Consider switching to a Residential / ISP node to reduce ban risks",
      "duration_ms": 234
    }
  ]
}
```

---

## Troubleshooting & Remediation

### 1. `IPv6 Dynamic Egress & Leak Audit` Fails / Warns
- **Cause**: Local ISP provides IPv6 connectivity, but the proxy client only handles IPv4. Outbound HTTPS traffic to dual-stack endpoints bypasses the proxy and leaks domestic location.
- **Solution**:
  - **Option A (Recommended)**: Enable IPv6 routing in your proxy client (e.g. set `ipv6: true` in Mihomo / Clash Verge with dual-stack rulesets).
  - **Option B**: Disable IPv6 in your operating system or router (e.g., Linux: `sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1`).

### 2. `IP Risk & ASN Attributes` Flags Data Center / Hosting IP
- **Cause**: Node egress IP is hosted on AWS, GCP, DigitalOcean, Vultr, or low-cost VPS providers.
- **Solution**:
  - Switch to an egress proxy providing a **Residential / ISP** ASN.
  - Avoid overcrowded public commercial proxy pools.

### 3. `Anthropic Endpoint & WAF Status` Fails (403 Forbidden / 1020 / Challenge)
- **Cause**: Egress IP is blocked by Cloudflare WAF due to high threat reputation or an unsupported region.
- **Solution**:
  - Switch your proxy node to an approved region (e.g., US, JP, SG, GB).
  - Select an IP with a clean reputation and low abuse history.

### 4. `Environment & Timezone Consistency` Flags Timezone Mismatch
- **Cause**: Outbound traffic exits in an approved region (e.g., US), but the host OS timezone is set to `Asia/Shanghai`.
- **Solution**:
  - Export the target timezone in your shell before launching Claude Code:
    ```bash
    export TZ="America/Los_Angeles"
    ```
  - Or align your OS timezone with the egress proxy region.

---

## Workspace Architecture

`check-claude` follows **Clean Architecture** principles across a modular Rust workspace:

```text
check-claude/
├── apps/
│   └── check_claude/              # Application Composition Root (CLI entry point)
│       ├── Cargo.toml
│       └── src/main.rs            # CLI parsing, language dispatch, runner wiring, exit codes
├── crates/
│   ├── check_claude_core/         # Core Domain & Contracts Engine
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── types.rs           # Core domain types (CheckId, CheckReport, CheckResult, Language)
│   │       ├── rule.rs            # CheckRule diagnostic trait definition
│   │       ├── runner.rs          # Pipeline execution engine
│   │       ├── context.rs         # Execution context & Fake-IP detection utilities
│   │       ├── error.rs           # Strongly typed domain error model
│   │       ├── tests.rs           # Core unit tests
│   │       └── lib.rs             # Public clean re-exports
│   ├── check_claude_rules/        # Diagnostic Rule Implementations
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── region.rs          # Official region eligibility whitelist rules
│   │       ├── nic_ip.rs          # NIC public IP leak detection & ISP heuristics
│   │       ├── ipv6.rs            # Outbound IPv6 dynamic probe & bypass audit
│   │       ├── ip_risk.rs         # Hosting vs Residential IP risk profiling
│   │       ├── endpoint.rs        # Anthropic endpoint HTTPS & WAF challenge checks
│   │       ├── fingerprint.rs     # Host OS timezone & locale consistency audit
│   │       ├── network.rs         # TCP latency probe & Fake-IP routing inspection
│   │       ├── registry.rs        # Default rules registry & execution order
│   │       ├── tests.rs           # Rule-level unit tests
│   │       └── lib.rs
│   └── check_claude_reporter/     # Presentation Layer (Read-Only)
│       ├── Cargo.toml
│       └── src/
│           ├── console.rs         # ANSI colored terminal renderer & remediation formatter
│           ├── json.rs            # Machine-readable JSON serializer
│           ├── tests.rs           # Presentation tests
│           └── lib.rs
├── Cargo.toml                     # Workspace root config & strict lints
├── rust-toolchain.toml            # Toolchain pin
└── AGENTS.md                      # Engineering standards & guidelines
```

### Architectural Boundaries
- **`check_claude_core`**: Zero dependencies on presentation libraries, terminal color crates, or CLI parsers.
- **`check_claude_reporter`**: Observes domain models (`CheckReport`, `CheckResult`); never executes probes or queries.
- **`apps/check_claude`**: The composition root that wires command line arguments, instantiates the runner, and dispatches to reporters.

---

## Engineering Standards & Testing

1. **Domain Invariants**: Domain objects enforce strict validation constructors (e.g. `CheckId::try_new()`); invalid or empty states are prevented at instantiation.
2. **Strict Zero-Panic Policy**: Enforced via workspace-wide Clippy configuration:
   ```toml
   [workspace.lints.clippy]
   unwrap_used = "deny"
   expect_used = "deny"
   panic = "deny"
   todo = "deny"
   dbg_macro = "deny"
   ```
3. **Dedicated Test Files**: All unit tests are organized into dedicated `tests.rs` modules, maintaining clean separation from production implementations.

### Run Test Suite
```bash
cargo test
```

---

## License

Dual-licensed under either:
- [MIT License](http://opensource.org/licenses/MIT)
- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

at your option.

---

<div align="center">
  <sub>Made with ❤️ for the Claude and AI developer community.</sub>
</div>
