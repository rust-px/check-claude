# check-claude

<div align="center">

[![Rust](https://img.shields.io/badge/Rust-2024%20Edition-orange?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](#)
[![Zero Panic](https://img.shields.io/badge/Safety-Zero--Panic%20Strict-success.svg)](#)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](#)
[![i18n](https://img.shields.io/badge/i18n-Chinese%20%7C%20English-blueviolet.svg)](#)

**现代化、工业级的 Claude / Anthropic 官方地区合规性、网络连通性与防封号风控诊断 CLI 工具**

*A modern, industrial-grade diagnostic CLI tool to verify whether your network and environment comply with Claude / Anthropic supported regions, prevent dual-stack IP leaks, and audit anti-ban risk factors.*

[简体中文](README.md) | [English](README_EN.md)

</div>

---

## 目录 (Table of Contents)

- [为什么需要 check-claude？(Pain Points)](#为什么需要-check-claude-pain-points)
- [核心特性 (Key Features)](#核心特性-key-features)
- [7 大核心检查规则全景矩阵 (Diagnostic Rules Matrix)](#7-大核心检查规则全景矩阵-diagnostic-rules-matrix)
- [安装与构建 (Installation & Build)](#安装与构建-installation--build)
- [使用指南与常用命令 (CLI Usage & Examples)](#使用指南与常用命令-cli-usage--examples)
  - [1. 基础交互运行](#1-基础交互运行)
  - [2. 语言切换 (中英双语)](#2-语言切换-中英双语)
  - [3. 详细诊断与修复建议](#3-详细诊断与修复建议)
  - [4. 单独检测指定分类](#4-单独检测指定分类)
  - [5. 离线快速检测模式](#5-离线快速检测模式)
  - [6. JSON 自动化报告输出](#6-json-自动化报告输出)
  - [7. 命令行完整参数表](#7-命令行完整参数表)
- [典型诊断输出示例 (Sample Output)](#典型诊断输出示例-sample-output)
- [常见风险告警与整改方案 (Troubleshooting & Remediation)](#常见风险告警与整改方案-troubleshooting--remediation)
- [工作区架构设计 (Architecture)](#工作区架构设计-architecture)
- [工程规范与测试 (Engineering Standards & Testing)](#工程规范与测试-engineering-standards--testing)
- [开源协议 (License)](#开源协议-license)

---

## 为什么需要 check-claude？(Pain Points)

在使用 **Claude Code**、**Claude 网页端 (claude.ai)**、**Claude Desktop** 或调用 **Anthropic API** 时，众多开发者与团队频繁遭遇封号、请求 403 阻断或 `"Claude is not available in your country"` 错误。Anthropic 拥有业内最为严苛的区域与网络风控策略之一：

1. **隐蔽的双栈 IPv6 泄露陷阱（最常见封号根源）**  
   本地系统启用了 IPv6（例如国内三大运营商分配的 `240e` / `2408` / `2409` 前缀），而在使用代理软件（如 Clash、Mihomo、Surge、Sing-box）时仅代理了 IPv4 流量。由于 Anthropic API 和 Cloudflare CDN 原生支持双栈解析，终端往往优先通过直连 IPv6 发起 HTTPS 请求，导致物理真实位置暴露并瞬间触发永久封禁。
2. **机房 IP 连坐式风控（Data Center / Hosting IP 封号）**  
   使用常见的云服务商（AWS、GCP、DigitalOcean、Linode、Oracle Cloud、搬瓦工等）节点或劣质 VPS 翻墙，这类 IP 在 ASN 数据库中被直接打上 `Hosting / Data Center` 标签。Anthropic 对数据中心 IP 实施常态化、大批量的“连坐封禁”。
3. **Cloudflare WAF 质询与 1020 拦截**  
   出口 IP 威胁信誉分（Threat Score）过高，触发 Cloudflare 验证码质询（Turnstile / Captcha Challenge）或直接返回 HTTP 1020 访问拒绝，导致终端 CLI 无法自动化交互。
4. **客户端指纹与时区冲突（Fraud Fingerprint Mismatch）**  
   出口 IP 位于合规支持地区（如美国、英国、新加坡），但宿主机操作系统时区仍为 `Asia/Shanghai`，且系统 Locale 语言为 `zh_CN`，形成强烈的反欺诈异常指纹。
5. **网卡物理/虚拟 IP 泄露与 TUN Fake-IP 分流异常**  
   虚拟网卡或物理网卡直接暴露了国内公网地址，或者代理工具的 TUN 模式 Fake-IP (`198.18.0.0/15`) 分流规则未正确生效，请求直连国内 DNS。

`check-claude` 专为解决上述痛点而生，在几秒内全面审计本地网络拓扑与运行环境，精准识别导致封禁的潜在风险点并给出可执行的整改建议。

---

## 核心特性 (Key Features)

- 🛡️ **7 维全方位立体化诊断矩阵**：覆盖出口地区、网卡绑定、动态 IPv6 泄露、IP 风险画像、端点 WAF 状态、系统时区指纹与网络 Fake-IP 路由。
- 🌐 **原生中英双语国际化 (i18n)**：全诊断引擎、控制台输出、整改建议均提供完整的中文与英文支持；在 TTY 终端下未传参时自动提供数字键交互选择，亦支持 `--lang` 参数或环境变量锁定。
- ⚡ **工业级零致命崩溃标准 (Zero-Panic Guarantee)**：全代码库遵循 strict workspace lints：`unwrap_used = "deny"`、`expect_used = "deny"`、`panic = "deny"`、`todo = "deny"`，全链路基于 `Result<T, CheckError>` 安全传递。
- 🚀 **极速本地诊断与自适应缓存**：针对三大运营商 IPv6 前缀内置零延迟离线启发式预判规则；支持 `--skip-network` 纯离线毫秒级自检。
- 📊 **CI/CD 与脚本集成友好**：提供 `--json` 结构化机器可读输出，遵循严格的 POSIX 退出码规范（存在严重不合规失败返回非零值，全部通过或仅有可选警告返回 `0`）。
- 🔒 **严格只读与隐私安全 (Zero-Mutation / Zero-Leak)**：仅进行非侵入式检测，绝不修改系统网络配置，绝不收集或向外泄露任何 API 密钥、Token 或敏感凭据。

---

## 7 大核心检查规则全景矩阵 (Diagnostic Rules Matrix)

| 阶段分类 (Category) | 检查标识 (Check ID) | 检查项名称 | 严重级别 | 诊断目的与核心原理 |
| :--- | :--- | :--- | :--- | :--- |
| **Region Eligibility** (`region`) | `region_claude_eligibility` | 出口 IP 地区可用性 | **Required** (必选) | 探测实际出站出口 IP 并比对 Anthropic 官方支持地区白名单（严查中国大陆 `CN`、中国香港 `HK`、中国澳门 `MO`、俄罗斯 `RU` 等受限地区）。 |
| **Region Eligibility** (`region`) | `nic_public_ip_eligibility` | 网卡公网 IP 绑定与泄露审计 | **Required** (必选) | 扫描宿主机所有物理与虚拟网络接口，检查是否直接绑定公网 IPv4/IPv6 地址（识别绕过代理直接暴露物理公网的隐患）。 |
| **Region Eligibility** (`region`) | `ipv6_dynamic_egress_probe` | IPv6 动态出站连通与泄露审计 | **Required** (必选) | 专门针对纯 IPv6 出口节点进行动态外网握手，探测双栈环境下 IPv6 流量是否绕过代理直连受限地区。 |
| **IP Risk Profile** (`ip_risk`) | `ip_risk_and_type` | IP 风险画像与机房属性 | **Recommended** (推荐) | 深度审计出口 IP 的 ASN、ISP 组织与网络类型，鉴别云服务器/机房 (Hosting/Datacenter) 与原生住宅宽带 (Residential)，评估批量封号风险。 |
| **Endpoint Access** (`endpoint`) | `anthropic_endpoint_waf` | Anthropic 官方端点与 WAF 状态 | **Required** (必选) | 对接 `api.anthropic.com` 与 `claude.ai`，实测 HTTP 响应（正常 401 鉴权 vs 403 区域阻断 / 1020 访问拒绝 / Cloudflare 人机质询）。 |
| **Fingerprint Audit** (`fingerprint`) | `timezone_consistency_audit` | 系统时区与语言环境指纹审计 | **Recommended** (推荐) | 检查宿主机系统时区（`TZ` / `/etc/localtime`）及 Locale，交叉比对出站 IP 所在地理区域，排查反欺诈系统敏感的指纹冲突。 |
| **Network** (`network` / `net`) | `network_anthropic_api` | Anthropic API 网络连通与代理识别 | **Recommended** (推荐) | 针对 `api.anthropic.com:443` 进行 TCP 握手与延迟测速，识别 TUN 模式 Fake-IP (`198.18.0.0/15`) 分流代理接管状态。 |

---

## 安装与构建 (Installation & Build)

### 前置条件
- 已安装 Rust 工具链（推荐最新稳定版或 2024 Edition 支持的编译器，支持 `rustup`）。

### 1. 从源码安装至系统 PATH
```bash
git clone https://github.com/your-username/check-claude.git
cd check-claude
cargo install --path apps/check_claude
```
安装完成后，即可在任意终端路径下直接调用 `check-claude`。

### 2. 本地直接编译 Release 版本
```bash
cargo build --release
# 二进制生成于 ./target/release/check_claude
./target/release/check_claude --help
```

### 3. 开发环境即时运行
```bash
cargo run -p check_claude
```

---

## 使用指南与常用命令 (CLI Usage & Examples)

### 1. 基础交互运行
在常规终端中直接运行，如果未指定语言参数，程序将智能提示选择显示语言：
```bash
cargo run -p check_claude
# 或已安装时：
check_claude
```
*交互提示：*
```text
请选择语言 / Select language: [1] 中文  [2] English (默认/Default: 1):
```

### 2. 语言切换 (中英双语)
通过 `-l` 或 `--lang` 显式指定语言，支持中文（`zh` / `cn`）或英文（`en`）：
```bash
# 中文模式
check_claude -l zh

# 英文模式
check_claude -l en
```
也可以通过环境变量全局设置默认语言：
```bash
export CHECK_CLAUDE_LANG=zh
check_claude
```

### 3. 详细诊断与修复建议
使用 `-v` (`--verbose`) 输出底层元数据（包括出站 IP、Cloudflare Ray ID、延迟毫秒数、已扫描网卡等），结合 `--suggest` 开启完整的行动建议建议：
```bash
check_claude -v --suggest
```

### 4. 单独检测指定分类
使用 `-c` 或 `--category` 参数按阶段分类定向执行，节省网络探测时间：
```bash
# 仅检查地区支持与 IPv6 泄露
check_claude -c region

# 仅检测 IP 风险画像 (机房 vs 住宅)
check_claude -c ip_risk

# 仅测试 Anthropic 端点连通性与 WAF 拦截
check_claude -c endpoint

# 仅审计时区与语言环境指纹
check_claude -c fingerprint

# 仅测试 API 端口 TCP 延迟与 Fake-IP 代理分流
check_claude -c net
```

### 5. 离线快速检测模式
在无外网连接或无需探测远程网络时，添加 `--skip-network` 跳过所有外部 HTTP/TCP 探测，仅对本地网卡与环境指纹进行毫秒级纯离线审计：
```bash
check_claude --skip-network -l zh
```

### 6. JSON 自动化报告输出
添加 `--json` 标志，诊断引擎将输出符合规范的机器可读 JSON 数据，方便集成至 CI/CD 流水线、自动化检测告警机器人或个人运维监控：
```bash
check_claude --json > report.json
```

### 7. 命令行完整参数表

| 参数 (Flag) | 简写 | 默认值 | 作用描述 |
| :--- | :---: | :---: | :--- |
| `--help` | `-h` | - | 打印命令行帮助信息与选项说明 |
| `--version` | `-V` | - | 打印当前软件版本号 |
| `--lang <LANG>` | `-l` | 交互选择/`zh` | 设置报告显示语言：`zh` (中文) 或 `en` (English) |
| `--verbose` | `-v` | `false` | 显示完整诊断元数据、上下文细节与毫秒级执行延迟 |
| `--suggest` | - | `false` | 始终显式输出可操作的修复与整改优化建议 |
| `--skip-network` | - | `false` | 跳过所有外网远程端点与延迟探测（纯离线检测模式） |
| `--timeout <MS>` | - | `3000` | 网络远程探测超时时长（单位：毫秒） |
| `--category <CAT>`| `-c` | 全部运行 | 过滤执行指定诊断分类：`region` / `ip_risk` / `endpoint` / `fingerprint` / `net` |
| `--json` | - | `false` | 以格式化 JSON 纯文本输出完整报告（自动静音交互式语言提示） |

---

## 典型诊断输出示例 (Sample Output)

### 控制台标准输出示例 (Console Rendering)

```text
============================================================
  Claude 地区与网络可用性诊断工具
============================================================

>> Claude 官方地区可用性
  [PASS] 出口 IP 地区可用性 (必选项)  (283ms)
         出口 IP 所在地区 (US) 已获得 Claude 官方正式支持
           - 出口 IP: 198.51.100.xx
           - 检测到的国家/地区: US
           - Cloudflare 边缘节点: SJC
  [PASS] 网卡公网 IP 绑定与泄露审计 (必选项) 
         本机网卡未直接绑定公网 IPv4/IPv6 地址（纯内网 NAT 环境，无泄露风险）
           - 公网 IP 数量: 0
           - 网络环境类型: 纯局域网 / NAT 子网（无公网 IP 暴露）
  [PASS] IPv6 动态出站连通与泄露审计 (必选项)  (141ms)
         未检测到活跃的公网 IPv6 出站连接（纯 IPv4 单栈或已禁用 IPv6；彻底免受旁路泄露）
           - IPv6 出站状态: 未激活 / 已禁用（无泄露风险）
           - 双栈泄露风险评估: 受保护：无公网 IPv6 流量，不会绕过代理泄露物理位置

>> IP 风险画像与机房属性
  [WARN] IP 风险画像与机房属性 (推荐项)  (234ms)
         出口 IP 被识别为数据中心/云机房 IP (AS14061 DigitalOcean, LLC)
           - 目标 IP: 198.51.100.xx
           - 运营商 / 组织: AS14061 DigitalOcean, LLC
           - 网络类型: 机房 / 云服务器 (Data Center)
           - 封号风险评估: 封号风险较高

>> Anthropic 接口与 WAF 拦截状态
  [PASS] Anthropic 官方端点与 WAF 状态 (必选项)  (531ms)
         Anthropic API 成功直通（401 鉴权未通过，证实未受区域或 WAF 阻断）
           - 目标 API 端点: https://api.anthropic.com/v1/messages
           - HTTP 状态码: 401
           - Cloudflare Ray ID: 8f1234567890abcd-SJC

>> 客户端时区与语言环境指纹
  [PASS] 系统时区与语言环境指纹审计 (推荐项)  (218ms)
         系统时区 (America/Los_Angeles) 与语言 (en_US.UTF-8) 与出口地区 (US) 基本一致或无明显冲突

>> 网络连通性与 Fake-IP 路由
  [PASS] Anthropic API 网络连通性与代理识别 (推荐项)  (68ms)
         成功连接至 api.anthropic.com:443，耗时 68 ms（真实 IP: 160.79.104.x）

------------------------------------------------------------
整改与修复建议：
  [*] IP 风险画像与机房属性:
      当前节点为数据中心/云机房 IP（如 VPS 或机场常见机房）。Anthropic 对机房 IP 的审计极严，容易遭遇批量连坐封号。建议选用原生住宅宽带（Residential/ISP）节点以提高账号安全性。

------------------------------------------------------------
汇总统计：6 通过, 1 警告, 0 失败, 0 跳过 (通过率: 85.7%)
检测判定：环境满足基本要求，但存在次要警告风险，建议适当优化。
```

### JSON 报告结构示例 (`--json`)

```json
{
  "results": [
    {
      "id": "region_claude_eligibility",
      "name": "出口 IP 地区可用性",
      "category": "region_eligibility",
      "severity": "required",
      "status": "pass",
      "summary": "出口 IP 所在地区 (US) 已获得 Claude 官方正式支持",
      "details": [
        { "key": "出口 IP", "value": "198.51.100.xx" },
        { "key": "检测到的国家/地区", "value": "US" }
      ],
      "suggestion": null,
      "duration_ms": 283
    },
    {
      "id": "ip_risk_and_type",
      "name": "IP 风险画像与机房属性",
      "category": "ip_risk_profile",
      "severity": "recommended",
      "status": "warn",
      "summary": "出口 IP 被识别为数据中心/云机房 IP",
      "details": [
        { "key": "网络类型", "value": "机房 / 云服务器 (Data Center)" },
        { "key": "封号风险评估", "value": "封号风险较高" }
      ],
      "suggestion": "当前节点为数据中心/云机房 IP，建议选用原生住宅宽带节点",
      "duration_ms": 234
    }
  ]
}
```

---

## 常见风险告警与整改方案 (Troubleshooting & Remediation)

### 1. 触发 `IPv6 动态出站连通与泄露审计` 失败 / 警告
- **原因分析**：本地宽带开通了 IPv6，代理客户端默认只接管了 IPv4 流量。系统发起网络请求时优先走 IPv6 直连，导致请求直接暴露国内公网 IP。
- **整改方案**：
  - **方案 A（推荐）**：在代理客户端中启用 IPv6 代理路由（例如在 Mihomo / Clash Verge 中开启 `ipv6: true`，并将规则集更新为双栈分流）。
  - **方案 B**：直接在操作系统或路由器中关闭 IPv6 协议栈（例如 Linux 执行 `sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1`，或在 Windows 网卡属性中取消勾选 Internet 协议版本 6）。

### 2. 触发 `IP 风险画像与机房属性` 警告（Data Center / Hosting）
- **原因分析**：节点来自阿里云、腾讯云海外区、搬瓦工、AWS、Vultr 等机房服务商。Anthropic 的风控引擎对于高并发机房 IP 具有极低容忍度。
- **整改方案**：
  - 更换提供**原生住宅宽带（Residential / ISP）**属性的节点；
  - 避免使用人数繁多的大型机场共享节点。

### 3. 触发 `Anthropic 官方端点与 WAF 状态` 失败（403 阻断 / 1020 拒绝 / 人机质询）
- **原因分析**：当前出口 IP 已被 Cloudflare 列入高风险黑名单，或该 IP 所在地区不在 Anthropic 允许名单中。
- **整改方案**：
  - 切换出口节点国家至受支持地区（如美国 `US`、日本 `JP`、新加坡 `SG`、英国 `GB` 等）；
  - 更换干净、未被 Abuse 污染的出口 IP。

### 4. 触发 `系统时区与语言环境指纹审计` 警告（Timezone Mismatch）
- **原因分析**：出口 IP 在欧美，而宿主机时区为 `Asia/Shanghai` 或类似受限地区时区。
- **整改方案**：
  - 运行 Claude Code 前在终端导出目标时区环境变量：
    ```bash
    export TZ="America/Los_Angeles"  # 例如切换至美国西岸时区
    ```
  - 或在操作系统设置中将自动设置时区功能关闭，并将时区调整为与代理节点一致。

---

## 工作区架构设计 (Architecture)

本项目采用遵循**整洁架构 (Clean Architecture)** 的 Rust Workspace 组织方式，业务领域模型、诊断规则实现、呈现展现与顶层 CLI 组装保持严格单向解耦：

```text
check-claude/
├── apps/
│   └── check_claude/              # 顶层 CLI 应用程序组合根 (Composition Root)
│       ├── Cargo.toml
│       └── src/main.rs            # CLI 参数解析、语言分发、规则执行器调度与退出码处理
├── crates/
│   ├── check_claude_core/         # 领域内核与基础契约 (Core Domain Engine)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── types.rs           # 核心领域实体 (CheckId, CheckReport, CheckResult, Language 等)
│   │       ├── rule.rs            # CheckRule 诊断规则契约特征 (Trait)
│   │       ├── runner.rs          # 诊断流水线调度引擎
│   │       ├── context.rs         # 环境执行上下文抽象与 Fake-IP 判定辅助
│   │       ├── error.rs           # 强类型领域错误定义
│   │       ├── tests.rs           # Core 单元测试
│   │       └── lib.rs             # 纯净公开导出接口
│   ├── check_claude_rules/        # 具体诊断规则库 (Diagnostic Rules)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── region.rs          # 官方支持地区比对规则 (Cloudflare Trace / ipinfo)
│   │       ├── nic_ip.rs          # 网卡公网 IP 暴露与三大运营商 IPv6 前缀启发式过滤
│   │       ├── ipv6.rs            # 纯 IPv6 出口动态路由与泄露审计
│   │       ├── ip_risk.rs         # IP 风险画像 (机房 Hosting vs 住宅 Residential) 判定
│   │       ├── endpoint.rs        # Anthropic 官方端点 HTTPS 握手与 Cloudflare WAF 质询
│   │       ├── fingerprint.rs     # 宿主机系统时区与语言环境指纹一致性审计
│   │       ├── network.rs         # api.anthropic.com TCP 延迟探测与 Fake-IP 代理识别
│   │       ├── registry.rs        # 预设规则注册表与执行序调度
│   │       ├── tests.rs           # 规则级单元测试
│   │       └── lib.rs
│   └── check_claude_reporter/     # 诊断呈现层 (Presentation Layer)
│       ├── Cargo.toml
│       └── src/
│           ├── console.rs         # 终端彩色输出渲染器、统计汇总与整改建议格式化
│           ├── json.rs            # 机器可读标准 JSON 序列化器
│           ├── tests.rs           # 呈现层测试
│           └── lib.rs
├── Cargo.toml                     # 工作区根配置 (统一依赖版本与 Strict Clippy Lints)
├── rust-toolchain.toml            # 工具链锁定
└── AGENTS.md                      # 工程规范与协作约束
```

### 分层依赖原则
- **`check_claude_core`**：核心底层，**严禁**向下依赖任何控制台颜色库、渲染模板或 CLI 参数解析器。
- **`check_claude_reporter`**：纯展示层，仅单向观察核心领域模型（`CheckReport`, `CheckResult`），**绝不执行**网络探测或环境探测。
- **`apps/check_claude`**：作为组合根（Composition Root），负责组装依赖并启动执行流程。

---

## 工程规范与测试 (Engineering Standards & Testing)

本仓库遵循严格的工业级生产标准进行构建与测试验证：

1. **强类型与领域不变量 (Domain Invariants)**：所有实体必须经由验证构造器构造（如 `CheckId::try_new()`），禁止非法空字符串或不可用状态。
2. **零致命崩溃保证 (Zero-Panic)**：根 `Cargo.toml` 中明确禁止 `panic`、`unwrap`、`expect`、`todo` 与 `dbg!`：
   ```toml
   [workspace.lints.clippy]
   unwrap_used = "deny"
   expect_used = "deny"
   panic = "deny"
   todo = "deny"
   dbg_macro = "deny"
   ```
3. **独立测试覆盖 (Dedicated Test Suites)**：所有单元测试与集成测试均放置于各模块专用的 `tests.rs` 文件中，禁止在业务实现文件末尾混合编写测试代码。

### 执行完整测试套件
```bash
cargo test
```

---

## 开源协议 (License)

本项目采用双重开源许可证授权：
- [MIT 许可证](http://opensource.org/licenses/MIT)
- [Apache 许可证 2.0 版本](http://www.apache.org/licenses/LICENSE-2.0)

您可以根据需要自由选择适用的许可证。

---

<div align="center">
  <sub>Made with ❤️ for the Claude and AI developer community.</sub>
</div>
