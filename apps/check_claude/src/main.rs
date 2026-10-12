use check_claude_core::{
    CheckCategory, CheckContext, CheckError, CheckReport, CheckRunner, Language,
};
use check_claude_reporter::{ConsoleReporter, JsonReporter};
use check_claude_rules::default_rules;
use clap::{Arg, ArgAction, Command};
use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

fn build_cli() -> Command {
    Command::new("check-claude")
        .version("0.1.0")
        .about("Diagnostic CLI to verify whether your network and environment are in a Claude-supported region")
        .arg(
            Arg::new("json")
                .long("json")
                .action(ArgAction::SetTrue)
                .help("Output diagnostic results in structured JSON format"),
        )
        .arg(
            Arg::new("lang")
                .short('l')
                .long("lang")
                .value_name("LANG")
                .help("设置报告显示语言 / Set display language: 'zh' (中文) 或 'en' (English)"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue)
                .help("Display detailed diagnostic metadata and environment parameters"),
        )
        .arg(
            Arg::new("suggest")
                .long("suggest")
                .action(ArgAction::SetTrue)
                .help("Always show actionable remediation recommendations"),
        )
        .arg(
            Arg::new("skip-network")
                .long("skip-network")
                .action(ArgAction::SetTrue)
                .help("Skip remote API endpoint and network latency probes"),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .value_name("MILLISECONDS")
                .default_value("3000")
                .help("Network probe timeout in milliseconds (default: 3000)"),
        )
        .arg(
            Arg::new("category")
                .short('c')
                .long("category")
                .value_name("CATEGORY")
                .help("Filter checks by category: region, ip_risk, endpoint, fingerprint, net"),
        )
}

fn determine_language(cli_lang: Option<&str>, json_output: bool) -> Language {
    if let Some(code) = cli_lang {
        if let Some(lang) = Language::from_code(code) {
            return lang;
        }
    }

    if let Ok(env_lang) = std::env::var("CHECK_CLAUDE_LANG") {
        if let Some(lang) = Language::from_code(&env_lang) {
            return lang;
        }
    }

    if !json_output && io::stdin().is_terminal() && io::stdout().is_terminal() {
        print!("请选择语言 / Select language: [1] 中文  [2] English (默认/Default: 1): ");
        let _ = io::stdout().flush();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            let trimmed = input.trim();
            if trimmed == "1"
                || trimmed.eq_ignore_ascii_case("zh")
                || trimmed.eq_ignore_ascii_case("cn")
                || trimmed.eq_ignore_ascii_case("chinese")
                || trimmed.is_empty()
            {
                return Language::Chinese;
            } else if trimmed == "2"
                || trimmed.eq_ignore_ascii_case("en")
                || trimmed.eq_ignore_ascii_case("english")
            {
                return Language::English;
            } else if let Some(lang) = Language::from_code(trimmed) {
                return lang;
            }
        }
    }

    // Default to Chinese (first option)
    Language::Chinese
}

fn parse_category(val: &str) -> Option<CheckCategory> {
    match val.to_lowercase().as_str() {
        "region" | "support" | "regioneligibility" | "nic" | "interface" | "ipv6" | "v6" => {
            Some(CheckCategory::RegionEligibility)
        }
        "ip" | "risk" | "ip_risk" | "ipriskprofile" => Some(CheckCategory::IpRiskProfile),
        "endpoint" | "endpointaccess" | "waf" => Some(CheckCategory::EndpointAccess),
        "fingerprint" | "timezone" | "locale" | "lang" | "fingerprintaudit" => {
            Some(CheckCategory::FingerprintAudit)
        }
        "network" | "net" => Some(CheckCategory::Network),

        _ => None,
    }
}

fn run_app() -> Result<(CheckReport, bool), CheckError> {
    let matches = build_cli().get_matches();

    let json_output = matches.get_flag("json");
    let verbose = matches.get_flag("verbose");
    let suggest = matches.get_flag("suggest");
    let skip_network = matches.get_flag("skip-network");

    let timeout_str = matches.get_one::<String>("timeout").map(|s| s.as_str()).unwrap_or("3000");
    let timeout_ms = timeout_str.parse::<u64>().unwrap_or(3000);

    let category_filter = matches.get_one::<String>("category").and_then(|c| parse_category(c));

    let cli_lang = matches.get_one::<String>("lang").map(|s| s.as_str());
    let lang = determine_language(cli_lang, json_output);

    let ctx = CheckContext::new(skip_network, verbose, timeout_ms, lang);

    let mut runner = CheckRunner::new();
    let rules = default_rules()?;
    for rule in rules {
        runner.add_boxed_rule(rule);
    }

    let report = match category_filter {
        Some(cat) => runner.run_categories(&[cat], &ctx)?,
        None => runner.run(&ctx)?,
    };

    if json_output {
        let json_rendered = JsonReporter::render(&report)?;
        println!("{}", json_rendered);
    } else {
        let reporter = ConsoleReporter::new(verbose, suggest, lang);
        let rendered = reporter.render(&report);
        print!("{}", rendered);
    }

    Ok((report, json_output))
}

fn main() -> ExitCode {
    match run_app() {
        Ok((report, _)) => {
            if report.has_critical_failures() {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(err) => {
            eprintln!("Error executing check-claude: {}", err);
            ExitCode::FAILURE
        }
    }
}
