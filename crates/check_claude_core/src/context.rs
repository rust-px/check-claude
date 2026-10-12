use crate::error::CheckError;
use getset::{CopyGetters, Getters};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, Getters, CopyGetters)]
pub struct CommandOutput {
    #[getset(get = "pub")]
    stdout: String,

    #[getset(get = "pub")]
    stderr: String,

    #[getset(get_copy = "pub")]
    exit_code: i32,

    #[getset(get_copy = "pub")]
    success: bool,
}

impl CommandOutput {
    pub fn new(stdout: impl Into<String>, stderr: impl Into<String>, exit_code: i32) -> Self {
        let stdout_s = stdout.into();
        let stderr_s = stderr.into();
        let success = exit_code == 0;
        Self {
            stdout: stdout_s,
            stderr: stderr_s,
            exit_code,
            success,
        }
    }
}

use crate::types::Language;

#[derive(Debug, Clone, Getters, CopyGetters)]
pub struct CheckContext {
    env_vars: HashMap<String, String>,

    #[getset(get_copy = "pub")]
    skip_network: bool,

    #[getset(get_copy = "pub")]
    verbose: bool,

    #[getset(get_copy = "pub")]
    timeout_ms: u64,

    #[getset(get_copy = "pub")]
    language: Language,
}

impl CheckContext {
    pub fn new(skip_network: bool, verbose: bool, timeout_ms: u64, language: Language) -> Self {
        let env_vars = std::env::vars().collect();
        Self {
            env_vars,
            skip_network,
            verbose,
            timeout_ms,
            language,
        }
    }

    pub fn with_env(
        env_vars: HashMap<String, String>,
        skip_network: bool,
        verbose: bool,
        timeout_ms: u64,
        language: Language,
    ) -> Self {
        Self {
            env_vars,
            skip_network,
            verbose,
            timeout_ms,
            language,
        }
    }


    pub fn get_env(&self, key: &str) -> Option<&str> {
        self.env_vars.get(key).map(|s| s.as_str())
    }

    pub fn find_in_path(&self, executable: &str) -> Option<PathBuf> {
        let path_var = self.get_env("PATH")?;
        for entry in std::env::split_paths(&path_var) {
            let candidate = entry.join(executable);
            if candidate.is_file() {
                return Some(candidate);
            }
            #[cfg(windows)]
            {
                let candidate_exe = entry.join(format!("{}.exe", executable));
                if candidate_exe.is_file() {
                    return Some(candidate_exe);
                }
                let candidate_cmd = entry.join(format!("{}.cmd", executable));
                if candidate_cmd.is_file() {
                    return Some(candidate_cmd);
                }
            }
        }
        None
    }

    pub fn run_command(&self, program: &str, args: &[&str]) -> Result<CommandOutput, CheckError> {
        let mut cmd = Command::new(program);
        cmd.args(args);

        let output = cmd.output().map_err(|err| CheckError::CommandExecutionFailed {
            cmd: program.to_string(),
            details: err.to_string(),
        })?;

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let exit_code = output.status.code().unwrap_or(-1);

        Ok(CommandOutput::new(stdout, stderr, exit_code))
    }

    pub fn resolve_ips(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, CheckError> {
        let addr_str = format!("{}:{}", host, port);
        let addrs: Vec<IpAddr> = addr_str
            .to_socket_addrs()
            .map_err(|err| CheckError::NetworkProbeFailed {
                target: addr_str,
                details: err.to_string(),
            })?
            .map(|sa| sa.ip())
            .collect();
        Ok(addrs)
    }

    pub fn probe_tcp(&self, host: &str, port: u16, timeout_ms: u64) -> Result<u64, CheckError> {
        let start = Instant::now();
        let addr_str = format!("{}:{}", host, port);
        let addrs = addr_str
            .to_socket_addrs()
            .map_err(|err| CheckError::NetworkProbeFailed {
                target: addr_str.clone(),
                details: err.to_string(),
            })?;

        let timeout = Duration::from_millis(timeout_ms);
        let mut last_error = None;

        for addr in addrs {
            match TcpStream::connect_timeout(&addr, timeout) {
                Ok(_stream) => {
                    let elapsed = start.elapsed().as_millis() as u64;
                    return Ok(elapsed);
                }
                Err(err) => {
                    last_error = Some(err);
                }
            }
        }

        let err_desc = match last_error {
            Some(e) => e.to_string(),
            None => "No socket addresses resolved".to_string(),
        };

        Err(CheckError::NetworkProbeFailed {
            target: addr_str,
            details: err_desc,
        })
    }
}

/// Determines if an IP address belongs to standard Fake-IP pools commonly used by
/// proxy clients (Clash, Mihomo, Sing-box, Surge, Shadowrocket, etc.).
///
/// Typical Fake-IP CIDRs:
/// - IPv4: 198.18.0.0/15 (RFC 2544 benchmark testing range, universally adopted for Fake-IP)
/// - IPv6: fc00::/18 (Unique local address range used by Clash Meta / Mihomo fake-ip-range6)
pub fn is_fake_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            (segments[0] & 0xffc0) == 0xfc00
        }
    }
}

pub fn is_fake_ip_str(ip_str: &str) -> bool {
    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        is_fake_ip(&ip)
    } else {
        false
    }
}
