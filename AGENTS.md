# Agent Guidelines

## 1. Engineering Standard

- Treat this as production software: no demo shortcuts, placeholder architecture, silent failures, or knowingly incomplete committed behavior.
- Before coding, define intended behavior, edge cases, state transitions, architectural fit, and verification strategy.
- Before building custom infrastructure or feature code, search online for a mature, maintained, version-compatible solution. Use it when available; adding dependencies is allowed and preferred over reinvention.
- Keep CLI diagnostics cohesive, configurable, deterministic, explicit about failures, and covered by focused tests for non-trivial pure logic. Complete the prescribed checks before declaring work done.

## 2. Dependencies and Tooling

### Rust dependencies

- Define every dependency in the root `Cargo.toml` under `[workspace.dependencies]`; sub-crates must not declare independent or duplicate versions.
- Crates under `apps/` and `crates/` must use `{ workspace = true }` without duplicate versions or conflicting feature declarations.
- For new libraries, verify maintenance and version compatibility, then add them at the workspace root and inherit them in member crates.

### Python packages

- Use `uv` exclusively (`uv add`, `uv sync`, or `uv pip install`), never `pip` or `python -m pip`.
- Reuse the existing environment and `uv` cache; do not unnecessarily reinstall available packages.

## 3. Editing and Commits

- Never run whole-workspace formatting (`cargo fmt`, `cargo fmt --all`, or equivalent global formatters). Format only edited files and lines; keep diffs focused to protect blame history and reduce merge conflicts.
- When the user explicitly requests a commit, assume required checks are already complete. Unless specifically asked, do not run extra verification, builds, tests, formatting, or broad status/diff commands.
- Stage only the requested files or changes just completed, commit them directly, and report the hash.

## 5. Domain Encapsulation and Cohesion

- A domain type owns its invariants. Prefer private fields and validate at construction with `new`/`try_new` returning `Result`; never create invalid state for an unrelated helper or later system to validate.
- Use `getset::CopyGetters` for simple getters over `Copy` fields and `getset::Getters` for simple borrowed getters instead of writing trivial accessor methods by hand. Keep a handwritten method when it enforces an invariant, computes or transforms a value, adapts the exposed type (for example, `Vec<T>` to `&[T]`), or otherwise represents domain behavior rather than raw field access.
- Keep behavior with its data and follow “Tell, Don’t Ask.” Logic primarily reading or transforming one domain type should normally be an inherent method.
- Avoid anemic domain models and feature envy: callers must not reproduce a type's rules or coordinate its internal transitions externally.
- Delegate validation and calculations to domain methods.
- Free functions are appropriate for generic stateless algorithms, symmetric operations without a clear owner, and cross-aggregate orchestration. Passive transport records need not gain artificial methods.
- Prefer extension traits (`*Ext`) when enriching third-party or standard library types.
- Production code and tests should use validated public constructors and behavior methods. Bypass constructors only in focused invariant tests or through a valid `Default` that preserves the same invariants.

## 6. CLI & Engine Structure and Code Organization

- Put unit and module tests in dedicated `tests.rs` files declared with `#[cfg(test)] mod tests;`, never at the bottom of implementation files.
- Give each feature or submodule single-responsibility files:
  - `types.rs`: structs, enums, value objects, and domain invariants.
  - `rule.rs`: diagnostic rule definition, check traits, and metadata.
  - `runner.rs`: check execution engine, task sequencing, and result collation.
  - `context.rs`: runtime environment, paths, mockable command/network executors.
  - `tests.rs`: focused unit and integration tests.
  - `mod.rs`: module declarations and clean public/crate re-exports.
- A workspace library crate's `lib.rs` is strictly its root and public re-export interface; delegate business logic to appropriate modules.
- Enforce strict workspace lints: `unwrap_used = "deny"`, `expect_used = "deny"`, `panic = "deny"`, `todo = "deny"`, `dbg_macro = "deny"`. All operations must explicitly handle errors via `Result` and domain errors.

## 7. Diagnostic Boundary and Environment Safety

- The environment checker runs in diverse user configurations (local developer machines, CI/CD runners, Docker containers, remote SSH sessions).
- Diagnostic rules must be non-destructive: check, inspect, and verify without mutating the host environment, altering configuration files, or wiping credentials.
- When remediation commands are generated (e.g. `npm install -g @anthropic-ai/claude-code`), format them as actionable suggestions rather than executing mutations without explicit user consent.
- Protect sensitive data: never log, print, or leak raw API keys, tokens, or credentials to terminal output or JSON reports; mask sensitive values (e.g., `sk-ant-...a1b2`).

## 8. Performance Engineering

- All local checks (OS, architecture, locale, PATH binaries, versions, git config) must execute swiftly with deterministic latency.
- Slow operations (network ping, endpoint TLS handshake, remote reachability) must have strict, bounded timeouts and must be skippable via CLI flags (e.g., `--skip-network`).
- Avoid wasteful process spawning: execute tools with minimal argument overhead and parse standard streams efficiently.
- Reuse buffers, pre-size collections, and avoid unnecessary heap allocations.

## 9. Architectural Layering and Capability Decoupling

- **No downward leaks into foundation crates**: Core checking engine crates (`check_claude_core`) must never depend on terminal rendering, ANSI color libraries, or CLI argument parsers.
- **Strict layer direction (Clean Architecture)**: Presentation crates (`check_claude_reporter`) observe domain results (`CheckReport`, `CheckResult`, `CheckStatus`). Presentation logic never executes environment probes.
- **Composition root**: The CLI application binary (`apps/check_claude`) serves as the composition root, wiring command line arguments, instantiating the runner, and delegating output to the reporter.

## 10. Execution Pipeline and Diagnostic Scheduling

- Phase-based diagnostic pipeline:
  1. Egress IP & Geolocation: probe public IP egress location and country code (via Cloudflare trace or IP geolocator).
  2. Claude Region Eligibility: verify detected country/territory against Anthropic official supported regions (flag unsupported regions like CN, HK, RU).
  3. Anthropic Endpoint & Geo-restriction: check HTTP status/Cloudflare region blocking for `api.anthropic.com` and `claude.ai`.
  4. Proxy & Routing Verification: inspect `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and check if outbound traffic is routed through supported region nodes.
  5. DNS Resolution & Anti-Poisoning: verify domain resolution integrity for Claude endpoints.
- Prerequisite awareness: If an upstream check indicates network offline or DNS failure, dependent probes must be skipped or marked as blocked with clear explanation rather than raising misleading errors.
