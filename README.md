# shellhist-forensic

[![shellhist-core](https://img.shields.io/crates/v/shellhist-core.svg?label=shellhist-core)](https://crates.io/crates/shellhist-core)
[![shellhist-forensic](https://img.shields.io/crates/v/shellhist-forensic.svg?label=shellhist-forensic)](https://crates.io/crates/shellhist-forensic)
[![Docs.rs](https://img.shields.io/docsrs/shellhist-forensic)](https://docs.rs/shellhist-forensic)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/shellhist-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/shellhist-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**A from-scratch shell command-history reader and a graded anomaly auditor — parse bash, zsh, fish, and PowerShell PSReadLine history straight off disk and surface the history clearing, back-dated entries, and download-pipe-to-shell payloads that an attacker hoped you would scroll past.**

Two crates, one workspace:

- **[`shellhist-core`](https://crates.io/crates/shellhist-core)** — the reader: bash (`.bash_history`, `#<epoch>` + multi-line), zsh (`.zsh_history`, `EXTENDED_HISTORY` `: start:elapsed;cmd` + backslash continuation), fish (`fish_history`, nearly-YAML with a 2-rule unescape), and PowerShell PSReadLine (`ConsoleHost_history.txt`, backtick continuation) into one uniform [`HistoryEntry`] stream. Pure Rust, no `unsafe`, no regex engine — reads a history file authored on any OS.
- **[`shellhist-forensic`](https://crates.io/crates/shellhist-forensic)** — the auditor: turns the parsed entry stream into severity-graded [`forensicnomicon::report::Finding`](https://crates.io/crates/forensicnomicon)s, so a host's shell history aggregates uniformly with the rest of the forensic fleet.

## Audit a history file in 30 seconds

```toml
[dependencies]
shellhist-forensic = "0.1"   # pulls in shellhist-core
```

```rust
use shellhist_core::parse_auto;
use shellhist_forensic::{audit, source};

// Bytes off disk + an optional filename hint; the format is auto-detected.
let entries = parse_auto(history_bytes, Some(".bash_history"));

for anomaly in audit(&entries) {
    let finding = anomaly.to_finding(source("host"));
    println!("[{:?}] {} — {}", finding.severity, finding.code, finding.note);
    // e.g. [Some(Medium)] SHELLHIST-REMOTE-EXEC-PIPE — the command "curl … | sh" downloads and pipes …
}
```

`parse_auto` sniffs the format from the bytes (the filename only disambiguates ties); `audit` grades what it finds. Malformed or truncated history never panics — it degrades to plain lines.

Skip the two-step and get findings directly:

```rust
use shellhist_core::parse_auto;
use shellhist_forensic::audit_findings;

let entries = parse_auto(history_bytes, Some("ConsoleHost_history.txt"));
let findings = audit_findings(&entries, "host");   // Vec<forensicnomicon::report::Finding>
```

## The anomaly codes

Each anomaly is an **observation** ("consistent with …"); the examiner draws the conclusions. Codes are a stable, published contract.

| Code | Severity | Category | What it observes |
|---|---|---|---|
| `SHELLHIST-HISTORY-DISABLED` | Medium | Concealment | A surviving command that disables or clears history (`unset HISTFILE`, `history -c`, …) — consistent with anti-forensic history tampering (MITRE T1070.003) |
| `SHELLHIST-TIMESTAMP-REGRESSION` | Medium | Integrity | An entry whose epoch precedes its predecessor's — history went backwards in time, consistent with injected or back-dated entries |
| `SHELLHIST-REMOTE-EXEC-PIPE` | Medium | Threat | A download piped straight into a shell (`curl … \| sh`) — consistent with remote payload execution (MITRE T1059 / T1105) |
| `SHELLHIST-PWSH-ENCODED-CMD` | Medium | Threat | An encoded or policy-bypassing PowerShell invocation — consistent with obfuscated execution (MITRE T1059.001 / T1027) |

`audit(&entries)` returns the typed [`HistAnomaly`] stream; each anomaly emits a graded `report::Finding` via `to_finding(source)`, and `audit_findings(&entries, scope)` does both in one call. `source(scope)` stamps the analyzer provenance.

## The reader: one stream across four shells

`shellhist-core` decodes each format's quirks and normalizes them into a single [`HistoryEntry`] (`shell`, `command`, `timestamp`, `elapsed`, `paths`):

```rust
use shellhist_core::{parse_auto, detect, Shell};

// Detect the format without committing to a parse…
assert_eq!(detect(b": 1700000000:0;ls", None), Shell::Zsh);

// …or just parse. Multi-line commands keep their embedded newlines; zsh
// EXTENDED_HISTORY entries carry both `timestamp` and `elapsed`.
let entries = parse_auto(b": 1700000000:5;make build\n", None);
assert_eq!(entries[0].command, "make build");
assert_eq!(entries[0].elapsed, Some(5));
```

Per-format entry points (`shellhist_core::{bash, zsh, fish, powershell}::parse`) are available when the shell is already known.

## What makes this different from `cat`-ing a history file

A history file looks like plain text, but each shell encodes timestamps, multi-line commands, and elapsed time differently — and an attacker's traces hide in exactly those seams. This workspace answers the questions a digital forensics examiner actually needs:

| Capability | `cat` / a line splitter | this workspace |
|---|---|---|
| Plain one-command-per-line read | ✅ | ✅ |
| bash `#<epoch>` timestamp + multi-line commands | — | ✅ |
| zsh `EXTENDED_HISTORY` (`: start:elapsed;cmd`) + backslash continuation | — | ✅ |
| fish nearly-YAML records + path association | — | ✅ |
| PowerShell PSReadLine backtick continuation | — | ✅ |
| Auto-detect format from bytes (filename only breaks ties) | — | ✅ |
| History-clearing / `unset HISTFILE` detection | — | ✅ |
| Timestamp-regression (back-dating) detection | — | ✅ |
| Download-pipe-to-shell detection | — | ✅ |
| Encoded-PowerShell detection | — | ✅ |
| Severity-graded `report::Finding` output | — | ✅ |
| Pure Rust, `#![forbid(unsafe_code)]` | — | ✅ |

## Trust, but verify

`shellhist-forensic` is built for untrusted history files from potentially compromised systems:

- **`#![forbid(unsafe_code)]`** across both crates — no FFI, no C bindings. It reads a history file authored on any OS.
- **Panic-free on malicious input** — parsing is lenient (lossy UTF-8) and bounds-checked; the workspace denies `clippy::unwrap_used` and `clippy::expect_used` in production code. A truncated or garbled file degrades to plain lines, never a crash.
- **Fuzzed** — five `cargo-fuzz` targets (`bash`, `zsh`, `fish`, `powershell`, and `forensic` for the full parse→audit pipeline); a `fuzz.yml` CI workflow builds and smoke-runs each.
- **Validated on real artifacts** — the analyzer is exercised end-to-end against a history file generated by an actual `bash` subshell (not a synthetic fixture), with its planted `curl … | sh` and `unset HISTFILE` traces re-surfaced (see `forensic/tests/real_data.rs`).

```bash
cargo test
cargo +nightly fuzz run forensic   # requires nightly + cargo-fuzz
```

## Where this fits

`shellhist-core` is the shell command-history foundation for the SecurityRonin forensic family. It sits in the PARSER layer — interpreting artifact records as forensic meaning — and feeds graded findings into [`issen`](https://github.com/SecurityRonin/issen) for cross-artifact correlation. Related fleet crates:

| Crate | Role |
|---|---|
| [`forensicnomicon`](https://crates.io/crates/forensicnomicon) | **KNOWLEDGE** — the shared `report::Finding` model every analyzer emits |
| [`issen`](https://github.com/SecurityRonin/issen) | **Orchestrator** — wires every forensic path and correlates findings |
| [`ntfs-forensic`](https://github.com/SecurityRonin/ntfs-forensic) | NTFS filesystem reader + anomaly auditor |

---

[Privacy Policy](https://securityronin.github.io/shellhist-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/shellhist-forensic/terms/) · © 2026 Security Ronin Ltd
