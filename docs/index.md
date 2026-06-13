# shellhist-forensic

A from-scratch shell command-history reader and a graded anomaly auditor — parse
bash, zsh, fish, and PowerShell PSReadLine history from a file authored on **any**
OS, then surface the history clearing, back-dated entries, and download-pipe-to-shell
payloads that an attacker hoped you would scroll past.

Two crates, one workspace:

- **[`shellhist-core`](https://crates.io/crates/shellhist-core)** — the reader: bash
  (`.bash_history`, `#<epoch>` + multi-line), zsh (`.zsh_history`, `EXTENDED_HISTORY`
  `: start:elapsed;cmd` + backslash continuation), fish (`fish_history`, nearly-YAML
  with a 2-rule unescape), and PowerShell PSReadLine (`ConsoleHost_history.txt`,
  backtick continuation) into one uniform `HistoryEntry` stream. No `unsafe`, no
  regex engine, no C bindings. The format is auto-detected from the bytes.
- **[`shellhist-forensic`](https://crates.io/crates/shellhist-forensic)** — the
  auditor: turns the parsed entry stream into severity-graded
  [`forensicnomicon::report::Finding`](https://crates.io/crates/forensicnomicon)s
  so a host's shell history aggregates uniformly with the rest of the fleet.

## Audit a history file

```rust
use shellhist_core::parse_auto;
use shellhist_forensic::{audit, source};

let entries = parse_auto(history_bytes, Some(".bash_history"));

for anomaly in audit(&entries) {
    let finding = anomaly.to_finding(source("host"));
    println!("[{:?}] {} — {}", finding.severity, finding.code, finding.note);
    // e.g. [Some(Medium)] SHELLHIST-REMOTE-EXEC-PIPE — the command "curl … | sh" downloads and pipes …
}
```

## The anomaly codes

Each anomaly is an **observation** ("consistent with …"); the examiner draws the
conclusions. Codes are a stable, published contract.

| Code | Severity | Category | What it observes |
|---|---|---|---|
| `SHELLHIST-HISTORY-DISABLED` | Medium | Concealment | A surviving command that disables or clears history (`unset HISTFILE`, `history -c`, …) — consistent with anti-forensic history tampering (MITRE T1070.003) |
| `SHELLHIST-TIMESTAMP-REGRESSION` | Medium | Integrity | An entry whose epoch precedes its predecessor's — history went backwards in time, consistent with injected or back-dated entries |
| `SHELLHIST-REMOTE-EXEC-PIPE` | Medium | Threat | A download piped straight into a shell (`curl … \| sh`) — consistent with remote payload execution (MITRE T1059 / T1105) |
| `SHELLHIST-PWSH-ENCODED-CMD` | Medium | Threat | An encoded or policy-bypassing PowerShell invocation — consistent with obfuscated execution (MITRE T1059.001 / T1027) |

## Trust but verify

`shellhist-core` is panic-free on untrusted input (lenient lossy-UTF-8 parsing, no
`unwrap` in production), fuzzed per format, and validated against a history file
produced by a real `bash` subshell (Doer-Checker). A history file is
attacker-controllable evidence; the reader treats it as such.

---

[Privacy Policy](https://securityronin.github.io/shellhist-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/shellhist-forensic/terms/) · © 2026 Security Ronin Ltd
