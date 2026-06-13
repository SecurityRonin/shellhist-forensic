//! `shellhist-core` — readers for shell command-history files.
//!
//! Parses the four common history formats into a uniform [`HistoryEntry`] stream:
//! bash (`.bash_history`), zsh (`.zsh_history`, including `EXTENDED_HISTORY`),
//! PowerShell PSReadLine (`ConsoleHost_history.txt`), and fish (`fish_history`).
//!
//! The input is attacker-controllable evidence: parsing is lenient (lossy UTF-8),
//! bounds-checked, and never panics. No `unsafe`. Findings live in the sibling
//! `shellhist-forensic` crate; this crate only decodes.

#![forbid(unsafe_code)]

pub mod bash;
pub mod fish;
pub mod powershell;
pub mod zsh;

/// The shell a history file was produced by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    PowerShell,
    /// Format could not be determined; parsed as plain one-command-per-line.
    Unknown,
}

/// One command-history entry, normalized across shells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// The shell this entry was decoded from.
    pub shell: Shell,
    /// The command text (multi-line commands keep their embedded newlines).
    pub command: String,
    /// Start time as Unix epoch seconds, when the format records it (bash with
    /// `HISTTIMEFORMAT`, zsh `EXTENDED_HISTORY`, fish). `None` for plain bash and
    /// PowerShell PSReadLine, which store no timestamps.
    pub timestamp: Option<i64>,
    /// Wall-clock duration in seconds (zsh `EXTENDED_HISTORY` only).
    pub elapsed: Option<i64>,
    /// Filesystem paths fish heuristically associated with the command.
    pub paths: Vec<String>,
}

impl HistoryEntry {
    pub(crate) fn plain(shell: Shell, command: impl Into<String>) -> Self {
        Self {
            shell,
            command: command.into(),
            timestamp: None,
            elapsed: None,
            paths: Vec::new(),
        }
    }
}

/// Strip a leading UTF-8 BOM (`EF BB BF`) if present.
#[must_use]
pub fn strip_bom(data: &[u8]) -> &[u8] {
    data.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(data)
}

/// Detect the history format from the bytes and an optional filename hint.
///
/// Content sniffing wins over the filename (a renamed file is still parseable):
/// a zsh `: <epoch>:<elapsed>;` line or a fish `- cmd:` record is unambiguous; a
/// bash `#<epoch>` timestamp line marks timestamped bash. Otherwise the filename
/// disambiguates PSReadLine vs plain bash; failing that, `Unknown` (plain lines).
#[must_use]
pub fn detect(data: &[u8], filename: Option<&str>) -> Shell {
    let text = String::from_utf8_lossy(strip_bom(data));

    for line in text.lines().take(200) {
        if zsh::is_extended_line(line) {
            return Shell::Zsh;
        }
        if line.starts_with("- cmd:") {
            return Shell::Fish;
        }
        if bash::parse_timestamp_line(line).is_some() {
            return Shell::Bash;
        }
    }

    if let Some(name) = filename {
        let lower = name.to_ascii_lowercase();
        if lower.contains("zsh_history") {
            return Shell::Zsh;
        }
        if lower.contains("fish_history") {
            return Shell::Fish;
        }
        if lower.contains("bash_history") {
            return Shell::Bash;
        }
        if lower.contains("consolehost_history") || lower.contains("psreadline") {
            return Shell::PowerShell;
        }
    }

    Shell::Unknown
}

/// Parse history bytes as the given shell.
#[must_use]
pub fn parse(data: &[u8], shell: Shell) -> Vec<HistoryEntry> {
    match shell {
        Shell::Bash | Shell::Unknown => bash::parse(data),
        Shell::Zsh => zsh::parse(data),
        Shell::Fish => fish::parse(data),
        Shell::PowerShell => powershell::parse(data),
    }
}

/// Detect the format, then parse. The zero-knowledge entry point.
#[must_use]
pub fn parse_auto(data: &[u8], filename: Option<&str>) -> Vec<HistoryEntry> {
    parse(data, detect(data, filename))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_bom_removes_only_a_leading_bom() {
        assert_eq!(strip_bom(b"\xEF\xBB\xBFhi"), b"hi");
        assert_eq!(strip_bom(b"hi"), b"hi");
    }

    #[test]
    fn detect_zsh_by_extended_line() {
        assert_eq!(detect(b": 1700000000:0;ls", None), Shell::Zsh);
    }

    #[test]
    fn detect_bash_by_timestamp_line() {
        assert_eq!(detect(b"#1700000000\nls\n", None), Shell::Bash);
    }

    #[test]
    fn detect_fish_by_cmd_record() {
        assert_eq!(
            detect(b"- cmd: ls\n  when: 1700000000\n", None),
            Shell::Fish
        );
    }

    #[test]
    fn detect_powershell_by_filename_when_content_is_plain() {
        assert_eq!(
            detect(b"Get-Process\nls\n", Some("ConsoleHost_history.txt")),
            Shell::PowerShell
        );
    }

    #[test]
    fn detect_falls_back_to_unknown_for_plain_unnamed() {
        assert_eq!(detect(b"ls\ncd /tmp\n", None), Shell::Unknown);
    }

    #[test]
    fn parse_auto_unknown_is_plain_lines() {
        let e = parse_auto(b"ls\ncd /tmp\n", None);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].command, "ls");
        assert_eq!(e[1].timestamp, None);
    }
}
