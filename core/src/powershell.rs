//! PowerShell PSReadLine history (`ConsoleHost_history.txt`).
//!
//! Plain one-command-per-line with **no timestamps** (Microsoft *about_PSReadLine*).
//! A command spanning multiple lines ends each non-final physical line with a
//! trailing backtick (PowerShell's line-continuation char); the reader rejoins
//! them. A leading UTF-8 BOM is stripped if present.
//!
//! Note for the analyzer: PSReadLine refuses to persist lines containing
//! `password`/`token`/`secret`/`apikey`/`asplaintext`, so the *absence* of a
//! credential command here is not evidence it was never run — a coverage caveat,
//! never a negative finding.

use crate::{HistoryEntry, Shell};

fn ends_with_continuation(line: &str) -> bool {
    // A trailing backtick continues the command. An even run of backticks is an
    // escaped literal backtick, not a continuation.
    line.bytes().rev().take_while(|&b| b == b'`').count() % 2 == 1
}

/// Parse PSReadLine history bytes into entries (all timestamps `None`).
#[must_use]
pub fn parse(data: &[u8]) -> Vec<HistoryEntry> {
    let text = String::from_utf8_lossy(crate::strip_bom(data));
    let mut entries = Vec::new();
    let mut current = String::new();
    let mut continuing = false;

    for line in text.split('\n') {
        if continuing {
            current.push('\n');
            current.push_str(line);
        } else {
            current = line.to_string();
        }
        if ends_with_continuation(line) {
            current.pop(); // drop the trailing backtick
            continuing = true;
        } else {
            if !current.is_empty() {
                entries.push(HistoryEntry::plain(
                    Shell::PowerShell,
                    std::mem::take(&mut current),
                ));
            }
            current.clear();
            continuing = false;
        }
    }
    if continuing && !current.is_empty() {
        entries.push(HistoryEntry::plain(Shell::PowerShell, current));
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_lines_become_entries_without_timestamps() {
        let e = parse(b"Get-Process\nGet-ChildItem\n");
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].command, "Get-Process");
        assert!(e.iter().all(|x| x.timestamp.is_none()));
        assert_eq!(e[0].shell, Shell::PowerShell);
    }

    #[test]
    fn leading_bom_is_stripped() {
        let e = parse(b"\xEF\xBB\xBFGet-Process\n");
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].command, "Get-Process");
    }

    #[test]
    fn backtick_continuation_rejoins_a_multiline_command() {
        let e = parse(b"Get-Process |`\nWhere-Object CPU -gt 1\nls\n");
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].command, "Get-Process |\nWhere-Object CPU -gt 1");
        assert_eq!(e[1].command, "ls");
    }

    #[test]
    fn empty_input_yields_no_entries() {
        assert!(parse(b"").is_empty());
    }
}
