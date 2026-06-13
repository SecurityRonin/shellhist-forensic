//! Zsh history (`.zsh_history`).
//!
//! With `EXTENDED_HISTORY` each entry is `: <beginning_time>:<elapsed_seconds>;<command>`
//! (zsh Options manual). A command containing newlines is written with each
//! embedded newline escaped as a trailing backslash before the physical newline;
//! the reader rejoins backslash-continued physical lines (zsh `Src/hist.c`
//! `readhistline`). Without `EXTENDED_HISTORY` the file is plain one-per-line.

use crate::{HistoryEntry, Shell};

/// True if `line` begins with the `EXTENDED_HISTORY` metadata prefix
/// `: <digits>:<digits>;`.
#[must_use]
pub fn is_extended_line(line: &str) -> bool {
    parse_extended_prefix(line).is_some()
}

/// Split `: <start>:<elapsed>;<command>` into `((start, elapsed), command)`.
fn parse_extended_prefix(line: &str) -> Option<((i64, i64), &str)> {
    let rest = line.strip_prefix(": ")?;
    let (meta, command) = rest.split_once(';')?;
    let (start, elapsed) = meta.split_once(':')?;
    if start.is_empty() || !start.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if elapsed.is_empty() || !elapsed.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((
        start.parse::<i64>().ok().zip(elapsed.parse::<i64>().ok())?,
        command,
    ))
}

/// Does this physical line end with an odd number of backslashes (a continuation)?
fn ends_with_odd_backslashes(line: &str) -> bool {
    line.bytes().rev().take_while(|&b| b == b'\\').count() % 2 == 1
}

/// Rejoin backslash-continued physical lines into logical lines, restoring the
/// embedded newline that the trailing backslash escaped.
fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut continuing = false;
    for line in text.split('\n') {
        if continuing {
            current.push('\n');
            current.push_str(line);
        } else {
            current = line.to_string();
        }
        if ends_with_odd_backslashes(line) {
            // Drop the trailing escape backslash; the newline is kept by the join.
            current.pop();
            continuing = true;
        } else {
            out.push(std::mem::take(&mut current));
            continuing = false;
        }
    }
    if continuing {
        out.push(current);
    }
    out
}

/// Parse zsh history bytes into entries.
#[must_use]
pub fn parse(data: &[u8]) -> Vec<HistoryEntry> {
    let text = String::from_utf8_lossy(crate::strip_bom(data));
    let mut entries = Vec::new();
    for ll in logical_lines(&text) {
        if ll.is_empty() {
            continue;
        }
        if let Some(((start, elapsed), command)) = parse_extended_prefix(&ll) {
            entries.push(HistoryEntry {
                shell: Shell::Zsh,
                command: command.to_string(),
                timestamp: Some(start),
                elapsed: Some(elapsed),
                paths: Vec::new(),
            });
        } else {
            entries.push(HistoryEntry::plain(Shell::Zsh, ll));
        }
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extended_prefix_is_recognized() {
        assert!(is_extended_line(": 1700000000:3;sleep 3"));
        assert!(!is_extended_line("plain command"));
        assert!(!is_extended_line(": notanumber:0;x"));
    }

    #[test]
    fn extended_entry_carries_start_and_elapsed() {
        let e = parse(b": 1700000000:3;sleep 3\n: 1700000010:0;ls\n");
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].timestamp, Some(1_700_000_000));
        assert_eq!(e[0].elapsed, Some(3));
        assert_eq!(e[0].command, "sleep 3");
        assert_eq!(e[1].elapsed, Some(0));
    }

    #[test]
    fn plain_zsh_history_has_no_timestamps() {
        let e = parse(b"ls\ncd /tmp\n");
        assert_eq!(e.len(), 2);
        assert!(e
            .iter()
            .all(|x| x.timestamp.is_none() && x.elapsed.is_none()));
    }

    #[test]
    fn backslash_continuation_rejoins_a_multiline_command() {
        // `echo a\<newline>b` stored as a continued line, restored with a newline.
        let e = parse(b": 1700000000:0;echo a\\\nb\n: 1700000001:0;ls\n");
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].command, "echo a\nb");
        assert_eq!(e[1].command, "ls");
    }

    #[test]
    fn a_command_containing_a_semicolon_keeps_it() {
        let e = parse(b": 1700000000:0;echo a; echo b\n");
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].command, "echo a; echo b");
    }

    #[test]
    fn empty_input_yields_no_entries() {
        assert!(parse(b"").is_empty());
    }
}
