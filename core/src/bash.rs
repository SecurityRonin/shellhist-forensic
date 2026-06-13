//! Bash history (`.bash_history`).
//!
//! Plain one-command-per-line by default. With `HISTTIMEFORMAT` set, each entry
//! is preceded by a `#<unix_epoch>` line (Bash manual, *Bash History Builtins*).
//! Multi-line commands are stored with literal embedded newlines (`cmdhist` on,
//! default), so a `#<digits>` line is the only reliable entry boundary — the
//! lines that follow it accumulate into one command until the next boundary.

use crate::{HistoryEntry, Shell};

/// If `line` is a bash timestamp line (`#` immediately followed by ≥1 digits and
/// nothing else), return the epoch. Bash writes only the raw integer.
#[must_use]
pub fn parse_timestamp_line(line: &str) -> Option<i64> {
    let rest = line.strip_prefix('#')?;
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    rest.parse::<i64>().ok()
}

/// Parse bash history bytes into entries.
#[must_use]
pub fn parse(data: &[u8]) -> Vec<HistoryEntry> {
    let text = String::from_utf8_lossy(crate::strip_bom(data));
    let mut entries = Vec::new();

    // `accumulating` is true once we have seen a `#<epoch>` marker: subsequent
    // physical lines belong to that one (possibly multi-line) command until the
    // next marker. Before any marker, the file is plain one-command-per-line.
    let mut pending_ts: Option<i64> = None;
    let mut accumulating = false;
    let mut cmd_lines: Vec<&str> = Vec::new();

    let flush = |entries: &mut Vec<HistoryEntry>, ts: Option<i64>, lines: &mut Vec<&str>| {
        if lines.is_empty() {
            return;
        }
        let command = lines.join("\n");
        lines.clear();
        if command.is_empty() {
            return;
        }
        entries.push(HistoryEntry {
            shell: Shell::Bash,
            command,
            timestamp: ts,
            elapsed: None,
            paths: Vec::new(),
        });
    };

    for line in text.lines() {
        if let Some(ts) = parse_timestamp_line(line) {
            flush(&mut entries, pending_ts, &mut cmd_lines);
            pending_ts = Some(ts);
            accumulating = true;
        } else if accumulating {
            cmd_lines.push(line);
        } else if !line.is_empty() {
            // Plain mode: each line is its own command.
            entries.push(HistoryEntry::plain(Shell::Bash, line));
        }
    }
    flush(&mut entries, pending_ts, &mut cmd_lines);

    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_line_requires_hash_then_only_digits() {
        assert_eq!(parse_timestamp_line("#1700000000"), Some(1_700_000_000));
        assert_eq!(parse_timestamp_line("#0"), Some(0));
        assert_eq!(parse_timestamp_line("# 1700"), None); // space after #
        assert_eq!(parse_timestamp_line("#abc"), None);
        assert_eq!(parse_timestamp_line("echo #1700"), None);
        assert_eq!(parse_timestamp_line("#"), None);
    }

    #[test]
    fn plain_history_is_one_command_per_line() {
        let e = parse(b"ls -la\ncd /tmp\nwhoami\n");
        assert_eq!(e.len(), 3);
        assert_eq!(e[0].command, "ls -la");
        assert!(e.iter().all(|x| x.timestamp.is_none()));
    }

    #[test]
    fn timestamped_history_pairs_each_command_with_its_epoch() {
        // The on-disk shape bash writes with HISTTIMEFORMAT set.
        let e = parse(b"#1700000000\nls\n#1700000005\nwhoami\n");
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].timestamp, Some(1_700_000_000));
        assert_eq!(e[0].command, "ls");
        assert_eq!(e[1].timestamp, Some(1_700_000_005));
        assert_eq!(e[1].command, "whoami");
    }

    #[test]
    fn multiline_command_keeps_embedded_newlines_under_one_timestamp() {
        // A `for` loop is stored with literal newlines (lithist/cmdhist).
        let e = parse(b"#1700000000\nfor i in 1 2\ndo echo $i\ndone\n#1700000009\nls\n");
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].command, "for i in 1 2\ndo echo $i\ndone");
        assert_eq!(e[0].timestamp, Some(1_700_000_000));
        assert_eq!(e[1].command, "ls");
    }

    #[test]
    fn empty_input_yields_no_entries() {
        assert!(parse(b"").is_empty());
        assert!(parse(b"\n\n").is_empty());
    }
}
