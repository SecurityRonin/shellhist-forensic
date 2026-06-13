//! Fish history (`fish_history`).
//!
//! A "nearly-YAML" record list (fish `src/history/yaml_backend.rs`): each entry is
//! `- cmd: <text>`, `  when: <epoch>`, and an optional `  paths:` block of
//! `    - <path>` lines. The `cmd` value can contain literal `:` and `#`, so it is
//! NOT valid YAML — parse by line prefix. Fish escapes EXACTLY two things in
//! `cmd`: `\` → `\\` and newline → `\n`; decoding reverses only those.

use crate::{HistoryEntry, Shell};

/// Reverse fish's two-rule escaping: `\\` → `\`, `\n` → newline. No other escape
/// exists, so a lone backslash before any other char is kept verbatim.
#[must_use]
pub fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                // An escaped backslash, or a trailing lone backslash at EOF: both
                // yield a single literal backslash.
                Some('\\') | None => out.push('\\'),
                Some('n') => out.push('\n'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Parse fish history bytes into entries.
#[must_use]
pub fn parse(data: &[u8]) -> Vec<HistoryEntry> {
    let text = String::from_utf8_lossy(crate::strip_bom(data));
    let mut entries: Vec<HistoryEntry> = Vec::new();
    let mut in_paths = false;

    for line in text.lines() {
        if let Some(cmd) = line.strip_prefix("- cmd: ") {
            entries.push(HistoryEntry {
                shell: Shell::Fish,
                command: unescape(cmd),
                timestamp: None,
                elapsed: None,
                paths: Vec::new(),
            });
            in_paths = false;
        } else if let Some(when) = line.strip_prefix("  when: ") {
            if let Some(last) = entries.last_mut() {
                last.timestamp = when.trim().parse::<i64>().ok();
            }
            in_paths = false;
        } else if line.trim_end() == "  paths:" {
            in_paths = true;
        } else if in_paths {
            if let Some(path) = line.strip_prefix("    - ") {
                if let Some(last) = entries.last_mut() {
                    last.paths.push(unescape(path));
                }
            } else {
                in_paths = false;
            }
        }
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescape_reverses_only_backslash_and_newline() {
        assert_eq!(unescape(r"a\\b"), r"a\b");
        assert_eq!(unescape(r"line1\nline2"), "line1\nline2");
        assert_eq!(unescape(r"keep\:colon"), r"keep\:colon"); // ':' not an escape
    }

    #[test]
    fn parses_cmd_when_and_paths() {
        let data = b"- cmd: git status\n  when: 1700000000\n  paths:\n    - /repo\n- cmd: ls\n  when: 1700000005\n";
        let e = parse(data);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].command, "git status");
        assert_eq!(e[0].timestamp, Some(1_700_000_000));
        assert_eq!(e[0].paths, vec!["/repo".to_string()]);
        assert_eq!(e[1].command, "ls");
        assert!(e[1].paths.is_empty());
    }

    #[test]
    fn cmd_with_colon_and_hash_is_kept_verbatim() {
        // The reason fish_history is not valid YAML — must not be lost.
        let e = parse(b"- cmd: echo http://x # note\n  when: 1700000000\n");
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].command, "echo http://x # note");
    }

    #[test]
    fn escaped_newline_in_cmd_is_restored() {
        let e = parse(b"- cmd: echo a\\nb\n  when: 1700000000\n");
        assert_eq!(e[0].command, "echo a\nb");
    }

    #[test]
    fn empty_input_yields_no_entries() {
        assert!(parse(b"").is_empty());
    }
}
