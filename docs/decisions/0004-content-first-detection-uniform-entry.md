# 4. Content-first format detection with filename tie-break; one uniform `HistoryEntry`

Date: 2026-07-24
Status: Accepted

## Context

An examiner points the reader at a file recovered from disk. The filename is
often unreliable: a `.bash_history` may have been renamed, carved, or copied to
a neutral name, and PSReadLine's `ConsoleHost_history.txt` and a plain
`.bash_history` are byte-identical when neither stores timestamps. The reader
must pick the right decoder from the bytes when it can, and fall back safely when
it cannot. Downstream correlation also needs the four shells' divergent encodings
(bash `#<epoch>`, zsh `: start:elapsed;`, fish records, PSReadLine plain)
flattened into one shape so shell history aggregates with the rest of the fleet.

## Decision

1. **Detect from content first, filename only to break ties.** `detect(data,
   filename)` (`core/src/lib.rs`) sniffs structural signatures — a zsh extended
   line `: <digits>:<digits>;`, a bash `#<digits>` timestamp line, a fish
   `- cmd:` record — before consulting the filename. The filename
   (`fish_history`, `bash_history`, `consolehost_history`/`psreadline`) only
   decides cases the bytes leave ambiguous (notably plain PSReadLine vs plain
   bash, which are indistinguishable by content — unit test
   `detect_powershell_by_filename_when_content_is_plain`).
2. **Fall back to `Shell::Unknown` → plain one-command-per-line**, routed to the
   bash parser (`parse` maps `Bash | Unknown => bash::parse`), so an unrecognized
   file still yields usable line entries rather than an error
   (`parse_auto_unknown_is_plain_lines`).
3. **`parse_auto(data, filename)` is the zero-knowledge entry point** —
   `detect` then `parse` — the secure-by-default path an examiner reaches for
   without knowing the shell.
4. **One `HistoryEntry`** normalizes all four shells (`core/src/lib.rs`):
   `shell`, `command` (multi-line commands keep embedded newlines), `timestamp`
   (`Option<i64>` epoch — `None` for formats that store none), `elapsed`
   (`Option<i64>`, zsh only), `paths` (fish-associated paths). Per-format entry
   points (`bash::parse`, `zsh::parse`, …) remain available when the shell is
   already known.

## Consequences

- Renaming a `.zsh_history` to an arbitrary name still parses correctly; the
  filename cannot force a wrong decode when the content is decisive.
- The plain-bash / plain-PSReadLine ambiguity is resolved by filename when
  present and defaults to bash-style plain-line parsing otherwise — an honest
  limitation documented in the detection tests, not hidden.
- Consumers and the analyzer see one entry type regardless of source shell;
  `Option` timestamps make "no timestamp recorded" (plain bash, PSReadLine)
  forensically distinct from a real epoch, rather than defaulting to 0.
