# shellhist-forensic — Purpose & Scope

> **Tier: Library.** This repository ships two library crates that are *linked*,
> not a binary an examiner runs. There is no CLI, GUI, or MCP server here. This
> document is the lighter, library-tier intent doc the fleet standard prescribes
> — a concise statement of what the crates are, who links them, and where the
> scope boundary sits. Load-bearing design decisions are recorded as ADRs in
> [`docs/decisions/`](decisions/).

## Purpose

Read shell command-history files off disk and grade them for the traces an
attacker leaves behind. A history file looks like plain text, but each shell
encodes timestamps, multi-line commands, and elapsed time differently — and the
suspicious entries hide in exactly those seams. `shellhist` decodes the four
common formats into one typed stream and surfaces the history clearing,
back-dated entries, and download-pipe-to-shell payloads an examiner needs to see.

Two crates, one workspace (see ADR 0001):

- **`shellhist-core`** — the reader. Parses bash (`.bash_history`, `#<epoch>`
  timestamps + multi-line commands), zsh (`.zsh_history`, `EXTENDED_HISTORY`
  `: start:elapsed;cmd` + backslash continuation), fish (`fish_history`,
  nearly-YAML with a two-rule unescape), and PowerShell PSReadLine
  (`ConsoleHost_history.txt`, backtick continuation) into a uniform
  `HistoryEntry` stream. Pure Rust, zero external dependencies, no `unsafe`, no
  regex engine (ADR 0002, 0003).
- **`shellhist-forensic`** — the auditor. Turns the parsed entry stream into
  severity-graded `forensicnomicon::report::Finding`s, so shell history
  aggregates uniformly with the rest of the forensic fleet (ADR 0005).

## Who links it

- **`issen`** (fleet ORCHESTRATION) — consumes graded findings for cross-artifact
  correlation. `shellhist-core` sits in the PARSER layer of the fleet
  architecture: it interprets artifact records as forensic meaning and depends
  only on `forensicnomicon` (KNOWLEDGE); it imports no CONTAINER, FILESYSTEM,
  PAGING, or LOG-FORMAT crate.
- **Third-party Rust code** that needs a robust shell-history reader — link
  `shellhist-core` alone (it never pulls in the finding model).
- **Fleet analyzers / front-ends** that want graded output — link
  `shellhist-forensic`.

The crates accept **bytes + an optional filename hint**; they are medium-agnostic
by design. Whoever located the file — the live OS, a mounted image via
`4n6mount`, or an extraction pipeline — hands over the bytes; `shellhist` does
not know or care about the source medium.

## What it does

- **Auto-detect the format from bytes**, with the filename only breaking ties
  (`parse_auto`, ADR 0004). Unrecognized input degrades to plain
  one-command-per-line rather than erroring.
- **Normalize four shells into one `HistoryEntry`** (`shell`, `command`,
  `timestamp`, `elapsed`, `paths`), with `Option` timestamps so "no timestamp
  recorded" stays distinct from a real epoch.
- **Grade anomalies** into stable, published codes (ADR 0005):

  | Code | Severity | Category | Observes |
  |---|---|---|---|
  | `SHELLHIST-HISTORY-DISABLED` | Medium | Concealment | Surviving history-clearing/disabling command (MITRE T1070.003) |
  | `SHELLHIST-TIMESTAMP-REGRESSION` | Medium | Integrity | Non-monotonic epoch — consistent with back-dated entries |
  | `SHELLHIST-REMOTE-EXEC-PIPE` | Medium | Threat | Download piped into a shell (MITRE T1059 / T1105) |
  | `SHELLHIST-PWSH-ENCODED-CMD` | Medium | Threat | Encoded / policy-bypassing PowerShell (MITRE T1059.001 / T1027) |

  Every finding is an **observation** ("consistent with …"); the examiner draws
  the conclusion.

## Scope

- Reading the four named history formats from raw bytes.
- Normalizing them to one entry stream.
- Grading the anomaly classes in the table above and emitting them as
  `forensicnomicon::report::Finding`s.

## Non-goals

- **No binary / CLI / GUI.** The user-facing surface is the fleet CLI (`issen`),
  not this repo. A debug harness, if ever added, does not change the library
  tier.
- **No source-medium handling.** No container decode, filesystem walk, or image
  mounting — callers pass bytes.
- **No recovery / carving of deleted or overwritten history** in the current
  scope (no `-carve` sibling yet). Only the live-file content is parsed.
- **No general obfuscated-command detection engine.** The anomaly matchers are
  deliberately simple substring/prefix checks (ADR 0002); they observe common
  patterns and will miss heavily obfuscated variants. This is an observation
  layer, not a detection product.
- **No negative findings.** The analyzer never asserts a command was *not* run —
  e.g. PSReadLine's refusal to persist credential-bearing lines is a documented
  coverage caveat, not evidence of absence.

## Validation approach

- **Spec-exact per-format fixtures.** Each parser's unit tests use byte fixtures
  derived from the authoritative grammar cited in the module header and
  `tests/data/README.md` (GNU Bash Reference Manual §9.2/§4.3.2; Zsh Manual
  §16.2.4 + `Src/hist.c`; fish `src/history/yaml_backend.rs`; Microsoft
  `about_PSReadLine`).
- **Real-artifact end-to-end check (Doer-Checker).** `forensic/tests/real_data.rs`
  runs against `tests/data/real_bash_history` — a history file produced by an
  actual `bash` subshell (not a synthetic fixture), with planted `curl … | sh`
  and `unset HISTFILE` traces the analyzer must re-surface. The generator command
  is recorded verbatim in `tests/data/README.md` for reproducibility.
- **Fuzzing.** Five `cargo-fuzz` targets (one per parser + `forensic` for the
  full parse→audit pipeline) assert the never-panic invariant on arbitrary input;
  `fuzz.yml` builds and smoke-runs each (ADR 0003).
- **Panic-free by lint.** `unwrap_used` / `expect_used` denied in production;
  `#![forbid(unsafe_code)]`; lenient lossy decoding degrades malformed input to
  plain lines rather than crashing.
