# 2. From-scratch, zero-dependency pure-Rust readers (no regex engine)

Date: 2026-07-24
Status: Accepted

## Context

The four history formats are all line-oriented text with small, well-specified
grammars:

- bash: plain lines, optional `#<epoch>` timestamp lines, literal multi-line
  commands (GNU Bash Reference Manual §9.2 / §4.3.2).
- zsh `EXTENDED_HISTORY`: `: <start>:<elapsed>;<command>` with backslash-newline
  continuation (Zsh Manual §16.2.4, `Src/hist.c`).
- fish: a "nearly-YAML" record list with exactly two escape rules
  (`src/history/yaml_backend.rs`).
- PowerShell PSReadLine: plain lines, no timestamps, backtick continuation
  (`about_PSReadLine`).

Each grammar is decidable by cheap prefix and boundary checks. A regex engine or
a YAML crate would add a dependency (and, for YAML, would be *wrong*: a fish
`cmd` value can contain literal `:` and `#`, so the file is not valid YAML). The
fleet "prefer our own crates / batteries-included" posture and the desire for a
single static, portable reader argue for the smallest honest dependency set.

## Decision

Hand-write each parser over `&[u8]` / `&str` with no third-party dependency:

1. `shellhist-core` has an **empty `[dependencies]`** table (`core/Cargo.toml`) —
   zero external crates, no regex engine, no YAML crate.
2. Each format is a self-contained module (`core/src/{bash,zsh,fish,powershell}.rs`)
   parsing by line prefix / boundary rules derived directly from the
   authoritative grammar cited in each module's doc header and in
   `tests/data/README.md`.
3. fish is parsed by line prefix, never as YAML, because its `cmd` values break
   YAML (`core/src/fish.rs` header); its two-rule unescape (`\\`→`\`, `\n`→
   newline) is implemented directly in `fish::unescape`.
4. `shellhist-forensic`'s only dependency beyond `shellhist-core` is
   `forensicnomicon` (the shared report model) — no regex there either; the
   anomaly matchers are plain substring/prefix checks over a lowercased copy
   (`is_history_disable` / `is_remote_exec_pipe` / `is_pwsh_encoded` in
   `forensic/src/lib.rs`).

## Consequences

- The reader is a pure-Rust leaf with no supply-chain surface of its own — a
  trust signal for parsing untrusted evidence, and a low `cargo deny` /
  `cargo vet` burden.
- The grammars are small and fixed, so the maintenance cost of owning the
  parsers is low and there is no engine to keep current.
- Correctness rides on spec-exact fixtures per module rather than a general
  parser's guarantees; robustness rides on fuzzing (see ADR 0003).
- Trade-off accepted: substring-based anomaly matching is deliberately simple
  and will miss heavily obfuscated variants; it is an *observation* layer
  ("consistent with"), not a detection engine (see ADR 0005).
