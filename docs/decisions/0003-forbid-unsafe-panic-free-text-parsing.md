# 3. `forbid(unsafe)` + panic-free lenient text parsing (no `safe-read`)

Date: 2026-07-24
Status: Accepted

## Context

These crates parse **untrusted, attacker-controllable** history files pulled
from a potentially compromised host. The fleet Paranoid Gatekeeper standard
(`ronin-issen/CLAUDE.md`) requires: never panic, never read out of bounds, never
trust a length field, and the global unsafe law makes `forbid(unsafe)` the
default and goal for parsers of attacker-crafted input.

The fleet's standard bounds-checked reader, the `safe-read` crate, exists for
**fixed-width integer fields read from a binary image** (`le/be_u16/u32/u64`,
returning 0 out of range). shellhist parses **line-oriented UTF-8 text**, not
packed binary structures — there are no integer field offsets to bounds-check;
the only numeric fields are ASCII-digit runs (`#<epoch>`, `: start:elapsed;`)
parsed via `str::parse` after an `is_ascii_digit` guard. So `safe-read` does not
apply here.

## Decision

1. **`#![forbid(unsafe_code)]`** in both crates (`core/src/lib.rs`,
   `forensic/src/lib.rs`) and `unsafe_code = "forbid"` in
   `[workspace.lints.rust]` (root `Cargo.toml`). No FFI, no C bindings, no `mmap`
   — there is no perf case for `unsafe` in line parsing, so the crate takes the
   strongest posture (`forbid`, not the `deny`+bounded-allow the mmap container
   readers use), and can honestly wear the "no unsafe" trust signal.
2. **Panic-free by lint**: `[workspace.lints.clippy]` denies `unwrap_used` and
   `expect_used` in production code; `correctness`/`suspicious` are `deny`;
   `all`/`pedantic` are `warn`. `clippy.toml` allows unwrap/expect only inside
   tests (`allow-unwrap-in-tests`).
3. **Lenient, lossy decoding**: every parser reads via
   `String::from_utf8_lossy(strip_bom(data))` (all four `core/src/*.rs`), so
   malformed or non-UTF-8 bytes degrade to replacement characters rather than
   erroring, and a leading BOM is stripped. A truncated or garbled file degrades
   to plain one-command-per-line, never a crash — the "degrade to plain lines"
   contract stated in the README.
4. **No `safe-read` dependency** — deliberately, because the format is text with
   no fixed-width integer fields; numeric parsing goes through digit-guarded
   `str::parse`, which cannot panic or overflow-index.
5. **Fuzzing** as the runtime partner to the static lints: five `cargo-fuzz`
   targets (`fuzz/fuzz_targets/{bash,zsh,fish,powershell}.rs` per parser, plus
   `forensic.rs` for the full parse→audit pipeline), with `fuzz.yml` building and
   smoke-running each. `cargo-fuzz` runs on nightly (commit d44eda0 — `+nightly`
   beats the `rust-toolchain.toml` pin).

## Consequences

- The crate presents a provable "zero places a crafted input can corrupt memory"
  surface (`rg unsafe` is empty), and an empirically fuzzed panic-free posture —
  the paired "fuzzed" (evidence) + "panic-free by lint" (static) claim the README
  is required to make.
- No `safe-read` line appears in `core/Cargo.toml`; a future change that adds
  binary-field parsing (e.g. a compiled history cache) would need to revisit this
  and route integer reads through `safe-read`.
- Lossy decoding means bytes are never rejected for encoding; the analyzer sees a
  best-effort text view, consistent with "surface what is there, never silently
  drop evidence."
