# 1. Two-crate reader/analyzer split: shellhist-core + shellhist-forensic

Date: 2026-07-24
Status: Accepted

## Context

The repository parses shell command-history files (bash, zsh, fish, PowerShell
PSReadLine) and grades the result for forensic anomalies. Two audiences want two
different things from the same bytes:

- A downstream tool (or a third party) that only needs *the parsed history* —
  a uniform, typed entry stream — with no opinion about what is suspicious.
- A forensic examiner (via `issen` or a future front-end) who needs *graded
  findings* — history clearing, timestamp regression, download-pipe-to-shell.

The SecurityRonin fleet standard (`ronin-issen/CLAUDE.md`, "Crate-structure
standard — reader/analyzer split") mandates that every format ship as a `core/`
reader crate and a `forensic/` analyzer crate in one workspace, so the raw
decode is reusable without pulling in the finding model, and the analyzer layer
carries the domain judgment.

## Decision

1. One workspace repo named `shellhist-forensic` (the analyzer is the headline)
   with two members (root `Cargo.toml` `members = ["core", "forensic"]`):
   - `core/` → crate **`shellhist-core`** — the reader. Decodes each format into
     a uniform `HistoryEntry` stream (`core/src/lib.rs`). No findings, no
     severity, no `forensicnomicon` dependency.
   - `forensic/` → crate **`shellhist-forensic`** — the auditor. Consumes
     `HistoryEntry` and emits `forensicnomicon::report::Finding` via the
     `HistAnomaly` type + `Observation` impl (`forensic/src/lib.rs`).
2. The bare stem `shellhist` is uncontested on crates.io, so the crates publish
   as `shellhist-core` / `shellhist-forensic` with their default import paths
   (`shellhist_core`, `shellhist_forensic`) — no `[lib] name` override was
   needed (no popular third-party `shellhist` to co-exist with).
3. `shellhist-forensic` depends **on `shellhist-core`** (`forensic/Cargo.toml`,
   `shellhist-core = { version = "0.1", path = "../core" }`). Unlike readers of
   binary container formats, a text history file exposes no lower-level slack or
   record structure the auditor must see beneath the reader's API — the parsed
   `HistoryEntry` stream (command text, timestamps, elapsed) carries everything
   the anomaly rules examine — so the default "forensic-over-core" dependency is
   the correct one here (the fleet's "may go lower" exception does not apply).

## Consequences

- A consumer that only wants parsed history links `shellhist-core` alone and
  never compiles the finding model.
- The analyzer keeps its typed `HistAnomaly` enum (domain knowledge) and
  converts to canonical `Finding`s in one place, per the fleet reporting model —
  `forensicnomicon` never enumerates every shell anomaly kind.
- Independent versioning: `shellhist-core` is at `0.1.0`, `shellhist-forensic`
  at `0.2.0` (their `Cargo.toml`s), released per-crate by release-plz with
  `<crate>-vX.Y.Z` tags.
- Following the standard leaves the door open to later `-carve` / `-integrity`
  siblings without restructuring, should recovery of overwritten history become
  in scope.
