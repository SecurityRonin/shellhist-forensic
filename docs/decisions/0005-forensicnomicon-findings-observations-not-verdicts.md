# 5. Emit `forensicnomicon::report::Finding`s as hedged observations, never verdicts

Date: 2026-07-24
Status: Accepted

## Context

The fleet has one normalized reporting vocabulary — `forensicnomicon::report`
(`Severity`, `Category`, `Observation`, `Finding`, `Source`) — so every analyzer
emits the same model and ORCHESTRATION (`issen`) renders findings uniformly
instead of N bespoke `XxxAnalysis` types (`ronin-issen/CLAUDE.md`, "The Reporting
Model"). Shell-history anomalies must therefore surface as `Finding`s, not a
custom result type. Separately, the fleet epistemology bars an analyzer from
stating legal conclusions: a finding is an *observation* ("consistent with …"),
and MITRE techniques are narrated as consistency, never as a verdict.

## Decision

1. **Keep a typed `HistAnomaly` enum** (`forensic/src/lib.rs`) carrying the
   domain knowledge — `HistoryDisabled`, `TimestampRegression`, `RemoteExecPipe`,
   `PwshEncodedCommand` — and convert to canonical `Finding`s via
   `impl Observation for HistAnomaly` (the producer pattern the fleet mandates;
   `forensicnomicon` never enumerates every shell anomaly kind).
2. **Published, stable anomaly codes** as scheme-prefixed SCREAMING-KEBAB:
   `SHELLHIST-HISTORY-DISABLED`, `SHELLHIST-TIMESTAMP-REGRESSION`,
   `SHELLHIST-REMOTE-EXEC-PIPE`, `SHELLHIST-PWSH-ENCODED-CMD` (`HistAnomaly::code`).
   These are a contract — never mutated; new variants get new codes.
3. **Category per anomaly** maps to the analytical lens: `Concealment`
   (history disabling), `Integrity` (timestamp regression), `Threat`
   (download-pipe, encoded PowerShell) — see the `category()` impl.
4. **Severity is graded, not `None`.** Every current anomaly is `Some(Medium)`
   (`severity()` impl) — these are scored observations, not "cannot grade in
   isolation" cases.
5. **Observations, not conclusions.** Notes and MITRE references
   (T1070.003, T1059/T1105, T1059.001/T1027) are phrased "consistent with …";
   the examiner draws the conclusion. A unit test guards this:
   `findings_are_hedged_observations_never_verdicts`.
6. **Convenience entry points**: `audit(&entries) -> Vec<HistAnomaly>` for the
   typed stream, `audit_findings(&entries, scope) -> Vec<Finding>` for the
   one-call graded output, and `source(scope)` to stamp analyzer provenance.

## Consequences

- Shell-history findings aggregate into one `forensicnomicon::report::Report`
  alongside NTFS, registry, EVTX, browser, etc., with no bespoke glue in `issen`.
- The published codes let downstream tooling and rules match on stable
  identifiers; changing one would be a breaking contract change.
- The hedged wording keeps the crate on the right side of the expert-witness
  epistemic layers — it reports what the pattern is consistent with, never that a
  crime or intent is proven.
- A coverage caveat is documented rather than emitted as a negative finding:
  PSReadLine refuses to persist credential-bearing lines
  (`core/src/powershell.rs` header), so the *absence* of such a command is not
  evidence it was never run — the analyzer never asserts a negative.
