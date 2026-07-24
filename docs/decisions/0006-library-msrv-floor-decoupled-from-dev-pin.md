# 6. Library MSRV floor decoupled from the pinned dev toolchain

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy (`ronin-issen/CLAUDE.md`; `CLAUDE.core.md`, "Rust MSRV &
Toolchain Policy") separates two versions: the **dev toolchain** (what the fleet
builds/fmt/clippy with, pinned fleet-wide to the current stable) from the
**declared MSRV** (`rust-version`, a downstream-facing compatibility promise).
Published libraries keep a **low, CI-verified MSRV** so they stay reusable by
third parties, and raise it only when a newer-Rust feature is genuinely needed —
never merely to match the dev pin. Both `shellhist-core` and `shellhist-forensic`
are published libraries, so they take the library treatment, not the app one.

## Decision

1. **Declared MSRV `rust-version = "1.81"`** in `[workspace.package]` (root
   `Cargo.toml`), inherited by both members — a deliberate low floor, decoupled
   from the dev pin, that both crates promise to build under.
2. **Dev toolchain pinned to `1.96.0`** in `rust-toolchain.toml` (with
   `rustfmt` + `clippy` components declared in the toml, per the fleet
   single-source-of-truth rule; commit 20a7c41). This is what contributors and CI
   build with; it does not change the promise in `rust-version`.
3. The gap between the `1.81` floor and the `1.96.0` pin is intentional: raising
   `rust-version` to `1.96.0` would narrow the crates' crates.io audience for no
   benefit.

## Consequences

- Third parties on Rust `1.81`+ can depend on `shellhist-core` /
  `shellhist-forensic`; the low floor is a compatibility feature to keep
  CI-verified, not to discard.
- Bumping the dev pin fleet-wide does not silently raise the libraries' promise;
  raising `rust-version` remains a deliberate, near-breaking change requiring a
  real reason.
- Rationale for the *exact* `1.81` choice (versus the fleet's usual `1.75`/`1.80`
  library floors) is reconstructed from structure; the original intent — likely
  the minimum that satisfies the `forensicnomicon = "1"` dependency and the
  edition-2021 feature set the parsers use — was not recovered in available
  history (the single feature commit 0e6fbd2 records no justification). It should
  be re-verified (and lowered toward `1.80` if the dependency graph allows)
  rather than treated as load-bearing.
