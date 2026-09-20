# AuthTrace64 Architecture

AuthTrace64 is a dependency-free Linux x86-64 program written in NASM. It uses
Linux system calls directly and does not link against libc.

## Data flow

1. Validate CLI arguments and the suspicious-source threshold.
2. Open the input with `openat` and validate it with `fstat`.
3. Read 4 KiB chunks with `read`.
4. Reconstruct lines in a fixed 8 KiB line buffer.
5. Parse supported OpenSSH accepted and failed authentication messages.
6. Aggregate usernames and source addresses in fixed-capacity hash tables.
7. Print the summary, activity tables, and suspicious-source report.
8. Close the file and return a documented process status.

## Bounded-memory guarantees

Memory use does not grow with the input file. The executable reserves:

- one 4 KiB input buffer;
- one 8 KiB line buffer;
- 1,024 source entries;
- 1,024 username entries; and
- small fixed buffers for `stat` data and number formatting.

Each table entry stores a key of at most 63 bytes and two 64-bit counters. If
either table reaches 1,024 distinct keys, AuthTrace64 exits with status `7`
instead of allocating more memory or silently losing data.

Lines longer than 8 KiB are counted as malformed and skipped through their next
newline. A final line without a newline is still processed.

## Supported events

The parser recognizes OpenSSH `sshd[PID]` messages containing:

- `Accepted <method> for <user> from <source>`; and
- `Failed <method> for [invalid user] <user> from <source>`.

The authentication method is intentionally treated generically, so password,
public-key, keyboard-interactive, and future method labels use the same path.
IPv4 and IPv6 source tokens are supported.

Unrelated lines are counted as ignored. Lines that begin like supported events
but omit required fields are counted as malformed.

## Suspicious-source rule

A source is suspicious when its failed-event count is greater than or equal to
the configured threshold. The default threshold is `5`; `--threshold N` or
`-t N` changes it for one run.

This rule is deliberately transparent. It is a reporting signal, not proof that
a source is malicious.
