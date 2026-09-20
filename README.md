# AuthTrace64

AuthTrace64 is a dependency-free x86-64 NASM Linux command-line analyzer for
OpenSSH authentication logs. It streams large files with bounded memory,
aggregates authentication activity, and reports sources that exceed a
configurable failed-login threshold.

> Current status: v1.0.0 release candidate. The implementation is complete and
> must pass final testing before a GitHub release is published.

## Features

- Linux x86-64 executable using system calls directly;
- 4 KiB streaming reads without loading the complete log into memory;
- line reconstruction across read-buffer boundaries;
- safe handling of unterminated and overlong input lines;
- regular-file validation with `fstat`;
- parsing of accepted and failed OpenSSH `sshd` events;
- generic authentication-method support;
- IPv4 and IPv6 source support;
- failed and accepted counts by source and username;
- invalid-user failure totals;
- configurable suspicious-source threshold;
- fixed-capacity hash tables with explicit overflow failure;
- robust partial-write and interrupted-system-call handling;
- distinct documented exit statuses;
- automated CLI, parsing, boundary, large-file, and failure tests; and
- GitHub Actions continuous integration.

## Requirements

- Linux x86-64 or Ubuntu on WSL 2
- NASM
- GNU `ld` from Binutils
- GNU Make
- Bash and standard GNU utilities for tests

## Build

    make

## Run

Analyze a log with the default suspicious threshold of five failures:

    ./authtrace /var/log/auth.log

Use a custom threshold:

    ./authtrace --threshold 3 /var/log/auth.log

Using Make:

    make run LOG=tests/fixtures/mixed_auth.log

Other commands:

    ./authtrace --help
    ./authtrace --version

Reading `/var/log/auth.log` may require appropriate system permissions. Do not
run AuthTrace64 with more privilege than necessary.

## Output

The report contains:

- total, ignored, malformed, and overlong line counts;
- accepted, failed, and invalid-user authentication counts;
- unique source and username counts;
- per-source and per-user accepted/failed totals; and
- sources whose failure count meets the configured threshold.

The activity tables use deterministic hash-table order rather than ranking.
Treat the suspicious-source section as an investigation signal, not proof of
malicious behavior.

## Supported OpenSSH Events

AuthTrace64 recognizes `sshd[PID]` records shaped like:

    Accepted <method> for <user> from <source>
    Failed <method> for <user> from <source>
    Failed <method> for invalid user <user> from <source>

Unrelated records are counted as ignored. Recognizable authentication records
with missing or invalid required fields are counted as malformed.

## Bounded-Memory Limits

- Input read buffer: 4 KiB
- Maximum line length: 8 KiB
- Maximum stored source length: 63 bytes
- Maximum stored username length: 63 bytes
- Maximum distinct sources: 1,024
- Maximum distinct usernames: 1,024

Exceeding a table capacity returns exit status `7`. Exceeding the line limit
counts the line as malformed and safely skips the rest of that line.

## Exit Statuses

| Status | Meaning |
|---:|---|
| `0` | Analysis completed successfully |
| `1` | Output write failure |
| `2` | Invalid command-line usage or threshold |
| `3` | Input file could not be opened |
| `4` | Input file could not be closed |
| `5` | Input file could not be read |
| `6` | Input is not a regular file or could not be validated |
| `7` | Source or username aggregation capacity was exceeded |

## Test

    make test

The suite tests CLI validation, help/version output, missing and non-regular
inputs, empty input, OpenSSH parsing, aggregation, thresholds, IPv6, read-buffer
boundaries, overlong lines, unterminated final lines, large streaming input, and
output failure handling.

## Release Build

Create a stripped executable and SHA-256 checksum:

    make release

Generated files:

    authtrace
    authtrace.sha256

## Clean

    make clean

## Architecture

See `docs/architecture.md` for the data flow, parser scope, memory model, and
suspicious-source rule.

## Limitations

- Linux x86-64 only;
- recognizes OpenSSH text logs, not binary journal files directly;
- stores at most 1,024 distinct sources and 1,024 distinct usernames per run;
- skips lines longer than 8 KiB; and
- does not perform IP reputation lookups or claim that a flagged source is
  malicious.

## License

This project is licensed under the MIT License. See `LICENSE`.
