# AuthTrace64

AuthTrace64 is an x86-64 NASM Linux command-line project designed to analyze
OpenSSH authentication logs using bounded-memory streaming I/O.

> Current status: v0.2 input validation and file-opening milestone.
> Log reading and analysis are not implemented yet.

## Problem

Linux authentication logs can be large and time-consuming to inspect manually.
AuthTrace64 aims to summarize authentication activity and identify suspicious
sources without loading the entire log file into memory.

## Intended Users

- Linux administrators
- Cybersecurity students
- Developers learning systems programming
- Users investigating OpenSSH authentication activity

## Current Milestone

Version 0.2 provides:

- an x86-64 NASM executable;
- exact command-line argument validation;
- read-only file opening with the Linux `openat` system call;
- safe file closing;
- separate standard output and error output;
- distinct process exit statuses;
- partial-write and interrupted-write handling;
- a repeatable Make-based build; and
- four automated CLI and file-validation tests.

## Requirements

- Linux x86-64 or Ubuntu on WSL 2
- NASM
- GNU `ld` from Binutils
- GNU Make
- Bash for the automated tests

## Build

    make

## Run

Using Make:

    make run LOG=tests/fixtures/sample_auth.log

Or run the executable directly:

    ./authtrace tests/fixtures/sample_auth.log

Expected output:

    AuthTrace64 v0.2
    Input file opened and closed successfully.

## Exit Statuses

| Status | Meaning |
|---:|---|
| `0` | Success |
| `1` | Output write failure |
| `2` | Invalid command-line usage |
| `3` | Input file could not be opened |
| `4` | Input file could not be closed |

## Test

    make test

Expected final result:

    PASS: all 4 tests passed

## Clean

    make clean

## Roadmap

Future milestones will add:

- regular-file validation;
- bounded-memory file streaming;
- line-boundary handling across input buffers;
- OpenSSH event parsing;
- authentication-event aggregation;
- suspicious-source reporting;
- large-file and malformed-input tests;
- continuous integration; and
- a final v1.0 release.

## License

This project is licensed under the MIT License. See `LICENSE`.
