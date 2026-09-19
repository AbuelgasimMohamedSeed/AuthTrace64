# AuthTrace64

AuthTrace64 is an x86-64 NASM Linux command-line project designed to analyze
OpenSSH authentication logs using bounded-memory streaming I/O.

> Current status: v0.1 repository foundation. Log analysis is not implemented yet.

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

Version 0.1 provides:

- a minimal x86-64 NASM executable;
- a repeatable Make-based build;
- an automated smoke test;
- failure checking for the `write` system call; and
- the initial project structure.

## Requirements

- Linux x86-64 or Ubuntu on WSL 2
- NASM
- GNU `ld` from Binutils
- GNU Make

## Build

```bash
make
```

## Run

```bash
make run
```

Expected output:

```text
AuthTrace64 v0.1
```

## Test

```bash
make test
```

Expected result:

```text
PASS: v0.1 smoke test
```

## Clean

```bash
make clean
```

## Roadmap

Future milestones will add:

- command-line argument validation;
- safe file opening and error reporting;
- bounded-memory streaming;
- line-boundary handling;
- OpenSSH event parsing;
- authentication-event aggregation;
- suspicious-source reporting; and
- a larger automated test suite.

## License

This project is licensed under the MIT License. See `LICENSE`.
