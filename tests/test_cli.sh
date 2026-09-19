#!/usr/bin/env bash
set -euo pipefail

target="${1:-./authtrace}"
case_count=0
failures=0
test_dir="$(mktemp -d)"
trap 'rm -rf -- "$test_dir"' EXIT

run_case() {
    local name="$1"
    local expected_status="$2"
    local expected_stdout="$3"
    local expected_stderr="$4"
    shift 4

    case_count=$((case_count + 1))

    set +e
    "$target" "$@" >"$test_dir/stdout" 2>"$test_dir/stderr"
    local actual_status=$?
    set -e

    printf '%b' "$expected_stdout" >"$test_dir/expected_stdout"
    printf '%b' "$expected_stderr" >"$test_dir/expected_stderr"

    if [[ "$actual_status" -eq "$expected_status" ]] \
        && cmp -s "$test_dir/stdout" "$test_dir/expected_stdout" \
        && cmp -s "$test_dir/stderr" "$test_dir/expected_stderr"; then
        printf 'PASS: %s\n' "$name"
        return
    fi

    printf 'FAIL: %s\n' "$name"
    printf '  expected status: %s; actual status: %s\n' \
        "$expected_status" "$actual_status"
    printf '  actual stdout:\n'
    sed 's/^/    /' "$test_dir/stdout"
    printf '  actual stderr:\n'
    sed 's/^/    /' "$test_dir/stderr"
    failures=$((failures + 1))
}

run_case \
    "no arguments" \
    2 \
    "" \
    "Usage: authtrace <auth-log-file>\n"

run_case \
    "too many arguments" \
    2 \
    "" \
    "Usage: authtrace <auth-log-file>\n" \
    tests/fixtures/sample_auth.log extra

run_case \
    "missing input file" \
    3 \
    "" \
    "authtrace: unable to open input file\n" \
    tests/fixtures/does-not-exist.log

run_case \
    "valid input file" \
    0 \
    "AuthTrace64 v0.2\nInput file opened and closed successfully.\n" \
    "" \
    tests/fixtures/sample_auth.log

if [[ "$failures" -ne 0 ]]; then
    printf 'FAIL: %s of %s tests failed\n' "$failures" "$case_count"
    exit 1
fi

printf 'PASS: all %s tests passed\n' "$case_count"
