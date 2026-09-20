#!/usr/bin/env bash
set -euo pipefail

target="${1:-./authtrace}"
case_count=0
failures=0
test_dir="$(mktemp -d)"
trap 'rm -rf -- "$test_dir"' EXIT

pass() {
    case_count=$((case_count + 1))
    printf 'PASS: %s\n' "$1"
}

fail() {
    case_count=$((case_count + 1))
    failures=$((failures + 1))
    printf 'FAIL: %s\n' "$1"
    if [[ -n "${2:-}" ]]; then
        printf '  %s\n' "$2"
    fi
}

capture() {
    set +e
    "$target" "$@" >"$test_dir/stdout" 2>"$test_dir/stderr"
    status=$?
    set -e
}

expect_exact() {
    local name="$1"
    local expected_status="$2"
    local expected_stdout="$3"
    local expected_stderr="$4"
    shift 4

    capture "$@"
    printf '%b' "$expected_stdout" >"$test_dir/expected_stdout"
    printf '%b' "$expected_stderr" >"$test_dir/expected_stderr"

    if [[ "$status" -eq "$expected_status" ]] \
        && cmp -s "$test_dir/stdout" "$test_dir/expected_stdout" \
        && cmp -s "$test_dir/stderr" "$test_dir/expected_stderr"; then
        pass "$name"
    else
        fail "$name" "expected status $expected_status, received $status"
        sed 's/^/    stdout: /' "$test_dir/stdout"
        sed 's/^/    stderr: /' "$test_dir/stderr"
    fi
}

expect_line() {
    local line="$1"
    grep -Fxq -- "$line" "$test_dir/stdout"
}

expect_exact \
    "no arguments" \
    2 \
    "" \
    "Usage: authtrace [--threshold N] <auth-log-file>\n"

expect_exact \
    "too many arguments" \
    2 \
    "" \
    "Usage: authtrace [--threshold N] <auth-log-file>\n" \
    tests/fixtures/sample_auth.log extra

expect_exact \
    "invalid zero threshold" \
    2 \
    "" \
    "Usage: authtrace [--threshold N] <auth-log-file>\n" \
    --threshold 0 tests/fixtures/sample_auth.log

expect_exact \
    "invalid text threshold" \
    2 \
    "" \
    "Usage: authtrace [--threshold N] <auth-log-file>\n" \
    --threshold nope tests/fixtures/sample_auth.log

expect_exact \
    "version option" \
    0 \
    "AuthTrace64 v1.0.0\n" \
    "" \
    --version

capture --help
if [[ "$status" -eq 0 ]] \
    && grep -Fq 'Usage: authtrace' "$test_dir/stdout" \
    && grep -Fq -- '--threshold N' "$test_dir/stdout" \
    && [[ ! -s "$test_dir/stderr" ]]; then
    pass "help option"
else
    fail "help option" "help output or status is incorrect"
fi

expect_exact \
    "missing input file" \
    3 \
    "" \
    "authtrace: unable to open input file\n" \
    tests/fixtures/does-not-exist.log

expect_exact \
    "directory rejected" \
    6 \
    "" \
    "authtrace: input must be a regular file\n" \
    tests/fixtures

: >"$test_dir/empty.log"
capture "$test_dir/empty.log"
if [[ "$status" -eq 0 ]] \
    && expect_line '  Lines processed: 0' \
    && expect_line '  Authentication events: 0' \
    && expect_line '  Unique sources: 0' \
    && [[ ! -s "$test_dir/stderr" ]]; then
    pass "empty file"
else
    fail "empty file" "empty-file summary is incorrect"
fi

capture --threshold 2 tests/fixtures/mixed_auth.log
if [[ "$status" -eq 0 ]] \
    && expect_line 'AuthTrace64 v1.0.0' \
    && expect_line 'Suspicious threshold: 2 failed attempts' \
    && expect_line '  Lines processed: 8' \
    && expect_line '  Authentication events: 6' \
    && expect_line '  Accepted: 2' \
    && expect_line '  Failed: 4' \
    && expect_line '  Invalid-user failures: 1' \
    && expect_line '  Ignored lines: 1' \
    && expect_line '  Malformed/overlong lines: 1' \
    && expect_line '  Unique sources: 3' \
    && expect_line '  Unique users: 4' \
    && [[ "$(grep -Fxc '  203.0.113.42 failed=2 accepted=0' "$test_dir/stdout")" -eq 2 ]] \
    && [[ "$(grep -Fxc '  192.0.2.55 failed=2 accepted=1' "$test_dir/stdout")" -eq 2 ]] \
    && [[ "$(grep -Fxc '  198.51.100.10 failed=0 accepted=1' "$test_dir/stdout")" -eq 1 ]] \
    && [[ ! -s "$test_dir/stderr" ]]; then
    pass "mixed OpenSSH analysis"
else
    fail "mixed OpenSSH analysis" "summary, aggregation, or suspicious reporting is incorrect"
    sed 's/^/    /' "$test_dir/stdout"
fi

{
    printf '%5000s\n' '' | tr ' ' x
    printf '%s\n' 'Sep 20 01:00:00 host sshd[2000]: Failed password for boundary from 2001:db8::1 port 22 ssh2'
} >"$test_dir/boundary.log"
capture "$test_dir/boundary.log"
if [[ "$status" -eq 0 ]] \
    && expect_line '  Lines processed: 2' \
    && expect_line '  Authentication events: 1' \
    && expect_line '  Ignored lines: 1' \
    && grep -Fq '2001:db8::1 failed=1 accepted=0' "$test_dir/stdout"; then
    pass "buffer-boundary and IPv6 handling"
else
    fail "buffer-boundary and IPv6 handling" "a line spanning read buffers was not handled correctly"
fi

{
    printf '%9000s\n' '' | tr ' ' x
    printf '%s' 'Sep 20 01:00:01 host sshd[2001]: Accepted password for finaluser from 198.51.100.77 port 22 ssh2'
} >"$test_dir/overlong.log"
capture "$test_dir/overlong.log"
if [[ "$status" -eq 0 ]] \
    && expect_line '  Lines processed: 2' \
    && expect_line '  Authentication events: 1' \
    && expect_line '  Malformed/overlong lines: 1' \
    && grep -Fq '198.51.100.77 failed=0 accepted=1' "$test_dir/stdout"; then
    pass "overlong line and final unterminated line"
else
    fail "overlong line and final unterminated line" "overlong or EOF line handling is incorrect"
fi

large_file="$test_dir/large.log"
: >"$large_file"
for ((i = 0; i < 2000; i++)); do
    printf 'Sep 20 01:00:02 host sshd[%d]: Failed password for loadtest from 203.0.113.99 port 22 ssh2\n' "$i" >>"$large_file"
done
capture --threshold 2000 "$large_file"
if [[ "$status" -eq 0 ]] \
    && expect_line '  Lines processed: 2000' \
    && expect_line '  Authentication events: 2000' \
    && expect_line '  Failed: 2000' \
    && [[ "$(grep -Fxc '  203.0.113.99 failed=2000 accepted=0' "$test_dir/stdout")" -eq 2 ]]; then
    pass "large streaming input"
else
    fail "large streaming input" "large-file counts are incorrect"
fi

set +e
"$target" tests/fixtures/sample_auth.log > /dev/full 2>"$test_dir/stderr"
status=$?
set -e
if [[ "$status" -eq 1 ]]; then
    pass "output write failure"
else
    fail "output write failure" "expected status 1, received $status"
fi

if [[ "$failures" -ne 0 ]]; then
    printf 'FAIL: %s of %s tests failed\n' "$failures" "$case_count"
    exit 1
fi

printf 'PASS: all %s tests passed\n' "$case_count"
