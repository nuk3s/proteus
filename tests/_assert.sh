#!/usr/bin/env bash
# tests/_assert.sh — sourced by *_test.sh for assertions and tracking.

PASS=0
FAIL=0

assert_eq() {
    local actual=$1 expected=$2 msg=${3:-eq}
    if [[ "$actual" == "$expected" ]]; then
        PASS=$((PASS+1))
        printf '  ✓ %s\n' "$msg"
    else
        FAIL=$((FAIL+1))
        printf '  ✗ %s\n      expected: %s\n      actual:   %s\n' "$msg" "$expected" "$actual"
    fi
}

# Pass if $1 numerically within ±$3 of $2.
assert_close() {
    local actual=$1 expected=$2 tol=$3 msg=${4:-close}
    local diff
    diff=$(awk -v a="$actual" -v e="$expected" 'BEGIN{d=a-e; if(d<0)d=-d; print d}')
    if awk -v d="$diff" -v t="$tol" 'BEGIN{exit !(d<=t)}'; then
        PASS=$((PASS+1))
        printf '  ✓ %s\n' "$msg"
    else
        FAIL=$((FAIL+1))
        printf '  ✗ %s\n      expected: %s ±%s\n      actual:   %s\n' "$msg" "$expected" "$tol" "$actual"
    fi
}

summary() {
    echo "  $PASS passed, $FAIL failed"
    return $(( FAIL > 0 ? 1 : 0 ))
}
