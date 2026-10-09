#!/usr/bin/env bash
# Smoke tests for nidhunt. Run after building:  ./tests/run_tests.sh
# Exercises the CPU backend (and the GPU backend if nidhunt-gpu was built).
set -uo pipefail
cd "$(dirname "$0")/.."

EXE=""; case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) EXE=".exe";; esac
CPU="./nidhunt${EXE}"
GPU="./nidhunt-gpu${EXE}"
[ -x "$CPU" ] || { echo "build first: $CPU not found"; exit 1; }

pass=0; fail=0
check() {  # check <name> <expected-substring> <command...>
    local name="$1" want="$2"; shift 2
    local out; out="$("$@" 2>&1)"
    if printf '%s' "$out" | grep -qF "$want"; then
        echo "ok   - $name"; pass=$((pass+1))
    else
        echo "FAIL - $name (wanted: $want)"; echo "$out" | sed 's/^/       /'; fail=$((fail+1))
    fi
}

echo "== self-test =="
check "self-test" "self-test OK" "$CPU" --self-test

echo "== CPU recovery =="
# Combinator: reconstruct sceNpSessionSignalingCreateContext from word pieces.
check "cpu combinator" "HIT GtuZGmN-tKw sceNpSessionSignalingCreateContext" \
    "$CPU" -t tests/targets_selftest.txt -p sceNp -v tests/vocab_selftest.txt -d 4
# Grammar: single slot holding whole candidate names.
check "cpu grammar" "HIT GtuZGmN-tKw sceNpSessionSignalingCreateContext" \
    "$CPU" -t tests/targets_selftest.txt -s tests/slot_selftest.txt
# Suffix: recover a real suffixed name (prefix + word slot + suffix slot).
check "cpu suffix" "HIT 23LRUSvYu1M sceAgcInit_0090" \
    "$CPU" -t tests/targets_suffix.txt -p sceAgc -s tests/vocab_suffix.txt -S tests/suffixes_suffix.txt

if [ -x "$GPU" ]; then
    echo "== GPU recovery =="
    check "gpu combinator" "HIT GtuZGmN-tKw sceNpSessionSignalingCreateContext" \
        "$GPU" --backend gpu -t tests/targets_selftest.txt -p sceNp -v tests/vocab_selftest.txt -d 4
    check "gpu suffix" "HIT 23LRUSvYu1M sceAgcInit_0090" \
        "$GPU" --backend gpu -t tests/targets_suffix.txt -p sceAgc -s tests/vocab_suffix.txt -S tests/suffixes_suffix.txt
else
    echo "(skip GPU tests: $GPU not built)"
fi

echo "== $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
