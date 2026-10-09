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
# The GPL section-7b attribution must appear in --version (Appropriate Legal Notice).
check "version attribution" "nidhunt by Josip Parlov (parl0v)" "$CPU" --version

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
# Two-block: a >39-char name exercises the second SHA-1 block / padlen==128.
check "cpu two-block" "HIT XOUAK95mhQ0" \
    "$CPU" -t tests/targets_twoblock.txt -s tests/slot_twoblock.txt
# Scalar SHA-1 path (forced even on a SHA-NI CPU).
check "cpu scalar" "HIT GtuZGmN-tKw sceNpSessionSignalingCreateContext" \
    env NIDHUNT_NO_NI=1 "$CPU" -t tests/targets_selftest.txt -p sceNp -v tests/vocab_selftest.txt -d 4

echo "== input validation =="
# An empty slot must be rejected (not crash, not silently do nothing).
out="$("$CPU" -t tests/targets_selftest.txt -s tests/slot_selftest.txt -s tests/empty.txt 2>&1)"; rc=$?
if [ $rc -ne 0 ] && printf '%s' "$out" | grep -qF "no usable words"; then
    echo "ok   - empty slot rejected"; pass=$((pass+1))
else
    echo "FAIL - empty slot rejected (rc=$rc)"; echo "$out" | sed 's/^/       /'; fail=$((fail+1))
fi

if [ -x "$GPU" ]; then
    echo "== GPU recovery =="
    check "gpu combinator" "HIT GtuZGmN-tKw sceNpSessionSignalingCreateContext" \
        "$GPU" --backend gpu -t tests/targets_selftest.txt -p sceNp -v tests/vocab_selftest.txt -d 4
    check "gpu suffix" "HIT 23LRUSvYu1M sceAgcInit_0090" \
        "$GPU" --backend gpu -t tests/targets_suffix.txt -p sceAgc -s tests/vocab_suffix.txt -S tests/suffixes_suffix.txt
    check "gpu two-block" "HIT XOUAK95mhQ0" \
        "$GPU" --backend gpu -t tests/targets_twoblock.txt -s tests/slot_twoblock.txt
    echo "== CPU/GPU parity =="
    # Both backends must find the identical set of hits for the same search.
    pc="$("$CPU" -t tests/targets_parity.txt -p sceVideoOut -v tests/vocab_parity.txt -d 1 2>/dev/null | grep '^HIT' | sort)"
    pg="$("$GPU" --backend gpu -t tests/targets_parity.txt -p sceVideoOut -v tests/vocab_parity.txt -d 1 2>/dev/null | grep '^HIT' | sort)"
    if [ -n "$pc" ] && [ "$pc" = "$pg" ]; then
        echo "ok   - cpu/gpu parity"; pass=$((pass+1))
    else
        echo "FAIL - cpu/gpu parity"; printf 'CPU:\n%s\nGPU:\n%s\n' "$pc" "$pg" | sed 's/^/       /'; fail=$((fail+1))
    fi
else
    echo "(skip GPU tests: $GPU not built)"
fi

PY=""
for cand in python3 python py; do
    if command -v "$cand" >/dev/null 2>&1 && "$cand" -c "import sys" >/dev/null 2>&1; then PY="$cand"; break; fi
done
if [ -n "$PY" ]; then
    echo "== vocab.py =="
    check "vocab nid" "GtuZGmN-tKw" "$PY" tools/vocab.py nid sceNpSessionSignalingCreateContext
    check "vocab check" "OK GtuZGmN-tKw" "$PY" tools/vocab.py check sceNpSessionSignalingCreateContext GtuZGmN-tKw
    # Frequency-ranked vocab: most common word of the sample set is "Out".
    check "vocab rank" "Out" "$PY" tools/vocab.py words --symbols tests/symbols_sample.txt --prefix sce --rank
    # Per-position lists write files for grammar mode.
    out="$("$PY" tools/vocab.py positions --symbols tests/symbols_sample.txt --prefix sceVideoOut --out /tmp/nh_pos 2>&1)"
    if [ -s /tmp/nh_pos_1.txt ]; then
        echo "ok   - vocab positions"; pass=$((pass+1))
    else
        echo "FAIL - vocab positions"; echo "$out" | sed 's/^/       /'; fail=$((fail+1))
    fi
else
    echo "(skip vocab.py tests: no python)"
fi

echo "== $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
