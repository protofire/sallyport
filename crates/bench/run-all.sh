#!/usr/bin/env bash
# Runs every measurement (one process per row so /usr/bin/time -l gives a per-row peak RSS) and
# appends TSV-ish lines to $1 (default evidence/bench/bench-results.log). Sequential on purpose: timings are
# wall-clock on an otherwise idle machine. Usage: crates/bench/run-all.sh [log] [full|quick]
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$ROOT"
LOG="${1:-evidence/bench/bench-results.log}"; SET="${2:-full}"
BIN=target/release/bench
run() { # extra env is passed through the environment; args = bench args
  local t; t=$(mktemp)
  /usr/bin/time -l "$BIN" "$@" >"$t.out" 2>"$t.err"
  local rss wall; rss=$(awk '/maximum resident/{print $1}' "$t.err"); wall=$(awk '/ real /{print $1}' "$t.err")
  grep -h RESULT "$t.out" | sed "s|\$| maxrss_bytes=$rss proc_wall_s=$wall threads=${RAYON_NUM_THREADS:-all} cmd=\"$*\"|" >>"$LOG"
  grep -q RESULT "$t.out" || { echo "FAILED: $* (see $t.err)" >>"$LOG"; tail -5 "$t.err" >>"$LOG"; }
  rm -f "$t" "$t.out"
}
for mode in composite succinct; do
  for s in 0 1 2 3; do run claim --mode $mode --step $s; done
  for s in 0 1 2; do run claim-inline --mode $mode --step $s; done
  for a in attest-slot attest-erc20 attest-erc20-compact attest-eth; do run $a --mode $mode; done
  for a in update-finality update-learn update-k170; do run $a --mode $mode; done
done
# constrained laptop profile: 4 threads, smaller segments (less RAM)
for po2 in 18 16; do
  RAYON_NUM_THREADS=4 run attest-erc20 --mode succinct --po2 $po2
  RAYON_NUM_THREADS=4 run attest-slot --mode succinct --po2 $po2
done
