#!/usr/bin/env bash
# Sums the "Skipped: N" counts across every per-TFM summary line in a
# `dotnet test` console log and prints a single integer.
#
# Exit 2 (with an ::error::) if the log contains NO summary lines at all —
# a missing summary must never read as "0 skips" to a PQ-required lane, or a
# console-format change would silently turn the zero-skip gate into a no-op.
# Each CI lane keeps its own policy (fail vs. notice) on the printed number;
# this script only owns the fragile log-parsing, in exactly one place.
set -euo pipefail

log="${1:?usage: count-skipped-tests.sh <test-output.log>}"

if ! grep -qE '^(Passed!|Failed!)' "$log"; then
  echo "::error::No 'Passed!/Failed!' summary lines found in $log — did the test run produce a summary? (console logger format change?)" >&2
  exit 2
fi

grep -E '^(Passed!|Failed!)' "$log" \
  | grep -oE 'Skipped:[[:space:]]*[0-9]+' \
  | grep -oE '[0-9]+' \
  | awk '{s+=$1} END {print s+0}'
