#!/usr/bin/env bash
# Build the encoder sweep against the in-tree spng.c (system zlib, which the
# project already depends on — no new third-party code, no network access)
# and run it once. All samples are synthesized by the binary itself.
set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(cd ../.. && pwd)"
OUT="${ROOT}/artifacts/bench"
mkdir -p "$OUT"

cc -std=c99 -O2 -Wall -Wextra -I"${ROOT}/spng" \
   encode_sweep.c "${ROOT}/spng/spng.c" -lz -lm -o "$OUT/encode_sweep"

"$OUT/encode_sweep" | tee "$OUT/sweep_results.txt"
