#!/usr/bin/env bash
# Build the ASan+UBSan persistent fuzz worker against system zlib.
# Output: artifacts/fuzz/build/fuzz_worker
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/artifacts/fuzz/build"
mkdir -p "$OUT"

CC="${CC:-gcc}"

SAN_FLAGS=(
    -O1 -g1
    -fsanitize=address,undefined
    -fno-sanitize=vptr
    -fno-omit-frame-pointer
    -fno-sanitize-recover=all
    -D_GNU_SOURCE -DSPNGT_HAVE_FMEMOPEN=1
)

# spng itself
"$CC" "${SAN_FLAGS[@]}" -I"$ROOT/spng" -c "$ROOT/spng/spng.c" -o "$OUT/spng.o"

# harness (the repo's libFuzzer target) + persistent worker driver
"$CC" "${SAN_FLAGS[@]}" -I"$ROOT/spng" -c "$ROOT/tests/spng_read_fuzzer.c" -o "$OUT/harness.o"
"$CC" "${SAN_FLAGS[@]}" -c "$ROOT/fuzz/worker_main.c" -o "$OUT/worker_main.o"

"$CC" "${SAN_FLAGS[@]}" "$OUT/worker_main.o" "$OUT/harness.o" "$OUT/spng.o" \
    -lz -lm -o "$OUT/fuzz_worker"

echo "built $OUT/fuzz_worker"
"$OUT/fuzz_worker" --help 2>/dev/null || true
