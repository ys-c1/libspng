#!/usr/bin/env bash
# Build a DEFECT-INJECTED variant for pipeline validation ONLY.
#
# The real spng/spng.c is never modified. A copy is made under
# artifacts/fuzz/injected/ and historical-style defects are patched into
# the copy, then compiled with ASan+UBSan. The resulting worker proves the
# full crash pipeline (capture -> stack -> minimize -> classify -> replay)
# works against genuine memory-safety faults.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IDIR="$ROOT/artifacts/fuzz/injected"
mkdir -p "$IDIR"

cp "$ROOT/spng/spng.c" "$IDIR/spng_injected.c"
cp "$ROOT/spng/spng.h" "$IDIR/spng.h"

python3 - "$IDIR/spng_injected.c" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
orig = s

# === Defect (PLTE chunk -> heap out-of-bounds read) ======================
# Two changes reproduce a classic historical libspng-class bug:
# 1. drop palette-count vs bit-depth validation
a = ("    if(ihdr->color_type == SPNG_COLOR_TYPE_INDEXED)\n    {\n"
     "        if(plte->n_entries > (1U << ihdr->bit_depth)) return 1;\n    }")
assert a in s, "check_plte anchor not found"
s = s.replace(a,
    "    if(ihdr->color_type == SPNG_COLOR_TYPE_INDEXED)\n    {\n"
    "        /* [INJ_PLTE] count vs bit-depth check removed */\n    }", 1)

# 2. tight heap LUT in expand_row. On x86 the SPNG_ARM block is compiled
#    out, so the function has a single closing brace to free against.
b = "    const struct spng_plte_entry *plte = decode_plte->rgba;\n"
assert b in s, "expand_row plte anchor not found"
s = s.replace(b, b +
    "    /* [INJ_PLTE] heap LUT deliberately sized to 4 entries */\n"
    "    struct spng_plte_entry *inj_lut = (struct spng_plte_entry *)"
    "malloc(4 * sizeof(struct spng_plte_entry));\n"
    "    for(unsigned inj_i = 0; inj_i < 4; inj_i++) "
    "inj_lut[inj_i] = decode_plte->rgba[inj_i];\n"
    "    plte = inj_lut;\n", 1)

# single function exit on x86: free before the closing brace
tail = ("            px[2] = plte[entry].blue;\n"
        "        }\n    }\n}\n")
assert tail in s, "expand_row tail anchor not found"
s = s.replace(tail,
    "            px[2] = plte[entry].blue;\n"
    "        }\n    }\n"
    "    free(inj_lut); /* [INJ_PLTE] */\n}\n", 1)

assert s != orig
assert "[INJ_PLTE]" in s
open(p, "w").write(s)
print("injected PLTE heap-OOB defect into", p)
PY

SAN_FLAGS=(
    -O1 -g1
    -fsanitize=address,undefined
    -fno-sanitize=vptr
    -fno-omit-frame-pointer
    -fno-sanitize-recover=all
    -DSPNG_INJECTED_VARIANT=1
    -D_GNU_SOURCE -DSPNGT_HAVE_FMEMOPEN=1
)

gcc "${SAN_FLAGS[@]}" -I"$IDIR" -c "$IDIR/spng_injected.c" -o "$IDIR/spng_inj.o"
gcc "${SAN_FLAGS[@]}" -I"$IDIR" -c "$ROOT/tests/spng_read_fuzzer.c" -o "$IDIR/harness_inj.o"
gcc "${SAN_FLAGS[@]}" -c "$ROOT/fuzz/worker_main.c" -o "$IDIR/worker_main_inj.o"
gcc "${SAN_FLAGS[@]}" "$IDIR/worker_main_inj.o" "$IDIR/harness_inj.o" \
    "$IDIR/spng_inj.o" -lz -lm -o "$IDIR/fuzz_worker_injected"

echo "built $IDIR/fuzz_worker_injected"
