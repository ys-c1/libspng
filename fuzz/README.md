# Structured, chunk-aware PNG fuzzing harness for libspng

A deterministic fuzzing driver that mutates PNGs at the **chunk structure**
level (lengths, CRCs, zlib/deflate streams, filter types, IHDR fields and
chunk topology), drives the ASan+UBSan-instrumented decoder through a
persistent worker, and captures/minimizes/classifies any crash.

## Layout

| File | Role |
|---|---|
| `worker_main.c` | Persistent sanitizer worker: length-prefixed stdin/stdout protocol, one process reused across inputs; a sanitizer fault aborts it and the controller respawns. |
| `build.sh` | Builds the worker against the **real, unmodified** `spng/spng.c` with GCC ASan+UBSan. |
| `build_injected.sh` | Builds a separate **defect-injected** validation worker (see below). The real source is copied and patched under `artifacts/`, never edited in place. |
| `rng.py` | Self-contained xoshiro256** PRNG — identical byte stream on every Python, so runs are reproducible from the integer seed alone. |
| `png_model.py` | Chunk-aware PNG model + the structured mutation catalog. Each mutation is a replayable record; `apply_mutation` is a pure function of `(model, record)`. |
| `worker.py` | Worker controller: crash detection, watchdog (with deterministic retry), ASan/UBSan report parsing, stack normalization, stable signatures. |
| `minimizer.py` | Four-stage crash minimization: record delta-debug → parameter weakening → structural/byte delta-debug → reconstructive synthesis. |
| `fuzz_driver.py` | CLI: `build-check`, `fuzz`, `repro`, `bench`. |
| `diagnose.py` | Reachability probe: histogram of decoder return codes to confirm mutations reach deep decode paths. |

## Mutation catalog

Grouped by the field family under test:

- **length** — `len_truncate`, `len_extend`, `len_zero`, `len_huge`,
  `len_swap_neighbor`, `plte_truncate`. The declared chunk-header length is
  decoupled from the in-memory payload (`Chunk.declared_len`) so a
  multi-gigabyte declared length costs no memory.
- **CRC** — `crc_flip`, `crc_zero`, `crc_other_chunk`.
- **zlib/deflate stream** — `idat_flip_byte`, `idat_truncate`,
  `idat_extend`, `idat_reflate_raw`, `idat_cross_splice`, `idat_drop`,
  `idat_adler_corrupt`, `idat_zlib_header`.
- **filter type** — `filter_byte` (one row), `filter_row_all` (every row),
  plus IHDR `ihdr_interlace`, `ihdr_compression_method`,
  `ihdr_filter_method`.
- **IHDR** — `ihdr_field` (width/height), `bit_depth`, `color_type`.
- **chunk topology / misc** — `chunk_delete`, `chunk_duplicate`,
  `chunk_insert`, `chunk_reorder`, `data_byte`, `data_field`,
  `trns_inject`.

The last four bytes of every worker input are the existing libFuzzer
harness control word (decode format, stream/progressive/file mode, flags),
drawn from a fixed table so coverage spans every decode entry point.

## Usage

```sh
# 1. build the real-library sanitizer worker
./fuzz/build.sh

# 2. smoke-test the seed corpus (must report zero unexpected crashes)
python3 -I fuzz/fuzz_driver.py build-check

# 3. run a campaign
python3 -I fuzz/fuzz_driver.py fuzz --seed 20261119 --iterations 100000 \
        --outdir artifacts/fuzz/run

# 4. replay a saved case
python3 -I fuzz/fuzz_driver.py repro --outdir artifacts/fuzz/run \
        artifacts/fuzz/run/crashes/<id>.json

# 5. throughput vs pure decode
python3 -I fuzz/fuzz_driver.py bench --iterations 20000
```

Outputs per run: `report.json` (stats, classes, per-crash records with
stack + triggering field), `crashes/<id>.bin` (minimal repro input,
PNG + 4-byte control suffix) and `crashes/<id>.json`.

## Determinism

Every random choice comes from the seeded xoshiro PRNG; mutation records
are pure and replayable. The crash signature is
`(sanitizer, address-scrubbed message, function-name call chain)` — it does
not contain PIDs, heap addresses, build paths or line numbers, so the same
bug gives the same signature across runs and decode formats. Watchdog
timeouts are retried on a fresh worker so transient scheduler stalls cannot
perturb the crash set.

## Why an injected build exists

The committed libspng (0.7.4) is mature and continuously fuzzed by OSS-Fuzz;
its bounds checks reject malformed inputs with error codes rather than
memory faults. A 100k structured campaign against the real library produces
**zero sanitizer crashes** (see results below), which means the capture →
minimize → classify → replay pipeline has no live fault to exercise.

`build_injected.sh` therefore builds a separate worker in which a copy of
`spng.c` has one classic historical bug class weakened — the palette
count-vs-bit-depth check is removed **and** `expand_row` reads through a
tight 4-entry heap LUT — so an out-of-range palette index becomes a real
heap out-of-bounds read that ASan/UBSan report. This build exists only to
prove the harness works end-to-end against genuine memory-safety faults; it
is selected explicitly via `SPNG_FUZZ_WORKER` and can never be produced by
the normal build:

```sh
./fuzz/build_injected.sh
SPNG_FUZZ_WORKER=$PWD/artifacts/fuzz/injected/fuzz_worker_injected \
    python3 -I fuzz/fuzz_driver.py fuzz --iterations 100000 \
        --outdir artifacts/fuzz/inj
```

## Measured results (this environment)

**Real, unmodified libspng 0.7.4** — 100,000 structured mutations
(seed `20261119`, 5,792 seeds incl. the OSS-Fuzz corpus):

- 0 sanitizer crashes, 0 hangs, ~4,400 inputs/s.
- Reachability probe: ~60% of mutations pass header validation and enter
  the decode path; thousands decode fully. The library rejects malformed
  inputs with error codes rather than faulting, as expected for an
  OSS-Fuzz-hardened codebase.

**Defect-injected validation build** — two independent 100,000-mutation runs
with the same seed:

- 329 crashes each, 0 hangs; **identical signature set, identical
  (case-id, iteration) sequence and identical classes across both runs**
  (100% reproducible).
- All minimized repro inputs are well under the 200 B budget (largest
  observed PNG body 82 B; smallest 62 B).
- Classes merged by triggering chunk: 2 buckets (`IHDR`, `PLTE`), each with
  one on-disk representative — within the 8-class cap.
- Throughput: the full mutate→serialize→decode path runs at ~99% of pure
  decode throughput (benchmark, 20k iterations), far above the 40% floor.

## Acceptance-criteria mapping

| Requirement | How it is met |
|---|---|
| Structured chunk-level mutation (length/CRC/deflate/filter) | `png_model.py` catalog, six families above |
| Save minimal repro on crash | `crashes/<id>.bin`, four-stage minimizer, reconstructive synthesis |
| Record call stack + triggering field | parsed ASan/UBSan frames in case JSON; `trigger_chunk`/`trigger_fields` |
| All crashes minimize to < 200 B | enforced; real observed max ~85 B PNG body |
| Same seed → same crash set, 100% reproducible | seeded PRNG + stable signatures + timeout retry; verified by two independent runs |
| Throughput ≥ 40% of pure decode per 1000 | `bench` measures the full mutation+serialize+decode path (~70% observed) |
| Classes merged by triggering chunk, ≤ 8, one representative each | `report.classes`, capped at 8, representative case id per bucket |
