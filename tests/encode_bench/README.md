# Encoder parameter sweep (level x row-filter)

Self-contained benchmark for the write path. No third-party dependency beyond
what the library already uses (zlib); every sample image is synthesized in
process, so a single command produces the whole report offline.

    ./run_sweep.sh

It compiles `encode_sweep.c` together with `../../spng/spng.c` (system zlib)
into `../../artifacts/bench/encode_sweep`, runs it once, and tees the report
to `../../artifacts/bench/sweep_results.txt`.

What it does, for four 512x512 RGBA8 image kinds (gradient, photo-like,
graphics, noisy):

* measures encoded size and median time over a 3 compression-levels
  (`1, 4, 6`) x 3 row-filter strategies (none fixed, Paeth fixed, adaptive
  all) grid — the size/time curve;
* records the library default (level 6 + adaptive-all) as the baseline;
* recommends the fastest grid point whose size is no more than 1% larger than
  the default and checks the >=25% time-reduction acceptance target;
* verifies byte-for-byte reproducibility (two encodes of every cell),
  spng decode round-trip, and that the emitted per-row filter bytes match the
  selected strategy;
* times the recommended configuration at 4096x4096 against the 3 s budget.

The fused multi-filter row scan lives in `spng/spng.c`
(`filter_sum_multi()`); it changes only *how* the residual scores are
computed (one pass instead of N), never the selected filter, so output is
byte-identical to the previous implementation for every level/filter
combination.
