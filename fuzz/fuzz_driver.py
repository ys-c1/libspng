#!/usr/bin/env python3
"""
Structured, chunk-aware fuzz driver for libspng.

Pipeline per iteration (fully deterministic given --seed):
  1. pick a seed PNG and a harness control suffix
  2. draw 1..4 structured chunk-level mutations (length / CRC / deflate
     stream / filter type / IHDR fields / chunk topology)
  3. serialize, send to the persistent ASan+UBSan worker
  4. on crash: record stack signature + triggering field, minimize the
     input, and bucket by triggering chunk (at most 8 buckets)

Commands:
  build-check   smoke-test the worker against the seed corpus
  fuzz          run N mutations and write the crash report
  repro         replay a saved case record and confirm it still crashes
  bench         throughput vs. pure-decode baseline
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from rng import Rng
from png_model import parse_png, apply_mutation, PngModel, ALL_OPS, random_mutation
from worker import Worker, make_suffix
import minimizer as minz

ROOT = os.path.dirname(HERE)
SEED_DIRS = (
    os.path.join(ROOT, "tests", "images"),
    os.path.join(ROOT, "tests", "crashers"),
    os.path.join(ROOT, "tests", "misc"),
    os.path.join(ROOT, "tests", "corpus"),
)
OUT_ROOT = os.path.join(ROOT, "artifacts", "fuzz")
MAX_CLASSES = 8
SIZE_BUDGET = 200  # minimized input (PNG portion) must stay below this


# --------------------------------------------------------------------------
# corpus
# --------------------------------------------------------------------------

def load_seeds() -> dict:
    seeds = {}
    for sdir in SEED_DIRS:
        if not os.path.isdir(sdir):
            continue
        for name in sorted(os.listdir(sdir)):
            if not name.endswith(".png"):
                continue
            path = os.path.join(sdir, name)
            with open(path, "rb") as f:
                blob = f.read()
            try:
                model = parse_png(blob)
            except ValueError:
                continue
            if not model.chunks:
                continue
            # prefix to avoid name collisions across directories
            key = f"{os.path.basename(sdir)}/{name}"
            seeds[key] = {"blob": blob, "model": model}
    return seeds


def plan_input(rng: Rng, seeds: dict):
    """Deterministically build one fuzzer input and its provenance record."""
    seed_name = rng.choice(sorted(seeds))
    model = seeds[seed_name]["model"].clone()
    n_muts = 1 if rng.chance(0.8) else rng.randrange(2, 5)
    records = []
    for _ in range(n_muts):
        rec = None
        # two retries if an op cannot apply to this model
        for _try in range(3):
            cand = random_mutation(rng, model)
            try:
                probe = model.clone()
                apply_mutation(probe, cand)
                rec = cand
                model = probe
                break
            except (ValueError, IndexError, struct.error):
                continue
        if rec is None:
            continue
        records.append(rec)
    suffix = make_suffix(rng)
    return seed_name, records, model.serialize(), suffix


# --------------------------------------------------------------------------
# classification
# --------------------------------------------------------------------------

def triggering_chunk(records: list, info=None, final_png: bytes | None = None) -> str:
    """Attribute the crash to a chunk.

    Preference order:
      1. a surviving mutation record (the field the fuzzer changed)
      2. the top in-library stack frame mapped to its owning chunk
      3. structural inspection of the crashing PNG's chunk types
      4. UNKNOWN
    """
    for r in records:
        c = r.get("chunk")
        if c:
            return c
    if info is not None and info.frames:
        fn = info.frames[0][0]
        mapping = {
            "expand_row": "PLTE", "check_plte": "PLTE",
            "trns_row": "tRNS",
            "defilter_scanline": "IDAT", "filter_scanline": "IDAT",
            "read_scanline": "IDAT", "read_scanline_bytes": "IDAT",
            "read_idat_bytes": "IDAT", "spng__inflate_stream": "IDAT",
            "check_ihdr": "IHDR", "check_sbit": "sBIT",
            "check_phys": "pHYs", "check_chrm_int": "cHRM",
            "check_time": "tIME",
        }
        for frame_fn, _loc in info.frames:
            if frame_fn in mapping:
                return mapping[frame_fn]
    if final_png is not None:
        try:
            model = parse_png(final_png)
            types = [c.type.decode("latin1") for c in model.chunks]
            for t in ("PLTE", "tRNS", "IDAT", "IHDR"):
                if t in types:
                    return t
        except ValueError:
            pass
    return "UNKNOWN"


def trigger_field(records: list, info=None) -> str:
    fields = ",".join(sorted({r["op"] for r in records}))
    if fields:
        return fields
    # Records were dropped during minimization: derive a field label from
    # the crashing function so the artifact still names the trigger path.
    if info is not None:
        fn_map = {
            "expand_row": "palette_index_oob",
            "check_plte": "plte_validation",
            "trns_row": "trns_index",
            "defilter_scanline": "filter_type",
            "read_scanline": "idat_stream",
            "read_scanline_bytes": "idat_stream",
            "read_idat_bytes": "idat_stream",
            "spng__inflate_stream": "deflate_stream",
            "check_ihdr": "ihdr_field",
        }
        for fn, _loc in info.frames:
            if fn in fn_map:
                return fn_map[fn]
    return "reconstructed"


# --------------------------------------------------------------------------
# fuzz loop
# --------------------------------------------------------------------------

def _record_crash(i, info, seed_name, records, png, suffix,
                  minimize, worker, seeds, crashdir, outdir,
                  seen_sig, class_order, report):
    case_id = hashlib.sha1(info.signature.encode()).hexdigest()[:12]
    chunk = triggering_chunk(records, info, png)
    case = {
        "id": case_id,
        "first_iteration": i,
        "seed_file": seed_name,
        "signature": info.signature,
        "sanitizer": info.kind,
        "message": info.message,
        "trigger_chunk": chunk,
        "trigger_fields": trigger_field(records, info),
        "suffix_hex": suffix.hex(),
        "stack": [{"fn": fn, "loc": loc}
                  for fn, loc in info.frames[:12]],
        "summary": info.summary,
        "mutations": records,
        "raw_size": len(png),
        "worker_log": os.path.relpath(info.log_path, outdir),
    }

    if minimize:
        try:
            base = seeds[seed_name]["model"]
            mpng, mrecs, mstats = minz.minimize(
                worker, base, records, suffix, info.signature,
                SIZE_BUDGET, trigger=chunk)
            case["minimized_size"] = len(mpng)
            case["minimization"] = mstats
            case["minimized_mutations"] = mrecs
            case["trigger_chunk"] = triggering_chunk(mrecs, info, mpng)
            case["trigger_fields"] = trigger_field(mrecs, info)
            mpng_suffix = mpng + suffix
            chunk = case["trigger_chunk"]
        except AssertionError as e:
            case["minimized_size"] = len(png)
            case["minimization"] = {"error": str(e)}
            mpng_suffix = png + suffix
    else:
        mpng_suffix = png + suffix
        case["minimized_size"] = len(png)

    with open(os.path.join(crashdir, f"{case_id}.bin"), "wb") as f:
        f.write(mpng_suffix)
    with open(os.path.join(crashdir, f"{case_id}.json"), "w") as f:
        json.dump(case, f, indent=2)
    report["crashes"].append(case)

    if info.signature not in seen_sig:
        if chunk not in class_order and len(class_order) < MAX_CLASSES:
            class_order.append(chunk)
        bucket = chunk if chunk in class_order else class_order[-1]
        seen_sig[info.signature] = bucket
        report["classes"].setdefault(bucket, {
            "trigger_chunk": bucket, "count": 0,
            "signatures": [], "representative": case_id})
    bucket = seen_sig[info.signature]
    cls = report["classes"][bucket]
    cls["count"] += 1
    if info.signature not in cls["signatures"]:
        cls["signatures"].append(info.signature)
    return case


def run_fuzz(seed: int, iterations: int, outdir: str,
             minimize: bool = True, progress: bool = True) -> dict:
    os.makedirs(outdir, exist_ok=True)
    crashdir = os.path.join(outdir, "crashes")
    logdir = os.path.join(outdir, "worker_logs")
    os.makedirs(crashdir, exist_ok=True)
    os.makedirs(logdir, exist_ok=True)

    seeds = load_seeds()
    if not seeds:
        raise SystemExit("no seed PNGs found in tests/images")
    rng = Rng(seed)
    worker = Worker(logdir)

    report = {
        "seed": seed, "iterations": iterations,
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "seed_corpus": sorted(seeds),
        "mutation_ops": ALL_OPS,
        "crashes": [], "classes": {}, "stats": {},
    }
    seen_sig = {}          # signature -> class id
    class_order = []       # chunk names in first-seen order
    hangs = []             # watchdog timeouts tracked separately, not crashes
    t0 = time.monotonic()
    next_ckpt = 1000
    window_t0 = t0
    window_done = 0

    try:
        for i in range(1, iterations + 1):
            seed_name, records, png, suffix = plan_input(rng, seeds)
            info = worker.run(png + suffix)

            if info is not None:
                # Watchdog timeouts are hangs, a distinct failure class from
                # memory-safety crashes. Record them separately and continue;
                # they do not participate in crash minimization/bucketing.
                if info.kind == "timeout":
                    hangs.append({
                        "first_iteration": i, "seed_file": seed_name,
                        "trigger_chunk": triggering_chunk(records, info, png),
                        "trigger_fields": trigger_field(records, info),
                        "suffix_hex": suffix.hex(),
                        "raw_size": len(png),
                    })
                    if i >= next_ckpt:
                        pass
                    # fall through to checkpoint handling below
                else:
                    _record_crash(
                        i, info, seed_name, records, png, suffix,
                        minimize, worker, seeds, crashdir, outdir,
                        seen_sig, class_order, report)

            if i >= next_ckpt:
                now = time.monotonic()
                rate = (i - window_done) / max(1e-9, now - window_t0)
                report["stats"].setdefault("checkpoints", []).append({
                    "iterations": i,
                    "total_elapsed_s": round(now - t0, 3),
                    "window_rate_per_s": round(rate, 1),
                    "crashes_so_far": len(report["crashes"]),
                })
                if progress:
                    print(f"[{i:>7}] {rate:8.1f} inputs/s  "
                          f"crashes={len(report['crashes'])} "
                          f"classes={len(class_order)}", flush=True)
                next_ckpt += 1000
                window_t0, window_done = now, i
    finally:
        worker.close()

    report["hangs"] = hangs
    elapsed = time.monotonic() - t0
    report["stats"].update({
        "elapsed_s": round(elapsed, 3),
        "throughput_per_s": round(iterations / max(1e-9, elapsed), 1),
        "total_crashes": len(report["crashes"]),
        "total_hangs": len(hangs),
        "distinct_signatures": len(seen_sig),
        "num_classes": len(report["classes"]),
        "all_minimized_under_budget": all(
            c.get("minimized_size", 1 << 30) < SIZE_BUDGET
            for c in report["crashes"]),
    })
    report["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    with open(os.path.join(outdir, "report.json"), "w") as f:
        json.dump(report, f, indent=2)
    return report


# --------------------------------------------------------------------------
# replay / benchmark
# --------------------------------------------------------------------------

def repro_case(outdir: str, case_json: str) -> bool:
    with open(case_json) as f:
        case = json.load(f)
    case_id = case["id"]
    with open(os.path.join(outdir, "crashes", f"{case_id}.bin"), "rb") as f:
        data = f.read()
    logdir = os.path.join(outdir, "repro_logs")
    os.makedirs(logdir, exist_ok=True)
    worker = Worker(logdir)
    try:
        info = worker.run(data)
    finally:
        worker.close()
    if info is None:
        print(f"FAIL {case_id}: no crash on replay")
        return False
    match = info.signature == case["signature"]
    print(f"{'OK  ' if match else 'DIFF'} {case_id}: "
          f"{info.kind} {info.message[:70]}")
    if not match:
        print(f"  expected {case['signature']}")
        print(f"  got      {info.signature}")
    return match


def benchmark(iterations: int, outdir: str) -> dict:
    """Compare full mutation pipeline vs pure re-decode of the seed corpus."""
    seeds = load_seeds()
    logdir = os.path.join(outdir, "bench_logs")
    os.makedirs(logdir, exist_ok=True)
    worker = Worker(logdir)
    blobs = [v["blob"] for v in seeds.values()]
    suffix = b"\x00\x01\x00\x00"  # RGBA8 buffer decode

    # baseline: pure decode, no mutation, same persistent worker
    t0 = time.monotonic()
    n = 0
    for _ in range(iterations):
        worker.run(blobs[n % len(blobs)] + suffix)
        n += 1
    base_elapsed = time.monotonic() - t0

    # fuzz path: structured mutation + serialize + worker
    rng = Rng(12345)
    t0 = time.monotonic()
    for _ in range(iterations):
        _, _, png, sfx = plan_input(rng, seeds)
        worker.run(png + sfx)
    fuzz_elapsed = time.monotonic() - t0
    worker.close()

    res = {
        "iterations": iterations,
        "pure_decode_s": round(base_elapsed, 4),
        "fuzz_path_s": round(fuzz_elapsed, 4),
        "pure_decode_rate": round(iterations / base_elapsed, 1),
        "fuzz_rate": round(iterations / fuzz_elapsed, 1),
        "relative_throughput": round(base_elapsed / fuzz_elapsed, 3),
    }
    with open(os.path.join(outdir, "benchmark.json"), "w") as f:
        json.dump(res, f, indent=2)
    return res


def smoke_test(outdir: str) -> int:
    seeds = load_seeds()
    logdir = os.path.join(outdir, "smoke_logs")
    os.makedirs(logdir, exist_ok=True)
    worker = Worker(logdir)
    bad = 0
    suffix = b"\x00\x01\x00\x00"
    for name in sorted(seeds):
        info = worker.run(seeds[name]["blob"] + suffix)
        if info is not None:
            bad += 1
            print(f"SEED CRASH {name}: {info.kind} {info.message}")
    worker.close()
    print(f"smoke test: {len(seeds)} seeds, {bad} unexpected crashes")
    return bad


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_bc = sub.add_parser("build-check")
    p_bc.add_argument("--outdir", default=os.path.join(OUT_ROOT, "run"))
    p = sub.add_parser("fuzz")
    p.add_argument("--seed", type=int, default=20261119)
    p.add_argument("--iterations", type=int, default=100_000)
    p.add_argument("--outdir", default=os.path.join(OUT_ROOT, "run"))
    p.add_argument("--no-minimize", action="store_true")
    p.add_argument("--quiet", action="store_true")
    p = sub.add_parser("repro")
    p.add_argument("--outdir", default=os.path.join(OUT_ROOT, "run"))
    p.add_argument("case_json")
    p = sub.add_parser("bench")
    p.add_argument("--iterations", type=int, default=20_000)
    p.add_argument("--outdir", default=os.path.join(OUT_ROOT, "run"))
    args = ap.parse_args()

    if args.cmd == "build-check":
        sys.exit(1 if smoke_test(args.outdir) else 0)
    if args.cmd == "fuzz":
        rep = run_fuzz(args.seed, args.iterations, args.outdir,
                       minimize=not args.no_minimize, progress=not args.quiet)
        st = rep["stats"]
        print(json.dumps(st, indent=2))
        print("classes:")
        for k, v in rep["classes"].items():
            print(f"  {k:8s} count={v['count']:5d} "
                  f"sigs={len(v['signatures'])} rep={v['representative']}")
    elif args.cmd == "repro":
        ok = repro_case(args.outdir, args.case_json)
        sys.exit(0 if ok else 1)
    elif args.cmd == "bench":
        print(json.dumps(benchmark(args.iterations, args.outdir), indent=2))


if __name__ == "__main__":
    main()
