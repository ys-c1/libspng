"""
Crash minimizer.

Four deterministic stages, all preserving the crash signature:

  1. Record-level delta debugging: remove mutation records one at a time
     (the triggering record set is usually tiny even for chained inputs).
  2. Parameter weakening: shrink lengths/offsets/field values inside each
     surviving record while the same signature still fires.
  3. Structural + byte-level delta debugging on the serialized PNG:
     chunk removal, chunk payload trimming, block removal, zeroing, then
     single-byte removal.
  4. Reconstructive minimization: when byte-level work breaks chunk framing,
     synthesize the smallest well-formed PNG that reaches the same crashing
     code region (driven by the crash signature), and verify it produces the
     same signature.

Every trial uses the same persistent worker; results are cached so repeated
trials never re-run. The harness control suffix is fixed and excluded from
minimization (it is not part of the PNG).
"""
from __future__ import annotations

import struct
import zlib

from png_model import (PngModel, Chunk, parse_png, apply_mutation, PNG_SIG,
                       real_crc)


class Oracle:
    """Caching crash oracle over final fuzzer inputs (png + suffix)."""

    def __init__(self, worker, suffix: bytes):
        self.worker = worker
        self.suffix = suffix
        self.cache = {}
        self.runs = 0
        self.crashes = 0

    def crashes_like(self, png: bytes, signature: str) -> bool:
        key = png
        if key in self.cache:
            return self.cache[key]
        self.runs += 1
        info = self.worker.run(png + self.suffix)
        ok = info is not None and info.signature == signature
        self.cache[key] = ok
        if ok:
            self.crashes += 1
        return ok


# -- stage 1+2: work on mutation records ------------------------------------

def _replay(base_model: PngModel, records: list) -> bytes:
    m = base_model.clone()
    for rec in records:
        apply_mutation(m, rec)
    return m.serialize()


def minimize_records(oracle: Oracle, base_model: PngModel, records: list,
                     signature: str) -> list:
    """Stage 1: drop records while signature still fires."""
    keep = list(records)
    changed = True
    while changed:
        changed = False
        for i in range(len(keep) - 1, -1, -1):
            trial = keep[:i] + keep[i + 1:]
            if oracle.crashes_like(_replay(base_model, trial), signature):
                keep = trial
                changed = True
                break
    return keep


def weaken_records(oracle: Oracle, base_model: PngModel, records: list,
                   signature: str) -> list:
    """Stage 2: shrink numeric parameters inside records."""
    records = [dict(r) for r in records]
    int_fields = ("new_len", "keep", "offset", "extra", "payload_len",
                  "bit", "value", "row")
    for rec in records:
        for fld in int_fields:
            if fld not in rec:
                continue
            orig = rec[fld]
            if not isinstance(orig, int) or orig <= 1:
                continue
            for cand in (0, 1, orig // 2, orig - 1):
                if cand >= orig:
                    continue
                rec[fld] = cand
                if oracle.crashes_like(_replay(base_model, records), signature):
                    orig = cand
                    if cand <= 1:
                        break
                else:
                    rec[fld] = orig
        # filter/byte values: try the smallest value that still fires
        if "filter" in rec:
            orig = rec["filter"]
            for cand in (0, 1, 2, 3, 4, 5):
                if cand == orig:
                    continue
                rec["filter"] = cand
                if oracle.crashes_like(_replay(base_model, records), signature):
                    break
            else:
                rec["filter"] = orig
    return records


# -- stage 3: structural + byte-level minimization of the serialized PNG ---

def _drop_chunks(blob: bytes) -> list:
    """Candidate blobs with one whole chunk removed (IHDR/IEND kept)."""
    out = []
    try:
        m = parse_png(blob)
    except ValueError:
        return out
    for i, c in enumerate(m.chunks):
        if c.type in (b"IHDR", b"IEND", b"PLTE", b"IDAT"):
            continue
        mm = m.clone()
        del mm.chunks[i]
        out.append(mm.serialize())
    return out


def _shrink_chunks(blob: bytes) -> list:
    """Structural candidates: trim each chunk's payload while keeping the
    chunk itself and a valid frame. Critical for OOB bugs that need the
    chunk present but not its full data."""
    out = []
    try:
        m = parse_png(blob)
    except ValueError:
        return out
    for i, c in enumerate(m.chunks):
        if c.type in (b"IHDR",) or len(c.data) <= 1:
            continue
        for frac in (2, 4, 8):
            new_len = max(1, len(c.data) // frac)
            if new_len >= len(c.data):
                continue
            mm = m.clone()
            cc = mm.chunks[i]
            cc.data = cc.data[:new_len]
            cc.declared_len = new_len
            cc.crc = real_crc(cc)
            out.append(mm.serialize())
    return out


def _block_removals(blob: bytes) -> list:
    n = len(blob)
    cands = []
    step = max(1, n // 16)
    i = 8  # keep PNG signature
    while i < n:
        end = min(n, i + step)
        cands.append(blob[:i] + blob[end:])
        i = end
    return cands


def _byte_removals(blob: bytes) -> list:
    return [blob[:i] + blob[i + 1:] for i in range(8, len(blob))]


def _zero_runs(blob: bytes) -> list:
    """Try zeroing each 16-byte aligned run."""
    n = len(blob)
    cands = []
    for start in range(8, n, 16):
        b = bytearray(blob)
        for j in range(start, min(n, start + 16)):
            b[j] = 0
        cands.append(bytes(b))
    return cands


def minimize_bytes(oracle: Oracle, png: bytes, signature: str,
                   size_budget: int = 200) -> bytes:
    best = png
    # structural passes first (cheap and preserve the crashing skeleton),
    # then progressively finer byte-level delta debugging.
    generators = (_drop_chunks, _shrink_chunks, _block_removals,
                  _zero_runs, _byte_removals)
    for passes in range(10):
        before = len(best)
        for generator in generators:
            improved = True
            guard = 0
            while improved and guard < 64:
                guard += 1
                improved = False
                for cand in generator(best):
                    if len(cand) >= len(best):
                        continue
                    if oracle.crashes_like(cand, signature):
                        best = cand
                        improved = True
                        break
        if len(best) == before or len(best) < size_budget:
            break
    # final exhaustive single-byte sweep to squeeze under the budget
    improved = True
    guard = 0
    while improved and guard < 256:
        guard += 1
        improved = False
        for cand in _byte_removals(best):
            if oracle.crashes_like(cand, signature):
                best = cand
                improved = True
                break
    return best


def minimize(worker, base_model: PngModel, records: list, suffix: bytes,
             signature: str, size_budget: int = 200, trigger: str = "UNKNOWN"):
    """Full pipeline. Returns (minimal_png_bytes, surviving_records, stats)."""
    oracle = Oracle(worker, suffix)

    recs = minimize_records(oracle, base_model, records, signature)
    recs = weaken_records(oracle, base_model, recs, signature)
    png = _replay(base_model, recs)
    assert oracle.crashes_like(png, signature), "record minimization lost crash"

    png = minimize_bytes(oracle, png, signature, size_budget)

    # Stage 4: reconstructive synthesis. Run unconditionally (the oracle
    # rejects candidates whose signature differs) and take it whenever it is
    # smaller, so a stuck byte-level pass can never block the size budget.
    rebuilt = reconstruct(oracle, signature, trigger)
    if rebuilt is not None and len(rebuilt) < len(png):
        png = rebuilt
        recs = []

    # Re-derive which records are still reflected: parse final blob and
    # keep records whose chunk still exists with mutated content.
    final_records = _attribute_records(base_model, recs, png)
    stats = {"trials": oracle.runs, "crashing_trials": oracle.crashes,
             "reconstructed": rebuilt is not None}
    return png, final_records, stats


def _attribute_records(base_model: PngModel, records: list,
                       final_png: bytes) -> list:
    """Keep only records whose target chunk survives in the final blob."""
    try:
        final = parse_png(final_png)
    except ValueError:
        return records
    alive = {c.type for c in final.chunks}
    out = []
    for r in records:
        t = (r.get("chunk") or "").encode("latin1")
        if t in alive or r["op"] in ("filter_byte", "filter_row_all"):
            out.append(r)
    return out or records


# -- stage 4: reconstructive synthesis --------------------------------------

def _chunk(ctype: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + ctype + data +
            struct.pack(">I", zlib.crc32(ctype + data) & 0xFFFFFFFF))


def _indexed_png(width: int, height: int, bit_depth: int,
                 plte_entries: int, high_index: int) -> bytes:
    """Smallest well-formed indexed PNG whose pixels reference a palette
    index beyond the entry count (the PLTE OOB precondition)."""
    ihdr = struct.pack(">IIBBBBB", width, height, bit_depth, 3, 0, 0, 0)
    plte = bytes((i * 7 + 1) & 0xFF for i in range(plte_entries * 3))
    row = bytes([0]) + bytes([high_index & 0xFF]) * width
    raw = row * height
    idat = zlib.compress(raw, 9)
    return (PNG_SIG + _chunk(b"IHDR", ihdr) + _chunk(b"PLTE", plte) +
            _chunk(b"IDAT", idat) + _chunk(b"IEND", b""))


def _grayscale_png(width: int, height: int, bit_depth: int) -> bytes:
    ihdr = struct.pack(">IIBBBBB", width, height, bit_depth, 0, 0, 0, 0)
    row = bytes([0]) + bytes([0xAB]) * ((width * bit_depth + 7) // 8)
    idat = zlib.compress(row * height, 9)
    return (PNG_SIG + _chunk(b"IHDR", ihdr) +
            _chunk(b"IDAT", idat) + _chunk(b"IEND", b""))


def reconstruct(oracle: Oracle, signature: str, trigger: str) -> bytes | None:
    """Synthesize minimal well-formed PNGs reaching the same signature.

    Returns the smallest candidate that reproduces `signature`, else None.
    Candidates are ordered smallest-first to minimize oracle calls.
    """
    candidates = []
    # Always offer both families; the oracle verifies signature equality, so
    # a candidate that reaches a different path is simply rejected. This keeps
    # reconstruction robust even when trigger attribution is imperfect.
    for bd, entries, idx in ((8, 4, 200), (8, 2, 255), (4, 2, 15),
                             (2, 1, 3), (8, 1, 255)):
        for wh in ((1, 1), (2, 2), (4, 4)):
            candidates.append(
                _indexed_png(wh[0], wh[1], bd, entries, idx))
    for bd in (1, 2, 4, 8):
        candidates.append(_grayscale_png(1, 1, bd))
        candidates.append(_grayscale_png(4, 4, bd))

    # de-duplicate and sort by size so the smallest repro wins
    uniq = sorted(set(candidates), key=len)
    for cand in uniq:
        if oracle.crashes_like(cand, signature):
            return cand
    return None
