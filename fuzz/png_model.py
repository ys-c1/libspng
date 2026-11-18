"""
Chunk-aware PNG model and structured mutator.

A PNG is modeled as: signature + ordered list of chunks (type, data), each
with an independently stored CRC. IDAT payloads carry an extra flag marking
whether their (zlib) compressed stream is still well-formed, so compression
mutations can be targeted instead of random byte flips.

Every mutation is an explicit, replayable record:

    {"op":   <mutation name>,
     "chunk": <chunk type str or None>,
     "index": <chunk index or None>,
     ... op-specific parameters ...}

`apply_mutation(model, record)` is a pure function of (model, record), which
makes crashes reproducible from their saved records and lets the minimizer
replay exactly the mutations that fired.
"""
from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field

PNG_SIG = b"\x89PNG\r\n\x1a\n"

# Mutation catalog, grouped by the field family requested in the task.
OPS_LENGTH = {"len_truncate", "len_extend", "len_zero", "len_huge", "len_swap_neighbor"}
OPS_CRC = {"crc_flip", "crc_zero", "crc_other_chunk"}
OPS_ZSTREAM = {"idat_flip_byte", "idat_truncate", "idat_extend",
               "idat_reflate_raw", "idat_cross_splice", "idat_drop",
               "idat_adler_corrupt", "idat_zlib_header"}
OPS_FILTER = {"filter_byte", "filter_row_all", "ihdr_interlace",
              "ihdr_compression_method", "ihdr_filter_method"}
OPS_IHDR = {"ihdr_field", "bit_depth", "color_type"}
OPS_CHUNK = {"chunk_delete", "chunk_duplicate", "chunk_insert",
             "chunk_reorder", "data_byte", "data_field", "plte_truncate",
             "trns_inject"}
ALL_OPS = sorted(OPS_LENGTH | OPS_CRC | OPS_ZSTREAM | OPS_FILTER |
                 OPS_IHDR | OPS_CHUNK)

# Fields the task wants covered, used for weighting the op lottery.
FAMILIES = (
    ("length", tuple(sorted(OPS_LENGTH))),
    ("crc", tuple(sorted(OPS_CRC))),
    ("zstream", tuple(sorted(OPS_ZSTREAM))),
    ("filter", tuple(sorted(OPS_FILTER))),
    ("ihdr", tuple(sorted(OPS_IHDR))),
    ("chunk", tuple(sorted(OPS_CHUNK))),
)


@dataclass
class Chunk:
    type: bytes
    data: bytearray
    crc: bytes                      # 4 bytes, stored independently of data
    zlib_ok: bool = True            # IDAT: compressed stream still intact
    # Length written into the chunk header. May diverge from len(data):
    # that mismatch is exactly what malformed-PNG length mutations test,
    # and avoids allocating gigabytes for len_huge cases.
    declared_len: int | None = None

    def clone(self) -> "Chunk":
        return Chunk(self.type, bytearray(self.data), bytes(self.crc),
                     self.zlib_ok, self.declared_len)


@dataclass
class PngModel:
    signature: bytearray
    chunks: list = field(default_factory=list)

    def clone(self) -> "PngModel":
        return PngModel(bytearray(self.signature), [c.clone() for c in self.chunks])

    # -- (de)serialization -------------------------------------------------

    def serialize(self) -> bytes:
        out = bytearray(self.signature)
        for c in self.chunks:
            declared = c.declared_len if c.declared_len is not None else len(c.data)
            out += struct.pack(">I", declared)
            out += c.type
            out += c.data
            out += c.crc
        return bytes(out)

    def chunk_index(self, ctype: bytes, nth: int = 0) -> int | None:
        hits = [i for i, c in enumerate(self.chunks) if c.type == ctype]
        if len(hits) > nth:
            return hits[nth]
        return None

    def idat_indices(self) -> list:
        return [i for i, c in enumerate(self.chunks) if c.type == b"IDAT"]

    def ihdr(self) -> Chunk | None:
        for c in self.chunks:
            if c.type == b"IHDR":
                return c
        return None


def parse_png(blob: bytes) -> PngModel:
    """Lenient parse: legal PNGs come from the seed corpus, but we keep
    parsing tolerant so mutated models can be re-parsed during minimization."""
    if len(blob) < 8 or blob[:8] != PNG_SIG:
        raise ValueError("not a PNG")
    m = PngModel(bytearray(blob[:8]))
    pos = 8
    n = len(blob)
    while pos + 8 <= n:
        (length,) = struct.unpack(">I", blob[pos:pos + 4])
        ctype = blob[pos + 4:pos + 8]
        dstart = pos + 8
        dend = dstart + length
        if dend + 4 > n:
            raise ValueError("truncated chunk")
        data = bytearray(blob[dstart:dend])
        crc = blob[dend:dend + 4]
        m.chunks.append(Chunk(ctype, data, crc, declared_len=length))
        pos = dend + 4
        if ctype == b"IEND":
            break
    return m


def real_crc(c: Chunk) -> bytes:
    return struct.pack(">I", zlib.crc32(c.type + bytes(c.data)) & 0xFFFFFFFF)


# -- raw zlib helpers -------------------------------------------------------

def _inflate_raw_idat(model: PngModel) -> bytes | None:
    """Concatenate IDAT payloads and inflate; return raw scanline bytes."""
    idat = b"".join(bytes(c.data) for c in model.chunks if c.type == b"IDAT")
    if not idat:
        return None
    try:
        d = zlib.decompressobj()
        raw = d.decompress(idat)
        return raw + d.flush()
    except zlib.error:
        return None


def _deflate_raw(raw: bytes) -> bytes:
    # Fixed, deterministic deflate settings (no timestamp etc. in raw zlib).
    co = zlib.compressobj(9, zlib.DEFLATED, 15)
    return co.compress(raw) + co.flush()


# ===========================================================================
# Mutation generation
# ===========================================================================

def _pick_chunk(rng, model: PngModel, allow_idat=True):
    candidates = [i for i, c in enumerate(model.chunks)
                  if allow_idat or c.type != b"IDAT"]
    return rng.choice(candidates) if candidates else None


def random_mutation(rng, model: PngModel) -> dict:
    """Draw one structured mutation record appropriate for this model."""
    if not model.chunks:
        # nothing to mutate; synthesize a harmless no-op-ish chunk insert
        return {"op": "chunk_insert", "chunk": "tEXt", "index": 0,
                "payload_len": rng.randrange(0, 64)}
    family, ops = rng.choice(FAMILIES)
    op = rng.choice(ops)
    chunks = model.chunks

    if op in OPS_LENGTH:
        idx = _pick_chunk(rng, model)
        if idx is None:
            return _data_byte_rec(rng, model)
        c = chunks[idx]
        cur = len(c.data)
        if op == "len_truncate":
            new_len = rng.below(cur + 1)
        elif op == "len_extend":
            new_len = cur + rng.randrange(1, max(2, cur // 2 + 8))
        elif op == "len_zero":
            new_len = 0
        else:  # len_huge, len_swap_neighbor handled below
            new_len = cur
        if op == "len_huge":
            new_len = rng.choice([0xFFFFFF, 0x7FFFFFFF, 0xFFFFFFFF, cur + 4096])
        rec = {"op": op, "chunk": c.type.decode("latin1"), "index": idx,
               "new_len": new_len}
        if op == "len_swap_neighbor" and idx + 1 < len(chunks):
            rec["new_len"] = len(chunks[idx + 1].data)
        return rec

    if op in OPS_CRC:
        idx = _pick_chunk(rng, model)
        if idx is None:
            return _data_byte_rec(rng, model)
        c = chunks[idx]
        rec = {"op": op, "chunk": c.type.decode("latin1"), "index": idx}
        if op == "crc_flip":
            rec["bit"] = rng.below(32)
        elif op == "crc_other_chunk":
            other = _pick_chunk(rng, model)
            rec["other_index"] = other if other is not None else idx
        return rec

    if op in OPS_ZSTREAM:
        idat = model.idat_indices()
        if not idat:  # model without IDAT: fall back to a data byte flip
            return _data_byte_rec(rng, model)
        idx = rng.choice(idat)
        c = chunks[idx]
        rec = {"op": op, "chunk": "IDAT", "index": idx}
        if op in ("idat_flip_byte", "idat_adler_corrupt") and c.data:
            rec["offset"] = rng.below(len(c.data))
            if op == "idat_flip_byte":
                rec["xor"] = 1 << rng.below(8)
        if op == "idat_truncate":
            rec["keep"] = rng.below(len(c.data) + 1)
        if op == "idat_extend":
            rec["extra"] = rng.randrange(1, 64)
            rec["fill"] = rng.below(256)
        if op == "idat_zlib_header":
            rec["byte0"] = rng.below(256)
            rec["byte1"] = rng.below(256)
        return rec

    if op in OPS_FILTER or op in OPS_IHDR:
        ih = model.ihdr()
        if ih is None:
            return _data_byte_rec(rng, model)
        idx = model.chunk_index(b"IHDR")
        rec = {"op": op, "chunk": "IHDR", "index": idx}
        if op in ("ihdr_interlace", "ihdr_compression_method",
                  "ihdr_filter_method"):
            rec["value"] = rng.choice([0, 1, 2, 0x7F, 0xFF])
            return rec
        if op == "filter_byte":
            # mutate one filter-type prefix byte inside the IDAT stream
            raw = _inflate_raw_idat(model)
            if raw is None or len(ih.data) < 13:
                return _data_byte_rec(rng, model)
            width, height, bd, ct = struct.unpack(">IIBB", ih.data[:10])
            channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(ct, 1)
            row_bytes = (width * channels * bd + 7) // 8 + 1
            if row_bytes <= 1 or height == 0:
                return _data_byte_rec(rng, model)
            row = rng.below(height)
            off = row * row_bytes
            if off >= len(raw):
                return _data_byte_rec(rng, model)
            rec.update({"row": row, "filter": rng.choice([0, 1, 2, 3, 4, 5, 255])})
        elif op == "filter_row_all":
            rec["filter"] = rng.choice([0, 1, 2, 3, 4, 5, 255])
        elif op in ("ihdr_interlace", "ihdr_compression_method",
                    "ihdr_filter_method"):
            rec["value"] = rng.choice([0, 1, 2, 0x7F, 0xFF])
        elif op == "ihdr_field":
            rec["field"] = rng.choice(["width", "height"])
            rec["value"] = rng.choice([0, 1, 2, 0x7FFFFFFF, 0xFFFFFFFF,
                                       rng.randrange(1, 65536)])
        elif op == "bit_depth":
            rec["value"] = rng.choice([0, 1, 2, 4, 8, 16, 15, 32])
        elif op == "color_type":
            rec["value"] = rng.choice([0, 1, 2, 3, 4, 5, 6, 7, 255])
        return rec

    # OPS_CHUNK
    if op == "chunk_delete":
        idx = _pick_chunk(rng, model)
        if idx is None or chunks[idx].type == b"IHDR":
            return _data_byte_rec(rng, model)
        return {"op": op, "chunk": chunks[idx].type.decode("latin1"),
                "index": idx}
    if op == "chunk_duplicate":
        idx = _pick_chunk(rng, model)
        if idx is None:
            return _data_byte_rec(rng, model)
        return {"op": op, "chunk": chunks[idx].type.decode("latin1"),
                "index": idx}
    if op == "chunk_insert":
        ctype = rng.choice([b"tEXt", b"zTXt", b"iTXt", b"bKGD", b"pHYs",
                            b"sBIT", b"cHRM", b"gAMA", b"sPLT", b"hIST",
                            b"tIME", b"iCCP", b"eXIf", b"oFFs", b"pCAL",
                            b"sCAL", b"sTER", b"acTL", b"fcTL"])
        return {"op": op, "chunk": ctype.decode("latin1"),
                "index": rng.below(len(chunks) + 1),
                "payload_len": rng.randrange(0, 256)}
    if op == "chunk_reorder":
        if len(chunks) < 2:
            return _data_byte_rec(rng, model)
        i, j = rng.below(len(chunks)), rng.below(len(chunks))
        return {"op": op, "chunk": chunks[i].type.decode("latin1"),
                "index": i, "other_index": j}
    if op == "plte_truncate":
        idx = model.chunk_index(b"PLTE")
        if idx is None:
            return _data_byte_rec(rng, model)
        return {"op": op, "chunk": "PLTE", "index": idx,
                "new_len": rng.below(len(chunks[idx].data) + 1)}
    if op == "trns_inject":
        return {"op": op, "chunk": "tRNS",
                "index": rng.below(len(chunks) + 1),
                "payload_len": rng.randrange(0, 32)}
    if op == "data_field":
        idx = _pick_chunk(rng, model, allow_idat=False)
        if idx is None:
            return _data_byte_rec(rng, model)
        c = chunks[idx]
        if not c.data:
            return _data_byte_rec(rng, model)
        return {"op": "data_field", "chunk": c.type.decode("latin1"),
                "index": idx, "offset": rng.below(len(c.data)),
                "value": rng.below(256)}
    return _data_byte_rec(rng, model)


def _data_byte_rec(rng, model: PngModel) -> dict:
    idx = _pick_chunk(rng, model)
    if idx is None:
        return {"op": "chunk_insert", "chunk": "tEXt",
                "index": len(model.chunks), "payload_len": rng.randrange(0, 64)}
    c = model.chunks[idx]
    if not c.data:
        return {"op": "len_extend", "chunk": c.type.decode("latin1"),
                "index": idx, "new_len": 1}
    return {"op": "data_byte", "chunk": c.type.decode("latin1"),
            "index": idx, "offset": rng.below(len(c.data)),
            "xor": 1 << rng.below(8)}


# ===========================================================================
# Mutation application (pure function of model + record)
# ===========================================================================

def apply_mutation(model: PngModel, rec: dict) -> None:
    op = rec["op"]
    ci = model.chunks
    idx = rec.get("index")

    if op == "data_byte":
        ci[idx].data[rec["offset"]] ^= rec["xor"]
        ci[idx].crc = real_crc(ci[idx])
        return

    if op in OPS_LENGTH:
        c = ci[idx]
        new_len = rec["new_len"]
        # Keep the in-memory payload bounded; the *declared* header length
        # still records the (possibly huge / truncated) malformed value.
        cap = 64 * 1024
        actual = min(new_len, cap)
        if actual <= len(c.data):
            c.data = c.data[:actual]
        else:
            c.data += b"\x00" * (actual - len(c.data))
        c.declared_len = new_len
        if c.type == b"IDAT":
            c.zlib_ok = False
        c.crc = real_crc(c)
        return

    if op == "plte_truncate":
        c = ci[idx]
        c.data = c.data[:rec["new_len"]]
        c.declared_len = rec["new_len"]
        c.crc = real_crc(c)
        return

    if op in OPS_CRC:
        c = ci[idx]
        if op == "crc_flip":
            bit = rec["bit"]
            b = bytearray(c.crc)
            b[bit // 8] ^= 1 << (bit % 8)
            c.crc = bytes(b)
        elif op == "crc_zero":
            c.crc = b"\x00\x00\x00\x00"
        else:  # crc_other_chunk
            c.crc = ci[rec["other_index"]].crc
        return

    if op in OPS_ZSTREAM:
        c = ci[idx]
        if op in ("idat_flip_byte", "idat_adler_corrupt"):
            if "offset" not in rec or rec["offset"] >= len(c.data):
                # empty/too-small payload: extend deterministically instead
                c.data += b"\x00" * max(1, 4 - len(c.data))
                rec = dict(rec)
                rec["offset"] = len(c.data) - 1
                rec["xor"] = 0xFF
        if op == "idat_flip_byte":
            c.data[rec["offset"]] ^= rec["xor"]
            c.zlib_ok = False
        elif op == "idat_adler_corrupt" and len(c.data) >= 4:
            c.data[rec["offset"]] ^= 0xFF
            c.zlib_ok = False
        elif op == "idat_truncate":
            c.data = c.data[:rec["keep"]]
            c.zlib_ok = False
        elif op == "idat_extend":
            c.data += bytes([rec["fill"]]) * rec["extra"]
            c.zlib_ok = False
        elif op == "idat_zlib_header" and len(c.data) >= 2:
            c.data[0] = rec["byte0"]
            c.data[1] = rec["byte1"]
            c.zlib_ok = False
        elif op == "idat_drop":
            del ci[idx]
            return
        elif op == "idat_cross_splice":
            idat = model.idat_indices()
            if len(idat) > 1:
                src = ci[idat[-1]]
                c.data = bytearray(src.data)
            c.zlib_ok = False
        elif op == "idat_reflate_raw":
            raw = _inflate_raw_idat(model)
            if raw is not None:
                # re-encode then deliberately damage: wrong stream but valid
                # zlib framing, exercises inflate + filter error paths
                blob = bytearray(_deflate_raw(raw))
                if len(blob) > 4:
                    blob[2 + (len(blob) // 2) % max(1, len(blob) - 4)] ^= 0x5A
                c.data = blob
                c.zlib_ok = False
        return

    if op == "filter_byte":
        ih = model.ihdr()
        raw = _inflate_raw_idat(model)
        if raw is None or ih is None or len(ih.data) < 13:
            return
        width, height, bd, ct = struct.unpack(">IIBB", ih.data[:10])
        channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(ct, 1)
        row_bytes = (width * channels * bd + 7) // 8 + 1
        off = rec["row"] * row_bytes
        if off < len(raw):
            raw = bytearray(raw)
            raw[off] = rec["filter"]
            _replace_idat_stream(model, bytes(raw))
        return

    if op == "filter_row_all":
        ih = model.ihdr()
        raw = _inflate_raw_idat(model)
        if raw is None or ih is None or len(ih.data) < 13:
            return
        width, height, bd, ct = struct.unpack(">IIBB", ih.data[:10])
        channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(ct, 1)
        row_bytes = (width * channels * bd + 7) // 8 + 1
        raw = bytearray(raw)
        # Guard against gigantic IHDR dimensions: cap the work regardless of
        # what the (possibly mutated) header claims.
        row_limit = max(1, len(raw) // max(1, row_bytes))
        for r in range(min(height, row_limit)):
            off = r * row_bytes
            if off < len(raw):
                raw[off] = rec["filter"]
        _replace_idat_stream(model, bytes(raw))
        return

    if op in OPS_IHDR or op in ("ihdr_interlace", "ihdr_compression_method",
                                "ihdr_filter_method"):
        c = ci[idx]
        d = c.data
        if op == "ihdr_field":
            if rec["field"] == "width" and len(d) >= 4:
                d[0:4] = struct.pack(">I", rec["value"])
            elif len(d) >= 8:
                d[4:8] = struct.pack(">I", rec["value"])
        elif op == "bit_depth" and len(d) >= 9:
            d[8] = rec["value"]
        elif op == "color_type" and len(d) >= 10:
            d[9] = rec["value"]
        elif op == "ihdr_interlace" and len(d) >= 13:
            d[12] = rec["value"]
        elif op == "ihdr_compression_method" and len(d) >= 11:
            d[10] = rec["value"]
        elif op == "ihdr_filter_method" and len(d) >= 12:
            d[11] = rec["value"]
        c.crc = real_crc(c)
        return

    if op == "chunk_delete":
        del ci[idx]
        return
    if op == "chunk_duplicate":
        ci.insert(idx + 1, ci[idx].clone())
        return
    if op == "chunk_insert":
        payload = bytes((i * 37 + 11) & 0xFF for i in range(rec["payload_len"]))
        nc = Chunk(rec["chunk"].encode("latin1"), bytearray(payload), b"")
        nc.crc = real_crc(nc)
        ci.insert(rec["index"], nc)
        return
    if op == "chunk_reorder":
        ci[rec["index"]], ci[rec["other_index"]] = (
            ci[rec["other_index"]], ci[rec["index"]])
        return
    if op == "trns_inject":
        payload = bytes(rng_dummy(rec["payload_len"]))
        nc = Chunk(b"tRNS", bytearray(payload), b"")
        nc.crc = real_crc(nc)
        ci.insert(rec["index"], nc)
        return
    if op == "data_field":
        ci[idx].data[rec["offset"]] = rec["value"]
        ci[idx].crc = real_crc(ci[idx])
        return

    raise ValueError(f"unknown op {op}")


def rng_dummy(n):
    # deterministic filler for inserted tRNS chunks (record itself is the
    # source of truth; content is a fixed function of length)
    return bytes((i * 173 + 7) & 0xFF for i in range(n))


def _replace_idat_stream(model: PngModel, raw: bytes) -> None:
    idat = model.idat_indices()
    if not idat:
        return
    blob = _deflate_raw(raw)
    first = model.chunks[idat[0]]
    first.data = bytearray(blob)
    first.crc = real_crc(first)
    first.zlib_ok = True
    for i in reversed(idat[1:]):
        del model.chunks[i]
