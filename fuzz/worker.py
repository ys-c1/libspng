"""
Persistent worker controller.

One sanitizer-instrumented worker process is kept alive across inputs.
A crash (ASan/UBSan abort, segv, assertion) kills the process; the controller
harvests its stderr report, normalizes the stack, and respawns. A watchdog
timeout handles hangs.
"""
from __future__ import annotations

import os
import re
import select
import signal
import subprocess
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
# Default = the real, unmodified library. Overridable via SPNG_FUZZ_WORKER
# (used to point at the defect-injected validation build).
WORKER = os.environ.get(
    "SPNG_FUZZ_WORKER",
    os.path.join(ROOT, "artifacts", "fuzz", "build", "fuzz_worker"))

# Harness control suffix (see tests/spng_read_fuzzer.c, last 4 bytes):
#   byte0 = control bits (stream/progressive/file_stream/discard)
#   byte1..2 = fmt (le16), byte3 = decode flags
SUFFIXES = [
    (0x00, 1, 0, 0),    # SPNG_FMT_RGBA8, buffer
    (0x00, 4, 0, 0),    # RGB8
    (0x00, 64, 0, 0),   # G8
    (0x00, 16, 0, 0),   # GA8
    (0x00, 2, 0, 0),    # RGBA16
    (0x00, 0, 1, 0),    # SPNG_FMT_PNG (256)
    (0x00, 0, 2, 0),    # SPNG_FMT_RAW (512)
    (0x02, 1, 0, 0),    # progressive RGBA8
    (0x01, 1, 0, 0),    # stream callback
    (0x05, 1, 0, 0),    # fmemopen file stream
    (0x0A, 1, 0, 0),    # progressive + CRC discard
    (0x00, 1, 0, 2),    # gamma flag
]


def make_suffix(rng) -> bytes:
    c, lo, hi, flags = rng.choice(SUFFIXES)
    return bytes((c, lo, hi, flags))


_ASAN_ERR = re.compile(r"(?:ERROR: )?(AddressSanitizer|LeakSanitizer): ([^\n]+)")
_UBSAN_ERR = re.compile(r"runtime error: ([^\n]+)")
_UBSAN_LOC = re.compile(r"([\w./-]+\.(?:c|h)):(\d+)(?::(\d+))?: runtime error")
# GCC and clang both emit "#N 0xADDR in FUNC LOCATION"; LOCATION may end
# with " (module+0xoff)" or be a bare file:line.
_FRAME = re.compile(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s+(.+?)\s*$",
                    re.MULTILINE)
_SUMMARY = re.compile(r"SUMMARY: ([^\n]+)")
_FATAL = re.compile(r"[Ff]atal: ([^\n]+)|([Ss]egmentation fault)|[Aa]borted")


class CrashInfo:
    def __init__(self, kind, message, frames, summary, raw_report,
                 returncode, sig, log_path):
        self.kind = kind                    # asan / ubsan / segv / abort / timeout
        self.message = message
        self.frames = frames                # [(function, file:line), ...] normalized
        self.summary = summary
        self.raw_report = raw_report
        self.returncode = returncode
        self.signal = sig
        self.log_path = log_path
        self.signature = self._signature()

    def _signature(self) -> str:
        """Stable identity independent of pid/address, build path or exact
        line number. The bug *class* is (sanitizer, message, function call
        chain); line numbers shift across formats/modes but the chain does
        not, so we key on function names only."""
        # scrub volatile heap addresses and large numbers from the message
        msg = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", self.message)
        msg = re.sub(r"\b\d{4,}\b", "N", msg)
        code_frames = [fn for fn, loc in self.frames
                       if "spng" in loc or "harness" in loc or
                       "spng_read_fuzzer" in loc]
        if not code_frames:
            code_frames = [fn for fn, _ in self.frames[:4]]
        chain = "|".join(code_frames[:5])
        return f"{self.kind}:{msg[:80]}::{chain}"

    def to_dict(self) -> dict:
        return {"kind": self.kind, "message": self.message,
                "signature": self.signature, "frames": self.frames,
                "summary": self.summary, "returncode": self.returncode,
                "signal": self.signal}


def _parse_report(report: str, log_path: str, returncode: int,
                  sig: int | None, timed_out: bool) -> CrashInfo | None:
    if timed_out:
        return CrashInfo("timeout", "watchdog timeout, process killed",
                         [], "", report, returncode, sig, log_path)
    if not report.strip() and sig in (signal.SIGSEGV, signal.SIGABRT,
                                      signal.SIGBUS, signal.SIGILL):
        return CrashInfo("segv" if sig == signal.SIGSEGV else "abort",
                         f"signal {sig} without sanitizer report",
                         [], "", report, returncode, sig, log_path)

    kind, message = "abort", f"exit={returncode} signal={sig}"
    m = _ASAN_ERR.search(report)
    if m:
        kind, message = "asan", m.group(2).strip()
    else:
        m = _UBSAN_LOC.search(report)
        if m:
            kind = "ubsan"
            m2 = _UBSAN_ERR.search(report)
            message = m2.group(1).strip() if m2 else "undefined behavior"
        else:
            m = _FATAL.search(report)
            if m:
                kind, message = "abort", (m.group(1) or m.group(2) or
                                          m.group(3) or "fatal").strip()
            elif not report.strip():
                return None

    frames = []
    for fm in _FRAME.finditer(report):
        fn, loc = fm.group(1), fm.group(2).strip()
        # keep file:line portion only (drop column, module path and +0x)
        lm = re.match(r"([^\s(]+:\d+)", loc)
        frames.append((fn, lm.group(1) if lm else loc))
    # UBSan reports don't always print symbolized frames; anchor on the
    # diagnostic location instead.
    if not frames:
        lm = _UBSAN_LOC.search(report)
        if lm:
            loc = f"{lm.group(1)}:{lm.group(2)}"
            frames.append(("(ubsan)", loc))

    sm = _SUMMARY.search(report)
    return CrashInfo(kind, message, frames,
                     sm.group(1).strip() if sm else "", report,
                     returncode, sig, log_path)


class Worker:
    def __init__(self, logdir: str, timeout_s: float = 8.0):
        self.logdir = logdir
        self.timeout_s = timeout_s
        self.gen = 0
        self.proc = None
        self.logfile = None
        self._start()

    def _start(self):
        if self.proc is not None:
            try:
                self.proc.wait(timeout=0.1)
            except Exception:
                pass
        if self.logfile is not None:
            self.logfile.close()
        self.gen += 1
        log_path = os.path.join(self.logdir, f"worker_g{self.gen}.log")
        self.log_path = log_path
        self.logfile = open(log_path, "wb")
        env = dict(os.environ)
        env.update({
            # Leak detection disabled: the worker is intentionally long-lived,
            # so end-of-process leak checks would fire on live allocations.
            "ASAN_OPTIONS": ("abort_on_error=1:halt_on_error=1:"
                             "detect_leaks=0:symbolize=1:"
                             "allocator_may_return_null=1:"
                             "disable_coredump=1"),
            "UBSAN_OPTIONS": ("halt_on_error=1:print_stacktrace=1:"
                              "symbolize=1:abort_on_error=1"),
            "ASAN_SYMBOLIZER_PATH": "/usr/bin/llvm-symbolizer",
        })
        self.proc = subprocess.Popen(
            [WORKER], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.logfile, env=env, bufsize=0)

    def close(self):
        if self.proc is None:
            return
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=2.0)
        except Exception:
            self.proc.kill()
            self.proc.wait()
        self.logfile.close()
        self.proc = None

    def _read_exact(self, n, deadline):
        buf = bytearray()
        while len(buf) < n:
            if self.proc.poll() is not None:
                return None  # worker died; caller harvests the report
            remain = min(deadline - time.monotonic(), 0.1)
            if remain <= 0:
                return None
            r, _, _ = select.select([self.proc.stdout], [], [], remain)
            if not r:
                continue
            chunk = os.read(self.proc.stdout.fileno(), n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return bytes(buf)

    def run(self, data: bytes, retries: int = 3) -> CrashInfo | None:
        """Send one input. Returns None on clean decode, CrashInfo on crash.

        A watchdog timeout is retried on a fresh worker: timeouts from
        transient scheduler/load stalls are indistinguishable from a real
        hang on the first observation, so only an input that still times
        out after `retries` attempts is reported as a hang. This keeps
        results deterministic across machines with different load.
        """
        for attempt in range(retries):
            frame = len(data).to_bytes(4, "little") + data
            try:
                self.proc.stdin.write(frame)
                self.proc.stdin.flush()
            except (BrokenPipeError, OSError):
                return self._harvest(timed_out=False)

            deadline = time.monotonic() + self.timeout_s
            reply = self._read_exact(5, deadline)
            if reply is None:
                if self.proc.poll() is None:
                    # timed out: kill, harvest, respawn, then retry
                    self.proc.kill()
                    info = self._harvest(timed_out=True)
                    if attempt < retries - 1:
                        continue
                    return info
                return self._harvest(timed_out=False)

            if reply[0] != 1:  # protocol violation means harness-side bug
                return self._harvest(timed_out=False)
            return None
        return None

    def _harvest(self, timed_out: bool) -> CrashInfo:
        proc = self.proc
        try:
            proc.wait(timeout=2.0)
        except Exception:
            proc.kill()
            proc.wait()
        rc, sig = proc.returncode, None
        if rc is not None and rc < 0:
            sig = -rc
        self.logfile.flush()
        with open(self.log_path, "rb") as f:
            raw = f.read().decode("utf-8", "replace")
        info = _parse_report(raw, self.log_path, rc, sig, timed_out)
        if info is None:  # clean EOF without report shouldn't happen; treat as abort
            info = CrashInfo("abort", f"worker exited rc={rc}", [], "",
                             raw, rc, sig, self.log_path)
        self._start()
        return info
