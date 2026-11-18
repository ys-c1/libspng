"""Deterministic PRNG (xoshiro256**) so runs are reproducible without
relying on Python's version-specific random module internals."""


class Rng:
    def __init__(self, seed: int):
        # SplitMix64 seeding, same reference algorithm everywhere.
        state = []
        x = seed & 0xFFFFFFFFFFFFFFFF
        for _ in range(4):
            x = (x + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
            z = x
            z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
            z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
            z = z ^ (z >> 31)
            state.append(z)
        self.s = state

    def next_u64(self) -> int:
        s = self.s
        result = (s[1] * 5) & 0xFFFFFFFFFFFFFFFF
        result = ((result << 7) | (result >> 57)) & 0xFFFFFFFFFFFFFFFF
        result = (result * 9) & 0xFFFFFFFFFFFFFFFF

        t = (s[1] << 17) & 0xFFFFFFFFFFFFFFFF
        s[2] ^= s[0]
        s[3] ^= s[1]
        s[1] ^= s[2]
        s[0] ^= s[3]
        s[2] ^= t
        s[3] = ((s[3] << 45) | (s[3] >> 19)) & 0xFFFFFFFFFFFFFFFF
        return result

    def below(self, n: int) -> int:
        """Uniform integer in [0, n) for n > 0."""
        if n <= 0:
            raise ValueError("n must be positive")
        return self.next_u64() % n

    def randrange(self, lo: int, hi: int) -> int:
        """Uniform integer in [lo, hi]."""
        if hi < lo:
            raise ValueError("empty range")
        return lo + self.below(hi - lo + 1)

    def choice(self, seq):
        return seq[self.below(len(seq))]

    def chance(self, p: float) -> bool:
        return self.next_u64() < int(p * (1 << 64))

    def bytes(self, n: int) -> bytes:
        out = bytearray(n)
        i = 0
        while i + 8 <= n:
            out[i:i + 8] = self.next_u64().to_bytes(8, "little")
            i += 8
        if i < n:
            out[i:] = self.next_u64().to_bytes(8, "little")[:n - i]
        return bytes(out)
