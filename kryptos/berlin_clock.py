"""Berlin Clock (Mengenlehreuhr) base-5 keying tests.

Sanborn confirmed "BERLIN...CLOCK" points at the Mengenlehreuhr, which encodes
time in base-5 lamp rows. This module tests concrete base-5 keystreams against
the cribs, including the EXACT period-5 seeds from the original submitted
hypothesis (segmented_modulo5_seeds = [12,2,4,3,16], base_clock_multiplier 4),
so that idea gets a fair, direct test rather than a hand-wave.

Success criterion: a keystream that decrypts all 24 crib positions to their
known plaintext. Anything less is reported as the honest near-miss it is.
"""

from __future__ import annotations

from .data import K4_CIPHERTEXT, KRYPTOS_ALPHABET, STANDARD_ALPHABET
from .solver import KNOWN_PLAINTEXT

ALPHABETS = {"standard": STANDARD_ALPHABET, "kryptos": KRYPTOS_ALPHABET}
N = len(KNOWN_PLAINTEXT)


def _crib_hits(keystream: list[int], alphabet: str, mode: str) -> int:
    """How many crib positions decrypt correctly under the given integer
    keystream and cipher mode."""
    m = {c: i for i, c in enumerate(alphabet)}
    A = alphabet
    hits = 0
    for pos, p in KNOWN_PLAINTEXT.items():
        c = m[K4_CIPHERTEXT[pos]]
        k = keystream[pos] % 26
        if mode == "vigenere":            # P = C - K
            dec = (c - k) % 26
        elif mode == "beaufort":          # P = K - C
            dec = (k - c) % 26
        elif mode == "variant-beaufort":  # P = C + K
            dec = (c + k) % 26
        else:
            raise ValueError(mode)
        if A[dec] == p:
            hits += 1
    return hits


def _mengenlehreuhr_lamps(t: int) -> int:
    """Total lit lamps when the clock shows t minutes past midnight.
    Rows: 5h(4)+1h(4)+5m(11)+1m(4). One concrete base-5 reading."""
    h, mnt = (t // 60) % 24, t % 60
    return (h // 5) + (h % 5) + (mnt // 5) + (mnt % 5)


def candidate_keystreams() -> dict[str, list[int]]:
    seeds = [12, 2, 4, 3, 16]          # segmented_modulo5_seeds (verbatim)
    mult = 4                           # base_clock_multiplier
    streams = {
        "seeds_period5": [seeds[i % 5] for i in range(97)],
        "seeds_period5_x4": [(seeds[i % 5] * mult) for i in range(97)],
        "lamps_by_minute": [_mengenlehreuhr_lamps(i) for i in range(97)],
        "lamps_x4": [_mengenlehreuhr_lamps(i) * mult for i in range(97)],
        "base5_digitsum": [sum(int(d) for d in _base5(i)) for i in range(97)],
        "i_mod5_x4": [(i % 5) * mult for i in range(97)],
    }
    return streams


def _base5(n: int) -> str:
    if n == 0:
        return "0"
    out = []
    while n:
        out.append(str(n % 5))
        n //= 5
    return "".join(reversed(out))


def report() -> str:
    lines = ["Berlin Clock / base-5 keying vs the cribs", "=" * 60,
             f"crib positions: {N}; chance ~{N/26:.1f}/{N}", ""]
    best = (None, -1)
    for name, ks in candidate_keystreams().items():
        for alpha_name, alpha in ALPHABETS.items():
            for mode in ("vigenere", "beaufort", "variant-beaufort"):
                hits = _crib_hits(ks, alpha, mode)
                if hits > best[1]:
                    best = (f"{name} / {alpha_name} / {mode}", hits)
                if hits >= 6:  # only surface anything notably above chance
                    lines.append(f"    {hits:>2}/{N}  {name} / {alpha_name} / {mode}")
    if best[1] < 6:
        lines.append("    (nothing rose meaningfully above chance)")
    lines.append("")
    lines.append("-" * 60)
    label, hits = best
    if hits == N:
        lines.append(f"FULL MATCH: {label} -- investigate.")
    else:
        lines.append(
            f"Best: {hits}/{N}  ({label}) vs chance ~{N/26:.1f}.\n"
            f"The submitted mod-5 seeds and the natural base-5 clock keystreams\n"
            f"do not key the cribs under any tested cipher/alphabet. Honest\n"
            f"negative: the Berlin-Clock base-5 idea, in these direct forms,\n"
            f"does not unlock K4."
        )
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
