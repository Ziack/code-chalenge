"""Non-standard hypothesis: a PERIODIC cipher hidden by one deliberate indel.

Motivation: K1-K3 each contain a deliberate misspelling. If K4's keystream has
one inserted/deleted position (Levenshtein distance 1), a true short period
would look broken to every periodic test (which is what we observed). This
module searches for a period that becomes self-consistent once a single slip is
allowed.

Model: key index at ciphertext position i is
    idx(i) = i + (delta if i >= slip else 0)      delta in {+1, -1}
    residue = idx(i) mod L
For each (cipher, alphabet, period L, slip position, delta), the 24 crib-derived
key letters must agree within each residue class. A CLEAN fit at small L would
mean: K4 = Vigenere/Beaufort period L + one indel -> a real structural lead.
We also try TWO slips (two deliberate faults).
"""

from __future__ import annotations

from collections import defaultdict
from itertools import combinations

from .data import K4_CIPHERTEXT, KRYPTOS_ALPHABET, STANDARD_ALPHABET
from .solver import KNOWN_PLAINTEXT

ALPHABETS = {"standard": STANDARD_ALPHABET, "kryptos": KRYPTOS_ALPHABET}
N = 97
KNOWN = len(KNOWN_PLAINTEXT)
CRIBS = sorted(KNOWN_PLAINTEXT)


def _required_key(mode: str, alphabet: str) -> dict[int, int]:
    m = {c: i for i, c in enumerate(alphabet)}
    out = {}
    for pos, p in KNOWN_PLAINTEXT.items():
        c, pv = m[K4_CIPHERTEXT[pos]], m[p]
        out[pos] = (c - pv) % 26 if mode == "vigenere" else (c + pv) % 26
    return out


def _agreement(residue_of, req: dict[int, int], L: int) -> int:
    """Max crib positions satisfiable: sum over residue classes of the size of
    the largest agreeing subset."""
    groups: dict[int, list[int]] = defaultdict(list)
    for pos in CRIBS:
        groups[residue_of(pos) % L].append(req[pos])
    total = 0
    for vals in groups.values():
        total += max(vals.count(v) for v in set(vals))
    return total


def search_one_slip(max_period: int = 16):
    best = {"agree": -1}
    for mode in ("vigenere", "beaufort"):
        for aname, alpha in ALPHABETS.items():
            req = _required_key(mode, alpha)
            for L in range(2, max_period + 1):
                for slip in range(0, N + 1):
                    for delta in (+1, -1):
                        f = lambda i, s=slip, d=delta: i + (d if i >= s else 0)
                        a = _agreement(f, req, L)
                        if a > best["agree"]:
                            best = {"agree": a, "mode": mode, "alpha": aname,
                                    "L": L, "slips": [(slip, delta)]}
    return best


def search_two_slips(max_period: int = 12):
    best = {"agree": -1}
    for mode in ("vigenere", "beaufort"):
        for aname, alpha in ALPHABETS.items():
            req = _required_key(mode, alpha)
            for L in range(2, max_period + 1):
                # restrict slip positions to a coarse grid for speed
                grid = list(range(0, N + 1, 2))
                for s1, s2 in combinations(grid, 2):
                    for d1 in (+1, -1):
                        for d2 in (+1, -1):
                            def f(i, s1=s1, s2=s2, d1=d1, d2=d2):
                                return i + (d1 if i >= s1 else 0) + (d2 if i >= s2 else 0)
                            a = _agreement(f, req, L)
                            if a > best["agree"]:
                                best = {"agree": a, "mode": mode, "alpha": aname,
                                        "L": L, "slips": [(s1, d1), (s2, d2)]}
    return best


def baseline_no_slip(max_period: int = 16) -> int:
    best = 0
    for mode in ("vigenere", "beaufort"):
        for alpha in ALPHABETS.values():
            req = _required_key(mode, alpha)
            for L in range(2, max_period + 1):
                best = max(best, _agreement(lambda i: i, req, L))
    return best


def report() -> str:
    lines = ["Levenshtein hypothesis: periodic cipher + deliberate indel(s)",
             "=" * 60, f"crib positions: {KNOWN}; a CLEAN fit needs {KNOWN}/{KNOWN}",
             ""]
    base = baseline_no_slip()
    lines.append(f"baseline (no slip), best agreement over periods 2-16: "
                 f"{base}/{KNOWN}")
    one = search_one_slip()
    lines.append(f"one slip:  {one['agree']}/{KNOWN}  "
                 f"(period {one['L']}, {one['mode']}/{one['alpha']}, "
                 f"slip {one['slips']})")
    two = search_two_slips()
    lines.append(f"two slips: {two['agree']}/{KNOWN}  "
                 f"(period {two['L']}, {two['mode']}/{two['alpha']}, "
                 f"slips {two['slips']})")
    lines.append("")
    lines.append("-" * 60)
    if max(one["agree"], two["agree"]) == KNOWN:
        lines.append("CLEAN periodic fit recovered via indel(s) -- strong lead.")
        lines.append("Reconstruct the full keystream and re-encrypt to verify.")
    else:
        gain = max(one["agree"], two["agree"]) - base
        lines.append(
            f"Allowing 1-2 indels lifts the best fit from {base} to "
            f"{max(one['agree'], two['agree'])}/{KNOWN} (+{gain}).\n"
            f"That gain is what you'd expect from extra free parameters, not a\n"
            f"recovered period -- no clean fit emerges. The Levenshtein idea is\n"
            f"sound and worth trying, but a single/double indel does NOT unmask a\n"
            f"short period in K4. (A real deliberate typo would more likely live\n"
            f"in the PLAINTEXT, like K1-K3, not in the keystream.)"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
