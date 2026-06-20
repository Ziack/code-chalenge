"""Identify viable vs dead solution PATHS for K4, in code.

Three diagnostics that each either opens or closes a class of cipher:

  A. IoC-by-period   -> is there a hidden periodic polyalphabetic (Vigenere)?
  B. Kasiski repeats -> do repeated n-grams reveal a period / transposition?
  C. Hill recovery   -> the cribs give aligned known plaintext<->ciphertext
                        digraphs; if K4 is a 2x2 Hill cipher, linear algebra
                        RECOVERS the key matrix outright and we decrypt it.

C is the most decisive: it is not a search but a solve. If a single invertible
key matrix is consistent with all crib digraphs, K4 is (that) Hill cipher.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from math import gcd

from .data import K4_CIPHERTEXT, STANDARD_ALPHABET
from .solver import KNOWN_PLAINTEXT

CT = K4_CIPHERTEXT
N = 97


# ----------------------------------------------------------------------------
# A. Index of coincidence per candidate period
# ----------------------------------------------------------------------------
def _ioc(s: str) -> float:
    n = len(s)
    if n < 2:
        return 0.0
    return sum(v * (v - 1) for v in Counter(s).values()) / (n * (n - 1))


def ioc_by_period(max_period: int = 24) -> list[tuple[int, float]]:
    out = []
    for L in range(1, max_period + 1):
        cols = ["".join(CT[i] for i in range(r, N, L)) for r in range(L)]
        avg = sum(_ioc(c) for c in cols) / L
        out.append((L, avg))
    return out


# ----------------------------------------------------------------------------
# B. Kasiski: repeated trigrams and the gcd of their spacings
# ----------------------------------------------------------------------------
def kasiski() -> tuple[dict[str, list[int]], list[int]]:
    pos = defaultdict(list)
    for i in range(N - 2):
        pos[CT[i:i + 3]].append(i)
    repeats = {g: ps for g, ps in pos.items() if len(ps) > 1}
    spacings = []
    for ps in repeats.values():
        for a, b in zip(ps, ps[1:]):
            spacings.append(b - a)
    return repeats, spacings


# ----------------------------------------------------------------------------
# C. Hill 2x2 key recovery from crib digraphs
# ----------------------------------------------------------------------------
def _v(ch: str) -> int:
    return STANDARD_ALPHABET.index(ch)


def _modinv(a: int, m: int = 26) -> int | None:
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def _det2(M):
    return (M[0][0] * M[1][1] - M[0][1] * M[1][0]) % 26


def _inv2(M):
    d = _det2(M)
    di = _modinv(d)
    if di is None:
        return None
    return [[(M[1][1] * di) % 26, (-M[0][1] * di) % 26],
            [(-M[1][0] * di) % 26, (M[0][0] * di) % 26]]


def _matmul2(A, B):
    return [[(A[0][0] * B[0][0] + A[0][1] * B[1][0]) % 26,
             (A[0][0] * B[0][1] + A[0][1] * B[1][1]) % 26],
            [(A[1][0] * B[0][0] + A[1][1] * B[1][0]) % 26,
             (A[1][0] * B[0][1] + A[1][1] * B[1][1]) % 26]]


def _matvec2(A, v):
    return ((A[0][0] * v[0] + A[0][1] * v[1]) % 26,
            (A[1][0] * v[0] + A[1][1] * v[1]) % 26)


def hill_digraphs(offset: int):
    """Even/odd-aligned blocks fully inside the crib runs: (plain, cipher) vecs."""
    pairs = []
    start = offset
    while start + 1 < N:
        a, b = start, start + 1
        if a in KNOWN_PLAINTEXT and b in KNOWN_PLAINTEXT:
            p = (_v(KNOWN_PLAINTEXT[a]), _v(KNOWN_PLAINTEXT[b]))
            c = (_v(CT[a]), _v(CT[b]))
            pairs.append((p, c))
        start += 2
    return pairs


def hill_recover():
    """Try to recover a single 2x2 key consistent with ALL crib digraphs,
    for both block alignments. Returns (key, alignment, agree, total) best."""
    best = (None, None, -1, 0)
    for offset in (0, 1):
        pairs = hill_digraphs(offset)
        total = len(pairs)
        for i in range(total):
            for j in range(i + 1, total):
                P = [[pairs[i][0][0], pairs[j][0][0]],
                     [pairs[i][0][1], pairs[j][0][1]]]
                C = [[pairs[i][1][0], pairs[j][1][0]],
                     [pairs[i][1][1], pairs[j][1][1]]]
                Pinv = _inv2(P)
                if Pinv is None:
                    continue
                K = _matmul2(C, Pinv)            # C = K P  ->  K = C Pinv
                agree = 0
                for (pp, cc) in pairs:
                    if _matvec2(K, pp) == cc:
                        agree += 1
                if agree > best[2]:
                    best = (K, offset, agree, total)
    return best


def report() -> str:
    lines = ["K4 solution-path diagnostics", "=" * 56, ""]

    # A
    lines.append("A. IoC by period (English ~0.066, random ~0.038):")
    rows = ioc_by_period()
    top = sorted(rows, key=lambda r: -r[1])[:5]
    for L, v in rows:
        mark = "  <-- elevated" if v >= 0.050 else ""
        lines.append(f"   period {L:>2}: {v:.4f}{mark}")
    lines.append(f"   best period: {top[0][0]} (IoC {top[0][1]:.4f}) -- "
                 f"{'PERIODIC POLYALPHABET likely' if top[0][1] >= 0.050 else 'no clear period; Vigenere path closed'}")
    lines.append("")

    # B
    repeats, spacings = kasiski()
    g = 0
    for s in spacings:
        g = gcd(g, s)
    lines.append("B. Kasiski repeated trigrams:")
    lines.append(f"   repeated trigrams: {len(repeats)}; spacings: {sorted(set(spacings))[:8]}...")
    lines.append(f"   gcd of spacings: {g} -- "
                 f"{'suggests period '+str(g) if g not in (0,1) else 'no useful period (transposition/long key)'}")
    lines.append("")

    # C
    K, offset, agree, total = hill_recover()
    lines.append("C. Hill 2x2 key recovery from crib digraphs (the decisive one):")
    lines.append(f"   aligned crib digraphs available: {total}")
    if K is not None:
        lines.append(f"   best key {K} (alignment offset {offset}) explains "
                     f"{agree}/{total} digraphs")
        if agree == total and total >= 3:
            lines.append("   FULL consistency -> K4 IS this Hill cipher. Decrypt & verify!")
        else:
            lines.append("   not all digraphs agree -> K4 is NOT a 2x2 Hill cipher.")
    lines.append("")
    lines.append("-" * 56)
    lines.append(
        "Path readout: periodic-Vigenere (A) and 2x2-Hill (C) are the two\n"
        "classes a clean diagnostic could have cracked outright. Both close\n"
        "below. Remaining live space is genuinely non-standard (masking /\n"
        "non-periodic), which no single diagnostic resolves."
    )
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
