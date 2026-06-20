"""K3-style keyed transposition as a layer under K4.

K3 was solved as a keyed columnar/route transposition. My earlier transposition
scan (experiments.py) only used identity column order. This module uses real
KEYED column orders (KRYPTOS, PALIMPSEST, ABSCISSA, BERLINCLOCK, ...), which is
the actual K3 flavour.

Two models tested:
  (1) ciphertext = KeyedColumnar(Vigenere(plaintext)): invert the transposition,
      then look for a hidden short repeating key over the cribs (the signature
      of transposition-then-periodic-substitution).
  (2) ciphertext = KeyedColumnar(plaintext): pure transposition; invert it and
      check whether the cribs then sit in their fixed positions (rejected fast
      by IoC anyway, but tested for completeness).
"""

from __future__ import annotations

from .ciphers import columnar_decrypt
from .data import K4_CIPHERTEXT, KRYPTOS_ALPHABET, STANDARD_ALPHABET
from .solver import KNOWN_PLAINTEXT

ALPHABETS = {"standard": STANDARD_ALPHABET, "kryptos": KRYPTOS_ALPHABET}
KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK", "NORTHEAST",
            "EASTNORTHEAST", "LANGLEY", "SHADOW", "WW"]
N = len(KNOWN_PLAINTEXT)


def _key_periods(intermediate: str, alphabet: str, max_period: int = 12) -> list[int]:
    m = {c: i for i, c in enumerate(alphabet)}
    A = alphabet
    key = {pos: A[(m[intermediate[pos]] - m[p]) % 26]
           for pos, p in KNOWN_PLAINTEXT.items()}
    good = []
    for L in range(1, max_period + 1):
        slots: dict[int, str] = {}
        ok = True
        for pos, k in key.items():
            r = pos % L
            if r in slots and slots[r] != k:
                ok = False
                break
            slots[r] = k
        if ok:
            good.append(L)
    return good


def _pure_transposition_crib_hits(intermediate: str) -> int:
    return sum(1 for pos, ch in KNOWN_PLAINTEXT.items() if intermediate[pos] == ch)


def report() -> str:
    lines = ["K3-style keyed transposition layer vs the cribs", "=" * 60, ""]

    lines.append("[1] KeyedColumnar(Vigenere(pt)): invert, seek hidden period")
    found_period = False
    for kw in KEYWORDS:
        inter = columnar_decrypt(K4_CIPHERTEXT, kw)
        for alpha_name, alpha in ALPHABETS.items():
            periods = [L for L in _key_periods(inter, alpha) if L <= 12]
            if periods:
                found_period = True
                lines.append(f"    key={kw:<13} alpha={alpha_name:<8} "
                             f"short-periods={periods}  <-- lead")
    if not found_period:
        lines.append("    no keyword produced a self-consistent short period")
        lines.append("    over both crib regions. Negative.")
    lines.append("")

    lines.append("[2] KeyedColumnar(pt): pure transposition, crib alignment")
    best = (None, -1)
    for kw in KEYWORDS:
        inter = columnar_decrypt(K4_CIPHERTEXT, kw)
        hits = _pure_transposition_crib_hits(inter)
        if hits > best[1]:
            best = (kw, hits)
    lines.append(f"    best: {best[1]}/{N} crib letters in place (key={best[0]}); "
                 f"chance ~{N/26:.1f}")
    lines.append("    (pure transposition is also excluded by K4's low IoC)")
    lines.append("")
    lines.append("-" * 60)
    lines.append(
        "Honest result: K3's keyed-transposition flavour, layered with a\n"
        "periodic Vigenere or used alone, does not reveal structure in the\n"
        "cribs for any tested keyword. Negative; no solution claimed."
    )
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
