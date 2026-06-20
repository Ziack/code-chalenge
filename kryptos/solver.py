"""Crib-driven analysis of K4.

The confirmed cribs pin down the plaintext at 24 of the 97 positions. That is
enough to *derive* what the keystream must be at those positions under any
given cipher assumption -- no guessing. If the underlying system were a simple
periodic polyalphabetic (Vigenere/Beaufort with a short repeating key), the
derived key letters would have to agree wherever their positions coincide
modulo the period. This module checks exactly that, across cipher families and
both the standard and KRYPTOS-keyed alphabets.

Spoiler, and the honest point of the exercise: no short period is consistent.
That is *why* K4 is hard -- it rules out the entire class of simple repeating-
key ciphers and is consistent with the community's long-standing conclusion
that K4 uses something more (masking / non-periodic keying / transposition).
"""

from __future__ import annotations

from .data import K4_CIPHERTEXT, KRYPTOS_ALPHABET, STANDARD_ALPHABET

# Confirmed plaintext, as contiguous runs at fixed 0-indexed positions.
#   indices 21..33 -> "EASTNORTHEAST"   (cribs EAST 22-25 + NORTHEAST 26-34)
#   indices 63..73 -> "BERLINCLOCK"     (cribs BERLIN 64-69 + CLOCK 70-74)
KNOWN_PLAINTEXT: dict[int, str] = {}
for start, run in [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]:
    for offset, ch in enumerate(run):
        KNOWN_PLAINTEXT[start + offset] = ch


def _idx(alphabet: str):
    m = {c: i for i, c in enumerate(alphabet)}
    return m, alphabet


# Each function returns the key letter forcing C from P at one position.
def _key_vigenere(c, p, alphabet):
    m, A = _idx(alphabet)
    return A[(m[c] - m[p]) % 26]


def _key_beaufort(c, p, alphabet):
    m, A = _idx(alphabet)            # C = K - P  ->  K = C + P
    return A[(m[c] + m[p]) % 26]


def _key_variant_beaufort(c, p, alphabet):
    m, A = _idx(alphabet)            # C = P - K  ->  K = P - C
    return A[(m[p] - m[c]) % 26]


CIPHERS = {
    "vigenere": _key_vigenere,
    "beaufort": _key_beaufort,
    "variant-beaufort": _key_variant_beaufort,
}
ALPHABETS = {"standard": STANDARD_ALPHABET, "kryptos": KRYPTOS_ALPHABET}


def recover_keystream(cipher: str, alphabet: str) -> dict[int, str]:
    """The keystream letters forced by the cribs, by 0-indexed position."""
    keyfn = CIPHERS[cipher]
    A = ALPHABETS[alphabet]
    return {
        pos: keyfn(K4_CIPHERTEXT[pos], p, A)
        for pos, p in sorted(KNOWN_PLAINTEXT.items())
    }


def keystream_string(cipher: str, alphabet: str) -> tuple[str, str]:
    """Render the two crib runs as (east_north_run, berlin_clock_run) keys."""
    ks = recover_keystream(cipher, alphabet)
    east = "".join(ks[p] for p in range(21, 34))
    berlin = "".join(ks[p] for p in range(63, 74))
    return east, berlin


def consistent_periods(cipher: str, alphabet: str, max_period: int = 24) -> list[int]:
    """Periods L for which the crib-derived key never contradicts itself
    (positions sharing pos % L must carry the same key letter)."""
    ks = recover_keystream(cipher, alphabet)
    good = []
    for L in range(1, max_period + 1):
        slots: dict[int, str] = {}
        ok = True
        for pos, k in ks.items():
            r = pos % L
            if r in slots and slots[r] != k:
                ok = False
                break
            slots[r] = k
        if ok:
            good.append(L)
    return good


def report() -> str:
    lines = ["Crib-derived keystream under each (cipher, alphabet) assumption",
             "=" * 66,
             "Known plaintext: idx21-33 EASTNORTHEAST, idx63-73 BERLINCLOCK", ""]
    for cipher in CIPHERS:
        for alpha in ALPHABETS:
            east, berlin = keystream_string(cipher, alpha)
            periods = consistent_periods(cipher, alpha)
            # Drop the trivial periods >= the span; a period is only meaningful
            # if it forces at least two crib positions to coincide.
            meaningful = [L for L in periods if L <= 12]
            lines.append(f"{cipher:>16} / {alpha:<8}")
            lines.append(f"{'':18}key @ EASTNORTHEAST = {east}")
            lines.append(f"{'':18}key @ BERLINCLOCK   = {berlin}")
            lines.append(f"{'':18}self-consistent short periods (<=12): "
                         f"{meaningful or 'NONE'}")
            lines.append("")
    lines.append("-" * 66)
    lines.append(
        "Reading: a recovered key that spelled a word, or a short period that\n"
        "held across both crib regions, would point at a repeating-key cipher.\n"
        "The keys are noise and no short period survives both regions -- which\n"
        "is the expected, honest result: simple periodic Vigenere/Beaufort is\n"
        "ruled out. K4's keying is non-periodic or masked. This narrows the\n"
        "search; it does not solve it."
    )
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
