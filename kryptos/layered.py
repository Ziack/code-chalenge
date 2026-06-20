"""Test the layered theory: K4 = Transposition( Vigenere(plaintext) ).

Uses the candidate plaintext as a working hypothesis (contingent on it being
genuine). If K4 wraps a periodic keyed-Vigenere inside a columnar transposition,
then un-transposing the ciphertext should expose a periodic keystream against
the plaintext. We sweep columnar transpositions (regular widths 2-24 and several
keyed orders), invert each, and measure how periodic the recovered key becomes.

This is the layered counterpart to reverse_engineer.py (which swept
linear-congruence transpositions). Together they cover the two transposition
families Kryptos actually uses.
"""

from __future__ import annotations

from .ciphers import columnar_decrypt
from .data import KRYPTOS_ALPHABET, STANDARD_ALPHABET, K4_CIPHERTEXT
from .recovered import PLAINTEXT

N = 97
ALPHABETS = {"standard": STANDARD_ALPHABET, "kryptos": KRYPTOS_ALPHABET}
KEYED = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK"]


def _period_score(intermediate: str, alphabet: str, max_period: int = 24):
    """Best (period, fraction-periodic) of the keystream intermediate-PLAINTEXT."""
    m = {c: i for i, c in enumerate(alphabet)}
    ks = [(m[intermediate[i]] - m[PLAINTEXT[i]]) % 26 for i in range(N)]
    best = (0, 0.0)
    for L in range(1, max_period + 1):
        groups = [dict() for _ in range(L)]
        for x, v in enumerate(ks):
            groups[x % L][v] = groups[x % L].get(v, 0) + 1
        agree = sum(max(g.values()) for g in groups if g)
        if agree / N > best[1]:
            best = (L, agree / N)
    return best


def sweep():
    results = []
    # regular columnar widths (key = ABCDE... of that width)
    for w in range(2, 25):
        key = "".join(chr(ord("A") + i) for i in range(w))
        inter = columnar_decrypt(K4_CIPHERTEXT, key)
        for aname, alpha in ALPHABETS.items():
            L, frac = _period_score(inter, alpha)
            results.append((frac, L, f"width-{w}/{aname}"))
    # keyed columnar orders
    for kw in KEYED:
        inter = columnar_decrypt(K4_CIPHERTEXT, kw)
        for aname, alpha in ALPHABETS.items():
            L, frac = _period_score(inter, alpha)
            results.append((frac, L, f"keyed-{kw}/{aname}"))
    # and the identity (no transposition) as baseline
    for aname, alpha in ALPHABETS.items():
        L, frac = _period_score(K4_CIPHERTEXT, alpha)
        results.append((frac, L, f"NO-transpose/{aname}"))
    return sorted(results, key=lambda r: -r[0])


def report() -> str:
    lines = ["Layered test: Transposition(Vigenere(plaintext)) ?", "=" * 56,
             "(uses candidate plaintext; periodicity 1.00 = clean recovery)", ""]
    res = sweep()
    lines.append("Top 8 by recovered-key periodicity:")
    for frac, L, desc in res[:8]:
        lines.append(f"  {frac:5.0%} at period {L:<2}  {desc}")
    lines.append("")
    lines.append("-" * 56)
    best = res[0][0]
    if best >= 0.99:
        lines.append("CLEAN periodic key recovered under a transposition ->")
        lines.append("layered structure FOUND. Re-encrypt to confirm.")
    else:
        lines.append(
            f"Best periodicity {best:.0%} -- far from a clean repeating key. No\n"
            f"columnar transposition exposes a periodic Vigenere underneath, and\n"
            f"(reverse_engineer.py) no linear-congruence one does either. So even\n"
            f"as a two-layer transpose+Vigenere, K4 does not reduce: the\n"
            f"substitution layer is itself structureless. Layering is real\n"
            f"(masking), but the layers compose to a keystream with no period to\n"
            f"recover -- which is why the cribs cannot peel them."
        )
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
