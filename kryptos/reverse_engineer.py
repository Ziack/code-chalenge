"""Reverse-engineering attempt using the now-known plaintext.

With full plaintext P and ciphertext C we can test structural hypotheses
directly. The strongest published lead (numberworld.blog) is that K4 is a
TRANSPOSITION of a keyed-Vigenere encryption, with the transposition a linear
congruence y = (a + b*x) mod 97 (their a=77, b=38, from K2's coordinates).

Model tested:  C = Transpose( Vigenere_keyed(P, periodic_key) )
  => V[x] = C[(a + b*x) mod 97]      (undo the transposition)
  => keystream[x] = V[x] - P[x]      (the key that Vigenere would need)
If the model is right for some (a,b), that keystream is PERIODIC with a short
key. We search all (a,b) and report how periodic the best one gets. A score of
1.0 at a small period would be a genuine reverse-engineering of the cipher.
"""

from __future__ import annotations

from .data import K4_CIPHERTEXT, KRYPTOS_ALPHABET, STANDARD_ALPHABET
from .recovered import PLAINTEXT

N = 97
ALPHABETS = {"standard": STANDARD_ALPHABET, "kryptos": KRYPTOS_ALPHABET}


def _keystream(a: int, b: int, alphabet: str, mode: str) -> list[int]:
    m = {c: i for i, c in enumerate(alphabet)}
    ks = []
    for x in range(N):
        v = m[K4_CIPHERTEXT[(a + b * x) % N]]   # undo transposition -> V[x]
        p = m[PLAINTEXT[x]]
        if mode == "vigenere":            # V = P + K
            ks.append((v - p) % 26)
        else:                             # beaufort: V = K - P
            ks.append((v + p) % 26)
    return ks


def _best_period_score(ks: list[int], max_period: int = 24) -> tuple[int, float]:
    """Return (period, fraction-of-positions matching the majority key for that
    period), maximised over periods 1..max_period. 1.0 == perfectly periodic."""
    best = (0, 0.0)
    for L in range(1, max_period + 1):
        groups: list[dict[int, int]] = [dict() for _ in range(L)]
        for x, v in enumerate(ks):
            g = groups[x % L]
            g[v] = g.get(v, 0) + 1
        agree = sum(max(g.values()) for g in groups if g)
        score = agree / N
        if score > best[1]:
            best = (L, score)
    return best


def search() -> dict:
    overall = {"score": -1.0}
    for mode in ("vigenere", "beaufort"):
        for alpha_name, alpha in ALPHABETS.items():
            for a in range(N):
                for b in range(1, N):       # gcd(b,97)=1 always (97 prime)
                    ks = _keystream(a, b, alpha, mode)
                    L, score = _best_period_score(ks)
                    if score > overall["score"]:
                        overall = {"a": a, "b": b, "alpha": alpha_name,
                                   "mode": mode, "period": L, "score": score}
    return overall


def report() -> str:
    lines = ["Reverse-engineering K4 from known plaintext", "=" * 60, ""]

    # The specific numberworld transposition first.
    lines.append("numberworld's exact transposition y = 77 + 38x (mod 97):")
    for mode in ("vigenere", "beaufort"):
        for alpha_name, alpha in ALPHABETS.items():
            ks = _keystream(77, 38, alpha, mode)
            L, score = _best_period_score(ks)
            lines.append(f"  {mode:<9}/{alpha_name:<8} best period {L:>2}, "
                         f"periodicity {score:.0%}")
    lines.append("")

    lines.append("Best over ALL linear-congruence transpositions (a in 0..96,")
    lines.append("b in 1..96), both ciphers, both alphabets:")
    best = search()
    lines.append(f"  a={best['a']} b={best['b']} {best['mode']}/{best['alpha']} "
                 f"-> period {best['period']}, periodicity {best['score']:.0%}")
    lines.append("")
    lines.append("-" * 60)
    if best["score"] >= 0.99:
        lines.append("PERFECT periodicity found -- the cipher is reverse-")
        lines.append("engineered as transpose-then-keyed-Vigenere. Investigate.")
    else:
        # A random keystream scores ~ baseline; show it for context.
        lines.append(
            f"Even the best transposition leaves the key only {best['score']:.0%}\n"
            f"periodic -- nowhere near the ~100% a real repeating key would give.\n"
            f"So K4 is NOT a linear-congruence transposition of a periodic\n"
            f"Vigenere (numberworld's model included). The cipher resists this\n"
            f"reconstruction too -- consistent with a hand 'masking' system that\n"
            f"has no compact algorithmic description. Honest negative."
        )
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
