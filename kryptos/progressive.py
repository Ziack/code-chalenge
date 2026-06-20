"""Non-standard path 1: a PROGRESSIVE (position-dependent) key.

If K4's key evolves with position rather than repeating, every period test
fails by construction. Test whether the key the cribs force fits a simple
function of position i:
    linear:    key(i) = (a + b*i)          mod 26
    quadratic: key(i) = (a + b*i + c*i^2)  mod 26
We fit a,b,c exhaustively (mod 26) and score against the 24 cribs. A full 24/24
fit means the keystream IS that progression -> reconstruct and verify.
"""

from __future__ import annotations

from .data import K4_CIPHERTEXT, KRYPTOS_ALPHABET, STANDARD_ALPHABET
from .solver import KNOWN_PLAINTEXT

ALPHABETS = {"standard": STANDARD_ALPHABET, "kryptos": KRYPTOS_ALPHABET}
KNOWN = len(KNOWN_PLAINTEXT)
ITEMS = sorted(KNOWN_PLAINTEXT)


def _required_key(mode: str, alphabet: str) -> dict[int, int]:
    m = {c: i for i, c in enumerate(alphabet)}
    out = {}
    for pos, p in KNOWN_PLAINTEXT.items():
        c, pv = m[K4_CIPHERTEXT[pos]], m[p]
        out[pos] = (c - pv) % 26 if mode == "vigenere" else (c + pv) % 26
    return out


def fit_linear(req):
    best = (-1, None)
    for a in range(26):
        for b in range(26):
            hits = sum(1 for i in ITEMS if (a + b * i) % 26 == req[i])
            if hits > best[0]:
                best = (hits, (a, b))
    return best


def fit_quadratic(req):
    best = (-1, None)
    for a in range(26):
        for b in range(26):
            for c in range(26):
                hits = sum(1 for i in ITEMS if (a + b * i + c * i * i) % 26 == req[i])
                if hits > best[0]:
                    best = (hits, (a, b, c))
    return best


def report() -> str:
    lines = ["Non-standard path 1: progressive (position-dependent) key",
             "=" * 58, f"crib positions: {KNOWN}; full fit = {KNOWN}/{KNOWN}", ""]
    overall = (-1, None)
    for mode in ("vigenere", "beaufort"):
        for aname, alpha in ALPHABETS.items():
            req = _required_key(mode, alpha)
            lh, lc = fit_linear(req)
            qh, qc = fit_quadratic(req)
            lines.append(f"{mode:<9}/{aname:<8}  linear best {lh:>2}/{KNOWN} "
                         f"(a,b)={lc}   quad best {qh:>2}/{KNOWN} (a,b,c)={qc}")
            overall = max(overall, (lh, f"linear {mode}/{aname}"),
                          (qh, f"quad {mode}/{aname}"), key=lambda t: t[0])
    lines.append("")
    lines.append("-" * 58)
    if overall[0] == KNOWN:
        lines.append(f"FULL fit via {overall[1]} -- progressive key found. "
                     f"Reconstruct keystream and re-encrypt to verify.")
    else:
        lines.append(
            f"Best {overall[0]}/{KNOWN} ({overall[1]}) -- below a clean fit.\n"
            f"The key is not a linear or quadratic function of position. A simple\n"
            f"progressive key does not explain K4 either. (Higher-degree fits\n"
            f"would trivially overfit 24 points and prove nothing.)"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
