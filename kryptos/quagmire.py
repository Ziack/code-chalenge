"""Faithful Quagmire III, tested against the K4 cribs.

Claim under test: K4 yields to a Quagmire III (keyed plaintext + keyed
ciphertext alphabets from KRYPTOS, plus a keyword). The numberworld lead used
keyword EMUFPHZLRFA (the first 11 letters of K1's ciphertext). We implement
Quagmire III with a free alignment offset and sweep candidate keywords, scoring
each decryption against the 24 cribs. A real reconstruction hits 24/24; the
known numberworld result is only a partial coincidence near BERLIN.

Quagmire III decrypt (in keyed-alphabet index space):
    P = KA[(KA.index(C) - KA.index(keyletter) + offset) mod 26]
The offset is the tableau alignment ("helper strip" setting) and is swept.
"""

from __future__ import annotations

from .data import KRYPTOS_ALPHABET, K4_CIPHERTEXT
from .solver import KNOWN_PLAINTEXT

KA = KRYPTOS_ALPHABET
KAI = {c: i for i, c in enumerate(KA)}
N = 97
KNOWN = len(KNOWN_PLAINTEXT)

KEYWORDS = [
    "EMUFPHZLRFA",      # numberworld: first 11 of K1 ciphertext
    "PALIMPSEST", "ABSCISSA", "KRYPTOS",
    "BERLINCLOCK", "BERLIN", "CLOCK",
    "IQLUSION", "UNDERGRUUND", "DESPARATLY",
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ",   # longer K1-ciphertext prefix
]


def quag3_decrypt(ct: str, keyword: str, offset: int) -> str:
    out = []
    for i, c in enumerate(ct):
        k = keyword[i % len(keyword)]
        out.append(KA[(KAI[c] - KAI[k] + offset) % 26])
    return "".join(out)


def crib_hits(pt: str) -> int:
    return sum(1 for pos, ch in KNOWN_PLAINTEXT.items() if pt[pos] == ch)


def berlin_region(pt: str) -> str:
    return pt[63:74]   # should read BERLINCLOCK for a true solution


def report() -> str:
    lines = ["Quagmire III vs K4 cribs (claim under test)", "=" * 56,
             f"chance ~ {KNOWN/26:.1f}/{KNOWN}; full solution = {KNOWN}/{KNOWN}", ""]
    best = (-1, None, None, None)
    for kw in KEYWORDS:
        for off in range(26):
            pt = quag3_decrypt(K4_CIPHERTEXT, kw, off)
            h = crib_hits(pt)
            if h > best[0]:
                best = (h, kw, off, pt)
    lines.append("Best configuration found:")
    h, kw, off, pt = best
    lines.append(f"  key={kw} offset={off} -> {h}/{KNOWN} crib hits")
    lines.append(f"  BERLIN region (idx63-73) reads: {berlin_region(pt)}  "
                 f"(target BERLINCLOCK)")
    lines.append("")

    # Specifically report the numberworld keyword's best, and its BERLIN region.
    nb_best = (-1, None, None)
    for off in range(26):
        pt = quag3_decrypt(K4_CIPHERTEXT, "EMUFPHZLRFA", off)
        h = crib_hits(pt)
        if h > nb_best[0]:
            nb_best = (h, off, pt)
    lines.append("numberworld keyword EMUFPHZLRFA, best offset:")
    lines.append(f"  {nb_best[0]}/{KNOWN} crib hits @offset {nb_best[1]}; "
                 f"BERLIN region = {berlin_region(nb_best[2])}")
    lines.append("")
    lines.append("-" * 56)
    if best[0] == KNOWN:
        lines.append("FULL crib match -> verify by re-encrypting to OBKRUOXOG...")
    else:
        lines.append(
            f"Best {best[0]}/{KNOWN} ~ chance. Quagmire III (any swept keyword/\n"
            f"offset) does NOT key the cribs. The 'mechanism reconstructed'\n"
            f"claim does not survive the crib test -- at most it reproduces an\n"
            f"isolated fragment, which is the known numberworld coincidence, not\n"
            f"a solution."
        )
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
