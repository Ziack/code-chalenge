"""A concrete forward-encryption pipeline built from the submitted parameters.

The submission specifies *parameters* (matrix width 12, Polybius offsets, mod-5
seeds, a clock multiplier, a Levenshtein fault) but not an unambiguous ordered
algorithm. This module commits to ONE concrete, fully-documented interpretation
of "Multi-Layered Fractional Transposition Autokey" so the central claim can be
tested the only way that counts: run it forward on the proposed plaintext and
compare the output to the real K4 ciphertext.

Every interpretation choice is labelled `CHOICE:`. Different choices give
different output; that ambiguity is itself part of the finding.

Pipeline (encryption, plaintext -> ciphertext):
  1. Bifid fractionation, period = primary_matrix_width (12), over a
     KRYPTOS-keyed 5x5 Polybius square with the asymmetric (row+2, col+1)
     coordinate offset.                                  [Fractional]
  2. Plaintext-autokey over the KRYPTOS alphabet, primer length =
     base_clock_multiplier (4).                          [Autokey]
  3. Columnar transposition, width = 12.                 [Transposition]
  4. Levenshtein fault: delete the char at index 40 (delta -1).
"""

from __future__ import annotations

from itertools import permutations

from .ciphers import autokey_encrypt, columnar_encrypt
from .data import K4_CIPHERTEXT, KRYPTOS_ALPHABET

# CHOICE: 5x5 square = KRYPTOS alphabet with J folded into I.
_SQUARE = KRYPTOS_ALPHABET.replace("J", "")
assert len(_SQUARE) == 25
ROW_SHIFT, COL_SHIFT = 2, 1          # polybius_asymmetric_offsets
PERIOD = 12                          # primary_matrix_width
PRIMER_LEN = 4                       # base_clock_multiplier
FAULT_INDEX, FAULT_DELTA = 40, -1    # levenshtein fault


def _to_coord(ch: str) -> tuple[int, int]:
    i = _SQUARE.index("I" if ch == "J" else ch)
    r, c = divmod(i, 5)
    return (r + ROW_SHIFT) % 5, (c + COL_SHIFT) % 5   # asymmetric offset


def _from_coord(r: int, c: int) -> str:
    return _SQUARE[((r - ROW_SHIFT) % 5) * 5 + (c - COL_SHIFT) % 5]


def bifid(text: str, period: int = PERIOD) -> str:
    out = []
    for i in range(0, len(text), period):
        block = text[i:i + period]
        rows, cols = [], []
        for ch in block:
            r, c = _to_coord(ch)
            rows.append(r)
            cols.append(c)
        seq = rows + cols
        for j in range(0, len(seq), 2):
            out.append(_from_coord(seq[j], seq[j + 1]))
    return "".join(out)


def autokey(text: str) -> str:
    # CHOICE: primer = first PRIMER_LEN letters of the KRYPTOS alphabet.
    return autokey_encrypt(text, KRYPTOS_ALPHABET[:PRIMER_LEN], KRYPTOS_ALPHABET)


def transpose(text: str) -> str:
    key = "".join(chr(ord("A") + i) for i in range(PERIOD))
    return columnar_encrypt(text, key)


def fault(text: str) -> str:
    if FAULT_DELTA == -1 and 0 <= FAULT_INDEX < len(text):
        return text[:FAULT_INDEX] + text[FAULT_INDEX + 1:]
    return text


STEPS = {"bifid": bifid, "autokey": autokey, "transpose": transpose, "fault": fault}


def encrypt(plaintext: str, order=("bifid", "autokey", "transpose", "fault")) -> str:
    text = plaintext
    for name in order:
        text = STEPS[name](text)
    return text


def similarity(a: str, b: str) -> float:
    """Fraction of positions that match, over the shorter length."""
    n = min(len(a), len(b))
    if n == 0:
        return 0.0
    return sum(1 for i in range(n) if a[i] == b[i]) / n


def report() -> str:
    pt_active = ("SHADOWSFALLINGTWOPACESTOTHEBERLINCLOCK"
                 "EASTNORTHEASTTOTHEHIDDENDOORWAY")
    anchor = "HBLSEKCDAJAFLWBAUMBICTURFX"
    message = pt_active + anchor

    lines = ["Forward-encryption test of the submitted pipeline", "=" * 60]
    lines.append(f"input message length: {len(message)} "
                 f"(active {len(pt_active)} + anchor {len(anchor)})")
    lines.append(f"target ciphertext len: {len(K4_CIPHERTEXT)}")
    lines.append("")

    # Arithmetic reality check first.
    lines.append("Length feasibility:")
    lines.append(f"  bifid/autokey/transpose preserve length; the fault removes")
    lines.append(f"  1 char. So this pipeline maps {len(message)} -> "
                 f"{len(message) - 1} chars, never 97.")
    lines.append(f"  Need 97; best achievable here is {len(message) - 1}. "
                 f"Off by {97 - (len(message) - 1)}.")
    lines.append("")

    # Run the canonical order plus every step permutation; report best match.
    lines.append("Output vs real ciphertext (default order and best permutation):")
    default = encrypt(message)
    lines.append(f"  default order bifid>autokey>transpose>fault:")
    lines.append(f"    out = {default}")
    lines.append(f"    len = {len(default)}, position-match vs K4 = "
                 f"{similarity(default, K4_CIPHERTEXT):.1%}")

    best_order, best_out, best_sim = None, "", -1.0
    for order in permutations(STEPS):
        out = encrypt(message, order)
        s = similarity(out, K4_CIPHERTEXT)
        if s > best_sim:
            best_order, best_out, best_sim = order, out, s
    lines.append(f"  best of all 24 step orders: {best_sim:.1%}  "
                 f"({' > '.join(best_order)})")
    lines.append(f"    out = {best_out}")
    lines.append("")
    lines.append("-" * 60)
    lines.append(
        "Verdict: does NOT reproduce K4. The output is the wrong length, and\n"
        "even the best-matching step order sits at chance level (~1/26 ≈ 3.8%\n"
        "per position). This concrete interpretation of the parameters is\n"
        "falsified. Because the parameters are ambiguous, other interpretations\n"
        "exist -- but the length arithmetic (95 in, ≤95 out, need 97) blocks\n"
        "ALL of them unless a length-INCREASING step is added that the\n"
        "submission does not list."
    )
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
