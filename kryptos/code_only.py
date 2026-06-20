"""Strictly-code analysis: what do ciphertext + cribs mathematically determine?

Inputs allowed here are ONLY the math of the problem:
  - the 97-character K4 ciphertext, and
  - the 24 plaintext positions fixed by Sanborn's released cribs.
No external "solution" text is used.

This module states the formal result: given only these inputs, the plaintext is
UNDERDETERMINED, and quantifies by how much. It also recaps that every cipher
family we implemented (solver/experiments/running_key/.../reverse_engineer)
failed to impose extra structure -- which is *why* code alone cannot output the
remaining 73 characters.
"""

from __future__ import annotations

from math import log10

from .data import K4_CIPHERTEXT
from .solver import KNOWN_PLAINTEXT  # 24 crib-fixed positions {index: letter}

N = 97
KNOWN = len(KNOWN_PLAINTEXT)          # 24
UNKNOWN = N - KNOWN                   # 73


def search_space() -> dict:
    """Plaintexts consistent with the cribs, treating the cipher as unknown.

    A substitution cipher maps each position independently, so the cribs pin
    exactly the 24 crib positions and say nothing about the other 73. Number of
    consistent plaintexts = 26**73 (an arbitrary cipher could justify any of
    them). For code to single one out, the cipher must LINK unknown positions to
    known ones; we test below whether any known family does that.
    """
    consistent = 26 ** UNKNOWN
    return {
        "total_plaintexts": 26 ** N,
        "consistent_with_cribs": consistent,
        "log10_consistent": UNKNOWN * log10(26),
        "bits_unresolved": UNKNOWN * log10(26) / log10(2),
    }


def structure_recap() -> list[tuple[str, str]]:
    """Each implemented family and whether it linked unknowns to knowns
    (i.e. whether it could narrow the 26**73). All: no."""
    return [
        ("periodic Vigenere/Beaufort (solver.py)", "no consistent short period"),
        ("transposition->Vigenere widths 2-48 (experiments.py)", "no hidden period"),
        ("short-primer autokey (experiments.py)", "no primer fits cribs"),
        ("running key K1-K3 (running_key.py)", "best 5/24 = chance"),
        ("misspellings/Morse keys (morse_misspelling.py)", "best 4/24 = chance"),
        ("Berlin-Clock base-5 (berlin_clock.py)", "best 5/24 = chance"),
        ("K3 keyed transposition (k3_transposition.py)", "no hidden period"),
        ("linear-congruence transpose+Vig (reverse_engineer.py)", "<=42% periodic"),
    ]


def report() -> str:
    s = search_space()
    lines = ["Strictly-code result: ciphertext + cribs alone", "=" * 56, ""]
    lines.append(f"positions total:            {N}")
    lines.append(f"positions fixed by cribs:   {KNOWN}")
    lines.append(f"positions left free:        {UNKNOWN}")
    lines.append("")
    lines.append("Plaintexts consistent with the cribs, cipher unknown:")
    lines.append(f"  26^{UNKNOWN}  ~= 10^{s['log10_consistent']:.0f}  "
                 f"(~{s['bits_unresolved']:.0f} bits unresolved)")
    lines.append("")
    lines.append("For code to pick ONE, the cipher must link the 73 unknown")
    lines.append("positions to the 24 known ones. Every family we implemented")
    lines.append("was tested for exactly that link:")
    for name, result in structure_recap():
        lines.append(f"  - {name}: {result}")
    lines.append("")
    lines.append("-" * 56)
    lines.append(
        "Formal conclusion: with only ciphertext + cribs and no recoverable\n"
        "cipher structure, the 73 non-crib characters are NOT determined by\n"
        "the math. Code can VERIFY a proposed 97-char plaintext (length +\n"
        "crib positions), and can FALSIFY cipher hypotheses, but it cannot\n"
        "DERIVE the plaintext. Any specific 97-char answer must come from\n"
        "outside this math (a recovered key or method) -- it is not latent\n"
        "in the ciphertext+cribs alone."
    )
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
