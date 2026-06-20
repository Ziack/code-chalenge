"""Bounded, reproducible attacks beyond simple periodic substitution.

Each experiment has a clear success criterion stated *before* it runs, so a hit
would be real signal and a miss is an honest negative. None of these is
expected to solve K4; the value is in ruling classes of system in or out.

Success criterion shared by the keying experiments: after the proposed
transform, do the 24 crib positions yield a keystream with a self-consistent
SHORT period (<=12) across BOTH crib regions? That is the signature of a
repeating-key cipher hiding under a transform. (Plain K4 fails this -- see
solver.py -- so a transform that *creates* it would be a genuine lead.)
"""

from __future__ import annotations

from .ciphers import autokey_decrypt, columnar_decrypt
from .data import K4_CIPHERTEXT, KRYPTOS_ALPHABET, STANDARD_ALPHABET
from .solver import KNOWN_PLAINTEXT

ALPHABETS = {"standard": STANDARD_ALPHABET, "kryptos": KRYPTOS_ALPHABET}


def _key_periods(intermediate: str, alphabet: str, max_period: int = 12) -> list[int]:
    """Vigenere keystream forced by the cribs on `intermediate`, then the set
    of short periods that are self-consistent across all crib positions."""
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


def transposition_scan(max_width: int = 48) -> list[str]:
    """Model: ciphertext = Transpose(Vigenere(plaintext)). Invert the
    transposition for each width, then test for a hidden short period."""
    hits = []
    for width in range(2, max_width + 1):
        key = "".join(chr(ord("A") + (i % 26)) for i in range(width))
        intermediate = columnar_decrypt(K4_CIPHERTEXT, key)
        for alpha_name, alpha in ALPHABETS.items():
            periods = _key_periods(intermediate, alpha)
            if periods:
                hits.append(f"width={width:>2} alpha={alpha_name:<8} "
                            f"short-periods={periods}")
    return hits


def autokey_scan(primer_len: int = 4) -> list[str]:
    """Model: ciphertext = ciphertext-free plaintext-autokey. Try every primer
    of the given length over both alphabets, decrypt, and check whether the
    crib positions then read as the known plaintext. (A solving primer would
    make ALL crib letters match.)"""
    from itertools import product
    hits = []
    for alpha_name, alpha in ALPHABETS.items():
        for combo in product(alpha, repeat=primer_len):
            primer = "".join(combo)
            pt = autokey_decrypt(K4_CIPHERTEXT, primer, alpha)
            if all(pt[pos] == ch for pos, ch in KNOWN_PLAINTEXT.items()):
                hits.append(f"alpha={alpha_name} primer={primer}")
    return hits


def report() -> str:
    lines = ["K4 bounded attack experiments", "=" * 60, ""]

    lines.append("[1] Transposition-then-Vigenere: invert a width-w columnar")
    lines.append("    transposition, look for a hidden short repeating key.")
    t_hits = transposition_scan()
    if t_hits:
        lines += [f"    HIT: {h}" for h in t_hits]
        lines.append("    ^ investigate -- a width created periodic structure.")
    else:
        lines.append("    no width (2-48) produced a self-consistent short")
        lines.append("    period over both crib regions. Negative result.")
    lines.append("")

    lines.append("[2] Plaintext-autokey: brute-force every 4-letter primer over")
    lines.append("    both alphabets; a solving primer reproduces all cribs.")
    a_hits = autokey_scan(primer_len=4)
    if a_hits:
        lines += [f"    HIT: {h}" for h in a_hits]
    else:
        lines.append("    no 4-letter primer reproduces the cribs. Negative")
        lines.append("    result (consistent with autokey alone not being it).")
    lines.append("")

    lines.append("-" * 60)
    lines.append(
        "Both negative. That is the honest outcome and it is still useful:\n"
        "simple transposition-over-Vigenere (any width <=48) and short-primer\n"
        "plaintext-autokey are both ruled out. No solution is claimed."
    )
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
