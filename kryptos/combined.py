"""Ideate a K4 method from the SOLVED K1-K3 and the hints, then test in code.

Known facts we are allowed to use (they are the solved mechanics of the
sculpture, not an external K4 answer):
  K1 = keyed-Vigenere, KRYPTOS-keyed alphabet, keyword PALIMPSEST
  K2 = same family, keyword ABSCISSA
  K3 = keyed columnar transposition
  hints = deliberate misspellings, BERLIN/CLOCK, "masking" = layering

Hypothesis family: K4 reuses the K1/K2 keyed-Vigenere engine with some keyword
drawn from the sculpture's vocabulary -- optionally after a K3-style
transposition. We sweep those keywords/ciphers/alphabets and score each
decryption against the 24 crib positions. A keyword that is really the key would
light up well above chance (~0.9/24); a real solution would hit 24/24.
"""

from __future__ import annotations

from .ciphers import columnar_decrypt
from .data import K4_CIPHERTEXT, KRYPTOS_ALPHABET, STANDARD_ALPHABET
from .solver import KNOWN_PLAINTEXT

N = 97
KNOWN = len(KNOWN_PLAINTEXT)
ALPHABETS = {"standard": STANDARD_ALPHABET, "kryptos": KRYPTOS_ALPHABET}

# Keywords drawn from K1-K3 and the hints.
KEYWORDS = [
    "PALIMPSEST", "ABSCISSA", "KRYPTOS",            # the actual K1-K3 keys/alphabet
    "IQLUSION", "UNDERGRUUND", "DESPARATLY",        # the deliberate misspellings
    "BERLIN", "CLOCK", "BERLINCLOCK",               # the cribs as candidate keys
    "EASTNORTHEAST", "NORTHEAST",                   # the other cribs
    "PALIMPSESTABSCISSA", "ABSCISSAPALIMPSEST",     # K1+K2 combined
    "SHADOW", "LUCID", "WW",                        # Morse / K2 vocabulary
]


def _decrypt_crib_hits(key: str, alphabet: str, mode: str, text: str) -> int:
    """Periodic-key decrypt of `text`; count matches at the 24 crib positions."""
    m = {c: i for i, c in enumerate(alphabet)}
    A = alphabet
    klen = len(key)
    hits = 0
    for pos, p in KNOWN_PLAINTEXT.items():
        c = m[text[pos]]
        k = m[key[pos % klen]]
        if mode == "vigenere":            # P = C - K
            dec = (c - k) % 26
        elif mode == "beaufort":          # P = K - C
            dec = (k - c) % 26
        else:                             # variant-beaufort: P = C + K
            dec = (c + k) % 26
        if A[dec] == p:
            hits += 1
    return hits


def sweep(text: str = K4_CIPHERTEXT, label: str = "no pre-transposition") -> list:
    rows = []
    for key in KEYWORDS:
        for alpha_name, alpha in ALPHABETS.items():
            for mode in ("vigenere", "beaufort", "variant-beaufort"):
                h = _decrypt_crib_hits(key, alpha, mode, text)
                rows.append((h, f"{label} | key={key} {mode}/{alpha_name}"))
    return rows


def report() -> str:
    lines = ["Method ideation from K1-K3 + hints, scored on 24 cribs",
             "=" * 58, f"chance ~ {KNOWN/26:.1f}/{KNOWN}", ""]

    all_rows = []
    # Stage 1: direct keyed-Vigenere family (the K1/K2 engine).
    all_rows += sweep(K4_CIPHERTEXT, "direct")

    # Stage 2: K3-style transposition first, then the K1/K2 engine.
    for kw in ("KRYPTOS", "ABSCISSA", "PALIMPSEST", "BERLINCLOCK"):
        pre = columnar_decrypt(K4_CIPHERTEXT, kw)
        all_rows += sweep(pre, f"K3-transpose[{kw}]")

    all_rows.sort(key=lambda r: -r[0])
    lines.append("Top 12 results (crib hits / 24):")
    for h, desc in all_rows[:12]:
        flag = "  <-- FULL" if h == KNOWN else ""
        lines.append(f"  {h:>2}/{KNOWN}  {desc}{flag}")

    best = all_rows[0][0]
    lines.append("")
    lines.append("-" * 58)
    if best == KNOWN:
        lines.append("FULL crib match -- candidate method found, verify by")
        lines.append("re-encrypting to OBKRUOXOG...")
    else:
        lines.append(
            f"Best {best}/{KNOWN} ~ chance. Reusing the K1/K2 keyed-Vigenere\n"
            f"engine with any sculpture keyword -- alone or after a K3-style\n"
            f"transposition -- does NOT key the cribs. The K1-K3 toolkit, applied\n"
            f"straightforwardly, does not extend to K4. Consistent with Scheidt's\n"
            f"statement that K4 uses a different (masking) technique."
        )
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
