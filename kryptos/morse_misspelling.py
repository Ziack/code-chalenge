"""Test the sculpture's misspellings and Morse-code strings as key material.

Two long-standing community ideas:
  (a) Sanborn's deliberate misspellings encode something (IQLUSION, UNDERGRUUND,
      DESPARATLY, the terminal Q's).
  (b) The Morse-code plaintexts beside the main sculpture are key material.

We test both as (1) running keys slid against the crib-forced keystream and
(2) autokey primers, under all cipher/alphabet variants. A real key fragment
would light up all 24 crib positions (running key) or reproduce the cribs
exactly (autokey primer). Anything else is noise.

Source strings are as catalogued by the Kryptos community (Elonka Dunin's
compilation); spellings are reproduced verbatim because exact letters matter.
"""

from __future__ import annotations

from .ciphers import autokey_decrypt
from .data import K4_CIPHERTEXT, KRYPTOS_ALPHABET, STANDARD_ALPHABET
from .running_key import _required_key, best_alignment
from .solver import KNOWN_PLAINTEXT

# --- misspellings / anomalies ------------------------------------------------
MISSPELLINGS = {
    "IQLUSION": "IQLUSION",           # K1: ILLUSION, L->Q
    "UNDERGRUUND": "UNDERGRUUND",     # K2: UNDERGROUND, O->U
    "DESPARATLY": "DESPARATLY",       # K3: DESPERATELY
    "misspell_concat": "IQLUSIONUNDERGRUUNDDESPARATLY",
    # just the anomalous letters, in order (Q from K1, U from K2, the K3 shifts)
    "anomaly_letters": "QUAA",
}

# --- Morse-code strings on the sculpture grounds -----------------------------
MORSE = {
    "VIRTUALLYINVISIBLE": "VIRTUALLYINVISIBLE",
    "DIGETALINTERPRETATU": "DIGETALINTERPRETATU",  # misspelled DIGITAL
    "TISYOURPOSITION": "TISYOURPOSITION",
    "SHADOWFORCES": "SHADOWFORCES",
    "LUCIDMEMORY": "LUCIDMEMORY",
    "RQ": "RQ",
    "morse_concat": ("LUCIDMEMORYTISYOURPOSITIONSHADOWFORCES"
                     "VIRTUALLYINVISIBLEDIGETALINTERPRETATU"),
}

ALL_KEYS = {**MISSPELLINGS, **MORSE}
ALPHABETS = {"standard": STANDARD_ALPHABET, "kryptos": KRYPTOS_ALPHABET}
N = len(KNOWN_PLAINTEXT)


def running_key_scan() -> list[tuple[str, int, str]]:
    """Best running-key alignment per candidate. Returns (label, hits, detail)."""
    rows = []
    for cipher in ("vigenere", "beaufort", "variant-beaufort"):
        for alpha_name, alpha in ALPHABETS.items():
            req = _required_key(cipher, alpha)
            need = max(req)
            for name, txt in ALL_KEYS.items():
                if len(txt) <= need:
                    # too short to cover both crib runs as a single running key
                    continue
                off, hits = best_alignment(txt, req)
                rows.append((f"{cipher}/{alpha_name} {name}", hits,
                             f"@offset {off}"))
    return sorted(rows, key=lambda r: -r[1])


def autokey_primer_scan() -> list[tuple[str, int]]:
    """Use each candidate as an autokey primer; count crib hits after decrypt."""
    rows = []
    for alpha_name, alpha in ALPHABETS.items():
        for name, primer in ALL_KEYS.items():
            pt = autokey_decrypt(K4_CIPHERTEXT, primer, alpha)
            hits = sum(1 for pos, ch in KNOWN_PLAINTEXT.items() if pt[pos] == ch)
            rows.append((f"{alpha_name} primer={name}", hits))
    return sorted(rows, key=lambda r: -r[1])


def report() -> str:
    lines = ["Misspellings & Morse as K4 key material", "=" * 60,
             f"crib positions: {N}; chance ~{N/26:.1f}/{N}", ""]

    lines.append("[A] As running keys (best alignment, top 8):")
    rk = running_key_scan()
    for label, hits, detail in rk[:8]:
        flag = "  <-- FULL" if hits == N else ""
        lines.append(f"    {hits:>2}/{N}  {label} {detail}{flag}")
    lines.append("")

    lines.append("[B] As autokey primers (top 8):")
    ak = autokey_primer_scan()
    for label, hits in ak[:8]:
        flag = "  <-- FULL" if hits == N else ""
        lines.append(f"    {hits:>2}/{N}  {label}{flag}")
    lines.append("")

    best = max(rk[0][1] if rk else 0, ak[0][1] if ak else 0)
    lines.append("-" * 60)
    if best == N:
        lines.append("FULL MATCH found -- investigate immediately.")
    else:
        lines.append(
            f"Best anywhere: {best}/{N} vs chance ~{N/26:.1f}. No misspelling or\n"
            f"Morse string keys the cribs, as a running key or an autokey primer,\n"
            f"under any tested variant. Honest negative; this hint, used directly\n"
            f"as key material, does not unlock K4."
        )
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
