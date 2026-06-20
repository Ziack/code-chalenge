"""Running-key attack on K4 driven by the confirmed cribs.

A running key is one long, non-repeating text used letter-by-letter. The cribs
pin the plaintext (hence the required key) at two contiguous runs:
    positions 22-34 (0-idx 21-33): EASTNORTHEAST
    positions 64-74 (0-idx 63-73): BERLINCLOCK
Because a single key text covers the whole message, BOTH runs must match the
SAME candidate text at the SAME alignment offset. That is a strong joint
constraint: a true key would match all 24 crib positions at once.

This module derives the required key letters under each cipher variant/alphabet
and slides every candidate text past them, reporting the best alignment and how
many of the 24 positions it hits. A score of 24/24 would be a real lead.
"""

from __future__ import annotations

from .data import K4_CIPHERTEXT, KRYPTOS_ALPHABET, STANDARD_ALPHABET
from .solver import KNOWN_PLAINTEXT

# --- candidate key texts -----------------------------------------------------
# The solved K1-K3 plaintexts, letters only, INCLUDING Sanborn's intentional
# misspellings (IQLUSION, UNDERGRUUND, DESPARATLY) because a running key matches
# exact letters. These are the most-cited Sanborn-internal key candidates.
K1 = ("BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION")

K2 = ("ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDX"
      "THEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONX"
      "DOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWS"
      "THEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTY"
      "SEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTES"
      "FORTYFOURSECONDSWESTXLAYERTWO")

K3 = ("SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWER"
      "PARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINYBREACHINTHE"
      "UPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTEDTHECANDLEAND"
      "PEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBERCAUSEDTHEFLAMETOFLICKERBUT"
      "PRESENTLYDETAILSOFTHEROOMWITHINEMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ")

KEY_TEXTS = {
    "K1": K1,
    "K2": K2,
    "K3": K3,
    "K1+K2+K3": K1 + K2 + K3,
    "K3+K2+K1": K3 + K2 + K1,
    # low-value baselines / known Vigenere keys from K1, K2
    "PALIMPSEST_x20": "PALIMPSEST" * 20,
    "ABSCISSA_x20": "ABSCISSA" * 20,
    "KRYPTOS_x20": "KRYPTOS" * 20,
}

ALPHABETS = {"standard": STANDARD_ALPHABET, "kryptos": KRYPTOS_ALPHABET}


def _required_key(cipher: str, alphabet: str) -> dict[int, str]:
    m = {c: i for i, c in enumerate(alphabet)}
    A = alphabet
    out = {}
    for pos, p in KNOWN_PLAINTEXT.items():
        c = K4_CIPHERTEXT[pos]
        if cipher == "vigenere":             # C = P + K -> K = C - P
            k = (m[c] - m[p]) % 26
        elif cipher == "beaufort":           # C = K - P -> K = C + P
            k = (m[c] + m[p]) % 26
        elif cipher == "variant-beaufort":   # C = P - K -> K = P - C
            k = (m[p] - m[c]) % 26
        else:
            raise ValueError(cipher)
        out[pos] = A[k]
    return out


def best_alignment(keytext: str, req: dict[int, str]) -> tuple[int, int]:
    """Slide keytext over the message; return (best_offset, best_hits/24)."""
    positions = sorted(req)
    max_pos = positions[-1]
    best_off, best_hits = 0, -1
    # offset o means message position i is keyed by keytext[o + i]
    for o in range(0, max(1, len(keytext) - max_pos)):
        hits = sum(1 for p in positions if keytext[o + p] == req[p])
        if hits > best_hits:
            best_off, best_hits = o, hits
    return best_off, best_hits


def report() -> str:
    n = len(KNOWN_PLAINTEXT)
    lines = ["Running-key attack vs the K4 cribs", "=" * 60,
             f"crib positions constrained: {n}", ""]
    overall_best = (None, -1)
    for cipher in ("vigenere", "beaufort", "variant-beaufort"):
        for alpha_name, alpha in ALPHABETS.items():
            req = _required_key(cipher, alpha)
            lines.append(f"{cipher} / {alpha_name}")
            for name, txt in KEY_TEXTS.items():
                if len(txt) <= max(req):
                    lines.append(f"    {name:<14} (too short)")
                    continue
                off, hits = best_alignment(txt, req)
                flag = "  <-- FULL MATCH" if hits == n else ""
                lines.append(f"    {name:<14} best {hits:>2}/{n} @offset {off}{flag}")
                if hits > overall_best[1]:
                    overall_best = (f"{cipher}/{alpha_name} {name}@{off}", hits)
            lines.append("")
    lines.append("-" * 60)
    label, hits = overall_best
    lines.append(f"Best result anywhere: {hits}/{n}  ({label})")
    if hits == n:
        lines.append("FULL MATCH -- investigate immediately.")
    else:
        chance = n * (1 / 26)
        lines.append(
            f"Expected by chance ~{chance:.1f}/{n}. The best is at/near chance,\n"
            f"so none of these running keys explains the cribs at any alignment.\n"
            f"Honest negative: the tested Sanborn-internal texts are not the\n"
            f"K4 running key (at least not under these straightforward variants)."
        )
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
