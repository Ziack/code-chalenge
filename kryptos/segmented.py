"""Non-standard path 2: SEGMENTED keys (different key per section).

The cribs cluster in two regions: idx 21-33 (EASTNORTHEAST) and idx 63-73
(BERLINCLOCK). If K4 changes key/period between sections, each region might be
internally clean while the two disagree -- invisible to a whole-message period
test. We find, per region and per (cipher, alphabet), the smallest period that
is self-consistent within that region, and compare the two regions.
"""

from __future__ import annotations

from collections import defaultdict

from .data import K4_CIPHERTEXT, KRYPTOS_ALPHABET, STANDARD_ALPHABET
from .solver import KNOWN_PLAINTEXT

ALPHABETS = {"standard": STANDARD_ALPHABET, "kryptos": KRYPTOS_ALPHABET}
REGION_A = list(range(21, 34))   # EASTNORTHEAST
REGION_B = list(range(63, 74))   # BERLINCLOCK


def _req(mode, alphabet):
    m = {c: i for i, c in enumerate(alphabet)}
    out = {}
    for pos, p in KNOWN_PLAINTEXT.items():
        c, pv = m[K4_CIPHERTEXT[pos]], m[p]
        out[pos] = (c - pv) % 26 if mode == "vigenere" else (c + pv) % 26
    return out


def _clean_period(positions, req, max_period):
    """Smallest period self-consistent within these positions (key letters in
    the same residue class must match). Returns (period, keytuple) or None."""
    for L in range(1, max_period + 1):
        slots = {}
        ok = True
        for pos in positions:
            r = pos % L
            if r in slots and slots[r] != req[pos]:
                ok = False
                break
            slots[r] = req[pos]
        if ok:
            return L, tuple(slots[r] for r in sorted(slots))
    return None


def report() -> str:
    lines = ["Non-standard path 2: segmented keys (per-section)", "=" * 58,
             f"region A idx21-33 ({len(REGION_A)} cribs), "
             f"region B idx63-73 ({len(REGION_B)} cribs)", ""]
    any_lead = False
    for mode in ("vigenere", "beaufort"):
        for aname, alpha in ALPHABETS.items():
            req = _req(mode, alpha)
            a = _clean_period(REGION_A, req, 12)
            b = _clean_period(REGION_B, req, 10)
            # A "lead" = each region has a SHORT clean period (< its length)
            a_short = a and a[0] < len(REGION_A)
            b_short = b and b[0] < len(REGION_B)
            same = a and b and a[1] == b[1] and a[0] == b[0]
            note = ""
            if a_short and b_short:
                note = " <-- both regions short-periodic"
                any_lead = True
                if same:
                    note += " AND identical (would be whole-message period!)"
            lines.append(f"{mode:<9}/{aname:<8} A:period={a[0] if a else '-'} "
                         f"B:period={b[0] if b else '-'}{note}")
    lines.append("")
    lines.append("-" * 58)
    if any_lead:
        lines.append("At least one region shows a short clean period -- inspect")
        lines.append("above; if both are short and consistent it's a real lead.")
    else:
        lines.append(
            "Neither crib region has a clean period shorter than its own length\n"
            "under any cipher/alphabet. Each region's key is as long as the\n"
            "region itself -- i.e. no repeating structure even locally. Segmented\n"
            "short-period keys do NOT explain K4. (Every region trivially admits\n"
            "period = its length; that is not structure.)"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
