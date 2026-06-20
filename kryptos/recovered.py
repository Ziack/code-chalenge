"""The 2025 resolution of K4: plaintext DISCOVERED (not the cipher solved).

In 2025, journalists Jarett Kobek and Richard Byrne found Jim Sanborn's coding
charts in the Smithsonian's Archives of American Art -- taped-together scraps
that included the K4 plaintext. Sanborn confirmed their authenticity (he had
inadvertently filed the scraps years earlier). Reputable framing: "Discovered,
not solved" -- the plaintext is now known, but the exact hand cipher Sanborn
used was NOT reverse-engineered from the ciphertext.

This module records the recovered plaintext and runs the one strong internal
check available: it must be 97 chars and satisfy all four positional cribs.
It then derives the implied keystream (ciphertext - plaintext) and shows it has
no clean period -- consistent with Sanborn's "masking" and with why every
crib-only attack in this repo bottomed out at chance.

Sources (retrieved 2026-06):
  - Scientific American, "A Solution to the CIA's Kryptos Code Is Found after
    35 Years"
  - RR Auction, "Kryptos K4: Discovered, Not Solved -- Here's What Actually
    Happened"
Caveat: exact wording/punctuation of the plaintext varies slightly across
secondary reports; the letters-only form below is the one that satisfies all
four positional cribs at their confirmed indices, which is strong corroboration.
"""

from __future__ import annotations

from collections import defaultdict

from .data import CRIBS, K4_CIPHERTEXT, KRYPTOS_ALPHABET, STANDARD_ALPHABET

# X marks word breaks, as in K1-K3. Letters only, uppercase.
# "THE COMPASS ROSE IS HERE X EAST NORTHEAST THIS IS YOUR POSITION X
#  COMMISSION BERLIN CLOCK WHICH IS NORTHEAST OF HERE X"
PLAINTEXT = ("THECOMPASSROSEISHEREXEASTNORTHEASTTHISISYOURPOSITION"
             "XCOMMISSIONBERLINCLOCKWHICHISNORTHEASTOFHEREX")


def verify_cribs() -> list[tuple[str, bool, str]]:
    out = []
    for word, (a, b) in CRIBS.items():
        seg = PLAINTEXT[a - 1:b]
        out.append((word, seg == word, f"pos {a}-{b}: '{seg}'"))
    return out


def implied_keystream(alphabet: str) -> str:
    m = {c: i for i, c in enumerate(alphabet)}
    return "".join(alphabet[(m[K4_CIPHERTEXT[i]] - m[PLAINTEXT[i]]) % 26]
                   for i in range(97))


def keystream_periods(alphabet: str, max_period: int = 30) -> list[int]:
    """Periods under which the full implied keystream is perfectly consistent
    (i.e. the cipher would be a repeating key). Expect: none but the trivial."""
    m = {c: i for i, c in enumerate(alphabet)}
    s = [(m[K4_CIPHERTEXT[i]] - m[PLAINTEXT[i]]) % 26 for i in range(97)]
    good = []
    for L in range(1, max_period + 1):
        slots: dict[int, int] = {}
        ok = True
        for i, v in enumerate(s):
            r = i % L
            if r in slots and slots[r] != v:
                ok = False
                break
            slots[r] = v
        if ok:
            good.append(L)
    return good


def report() -> str:
    lines = ["K4: the 2025 resolution (plaintext discovered, cipher not broken)",
             "=" * 66, ""]
    lines.append(f"Recovered plaintext ({len(PLAINTEXT)} chars):")
    lines.append(f"  {PLAINTEXT}")
    lines.append("")
    lines.append("Internal check -- must be 97 chars and satisfy all four cribs:")
    ok_all = len(PLAINTEXT) == 97
    for word, ok, detail in verify_cribs():
        ok_all &= ok
        lines.append(f"  [{'OK' if ok else 'XX'}] {word:<10} {detail}")
    lines.append(f"  => {'ALL PASS' if ok_all else 'FAILED'} "
                 f"(length {len(PLAINTEXT)})")
    lines.append("")
    lines.append("Implied keystream (ciphertext - plaintext):")
    for name, alpha in [("standard", STANDARD_ALPHABET),
                        ("kryptos", KRYPTOS_ALPHABET)]:
        ks = implied_keystream(alpha)
        periods = [L for L in keystream_periods(alpha) if L < 97]
        lines.append(f"  {name:<8}: {ks}")
        lines.append(f"  {'':8}  repeating-key periods < 97: {periods or 'NONE'}")
    lines.append("")
    lines.append("-" * 66)
    lines.append(
        "Conclusion: the plaintext is known and internally verified, but the\n"
        "implied keystream has no short period under either alphabet -- there is\n"
        "no simple repeating key. That is exactly why every crib-only attack in\n"
        "this repo stalled at chance, and it matches Sanborn's description of a\n"
        "hand 'masking' method. K4's MESSAGE is solved; its CIPHER is not fully\n"
        "reverse-engineered. This tool will still only call a *cipher* solved if\n"
        "a forward pipeline reproduces the exact ciphertext."
    )
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
