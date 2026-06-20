"""Test the 'physical selector' core of the shadow/light hypothesis, in code.

The hypothesis states the light/shadow effect operates on the 97 K4 characters
"as a character reservoir, stencil, register, routing field, or selection
layer." Any such operation can only PICK / OMIT / REORDER existing ciphertext
characters. It cannot change a letter's identity and cannot manufacture letters
that are not present. Therefore, for every letter L:

        (output count of L)  <=  (count of L in the 97 ciphertext chars)

If the target plaintext needs MORE of some letter than the ciphertext contains,
no selector/stencil/router can produce it -- a SUBSTITUTION (i.e. cryptography)
is mandatory. This decides the 'physical selector operating on the characters'
mechanism without any optics, timing, or verification.
"""

from __future__ import annotations

from collections import Counter

from .data import CRIBS, K4_CIPHERTEXT
from .recovered import PLAINTEXT

CT = Counter(K4_CIPHERTEXT)
PT = Counter(PLAINTEXT)


def deficits() -> dict[str, int]:
    """Letters the plaintext needs but the ciphertext cannot supply by
    selection: max(0, pt_count - ct_count)."""
    out = {}
    for ch in sorted(set(PLAINTEXT)):
        short = PT[ch] - CT.get(ch, 0)
        if short > 0:
            out[ch] = short
    return out


def position_aligned() -> bool:
    return all(PLAINTEXT[a - 1:b] == w for w, (a, b) in CRIBS.items())


def report() -> str:
    d = deficits()
    total_short = sum(d.values())
    lines = ["Shadow-as-selector test: can a stencil/router over the 97",
             "ciphertext characters produce the plaintext?", "=" * 56, ""]
    lines.append("letters the plaintext needs but the ciphertext cannot supply")
    lines.append("by any selection/stencil/routing (pt_count > ct_count):")
    for ch, short in d.items():
        lines.append(f"   {ch}: needs {PT[ch]:>2}, ciphertext has "
                     f"{CT.get(ch,0):>2}  -> short by {short}")
    lines.append("")
    lines.append(f"letters impossible to source by selection: {len(d)} of 26")
    lines.append(f"total characters that cannot be supplied: {total_short}")
    lines.append("")
    lines.append("-" * 56)
    if total_short > 0:
        lines.append(
            f"VERDICT: a physical selector/stencil/router/reservoir operating on\n"
            f"the 97 K4 characters CANNOT produce the plaintext -- it would need\n"
            f"{total_short} characters that simply are not in the ciphertext\n"
            f"(e.g. it would have to find more S/E/O/H/I than exist). Changing\n"
            f"letter identities is SUBSTITUTION = cryptography, not a light/shadow\n"
            f"selection. So the substitution layer is mandatory and physical.\n")
    # The complementary point: no reordering is needed either.
    lines.append(f"And the plaintext is position-aligned (cribs at the ciphertext"
                 f" crib indices, readable in order): {position_aligned()}.")
    lines.append(
        "So there is also no net transposition for a 'routing/ordering' layer to\n"
        "perform. Between them, these two facts leave a physical selector with no\n"
        "work to do: identity-changes are required (a cipher) and ordering is the\n"
        "identity. The 'shadow operates on the characters' mechanism is not just\n"
        "unverified -- it is squeezed out by what the characters themselves show."
    )
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
