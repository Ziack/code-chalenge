"""Review of the 'Kryptos K4 Solution Final' PDF (by Nsiela Sernic Japhet).

The document lays out a multi-step grid construction and a final formula:

    Message = (Cipher^2 + Key^2)^2 - OFFSET   (mod MODULUS)

with a reverse-engineered keyword (AKECAUUUKHIDGJTC...). It deserves a real
check rather than a wave-off. Here is the result of checking it.

WHY IT DOES NOT HOLD UP (all verifiable; see __main__):

1. The formula is UNCONSTRAINED. In the worked examples the OFFSET (97, 95,
   93, ...) and the MODULUS (25, 28, 22, 24, 29, ...) are BOTH chosen
   per-letter. With two free integers per position you can hit any target:
   from the single input pair (O,A), letting offset range 90..100 and modulus
   20..30 produces ALL 26 letters. A rule that can output anything predicts
   nothing -- it is fitted to the answer, not deriving it.

2. The output is NOT the real plaintext. The document's 'Message' reads
   T-NORTHEAST-BERLIN-CLOCK-EAST tiled diagonally -- i.e. the already-known
   cribs rearranged. It is not the archive-confirmed plaintext
   'THE COMPASS ROSE IS HERE ...'. So even taken at face value it reproduces
   the clues, not the message.

3. The key derivation is word-association, not cryptography:
   'Wood=Mood=Mod', 'MUD=boue=bout=END=AND=ET=Eight=8',
   'SCALE=KEY=CLE=SEL=SALT=STONE=CRYSTAL', and a 'masking' list of
   Numerology / Anagram / Gematria / Language of Birds. None of it is a
   reproducible procedure another person could run to get the same key.

4. It never reproduces the 97-char ciphertext from a plaintext -- the one
   test Sanborn says actually validates a method.

Verdict: not a valid solution of the K4 cipher. (The real plaintext is known
from the 2025 Smithsonian archive find; see recovered.py. This PDF predates /
sidesteps that and does not reconstruct the cipher.)
"""

from __future__ import annotations


def _val(ch: str) -> int:
    return ord(ch) - ord("A")


def _letter(v: int) -> str:
    return chr((v % 26) + ord("A"))


def headline_example() -> tuple[int, str]:
    o, a = _val("O"), _val("A")
    r = ((o ** 2 + a ** 2) ** 2 - 97) % 25
    return r, _letter(r)


def reachable_from_single_pair() -> set[str]:
    """Letters producible from the one pair (O,A) by varying offset/modulus
    over exactly the ranges the document uses."""
    base = (_val("O") ** 2 + _val("A") ** 2) ** 2
    out = set()
    for offset in range(90, 101):
        for modulus in range(20, 31):
            v = (base - offset) % modulus
            if v < 26:
                out.add(_letter(v))
    return out


def report() -> str:
    r, ch = headline_example()
    reach = reachable_from_single_pair()
    lines = ["Review: 'Kryptos K4 Solution Final' (PDF)", "=" * 56, ""]
    lines.append(f"1. Headline example reproduces: (O^2+A^2)^2-97 mod 25 = "
                 f"{r} = {ch}  (matches their 'T')")
    lines.append("   ...but the formula is UNCONSTRAINED:")
    lines.append(f"   from the single pair (O,A), varying offset 90..100 and")
    lines.append(f"   modulus 20..30 reaches {len(reach)}/26 target letters: "
                 f"{''.join(sorted(reach))}")
    lines.append("   A per-letter free offset+modulus can force any output.")
    lines.append("")
    lines.append("2. Its 'Message' = TNORTHEAST/BERLIN/CLOCK/EAST tiled (the")
    lines.append("   known cribs), NOT the archive plaintext THECOMPASSROSE...")
    lines.append("")
    lines.append("3. Keys come from word-play (Wood=Mood=Mod; MUD=...=Eight=8;")
    lines.append("   SCALE=KEY=SALT=STONE), not a reproducible procedure.")
    lines.append("")
    lines.append("4. It never re-encrypts a plaintext into the 97-char K4.")
    lines.append("-" * 56)
    lines.append("Verdict: not a valid solution of the K4 cipher. It fits a")
    lines.append("flexible formula to the already-public cribs; it does not")
    lines.append("derive or reproduce them, nor the real plaintext.")
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
