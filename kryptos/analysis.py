"""Measurement tools: crib checking, index of coincidence, frequency scoring.

None of this "solves" anything. It quantifies how a candidate stacks up against
facts, so you can tell signal from wishful thinking.
"""

from __future__ import annotations

from collections import Counter

from .data import CRIBS, ENGLISH_FREQ, K4_CIPHERTEXT


def index_of_coincidence(text: str) -> float:
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def chi_squared_english(text: str) -> float:
    """Lower is more English-like. ~ for a 97-char sample, English lands well
    below a random-uniform baseline."""
    n = len(text)
    score = 0.0
    counts = Counter(text)
    for letter, pct in ENGLISH_FREQ.items():
        expected = pct / 100.0 * n
        observed = counts.get(letter, 0)
        if expected > 0:
            score += (observed - expected) ** 2 / expected
    return score


def check_cribs_positional(plaintext: str) -> list[tuple[str, str, str, bool]]:
    """Treat `plaintext` as a positional decryption of the 97-char ciphertext
    (plaintext[i] is the decryption of ciphertext[i]). Returns one row per crib:
    (word, expected, found, ok)."""
    rows = []
    for word, (a, b) in CRIBS.items():
        found = plaintext[a - 1:b] if len(plaintext) >= b else "<out-of-range>"
        rows.append((word, word, found, found == word))
    return rows


def find_substrings(plaintext: str, words: list[str]) -> dict[str, list[int]]:
    """Where (if anywhere) do these words appear, ignoring position? Returns
    1-indexed start positions. Useful for transposition hypotheses where the
    plaintext is readable but not positionally aligned to the ciphertext."""
    out: dict[str, list[int]] = {}
    for w in words:
        starts, i = [], plaintext.find(w)
        while i != -1:
            starts.append(i + 1)
            i = plaintext.find(w, i + 1)
        out[w] = starts
    return out


def report(plaintext: str) -> str:
    lines = []
    lines.append(f"length:                {len(plaintext)} (ciphertext is {len(K4_CIPHERTEXT)})")
    lines.append(f"index of coincidence:  {index_of_coincidence(plaintext):.4f}  "
                 f"(English prose ~0.066, random ~0.038)")
    lines.append(f"chi-squared vs English: {chi_squared_english(plaintext):.1f}  (lower = more English-like)")
    lines.append("")
    lines.append("Positional crib check (plaintext[i] decrypts ciphertext[i]):")
    all_ok = True
    for word, _exp, found, ok in check_cribs_positional(plaintext):
        a, b = CRIBS[word]
        mark = "OK " if ok else "XX "
        all_ok &= ok
        lines.append(f"  {mark} pos {a:>2}-{b:<2} expected {word:<10} found {found}")
    lines.append(f"  => positional cribs {'ALL satisfied' if all_ok else 'NOT satisfied'}")
    return "\n".join(lines)
