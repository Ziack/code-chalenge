#!/usr/bin/env python3
"""Entry point: audit the current hypothesis and show baseline measurements.

Usage:
    python3 analyze.py
"""

from kryptos.analysis import index_of_coincidence, chi_squared_english
from kryptos.data import CRIBS, K4_CIPHERTEXT
from kryptos.hypothesis import audit


def main() -> None:
    print("Kryptos K4 -- ciphertext baseline")
    print("=" * 60)
    print(f"ciphertext: {K4_CIPHERTEXT}")
    print(f"length:     {len(K4_CIPHERTEXT)}")
    print(f"IoC:        {index_of_coincidence(K4_CIPHERTEXT):.4f} "
          f"(English ~0.066, random ~0.038)")
    print(f"chi^2:      {chi_squared_english(K4_CIPHERTEXT):.1f}")
    print("\nConfirmed cribs (1-indexed ciphertext positions):")
    for word, (a, b) in CRIBS.items():
        print(f"  {a:>2}-{b:<2}  {word:<10} ciphertext='{K4_CIPHERTEXT[a-1:b]}'")
    print()
    print(audit().render())


if __name__ == "__main__":
    main()
