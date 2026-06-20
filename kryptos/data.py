"""Canonical, sourced facts about Kryptos K4.

Everything in this file is publicly documented. Nothing here is a guess.
If a value is ever changed, cite the source in the comment next to it so the
rest of the tooling stays trustworthy.
"""

# The 97-character K4 ciphertext, exactly as carved on the sculpture.
# Source: photographs of the Kryptos sculpture; reproduced identically across
# the Kryptos community (elonka.com, the Kryptos Yahoo/Google groups, etc.).
K4_CIPHERTEXT = (
    "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSO"
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTM"
    "ZFPKWGDKZXTJCDIGKUHUAUEKCAR"
)
assert len(K4_CIPHERTEXT) == 97, "K4 is 97 characters"

# Confirmed plaintext cribs released by Jim Sanborn, expressed as the
# 1-INDEXED ciphertext positions whose decryption is known.
#
#   2010 : positions 64-69 decrypt to BERLIN
#   2014 : positions 70-74 decrypt to CLOCK      (so 64-74 = BERLINCLOCK)
#   2020 : positions 26-34 decrypt to NORTHEAST
#   2020 : positions 22-25 decrypt to EAST       (overlaps NORTHEAST's start)
#
# IMPORTANT: Sanborn gave these as POSITIONAL facts about the ciphertext.
# The community-standard reading is that ciphertext char i and plaintext char i
# share an index, i.e. the system does not transpose letters out of position.
# A solver who proposes a transposition step is implicitly claiming Sanborn's
# clues mean something looser; that is a real (defensible) assumption, but it
# must be stated, not smuggled in.
CRIBS = {
    "EAST":      (22, 25),
    "NORTHEAST": (26, 34),
    "BERLIN":    (64, 69),
    "CLOCK":     (70, 74),
}

# The KRYPTOS-keyed alphabet used to build the Vigenere tableau in K1-K3.
# Keyword KRYPTOS, then the remaining letters of the alphabet in order.
KRYPTOS_ALPHABET = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
assert sorted(KRYPTOS_ALPHABET) == list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

STANDARD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# English single-letter frequencies (%), for scoring candidate plaintexts.
ENGLISH_FREQ = {
    "A": 8.17, "B": 1.49, "C": 2.78, "D": 4.25, "E": 12.70, "F": 2.23,
    "G": 2.02, "H": 6.09, "I": 6.97, "J": 0.15, "K": 0.77, "L": 4.03,
    "M": 2.41, "N": 6.75, "O": 7.51, "P": 1.93, "Q": 0.10, "R": 5.99,
    "S": 6.33, "T": 9.06, "U": 2.76, "V": 0.98, "W": 2.36, "X": 0.15,
    "Y": 1.97, "Z": 0.07,
}
