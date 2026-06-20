# Kryptos K4 — exploratory cryptanalysis tooling

K4 is the **publicly unsolved** final passage of Jim Sanborn's *Kryptos*
sculpture (97 characters). This package does **not** claim a solution. It
exists to test ideas against the small set of hard, public facts, so that a
hypothesis either earns confidence or gets ruled out — rather than being
asserted.

## What's here

| File | Purpose |
|------|---------|
| `data.py` | Sourced facts only: the 97-char ciphertext, the confirmed Sanborn cribs, the KRYPTOS-keyed alphabet, English letter frequencies. |
| `ciphers.py` | Round-trippable primitives: Vigenère, Beaufort, plaintext-autokey, columnar transposition — over either the standard or KRYPTOS-keyed alphabet. Run it directly for a self-test. |
| `analysis.py` | Measurements: index of coincidence, χ² vs English, positional crib checking, order-agnostic substring search. |
| `hypothesis.py` | Records a submitted hypothesis verbatim and runs every check that can be run, reporting PASS/FAIL plainly. |
| `../analyze.py` | Entry point. `python3 analyze.py`. |

```bash
python3 -m kryptos.ciphers   # primitives self-test
python3 analyze.py           # baseline + current hypothesis audit
```

## The confirmed cribs (the facts any solution must satisfy)

Sanborn released these as **positional** facts about the ciphertext
(1-indexed):

| Positions | Plaintext | Released |
|-----------|-----------|----------|
| 22–25 | `EAST` | 2020 |
| 26–34 | `NORTHEAST` | 2020 |
| 64–69 | `BERLIN` | 2010 |
| 70–74 | `CLOCK` | 2014 |

The community-standard reading is that ciphertext index *i* and plaintext
index *i* are the same position (the system substitutes but does not transpose
letters out of place). A solver who introduces a transposition step is
implicitly loosening that reading — a defensible move, but one that must be
stated, because it changes what "the crib is at position 64" means.

## The only proof that counts

Sanborn has repeatedly said the way to confirm a solution is to **reproduce the
exact ciphertext** by encrypting the proposed plaintext with the proposed
method. So the bar for any hypothesis here is:

> Give a runnable, reversible pipeline that turns the plaintext into
> `OBKRUOXOG…` (all 97 chars). Then it's verified. Until then it's a guess.

Readable English plaintext, thematic phrases, and matching crib *words* are
encouraging but prove nothing on their own — anyone can write English.

## Status of the current submission

See `python3 analyze.py`. As recorded, the submitted hypothesis fails the
runnable checks: the segment lengths don't total 97, the cribs don't land in
their fixed positions, and no forward-encryption pipeline is specified, so the
central claim can't be reproduced. The crib *words* do appear in the proposed
plaintext, which is why a fully-specified transposition pipeline is the natural
next thing to implement and test.
