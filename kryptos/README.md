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
| `solver.py` | Crib-driven keystream recovery: derives the key the cribs *force* under each cipher/alphabet and tests for a consistent short period. |
| `hypothesis.py` | Records a submitted hypothesis verbatim and runs every check that can be run, reporting PASS/FAIL plainly. |
| `../analyze.py` | Entry point. `python3 analyze.py`. |

```bash
python3 -m kryptos.ciphers   # primitives self-test
python3 -m kryptos.solver    # crib-driven keystream / periodicity analysis
python3 analyze.py           # baseline + current hypothesis audit
```

## My own line of attack (and its honest result)

The cribs fix the plaintext at 24 positions. `solver.py` uses that to *derive*
the keystream those positions force — no guessing — under Vigenère, Beaufort,
and variant-Beaufort, over both the standard and KRYPTOS-keyed alphabets, then
checks whether any short repeating period is self-consistent across both crib
regions.

Result: the forced key letters are noise, and **no period ≤ 12 survives** under
any of the six assumptions. That is the expected, useful finding — it rules out
the entire class of simple periodic polyalphabetic ciphers and matches the
community's long-standing conclusion that K4's keying is non-periodic or
masked. It narrows the search space; it does not solve K4 (nothing here does).

### Ruled out so far (`experiments.py`)

Each attack states its success criterion before running, so a miss is an
honest negative, not a silent failure. To date, all negative:

- **Simple periodic Vigenère/Beaufort** (standard & KRYPTOS alphabets) — no
  consistent short period (`solver.py`).
- **Transposition-then-Vigenère** for every columnar width 2–48 — no hidden
  short period emerges.
- **Short-primer plaintext-autokey** (all 4-letter primers, both alphabets) —
  no primer reproduces the cribs.
- **Running key from the K1–K3 plaintexts** (plus PALIMPSEST/ABSCISSA/KRYPTOS),
  every alignment, three cipher variants × two alphabets — best alignment hits
  only 5 of 24 crib positions (chance ≈ 0.9), i.e. noise (`running_key.py`).
- **Misspellings & Morse strings as key material** (IQLUSION, UNDERGRUUND,
  DESPARATLY; VIRTUALLY INVISIBLE, DIGETAL INTERPRETATU, SHADOW FORCES, LUCID
  MEMORY, …), as running keys and as autokey primers — best 4 of 24, chance
  level (`morse_misspelling.py`).
- **Berlin-Clock base-5 keying** including the submitted mod-5 seeds
  `[12,2,4,3,16]` ×4 and natural Mengenlehreuhr lamp keystreams — best 5 of 24,
  chance level (`berlin_clock.py`).
- **K3-style keyed columnar transposition** (KRYPTOS / PALIMPSEST / ABSCISSA /
  BERLINCLOCK / … column orders), as a layer under Vigenère and standalone — no
  hidden period, best 4 of 24 standalone (`k3_transposition.py`).

These are real eliminations. They do **not** add up to a solution, and the
tooling will not declare one unless a pipeline reproduces the exact ciphertext
`OBKRUOXOG…`.

### Forward test of the submitted width-12 pipeline (`pipeline.py`)

`pipeline.py` implements one concrete, fully-documented reading of the submitted
"Multi-Layered Fractional Transposition Autokey" (bifid over a KRYPTOS Polybius
square with the asymmetric offset → plaintext-autokey → width-12 columnar
transposition → the Levenshtein delete) and runs it *forward* on the proposed
plaintext. It does **not** reproduce K4:

- **Length is impossible by arithmetic.** The proposed message is 95 chars
  (`active` 69 + `anchor` 26). Bifid/autokey/transposition preserve length and
  the fault removes one, so the pipeline yields ≤ 95 chars — but K4 is 97. No
  ordering of these steps can close a 3-char gap; only an unspecified
  length-*increasing* step could, and none is listed.
- **Content is at chance.** Across all 24 step orderings the best
  position-match to the real ciphertext is ~8% — at/near the ~3.8% you'd expect
  by chance — i.e. noise.

This falsifies the concrete interpretation. Other readings of the ambiguous
parameters exist, but the length arithmetic rules all of them out unless the
plaintext or the step list changes.

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
