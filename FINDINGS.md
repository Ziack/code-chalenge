# K4 solution-path map (code-derived)

A consolidated record of which cipher classes this repo has tested against the
97-char ciphertext and the 24 crib positions, what each found, and which paths
remain logically open. Everything here is reproducible (`python3 -m kryptos.<mod>`).

Chance baseline for a crib-hit score is ~0.9 / 24.

## Dead paths (closed in code)

| Path | Module | Diagnostic / result | Status |
|------|--------|---------------------|--------|
| Periodic Vigenère/Beaufort | `solver`, `paths` | no consistent short period; IoC-by-period peaks at 0.044 (< English 0.066) | **closed** |
| Index-of-coincidence period | `paths` | no period shows polyalphabetic structure | **closed** |
| Kasiski / repeated n-grams | `paths` | **0** repeated trigrams in 97 chars → no period handle | **closed** |
| 2×2 Hill cipher | `paths` | crib digraphs solve a key that explains only 2/11 → inconsistent | **closed** |
| Transposition → Vigenère (w 2–48) | `experiments` | no hidden period | **closed** |
| Linear-congruence transpose + Vigenère | `reverse_engineer` | ≤42% periodic even with plaintext | **closed** |
| K3-style keyed transposition (+ Vigenère) | `k3_transposition`, `combined` | no hidden period; best 5/24 | **closed** |
| Short-primer autokey | `experiments` | no primer fits cribs | **closed** |
| Running key (K1–K3 plaintexts) | `running_key` | best 5/24 = chance | **closed** |
| Misspellings / Morse as key | `morse_misspelling` | best 4/24 = chance | **closed** |
| Berlin-Clock base-5 keying | `berlin_clock` | best 5/24 = chance | **closed** |
| K1/K2 engine + sculpture keywords | `combined` | best 5/24 = chance | **closed** |

## The formal limit

`code_only.py`: with only ciphertext + cribs and **no recoverable cipher
structure**, 73 positions stay free — 26⁷³ ≈ 10¹⁰³ consistent plaintexts. Code
can **verify** a candidate and **falsify** a cipher hypothesis, but cannot
**derive** the plaintext. This is proved, not assumed.

## Remaining live space (genuinely non-standard)

These are not closed, but none is resolvable by a single diagnostic — each needs
a *specific* rule supplied before code can test it:

- **Non-periodic / progressive keying** (key that evolves by position via an
  unstated rule).
- **Multi-stage masking** (≥2 layered transforms; the search space is open-ended
  without knowing the layers/order).
- **3×3 or larger Hill**, or block ciphers with unknown block boundaries.
- **Off-tableau hand methods** (Scheidt's "masking") with no compact algebraic form.

## What would actually close it

Per Sanborn, a method is validated only by **re-encrypting a plaintext into the
exact ciphertext `OBKRUOXOG…`**. The missing input is the **key + exact step
sequence** (e.g. Sanborn's archive charts). Given any fully-specified candidate,
`kryptos/ciphers.py` settles it instantly. Short of that, the math above shows
the answer is not latent in the ciphertext + cribs alone.
