"""The Berlin Clock MECHANISM as a keystream generator (faithful model).

Mengenlehreuhr at minute-of-day t (h=t//60, m=t%60):
  row1 (5h): h//5 lamps   row2 (1h): h%5
  row3 (5m): m//5 lamps   row4 (1m): m%5
The defining feature is the sawtooth reset every 5 -> a NON-linear function of
time. We turn the clock into a keystream by reading a lamp-derived value at
successive times (start, start+step, ...), map to a Vigenere/Beaufort shift, and
score against the 24 cribs over a full sweep of start time, step, and a small
multiplier.

Structural caveat (proved elsewhere): a clock is a deterministic, cyclic
device, so any clock-driven keystream is structured/quasi-periodic. segmented.py
showed K4's crib-forced key is maximally aperiodic even locally -- so this path
is expected to fail, and the sweep makes that concrete rather than assumed.
"""

from __future__ import annotations

from .data import K4_CIPHERTEXT, KRYPTOS_ALPHABET, STANDARD_ALPHABET
from .solver import KNOWN_PLAINTEXT

ALPHABETS = {"standard": STANDARD_ALPHABET, "kryptos": KRYPTOS_ALPHABET}
KNOWN = len(KNOWN_PLAINTEXT)


def lamp_value(t: int, kind: str) -> int:
    h, m = (t // 60) % 24, t % 60
    r1, r2, r3, r4 = h // 5, h % 5, m // 5, m % 5
    if kind == "count":          # total lamps lit (sawtooth sum)
        return r1 + r2 + r3 + r4
    if kind == "rows_concat":    # 4 base-5 digits combined
        return ((r1 * 5 + r2) + (r3 * 5 + r4))
    if kind == "minutes_block":  # 5-min block index (the most clock-specific)
        return r3
    if kind == "weighted":       # weight rows like the dial values
        return 5 * r1 + r2 + 5 * r3 + r4
    raise ValueError(kind)


def crib_hits(shift_of, mode: str, alphabet: str) -> int:
    m = {c: i for i, c in enumerate(alphabet)}
    A = alphabet
    hits = 0
    for pos, p in KNOWN_PLAINTEXT.items():
        c = m[K4_CIPHERTEXT[pos]]
        k = shift_of(pos) % 26
        dec = (c - k) % 26 if mode == "vigenere" else (k - c) % 26
        if A[dec] == p:
            hits += 1
    return hits


def search():
    best = {"hits": -1}
    for kind in ("count", "rows_concat", "minutes_block", "weighted"):
        for start in range(0, 1440):
            for step in range(1, 8):
                for mult in (1, 2, 3, 4, 5):
                    shift = lambda i, s=start, st=step, mu=mult, k=kind: \
                        lamp_value(s + i * st, k) * mu
                    for mode in ("vigenere", "beaufort"):
                        for aname, alpha in ALPHABETS.items():
                            h = crib_hits(shift, mode, alpha)
                            if h > best["hits"]:
                                best = {"hits": h, "kind": kind, "start": start,
                                        "step": step, "mult": mult,
                                        "mode": mode, "alpha": aname}
    return best


def report() -> str:
    lines = ["Berlin Clock mechanism as keystream, vs K4 cribs", "=" * 56,
             f"chance ~ {KNOWN/26:.1f}/{KNOWN}; full = {KNOWN}/{KNOWN}", ""]
    b = search()
    lines.append("Best over all encodings/start-times/steps/multipliers:")
    lines.append(f"  {b['hits']}/{KNOWN}  kind={b['kind']} start={b['start']}min "
                 f"step={b['step']} mult={b['mult']} {b['mode']}/{b['alpha']}")
    lines.append("")
    lines.append("-" * 56)
    if b["hits"] == KNOWN:
        lines.append("FULL crib match via the clock mechanism -- reconstruct and")
        lines.append("re-encrypt to verify against OBKRUOXOG...")
    else:
        lines.append(
            f"Best {b['hits']}/{KNOWN} ~ chance. No faithful Berlin-Clock\n"
            f"keystream (any start/step/encoding) keys the cribs. This is the\n"
            f"expected result and now a demonstrated one: a cyclic clock emits a\n"
            f"structured sequence, but K4's required key is maximally aperiodic\n"
            f"(segmented.py). The clock's mechanism is not the keystream.\n"
            f"If it matters, it is more likely a SEMANTIC clue (the message says\n"
            f"'BERLIN CLOCK') than the cipher's key generator."
        )
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
