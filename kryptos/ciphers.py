"""Reversible classical-cipher primitives, parameterised by alphabet.

These are deliberately small, exact, and round-trippable. Each encrypt has a
matching decrypt, and there is a self-test at the bottom (run this file
directly) that asserts encrypt/decrypt are true inverses. The point of the
tooling is to let you *reproduce a ciphertext*, which is the only real proof
for a K4 claim, so the primitives have to be trustworthy first.
"""

from __future__ import annotations

from .data import STANDARD_ALPHABET


def _index_map(alphabet: str) -> dict[str, int]:
    return {c: i for i, c in enumerate(alphabet)}


# ----------------------------------------------------------------------------
# Vigenere family (substitution; preserves letter order)
# ----------------------------------------------------------------------------

def vigenere_encrypt(plaintext: str, key: str, alphabet: str = STANDARD_ALPHABET) -> str:
    idx, n = _index_map(alphabet), len(alphabet)
    out = []
    for i, p in enumerate(plaintext):
        k = key[i % len(key)]
        out.append(alphabet[(idx[p] + idx[k]) % n])
    return "".join(out)


def vigenere_decrypt(ciphertext: str, key: str, alphabet: str = STANDARD_ALPHABET) -> str:
    idx, n = _index_map(alphabet), len(alphabet)
    out = []
    for i, c in enumerate(ciphertext):
        k = key[i % len(key)]
        out.append(alphabet[(idx[c] - idx[k]) % n])
    return "".join(out)


def beaufort(text: str, key: str, alphabet: str = STANDARD_ALPHABET) -> str:
    """Beaufort is its own inverse: C = K - P (mod n)."""
    idx, n = _index_map(alphabet), len(alphabet)
    out = []
    for i, t in enumerate(text):
        k = key[i % len(key)]
        out.append(alphabet[(idx[k] - idx[t]) % n])
    return "".join(out)


# ----------------------------------------------------------------------------
# Autokey (the keystream is extended by the plaintext itself)
# ----------------------------------------------------------------------------

def autokey_encrypt(plaintext: str, primer: str, alphabet: str = STANDARD_ALPHABET) -> str:
    idx, n = _index_map(alphabet), len(alphabet)
    keystream = primer + plaintext  # plaintext autokey
    return "".join(
        alphabet[(idx[p] + idx[keystream[i]]) % n] for i, p in enumerate(plaintext)
    )


def autokey_decrypt(ciphertext: str, primer: str, alphabet: str = STANDARD_ALPHABET) -> str:
    idx, n = _index_map(alphabet), len(alphabet)
    key = list(primer)
    out = []
    for i, c in enumerate(ciphertext):
        p = alphabet[(idx[c] - idx[key[i]]) % n]
        out.append(p)
        key.append(p)  # recovered plaintext feeds the keystream
    return "".join(out)


# ----------------------------------------------------------------------------
# Columnar transposition (reorders letters; this is the only family here that
# can move BERLIN to a different index than it occupies in the ciphertext)
# ----------------------------------------------------------------------------

def _key_order(key: str) -> list[int]:
    # Rank columns by their key letter (stable for duplicates).
    return [i for i, _ in sorted(enumerate(key), key=lambda kv: (kv[1], kv[0]))]


def columnar_encrypt(plaintext: str, key: str) -> str:
    cols = len(key)
    order = _key_order(key)
    rows = [plaintext[i:i + cols] for i in range(0, len(plaintext), cols)]
    out = []
    for col in order:
        for row in rows:
            if col < len(row):
                out.append(row[col])
    return "".join(out)


def columnar_decrypt(ciphertext: str, key: str) -> str:
    cols = len(key)
    n = len(ciphertext)
    full_rows, rem = divmod(n, cols)
    order = _key_order(key)
    # column lengths in original (unsorted) column order
    col_len = [full_rows + (1 if c < rem else 0) for c in range(cols)]
    # slice the ciphertext back into columns following the read-out order
    chunks: dict[int, str] = {}
    pos = 0
    for col in order:
        L = col_len[col]
        chunks[col] = ciphertext[pos:pos + L]
        pos += L
    # rebuild row by row
    out, ptrs = [], {c: 0 for c in range(cols)}
    for r in range(full_rows + (1 if rem else 0)):
        for c in range(cols):
            if r < col_len[c]:
                out.append(chunks[c][ptrs[c]])
                ptrs[c] += 1
    return "".join(out)


if __name__ == "__main__":
    from .data import KRYPTOS_ALPHABET
    msg, key = "THEQUICKBROWNFOXJUMPS", "KRYPTOS"
    assert vigenere_decrypt(vigenere_encrypt(msg, key), key) == msg
    assert vigenere_decrypt(
        vigenere_encrypt(msg, key, KRYPTOS_ALPHABET), key, KRYPTOS_ALPHABET
    ) == msg
    assert beaufort(beaufort(msg, key), key) == msg
    assert autokey_decrypt(autokey_encrypt(msg, key), key) == msg
    assert columnar_decrypt(columnar_encrypt(msg, "CIPHER"), "CIPHER") == msg
    assert columnar_decrypt(columnar_encrypt("ABCDEFGHIJ", "KEYB"), "KEYB") == "ABCDEFGHIJ"
    print("ciphers.py self-test passed: all primitives round-trip cleanly")
