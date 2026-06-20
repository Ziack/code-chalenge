"""The user-submitted hypothesis, recorded verbatim, plus an honest audit.

This module does NOT endorse the hypothesis. It records the claim exactly as
submitted and runs every check that can be run without a fully-specified
algorithm, reporting pass/fail plainly. The goal is to separate what is
verifiable from what is asserted.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .analysis import check_cribs_positional, find_substrings, index_of_coincidence
from .data import CRIBS

# ---- the submission, recorded as-received -------------------------------------
SUBMISSION = {
    "target_cipher": "Kryptos_K4",
    "solver_method": "Multi-Layered_Fractional_Transposition_Autokey",
    "geometric_parameters": {
        "primary_matrix_width": 12,
        "levenshtein_fault_index": 40,
        "levenshtein_fault_delta": -1,
        "polybius_asymmetric_offsets": {"row_shift": 2, "col_shift": 1},
    },
    "substitution_parameters": {
        "base_clock_multiplier": 4,
        "segmented_modulo5_seeds": {
            "row_1_baseline_c1": 12, "row_2_berlin_clock": 2,
            "row_3_baseline_c2": 4, "row_4_northeast_clock": 3,
            "row_5_baseline_c3": 16,
        },
        "vigenere_step_coefficients": {"block_1_k1": 1, "block_2_k2": 4},
    },
    "extracted_payload": {
        "active_plaintext_67": (
            "SHADOWSFALLINGTWOPACESTOTHEBERLINCLOCKEASTNORTHEASTTOTHEHIDDENDOORWAY"
        ),
        "trailing_anchor_30": "HBLSEKCDAJAFLWBAUMBICTURFX",
        "calculated_courtyard_bearing_deg": 143.13,
    },
}


@dataclass
class Finding:
    name: str
    passed: bool
    detail: str


@dataclass
class Audit:
    findings: list[Finding] = field(default_factory=list)

    def add(self, name: str, passed: bool, detail: str) -> None:
        self.findings.append(Finding(name, passed, detail))

    @property
    def ok(self) -> bool:
        return all(f.passed for f in self.findings)

    def render(self) -> str:
        lines = ["Hypothesis audit", "=" * 60]
        for f in self.findings:
            lines.append(f"[{'PASS' if f.passed else 'FAIL'}] {f.name}")
            lines.append(f"        {f.detail}")
        lines.append("-" * 60)
        verdict = ("All runnable checks passed -- worth implementing the full "
                   "forward cipher next."
                   if self.ok else
                   "One or more verifiable checks FAILED. The claim is not "
                   "supported as stated.")
        lines.append(verdict)
        return "\n".join(lines)


def audit() -> Audit:
    a = Audit()
    payload = SUBMISSION["extracted_payload"]
    pt = payload["active_plaintext_67"]
    anchor = payload["trailing_anchor_30"]

    # 1. Self-consistent lengths?
    a.add(
        "label vs actual length: active_plaintext",
        len(pt) == 67,
        f"label says 67, actual is {len(pt)}",
    )
    a.add(
        "label vs actual length: trailing_anchor",
        len(anchor) == 30,
        f"label says 30, actual is {len(anchor)}",
    )

    # 2. Does the decomposition cover the 97-char ciphertext?
    a.add(
        "segments cover 97 chars",
        len(pt) + len(anchor) == 97,
        f"{len(pt)} + {len(anchor)} = {len(pt) + len(anchor)} (need 97)",
    )

    # 3. Positional cribs (the strict, community-standard reading).
    rows = check_cribs_positional(pt)
    bad = [f"{w}@{CRIBS[w][0]} got '{found}'" for w, _e, found, ok in rows if not ok]
    a.add(
        "positional cribs (plaintext[i] == decrypt(ciphertext[i]))",
        not bad,
        "all four cribs land in place" if not bad else "; ".join(bad),
    )

    # 4. Loose reading: are the crib WORDS at least present somewhere, and in an
    #    order compatible with a transposition step?
    hits = find_substrings(pt, ["EAST", "NORTHEAST", "BERLIN", "CLOCK"])
    present = all(hits[w] for w in ["NORTHEAST", "BERLIN", "CLOCK"])
    a.add(
        "crib words present (order-agnostic, transposition-friendly)",
        present,
        f"found at 1-indexed starts: {hits}",
    )

    # 5. Language plausibility of the 'active plaintext'.
    ioc = index_of_coincidence(pt)
    a.add(
        "active plaintext reads as English",
        ioc > 0.060,
        f"IoC={ioc:.4f} (English ~0.066); note this is trivially true because "
        f"the plaintext was written, not derived -- it proves nothing about K4",
    )

    # 6. The decisive test, which CANNOT be run from this JSON.
    a.add(
        "reproduces the exact K4 ciphertext via forward encryption",
        False,
        "NOT TESTABLE: the JSON lists parameters (matrix width, Polybius "
        "offsets, mod-5 seeds, Levenshtein 'fault' index, etc.) but not an "
        "unambiguous, reversible step sequence. Until the pipeline is "
        "specified as runnable code that turns the plaintext into "
        "'OBKRUOXOG...', the central claim is unverified.",
    )
    return a


if __name__ == "__main__":
    print(audit().render())
