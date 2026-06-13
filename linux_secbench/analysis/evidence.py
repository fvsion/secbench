"""Combining several weak clues into one confidence (Dempster–Shafer).

When the credential scanner looks at a line, it usually has *several* weak hints
at once: the value looks random (high entropy), the key is named "password", the
file lives somewhere sensitive, the text matches a known token shape. None alone
is proof. The naive approaches are both wrong: taking the strongest single hint
ignores corroboration, and multiplying probabilities assumes the hints are
independent when they overlap.

Dempster–Shafer theory handles exactly this — combining overlapping, uncertain
evidence while keeping an explicit "don't know" bucket so weak hints raise
confidence without ever pretending to certainty they haven't earned. Here the
question is binary — is this a real secret or not — and each clue contributes a
little belief toward "secret", a little toward "not", and leaves the rest as
uncertainty. Combining them yields one calibrated belief we map to the existing
confidence levels.
"""

from __future__ import annotations

import dataclasses
from typing import List, Tuple

from ..core.model import Confidence

# A piece of evidence: (mass toward "secret", mass toward "not secret").
# Whatever is left over (1 − s − n) is uncertainty — the "don't know" bucket.
Signal = Tuple[float, float]


@dataclasses.dataclass
class Belief:
    secret: float       # belief it IS a secret
    not_secret: float   # belief it is NOT
    uncertain: float    # unassigned mass

    @property
    def plausibility(self) -> float:
        """Upper bound on the secret belief (belief + the benefit of the doubt)."""
        return self.secret + self.uncertain

    def confidence(self) -> Confidence:
        if self.secret >= 0.8:
            return Confidence.CERTAIN
        if self.secret >= 0.5:
            return Confidence.LIKELY
        return Confidence.POSSIBLE

    def is_secret(self, threshold: float = 0.4) -> bool:
        """Whether the fused belief clears the reporting bar."""
        return self.secret >= threshold


def combine(signals: List[Signal]) -> Belief:
    """Fuse evidence with Dempster's rule of combination.

    Starts from total uncertainty and folds in each signal, renormalising away
    the conflict (the mass where two signals flatly disagree). Empty input
    returns pure uncertainty.
    """
    # Vacuous belief: everything is uncertain to begin with.
    bel_s, bel_n, bel_u = 0.0, 0.0, 1.0
    for s, n in signals:
        s = min(1.0, max(0.0, s))
        n = min(1.0, max(0.0, n))
        u = max(0.0, 1.0 - s - n)
        # Dempster combination of (bel_s, bel_n, bel_u) with (s, n, u).
        new_s = bel_s * s + bel_s * u + bel_u * s
        new_n = bel_n * n + bel_n * u + bel_u * n
        new_u = bel_u * u
        conflict = bel_s * n + bel_n * s   # the two sides disagreeing
        norm = 1.0 - conflict
        if norm <= 0:
            # Total conflict — fall back to uncertainty rather than divide by 0.
            bel_s, bel_n, bel_u = 0.0, 0.0, 1.0
            continue
        bel_s, bel_n, bel_u = new_s / norm, new_n / norm, new_u / norm
    return Belief(bel_s, bel_n, bel_u)


# --------------------------------------------------------------------------- #
# Convenience: turn the credential scanner's clues into a fused belief.
# --------------------------------------------------------------------------- #

def fuse_secret_signals(
    *,
    known_marker: bool = False,
    high_entropy: bool = False,
    secret_keyword: bool = False,
    sensitive_location: bool = False,
    looks_like_placeholder: bool = False,
) -> Belief:
    """Combine the credential-scanner clues into one belief about "is a secret".

    Each clue is weighted by how telling it is on its own — a literal private-key
    header is near-conclusive; a high-entropy value is suggestive; a placeholder
    is evidence *against*. The masses leave generous uncertainty so that one
    weak clue stays "possible" and only corroboration reaches "certain".
    """
    signals: List[Signal] = []
    if known_marker:
        signals.append((0.85, 0.0))     # e.g. "-----BEGIN PRIVATE KEY-----"
    if high_entropy:
        signals.append((0.5, 0.05))     # random-looking value
    if secret_keyword:
        signals.append((0.45, 0.05))    # key named password/token/...
    if sensitive_location:
        signals.append((0.25, 0.0))     # under /etc, a .env, etc.
    if looks_like_placeholder:
        signals.append((0.0, 0.7))      # "changeme", "example" → evidence against
    return combine(signals)
