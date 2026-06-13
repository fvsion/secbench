"""Pure-stdlib statistical primitives borrowed from other domains.

Kept free of any project imports so it can be unit-tested in isolation and
reused anywhere. Each function documents *why* the technique is the right tool,
not just what it computes.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import List, Sequence


def shannon_entropy(data: str) -> float:
    """Shannon entropy in bits-per-character of ``data``.

    From information theory: high entropy means the characters are close to
    uniformly distributed, which is the signature of a random token (an API
    key, a password hash) as opposed to natural-language text or a path. This
    is the core discriminator the secret scanner uses to avoid drowning in
    false positives — English prose sits around 3–4 bits/char, a base64 secret
    closer to 5–6.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def normalized_entropy(data: str) -> float:
    """Entropy scaled to 0–1 against the maximum possible for the alphabet used.

    Normalizing makes a threshold meaningful regardless of how many distinct
    characters a string draws on, so the same cut-off works for hex, base64,
    and arbitrary tokens.
    """
    if not data:
        return 0.0
    distinct = len(set(data))
    if distinct <= 1:
        return 0.0
    return shannon_entropy(data) / math.log2(distinct)


def median(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    mid = len(s) // 2
    if len(s) % 2:
        return float(s[mid])
    return (s[mid - 1] + s[mid]) / 2.0


def median_absolute_deviation(values: Sequence[float]) -> float:
    """The median of absolute deviations from the median (MAD).

    A robust dispersion measure: unlike standard deviation it is not dragged
    around by the very outliers we are trying to detect. One compromised
    account with a wildly anomalous attribute will not inflate the spread and
    hide itself.
    """
    if not values:
        return 0.0
    med = median(values)
    return median([abs(v - med) for v in values])


def modified_z_scores(values: Sequence[float]) -> List[float]:
    """Iglewicz–Hoaglin modified z-scores using the MAD.

    The constant 0.6745 makes the MAD a consistent estimator of the standard
    deviation for normal data. A common convention flags |score| > 3.5 as an
    outlier; we expose the raw scores so callers choose their own threshold.
    Returns zeros when the data has no spread (every value identical).
    """
    if not values:
        return []
    med = median(values)
    mad = median_absolute_deviation(values)
    if mad == 0:
        # Fall back to mean absolute deviation to avoid divide-by-zero while
        # still surfacing the single value that differs, if any.
        mean_abs = sum(abs(v - med) for v in values) / len(values)
        if mean_abs == 0:
            return [0.0 for _ in values]
        return [0.7979 * (v - med) / mean_abs for v in values]
    return [0.6745 * (v - med) / mad for v in values]


def _stdev(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return (sum((v - mean) ** 2 for v in values) / len(values)) ** 0.5


def cusum(values: Sequence[float], k: float = 0.5, h: float = 4.0) -> List[int]:
    """Tabular CUSUM change detection (Page, 1954); returns shift indices.

    From statistical process control: instead of reacting only to a single
    point breaching a control limit, CUSUM accumulates small deviations from an
    *established baseline* and fires when the running sum crosses a threshold —
    so it catches a slow, sustained drift (e.g. compliance eroding a little each
    rescan) that point-wise limits miss.

    The baseline mean/sd are taken from the earlier portion of the series, not
    the whole of it: a level shift contaminates the global mean (it settles
    between the two levels, so neither side accumulates), whereas referencing
    the in-control baseline is what makes the detector actually fire. ``k`` is
    the slack and ``h`` the decision threshold, both in baseline-sd units.

    We watch the security-relevant direction — a downward shift in compliance —
    and return the indices at which a sustained drop is signalled. Empty when
    the series is too short.
    """
    n = len(values)
    if n < 4:
        return []
    baseline = values[: max(2, n // 2)]
    mu0 = sum(baseline) / len(baseline)
    sd = _stdev(baseline) or _stdev(values) or 1.0
    slack = k * sd
    threshold = h * sd
    s_low = 0.0
    signals: List[int] = []
    for i, v in enumerate(values):
        # Lower CUSUM accumulates downward deviations from the baseline beyond
        # the slack; it cannot go positive.
        s_low = min(0.0, s_low + (v - mu0) + slack)
        if -s_low > threshold:
            signals.append(i)
            s_low = 0.0  # reset after signalling
    return signals


def _student_t_pdf(x: float, df: float, loc: float, scale: float) -> float:
    """Student-t probability density — the predictive distribution for BOCPD."""
    if scale <= 0:
        scale = 1e-9
    z = (x - loc) / scale
    coeff = math.gamma((df + 1) / 2) / (math.gamma(df / 2) * math.sqrt(df * math.pi) * scale)
    return coeff * (1 + z * z / df) ** (-(df + 1) / 2)


def bocpd(
    values: Sequence[float],
    hazard: float = 0.15,
    mu0: Optional[float] = None,
    kappa0: float = 1.0,
    alpha0: float = 2.0,
    beta0: Optional[float] = None,
) -> List[int]:
    """Bayesian Online Changepoint Detection (Adams & MacKay, 2007).

    Where CUSUM accumulates deviation from a fixed baseline, BOCPD keeps a
    probability distribution over "how long since the last change" and updates
    it every new scan. When the data stops looking like the current regime it
    rapidly concludes a change happened — so it adapts to *multiple* shifts and
    to a new normal, which a single-baseline detector does not.

    This is the 1-D Gaussian version with a Normal-Inverse-Gamma prior (so the
    predictive is a Student-t) and a constant hazard. ``hazard`` is the prior
    probability that any given step is a change (≈ 1/expected-run-length).

    Returns the indices at which a changepoint is most-probably detected (the
    run-length estimate collapses back toward zero). Empty for short series.
    """
    n = len(values)
    if n < 4:
        return []
    if mu0 is None:
        mu0 = sum(values) / n
    # Seed the prior variance from a robust estimate of the *within-regime*
    # noise — the MAD of step-to-step differences. Using the whole-series
    # variance would be self-defeating: a big shift inflates it, so the very
    # change we want to detect would look unremarkable. Differences cancel the
    # level, and their MAD ignores the one large jump at the change.
    if beta0 is None:
        diffs = [values[i] - values[i - 1] for i in range(1, n)]
        sigma = (median_absolute_deviation(diffs) / 0.6745) if diffs else 0.0
        if sigma <= 0:
            sigma = _stdev(values) or 1.0
        beta0 = max(sigma, 1e-3) ** 2

    # Per-run-length Normal-Inverse-Gamma parameters; index r = run length.
    mu = [mu0]
    kappa = [kappa0]
    alpha = [alpha0]
    beta = [beta0]
    run_prob = [1.0]            # P(run length = r) at current step
    map_run = []                # most-likely run length after each datum

    for x in values:
        # Predictive probability of x under each current run length.
        pred = []
        for r in range(len(run_prob)):
            df = 2 * alpha[r]
            scale = math.sqrt(beta[r] * (kappa[r] + 1) / (alpha[r] * kappa[r]))
            pred.append(_student_t_pdf(x, df, mu[r], scale))

        # Growth (no change) and changepoint (reset to run length 0) masses.
        new_prob = [0.0] * (len(run_prob) + 1)
        cp_mass = 0.0
        for r in range(len(run_prob)):
            new_prob[r + 1] = run_prob[r] * pred[r] * (1 - hazard)
            cp_mass += run_prob[r] * pred[r] * hazard
        new_prob[0] = cp_mass

        total = sum(new_prob) or 1.0
        run_prob = [p / total for p in new_prob]

        # Update sufficient statistics: each surviving run length absorbs x,
        # and a fresh run length 0 is seeded from the prior.
        new_mu = [mu0]
        new_kappa = [kappa0]
        new_alpha = [alpha0]
        new_beta = [beta0]
        for r in range(len(mu)):
            new_kappa.append(kappa[r] + 1)
            new_mu.append((kappa[r] * mu[r] + x) / (kappa[r] + 1))
            new_alpha.append(alpha[r] + 0.5)
            new_beta.append(beta[r] + (kappa[r] * (x - mu[r]) ** 2) / (2 * (kappa[r] + 1)))
        mu, kappa, alpha, beta = new_mu, new_kappa, new_alpha, new_beta

        map_run.append(max(range(len(run_prob)), key=lambda r: run_prob[r]))

    # A changepoint is where the most-likely run length collapses (a new regime
    # begins): it drops sharply and lands near zero.
    signals = []
    for i in range(1, len(map_run)):
        if map_run[i] < map_run[i - 1] - 1 and map_run[i] <= 1:
            signals.append(i)
    return signals


def ewma(values: Sequence[float], alpha: float = 0.4) -> List[float]:
    """Exponentially weighted moving average.

    Straight from quantitative finance and statistical process control: recent
    observations are weighted more heavily than old ones, so the smoothed
    series tracks genuine drift in compliance over a run of rescans while
    damping the single-scan noise of a transient finding. ``alpha`` is the
    responsiveness (higher = follows recent values faster).
    """
    if not values:
        return []
    if not 0.0 < alpha <= 1.0:
        raise ValueError("alpha must be in (0, 1]")
    out = [float(values[0])]
    for v in values[1:]:
        out.append(alpha * v + (1.0 - alpha) * out[-1])
    return out
