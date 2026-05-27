"""Statistical helpers used in the paper's experiment design (paper §4.2):

  * paired McNemar test for binary outcomes
  * Wilcoxon signed-rank for paired latency distributions
  * Mann–Whitney U for two independent latency distributions (paper §4.2.3)
  * Wilson score interval for proportions (95% CI)
  * Holm–Bonferroni multiple-comparison correction
"""
from __future__ import annotations
import math
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple


# ---------------- proportions ----------------
def wilson_ci(successes: int, total: int, z: float = 1.96) -> Tuple[float, float]:
    if total == 0:
        return (0.0, 0.0)
    p = successes / total
    z2 = z * z
    denom = 1 + z2 / total
    center = (p + z2 / (2 * total)) / denom
    half = (z * math.sqrt(p * (1 - p) / total + z2 / (4 * total * total))) / denom
    return (max(0.0, center - half), min(1.0, center + half))


# ---------------- McNemar (paired binary) ----------------
@dataclass
class McNemarResult:
    b: int   # only A correct (or only A blocked)
    c: int   # only B correct
    chi2: float
    p_value: float


def mcnemar(decisions_a: Sequence[bool], decisions_b: Sequence[bool]) -> McNemarResult:
    """Paired binary outcomes. We compare *correct* on each item.

    `decisions_a[i]` is True iff system A made the right call on case i.
    """
    if len(decisions_a) != len(decisions_b):
        raise ValueError("inputs must be paired (same length)")
    b = sum(1 for a, x in zip(decisions_a, decisions_b) if a and not x)
    c = sum(1 for a, x in zip(decisions_a, decisions_b) if x and not a)
    if b + c == 0:
        return McNemarResult(0, 0, 0.0, 1.0)
    # mid-p exact binomial p-value (two-sided, conservative continuity correction)
    chi2 = (abs(b - c) - 1) ** 2 / (b + c) if (b + c) > 0 else 0.0
    # Approximate p-value via chi^2 with 1 dof.
    p = math.exp(-chi2 / 2.0)
    return McNemarResult(b, c, chi2, p)


# ---------------- Wilcoxon signed-rank ----------------
@dataclass
class WilcoxonResult:
    statistic: float
    z: float
    p_value: float


def wilcoxon_signed_rank(diffs: Sequence[float]) -> WilcoxonResult:
    nonzero = [d for d in diffs if d != 0]
    n = len(nonzero)
    if n == 0:
        return WilcoxonResult(0.0, 0.0, 1.0)
    abs_sorted = sorted(((abs(d), d) for d in nonzero), key=lambda x: x[0])
    # average ranks for ties
    ranks: List[float] = []
    i = 0
    while i < n:
        j = i
        while j + 1 < n and abs_sorted[j + 1][0] == abs_sorted[i][0]:
            j += 1
        avg = (i + j) / 2 + 1
        for _ in range(j - i + 1):
            ranks.append(avg)
        i = j + 1
    w_plus = sum(r for r, (_, d) in zip(ranks, abs_sorted) if d > 0)
    w_minus = sum(r for r, (_, d) in zip(ranks, abs_sorted) if d < 0)
    w = min(w_plus, w_minus)
    mean = n * (n + 1) / 4
    var = n * (n + 1) * (2 * n + 1) / 24
    if var == 0:
        return WilcoxonResult(w, 0.0, 1.0)
    z = (w - mean) / math.sqrt(var)
    # two-sided normal approximation
    p = 2 * (1 - _phi(abs(z)))
    return WilcoxonResult(w, z, p)


def _phi(x: float) -> float:
    return 0.5 * (1 + math.erf(x / math.sqrt(2)))


# ---------------- Mann–Whitney U (independent two-sample) ----------------
@dataclass
class MannWhitneyResult:
    u: float
    z: float
    p_value: float


def mann_whitney_u(xs: Sequence[float], ys: Sequence[float]) -> MannWhitneyResult:
    """Two-sided Mann–Whitney U with normal approximation + tie correction.

    Used in paper §4.2.3 for latency distributions across systems where
    pairing is impossible (different schedulers / different runs).
    """
    n1, n2 = len(xs), len(ys)
    if n1 == 0 or n2 == 0:
        return MannWhitneyResult(0.0, 0.0, 1.0)
    combined = sorted(((v, 0) for v in xs), key=lambda x: x[0]) + \
               sorted(((v, 1) for v in ys), key=lambda x: x[0])
    combined.sort(key=lambda x: x[0])
    # average ranks
    ranks: List[float] = []
    i = 0
    n = len(combined)
    tie_correction = 0.0
    while i < n:
        j = i
        while j + 1 < n and combined[j + 1][0] == combined[i][0]:
            j += 1
        avg = (i + j) / 2 + 1
        for _ in range(j - i + 1):
            ranks.append(avg)
        if j > i:
            t = j - i + 1
            tie_correction += t ** 3 - t
        i = j + 1
    r1 = sum(r for r, (_, g) in zip(ranks, combined) if g == 0)
    u1 = r1 - n1 * (n1 + 1) / 2
    u2 = n1 * n2 - u1
    u = min(u1, u2)
    mu = n1 * n2 / 2
    sigma2 = n1 * n2 * (n1 + n2 + 1) / 12
    sigma2 -= n1 * n2 * tie_correction / (12 * (n1 + n2) * (n1 + n2 - 1)) if (n1 + n2) > 1 else 0
    if sigma2 <= 0:
        return MannWhitneyResult(u, 0.0, 1.0)
    z = (u - mu) / math.sqrt(sigma2)
    p = 2 * (1 - _phi(abs(z)))
    return MannWhitneyResult(u, z, p)


# ---------------- Holm–Bonferroni ----------------
def holm_bonferroni(p_values: Iterable[float], alpha: float = 0.05) -> List[bool]:
    """Returns a list of booleans (reject null at corrected level, in input order)."""
    p_list = list(p_values)
    indexed = sorted(enumerate(p_list), key=lambda x: x[1])
    n = len(indexed)
    rej = [False] * n
    for k, (idx, p) in enumerate(indexed):
        thr = alpha / (n - k)
        if p <= thr:
            rej[idx] = True
        else:
            break
    return rej


# ---------------- aggregate metrics ----------------
def median(xs: Sequence[float]) -> float:
    s = sorted(xs)
    n = len(s)
    if n == 0:
        return 0.0
    if n % 2:
        return s[n // 2]
    return 0.5 * (s[n // 2 - 1] + s[n // 2])


def clopper_pearson_upper(successes: int, total: int,
                           alpha: float = 0.05) -> float:
    """One-sided Clopper-Pearson upper 95% bound on a proportion.

    Used by paper §5.1.4 for zero-event reporting: "0 successes in N
    trials does not mean 'never'; it bounds the success rate by the
    upper limit of the exact binomial CI."

    Returns the upper bound on p such that P(X <= successes) >= alpha
    under a Binomial(total, p) model. For the common zero-event case
    (successes=0) this reduces to 1 - alpha**(1/total).
    """
    if total == 0:
        return 1.0
    if successes >= total:
        return 1.0
    if successes == 0:
        # Closed form for zero successes
        return 1.0 - alpha ** (1.0 / total)
    # Bisection on the incomplete-beta tail
    lo, hi = float(successes) / total, 1.0
    for _ in range(60):
        mid = 0.5 * (lo + hi)
        # P(X <= successes) under Bin(total, mid)
        cum = _binom_cdf(successes, total, mid)
        if cum < alpha:
            hi = mid
        else:
            lo = mid
    return hi


def _binom_cdf(k: int, n: int, p: float) -> float:
    """Compute P(X <= k) for X ~ Binomial(n, p) via direct summation
    in log-space to avoid overflow on large n."""
    # log binomial coefficient
    if p <= 0.0:
        return 1.0 if k >= 0 else 0.0
    if p >= 1.0:
        return 1.0 if k >= n else 0.0
    total = 0.0
    log_p = math.log(p)
    log_1mp = math.log(1.0 - p)
    log_coef = 0.0  # log C(n, 0) = 0
    for i in range(0, k + 1):
        log_pmf = log_coef + i * log_p + (n - i) * log_1mp
        total += math.exp(log_pmf)
        # update log_coef: C(n, i+1) = C(n, i) * (n - i) / (i + 1)
        if i < k:
            log_coef += math.log(n - i) - math.log(i + 1)
    return total


def clustered_bootstrap_ci(values: Sequence[float],
                            cluster_ids: Sequence,
                            *, reps: int = 10_000,
                            alpha: float = 0.05,
                            seed: int = 0,
                            statistic: str = "mean"
                            ) -> Tuple[float, float, float]:
    """Cluster-bootstrap CI for non-independent observations.

    Required by paper §5.A statistics protocol: trajectory-level
    observations are NOT independent Bernoulli trials when many trajectories
    are generated from the same task unit. The clustered bootstrap resamples
    *task units* (with replacement) instead of trajectories, then re-aggregates
    the per-unit statistic.

    Args:
      values       : per-trajectory observations (e.g. 0/1 unsafe-commit)
      cluster_ids  : the task-unit id each value belongs to
      reps         : 10 000 by default (paper protocol)
      statistic    : "mean" (proportion) or "any" (unit has >=1 success)

    Returns: (point_estimate, lo, hi) on the (1-alpha) CI of the
    population statistic.
    """
    import random
    if not values:
        return (0.0, 0.0, 0.0)
    if len(values) != len(cluster_ids):
        raise ValueError("values and cluster_ids must align")

    # group by cluster
    groups: dict = {}
    for v, cid in zip(values, cluster_ids):
        groups.setdefault(cid, []).append(float(v))
    cluster_keys = list(groups.keys())

    def _agg(sampled_keys):
        if statistic == "any":
            # Unit-level: a unit "succeeds" if ANY of its trajectories did.
            succ = 0
            for k in sampled_keys:
                if max(groups[k]) > 0:
                    succ += 1
            return succ / len(sampled_keys)
        # Default: proportion of trajectories with success
        total = 0; n = 0
        for k in sampled_keys:
            total += sum(groups[k])
            n     += len(groups[k])
        return total / max(n, 1)

    point = _agg(cluster_keys)

    rng = random.Random(seed)
    estimates: List[float] = []
    n_cl = len(cluster_keys)
    for _ in range(reps):
        sample = [cluster_keys[rng.randrange(n_cl)] for _ in range(n_cl)]
        estimates.append(_agg(sample))
    estimates.sort()
    lo = estimates[int((alpha / 2) * reps)]
    hi = estimates[int((1 - alpha / 2) * reps) - 1]
    return (point, lo, hi)


def bootstrap_ci(values: Sequence[float], *, reps: int = 2000,
                 alpha: float = 0.05, seed: int = 0) -> Tuple[float, float]:
    """Percentile-bootstrap (1-alpha) confidence interval for the mean.

    Used by paper §4.3 to report per-cluster bootstrap CIs on Task-UCR / ASR.
    """
    import random
    if not values:
        return (0.0, 0.0)
    rng = random.Random(seed)
    n = len(values)
    means: List[float] = []
    for _ in range(reps):
        sample_sum = 0.0
        for _ in range(n):
            sample_sum += values[rng.randrange(n)]
        means.append(sample_sum / n)
    means.sort()
    lo = means[int((alpha / 2) * reps)]
    hi = means[int((1 - alpha / 2) * reps) - 1]
    return (lo, hi)


def percentile(xs: Sequence[float], q: float) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    k = (len(s) - 1) * q
    lo = int(math.floor(k))
    hi = int(math.ceil(k))
    if lo == hi:
        return s[lo]
    return s[lo] + (s[hi] - s[lo]) * (k - lo)
