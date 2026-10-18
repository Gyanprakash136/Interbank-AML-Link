"""Evaluation metrics with explicit raw counts and denominators.

Rates are ``None`` (not 0.0) when the denominator is zero, so an undefined metric is
never reported as a perfect or a zero score. Evaluation-only: never import from
operational modules.
"""

from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional, Set


def safe_div(num: float, den: float) -> Optional[float]:
    return None if den == 0 else num / den


@dataclass(frozen=True)
class Confusion:
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def precision(self) -> Optional[float]:
        return safe_div(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> Optional[float]:
        return safe_div(self.tp, self.tp + self.fn)

    @property
    def f1(self) -> Optional[float]:
        p, r = self.precision, self.recall
        if p is None or r is None or (p + r) == 0:
            return None
        return 2 * p * r / (p + r)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.update(precision=self.precision, recall=self.recall, f1=self.f1,
                 predicted_positive=self.tp + self.fp, actual_positive=self.tp + self.fn,
                 universe=self.tp + self.fp + self.fn + self.tn)
        return d


def confusion_from_sets(predicted: Set[str], positives: Set[str], universe: Set[str]) -> Confusion:
    """Counts over ``universe``; predictions/positives outside it are rejected loudly."""
    outside = (predicted | positives) - universe
    if outside:
        raise ValueError(f"{len(outside)} predicted/positive ids are outside the universe")
    tp = len(predicted & positives)
    fp = len(predicted - positives)
    fn = len(positives - predicted)
    tn = len(universe) - tp - fp - fn
    return Confusion(tp=tp, fp=fp, fn=fn, tn=tn)
