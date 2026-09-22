"""Confusion-matrix metrics (shared by the experiment scripts)."""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class Metrics:
    tp: int; fp: int; tn: int; fn: int

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def as_dict(self) -> dict:
        return {"tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
                "precision": round(self.precision, 4),
                "recall": round(self.recall, 4),
                "f1": round(self.f1, 4)}


def confusion(pairs: list[tuple[bool, bool]]) -> Metrics:
    """pairs = list of (predicted_positive, ground_truth_positive)."""
    tp = sum(1 for p, g in pairs if p and g)
    fp = sum(1 for p, g in pairs if p and not g)
    tn = sum(1 for p, g in pairs if not p and not g)
    fn = sum(1 for p, g in pairs if not p and g)
    return Metrics(tp, fp, tn, fn)
