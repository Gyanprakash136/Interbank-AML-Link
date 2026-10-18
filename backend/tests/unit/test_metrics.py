import pytest

from app.evaluation.metrics import Confusion, confusion_from_sets


def test_confusion_counts_and_rates():
    c = confusion_from_sets({"a", "b", "c"}, {"b", "c", "d"}, {"a", "b", "c", "d", "e", "f"})
    assert (c.tp, c.fp, c.fn, c.tn) == (2, 1, 1, 2)
    assert c.precision == pytest.approx(2 / 3)
    assert c.recall == pytest.approx(2 / 3)
    assert c.f1 == pytest.approx(2 / 3)
    d = c.to_dict()
    assert d["predicted_positive"] == 3 and d["actual_positive"] == 3 and d["universe"] == 6


def test_undefined_rates_are_none_not_zero():
    c = confusion_from_sets(set(), {"x"}, {"x", "y"})
    assert c.precision is None and c.recall == 0.0 and c.f1 is None
    empty = confusion_from_sets(set(), set(), {"x"})
    assert empty.precision is None and empty.recall is None


def test_ids_outside_universe_rejected():
    with pytest.raises(ValueError):
        confusion_from_sets({"zzz"}, set(), {"a"})
