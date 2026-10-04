"""Mosca tiering on hand-made cases."""
import pandas as pd

from risk import CRITICAL_OVERSHOOT_YEARS, apply_risk, classify, criticality_for


def test_critical_when_overshoot_above_threshold():
    tier, over, at_risk = classify(True, False, False, "RSA", x=10, y=5, z=12)
    assert over == 3 > CRITICAL_OVERSHOOT_YEARS and tier == "Critical" and at_risk


def test_high_when_small_overshoot():
    tier, over, at_risk = classify(True, False, False, "ECC", x=8, y=5, z=12)
    assert over == 1 and tier == "High" and at_risk


def test_medium_when_marginal_or_weak():
    assert classify(True, False, False, "RSA", x=5, y=5, z=12)[0] == "Medium"   # within margin of Z
    assert classify(False, True, False, "hash", x=1, y=1, z=30)[0] == "Medium"  # MD5-like
    assert classify(False, False, True, "AES", x=1, y=1, z=30)[0] == "Medium"   # AES-128


def test_low_cases():
    assert classify(True, False, False, "RSA", x=1, y=1, z=30)[0] == "Low"
    assert classify(False, False, False, "PQC", x=50, y=50, z=1)[0] == "Low"
    assert classify(False, False, False, "AES", x=50, y=50, z=1)[0] == "Low"     # AES-256 not qv


def test_criticality_keywords():
    assert criticality_for("payments/x.py") == "High"
    assert criticality_for("archive/x.py") == "Medium"
    assert criticality_for("docs/x.md") == "Low"


def test_apply_risk_reranks_with_z():
    df = pd.DataFrame([{"file": "payments/a.py", "line": 1, "family": "RSA", "quantum_vulnerable": True,
                        "classically_weak": False, "marginal": False}])
    assert apply_risk(df, y=5, z=12).iloc[0]["tier"] == "Critical"
    assert apply_risk(df, y=5, z=40).iloc[0]["tier"] == "Low"
