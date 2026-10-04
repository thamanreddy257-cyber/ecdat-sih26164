"""Mosca risk engine.

Mosca's inequality: an asset is at quantum risk when  X + Y > Z
  X = data shelf-life (years the protected data must stay confidential)
  Y = migration time  (years needed to move this system to PQC)
  Z = years until a cryptographically relevant quantum computer (CRQC)
Z is a SCENARIO PARAMETER chosen by the user, not a prediction.

Everything here is pure pandas on the cached scan results, so changing
X / Y / Z re-ranks instantly without rescanning.
"""
from __future__ import annotations

import pandas as pd

# ---- Scenario defaults (all editable in the UI) ----
DEFAULT_Y_MIGRATION = 5
DEFAULT_Z_CRQC = 12

# ---- Tier thresholds ----
CRITICAL_OVERSHOOT_YEARS = 2   # quantum-vulnerable AND overshoot (X+Y-Z) above this -> Critical
MARGIN_YEARS = 2               # quantum-vulnerable with X+Y within this many years of Z -> Medium

TIERS = ["Critical", "High", "Medium", "Low"]
TIER_RANK = {t: i for i, t in enumerate(TIERS)}

# ---- Criticality from path keywords (first match wins; edit freely) ----
CRITICALITY_RULES = [
    ("payments", "High"), ("payment", "High"), ("billing", "High"),
    ("auth", "High"), ("identity", "High"), ("keys", "High"), ("secrets", "High"),
    ("infra", "Medium"), ("archive", "Medium"), ("services", "Medium"),
    ("test", "Low"), ("docs", "Low"), ("examples", "Low"), ("sandbox", "Low"),
]
DEFAULT_CRITICALITY = "Medium"

# Default data shelf-life X (years) per criticality level.
DEFAULT_SHELF_LIFE = {"High": 10, "Medium": 8, "Low": 2}

TIER_RULES_TEXT = f"""
- **Critical** - quantum-vulnerable and overshoot (X + Y - Z) > {CRITICAL_OVERSHOOT_YEARS} years
- **High** - quantum-vulnerable and X + Y > Z
- **Medium** - classically weak today (e.g. MD5, SHA-1, ECB, 3DES, TLS 1.0), AES-128 (Grover margin),
  or quantum-vulnerable with X + Y within {MARGIN_YEARS} years of Z
- **Low** - already post-quantum, or not at risk under this scenario
"""


def top_folder(path: str) -> str:
    """'payments/rsa_keys.py' -> 'payments';  'README.md' -> '(root)'."""
    parts = str(path).split("/")
    return parts[0] if len(parts) > 1 else "(root)"


def criticality_for(path: str) -> str:
    p = str(path).lower()
    for keyword, level in CRITICALITY_RULES:
        if keyword in p:
            return level
    return DEFAULT_CRITICALITY


def folder_table(df: pd.DataFrame) -> pd.DataFrame:
    """One row per top-level folder with its criticality and default X (editable in UI)."""
    folders = sorted({top_folder(f) for f in df["file"]}) if not df.empty else []
    rows = []
    for f in folders:
        crit = criticality_for(f)
        rows.append({"folder": f, "criticality": crit, "shelf_life_X": DEFAULT_SHELF_LIFE[crit]})
    return pd.DataFrame(rows, columns=["folder", "criticality", "shelf_life_X"])


def classify(quantum_vulnerable: bool, classically_weak: bool, marginal: bool,
             family: str, x: float, y: float, z: float) -> tuple[str, float, bool]:
    """Return (tier, overshoot, mosca_at_risk) for one asset."""
    overshoot = x + y - z
    at_risk = bool(quantum_vulnerable) and overshoot > 0
    if family == "PQC":
        return "Low", overshoot, False
    if at_risk and overshoot > CRITICAL_OVERSHOOT_YEARS:
        return "Critical", overshoot, True
    if at_risk:
        return "High", overshoot, True
    if classically_weak or marginal or (quantum_vulnerable and overshoot >= -MARGIN_YEARS):
        return "Medium", overshoot, False
    return "Low", overshoot, False


def apply_risk(df: pd.DataFrame, y: float, z: float, folders: pd.DataFrame | None = None) -> pd.DataFrame:
    """Add folder, criticality, X, Y, Z, overshoot, mosca_at_risk and tier columns."""
    out = df.copy()
    if out.empty:
        for c in ["folder", "criticality", "X", "Y", "Z", "overshoot", "mosca_at_risk", "tier"]:
            out[c] = pd.Series(dtype=object)
        return out
    if folders is None or folders.empty:
        folders = folder_table(out)
    crit_map = dict(zip(folders["folder"], folders["criticality"]))
    x_map = dict(zip(folders["folder"], folders["shelf_life_X"]))

    out["folder"] = out["file"].map(top_folder)
    out["criticality"] = out["folder"].map(lambda f: crit_map.get(f, criticality_for(f)))
    out["X"] = out["folder"].map(lambda f: float(x_map.get(f, DEFAULT_SHELF_LIFE[criticality_for(f)])))
    out["Y"], out["Z"] = float(y), float(z)
    res = [classify(r.quantum_vulnerable, r.classically_weak, r.marginal, r.family, r.X, y, z)
           for r in out.itertuples()]
    out["tier"] = [t for t, _, _ in res]
    out["overshoot"] = [o for _, o, _ in res]
    out["mosca_at_risk"] = [a for _, _, a in res]
    out["tier_rank"] = out["tier"].map(TIER_RANK)
    return out.sort_values(["tier_rank", "file", "line"]).reset_index(drop=True)


def tier_counts(df: pd.DataFrame) -> dict:
    counts = df["tier"].value_counts().to_dict() if not df.empty else {}
    return {t: int(counts.get(t, 0)) for t in TIERS}
