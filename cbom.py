"""CycloneDX 1.6 CBOM (Cryptography Bill of Materials) writer.

Field names follow the official CycloneDX 1.6 JSON schema (bom-1.6.schema.json):
component.type = "cryptographic-asset", component.cryptoProperties with
assetType / algorithmProperties / certificateProperties / protocolProperties /
relatedCryptoMaterialProperties, and evidence.occurrences (location, line).
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone

import pandas as pd

from risk import TIER_RANK
from rules import NIST_QUANTUM_LEVEL

TOOL_NAME, TOOL_VERSION = "ECDAT", "0.1.0"
REQUIRED_TOP_LEVEL = ["bomFormat", "specVersion", "serialNumber", "version", "metadata", "components"]

AES_NIST_LEVEL = {"128": 1, "192": 3, "256": 5}   # NIST categories are defined by AES key sizes
MODES = {"ECB": "ecb", "CBC": "cbc", "GCM": "gcm", "CCM": "ccm", "CTR": "ctr", "CFB": "cfb", "OFB": "ofb"}
CURVE_HINT = re.compile(r"(?i)^(secp|prime|P-?\d|brainpool|X25519|Ed25519)")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-")


def _algorithm_properties(row) -> dict:
    props = {"primitive": row.primitive or "unknown"}
    param = str(row.param or "")
    if param and CURVE_HINT.match(param):
        props["curve"] = param
    elif param:
        props["parameterSetIdentifier"] = param
    mode = str(row.algorithm).split("-")[-1]
    if row.family == "AES" and mode in MODES:
        props["mode"] = MODES[mode]
    if row.quantum_vulnerable:
        props["nistQuantumSecurityLevel"] = 0          # 0 = meets no NIST PQC category
    elif (row.algorithm, param) in NIST_QUANTUM_LEVEL:
        props["nistQuantumSecurityLevel"] = NIST_QUANTUM_LEVEL[(row.algorithm, param)]
    elif row.family == "AES" and param in AES_NIST_LEVEL:
        props["nistQuantumSecurityLevel"] = AES_NIST_LEVEL[param]
    return props


def _cipher_suites(snippet: str) -> list[dict]:
    m = re.search(r"(?:ssl_ciphers|SSLCipherSuite)\s+['\"]?([^'\";]+)", snippet or "")
    if not m:
        return []
    return [{"name": s} for s in m.group(1).split(":") if s and not s.startswith("!")]


def _properties(group: pd.DataFrame) -> list[dict]:
    worst = group.loc[group["tier_rank"].idxmin()] if "tier_rank" in group else group.iloc[0]
    props = [
        {"name": "ecdat:family", "value": str(worst["family"])},
        {"name": "ecdat:confidence", "value": "high" if (group["confidence"] == "high").any() else "medium"},
        {"name": "ecdat:quantumVulnerable", "value": str(bool(worst["quantum_vulnerable"])).lower()},
        {"name": "ecdat:classicallyWeak", "value": str(bool(group["classically_weak"].any())).lower()},
    ]
    if "tier" in group:
        props.insert(0, {"name": "ecdat:tier", "value": str(worst["tier"])})
        props.append({"name": "ecdat:moscaOvershootYears", "value": f"{float(worst['overshoot']):g}"})
    if "replacement" in group and worst.get("replacement"):
        props.append({"name": "ecdat:recommendation", "value": str(worst["replacement"])})
    return props


def _occurrences(group: pd.DataFrame) -> dict:
    return {"occurrences": [
        {"location": r.file, "line": int(r.line), "additionalContext": str(r.snippet)[:200]}
        for r in group.itertuples()]}


def build_cbom(df: pd.DataFrame, target_name: str = "scanned-repository") -> dict:
    """Build a CycloneDX 1.6 CBOM dict from (risk-scored) findings."""
    components: list[dict] = []
    refs: dict[str, str] = {}          # asset name -> bom-ref (algorithm components)

    def algo_ref(name: str, primitive: str, extra: dict | None = None) -> str:
        """Get or create an algorithm component (used for certificate key/signature links)."""
        if name not in refs:
            refs[name] = f"crypto-algorithm-{_slug(name)}"
            props = {"primitive": primitive}
            props.update(extra or {})
            components.append({"type": "cryptographic-asset", "bom-ref": refs[name], "name": name,
                               "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": props}})
        return refs[name]

    if not df.empty:
        # 1) algorithm assets (one component per unique asset name)
        algos = df[df["kind"] == "algorithm"]
        for name, g in algos.groupby("asset", sort=True):
            r = g.iloc[0]
            ref = f"crypto-algorithm-{_slug(name)}"
            refs[name] = ref
            components.append({
                "type": "cryptographic-asset", "bom-ref": ref, "name": name,
                "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": _algorithm_properties(r)},
                "evidence": _occurrences(g), "properties": _properties(g)})

        # 2) protocols
        for name, g in df[df["kind"] == "protocol"].groupby("asset", sort=True):
            r = g.iloc[0]
            pp = {"type": "tls"}
            v = re.match(r"TLSv(\d\.\d)", name)
            if v:
                pp["version"] = v.group(1)
            suites = [s for snip in g["snippet"] for s in _cipher_suites(snip)]
            if suites:
                pp["cipherSuites"] = suites
            components.append({
                "type": "cryptographic-asset", "bom-ref": f"crypto-protocol-{_slug(name)}", "name": name,
                "cryptoProperties": {"assetType": "protocol", "protocolProperties": pp},
                "evidence": _occurrences(g), "properties": _properties(g)})

        # 3) key material (hard-coded keys) - the key VALUE is never written to the CBOM
        for i, (name, g) in enumerate(df[df["kind"] == "related-crypto-material"].groupby("asset", sort=True)):
            r = g.iloc[0]
            rcm = {"type": "private-key", "format": "PEM"}
            if str(r.param).isdigit():
                rcm["size"] = int(r.param)
            components.append({
                "type": "cryptographic-asset", "bom-ref": f"crypto-key-{_slug(name)}-{i}", "name": name,
                "cryptoProperties": {"assetType": "related-crypto-material",
                                     "relatedCryptoMaterialProperties": rcm},
                "evidence": _occurrences(g), "properties": _properties(g)})

        # 4) certificates (one component per certificate occurrence)
        for i, r in enumerate(df[df["kind"] == "certificate"].itertuples()):
            key_name = f"{r.algorithm}-{r.param}" if r.param else r.algorithm
            key_extra = ({"curve": r.param} if r.family == "ECC" and r.param
                         else {"parameterSetIdentifier": str(r.param)} if r.param else {})
            cp = {
                "subjectName": r.cert_subject, "issuerName": r.cert_issuer,
                "notValidBefore": r.cert_not_before, "notValidAfter": r.cert_not_after,
                "signatureAlgorithmRef": algo_ref(r.cert_sig_alg, "signature"),
                "subjectPublicKeyRef": algo_ref(key_name, "pke" if r.family == "RSA" else "signature", key_extra),
                "certificateFormat": "X.509",
            }
            g = df.loc[[r.Index]]
            components.append({
                "type": "cryptographic-asset", "bom-ref": f"crypto-certificate-{i}-{_slug(r.file)}",
                "name": r.asset,
                "cryptoProperties": {"assetType": "certificate", "certificateProperties": cp},
                "evidence": _occurrences(g),
                "properties": _properties(g) + [{"name": "ecdat:daysToExpiry", "value": str(int(r.cert_days_left))}]})

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "tools": {"components": [{"type": "application", "name": TOOL_NAME, "version": TOOL_VERSION}]},
            "component": {"type": "application", "bom-ref": "scan-target", "name": target_name},
        },
        "components": components,
    }


def cbom_json(df: pd.DataFrame, target_name: str = "scanned-repository") -> str:
    return json.dumps(build_cbom(df, target_name), indent=2, default=str)


def validate_cbom(bom: dict | str) -> list[str]:
    """Light structural validation. Returns a list of problems (empty = OK).
    For full schema validation see tests/test_cbom.py (uses the official schema if installed)."""
    errors: list[str] = []
    if isinstance(bom, str):
        try:
            bom = json.loads(bom)
        except json.JSONDecodeError as e:
            return [f"invalid JSON: {e}"]
    try:
        json.dumps(bom)
    except (TypeError, ValueError) as e:
        return [f"not JSON-serialisable: {e}"]
    for key in REQUIRED_TOP_LEVEL:
        if key not in bom:
            errors.append(f"missing top-level key: {key}")
    if bom.get("bomFormat") != "CycloneDX":
        errors.append("bomFormat must be 'CycloneDX'")
    if bom.get("specVersion") != "1.6":
        errors.append("specVersion must be '1.6'")
    if not re.fullmatch(r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                        str(bom.get("serialNumber", ""))):
        errors.append("serialNumber must be urn:uuid:<uuid>")
    if not isinstance(bom.get("version"), int) or bom.get("version", 0) < 1:
        errors.append("version must be an integer >= 1")
    seen = set()
    for c in bom.get("components", []):
        ref = c.get("bom-ref")
        if ref in seen:
            errors.append(f"duplicate bom-ref: {ref}")
        seen.add(ref)
        if c.get("type") != "cryptographic-asset" or "name" not in c:
            errors.append(f"component {ref}: needs type 'cryptographic-asset' and a name")
        if "assetType" not in c.get("cryptoProperties", {}):
            errors.append(f"component {ref}: cryptoProperties.assetType missing")
    return errors


__all__ = ["build_cbom", "cbom_json", "validate_cbom", "TIER_RANK"]
