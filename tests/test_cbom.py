"""CBOM top-level structure (+ full schema validation when the official schema is installed)."""
import json

import pytest

from cbom import build_cbom, validate_cbom
from conftest import SAMPLE
from recommend import add_recommendations
from risk import apply_risk
from scanner import scan_folder


@pytest.fixture(scope="module")
def bom():
    df, _ = scan_folder(SAMPLE)
    return build_cbom(add_recommendations(apply_risk(df, 5, 12)), "sample_repo")


def test_top_level(bom):
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    assert bom["serialNumber"].startswith("urn:uuid:") and bom["version"] == 1
    assert bom["metadata"]["tools"]["components"][0]["name"] == "ECDAT"
    assert validate_cbom(bom) == []
    assert validate_cbom(json.dumps(bom)) == []


def test_components(bom):
    types = {c["cryptoProperties"]["assetType"] for c in bom["components"]}
    assert types == {"algorithm", "certificate", "protocol", "related-crypto-material"}
    assert all(c["type"] == "cryptographic-asset" for c in bom["components"])
    refs = {c["bom-ref"] for c in bom["components"]}
    for c in bom["components"]:
        cp = c["cryptoProperties"].get("certificateProperties")
        if cp:   # certificate links must point at existing components
            assert cp["signatureAlgorithmRef"] in refs and cp["subjectPublicKeyRef"] in refs
    ecb = next(c for c in bom["components"] if c["name"] == "AES-128-ECB")
    assert ecb["cryptoProperties"]["algorithmProperties"]["mode"] == "ecb"
    assert ecb["evidence"]["occurrences"][0]["location"] == "auth/token_utils.py"


def test_private_key_value_never_exported(bom):
    assert "MII" not in json.dumps(bom)    # PEM key bodies start with MII...


def test_validator_catches_problems():
    assert "missing top-level key: components" in validate_cbom({"bomFormat": "CycloneDX"})
    assert validate_cbom("{not json")[0].startswith("invalid JSON")


def test_official_schema(bom):
    """Validate against the official CycloneDX 1.6 JSON schema shipped in cyclonedx-python-lib."""
    pytest.importorskip("cyclonedx")
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator
    err = JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(bom))
    assert err is None, str(err)
