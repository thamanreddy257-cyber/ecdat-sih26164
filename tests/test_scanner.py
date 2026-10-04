"""Rule matches on the bundled sample repo + certificate parsing."""
import pytest

from conftest import SAMPLE
from scanner import _dedupe, scan_folder, scan_text


@pytest.fixture(scope="module")
def scan():
    return scan_folder(SAMPLE)


def has(df, file, rule_id, asset=None):
    m = (df["file"] == file) & (df["rule_id"] == rule_id)
    if asset:
        m &= df["asset"] == asset
    return bool(m.any())


def test_python_rules(scan):
    df, _ = scan
    assert has(df, "payments/rsa_keys.py", "RSA-PY-GEN", "RSA-2048")
    assert has(df, "auth/token_utils.py", "MD5-API")
    assert has(df, "auth/token_utils.py", "SHA1-API")
    assert has(df, "auth/token_utils.py", "AES-PY-ECB", "AES-128-ECB")
    assert has(df, "archive/backup_crypto.py", "AES-PY-GCM", "AES-256-GCM")
    assert has(df, "archive/backup_crypto.py", "SHA2-API", "SHA-256")


def test_java_rules(scan):
    df, _ = scan
    assert has(df, "payments/PaymentSigner.java", "RSA-JAVA-KPG", "RSA-2048")
    assert has(df, "payments/PaymentSigner.java", "SIG-SHA1-RSA")
    assert has(df, "payments/PaymentSigner.java", "3DES")
    assert has(df, "auth/EcdsaAuth.java", "EC-JAVA-KPG", "ECDSA-secp256r1")
    assert has(df, "auth/EcdsaAuth.java", "AES-JAVA-DEFAULT", "AES-ECB")


def test_js_and_config_rules(scan):
    df, _ = scan
    assert has(df, "services/key_exchange.js", "ECDH-JS", "ECDH-prime256v1")
    assert has(df, "services/key_exchange.js", "RSA-JS-GEN", "RSA-2048")
    tls = df[(df["file"] == "infra/nginx.conf") & (df["family"] == "protocol")]
    assert {"TLSv1.0", "TLSv1.1", "TLSv1.2", "Weak TLS cipher list"} <= set(tls["asset"])
    # TLS versions inside the ssl_protocols directive are upgraded to high confidence
    assert (tls[tls["asset"].str.startswith("TLSv")]["confidence"] == "high").all()


def test_private_key_and_pqc(scan):
    df, _ = scan
    key = df[df["rule_id"] == "PEM-PRIVATE-KEY"]
    assert len(key) == 1 and key.iloc[0]["asset"] == "Private key (RSA-2048)"
    pqc = df[df["family"] == "PQC"]
    assert {"ML-KEM-768", "ML-DSA-65"} <= set(pqc["asset"])
    assert not pqc["quantum_vulnerable"].any()


def test_no_findings_from_base64_and_binary(scan):
    df, summary = scan
    assert not (df["file"] == "archive/blob.bin").any()
    assert summary["files_skipped"] >= 1
    # only the BEGIN line of the embedded key produces a finding
    assert (df["file"] == "auth/dev_keys.py").sum() == 1


def test_dedupe_keeps_specific_rule():
    rows = scan_text('Signature s = Signature.getInstance("SHA1withRSA");', "x.java", "java")
    assert [r["rule_id"] for r in _dedupe(rows)] == ["SIG-SHA1-RSA"]


def test_certificates(scan):
    df, summary = scan
    certs = df[df["kind"] == "certificate"].set_index("file")
    assert summary["certificates"] == 3
    rsa2048 = certs.loc["infra/certs/server_rsa2048.pem"]
    assert (rsa2048["algorithm"], rsa2048["param"]) == ("RSA", "2048")
    assert rsa2048["cert_sig_alg"] == "sha256WithRSAEncryption"
    ec = certs.loc["infra/certs/api_ecdsa_p256.pem"]
    assert (ec["algorithm"], ec["param"]) == ("ECDSA", "secp256r1")
    legacy = certs.loc["infra/certs/legacy_rsa1024_sha1.pem"]
    assert legacy["param"] == "1024" and legacy["cert_sig_alg"] == "sha1WithRSAEncryption"
    assert legacy["classically_weak"] and legacy["cert_days_left"] <= 90
    assert (certs["confidence"] == "high").all()


def test_invalid_folder():
    with pytest.raises(FileNotFoundError):
        scan_folder(SAMPLE / "does-not-exist")


def test_bad_encoding(tmp_path):
    (tmp_path / "weird.py").write_bytes(b"\xff\xfe h = hashlib.md5(b'x')\n")
    df, _ = scan_folder(tmp_path)
    assert (df["rule_id"] == "MD5-API").any()
