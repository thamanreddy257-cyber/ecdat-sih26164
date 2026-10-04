"""Folder scanner: runs rules line by line and parses X.509 certificates.

Phase 1 scope: text source/config files and PEM/DER certificates only.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from rules import BASE64_LINE, EXT_LANG, RULES

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env",
             "__pycache__", ".mypy_cache", ".pytest_cache", "dist", "build", ".idea", ".vscode"}
CERT_EXTS = {".pem", ".crt", ".cer", ".der"}
MAX_FILE_BYTES = 2_000_000      # files larger than this are skipped
PARAM_WINDOW = 3                # lines after a match searched for key size / curve
SNIPPET_LEN = 140
NEAR_EXPIRY_DAYS = 90
PEM_BLOCK = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)

COLUMNS = ["file", "line", "asset", "algorithm", "param", "family", "kind", "primitive",
           "snippet", "confidence", "quantum_vulnerable", "classically_weak", "marginal",
           "rule_id", "notes", "cert_subject", "cert_issuer", "cert_sig_alg",
           "cert_not_before", "cert_not_after", "cert_days_left"]


# ---------------------------------------------------------------- helpers
def _is_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return b"\x00" in fh.read(4096)
    except OSError:
        return True


def _read_text(path: Path) -> str | None:
    """Read a file as text; tolerate bad encodings. Returns None if unreadable."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    for enc in ("utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def _asset_name(algorithm: str, param: str) -> str:
    """Human-readable asset name, e.g. RSA-2048, AES-256-GCM, SHA-384, SHA3-256."""
    if not param:
        return algorithm
    if algorithm == "SHA-2":
        return f"SHA-{param}"
    if algorithm == "SHA-3":
        return f"SHA3-{param}"
    if algorithm.startswith("AES-"):                     # AES-GCM + 256 -> AES-256-GCM
        return f"AES-{param}-{algorithm[4:]}"
    return f"{algorithm}-{param}"


def _key_facts(key) -> tuple[str, str, str]:
    """(algorithm, param, family) for a public or private key object."""
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return "RSA", str(key.key_size), "RSA"
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return "ECDSA", key.curve.name, "ECC"
    if isinstance(key, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
        return "DSA", str(key.key_size), "DH/DSA"
    if isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        return "Ed25519", "", "ECC"
    if isinstance(key, (ed448.Ed448PublicKey, ed448.Ed448PrivateKey)):
        return "Ed448", "", "ECC"
    return type(key).__name__, "", "key-material"


def _row(**kw) -> dict:
    row = {c: None for c in COLUMNS}
    row.update(kw)
    return row


# ---------------------------------------------------------------- certificates
def parse_certificates(path: Path, rel: str) -> list[dict]:
    """Parse every certificate in a PEM/DER file into a finding row."""
    try:
        data = path.read_bytes()
    except OSError:
        return []
    certs: list[x509.Certificate] = []
    try:
        if b"-----BEGIN CERTIFICATE-----" in data:
            certs = x509.load_pem_x509_certificates(data)
        elif path.suffix.lower() in {".der", ".cer", ".crt"}:
            certs = [x509.load_der_x509_certificate(data)]
    except ValueError:
        return []

    text = data.decode("latin-1")
    begin_lines = [i + 1 for i, l in enumerate(text.splitlines()) if "BEGIN CERTIFICATE" in l] or [1]
    now = datetime.now(timezone.utc)
    rows = []
    for idx, cert in enumerate(certs):
        algo, param, family = _key_facts(cert.public_key())
        hash_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else ""
        sig_oid = cert.signature_algorithm_oid
        sig_name = getattr(sig_oid, "_name", None) or sig_oid.dotted_string
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
        not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
        days_left = (not_after - now).days

        weak_reasons = []
        if family == "RSA" and int(param) < 2048:
            weak_reasons.append(f"RSA-{param} below 2048 bits")
        if hash_alg in {"md5", "sha1"}:
            weak_reasons.append(f"{hash_alg.upper()} signature")
        if days_left < 0:
            weak_reasons.append("expired")
        notes = "; ".join(weak_reasons) or "Public key is quantum-vulnerable (Shor)."
        rows.append(_row(
            file=rel, line=begin_lines[min(idx, len(begin_lines) - 1)],
            asset=f"X.509 cert ({_asset_name(algo, param)}, {hash_alg or sig_name})",
            algorithm=algo, param=param, family=family, kind="certificate", primitive="signature",
            snippet=f"subject={cert.subject.rfc4514_string()}",
            confidence="high",
            quantum_vulnerable=family in {"RSA", "ECC", "DH/DSA"},
            classically_weak=bool(weak_reasons), marginal=False,
            rule_id="CERT-X509", notes=notes,
            cert_subject=cert.subject.rfc4514_string(), cert_issuer=cert.issuer.rfc4514_string(),
            cert_sig_alg=sig_name, cert_not_before=not_before.isoformat(),
            cert_not_after=not_after.isoformat(), cert_days_left=days_left,
        ))
    return rows


def _private_key_facts(text: str, start_line: int) -> tuple[str, str, str] | None:
    """Try to load the PEM private-key block that starts at start_line (1-based)."""
    rest = "\n".join(text.splitlines()[start_line - 1:])
    m = PEM_BLOCK.search(rest)
    if not m:
        return None
    # Strip indentation / string quotes left over from source code.
    block = "\n".join(l.strip().strip("\"',") for l in m.group(0).splitlines())
    try:
        key = serialization.load_pem_private_key(block.encode(), password=None)
    except (ValueError, TypeError):
        return None
    return _key_facts(key)


# ---------------------------------------------------------------- source scanning
def scan_text(text: str, rel: str, lang: str) -> list[dict]:
    rows = []
    lines = text.splitlines()
    rules = [r for r in RULES if r.applies_to(lang)]
    for n, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or BASE64_LINE.match(line):
            continue
        for rule in rules:
            if not rule.regex().search(line):
                continue
            confidence = rule.confidence
            if confidence == "medium" and rule.high_context and re.search(rule.high_context, line):
                confidence = "high"
            param = ""
            if rule.param_pattern:
                window = "\n".join(lines[n - 1:n + PARAM_WINDOW])
                m = re.search(rule.param_pattern, window)
                param = m.group(1) if m else ""
            algorithm, family, qv, weak, notes = (rule.algorithm, rule.family,
                                                   rule.quantum_vulnerable, rule.classically_weak, rule.notes)
            asset = _asset_name(algorithm, param)
            if rule.id == "PEM-PRIVATE-KEY":      # load the key to report real facts
                facts = _private_key_facts(text, n)
                if facts:
                    k_alg, param, k_fam = facts
                    algorithm = f"{k_alg} private key"
                    asset = f"Private key ({_asset_name(k_alg, param)})"
                    qv = k_fam in {"RSA", "ECC", "DH/DSA"}
            weak = weak or (family == "RSA" and param.isdigit() and int(param) < 2048)
            marginal = family == "AES" and param == "128"   # Grover halves effective strength
            rows.append(_row(
                file=rel, line=n, asset=asset, algorithm=algorithm,
                param=param, family=family, kind=rule.kind, primitive=rule.primitive,
                snippet=line[:SNIPPET_LEN], confidence=confidence, quantum_vulnerable=qv,
                classically_weak=weak, marginal=marginal, rule_id=rule.id, notes=notes,
            ))
    return rows


def _dedupe(rows: list[dict]) -> list[dict]:
    """Drop sensible duplicates on the same file+line+family:
    - the same base algorithm found by several rules -> keep the highest confidence
    - medium keyword hits when a high-confidence API hit exists for that family
    """
    best: dict[tuple, dict] = {}
    for r in rows:
        key = (r["file"], r["line"], r["family"], r["algorithm"])
        cur = best.get(key)
        if cur is None or (cur["confidence"] == "medium" and r["confidence"] == "high") \
                or (cur["confidence"] == r["confidence"] and not cur["param"] and r["param"]):
            best[key] = r
    kept = list(best.values())
    high_fams = {(r["file"], r["line"], r["family"]) for r in kept if r["confidence"] == "high"}
    return [r for r in kept
            if r["confidence"] == "high" or (r["file"], r["line"], r["family"]) not in high_fams]


def scan_folder(folder: str | os.PathLike) -> tuple[pd.DataFrame, dict]:
    """Scan a folder. Returns (findings DataFrame, summary dict).
    Raises FileNotFoundError / NotADirectoryError for an invalid path."""
    root = Path(folder).expanduser()
    if not root.exists():
        raise FileNotFoundError(f"Folder not found: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Not a folder: {root}")

    rows: list[dict] = []
    stats = {"files_scanned": 0, "files_skipped": 0, "certificates": 0}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            ext = path.suffix.lower()
            try:
                too_big = path.stat().st_size > MAX_FILE_BYTES
            except OSError:
                too_big = True
            if too_big:
                stats["files_skipped"] += 1
                continue
            if ext in CERT_EXTS:
                cert_rows = parse_certificates(path, rel)
                stats["certificates"] += len(cert_rows)
                rows.extend(cert_rows)
                stats["files_scanned"] += 1
                if cert_rows or ext == ".der":
                    continue          # cert file: base64 body is not scanned for keywords
            if _is_binary(path):
                stats["files_skipped"] += 1
                continue
            text = _read_text(path)
            if text is None:
                stats["files_skipped"] += 1
                continue
            if ext not in CERT_EXTS:
                stats["files_scanned"] += 1
            rows.extend(scan_text(text, rel, EXT_LANG.get(ext, "other")))

    df = pd.DataFrame(_dedupe(rows), columns=COLUMNS)
    if not df.empty:
        df = df.sort_values(["file", "line", "family"]).reset_index(drop=True)
        df["line"] = df["line"].astype(int)
    summary = {
        **stats,
        "findings": len(df),
        "unique_assets": int(df["asset"].nunique()) if not df.empty else 0,
        "quantum_vulnerable": int(df["quantum_vulnerable"].sum()) if not df.empty else 0,
        "classically_weak": int(df["classically_weak"].sum()) if not df.empty else 0,
        "by_family": df["family"].value_counts().to_dict() if not df.empty else {},
        "certs_near_expiry": int((df["cert_days_left"].dropna() <= NEAR_EXPIRY_DAYS).sum()) if not df.empty else 0,
    }
    return df, summary
